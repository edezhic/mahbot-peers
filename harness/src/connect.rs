//! Connecting two machines over the simulated link.
//!
//! The endpoints are built by the library's transport, over the same
//! abstract-socket and clock seams a real deployment uses: the only difference
//! is which socket and which clock are handed in.
//!
//! A connection attempt drives the clock itself, because nothing else would: a
//! lost handshake datagram is retransmitted by a quinn timer, and a timer only
//! fires when time moves. The budget is virtual, so a link that drops everything
//! fails at a deterministic instant instead of hanging the test.
//!
//! One machine may serve several dialers at once. Its own endpoint accepts every
//! connection it is offered and files it by the dialer's address; each attempt
//! takes only the connection its own dialer made, because an accept loop that
//! returned whichever connection came first would hand two attempts each other's
//! halves. An endpoint the caller built serves one attempt and files anything
//! else it is offered into the same inbox.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use mahbot_peers::identity::Fingerprint;
use mahbot_peers::net::TransportError;
use mahbot_peers::peer::RecordStore;
use mahbot_peers::tls::PeerPolicy;
use quinn::{Connection, Endpoint, Incoming};

use crate::machine::Machine;

/// The name rustls is given for a connection, from the library, so the rig and the
/// crate cannot name the same service differently.
pub const SERVER_NAME: &str = mahbot_peers::net::SERVER_NAME;

/// The fingerprints one machine trusts.
#[derive(Debug, Default)]
pub struct TrustSet {
    peers: Mutex<HashSet<Fingerprint>>,
}

impl TrustSet {
    pub fn insert(&self, peer: Fingerprint) {
        self.lock().insert(peer);
    }

    pub fn contains(&self, peer: &Fingerprint) -> bool {
        self.lock().contains(peer)
    }

    fn lock(&self) -> MutexGuard<'_, HashSet<Fingerprint>> {
        self.peers.lock().expect("trust set is not poisoned")
    }
}

impl PeerPolicy for TrustSet {
    fn trusts(&self, peer: &Fingerprint) -> bool {
        self.contains(peer)
    }
}

/// What a machine's endpoint trusts: the in-memory set a case fills with
/// `Machine::trust`, and the durable records a person wrote.
///
/// The peer-layer cases use the record half; the transport cases use the set. One
/// endpoint serves both, because a machine has one socket and the endpoint built
/// over it is the one a beacon session and a peer dial share.
#[derive(Debug)]
pub struct Policy {
    pub trust: Arc<TrustSet>,
    pub records: RecordStore,
}

impl PeerPolicy for Policy {
    fn trusts(&self, peer: &Fingerprint) -> bool {
        self.trust.contains(peer) || self.records.trusts(&peer.peer_id())
    }
}

/// Incoming connections one machine has been offered, filed by the dialer's
/// address until the attempt that dialed them takes its own.
///
/// One entry per address, replaced by a newer connection from the same dialer:
/// an attempt abandoned mid-handshake leaves at most one stale entry behind, and
/// the map is bounded by the number of machines that ever dialed this one.
#[derive(Debug, Default)]
pub(crate) struct Inbox {
    waiting: Mutex<HashMap<SocketAddr, Incoming>>,
}

impl Inbox {
    fn lock(&self) -> MutexGuard<'_, HashMap<SocketAddr, Incoming>> {
        self.waiting.lock().expect("inbox is not poisoned")
    }

    fn put(&self, incoming: Incoming) {
        // Dropping the previous connection closes it: the attempt that would
        // have taken it has already given up.
        self.lock().insert(incoming.remote_address(), incoming);
    }

    fn take(&self, from: SocketAddr) -> Option<Incoming> {
        self.lock().remove(&from)
    }

    /// How many dialers are waiting: at most one entry per address.
    pub(crate) fn len(&self) -> usize {
        self.lock().len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }
}

impl Machine {
    /// This machine's endpoint, created once and reused.
    ///
    /// Both directions are pinned to the machine's trust set, so a peer it does
    /// not trust cannot complete a handshake with it.
    pub(crate) fn endpoint(&self) -> Result<Endpoint, TransportError> {
        let mut slot = self.endpoint_slot();
        if let Some(endpoint) = slot.as_ref() {
            return Ok(endpoint.clone());
        }
        let policy: Arc<dyn PeerPolicy> = Arc::new(Policy {
            trust: Arc::clone(&self.trust),
            records: self.records.clone(),
        });
        let endpoint = self.transport.endpoint(
            Arc::clone(&self.socket) as Arc<dyn quinn::AsyncUdpSocket>,
            self.clock.runtime(),
            &self.identity,
            policy,
        )?;
        *slot = Some(endpoint.clone());
        Ok(endpoint)
    }

    /// Start the task that accepts connections for this machine, once.
    ///
    /// The task runs on this machine's own endpoint, which is the one `connect`
    /// dials; an endpoint a caller builds is served by [`connect_over`] itself.
    /// It belongs to the runtime that is current at the first connect, the same
    /// one the endpoint's driver runs on: a machine cannot be carried across two
    /// `block_on` calls. It ends when the endpoint closes, which dropping the
    /// machine does.
    ///
    /// # Panics
    ///
    /// When the accept task panicked: the panic is resumed here, on the attempt
    /// that found the task finished, instead of becoming a misleading timeout.
    pub(crate) async fn start_accepting(&self) -> Result<(), ConnectError> {
        let finished = {
            let mut slot = self.accepting();
            match slot.as_ref() {
                Some(task) if task.is_finished() => slot.take(),
                _ => None,
            }
        };
        if let Some(task) = finished
            && let Err(error) = task.await
        {
            std::panic::resume_unwind(error.into_panic());
        }
        let endpoint = self.endpoint()?;
        let mut slot = self.accepting();
        if slot.is_some() {
            return Ok(());
        }
        let inbox = Arc::clone(&self.inbox);
        *slot = Some(tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                inbox.put(incoming);
            }
        }));
        Ok(())
    }
}

/// Both ends of one connection.
#[derive(Debug)]
pub struct Pair {
    /// The side that called `connect`.
    pub client: Connection,
    /// The side that accepted.
    pub server: Connection,
}

/// How much virtual time one connection attempt may take.
pub const DEFAULT_CONNECT_BUDGET: Duration = Duration::from_secs(10);

/// Connect `from` to `to`, both of which must trust each other.
///
/// # Errors
///
/// Any handshake failure, or [`ConnectError::TimedOut`] once the virtual budget
/// is spent.
pub async fn connect(from: &Machine, to: &Machine) -> Result<Pair, ConnectError> {
    connect_by(from, to, DEFAULT_CONNECT_BUDGET).await
}

/// Connect with an explicit virtual-time budget.
///
/// # Errors
///
/// Any handshake failure, or [`ConnectError::TimedOut`] once the virtual budget
/// is spent.
pub async fn connect_by(
    from: &Machine,
    to: &Machine,
    budget: Duration,
) -> Result<Pair, ConnectError> {
    to.start_accepting().await?;
    drive(from, to, Accepting::Filed, budget).await
}

/// Connect to `to` over an endpoint the caller built, for a case that has to
/// change something about the server side — a different ALPN, a server with no
/// accept task.
///
/// The clock is advanced in steps while the handshake is pending, so retransmits
/// and timeouts happen at virtual instants the test can reason about. One
/// attempt at a time per `(from, to)` pair: two attempts from the same machine to
/// the same machine cannot be told apart by address, and one caller-supplied
/// endpoint serves one attempt at a time — a connection it is offered from
/// another machine is refused rather than paired with the wrong dialer.
///
/// # Errors
///
/// Any handshake failure, [`ConnectError::Closed`] when the endpoint closed
/// before the handshake, or [`ConnectError::TimedOut`] once the virtual budget is
/// spent.
pub async fn connect_over(
    from: &Machine,
    to: &Machine,
    server_endpoint: &Endpoint,
    budget: Duration,
) -> Result<Pair, ConnectError> {
    drive(from, to, Accepting::Direct(server_endpoint), budget).await
}

/// Where the server's half of the handshake comes from.
#[derive(Clone, Copy)]
enum Accepting<'a> {
    /// The machine's own accept task, keyed by the dialer's address.
    Filed,
    /// An endpoint the caller built, which serves this one attempt.
    Direct(&'a Endpoint),
}

/// Dial, and wait for the other side's half of the same connection.
async fn drive(
    from: &Machine,
    to: &Machine,
    accepting: Accepting<'_>,
    budget: Duration,
) -> Result<Pair, ConnectError> {
    let client_endpoint = from.endpoint()?;
    let attempt = attempt(from, to, &client_endpoint, accepting);
    from.clock
        .drive(budget, attempt)
        .await
        .unwrap_or(Err(ConnectError::TimedOut { budget }))
}

/// Both halves of one connection. The accept side has to be polled while the
/// dial is pending: the server holds its half in an incoming until the
/// application takes it, and the client's handshake does not finish before that.
async fn attempt(
    from: &Machine,
    to: &Machine,
    client_endpoint: &Endpoint,
    accepting: Accepting<'_>,
) -> Result<Pair, ConnectError> {
    let accept = accept_for(to, accepting, from.addr());
    let dial = async {
        client_endpoint
            .connect(to.addr(), SERVER_NAME)
            .map_err(ConnectError::Connect)?
            .await
            .map_err(ConnectError::Connection)
    };
    let (server, client) = tokio::try_join!(accept, dial)?;
    Ok(Pair { client, server })
}

/// Wait for the connection `from` dialed, from wherever the server's half comes.
async fn accept_for(
    to: &Machine,
    accepting: Accepting<'_>,
    from: SocketAddr,
) -> Result<Connection, ConnectError> {
    loop {
        let incoming = match accepting {
            // The machine's own endpoint files every connection it is offered,
            // so this attempt takes only its own and leaves the rest.
            Accepting::Filed => {
                let Some(incoming) = to.inbox.take(from) else {
                    tokio::task::yield_now().await;
                    continue;
                };
                incoming
            }
            // A caller-supplied endpoint has no task: this attempt accepts for
            // itself, and a connection from another machine is refused because
            // one such endpoint serves one attempt at a time.
            Accepting::Direct(endpoint) => {
                let Some(incoming) = endpoint.accept().await else {
                    return Err(ConnectError::Closed);
                };
                if incoming.remote_address() != from {
                    continue;
                }
                incoming
            }
        };
        if let Some(server) = settle(incoming).await? {
            return Ok(server);
        }
    }
}

/// Take one incoming connection, or `None` when it belongs to an attempt that
/// was abandoned: that attempt's abort closes its connection, and the next dial
/// on the same pair must not be handed it.
///
/// A handshake the server actually refused arrives as a transport error, so it
/// is surfaced instead of being retried.
async fn settle(incoming: Incoming) -> Result<Option<Connection>, ConnectError> {
    match incoming.await {
        Ok(server) => Ok(Some(server)),
        Err(quinn::ConnectionError::ConnectionClosed { .. }) => Ok(None),
        Err(error) => Err(ConnectError::Connection(error)),
    }
}

/// Why two machines could not be connected.
#[derive(Debug)]
pub enum ConnectError {
    Transport(TransportError),
    Connect(quinn::ConnectError),
    Connection(quinn::ConnectionError),
    /// The endpoint closed before the handshake finished.
    Closed,
    TimedOut {
        budget: Duration,
    },
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => write!(f, "endpoint: {error}"),
            Self::Connect(error) => write!(f, "cannot dial: {error}"),
            Self::Connection(error) => write!(f, "handshake: {error}"),
            Self::Closed => f.write_str("the endpoint closed before the handshake"),
            Self::TimedOut { budget } => {
                write!(f, "no handshake within {budget:?} of virtual time")
            }
        }
    }
}

impl std::error::Error for ConnectError {}

impl From<TransportError> for ConnectError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}
