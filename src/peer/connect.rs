//! The per-machine connection manager: dialling, accepting, one connection per
//! pair, and the four failures.
//!
//! # Reconnecting
//!
//! A machine dials the address authenticated data last arrived from, then asks the
//! beacon once, then stops. There is no periodic re-check and no timer that starts
//! an attempt: the next attempt happens only on a lost connection, on this machine's
//! own start, when a person asks, or when a fresh address for that peer arrives in an
//! introduction — that last one is handed to [`Connections::connect_with`], which
//! tries it first. A peer that comes back online dials out itself, which is what
//! re-establishes the pair; the side that stayed up does not poll for it.
//!
//! Recovery is the manager's: [`Connections::keep_connected`] watches the pair's
//! live connection and dials again when it is gone, so a caller runs one per paired
//! peer and does not dial itself. A connection that carried anything and then died
//! is a link failure and is re-dialled without a bound; only dials that carried
//! nothing are counted. When the keeper stops instead of dialling, it says which way
//! it stopped: [`Keeper`], and what counts is stated on
//! [`Connections::keep_connected`].
//!
//! # A quiet pair
//!
//! A keep-alive on either machine holds a silent pair: QUIC's idle timeout is the
//! smaller of the two machines' and a ping resets it on both, so
//! [`Connections::new`] accepts a transport with no keep-alive at all, and a silent
//! pair then lives only while the peer keeps pinging. With both sides silent the
//! connection closes at the idle timeout and [`Connections::keep_connected`] dials it
//! again — recovery, not a failure of the pair.
//!
//! The keeper judges a fresh connection by its own window, [`KEEPER_SETTLE`], not by
//! the transport's idle timeout. A connection the keeper dialled that ends inside
//! that window having carried nothing is a strike against the peer, and
//! [`KEEPER_UNSTABLE_LIMIT`] of those in a row stop the keeper, so a transport whose
//! idle timeout is not longer than the window would turn each ordinary silent drop
//! into a strike and a run of them into a stop. That is why [`Connections::new`]
//! refuses one. The check reads this machine's transport only: over the wire the
//! effective timeout is the smaller of the two machines', so a peer built with a
//! shorter one can still close a quiet connection inside this machine's window.
//!
//! The manager reads the record store as it is loaded. A process that shares a
//! storage root with another — the self-update window — calls
//! [`RecordStore::reload`] before it dials or starts a keeper, so a pairing the
//! other process completed is seen. A running keeper does not reload on its own: its
//! next dial reads the store as the caller last loaded it, so another process's later
//! write is picked up by a caller's reload or by the next start.
//!
//! # One connection per pair
//!
//! Two connections between one pair happen when both machines dial at the same
//! moment, and the rule is asymmetric so both sides keep the same one: the
//! connection started by the machine with the smaller fingerprint is kept and the
//! other is dropped. A machine may dial while it believes it is connected, and
//! losing the dropped connection is not a failure of the pair. When both
//! connections were started by the same machine — a machine that dialed twice —
//! the one whose TLS exporter is smaller is kept, a value both sides compute
//! identically.
//!
//! Liveness is read only to drop a connection that has already closed: it can
//! carry nothing, so it is not a candidate. The choice between two live
//! connections reads only the facts both sides share; when one side has observed a
//! close the other has not, the two may briefly name different connections, and
//! each closes the loser — the next dial re-establishes the pair.
//!
//! A collision needs no second recovery path. Both machines run the manager: when
//! the connection one side kept then dies, the machine whose dial lost re-dials, and
//! the machine that kept it dials again because its connection is gone. Whichever
//! dial wins, both keepers adopt the connection the rule keeps. A machine running the
//! peer layer without a keeper is not a configuration this product has.
//!
//! # Accepting
//!
//! [`Connections::serve`] is the accept loop, and the caller runs it: the crate has
//! no runtime of its own to spawn on, so the caller keeps the handle and decides
//! when the loop stops. Run [`ACCEPT_LANES`] copies of it, so one peer that opens a
//! connection and stalls cannot block every other peer for the whole connect
//! budget. Accepting records the peer's authenticated source address — one small
//! blocking file read, and a write only when the address changed — on the task that
//! accepted it: this crate has no blocking pool to hand it to, and a product that
//! must keep its reactor free runs the accept loop on a task it can block.
//!
//! # The four failures
//!
//! The beacon cannot be reached; the beacon does not know the peer; the peer's
//! address is known and no connection can be made; the peer is not trusted. Each
//! is reported as itself, none as another, and none turns into a retry loop. "Not
//! trusted" is decided here and only here: the far side's refusal text is
//! diagnostic and may be forged, so it never drives trust or a retry.

use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use quinn::{Connection, ConnectionError, Endpoint, Incoming, Runtime};
use rustls::pki_types::CertificateDer;

use crate::beacon::{Beacon, timeout};
use crate::identity::{Fingerprint, Identity, PeerId};
use crate::net::{SERVER_NAME, Transport};
use crate::peer::record::RecordStore;

/// How long one dial or one handshake may take before it is reported as no path.
const DEFAULT_CONNECT_BUDGET: Duration = Duration::from_secs(10);

/// How long a connection must stay up before the keeper counts it as one the peer
/// keeps.
///
/// A connection the keeper dialled that ends inside this window without carrying
/// anything is one the pair never got to use, and a run of those is bounded. The
/// window is the keeper's own, not the transport's: the module's *A quiet pair* note
/// says why a transport whose idle timeout is not longer than this window is refused.
/// It is not a poll interval — nothing is re-dialled while a connection is up.
/// [`Connections::keep_connected`] states what the window decides.
pub const KEEPER_SETTLE: Duration = Duration::from_secs(10);

/// How many dials in a row may produce a connection that ends before the pair
/// carried anything and inside [`KEEPER_SETTLE`], before the keeper stops.
///
/// One is an ordinary loss; a run of them is a peer that accepts and drops, and
/// re-dialling at handshake rate is the silent retry loop the design rules out. It
/// is public because the test rig drives cases by that number, and because a caller
/// deciding what to do after a [`Keeper::Unstable`] stop may want it.
pub const KEEPER_UNSTABLE_LIMIT: u8 = 3;

/// How many accept loops a machine should run at once.
///
/// One loop awaiting a stalled peer's handshake would block every other peer for
/// the whole connect budget on a public address; four lanes let three others make
/// progress while one is stalled, without an unbounded task per incoming
/// connection. The caller spawns them, because the crate has no runtime of its own.
pub const ACCEPT_LANES: usize = 4;

/// The TLS exporter label the same-starter tie-break reads. Both sides of one
/// connection derive the same bytes under it.
const TIE_BREAK_LABEL: &[u8] = b"mahbot-peers connection tie-break v1";

/// Which machine started a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Started {
    /// This machine dialed.
    Here,
    /// The peer dialed and this machine accepted.
    There,
}

/// One live connection and who started it.
struct Live {
    connection: Connection,
    started_by: Started,
}

/// What one attempt to reach a peer produced, before it is folded into the four
/// failures.
enum Attempt {
    /// The pair's connection, ready to watch.
    ///
    /// `kept_this` says whether this attempt's own connection is the one kept; it is
    /// false when that connection lost the tie-break to one the pair already held.
    Kept {
        connection: Connection,
        kept_this: bool,
    },
    /// A handshake completed at `address`, but the tie-break dropped the connection
    /// and no other took its place: a dial that carried nothing, not a failed dial.
    /// [`Connections::connect_with`] answers with the pair's live connection when one
    /// exists, and reports this cause only when the pair has none.
    Dropped {
        address: SocketAddr,
        cause: &'static str,
    },
    /// The attempt failed with one of the four failures.
    Failed(ConnectFailure),
}

/// The connection manager of one machine.
pub struct Connections {
    me: PeerId,
    store: RecordStore,
    beacon: Option<Beacon>,
    runtime: Arc<dyn Runtime>,
    pairs: Mutex<BTreeMap<PeerId, Live>>,
}

impl fmt::Debug for Connections {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connections")
            .field("me", &self.me)
            .field("beacon", &self.beacon.is_some())
            .finish_non_exhaustive()
    }
}

impl Connections {
    /// Build the manager for `me`, trusting exactly what `store` remembers, over the
    /// transport the endpoint will be built from.
    ///
    /// The endpoint the caller passes to [`Self::connect`] and runs
    /// [`Self::serve`] over must be built over the same store as its
    /// [`crate::tls::PeerPolicy`] and from this same `transport`: the handshake would
    /// otherwise trust a peer this manager does not, and the keeper would judge
    /// connections by a window the endpoint's own transport was never checked
    /// against. quinn exposes no way to read an endpoint's transport back, so this is
    /// a contract the caller keeps, not something the manager can check. The store is
    /// read as it is loaded; see the module docs on the self-update window.
    ///
    /// # Errors
    ///
    /// [`ManagerError::IdleTimeoutTooShort`] when `transport`'s idle timeout is not
    /// longer than [`KEEPER_SETTLE`] — the module's *A quiet pair* note says why —
    /// and [`ManagerError::KeepAliveNotBelowIdle`] when its keep-alive is not
    /// shorter than its idle timeout, so it could never fire. Both read this
    /// machine's transport only; each variant says what that leaves out.
    pub fn new(
        me: &Identity,
        store: RecordStore,
        beacon: Option<Beacon>,
        runtime: Arc<dyn Runtime>,
        transport: &Transport,
    ) -> Result<Self, ManagerError> {
        if transport.idle_timeout <= KEEPER_SETTLE {
            return Err(ManagerError::IdleTimeoutTooShort {
                idle_timeout: transport.idle_timeout,
            });
        }
        if let Some(keep_alive) = transport.keep_alive
            && keep_alive >= transport.idle_timeout
        {
            return Err(ManagerError::KeepAliveNotBelowIdle {
                keep_alive,
                idle_timeout: transport.idle_timeout,
            });
        }
        Ok(Self {
            me: me.peer_id(),
            store,
            beacon,
            runtime,
            pairs: Mutex::new(BTreeMap::new()),
        })
    }

    /// The live connection to `peer`, if there is one.
    ///
    /// A connection that has closed — an idle timeout, a link loss, the peer
    /// closing it — is not reported. Its entry is replaced or dropped by the next
    /// adoption for that peer, so a peer this machine never dials again keeps a dead
    /// handle (and the quinn state behind it) until the manager is dropped.
    #[must_use]
    pub fn live(&self, peer: &PeerId) -> Option<Connection> {
        self.current(peer).map(|(connection, _)| connection)
    }

    /// Who started the live connection to `peer`, if there is one.
    ///
    /// A closed connection is not one; see [`Self::live`] for what happens to its
    /// entry.
    #[must_use]
    pub fn started_by(&self, peer: &PeerId) -> Option<Started> {
        self.current(peer).map(|(_, started_by)| started_by)
    }

    /// The pair's live connection and its starter, or `None` when the recorded
    /// connection has closed. The rule is [`Self::live`]'s.
    fn current(&self, peer: &PeerId) -> Option<(Connection, Started)> {
        let pairs = self.pairs();
        let live = pairs.get(peer)?;
        if live.connection.close_reason().is_some() {
            return None;
        }
        Some((live.connection.clone(), live.started_by))
    }

    /// Connect to `peer` with no fresh address to try first.
    ///
    /// Equivalent to [`Self::connect_with`] with no hint; the order and the adoption
    /// rule are stated there and in the module docs.
    pub async fn connect(
        &self,
        endpoint: &Endpoint,
        peer: &Fingerprint,
    ) -> Result<Connection, ConnectFailure> {
        self.connect_with(endpoint, peer, None).await
    }

    /// Connect to `peer`, trying `hint` first.
    ///
    /// The order after the hint is the module's. `hint` is an address the peer sent
    /// in an introduction — its own, as the beacon observed it — and it is
    /// self-asserted: the handshake still proves the key. It is the carrier for "a
    /// fresh address for that peer arriving in an introduction".
    ///
    /// A connection the handshake proves is the peer's is adopted under the
    /// tie-break and returned — which may be a different connection than the one
    /// this call made, if the peer's own dial won, and which a concurrent accept may
    /// replace a moment later. When this call's own dial loses the tie-break, the
    /// answer is the connection the pair kept: the caller asked to reach the peer, and
    /// the peer is reached. Only when the tie-break drops the dial and the pair holds
    /// nothing does this report [`ConnectFailure::NoDirectPath`], with the tie-break's
    /// cause. The handle is a connection, not a promise: the pair's live one is
    /// [`Self::live`]. The address this call dialed is not written to the record; see
    /// [`crate::peer::PeerRecord::last_address`].
    pub async fn connect_with(
        &self,
        endpoint: &Endpoint,
        peer: &Fingerprint,
        hint: Option<SocketAddr>,
    ) -> Result<Connection, ConnectFailure> {
        match self.attempt(endpoint, peer, hint).await {
            Attempt::Kept { connection, .. } => Ok(connection),
            Attempt::Dropped { address, cause } => {
                // A dial the tie-break dropped is not a failed dial when the pair is
                // connected: that connection is the answer.
                if let Some(connection) = self.live(&peer.peer_id()) {
                    return Ok(connection);
                }
                Err(ConnectFailure::NoDirectPath {
                    peer: *peer,
                    address,
                    cause: cause.to_owned(),
                })
            }
            Attempt::Failed(failure) => Err(failure),
        }
    }

    /// One attempt to reach `peer`, in the module's order, before it is folded into
    /// the four failures.
    async fn attempt(
        &self,
        endpoint: &Endpoint,
        peer: &Fingerprint,
        hint: Option<SocketAddr>,
    ) -> Attempt {
        let peer_id = peer.peer_id();
        if !self.store.trusts(&peer_id) {
            let cause = if self.store.is_closed(&peer_id) {
                NotTrustedCause::Closed
            } else {
                NotTrustedCause::NoRecord
            };
            return Attempt::Failed(ConnectFailure::NotTrusted { peer: *peer, cause });
        }
        let remembered = self
            .store
            .get(&peer_id)
            .and_then(|record| record.last_address());
        let mut addresses = Vec::with_capacity(2);
        if let Some(hint) = hint {
            addresses.push(hint);
        }
        if let Some(remembered) = remembered
            && Some(remembered) != hint
        {
            addresses.push(remembered);
        }
        let mut tried = Vec::new();
        for address in addresses {
            match self.dial(endpoint, address, peer).await {
                Ok(connection) => return self.here(peer, address, connection),
                Err(cause) => tried.push((address, cause)),
            }
        }
        let Some(beacon) = &self.beacon else {
            return Attempt::Failed(ConnectFailure::BeaconUnreachable {
                peer: *peer,
                cause: cause(&tried, "no beacon is configured"),
            });
        };
        let session = match beacon.connect().await {
            Ok(session) => session,
            Err(error) => {
                return Attempt::Failed(ConnectFailure::BeaconUnreachable {
                    peer: *peer,
                    cause: cause(&tried, &format!("the beacon: {error}")),
                });
            }
        };
        let address = match session.lookup(&peer_id).await {
            Ok(Some(address)) => address,
            Ok(None) => {
                return Attempt::Failed(ConnectFailure::PeerUnknown {
                    peer: *peer,
                    cause: cause(&tried, "the peer is not registered"),
                });
            }
            Err(error) => {
                return Attempt::Failed(ConnectFailure::BeaconUnreachable {
                    peer: *peer,
                    cause: cause(&tried, &format!("the beacon: {error}")),
                });
            }
        };
        match self.dial(endpoint, address, peer).await {
            Ok(connection) => self.here(peer, address, connection),
            Err(error) => Attempt::Failed(ConnectFailure::NoDirectPath {
                peer: *peer,
                address,
                cause: error.to_string(),
            }),
        }
    }

    /// Adopt this machine's own dial.
    ///
    /// A handshake that completed but whose connection the tie-break dropped is
    /// [`Attempt::Dropped`], not a dial failure: the address answered, and the
    /// keeper treats it as a dial that carried nothing rather than giving up.
    fn here(&self, peer: &Fingerprint, address: SocketAddr, connection: Connection) -> Attempt {
        match self.adopt(peer.peer_id(), connection, Started::Here) {
            Ok((connection, kept_this)) => Attempt::Kept {
                connection,
                kept_this,
            },
            Err(cause) => Attempt::Dropped { address, cause },
        }
    }

    /// Take one incoming connection.
    ///
    /// The handshake already proved the peer's key against the endpoint's policy;
    /// this checks the record again, applies the tie-break, and records the address
    /// the kept connection came from. Every failure here ends its own connection: a
    /// refused stranger and a handshake that timed out are ordinary events on a
    /// public address, and the loop moves on.
    async fn accept(&self, incoming: Incoming) {
        let Some(Ok(connection)) = timeout(&*self.runtime, DEFAULT_CONNECT_BUDGET, async move {
            incoming.await
        })
        .await
        else {
            return;
        };
        let Some(presented) = presented(&connection) else {
            connection.close(0u32.into(), b"the handshake proved no key");
            return;
        };
        let peer = presented.peer_id();
        if !self.store.trusts(&peer) {
            let reason: &[u8] = if self.store.is_closed(&peer) {
                b"the pair is closed on this machine until a person clears it"
            } else {
                b"not a paired peer"
            };
            connection.close(0u32.into(), reason);
            return;
        }
        // The tie-break runs before the address write: the write is a hint that
        // saves a beacon trip, and delaying the adoption by it would let the keeper
        // see the pair empty while the peer's own connection was still being taken.
        // Only a connection the tie-break keeps teaches an address. When it keeps the
        // one the pair already held, that connection may be this machine's own
        // outbound one, whose remote address is the address this machine dialled —
        // never a fact the record may hold.
        if let Ok((kept, kept_this)) = self.adopt(peer, connection, Started::There)
            && kept_this
        {
            self.note_address(&peer, kept.remote_address());
        }
    }

    /// Serve incoming connections on `endpoint` until it closes.
    ///
    /// This is the accept loop, and the caller runs it: the crate has no runtime of
    /// its own to spawn on, so the caller keeps the handle and decides when the loop
    /// stops — closing the endpoint is what ends it, because quinn's `accept` answers
    /// nothing else. Run [`ACCEPT_LANES`] copies, so one peer that opens a
    /// connection and stalls cannot block every other peer for the whole connect
    /// budget. The manager holds one live connection per pair; an incoming one that
    /// loses the tie-break is closed here.
    ///
    /// Accepting writes the peer's authenticated source address when it changed — a
    /// small blocking file operation — so run the loop on a task that may block; the
    /// module's *Accepting* note says why.
    pub async fn serve(self: Arc<Self>, endpoint: Endpoint) {
        while let Some(incoming) = endpoint.accept().await {
            self.accept(incoming).await;
        }
    }

    /// Keep the pair with `peer` connected until an attempt fails with the pair
    /// holding no connection, or a run of dials carries nothing.
    ///
    /// The manager owns recovery: the caller runs this once per paired peer and does
    /// not dial. It waits on the pair's connection, so a quiet pair costs nothing and
    /// a pair that stays up is never re-dialled; when the connection is gone it dials
    /// again in [`Self::connect`]'s order.
    ///
    /// A connection that carried anything — a QUIC datagram or stream frame either
    /// way — and then died is a link failure: the keeper re-dials it however many
    /// times it happens and however long it lived, with no bound, because that is
    /// recovery and not a loop. A connection that outlives [`KEEPER_SETTLE`] is
    /// settled the same way: the pair got to use it, so its loss is ordinary churn and
    /// clears the count.
    ///
    /// Only a dial whose connection ends before the pair carried anything and inside
    /// [`KEEPER_SETTLE`] is bounded: [`KEEPER_UNSTABLE_LIMIT`] of those in a row stop
    /// the keeper with [`Keeper::Unstable`], whose cause says what ended the last one,
    /// so a peer that takes a connection and drops it is not re-dialled for ever. A
    /// dial that fails outright stops it at once with [`Keeper::Failed`] — unless the
    /// accept lane connected meanwhile, because a pair that is connected now is never
    /// stopped: before giving up, for whatever reason, the keeper asks whether the
    /// pair is connected.
    pub async fn keep_connected(&self, endpoint: &Endpoint, peer: &Fingerprint) -> Keeper {
        let peer_id = peer.peer_id();
        let mut strikes = 0u8;
        loop {
            // A connected pair is never stopped and never dialled over: watch it.
            if let Some(live) = self.live(&peer_id) {
                strikes = 0;
                live.closed().await;
                continue;
            }
            let (counted, cause) = match self.attempt(endpoint, peer, None).await {
                Attempt::Kept {
                    connection,
                    kept_this,
                } => {
                    // A dial that lost the tie-break to a connection the pair already
                    // holds carried nothing; the pair is connected and is watched
                    // next time round.
                    if !kept_this {
                        strikes = 0;
                        continue;
                    }
                    match timeout(&*self.runtime, KEEPER_SETTLE, connection.closed()).await {
                        // The peer kept it past the window: settled.
                        None => {
                            strikes = 0;
                            continue;
                        }
                        // A connection that carried anything is a link failure, however
                        // briefly it lived.
                        Some(error) => (!carried(&connection), close_cause(&error)),
                    }
                }
                Attempt::Dropped { cause, .. } => (true, cause.to_owned()),
                Attempt::Failed(failure) => {
                    // The accept lane may have connected while this dial failed: a
                    // connected pair is never stopped.
                    if self.live(&peer_id).is_some() {
                        strikes = 0;
                        continue;
                    }
                    return Keeper::Failed(failure);
                }
            };
            if !counted || self.live(&peer_id).is_some() {
                // This dial produced nothing the pair had not already got, or the
                // pair is connected now.
                strikes = 0;
                continue;
            }
            strikes = strikes.saturating_add(1);
            if strikes >= KEEPER_UNSTABLE_LIMIT {
                // Ask once more, as late as possible: an adoption that landed while
                // the strike was booked must not be reported as giving up on the pair.
                if self.live(&peer_id).is_some() {
                    strikes = 0;
                    continue;
                }
                return Keeper::Unstable { peer: *peer, cause };
            }
        }
    }

    /// Remember the peer's authenticated source address.
    ///
    /// Best effort on purpose: the address is a hint that saves a beacon trip, not
    /// identity — the key is checked on every handshake — so a record that cannot be
    /// written is a hint lost, not a connection refused. Only an accept calls this;
    /// the write, and the task it runs on, are the module's "Accepting" note.
    fn note_address(&self, peer: &PeerId, address: SocketAddr) {
        let _ = self.store.record_address(peer, address);
    }

    /// Dial one address and prove the handshake is the peer this machine asked
    /// for.
    async fn dial(
        &self,
        endpoint: &Endpoint,
        address: SocketAddr,
        peer: &Fingerprint,
    ) -> Result<Connection, DialError> {
        let connecting = endpoint
            .connect(address, SERVER_NAME)
            .map_err(|error| DialError::Dial(error.to_string()))?;
        let connection = match timeout(&*self.runtime, DEFAULT_CONNECT_BUDGET, connecting).await {
            Some(Ok(connection)) => connection,
            Some(Err(error)) => return Err(DialError::Handshake(error.to_string())),
            None => return Err(DialError::TimedOut),
        };
        let presented = presented(&connection).ok_or(DialError::NoIdentity)?;
        if presented != *peer {
            connection.close(0u32.into(), b"not the peer this machine asked for");
            return Err(DialError::WrongPeer {
                expected: *peer,
                presented,
            });
        }
        Ok(connection)
    }

    /// Keep one connection for the pair, by the rule the module states.
    ///
    /// The answer is the pair's connection and `kept_this`: whether the connection
    /// this call passed in is the one kept.
    fn adopt(
        &self,
        peer: PeerId,
        connection: Connection,
        started_by: Started,
    ) -> Result<(Connection, bool), &'static str> {
        let preferred = if self.me < peer {
            Started::Here
        } else {
            Started::There
        };
        let mut pairs = self.pairs();
        let Some(existing) = pairs.remove(&peer) else {
            pairs.insert(
                peer,
                Live {
                    connection: connection.clone(),
                    started_by,
                },
            );
            return Ok((connection, true));
        };
        let keep_new = if existing.connection.close_reason().is_some() {
            true
        } else if started_by != existing.started_by {
            started_by == preferred
        } else if let Some(keep_new) = keep_new_of_same_starter(&connection, &existing.connection) {
            keep_new
        } else {
            existing
                .connection
                .close(0u32.into(), TIE_BREAK_CAUSE.as_bytes());
            connection.close(0u32.into(), TIE_BREAK_CAUSE.as_bytes());
            return Err(TIE_BREAK_CAUSE);
        };
        let (kept, dropped) = if keep_new {
            (
                Live {
                    connection,
                    started_by,
                },
                existing.connection,
            )
        } else {
            (existing, connection)
        };
        dropped.close(0u32.into(), SUPERSEDED_CAUSE.as_bytes());
        if kept.connection.close_reason().is_some() {
            return Err(ADOPTION_LOST_CAUSE);
        }
        pairs.insert(
            peer,
            Live {
                connection: kept.connection.clone(),
                started_by: kept.started_by,
            },
        );
        Ok((kept.connection, keep_new))
    }

    fn pairs(&self) -> MutexGuard<'_, BTreeMap<PeerId, Live>> {
        self.pairs
            .lock()
            .expect("the connection map is not poisoned")
    }
}

/// The fingerprint a completed handshake proved, if it proved one.
fn presented(connection: &Connection) -> Option<Fingerprint> {
    let identity = connection.peer_identity()?;
    let certificates = identity.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    Fingerprint::from_spki(certificates.first()?.as_ref())
}

/// Whether a connection carried anything: one QUIC datagram or stream frame either
/// way.
///
/// Keep-alives, handshake frames and acknowledgements are not traffic, so they do
/// not turn a peer that drops a fresh connection into a link failure.
fn carried(connection: &Connection) -> bool {
    let stats = connection.stats();
    stats.frame_tx.datagram > 0
        || stats.frame_rx.datagram > 0
        || stats.frame_tx.stream > 0
        || stats.frame_rx.stream > 0
}

/// What ended a connection, in words a person reads.
///
/// The class is not a decision — the keeper counts any connection that ended before
/// it carried anything and inside [`KEEPER_SETTLE`] — it is the detail that explains
/// why the keeper stopped.
fn close_cause(error: &ConnectionError) -> String {
    match error {
        ConnectionError::ApplicationClosed(_) | ConnectionError::ConnectionClosed(_) => {
            "the peer closed it".to_owned()
        }
        ConnectionError::TimedOut => "it timed out".to_owned(),
        ConnectionError::Reset => "the peer reset it".to_owned(),
        ConnectionError::TransportError(error) => format!("the link failed: {error}"),
        ConnectionError::LocallyClosed => "this machine closed it".to_owned(),
        ConnectionError::VersionMismatch => {
            "the peer speaks no version this machine does".to_owned()
        }
        ConnectionError::CidsExhausted => "no connection id could be allocated".to_owned(),
    }
}

/// Whether `new` should replace `old` when both were started by the same machine.
///
/// Both endpoints derive the same exporter bytes for one connection, so the
/// connection with the smaller value is a choice both sides compute identically —
/// unlike "the newer one", which each side may have adopted first. `None` is the
/// value that cannot be computed, which [`Connections::adopt`] turns into keeping
/// neither.
fn keep_new_of_same_starter(new: &Connection, old: &Connection) -> Option<bool> {
    let value = |connection: &Connection| {
        let mut out = [0u8; 32];
        connection
            .export_keying_material(&mut out, TIE_BREAK_LABEL, b"")
            .ok()
            .map(|()| out)
    };
    Some(value(new)? < value(old)?)
}

/// What a failed same-starter tie-break closes both connections with.
const TIE_BREAK_CAUSE: &str = "the pair's tie-break could not be computed";

/// What the tie-break closes a connection it does not keep with.
const SUPERSEDED_CAUSE: &str = "superseded by the pair's tie-break";

/// Why a dial that completed a handshake did not become the pair's connection: the
/// connection it kept had already closed.
const ADOPTION_LOST_CAUSE: &str = "the connection closed before the pair adopted it";

/// The cause of a failed beacon leg, naming the addresses tried before it.
///
/// The four failures are classes; this is the detail a reader acts on, so a
/// remembered address that did not answer is named rather than folded away.
fn cause(tried: &[(SocketAddr, DialError)], detail: &str) -> String {
    if tried.is_empty() {
        return detail.to_owned();
    }
    let mut text = String::new();
    for (address, error) in tried {
        let _ = write!(text, "the address {address} did not answer ({error}); ");
    }
    text.push_str(detail);
    text
}

/// Why the pair could not be connected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectFailure {
    /// The beacon leg failed: no beacon is configured, the beacon did not answer,
    /// or it refused the lookup. `cause` names which, and the remembered addresses
    /// that did not answer before it, because the four failures are classes and the
    /// cause is the detail a reader acts on.
    BeaconUnreachable { peer: Fingerprint, cause: String },
    /// The beacon has no address for the peer: it is not registered. `cause` names
    /// the addresses tried before the beacon, because the remembered dial's detail
    /// is what a reader acts on.
    PeerUnknown { peer: Fingerprint, cause: String },
    /// The peer's address is known and no connection could be made — or a dial's
    /// handshake completed but the tie-break dropped it while the pair held nothing.
    /// `cause` is diagnostic: the text may have been written by the far side, or name
    /// the tie-break that dropped the dial.
    NoDirectPath {
        peer: Fingerprint,
        address: SocketAddr,
        cause: String,
    },
    /// This machine does not trust the peer. Decided locally and only locally;
    /// `cause` says which of the two local states it is.
    NotTrusted {
        peer: Fingerprint,
        cause: NotTrustedCause,
    },
}

/// Why this machine does not trust a peer: no record at all, or a pair its person
/// closed after repeated failed comparisons.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotTrustedCause {
    /// No record says a person paired this machine with the peer.
    NoRecord,
    /// The pair is closed on this machine until a person clears it.
    Closed,
}

/// Why a connection manager could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagerError {
    /// The transport's idle timeout is not longer than [`KEEPER_SETTLE`]; the
    /// module's *A quiet pair* note says why that is refused. Raise the timeout above
    /// the window.
    ///
    /// The check reads this machine's transport only: QUIC's effective idle timeout
    /// is the smaller of the two machines', so a peer built with a shorter one can
    /// still close a quiet connection inside this machine's window.
    IdleTimeoutTooShort { idle_timeout: Duration },
    /// The transport's keep-alive is not shorter than its idle timeout, so it could
    /// never fire: a quiet connection would time out before a ping kept it alive.
    ///
    /// The check reads this machine's transport only: the keep-alive must also be
    /// shorter than the peer's idle timeout, so one that is short enough here can
    /// still be too long for the pair.
    KeepAliveNotBelowIdle {
        keep_alive: Duration,
        idle_timeout: Duration,
    },
}

/// What both refusals say about their reach: they read this machine's transport,
/// while over the wire the effective timeout is the smaller of the two machines'.
const LOCAL_TRANSPORT_ONLY: &str = concat!(
    "; the check reads this machine's transport only, while over the wire the ",
    "effective timeout is the smaller of the two machines'",
);

impl fmt::Display for ManagerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdleTimeoutTooShort { idle_timeout } => write!(
                f,
                "the transport's idle timeout {idle_timeout:?} is not longer than the \
                 {KEEPER_SETTLE:?} window the keeper judges a fresh connection by\
                 {LOCAL_TRANSPORT_ONLY}"
            ),
            Self::KeepAliveNotBelowIdle {
                keep_alive,
                idle_timeout,
            } => write!(
                f,
                "the transport's keep-alive {keep_alive:?} is not shorter than its idle \
                 timeout {idle_timeout:?}, so it could never fire{LOCAL_TRANSPORT_ONLY}"
            ),
        }
    }
}

impl std::error::Error for ManagerError {}

/// Why a keeper stopped.
///
/// Either way the keeper is finished: this machine's next start or a person starts
/// it again. A fresh address for the peer does not start a keeper; it is handed to
/// [`Connections::connect_with`], which makes one dial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Keeper {
    /// An attempt failed with one of the four failures while the pair held no
    /// connection. Not necessarily a dial: "not trusted" is decided before an address
    /// is chosen.
    Failed(ConnectFailure),
    /// The run of dials that carried nothing reached [`KEEPER_UNSTABLE_LIMIT`], so
    /// the keeper stopped instead of handshaking in a loop. `cause` says what ended
    /// the last connection, or which tie-break dropped it.
    Unstable { peer: Fingerprint, cause: String },
}

impl fmt::Display for Keeper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Failed(failure) => write!(f, "this machine stopped trying: {failure}"),
            Self::Unstable { peer, cause } => write!(
                f,
                "this machine stopped trying {peer} after {KEEPER_UNSTABLE_LIMIT} dials in a row \
                 produced a connection that ended before the pair carried anything ({cause})"
            ),
        }
    }
}

impl std::error::Error for Keeper {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Failed(failure) => Some(failure),
            Self::Unstable { .. } => None,
        }
    }
}

impl fmt::Display for ConnectFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BeaconUnreachable { peer, cause } => {
                write!(
                    f,
                    "the beacon is not available, so {peer} cannot be looked up: {cause}"
                )
            }
            Self::PeerUnknown { peer, cause } => {
                write!(f, "the beacon does not know {peer}: {cause}")
            }
            Self::NoDirectPath {
                peer,
                address,
                cause,
            } => write!(f, "no direct path to {peer} at {address}: {cause}"),
            Self::NotTrusted { peer, cause } => match cause {
                NotTrustedCause::NoRecord => write!(
                    f,
                    "{peer} is not trusted: no record says a person paired this machine with it"
                ),
                NotTrustedCause::Closed => write!(
                    f,
                    "{peer} is not trusted: the pair is closed on this machine until a person clears it"
                ),
            },
        }
    }
}

impl std::error::Error for ConnectFailure {}

/// Why one dial failed. Never reported outward as-is: [`Connections::connect`]
/// folds it into one of the three failures a dial can decide — a dial is never
/// `NotTrusted`, which is decided before an address is chosen.
#[derive(Clone, Debug)]
enum DialError {
    Dial(String),
    Handshake(String),
    TimedOut,
    NoIdentity,
    WrongPeer {
        expected: Fingerprint,
        presented: Fingerprint,
    },
}

impl fmt::Display for DialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dial(error) => write!(f, "cannot dial: {error}"),
            Self::Handshake(error) => write!(f, "handshake: {error}"),
            Self::TimedOut => f.write_str("no handshake within the connect budget"),
            Self::NoIdentity => f.write_str("the handshake proved no key"),
            Self::WrongPeer {
                expected,
                presented,
            } => write!(
                f,
                "the address presented {presented}, not the peer asked for ({expected})"
            ),
        }
    }
}
