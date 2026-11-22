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
//! # The connection level travels with the connection
//!
//! Every kept connection runs one small exchange after it is adopted: each side sends
//! the binding it holds for the other — a [`crate::peer::access::Fact`], or nothing —
//! and keeps what it is sent as a claim. It is the manager's own handshake, not the
//! pair's traffic: a connection that only exchanged its binding and then died carried
//! nothing, which is why the keeper measures the exchange's frames and does not count
//! them. The exchange never delays adoption, never fails a connection and never closes
//! one; a peer that does not answer costs its own budget and is tried again on the
//! next connection.
//!
//! A machine whose trust was withdrawn is not one to keep: the keeper closes what is
//! live and stops with [`NotTrustedCause::Withdrawn`], and the handshake refuses the
//! key before the manager sees it. A binding changed while the connection is up is a
//! reconnection — [`Connections::disconnect`] is how a caller makes it one — and the
//! next connection carries the new fact.
//!
//! # Whose record the manager reads
//!
//! Every reach — a dial, an accepted connection, a keeper's round — asks the record on
//! disk, not the copy this process loaded. The store is a handle, and a product holds
//! more than one over one root: the manager one, the rights layer another, a restart a
//! third. A withdrawal written through any of them, or by the other process the
//! self-update window keeps on this root, is therefore seen before the next dial,
//! before the next handshake and — within one keeper round — while a connection is up,
//! and the manager closes it. The round is [`TRUST_POLL`] while a connection is
//! watched and [`KEEPER_SETTLE`] while a fresh dial is still being judged, so the bound
//! is the larger of the two. Nothing here depends on the caller reloading, and nothing
//! depends on the manager and the rights layer sharing a handle.
//!
//! The price is one small read per round per peer: a record is at most
//! [`crate::peer::record::MAX_RECORD_BYTES`], usually under a kilobyte, and a keeper
//! round is seconds apart.
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
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use quinn::{Connection, ConnectionError, Endpoint, Incoming, Runtime};
use rustls::pki_types::CertificateDer;

use crate::beacon::{Beacon, timeout};
use crate::identity::{Fingerprint, Identity, PeerId};
use crate::net::{SERVER_NAME, Transport};
use crate::peer::binding;
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

/// How often a keeper re-reads the pair's trust while a connection is up.
///
/// A live connection is watched by waiting on it, and a withdrawal leaves no trace on
/// the wire: it is a file. So the wait is cut into rounds of this length, and each
/// round asks the record again. Five seconds is short enough that a withdrawn machine
/// stops being reachable promptly and long enough that a quiet pair costs one small
/// file read per peer per round. It is public because a caller deciding how soon a
/// withdrawal must take effect needs the bound — the larger of this and
/// [`KEEPER_SETTLE`], which is the round while a fresh dial is still being judged.
pub const TRUST_POLL: Duration = Duration::from_secs(5);

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

/// One live connection, who started it, and what the keeper judges its use by.
struct Live {
    connection: Connection,
    started_by: Started,
    /// Made once per connection and shared with every handle on it: two handles are the
    /// same connection exactly when they share this cell, so nothing has to compare an id
    /// that a dropped connection's address can hand out again.
    watch: Arc<Watch>,
}

/// What the keeper reads to tell the pair's use from the manager's own exchange.
///
/// The frame counters at adoption, and the frames written since then that belong to
/// the binding exchange — the manager's handshake and not the pair's use: a connection
/// that only exchanged its binding and then died carried nothing. The message layer
/// adds its own measurement: a round is an offer in flight, `quiet` is where the
/// frames stood when the last one finished, and `taken` is a message the peer took.
#[derive(Debug)]
struct Watch {
    carried_from: Frames,
    /// The frames the exchange wrote, once it has finished; `None` while it is still
    /// in flight.
    exchanged: Mutex<Option<Frames>>,
    /// How many messages this connection has taken from this machine.
    taken: AtomicU64,
    /// The frames up to the end of the last message round; `None` before one ran.
    quiet: Mutex<Option<Frames>>,
    /// How many message rounds are in flight now.
    rounds: AtomicU32,
}

impl Live {
    /// Adopt `connection`, taking the frame counters the keeper judges it from now.
    fn new(connection: Connection, started_by: Started) -> Self {
        Self {
            watch: Arc::new(Watch {
                carried_from: Frames::of(&connection),
                exchanged: Mutex::new(None),
                taken: AtomicU64::new(0),
                quiet: Mutex::new(None),
                rounds: AtomicU32::new(0),
            }),
            connection,
            started_by,
        }
    }
}

impl Watch {
    /// Whether the binding exchange has finished on this connection.
    fn exchange_done(&self) -> bool {
        self.exchanged
            .lock()
            .expect("the exchange count is not poisoned")
            .is_some()
    }
}

/// The four QUIC frame counters the keeper's "carried anything" test reads.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Frames {
    datagrams_out: u64,
    datagrams_in: u64,
    streams_out: u64,
    streams_in: u64,
}

impl Frames {
    /// The counters as they stand on `connection`.
    fn of(connection: &Connection) -> Self {
        let stats = connection.stats();
        Self {
            datagrams_out: stats.frame_tx.datagram,
            datagrams_in: stats.frame_rx.datagram,
            streams_out: stats.frame_tx.stream,
            streams_in: stats.frame_rx.stream,
        }
    }

    /// What `later` added to `self`, saturating rather than wrapping.
    fn delta(self, later: Self) -> Self {
        Self {
            datagrams_out: later.datagrams_out.saturating_sub(self.datagrams_out),
            datagrams_in: later.datagrams_in.saturating_sub(self.datagrams_in),
            streams_out: later.streams_out.saturating_sub(self.streams_out),
            streams_in: later.streams_in.saturating_sub(self.streams_in),
        }
    }

    /// Whether the connection carried anything the pair used: a datagram or stream
    /// frame either way beyond `from`, less the stream frames `quiet` names.
    fn beyond(self, from: Self, quiet: Self) -> bool {
        self.datagrams_out > from.datagrams_out
            || self.datagrams_in > from.datagrams_in
            || self.streams_out > from.streams_out.saturating_add(quiet.streams_out)
            || self.streams_in > from.streams_in.saturating_add(quiet.streams_in)
    }
}

/// One pair's live connection, as the message layer offers over it.
///
/// Cheap to clone: the connection is a handle and the watch is shared with the keeper, so
/// what the message layer reports — a round begun or ended, a message taken — is what the
/// keeper judges the connection by. An offer in flight and an offer that finished are not
/// the pair's traffic; a message the peer took always is.
#[derive(Clone)]
pub struct Traffic {
    connection: Connection,
    watch: Arc<Watch>,
}

impl fmt::Debug for Traffic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Traffic")
            .field("connection", &self.connection.stable_id())
            .field("exchange_done", &self.exchange_done())
            .field("taken", &self.watch.taken.load(Ordering::SeqCst))
            .field("rounds", &self.watch.rounds.load(Ordering::SeqCst))
            .finish_non_exhaustive()
    }
}

impl Traffic {
    /// The live connection to offer over.
    ///
    /// The connection is the manager's own: [`Connections::connect`] hands the same one to
    /// a caller that asks, so this exposes nothing a caller could not reach. A stream a
    /// caller opens on it before [`Self::exchange_done`] is taken for the binding
    /// exchange's by the far side, so a caller that speaks its own frames waits for the
    /// exchange to finish first.
    #[must_use]
    pub const fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Whether `self` and `other` are the same live connection.
    ///
    /// A connection's own id is not what decides this: it is the address of the connection
    /// object, and a connection dropped by the manager can be replaced by a new one at the
    /// same address. The watch is made once per connection, shared by every handle on it and
    /// dropped with the last one, so sharing it is what "the same connection" means.
    #[must_use]
    pub(crate) fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.watch, &other.watch)
    }

    /// Whether the binding exchange has finished on this connection.
    ///
    /// The exchange owns the first stream a kept connection carries, so a message is
    /// never offered before it: a receiver would take the exchange's stream for an
    /// offer.
    #[must_use]
    pub fn exchange_done(&self) -> bool {
        self.watch.exchange_done()
    }

    /// Mark one offer as started, until the guard is dropped.
    ///
    /// Until then the connection is not judged by its frames: an offer in flight is this
    /// machine's own act, not evidence the pair is alive. A guard rather than a paired call,
    /// because a round abandoned mid-offer — a service dropped, a task cancelled — must not
    /// leave the connection looking like one that carries nothing for the rest of its life.
    pub(crate) fn round(&self) -> Round<'_> {
        self.watch.rounds.fetch_add(1, Ordering::SeqCst);
        Round { traffic: self }
    }

    /// Record that the peer took a message over this connection.
    ///
    /// A taken message is the pair's use however the frames are counted, so it is
    /// remembered separately from them.
    pub(crate) fn took(&self) {
        self.watch.taken.fetch_add(1, Ordering::SeqCst);
    }

    /// Mark the offer as finished, keeping where the frames stood when it ended.
    ///
    /// The measurement is taken from the connection's adoption, so it already contains
    /// the binding exchange's frames and nothing has to be added to it.
    fn end_round(&self) {
        *self
            .watch
            .quiet
            .lock()
            .expect("the message round is not poisoned") =
            Some(self.watch.carried_from.delta(Frames::of(&self.connection)));
        self.watch.rounds.fetch_sub(1, Ordering::SeqCst);
    }
}

/// One offer in flight, ended when it is dropped however the round ends.
pub(crate) struct Round<'a> {
    traffic: &'a Traffic,
}

impl Drop for Round<'_> {
    fn drop(&mut self) {
        self.traffic.end_round();
    }
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
        watch: Arc<Watch>,
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

/// The pair's live connection, or `None` when the pair has none or the recorded one has
/// closed.
fn open<'a>(pairs: &'a BTreeMap<PeerId, Live>, peer: &PeerId) -> Option<&'a Live> {
    let live = pairs.get(peer)?;
    live.connection.close_reason().is_none().then_some(live)
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
    /// Build the manager for `me`, trusting what `store`'s root records, over the
    /// transport the endpoint will be built from.
    ///
    /// The endpoint the caller passes to [`Self::connect`] and runs
    /// [`Self::serve`] over must be built from this same `transport`: the keeper
    /// judges connections by a window the endpoint's own transport was never checked
    /// against, and quinn exposes no way to read an endpoint's transport back, so this
    /// is a contract the caller keeps, not something the manager can check. Which
    /// handle of the root either side holds does not matter — every reach asks the
    /// record on disk; see the module docs.
    ///
    /// The endpoint's [`crate::tls::PeerPolicy`] should be this store, or one over the
    /// same root: the handshake asks the record file, so a withdrawal refuses the next
    /// handshake. That read takes the store's write guard for the length of one small
    /// file read, so a handshake can wait behind a record publish's `fsync`, and a
    /// refused accept costs the same one read. Both are the crate's ordinary blocking
    /// file work; see the module's *Accepting* note.
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

    /// The pair's live connection as the message layer offers over it, or `None` when
    /// the pair has no live connection.
    ///
    /// A closed connection is not one; see [`Self::live`]. The handle shares the
    /// manager's own measurement of the connection, so what the message layer reports
    /// back — a round begun or ended, a message taken — is what the keeper judges the
    /// connection by.
    #[must_use]
    pub fn traffic(&self, peer: &PeerId) -> Option<Traffic> {
        let pairs = self.pairs();
        let live = open(&pairs, peer)?;
        Some(Traffic {
            connection: live.connection.clone(),
            watch: live.watch.clone(),
        })
    }

    /// Whether `traffic` is the pair's live connection now.
    ///
    /// A receiver task belongs to one connection: when the manager replaces it — a
    /// reconnection, a tie-break, a withdrawal — the task's connection is no longer the
    /// pair's, and the task stops instead of reading a connection nobody keeps. The
    /// comparison is [`Traffic::same`]'s, so one rule decides what "the pair's connection"
    /// means for both the manager and the layer above it.
    #[must_use]
    pub(crate) fn is_live(&self, peer: &PeerId, traffic: &Traffic) -> bool {
        let pairs = self.pairs();
        open(&pairs, peer).is_some_and(|live| Arc::ptr_eq(&live.watch, &traffic.watch))
    }

    /// The pair's live connection and its starter, or `None` when the recorded
    /// connection has closed. The rule is [`Self::live`]'s.
    fn current(&self, peer: &PeerId) -> Option<(Connection, Started)> {
        let pairs = self.pairs();
        let live = open(&pairs, peer)?;
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
        if let Err(cause) = self.standing_now(&peer_id) {
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
            Ok((connection, kept_this, watch)) => {
                if kept_this {
                    self.start_exchange(peer.peer_id(), &connection, &watch, Started::Here);
                }
                Attempt::Kept {
                    connection,
                    kept_this,
                    watch,
                }
            }
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
        if let Err(cause) = self.standing_now(&peer) {
            connection.close(0u32.into(), refusal_text(&cause));
            return;
        }
        // The tie-break runs before the address write: the write is a hint that
        // saves a beacon trip, and delaying the adoption by it would let the keeper
        // see the pair empty while the peer's own connection was still being taken.
        // Only a connection the tie-break keeps teaches an address. When it keeps the
        // one the pair already held, that connection may be this machine's own
        // outbound one, whose remote address is the address this machine dialled —
        // never a fact the record may hold.
        if let Ok((kept, kept_this, watch)) = self.adopt(peer, connection, Started::There)
            && kept_this
        {
            self.note_address(&peer, kept.remote_address());
            self.start_exchange(peer, &kept, &watch, Started::There);
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
    /// not dial. A pair that stays up is never re-dialled: the keeper watches the
    /// connection in rounds of [`TRUST_POLL`], asking the record each round whether
    /// this machine still trusts the peer, and dials again in [`Self::connect`]'s order
    /// once the connection is gone.
    ///
    /// A connection that carried anything — a QUIC datagram or stream frame either
    /// way, beyond the manager's own binding exchange and the message layer's own
    /// rounds — and then died is a link failure: the keeper re-dials it however many
    /// times it happens and however long it lived, with no bound, because that is
    /// recovery and not a loop. A connection that only exchanged its binding and then
    /// died carried nothing, because the exchange is the manager's handshake and not
    /// the pair's use: the frames it wrote are measured and subtracted, and a connection
    /// that dies before that measurement lands is judged as carrying nothing too. That
    /// window is the whole [`crate::peer::EXCHANGE_BUDGET`], so a pair's own traffic
    /// inside it is discounted with the exchange's — the price of a bound the keeper can
    /// keep without a second handshake. A connection that outlives [`KEEPER_SETTLE`] is
    /// settled the same way: the pair got to use it, so its loss is ordinary churn and
    /// clears the count.
    ///
    /// The message layer's offers are measured with the exchange: an offer in flight,
    /// and an offer that finished, are not the pair's traffic, so a peer that keeps
    /// dropping a connection after one unanswered offer is not mistaken for a live pair.
    /// A message the peer took is: it is the peer acting, so the connection carried
    /// something and its loss is a link failure.
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
            // A pair whose trust is withdrawn is not one to keep: close what is live
            // and stop, naming the withdrawal rather than a lost path. The record is
            // read from disk, so a withdrawal written through another handle — or by
            // the other process on this root — stops the keeper too.
            if let Err(cause) = self.standing_now(&peer_id) {
                if let Some(live) = self.live(&peer_id) {
                    live.close(0u32.into(), refusal_text(&cause));
                }
                return Keeper::Failed(ConnectFailure::NotTrusted { peer: *peer, cause });
            }
            // A connected pair is never stopped and never dialled over: watch it, and
            // come back to the record each round, because a withdrawal is a file and
            // leaves no trace on the wire.
            if let Some(live) = self.live(&peer_id) {
                strikes = 0;
                let _ = timeout(&*self.runtime, TRUST_POLL, live.closed()).await;
                continue;
            }
            let (counted, cause) = match self.attempt(endpoint, peer, None).await {
                Attempt::Kept {
                    connection,
                    kept_this,
                    watch,
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
                        Some(error) => (!carried(&connection, &watch), close_cause(&error)),
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

    /// Whether this machine trusts `peer` now, and why not, from one read of the
    /// record on disk.
    ///
    /// The one place the manager's reaches ask the question, so a dial, an accepted
    /// connection and a keeper's round cannot disagree about it. It reads the file once:
    /// a reach that trusts the peer and one that refuses it both cost one small read.
    /// A record that cannot be read is not trusted, and it says so with the read's own
    /// refusal: the manager fails closed, and the cause points a person at the record
    /// rather than at a pairing that was never made.
    fn standing_now(&self, peer: &PeerId) -> Result<(), NotTrustedCause> {
        let limits = self.store.limits();
        let record = match self.store.reread(peer) {
            Ok(record) => record,
            Err(error) => {
                return Err(NotTrustedCause::Unreadable {
                    detail: error.to_string(),
                });
            }
        };
        match record {
            Some(record) if record.trusted(&limits) => Ok(()),
            Some(record) if record.is_withdrawn() => Err(NotTrustedCause::Withdrawn),
            Some(record) if record.is_closed(&limits) => Err(NotTrustedCause::Closed),
            _ => Err(NotTrustedCause::NoRecord),
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

    /// Run this machine's half of the binding exchange on a kept connection, on its
    /// own task.
    ///
    /// The exchange is the manager's handshake, not the pair's traffic: it never
    /// delays adoption, never fails a connection and never closes one. What it writes
    /// is measured and kept in the connection's [`Watch`], so a connection that only
    /// exchanged its binding and then died is judged as one that carried nothing. The
    /// measurement starts from the frames the connection had when it was adopted — the
    /// exchange's own stream is opened at that moment — so nothing the exchange writes
    /// is counted as the pair's. The local fact is read from the store this manager
    /// holds, which the reach that adopted the connection has just re-read from disk: a
    /// binding written before the connection is what travels. A binding changed while
    /// the connection is up is a reconnection, and [`Self::disconnect`] is how the
    /// caller makes it one.
    fn start_exchange(
        &self,
        peer: PeerId,
        connection: &Connection,
        watch: &Arc<Watch>,
        started: Started,
    ) {
        let local = self
            .store
            .get(&peer)
            .and_then(|record| record.binding().map(|binding| binding.fact().clone()));
        let connection = connection.clone();
        let from = watch.carried_from;
        let store = self.store.clone();
        let runtime = Arc::clone(&self.runtime);
        let watch = Arc::clone(watch);
        let spawned = Arc::clone(&runtime);
        runtime.spawn(Box::pin(async move {
            let fact = binding::exchange(&connection, local, started, &*spawned).await;
            if let Some(fact) = fact {
                let _ = store.record_claim(&peer, &fact);
            }
            // Marked after the claim is kept: the message layer offers once this is set,
            // and a message offered before the claim landed would find no pair to name.
            let written = from.delta(Frames::of(&connection));
            *watch
                .exchanged
                .lock()
                .expect("the exchange count is not poisoned") = Some(written);
        }));
    }

    /// Close the pair's live connection so the keeper dials again.
    ///
    /// A binding changed while a connection is up takes effect at the next one — the
    /// plan's reconnection, not a new acquaintance — and a withdrawn trust closes what
    /// is live as well as refusing what comes next. Answers whether there was a live
    /// connection to close.
    pub fn disconnect(&self, peer: &PeerId) -> bool {
        let mut pairs = self.pairs();
        match pairs.remove(peer) {
            Some(live) => {
                live.connection
                    .close(0u32.into(), RECONNECT_CAUSE.as_bytes());
                true
            }
            None => false,
        }
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
    ) -> Result<(Connection, bool, Arc<Watch>), &'static str> {
        let preferred = if self.me < peer {
            Started::Here
        } else {
            Started::There
        };
        let mut pairs = self.pairs();
        let Some(existing) = pairs.remove(&peer) else {
            let live = Live::new(connection, started_by);
            let answer = (live.connection.clone(), true, live.watch.clone());
            pairs.insert(peer, live);
            return Ok(answer);
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
            (Live::new(connection, started_by), existing)
        } else {
            (existing, Live::new(connection, started_by))
        };
        dropped
            .connection
            .close(0u32.into(), SUPERSEDED_CAUSE.as_bytes());
        if kept.connection.close_reason().is_some() {
            return Err(ADOPTION_LOST_CAUSE);
        }
        let answer = (kept.connection.clone(), keep_new, kept.watch.clone());
        pairs.insert(peer, kept);
        Ok(answer)
    }

    fn pairs(&self) -> MutexGuard<'_, BTreeMap<PeerId, Live>> {
        self.pairs
            .lock()
            .expect("the connection map is not poisoned")
    }
}

/// The fingerprint a completed handshake proved, if it proved one.
pub(crate) fn presented(connection: &Connection) -> Option<Fingerprint> {
    let identity = connection.peer_identity()?;
    let certificates = identity.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    Fingerprint::from_spki(certificates.first()?.as_ref())
}

/// Whether a connection carried anything the pair used: one QUIC datagram or stream
/// frame either way, beyond what the connection had when it was adopted, less the
/// stream frames the binding exchange wrote and those of the last message round.
///
/// Keep-alives, handshake frames and acknowledgements are not traffic, so they do
/// not turn a peer that drops a fresh connection into a link failure. Neither is the
/// manager's own binding exchange: it is the manager's handshake, and a connection
/// that only exchanged its binding and then died carried nothing. The exchange is
/// measured as it runs; a connection that died before the measurement landed is
/// judged as one that carried nothing, which bounds the keeper instead of letting it
/// re-dial. That window is the exchange's whole budget, [`crate::peer::EXCHANGE_BUDGET`],
/// and not only the handshake: traffic the pair sends inside it is discounted too,
/// which is the price of the bound.
///
/// The message layer is measured the same way and for the same reason: an offer in
/// flight is this machine's own act, and an offer that finished is measured back to
/// where the frames stood when the round ended, so neither counts as the pair's use.
/// A message the peer took is different — the peer acted on it, which is the pair
/// being alive — so it counts however the frames are read. The receiving half is not
/// measured at all: a stream the peer opened is the peer acting, and answering it is
/// the pair being used, so only this machine's own rounds are discounted.
fn carried(connection: &Connection, watch: &Watch) -> bool {
    if watch.taken.load(Ordering::SeqCst) > 0 {
        return true;
    }
    if watch.rounds.load(Ordering::SeqCst) > 0 {
        return false;
    }
    let quiet = *watch
        .quiet
        .lock()
        .expect("the message round is not poisoned");
    let exchanged = *watch
        .exchanged
        .lock()
        .expect("the exchange count is not poisoned");
    quiet
        .or(exchanged)
        .is_some_and(|quiet| Frames::of(connection).beyond(watch.carried_from, quiet))
}

/// What a connection is closed with when the record does not vouch for the pair.
///
/// One text per cause, and the same text wherever the manager closes: an accepted
/// connection and a live one the keeper stops both say why they are closed. The texts
/// are generic because they travel to the peer — which file, and which fault, is this
/// machine's business and is in the [`NotTrustedCause`] the caller is given.
fn refusal_text(cause: &NotTrustedCause) -> &'static [u8] {
    match cause {
        NotTrustedCause::Withdrawn => NOT_TRUSTED_CAUSE.as_bytes(),
        NotTrustedCause::Closed => b"the pair is closed on this machine until a person clears it",
        NotTrustedCause::NoRecord => b"not a paired peer",
        NotTrustedCause::Unreadable { .. } => b"the pair's record cannot be read on this machine",
    }
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

/// What [`Connections::disconnect`] closes the pair's connection with: the connection
/// level changed, and the next connection carries it.
const RECONNECT_CAUSE: &str = "the pair is reconnecting";

/// What a connection is closed with when a person withdrew this machine's trust in the
/// pair.
const NOT_TRUSTED_CAUSE: &str = "this machine's trust in the pair is withdrawn";

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
    /// `cause` names the local state it is.
    NotTrusted {
        peer: Fingerprint,
        cause: NotTrustedCause,
    },
}

/// Why this machine does not trust a peer: no record at all, a pair its person closed
/// after repeated failed comparisons, a trust its person withdrew, or a record that is
/// there and cannot be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NotTrustedCause {
    /// No record says a person paired this machine with the peer.
    NoRecord,
    /// The pair is closed on this machine until a person clears it.
    Closed,
    /// A person withdrew this machine's trust in the peer; a person must restore it.
    Withdrawn,
    /// The peer's record is there and could not be read: unreadable, reachable by
    /// another account, or not a record this build can read. Distinct from
    /// [`Self::NoRecord`], because the file a person must look at is the one that is
    /// there and not a pairing that was never made. `detail` is the record's own
    /// refusal, which names the file and, where one command repairs it, the command.
    Unreadable { detail: String },
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
                NotTrustedCause::Withdrawn => write!(
                    f,
                    "{peer} is not trusted: a person withdrew this machine's trust in it"
                ),
                NotTrustedCause::Unreadable { detail } => write!(
                    f,
                    "{peer} is not trusted: its record cannot be read — {detail}"
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
