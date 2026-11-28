//! The per-machine connection manager: dialling, accepting, one connection per
//! pair, and the punch.
//!
//! # The order
//!
//! One dial — [`Connections::connect`] — tries, in this order:
//!
//! 1. **The hint**, when the caller has one: an address the peer sent in an introduction, or
//!    one a product was handed. One dial of it, bounded by the same budget as any other.
//! 2. **Every address the record remembers** for the peer, newest first, all of them dialled at
//!    once. They are equally authenticated — each completed a handshake once — so waiting for
//!    four ten-second dials in turn would spend a budget on an order that says nothing. The order
//!    is only the order they are reported in.
//! 3. **The beacon**, and only when nothing above worked: the beacon is not consulted while an
//!    earlier address works, which is what keeps a working pair off it entirely.
//!
//! A dial that completes a handshake at any of these addresses is the pair's connection, and the
//! address is written to the record: a completed authenticated handshake is authenticated data.
//! An address that arrived only as a claim — the caller's hint, a peer's candidate, the beacon's
//! observation — is never written on the strength of the claim alone.
//!
//! # A punch
//!
//! The third step is where two machines behind network address translation can meet, and it is
//! called a punch because that is what it is: both sides dial the other's *observed* address — the
//! one the beacon sees on the machine's own registration — at the same time, so the packet that
//! opens one side's mapping is the one the other side's filter admits.
//!
//! The connectivity check is the authenticated handshake itself. There is no STUN exchange, no
//! second socket, no second protocol and no separate check phase: a punch dials addresses with
//! exactly the code a remembered address is dialled with, and the handshake that proves the key
//! is the same handshake that proves the path. What a punch adds is only *which* addresses are
//! dialled and *when*.
//!
//! The set a punch dials is the beacon's observed address first, then the candidate list the peer
//! sent — filtered, deduplicated, and capped at [`crate::peer::MAX_CANDIDATES`]; which sources are
//! filtered is [`Connections::declares`]'s rule. The candidate list travels in the signed, opaque
//! introduction payload the beacon already relays, so the beacon gains no duty and no new frame:
//! it carries a candidate list as it carries a ceremony flight. It is signed and not encrypted, so
//! the beacon *can* read it — that exposure is named here rather than discovered, and it is the
//! price of not adding a protocol the beacon would have to learn. The whole punch fits inside
//! [`DIAL_BUDGET`]: one beacon session for the lookup and the introduction together, five seconds
//! of waiting for the peer's list, and five seconds for the candidate dials themselves. A list the
//! presence already holds is dialled at once unless it is older than `COORDINATION_FRESH`: a stale
//! list is worth nothing, and waiting one window for a fresh one is the same punch a moment later.
//!
//! One rule governs sending a candidate list: it is never sent to a peer while a ceremony with
//! that peer is running — the presence's `busy_with` — because an older build ends its ceremony on
//! any payload outside its closed set. A list is worth one dial later; a person's comparison is
//! not worth losing. A ceremony whose opening is still in flight is the one window this cannot
//! see: `busy_with` answers for what this machine already knows, and a payload that arrives before
//! the opening does can still end an older build's ceremony. The window is accepted and named in
//! `crate::peer::presence`'s note.
//!
//! # The outcome table
//!
//! Let a side be its mapping, its filtering and its pooling. A punch is both sides dialling each
//! other's beacon-observed address at the same time. A dial from A to B's observed address
//! completes iff B's mapping is endpoint-independent — so the address B registered is valid for
//! any source — **and** B's filtering admits A's mapping, where "admits" means:
//!
//! - endpoint-independent filtering: always;
//! - address-dependent filtering: A's mapping has the same IP address as A's observed address,
//!   which is true when A pools one external address across destinations;
//! - address-and-port-dependent filtering: A's mapping is exactly A's observed address, which is
//!   true only when A's mapping is endpoint-independent.
//!
//! The pair connects iff either direction completes. Each side's mapping therefore decides
//! whether the other side's dial can complete at all, its filtering decides what it admits from
//! the other side, and its pooling decides only what address-dependent filtering admits — so a
//! row names a filtering only on the side whose dial is being admitted, and says "any filtering"
//! where that side's filter never decides. "Destination-dependent mapping" is address-dependent
//! and address-and-port-dependent together: neither is the observed endpoint, and the model does
//! not distinguish them in any row. Every combination of mapping, filtering and pooling the model
//! can be configured with is in one of rows 1–11, and the shapes that are not a mapping and filtering
//! pair are rows 12–18:
//!
//! | # | A | B | outcome |
//! |---|---|---|---|
//! | 1 | endpoint-independent mapping + endpoint-independent filtering | the same | connects on the first dial |
//! | 2 | endpoint-independent mapping + endpoint-independent filtering | endpoint-independent mapping + address-dependent filtering | connects |
//! | 3 | endpoint-independent mapping + endpoint-independent filtering | endpoint-independent mapping + address-and-port-dependent filtering | connects |
//! | 4 | endpoint-independent mapping + address-dependent filtering | the same | connects |
//! | 5 | endpoint-independent mapping + address-dependent filtering | endpoint-independent mapping + address-and-port-dependent filtering | connects |
//! | 6 | endpoint-independent mapping + address-and-port-dependent filtering | the same | connects |
//! | 7 | destination-dependent mapping, any filtering, any pooling | endpoint-independent mapping + endpoint-independent filtering | connects (B's filter admits A) |
//! | 8 | destination-dependent mapping, any filtering, one shared external address | endpoint-independent mapping + address-dependent filtering | connects (A's mapping has the address B wrote to) |
//! | 9 | destination-dependent mapping, any filtering, a different external address per destination | endpoint-independent mapping + address-dependent filtering | does not connect (the address differs from the one B wrote to) |
//! | 10 | destination-dependent mapping, any filtering, any pooling | endpoint-independent mapping + address-and-port-dependent filtering | does not connect: A's mapping is not A's observed endpoint, so B's filter refuses it, and B's dial does not survive A's destination-scoped mapping |
//! | 11 | destination-dependent mapping, any filtering, any pooling | the same | does not connect (both observed addresses are destination-scoped) |
//! | 12 | two machines behind one network, the product declares both local addresses | | connects locally, with no hairpin |
//! | 13 | two machines behind one network, no declared address, hairpin translation on, endpoint-independent mapping and filtering | | connects through the hairpin |
//! | 14 | two machines behind one network, no declared address, no hairpin | | does not connect (the hairpin is what would have carried it) |
//! | 15 | one machine behind two networks in a row, endpoint-independent mapping and filtering at each, the other behind one | | connects |
//! | 16 | UDP blocked towards the peer only | | no direct path |
//! | 17 | UDP blocked entirely | | the beacon is unreachable |
//! | 18 | an address of another family (IPv6) | | carried and tried like any other, with no preference stated |
//!
//! Rows 1–6 hold whatever the pooling: an endpoint-independent mapping is the observed endpoint,
//! so all three filters admit it. The classes are named and not counted. Nothing in this crate
//! branches on them: the same dial runs whatever the pair is behind, and the table is what that
//! one dial does.
//!
//! # What is not attempted, and why
//!
//! - **Interface enumeration.** This crate is handed one socket, so it cannot enumerate the
//!   machine's interfaces portably — and a machine's local addresses are the product's knowledge,
//!   not the library's. The product hands them in with [`Connections::declares`], and they travel
//!   in the candidate list.
//! - **Port mapping.** Asking a router to forward a port is a second protocol and a third-party
//!   device, with no portable way to do it without a dependency this crate does not take.
//! - **NAT classification.** The check is the handshake, and the outcome table above shows the
//!   crate's behaviour does not branch on the class: a class would be a guess it cannot act on,
//!   and a guess that costs a probe of its own.
//!
//! # A withdrawn trust, and a changed binding
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
//! and the manager closes it. The round is at most [`TRUST_POLL`] — the settle window
//! only cuts it shorter — so that is the bound while a connection is up. Nothing here
//! depends on the caller reloading, and nothing depends on the manager and the rights
//! layer sharing a handle.
//!
//! # A quiet pair, and how long a vanished peer goes unnoticed
//!
//! A keep-alive on either machine holds a silent pair: QUIC's idle timeout is the
//! smaller of the two machines' and a ping resets it on both, so
//! [`Connections::new`] accepts a transport with no keep-alive at all, and a silent
//! pair then lives only while the peer keeps pinging. With both sides silent the
//! connection closes at the idle timeout and [`Connections::keep_connected`] dials it
//! again — recovery, not a failure of the pair.
//!
//! How long a vanished peer goes unnoticed is stated, and it is this machine's own
//! bound rather than an accident of the two machines' settings: with a keep-alive,
//! [`Connections::vanish_bound`] answers [`Vanish::Measured`] — this machine's liveness
//! bound, [`VANISH_BOUND`], or twice the keep-alive when that is longer, plus the two keeper
//! rounds that cover the manager's own liveness poll (`LIVENESS_POLL`) and the round that
//! acts on the silence — because this machine's own pings make a live peer answer and one
//! that has not answered for the bound is gone; without a keep-alive, or while the reader
//! cannot be heard from, it answers [`Vanish::Unmeasured`], whose bound is the transport's
//! idle timeout plus one keeper round — the two machines' negotiated timeout, which this
//! machine cannot tighten alone. The reading is a [`Vanish`] and not a bare duration so a
//! product can tell a bound that is kept from one that is not measured. Either way the loss is
//! the pair's recovery and not a failure counted against the peer: a connection that ends
//! because it timed out is a peer that went quiet, which is exactly what a NAT mapping expiring
//! or a laptop closing looks like, so it is re-dialled at once and never becomes a strike. That
//! is what keeps a peer built with a shorter idle timeout than this machine's from turning an
//! ordinary quiet drop into a refusal.
//!
//! The keeper still judges a fresh connection by its own window, [`KEEPER_SETTLE`]: a
//! connection the keeper dialled that ends inside that window having carried nothing,
//! and for any reason other than a timeout, is a strike against the peer. A transport
//! whose idle timeout is not longer than the window would turn each ordinary silent
//! drop into one, which is why [`Connections::new`] refuses it. The check reads this
//! machine's transport only; the timeout rule above is what makes a shorter one on the
//! peer harmless.
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
//! Liveness is read only to drop a connection that has already closed, and to keep a
//! connection that has stopped answering from outranking one that works: a connection
//! that has shown no sign of life for this machine's liveness bound — [`VANISH_BOUND`],
//! or twice the keep-alive when that is slower — is not a candidate beside a fresh one,
//! whatever the rule would otherwise say.
//!
//! That rule is about the peer going quiet, not about this machine's reading cadence, so
//! the manager samples the sign of life itself instead of letting whoever asks date the
//! peer's last datagram to the look: a reading taken only when a keeper or a caller looked
//! would call a connection that has been silent for longer than the bound fresh. One reader
//! of its own runs once a `LIVENESS_POLL` for the manager's whole life, and the manager keeps
//! the moment of its last pass. Finding it out costs no traffic of the crate's own — the
//! reader looks at the datagrams the peer has already sent, and a peer this machine is
//! pinging answers — so the test cannot reset the accounting it is judged by. A reader that
//! cannot be heard from — one that never started, or whose last pass is more than two polls
//! ago — has measured nothing, and [`Connections::vanish_bound`] says so: the reading is
//! [`Vanish::Unmeasured`], not merely a bound the code declines to apply.
//!
//! The choice between two live connections reads only the facts both sides share; when one
//! side has observed a close the other has not, the two may briefly name different
//! connections, and each closes the loser — the next dial re-establishes the pair.
//!
//! A collision needs no second recovery path. Both machines run the manager: when
//! the connection one side kept then dies, the machine whose dial lost re-dials, and
//! the machine that kept it dials again because its connection is gone. Whichever
//! dial wins, both keepers adopt the connection the rule keeps. A machine that runs the
//! peer layer without a keeper dials only when a caller asks and nothing retries for it;
//! [`Connections::recovery`] says so by answering [`Recovery::Unwatched`] for a pair
//! nothing has dialled.
//!
//! # Accepting
//!
//! [`Connections::serve`] is the accept loop, and the caller runs it: the crate has
//! no runtime of its own to spawn on, so the caller keeps the handle and decides
//! when the loop stops. The loop hands each incoming connection to a task of its own.
//! Accepting records the peer's authenticated source address — one small blocking
//! file read, and a write only when the address changed — on that task, not on the
//! loop: this crate has no blocking pool to hand it to, and that task is the one
//! place a blocking read costs nothing else. A dial writes the address it completed at
//! the same way, on the caller's own task; the rule for what may be written is one rule
//! for both, and it is [`crate::peer::PeerRecord::last_address`]'s.

use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use quinn::{Connection, ConnectionError, Endpoint, Incoming, Runtime};
use rustls::pki_types::CertificateDer;

use crate::beacon::{BEACON_REQUEST_TIMEOUT, Beacon, BeaconError, Session, sleep, timeout};
use crate::identity::{Fingerprint, Identity, PeerId};
use crate::net::{SERVER_NAME, Transport};
use crate::peer::binding;
use crate::peer::presence::Presence;
use crate::peer::record::{PeerRecord, RecordError, RecordStore, Untrusted};
use crate::peer::recovery::{ConnectFailure, NotTrustedCause, Recovery, StopCause, recheck};
use crate::peer::traverse::{self, Candidates, PUNCH_DIAL_BUDGET, PUNCH_REARM, PUNCH_WINDOW};

/// How long one dial or one handshake may take before it is reported as no path.
const DEFAULT_CONNECT_BUDGET: Duration = Duration::from_secs(10);

/// The longest one dial can take before it answers: the hint and then the remembered set — two
/// dials of their own — the beacon's own two exchanges, the wait for the peer's candidates, and
/// the candidate dials.
///
/// [`crate::peer::actions::ACTION_BUDGET`] holds this much back for the dial its record read waits
/// for, so a dial a slow read delayed can still run to its own end. Public as one of the stated
/// numbers a caller plans against, and as the product-facing bound on one dial: this is how long a
/// caller waits before an honest failure, and the punch fits inside it rather than extending it.
pub const DIAL_BUDGET: Duration = Duration::from_secs(
    (2 * DEFAULT_CONNECT_BUDGET.as_secs())
        + (2 * BEACON_REQUEST_TIMEOUT.as_secs())
        + PUNCH_WINDOW.as_secs()
        + PUNCH_DIAL_BUDGET.as_secs(),
);

// The bound is a promise a caller plans against, so it is checked rather than remembered: a stage
// added without re-arguing the sum fails the build here instead of quietly making every dial
// longer than the number its callers were given.
const _: () = assert!(DIAL_BUDGET.as_secs() == 60);

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

/// How long a connection may go without a sign of life from the peer before this
/// machine treats it as gone.
///
/// A sign of life is a datagram the peer has sent on the connection: with a keep-alive
/// this machine's own pings make a live peer answer, so a peer that has not answered for
/// this long is gone, whatever either machine advertised. It decides two things. A
/// connection that has shown no sign of life for this long does not outrank a fresh one
/// in the tie-break, so a connection that is merely not yet declared dead cannot keep a
/// working one out. And the keeper closes such a connection instead of waiting for the
/// transport's idle timeout, which is how [`Connections::vanish_bound`] can name a bound
/// that is this machine's rather than the two machines' negotiated one.
///
/// This is the floor, not the rule: a live quiet peer must not be declared gone between
/// two pings, so a keep-alive slower than half of this raises the bound to twice the
/// keep-alive — [`Connections::vanish_bound`] answers the one that applies. The default
/// keep-alive is ten seconds, which is exactly half, so the default bound is this one. It
/// is only applied when this machine has a keep-alive at all; without one nothing this
/// machine sends would make a silent peer answer, and the bound is the transport's idle
/// timeout instead.
pub const VANISH_BOUND: Duration = Duration::from_secs(20);

/// How many incoming connections may be in a handshake at once.
///
/// [`Connections::serve`] hands each incoming connection to a task of its own, so a
/// stalled handshake never blocks the next accept. This is the cap on how many of those
/// tasks may exist: a public address that is flooded with half-finished handshakes costs
/// at most this many, and the accept loop stops pulling from the endpoint until one
/// finishes.
///
/// It is not what throttles a punch: a punch dials at most [`crate::peer::MAX_CANDIDATES`]
/// connections at once, well under this cap, and the cap's argument is about strangers flooding
/// a public address rather than about a pair reaching itself.
pub const ACCEPT_IN_FLIGHT: usize = 64;

/// How often a keeper re-reads the pair's trust while a connection is up.
///
/// A live connection is watched by waiting on it, and a withdrawal leaves no trace on
/// the wire: it is a file. So the wait is cut into rounds of this length, and each
/// round asks the record again. Five seconds is short enough that a withdrawn machine
/// stops being reachable promptly and long enough that a quiet pair costs one small
/// file read per peer per round. It is public because a caller deciding how soon a
/// withdrawal must take effect needs the bound, and this is it: a round that watches a
/// connection is at most this long, because [`KEEPER_SETTLE`] only cuts it shorter. A
/// round that dials is the dial's own budget instead — nothing is up to withdraw.
pub const TRUST_POLL: Duration = Duration::from_secs(5);

/// How often the manager's own reader samples whether each live connection's peer is still
/// answering.
///
/// Shorter than a keeper round, which is what makes [`Connections::vanish_bound`]'s two rounds
/// cover it. Not public: a product cannot act on a sampling period, and `vanish_bound` states the
/// total it needs.
const LIVENESS_POLL: Duration = Duration::from_secs(1);

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
/// that only exchanged its binding and then died carried nothing.
#[derive(Debug)]
struct Watch {
    carried_from: Frames,
    /// When the manager adopted this connection: the moment [`KEEPER_SETTLE`] is measured
    /// from.
    adopted: Instant,
    /// The frames the exchange wrote, once it has finished; `None` while it is still
    /// in flight.
    exchanged: Mutex<Option<Frames>>,
    /// How many messages, actions or transfers this connection has carried an accepted
    /// answer for, or a byte of.
    taken: AtomicU64,
    /// The frames up to the end of the last offer, action or transfer round; `None` before
    /// one ran.
    quiet: Mutex<Option<Frames>>,
    /// How many offer, action or transfer rounds are in flight now.
    rounds: AtomicU32,
    /// The last sign of life the peer gave, sampled by the manager's own reader.
    life: Mutex<Life>,
    /// Whether the keeper has folded this connection's death into the pair's recovery. A
    /// connection is judged once, so its loss cannot be counted twice.
    judged: AtomicBool,
}

/// The manager's own liveness reader: whether it was started, and when it last looked.
struct Reader {
    started: bool,
    pass: Option<Instant>,
}

/// The peer's last sign of life on one connection.
///
/// A datagram the peer has sent is the signal: keep-alives are answered, so a live peer
/// answers this machine's pings, and a peer that has stopped answering sends nothing. Sampled
/// by the manager's own reader, so the answer is the same whoever asks; the module's note on
/// liveness says why it is sampled rather than read on demand.
#[derive(Clone, Copy, Debug)]
struct Life {
    /// The datagrams the peer had sent when `at` was taken.
    datagrams: u64,
    /// When the peer was last seen to have sent one.
    at: Instant,
}

impl Life {
    /// Take a reading: a datagram the peer has sent since the last one moves `at` forward.
    fn sample(&mut self, connection: &Connection, now: Instant) {
        let sent = connection.stats().udp_rx.datagrams;
        if sent > self.datagrams {
            self.datagrams = sent;
            self.at = now;
        }
    }

    /// Whether the peer has shown a sign of life within `bound`.
    ///
    /// True when the manager's reader cannot be heard from — `heard` is false — because a
    /// machine that cannot measure silence must not conclude silence: a reader that never ran
    /// would otherwise make every healthy connection read as vanished once the bound passed,
    /// and the pair would redial a working peer for ever, each loss counted as settled so the
    /// episode cap never bounded it. The transport's own timeout still ends a connection that
    /// is really gone.
    fn shows_life(&self, now: Instant, bound: Duration, heard: bool) -> bool {
        !heard || now.saturating_duration_since(self.at) < bound
    }
}

impl Live {
    /// Adopt `connection`, taking the frame counters the keeper judges it from now.
    fn new(connection: Connection, started_by: Started, now: Instant) -> Self {
        let datagrams = connection.stats().udp_rx.datagrams;
        Self {
            watch: Arc::new(Watch {
                carried_from: Frames::of(&connection),
                adopted: now,
                exchanged: Mutex::new(None),
                taken: AtomicU64::new(0),
                quiet: Mutex::new(None),
                rounds: AtomicU32::new(0),
                life: Mutex::new(Life { datagrams, at: now }),
                judged: AtomicBool::new(false),
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

/// One pair's live connection, as the message, action and transfer layers use it.
///
/// Cheap to clone: the connection is a handle and the watch is shared with the keeper, so
/// what the layers above report — a round begun or ended, a request accepted, a transfer that
/// moved a byte — is what the keeper judges the connection by. An offer, an action request or
/// a transfer attempt in flight and one that finished are not the pair's traffic; an accepted
/// answer always is.
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
    /// The exchange owns the first stream a kept connection carries, so a message or an
    /// action is never offered before it: a receiver would take the exchange's stream for a
    /// request.
    #[must_use]
    pub fn exchange_done(&self) -> bool {
        self.watch.exchange_done()
    }

    /// How many answers this connection has carried that the peer accepted: a message it took,
    /// an action it ran, ran with a result too large to carry, or answered as already
    /// executed, or a transfer that moved a byte.
    ///
    /// The keeper reads the same counter, beside the in-flight rounds, to tell a lost live pair
    /// from a dial that carried nothing. Hidden from the documented API: it exists for the
    /// workspace's own measurement of a connection.
    #[doc(hidden)]
    #[must_use]
    pub fn taken(&self) -> u64 {
        self.watch.taken.load(Ordering::SeqCst)
    }

    /// How many offers, action requests or transfer attempts are in flight on this connection
    /// now.
    ///
    /// Hidden for the reason [`Self::taken`] is.
    #[doc(hidden)]
    #[must_use]
    pub fn rounds(&self) -> u32 {
        self.watch.rounds.load(Ordering::SeqCst)
    }

    /// Mark one offer, action request or transfer attempt as started, until the guard is
    /// dropped.
    ///
    /// Until then the connection is not judged by its frames: a request in flight is this
    /// machine's own act, not evidence the pair is alive. A guard rather than a paired call,
    /// because a round abandoned mid-offer — a service dropped, a task cancelled — must not
    /// leave the connection looking like one that carries nothing for the rest of its life.
    pub(crate) fn round(&self) -> Round<'_> {
        self.watch.rounds.fetch_add(1, Ordering::SeqCst);
        Round { traffic: self }
    }

    /// Record that the peer accepted a message offer or an action request, or that a transfer
    /// moved a byte, over this connection.
    ///
    /// The layers agree on what counts: a message the peer took, or an action it ran, ran with
    /// a result too large to carry, or answered as already executed, or a transfer that moved
    /// at least one byte of the file. A message's repeat is not counted here because its take
    /// was; an action's repeat is, because its journal proves the receiver accepted the
    /// operation before; a transfer that was answered `Resume` and then moved nothing is not,
    /// because a resume is the receiver's answer and not its use. Every other answer —
    /// refused, not ready, slow down, memory full, not recorded, busy, unsupported,
    /// unreadable — means the peer took nothing, so a connection that drops after one is not
    /// counted as a link failure.
    pub(crate) fn took(&self) {
        self.watch.taken.fetch_add(1, Ordering::SeqCst);
    }

    /// Mark the round as finished, keeping where the frames stood when it ended.
    ///
    /// The measurement is taken from the connection's adoption, so it already contains
    /// the binding exchange's frames and nothing has to be added to it.
    fn end_round(&self) {
        *self
            .watch
            .quiet
            .lock()
            .expect("the offer round is not poisoned") =
            Some(self.watch.carried_from.delta(Frames::of(&self.connection)));
        self.watch.rounds.fetch_sub(1, Ordering::SeqCst);
    }
}

/// One offer, action request or transfer attempt in flight, ended when it is dropped however
/// the round ends.
pub(crate) struct Round<'a> {
    traffic: &'a Traffic,
}

impl Drop for Round<'_> {
    fn drop(&mut self) {
        self.traffic.end_round();
    }
}

/// The pair's live connection, or `None` when the pair has none or the recorded one has
/// closed.
fn open<'a>(pairs: &'a BTreeMap<PeerId, Live>, peer: &PeerId) -> Option<&'a Live> {
    let live = pairs.get(peer)?;
    live.connection.close_reason().is_none().then_some(live)
}

/// Where the beacon stage speaks: the machine's one registration, or a session the manager
/// opened for this dial because the machine keeps no presence.
///
/// One type for the two, so the stage above asks for a lookup and an introduction without caring
/// which it has. The difference that matters is stated where the leg is chosen: a presence's
/// request rides the registration and never dials a second session, so the beacon keeps one
/// registration per machine.
enum Leg<'a> {
    /// The presence's registration.
    Presence(&'a Presence),
    /// A session of the manager's own, opened for this dial.
    Session(Session),
}

impl Leg<'_> {
    /// Where `id` is, if the beacon has it registered.
    async fn lookup(&self, id: &PeerId) -> Result<Option<SocketAddr>, BeaconError> {
        match self {
            Self::Presence(presence) => presence.lookup(id).await,
            Self::Session(session) => session.lookup(id).await,
        }
    }

    /// Hand `payload` to `to`, signed by this machine's key.
    async fn introduce(&self, to: PeerId, payload: &[u8]) -> Result<(), BeaconError> {
        match self {
            Self::Presence(presence) => presence.introduce(to, payload).await,
            Self::Session(session) => session.introduce(to, payload).await,
        }
    }
}

/// What one read of the pair's record answers; see [`Connections::standing`].
// The record is carried whole so a caller that needs it does not read the file a second time.
// The answer lives for the length of one call, and 320 bytes on a stack that has just read a
// file is not a cost worth an allocation.
#[allow(clippy::large_enum_variant)]
pub(crate) enum RecordRead {
    /// A person paired the two and nothing has taken it away. The record itself, so a caller
    /// that needs it does not read the file a second time.
    Trusted(PeerRecord),
    /// The read failed in a way that may pass. Not a decision about the peer: the dial is
    /// deferred, and this is the fault in the record's own words.
    Deferred { detail: String },
    /// A record a person must look at, in the read's own words: it never becomes trust, and
    /// each layer answers it in its own vocabulary.
    Unreadable(RecordError),
    /// No record, or one this build must not trust.
    Refused(NotTrustedCause),
}

impl RecordRead {
    /// The record, when this read is trust.
    fn trusted(&self) -> Option<&PeerRecord> {
        match self {
            Self::Trusted(record) => Some(record),
            _ => None,
        }
    }

    /// The failure this read answers a dial with, or `None` when it is trust.
    fn refusal(&self, peer: Fingerprint) -> Option<ConnectFailure> {
        match self {
            Self::Trusted(_) => None,
            Self::Deferred { detail } => Some(ConnectFailure::Deferred {
                peer,
                detail: detail.clone(),
            }),
            Self::Unreadable(error) => Some(ConnectFailure::NotTrusted {
                peer,
                cause: unreadable(error),
            }),
            Self::Refused(cause) => Some(ConnectFailure::NotTrusted {
                peer,
                cause: cause.clone(),
            }),
        }
    }
}

/// The refusal a record this machine could not read is, in the read's own words.
fn unreadable(error: &RecordError) -> NotTrustedCause {
    NotTrustedCause::Unreadable {
        detail: error.to_string(),
    }
}

/// Wait `for_at_most`, and never longer than one keeper round.
///
/// A keeper looks again at least once a round whatever the policy's next moment is: an
/// inbound connection, a withdrawal and a wake all arrive without a timer. The wait is the
/// crate's one timer, and dropping the keeper ends it.
async fn pause(connections: &Connections, for_at_most: Duration) {
    sleep(&*connections.runtime, for_at_most.min(TRUST_POLL)).await;
}

/// How long this machine takes to notice that a peer has gone silent, and whether that bound is
/// one it can measure.
///
/// Non-exhaustive: a new reading is a new answer, and a consumer compiled against an earlier
/// version must still build.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vanish {
    /// The bound holds: this machine pings, and its own reader samples the peer's answers, so a
    /// connection that has shown no sign of life for `bound` is closed and re-dialled.
    Measured { bound: Duration },
    /// Nothing here measures the peer's silence, so nothing is judged vanished and a connection
    /// lives until the transport's own timeout ends it: `bound` is what that leaves. Either this
    /// machine has no keep-alive — nothing it sends would make a silent peer answer — or its own
    /// reader has not been heard from, and a machine that cannot measure silence must not
    /// conclude it.
    Unmeasured { bound: Duration },
}

impl Vanish {
    /// The bound itself, whichever of the two it is.
    #[must_use]
    pub const fn bound(self) -> Duration {
        match self {
            Self::Measured { bound } | Self::Unmeasured { bound } => bound,
        }
    }

    /// Whether this machine measures the peer's silence at all.
    #[must_use]
    pub const fn measured(self) -> bool {
        matches!(self, Self::Measured { .. })
    }
}

impl fmt::Display for Vanish {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Measured { bound } => write!(f, "a vanished peer is noticed within {bound:?}"),
            Self::Unmeasured { bound } => write!(
                f,
                "a vanished peer is noticed within {bound:?}, by the transport's own timeout: \
                 this machine does not measure the silence itself"
            ),
        }
    }
}

/// The connection manager of one machine.
///
/// The accept loop and one keeper per paired peer are futures the caller spawns and
/// decides when to drop; the machine's presence, when the caller keeps one, runs its own.
pub struct Connections {
    me: PeerId,
    store: RecordStore,
    beacon: Option<Beacon>,
    /// The machine's one presence, when the caller keeps one: the punch carries candidates both
    /// ways through it, and its registration is the session the beacon stage speaks on.
    presence: Option<Arc<Presence>>,
    /// Addresses the product declares this machine has; never read from anywhere else.
    declared: Arc<Mutex<Vec<SocketAddr>>>,
    runtime: Arc<dyn Runtime>,
    /// How this machine's transport bounds a silent connection; see
    /// [`Self::vanish_bound`].
    idle_timeout: Duration,
    keep_alive: Option<Duration>,
    /// The slow re-check this machine waits before dialling again, spread by its own key; see
    /// [`recheck`].
    recheck: Duration,
    pairs: Arc<Mutex<BTreeMap<PeerId, Live>>>,
    /// How each pair's recovery stands, and whether a dial is in flight for it.
    retry: Mutex<BTreeMap<PeerId, Watched>>,
    /// The manager's own liveness reader; see [`Self::start_liveness`] and
    /// [`Self::reader_heard`].
    reader: Arc<Mutex<Reader>>,
    /// How many incoming connections are in a handshake now; see [`ACCEPT_IN_FLIGHT`].
    in_flight: AtomicUsize,
}

impl fmt::Debug for Connections {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connections")
            .field("me", &self.me)
            .field("beacon", &self.beacon.is_some())
            .field("presence", &self.presence.is_some())
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
    /// longer than [`KEEPER_SETTLE`] — the module's *A quiet pair* note says why — and
    /// [`ManagerError::KeepAliveNotBelowIdle`] when its keep-alive is not shorter than
    /// its idle timeout, so it could never fire. Each check reads this machine's transport
    /// only; each variant says what that leaves out. A keep-alive slower than half of
    /// [`VANISH_BOUND`] is accepted and raises this machine's own liveness bound with it,
    /// which is what [`Self::vanish_bound`] then states.
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
            presence: None,
            declared: Arc::new(Mutex::new(Vec::new())),
            runtime,
            idle_timeout: transport.idle_timeout,
            keep_alive: transport.keep_alive,
            recheck: recheck(&me.peer_id()),
            pairs: Arc::new(Mutex::new(BTreeMap::new())),
            retry: Mutex::new(BTreeMap::new()),
            reader: Arc::new(Mutex::new(Reader {
                started: false,
                pass: None,
            })),
            in_flight: AtomicUsize::new(0),
        })
    }

    /// Hand this manager the machine's one presence, so the punch can carry candidates both
    /// ways: our payload is sent on the registration, and the peer's arrives through the one
    /// reader.
    ///
    /// A manager without a presence still sends its candidates and dials the beacon's address;
    /// it cannot receive the peer's, so its punch is one-sided. The presence and the beacon must
    /// be over the same endpoint and identity — one registration, one socket — because the
    /// address the beacon observes on the registration is the one the peer is told to dial.
    ///
    /// An [`Arc`] because a machine has one presence and more than one reader of it: a product
    /// that runs a ceremony and a manager over the same machine hands both the same
    /// registration, and the manager's `busy_with` is what keeps a candidate list away from a
    /// ceremony that is still comparing.
    #[must_use]
    pub fn with_presence(mut self, presence: Arc<Presence>) -> Self {
        self.presence = Some(presence);
        self
    }

    /// Declare addresses this machine has, beyond the socket's own: the product's knowledge of
    /// its own machine.
    ///
    /// They travel in the coordination payload, and they are the only way a private address a peer
    /// names may be dialled — the filter admits a private candidate only when this machine holds
    /// an address in the same block: the /8 of 10/8, the /12 of 172.16/12, the /16 of 192.168/16,
    /// the /10 of the carrier-shared 100.64/10, or the /7 of fc00::/7. This is the product's set
    /// and nothing else: the punch composes the endpoint's own local address after it when the
    /// list has room, so a declared set that fills [`crate::peer::MAX_CANDIDATES`] leaves the
    /// socket's own address out, and an unspecified one is never sent.
    ///
    /// Candidates that arrive from the network are filtered; the caller's hint and the beacon's
    /// own observed address are not. The hint is the product's knowledge of its own machine, and a
    /// product may legitimately redial a private or local address; the beacon's answer is the
    /// beacon's observation of where the peer appears, not a claim the peer made about itself. A
    /// global address a paired peer names is still dialled, which is an accepted cost bounded by
    /// the ceiling and the re-arm interval.
    ///
    /// Each call states the whole set: a later call replaces what an earlier one declared,
    /// repeats are dropped, and the list is cut at [`crate::peer::MAX_CANDIDATES`]. Nothing here
    /// reads the machine's interfaces: which addresses it has is the product's fact.
    pub fn declares(&self, addresses: impl IntoIterator<Item = SocketAddr>) {
        // The ceiling and the deduplication are [`Candidates`]'s, so a declared set is bounded by
        // the same rule as the set a punch dials.
        let declared = Candidates::new(
            addresses
                .into_iter()
                .filter(|address| !address.ip().is_unspecified()),
        );
        *self
            .declared
            .lock()
            .expect("the declared addresses are not poisoned") = declared.addresses().to_vec();
    }

    /// The addresses the product declared this machine has, as they were handed in.
    ///
    /// These travel in the coordination payload beside the endpoint's own local address, and
    /// they are what opens the filter's private-address gate: the socket's own address is not a
    /// declaration and opens nothing.
    fn declared(&self) -> Vec<SocketAddr> {
        self.declared
            .lock()
            .expect("the declared addresses are not poisoned")
            .clone()
    }

    /// How long this machine takes to notice that a peer has gone silent, and whether it can
    /// measure that at all.
    ///
    /// A stated bound in this machine's own terms rather than the two machines' negotiated
    /// idle timeout. With a keep-alive, this machine's own pings make a live peer answer, so a
    /// peer that has not answered for the liveness bound is gone — that is [`VANISH_BOUND`], or
    /// twice the keep-alive when that is longer, so a slower keep-alive never declares a live
    /// quiet peer gone between two pings — and the keeper closes it and dials again. That
    /// answer adds two keeper rounds: one for the liveness reader's own poll, which is shorter
    /// than a round, and one for the round that acts on the silence. It holds whatever the peer
    /// advertised.
    ///
    /// It is [`Vanish::Measured`] only while the manager's own reader can be heard from. A
    /// reader that never started, or whose last pass is more than two polls ago, has measured
    /// nothing, and nothing is then judged vanished: the connection lives until the transport's
    /// own timeout ends it rather than every healthy connection being closed and re-dialled once
    /// the bound passes. That is [`Vanish::Unmeasured`], the transport's idle timeout plus the
    /// one keeper round it takes to see the close. Without a keep-alive it is unmeasured too:
    /// nothing this machine sends would make a silent peer answer, and that one this machine
    /// cannot tighten alone, because over the wire the effective timeout is the smaller of the
    /// two machines'.
    ///
    /// Either way the loss is a redial and not a failure counted against the pair: a
    /// connection that ended because it timed out is a peer that went quiet.
    #[must_use]
    pub fn vanish_bound(&self) -> Vanish {
        match self.vanished_after() {
            Some(bound) if self.reader_heard(self.runtime.now()) => Vanish::Measured {
                bound: bound + 2 * TRUST_POLL,
            },
            _ => Vanish::Unmeasured {
                bound: self.idle_timeout + TRUST_POLL,
            },
        }
    }

    /// Whether the manager's own reader has been heard from: its last pass is at most two polls
    /// old. A reader that cannot be heard from has measured nothing.
    fn reader_heard(&self, now: Instant) -> bool {
        self.reader
            .lock()
            .expect("the reader state is not poisoned")
            .pass
            .is_some_and(|pass| {
                now.saturating_duration_since(pass) <= LIVENESS_POLL.saturating_mul(2)
            })
    }

    /// How long a connection may go without a sign of life from the peer before this machine
    /// treats it as gone, if a keep-alive makes that readable at all.
    ///
    /// [`VANISH_BOUND`], or twice the keep-alive when that is longer: a live quiet peer
    /// answers a ping within one keep-alive, and must not be declared gone between two.
    fn vanished_after(&self) -> Option<Duration> {
        self.keep_alive
            .map(|keep_alive| VANISH_BOUND.max(keep_alive.saturating_mul(2)))
    }

    /// Whether `connection` has shown no sign of life for longer than this machine's liveness
    /// bound; see [`Self::vanished_after`]. Always false without a keep-alive: nothing this
    /// machine sends would make a silent peer answer.
    fn vanished(&self, watch: &Watch, now: Instant) -> bool {
        self.vanished_after().is_some_and(|bound| {
            !watch
                .life
                .lock()
                .expect("the life count is not poisoned")
                .shows_life(now, bound, self.reader_heard(now))
        })
    }

    /// How this machine's recovery of `peer` stands, readable at any time.
    ///
    /// [`Recovery::Connected`] when the pair has a live connection, [`Recovery::Unwatched`]
    /// when nothing has happened for it, and otherwise what the retry policy is doing:
    /// dialling, waiting until a stated moment, or stopped with the reason. It is not durable
    /// and not an audit entry; see [`crate::peer::recovery`].
    ///
    /// Reading it also folds in a dial whose caller went away before anybody judged it — a
    /// service that stopped, a cancelled keeper — so the answer is never a stale "dialling"
    /// that nothing would dial out of. What it cannot say is who makes the next dial of a wait:
    /// [`Self::watched`] is that answer, and it is a separate one because a pair a keeper
    /// watches and one nobody watches are waiting for the same moment.
    #[must_use]
    pub fn recovery(&self, peer: &PeerId) -> Recovery {
        if self.live(peer).is_some() {
            return Recovery::Connected;
        }
        self.settle_stale(peer);
        self.policy(peer)
    }

    /// Whether a keeper is running for `peer` now.
    ///
    /// A pair a keeper watches is dialled again by itself at the moment its
    /// [`Recovery::Waiting`] or [`Recovery::Exhausted`] names; a pair nobody watches is
    /// dialled only by a caller that asks — [`Self::ensure`], which is how a waiting message
    /// and a requested action do. A stopped pair reads [`Recovery::Stopped`] either way, and a
    /// keeper dropped mid-dial leaves the episode where it was: what it was doing is still
    /// true, only nothing will do it next.
    #[must_use]
    pub fn watched(&self, peer: &PeerId) -> bool {
        self.retry()
            .get(peer)
            .is_some_and(|watched| watched.keepers > 0)
    }

    /// What the retry policy says about `peer`, with the live connection not in front of it.
    ///
    /// [`Self::recovery`] answers [`Recovery::Connected`] for a pair that has one; this is
    /// what the policy itself would say, which is what a caller about to dial needs. A dial in
    /// flight is the pair dialling, whoever took it: the state can move on from
    /// [`Recovery::Dialling`] while a dial runs — a dead connection judged under it — and
    /// answering the state instead would send the next caller round again for a dial that is
    /// already running.
    fn policy(&self, peer: &PeerId) -> Recovery {
        match self.retry().get(peer) {
            Some(watched) => watched.report(),
            None => Recovery::Unwatched,
        }
    }

    /// Take this round's answer to "has [`Self::ensure`] anything to do now?": a dial that is
    /// due, or a stop whose cause is due to be asked about again — at most once a round, so a
    /// queue's poll does not cost a record read a second.
    ///
    /// It is named for the taking rather than for the question because it stamps the round it
    /// answers: a second call inside the same round is told nothing is due while a stop's cause
    /// is still being re-asked.
    fn take_due(&self, peer: &PeerId, now: Instant) -> bool {
        let mut retry = self.retry();
        let Some(watched) = retry.get_mut(peer) else {
            return true;
        };
        let state = watched.report();
        state.due(now) || (matches!(state, Recovery::Stopped { .. }) && watched.stop_due(now))
    }

    /// A reason to start over arrived for `peer`: a fresh address for it, or a person asking
    /// again. A fresh episode starts now.
    ///
    /// Public because a person asking again is news the product has and the crate cannot
    /// observe: this is how a product hands in a "try now", and it is the same reason a hint
    /// carrying a fresh address is news.
    ///
    /// A stopped pair is not woken; [`Self::ensure`] re-opens a stop whose cause has gone, and
    /// this call makes it ask at once rather than after the round it would otherwise have
    /// waited. A connected, dialling or unwatched pair is left alone. A standing reason, like a
    /// message waiting, is not news and is handed in without resetting the episode, so a peer
    /// that keeps dropping a connection cannot have the queue re-arm it.
    pub fn wake(&self, peer: &PeerId) {
        // A dial nobody finished is settled first: a reason to start over cannot be weighed
        // against a state that is only still "dialling" because its caller went away.
        self.settle_stale(peer);
        let now = self.runtime.now();
        let mut retry = self.retry();
        let watched = retry.entry(*peer).or_insert_with(Watched::unwatched);
        // A person's act is news, so a stop's cause is asked about at once rather than after
        // the round a queue's poll would otherwise have waited for.
        watched.checked = None;
        watched.state.wake(now);
    }

    /// Something wants `peer` up now — a message waiting to be delivered, or a transfer
    /// waiting for the pair — and the next dial is made due at once, keeping the episode.
    ///
    /// This is the reason a queued message may cause a dial without becoming a dial per
    /// second: it moves one wait, it does not reset the count, so a peer that keeps accepting
    /// a connection and dropping it is still bounded by the episode. The crate's own queue and
    /// the crate's own transfer layer are its only callers; a coordination payload's re-arm is
    /// the same transition, reached through [`Self::rearm`], which bounds it to one per
    /// [`PUNCH_REARM`] and refuses a used-up episode — that guard lives there and not here,
    /// because this method moves a used-up episode's next check as it moves any other wait. A
    /// caller with a genuinely new reason to start over — a fresh address — calls [`Self::wake`],
    /// and one that only wants to dial calls [`Self::ensure`], which is paced the same way.
    pub(crate) fn hurry(&self, peer: &PeerId) {
        self.settle_stale(peer);
        let now = self.runtime.now();
        self.transition(*peer, |state| state.hurry(now));
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

    /// The pair's live connection as the message, action and transfer layers use it, or `None`
    /// when the pair has no live connection.
    ///
    /// A closed connection is not one; see [`Self::live`]. The handle shares the
    /// manager's own measurement of the connection, so what the layers above report back —
    /// a round begun or ended, a request accepted — is what the keeper judges the
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

    /// The last connection the manager adopted for `peer`, with the cell the keeper judges
    /// it by, whether or not it has closed.
    ///
    /// A closed connection is not the pair's connection — [`Self::live`] is — but it is
    /// still the one the keeper has to judge: a dial whose connection died before the
    /// keeper looked must not escape the settle window.
    fn judgeable(&self, peer: &PeerId) -> Option<(Connection, Arc<Watch>)> {
        let pairs = self.pairs();
        let live = pairs.get(peer)?;
        Some((live.connection.clone(), Arc::clone(&live.watch)))
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
    /// `hint` is an address the peer sent in an introduction — its own, as the beacon observed
    /// it — and it is self-asserted: the handshake still proves the key. It is the carrier for "a
    /// fresh address for that peer", which is one of the reasons a fresh episode starts, so a
    /// hinted call hands it in through [`Self::wake`] before it dials. It is not proof that the
    /// address works — an introduction may be stale — so a pair that stopped because it had
    /// nowhere to dial is re-opened by the dial that reaches the peer, not by the hint. A call
    /// with no hint adds no reason of its own to the policy — only a hint starts a fresh
    /// episode — but it still reads the record, and a read that fails this instant is folded in as
    /// the deferral it is, which moves the next dial to the deferral's own moment. The answer is
    /// then the state's own reason, so a fault never stands in for what the last dial met; a state
    /// that names nothing — a dial already in flight, or a pair already connected — answers the
    /// fault itself, because the dial this call asked for is what could not proceed.
    ///
    /// A dial that reaches the peer is folded in as the pair's next dial, so a pair a keeper runs
    /// for does not keep a stale wait or a used-up episode across a connection that works. A dial
    /// that fails folds nothing — it is not a dial the policy made — with one exception: a pair
    /// that came up while this dial was trying is folded in as this dial, the wrong key included,
    /// because the policy must not keep a wait across a connection that works. A refusal or a
    /// deferral folds nothing even then: the connection arrived some other way, and a stop this
    /// dial respects has to stand. A caller that wants the policy's pacing calls [`Self::ensure`].
    ///
    /// A connection the handshake proves is the peer's is adopted under the tie-break and returned
    /// — which may be a different connection than the one this call made, if the peer's own dial
    /// won, and which a concurrent accept may replace a moment later. When this call's own dial
    /// loses the tie-break, the answer is the connection the pair kept: the caller asked to reach
    /// the peer, and the peer is reached. The same holds for a network failure — a beacon that
    /// could not be reached, a peer the beacon does not know, no direct path: a punch runs both
    /// directions at once, so the peer's own dial may have connected the pair while this one was
    /// still trying, and a caller that asked to reach the peer is answered with the peer reached.
    /// That is true for every caller of [`Self::connect`], not only for a dial the tie-break
    /// dropped, and for those three network failures only. [`ConnectFailure::WrongPeer`] is the
    /// exception: an address that proved a key which is not the peer's is a security fact, and the
    /// pair's own connection does not disprove it, so it is answered as itself even when the pair
    /// came up while this dial was still trying. [`ConnectFailure::NotTrusted`] and
    /// [`ConnectFailure::Nowhere`] are answered as themselves whatever the pair holds, because a
    /// live connection does not change a decision this machine made or a configuration it lacks. A
    /// [`ConnectFailure::Deferred`] is answered with the state's own reason rather than with
    /// itself, since the fault is this machine's read and not a fact about the peer, and a
    /// [`ConnectFailure::NoDirectPath`] names every address it tried.
    ///
    /// The handle is a connection, not a promise: the pair's live one is [`Self::live`]. The
    /// address this call dialled is written to the record only when the handshake at it completed,
    /// because that is what makes it authenticated data; a hint that did not complete is never
    /// written. See [`crate::peer::PeerRecord::last_address`].
    pub async fn connect_with(
        &self,
        endpoint: &Endpoint,
        peer: &Fingerprint,
        hint: Option<SocketAddr>,
    ) -> Result<Connection, ConnectFailure> {
        let peer_id = peer.peer_id();
        if hint.is_some() {
            // A hint is news: a fresh episode starts, because a caller has just shown this
            // machine an address. `wake` settles a dial nobody finished first and clears a
            // stop's re-ask stamp, so the reason to start over is not weighed against a state
            // that only still reads "dialling" or against a cause this call should ask about.
            self.wake(&peer_id);
        }
        match Box::pin(self.try_peer(endpoint, peer, hint, None)).await {
            Ok(connection) => {
                // A dial the policy knows about: a pair a keeper runs for has this counted as
                // its next dial, so a stale wait or a used-up episode does not outlive the
                // connection. A pair no keeper runs for stays `Unwatched`: nothing will
                // re-dial it, and the state must not claim otherwise.
                self.adopted_here(peer_id);
                Ok(connection)
            }
            Err(failure) => {
                // A punch runs both directions at once, and the peer's own dial may have reached
                // this machine while this one was still trying, or this dial's other addresses
                // may have. A connection that works is folded in as the dial the policy knows
                // about, whatever this dial met, so a keeper does not keep a stale wait or a
                // used-up episode across it.
                //
                // Only where the record said this machine trusts the peer: the failures a dial can
                // reach only after that read passed. A refusal or a deferral may be answered while
                // the pair holds a connection that arrived some other way, and folding it would
                // clear a stop this dial exists to respect. No case pins the difference, because a
                // stop closes what is live and refuses what arrives, so a stop and a live
                // connection cannot both be true today — this is what keeps that from being an
                // accident.
                let reached = match failure {
                    ConnectFailure::WrongPeer { .. }
                    | ConnectFailure::BeaconUnreachable { .. }
                    | ConnectFailure::PeerUnknown { .. }
                    | ConnectFailure::NoDirectPath { .. }
                    | ConnectFailure::Nowhere { .. } => self.live(&peer_id),
                    ConnectFailure::NotTrusted { .. } | ConnectFailure::Deferred { .. } => None,
                };
                if reached.is_some() {
                    self.adopted_here(peer_id);
                }
                match failure {
                    // A wrong key is a security fact about an address, and the pair's own
                    // connection does not disprove it: it is answered as itself.
                    ConnectFailure::WrongPeer { .. } => Err(failure),
                    // A network answer names no path, and that is the answer to *this* dial, not
                    // to the pair: a caller that asked to reach the peer is answered with the
                    // peer reached.
                    ConnectFailure::BeaconUnreachable { .. }
                    | ConnectFailure::PeerUnknown { .. }
                    | ConnectFailure::NoDirectPath { .. } => reached.ok_or(failure),
                    // A deferral is not this dial's answer: the answer is the state a product
                    // reads, which keeps whatever reason it had — the fault itself when the state
                    // names none.
                    ConnectFailure::Deferred { .. } => {
                        let (_, named) = self.state_and_reason(&peer_id);
                        Err(named.unwrap_or(failure))
                    }
                    other => Err(other),
                }
            }
        }
    }

    /// Fold a pair that holds a connection into the policy as this dial: the pair is connected,
    /// and a stop is open again.
    ///
    /// The callers check both halves of the premise. This machine's read of the record said it
    /// trusts the peer — a refusal or a deferral is never folded, because a connection that
    /// arrived some other way must not clear a stop this dial exists to respect — and the pair
    /// holds a connection: either the one this dial kept, or one the peer's own dial brought up
    /// while this one was still trying. Both of a stop's causes are disproved by that.
    fn adopted_here(&self, peer: PeerId) {
        let now = self.runtime.now();
        self.transition(peer, |state| {
            state.trust_restored(now);
            state.located(now);
            state.adopted();
        });
    }

    /// One try at reaching `peer`, in the module's order, before it is folded into the
    /// failures.
    ///
    /// `standing` is this machine's trust in the peer, read by a caller that had to read the
    /// record anyway; `None` asks here. Either way the answer is one read of the file, and the
    /// addresses that read found are the ones the second step dials.
    ///
    /// The three steps and the punch's failure mapping are the module's *The order* and *A punch*
    /// notes. Two things are this function's own. Every address it actually dialled is kept, in
    /// the order it tried them and without repeats, so a
    /// [`ConnectFailure::NoDirectPath`] names the whole set rather than one address of it. And the
    /// punch counts as **one** dial of the recovery episode: nothing here calls
    /// [`Recovery::failed`] per candidate, and the accounting is [`Self::ensure`]'s and
    /// [`Self::judge`]'s, unchanged.
    async fn try_peer(
        &self,
        endpoint: &Endpoint,
        peer: &Fingerprint,
        hint: Option<SocketAddr>,
        standing: Option<RecordRead>,
    ) -> Result<Connection, ConnectFailure> {
        let peer_id = peer.peer_id();
        let standing = match standing {
            Some(standing) => standing,
            None => self.standing(&peer_id),
        };
        if let Some(failure) = standing.refusal(*peer) {
            return Err(failure);
        }
        let mut tried: Vec<(SocketAddr, AddressError)> = Vec::new();
        let mut completed = false;
        let answer = if let Some(connection) = self
            .dial_known(
                endpoint,
                peer,
                hint,
                standing.trusted(),
                &mut tried,
                &mut completed,
            )
            .await
        {
            Ok(connection)
        } else if let Some(connection) = self.live(&peer_id) {
            // An accept may have connected the pair while this dial was trying its known
            // addresses: the peer is reached, and the beacon has nothing to add.
            Ok(connection)
        } else {
            self.punch(endpoint, peer, &mut tried, &mut completed).await
        };
        // A wrong key met on the way outranks whatever the dial answered: the pair being up, a
        // beacon that could not be reached and a set that reached nothing all say nothing about
        // an address that answered with another machine's key. This is the one place the
        // precedence is applied, so a new failure arm anywhere below cannot drop the fact.
        if let Some(failure) = wrong_key(peer, &tried) {
            self.forget_wrong_keys(&peer_id, &tried);
            return Err(failure);
        }
        answer
    }

    /// The first two steps of the module's order: the hint, then every address `record`
    /// remembers for the peer, all of them dialled at once.
    ///
    /// `record` is the read that found the pair trusted, so the addresses dialled here are the
    /// ones that read found. `Some` is the pair's connection. `None` means nothing was reached —
    /// including a dial whose handshake completed and whose connection the tie-break dropped with
    /// the pair holding nothing, which `completed` records — and the beacon stage is next, with
    /// `tried` naming every address this dial has failed at.
    async fn dial_known(
        &self,
        endpoint: &Endpoint,
        peer: &Fingerprint,
        hint: Option<SocketAddr>,
        record: Option<&PeerRecord>,
        tried: &mut Vec<(SocketAddr, AddressError)>,
        completed: &mut bool,
    ) -> Option<Connection> {
        // The hint, once: a claim about where the peer is, which the handshake either confirms or
        // disproves. A connection the tie-break dropped is no answer about the path — the caller
        // finds the pair's own connection, if there is one — so the next step still runs.
        if let Some(hint) = hint
            && let Some(connection) = self
                .dial_and_adopt(
                    endpoint,
                    peer,
                    [hint],
                    DEFAULT_CONNECT_BUDGET,
                    tried,
                    completed,
                )
                .await
        {
            return Some(connection);
        }
        // The remembered set, all at once. They are equally authenticated, so their order says
        // nothing about which is likelier; four sequential ten-second dials would spend the whole
        // budget on that order. The hint was just tried, so it is not tried twice.
        let remembered: Vec<SocketAddr> = record
            .map(PeerRecord::addresses)
            .unwrap_or_default()
            .iter()
            .copied()
            .filter(|address| Some(*address) != hint)
            .collect();
        if remembered.is_empty() {
            return None;
        }
        self.dial_and_adopt(
            endpoint,
            peer,
            remembered,
            DEFAULT_CONNECT_BUDGET,
            tried,
            completed,
        )
        .await
    }

    /// Dial a whole set at once, record every fault it met, and adopt whatever completed.
    ///
    /// `completed` is updated in place: a handshake that completed and then lost the tie-break is
    /// not a failed path, so a later refusal says so rather than naming a blocked network. The
    /// answer is the pair's connection, or `None` when the set left the pair with nothing — which
    /// is no answer about the path, so the caller's next stage still runs.
    async fn dial_and_adopt(
        &self,
        endpoint: &Endpoint,
        peer: &Fingerprint,
        addresses: impl IntoIterator<Item = SocketAddr>,
        budget: Duration,
        tried: &mut Vec<(SocketAddr, AddressError)>,
        completed: &mut bool,
    ) -> Option<Connection> {
        let dials = addresses
            .into_iter()
            .map(|address| (address, self.dial_to(endpoint, address, peer, budget)))
            .collect();
        let (reached, failures) = traverse::dial_all(dials).await;
        *completed |= !reached.is_empty();
        for (address, error) in failures {
            note(tried, address, error);
        }
        self.adopt_all(peer, reached)
    }

    /// The third step: the beacon, the punch it asks for, and the failures it can answer with.
    async fn punch(
        &self,
        endpoint: &Endpoint,
        peer: &Fingerprint,
        tried: &mut Vec<(SocketAddr, AddressError)>,
        completed: &mut bool,
    ) -> Result<Connection, ConnectFailure> {
        let peer_id = peer.peer_id();
        let leg = match self.beacon_leg(peer, tried).await {
            Ok(leg) => leg,
            Err(failure) => return Err(failure),
        };
        // A ceremony with this peer is running here: an older build would end it on a payload
        // outside its closed set, so nothing is sent, nothing is waited for, and the peer's own
        // candidates — a stored list included — are not dialled. The rule is read first, so a
        // dial that is stepping aside does not take the coordination lock for a list it will
        // not use.
        let may_send = self
            .presence
            .as_ref()
            .is_none_or(|presence| !presence.busy_with(&peer_id));
        let declared = self.declared();
        let local = endpoint
            .local_addr()
            .ok()
            .filter(|address| !address.ip().is_unspecified());
        let ours = Candidates::new(declared.iter().copied().chain(local));
        // Our candidates, and the generation to wait past. The generation is read *before* the
        // payload is sent, so one that arrives while this dial is sending is not missed; a list
        // already stored at entry is used as it is and nothing waits, unless it is older than
        // `COORDINATION_FRESH` — a stale list is worth nothing, and waiting one window for a
        // fresh one is the same punch later.
        let stored = if may_send {
            self.presence
                .as_ref()
                .and_then(|presence| presence.candidates(&peer_id))
        } else {
            None
        };
        let generation = stored.as_ref().map_or(0, |(_, generation)| *generation);
        // An empty list encodes to nothing — the format refuses a count of zero — so a machine
        // that knows of no address of its own sends no payload at all rather than one the peer
        // would drop as unrecognised.
        let payload = ours.encode();
        let introduce = async {
            match (&payload, may_send) {
                (Some(payload), true) => leg.introduce(peer_id, payload).await,
                _ => Ok(()),
            }
        };
        // Neither request may abort the other: an introduction the beacon refused does not turn
        // an address it did answer with into a failure, and a lookup that failed does not throw
        // away an introduction that was delivered. Each request carries its own
        // [`BEACON_REQUEST_TIMEOUT`], so no outer deadline can discard a lookup the beacon
        // answered; both answers are kept for the refusal.
        let (lookup, introduced) = traverse::join2(leg.lookup(&peer_id), introduce).await;
        let observed = match lookup {
            Ok(address) => address,
            Err(error) => {
                return Err(ConnectFailure::BeaconUnreachable {
                    peer: *peer,
                    cause: cause(tried, &unreachable(error.to_string(), &error)),
                });
            }
        };
        let theirs = if may_send {
            match stored {
                Some((candidates, _)) => Some(candidates),
                None => match &self.presence {
                    Some(presence) => {
                        presence
                            .wait_for_candidates(&peer_id, generation, PUNCH_WINDOW)
                            .await
                    }
                    None => None,
                },
            }
        } else {
            // A ceremony with this peer is running here, so the punch steps aside: the dial set
            // is the beacon's answer alone, and neither a stored list nor a wait is used.
            None
        };
        let set = punch_set(observed, theirs.as_ref(), &declared, local);
        if set.is_empty() {
            // The beacon has no registration for the peer and the peer named nothing to dial.
            return Err(ConnectFailure::PeerUnknown {
                peer: *peer,
                cause: cause(tried, "the peer is not registered"),
            });
        }
        match self
            .dial_and_adopt(
                endpoint,
                peer,
                set.iter().copied(),
                PUNCH_DIAL_BUDGET,
                tried,
                completed,
            )
            .await
        {
            Some(connection) => Ok(connection),
            // Every dial failed, or the one that completed was dropped with the pair holding
            // nothing: the refusal names the whole set rather than the one address that was last.
            None => Err(no_path(peer, tried, *completed, &introduced)),
        }
    }

    /// Adopt every connection a set of dials completed, and answer the pair's one connection.
    ///
    /// Every completion is adopted, not only the first: the peer accepts a handshake the moment
    /// it completes, so a completed dial this side dropped would leave the two machines keeping
    /// different connections. The tie-break decides which of them the pair keeps, and it decides
    /// the same on both sides because it reads only who started what and the exporter both ends
    /// compute. The answer is the pair's connection, or `None` when the set left the pair with
    /// nothing.
    fn adopt_all(
        &self,
        peer: &Fingerprint,
        reached: Vec<(SocketAddr, Connection)>,
    ) -> Option<Connection> {
        for (_, connection) in reached {
            self.here(peer, connection);
        }
        // A dial the tie-break dropped is not the answer when the pair holds one: the caller
        // asked to reach the peer, and the peer is reached. The pair's connection wrote its own
        // address when it was adopted, so nothing is written again here.
        self.live(&peer.peer_id())
    }

    /// The session the beacon stage speaks on: the machine's one registration when there is a
    /// presence, and one session of the manager's own otherwise.
    ///
    /// The two failures of this step: nothing configured at all, which is configuration rather
    /// than a network state, and a beacon that would not open a session.
    async fn beacon_leg<'a>(
        &'a self,
        peer: &Fingerprint,
        tried: &[(SocketAddr, AddressError)],
    ) -> Result<Leg<'a>, ConnectFailure> {
        if let Some(presence) = &self.presence {
            return Ok(Leg::Presence(presence));
        }
        let Some(beacon) = self.beacon() else {
            return Err(if tried.is_empty() {
                ConnectFailure::Nowhere { peer: *peer }
            } else {
                ConnectFailure::BeaconUnreachable {
                    peer: *peer,
                    cause: cause(tried, "no beacon is configured"),
                }
            });
        };
        match beacon.connect().await {
            Ok(session) => Ok(Leg::Session(session)),
            Err(error) => Err(ConnectFailure::BeaconUnreachable {
                peer: *peer,
                cause: cause(tried, &unreachable(error.to_string(), &error)),
            }),
        }
    }

    /// One address's dial, boxed for a set that is polled together.
    ///
    /// `budget` is the whole dial's bound, applied once: [`Self::try_address`] spends it on the
    /// handshake, and a punch's five seconds are shorter than a lone dial's ten.
    fn dial_to<'a>(
        &'a self,
        endpoint: &'a Endpoint,
        address: SocketAddr,
        peer: &'a Fingerprint,
        budget: Duration,
    ) -> traverse::Dial<'a, Connection, AddressError> {
        Box::pin(async move { self.try_address(endpoint, address, peer, budget).await })
    }

    /// Adopt this machine's own dial and answer the pair's connection.
    ///
    /// `None` when the tie-break dropped it. That is not a dial failure — the address answered —
    /// and a dropped dial is marked judged, so the keeper never counts it as a strike: losing the
    /// tie-break is the design doing its job, and a punch dials several addresses at once, so
    /// counting each one would spend a whole episode in one round.
    ///
    /// The kept connection's remote address is written to the record here, because a completed
    /// authenticated handshake is authenticated data: the peer answered at that address with the
    /// key this machine trusts. Only the dial that kept the connection writes, so a dial the
    /// tie-break dropped adds nothing — the pair's connection was written when it was adopted —
    /// and a hint that did not complete is never written at all.
    fn here(&self, peer: &Fingerprint, connection: Connection) -> Option<Connection> {
        match self.adopt(peer.peer_id(), connection, Started::Here) {
            Some((connection, kept_this, watch)) => {
                if kept_this {
                    self.note_address(&peer.peer_id(), connection.remote_address());
                    self.start_exchange(peer.peer_id(), &connection, &watch, Started::Here);
                }
                Some(connection)
            }
            None => None,
        }
    }

    /// Take one incoming connection.
    ///
    /// The handshake already proved the peer's key against the endpoint's policy;
    /// this checks the record again, applies the tie-break, and records the address
    /// the kept connection came from. Every failure here ends its own connection: a
    /// refused stranger and a handshake that timed out are ordinary events on a
    /// public address, and the next incoming connection is taken regardless.
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
        let standing = self.standing(&peer);
        match standing {
            RecordRead::Trusted(_) => {}
            // A read this machine could not complete is not a refusal: the connection is
            // closed with the fault's own reason, and the peer's next dial meets a record
            // that may be readable again.
            RecordRead::Deferred { .. } => {
                connection.close(0u32.into(), DEFERRED_CAUSE.as_bytes());
                return;
            }
            RecordRead::Unreadable(error) => {
                connection.close(0u32.into(), cause_text(&unreadable(&error)));
                return;
            }
            RecordRead::Refused(cause) => {
                connection.close(0u32.into(), cause_text(&cause));
                return;
            }
        }
        // The tie-break runs before the address write: the write is a hint that
        // saves a beacon trip, and delaying the adoption by it would let the keeper
        // see the pair empty while the peer's own connection was still being taken.
        // Only a connection the tie-break keeps teaches an address here. When it keeps the one
        // the pair already held, that connection's remote address was written by the reach that
        // adopted it — a dial writes the address it completed at, and an accept the address it
        // arrived from — so nothing is lost by not writing it twice.
        if let Some((kept, kept_this, watch)) = self.adopt(peer, connection, Started::There)
            && kept_this
        {
            self.note_address(&peer, kept.remote_address());
            self.start_exchange(peer, &kept, &watch, Started::There);
            // An authenticated connection from the peer is a reason to stop waiting: the
            // pair is connected, so the episode stops dialling and watches instead. It is
            // also an address, so a pair that stopped because it had nowhere to dial is open
            // again — it consumes a dial number rather than starting a fresh episode.
            self.transition(peer, |state| {
                state.adopted();
                state.located(self.runtime.now());
            });
        }
    }

    /// Serve incoming connections on `endpoint` until it closes.
    ///
    /// This is the accept loop, and the caller runs it once: the crate has no runtime of
    /// its own to spawn on, so the caller keeps the handle and decides when the loop
    /// stops — closing the endpoint is what ends it, because quinn's `accept` answers
    /// nothing else.
    ///
    /// The loop does not wait for a handshake. Each incoming connection is handed to a
    /// task of its own, so a burst of peers that open a connection and stall costs at most
    /// [`ACCEPT_IN_FLIGHT`] handshakes at once rather than one after another; at the cap the
    /// loop stops pulling from the endpoint and looks again after one round of [`TRUST_POLL`],
    /// so a full machine's next accept waits up to that round and never the length of a
    /// handshake.
    ///
    /// The loop itself only takes and hands over. The address write that accepting needs
    /// happens on the task that took the connection, so a caller can run this loop on the
    /// reactor it serves.
    pub async fn serve(self: Arc<Self>, endpoint: Endpoint) {
        loop {
            // The cap is checked before the next connection is taken, so a full machine does
            // not hold a handshake outside `accept`'s own budget.
            while self.in_flight.load(Ordering::SeqCst) >= ACCEPT_IN_FLIGHT {
                pause(&self, TRUST_POLL).await;
            }
            let Some(incoming) = endpoint.accept().await else {
                return;
            };
            self.in_flight.fetch_add(1, Ordering::SeqCst);
            let this = Arc::clone(&self);
            let place = InFlight(Arc::clone(&self));
            self.runtime.spawn(Box::pin(async move {
                // The place is given back however the task ends, including an abort.
                let _place = place;
                this.accept(incoming).await;
            }));
        }
    }

    /// Keep the pair with `peer` connected until nothing can dial it again by itself.
    ///
    /// The manager owns recovery: the caller runs this once per paired peer and does not
    /// dial. A pair that stays up is never re-dialled: the keeper watches the connection
    /// in rounds of [`TRUST_POLL`], asking the record each round whether this machine
    /// still trusts the peer, and dials again in [`Self::connect`]'s order once the
    /// connection is gone. A pair that is down is dialled in episodes — the gaps grow,
    /// the episode is capped, and once it is used up the pair is dialled once a
    /// [`crate::peer::RECOVERY_RECHECK`] — so a peer that keeps refusing is dialled at a
    /// decreasing rate rather than at handshake rate, and the state is readable through
    /// [`Self::recovery`] the whole time.
    ///
    /// It returns when it reaches a stop, and says which: [`StopCause::NotTrusted`] when this
    /// machine does not trust the peer or cannot read the record that would say it does, and
    /// [`StopCause::Nowhere`] when there is no beacon and no remembered address. Everything
    /// else — a beacon that is down, a peer that is not registered, a path that does not
    /// work — is a state that can pass, and the keeper waits for it to. [`Self::recovery`]
    /// keeps reporting the same reason after the keeper has returned, and a stop is not
    /// permanent while its cause is: [`Self::ensure`] re-opens it and dials once, and running
    /// the keeper again restores self-recovery — nothing inside the crate does that by itself,
    /// and [`Self::watched`] is how a product knows it is the one that has to. Dropping the
    /// future ends the watching too, and nothing then dials the pair by itself: a pair waiting
    /// out a gap keeps its state and its count and reads [`Self::watched`] false. A keeper
    /// dropped mid-dial is settled by the next reader — the dial's connection is judged as the
    /// keeper would have judged it, which leaves a wait or a used-up episode behind when the
    /// dial produced one, and [`Recovery::Unwatched`] when it produced nothing to judge.
    ///
    /// A connection that carried anything — a QUIC datagram or stream frame either
    /// way, beyond the manager's own binding exchange and the layers' own rounds — and
    /// then died is a link failure: the next dial is due at once, however many
    /// times it happens and however long it lived, because that is recovery and not a
    /// loop. A connection that only exchanged its binding and then died carried
    /// nothing, because the exchange is the manager's handshake and not the pair's use:
    /// the frames it wrote are measured and subtracted, and a connection that dies
    /// before that measurement lands is judged as carrying nothing too. That window is
    /// the whole [`crate::peer::EXCHANGE_BUDGET`], so a pair's own traffic inside it is
    /// discounted with the exchange's — the price of a bound the keeper can keep
    /// without a second handshake. A connection that outlives [`KEEPER_SETTLE`] is
    /// settled the same way: the pair got to use it, so its loss is ordinary churn.
    ///
    /// Only a dial whose connection ends before the pair carried anything, inside
    /// [`KEEPER_SETTLE`] and for a reason other than a timeout, is a strike. A timeout is
    /// the peer going quiet — a NAT mapping expiring, a laptop closing — so it is a
    /// redial at once and never a strike, which is what keeps a peer built with a shorter
    /// idle timeout than this machine's from turning an ordinary quiet drop into a
    /// refusal. A run of strikes is bounded by [`crate::peer::RECOVERY_DIALS`] like any
    /// other failed dial, so a peer that takes a connection and drops it is not re-dialled
    /// in a loop; a strike is counted even when another dialer has connected by then,
    /// because a dial that produced a connection which died at once is exactly the
    /// signature the bound is for. A dial that fails outright while the pair is connected
    /// is the other way round and is not counted: a pair that is connected has nothing to
    /// recover from.
    pub async fn keep_connected(&self, endpoint: &Endpoint, peer: &Fingerprint) -> StopCause {
        let peer_id = peer.peer_id();
        // For as long as this future lives the pair has a keeper, and a state that says a
        // dial is coming is one somebody will make. Dropping the future — a caller's task
        // cancelled — ends that, and the pair must stop claiming a retry. A caller asking
        // again is a person's answer to whatever stopped the keeper, so the episode starts
        // fresh here — but only for the pair's first keeper: a second one is not a new start
        // and must not hand a peer that keeps dropping a connection a second episode.
        let _kept = Kept::new(self, peer_id, self.runtime.now());
        loop {
            // Read before the trust check, so a coordination payload that arrives while this
            // round runs is not missed: the wait below returns for a generation past this one,
            // and the round then asks the record again rather than dialling on the payload's
            // word. A withdrawn peer therefore causes no dial.
            let generation = self.coordination_generation(&peer_id);
            // A pair whose trust is gone is not one to keep: close what is live and stop,
            // naming the trust rather than a lost path. The record is read from disk, so a
            // withdrawal written through another handle — or by the other process on this
            // root — stops the keeper too.
            let standing = self.standing(&peer_id);
            match standing {
                RecordRead::Trusted(_) => {}
                RecordRead::Deferred { .. } => {
                    // A local read that failed this instant is not the peer's fault and not a
                    // decision: the pair keeps its place and its live connection — nothing is
                    // trusted on a file nobody could read, and nothing is torn down for it
                    // either — and the next round asks again. The deferral itself is already
                    // folded in; `standing` is the one place that does it.
                    self.deferral_pause(None).await;
                    continue;
                }
                RecordRead::Unreadable(error) => {
                    return self.refused(&peer_id, unreadable(&error));
                }
                RecordRead::Refused(cause) => {
                    return self.refused(&peer_id, cause);
                }
            }
            if let Some((connection, watch)) = self.judgeable(&peer_id)
                && (!watch.judged.load(Ordering::SeqCst) || connection.close_reason().is_none())
            {
                self.watch(&peer_id, *peer, &connection, &watch).await;
                continue;
            }
            if !self.somewhere_to_dial(&peer_id) {
                // Nothing to dial and nothing that could tell this machine where the peer
                // is: configuration, not a network state that can pass.
                self.transition(peer_id, |state| state.stop(StopCause::Nowhere));
                return StopCause::Nowhere;
            }
            let (state, _) = self.ensure(endpoint, peer).await;
            match state {
                // A dial is running — this call's, or one another caller took — and the round
                // that notices an inbound connection, a withdrawal or a wake is what comes
                // next. Every arm of this loop waits, so no state can make it a hot loop.
                Recovery::Dialling { .. } | Recovery::Connected | Recovery::Unwatched => {
                    self.pause_or_punch(&peer_id, generation, TRUST_POLL).await;
                }
                Recovery::Waiting { until, .. } | Recovery::Exhausted { until, .. } => {
                    // One timer, and it is the sooner of the policy's moment, the round that
                    // notices an inbound connection, a withdrawal or a wake, and a coordination
                    // payload that asks for a punch.
                    self.pause_or_punch(
                        &peer_id,
                        generation,
                        until.saturating_duration_since(self.runtime.now()),
                    )
                    .await;
                }
                // A stop is answered here rather than dialled through. The keeper's own two
                // stops return from the branch that wrote them, so a stop that reaches here was
                // written by something else — another keeper for the same pair, or a service
                // path — and it is that writer's decision, not a reason to dial.
                Recovery::Stopped { cause } => return cause,
            }
        }
    }

    /// Close what is live for `peer` and stop the pair for a refusal the record answered.
    ///
    /// The cause travels to the peer in [`cause_text`]'s words — which file, and which fault,
    /// is this machine's business — and the stop keeps it for the caller.
    fn refused(&self, peer: &PeerId, cause: NotTrustedCause) -> StopCause {
        if let Some(live) = self.live(peer) {
            live.close(0u32.into(), cause_text(&cause));
        }
        let stop = StopCause::NotTrusted(cause);
        self.transition(*peer, |state| state.stop(stop.clone()));
        stop
    }

    /// Make one dial to `peer`, if the retry policy says one is due.
    ///
    /// This is how a service with something to deliver — a message waiting, an action a
    /// person asked for — dials without waiting for a keeper, and how the keeper dials. It
    /// is paced by the same policy: a call that finds the pair connected, already dialling
    /// or waiting out a gap makes no dial and answers the state, so a queue that asks once a
    /// second does not dial once a second and does not open a beacon session per poll. The
    /// dial itself is [`Self::connect`]'s, with no fresh address.
    ///
    /// The answer is the policy's own state after the call, and the failure this call has to
    /// report — `None` when the pair is up and `None` when nothing was due and nothing had to be
    /// decided, except that a stopped pair always answers its cause, whether this call wrote the
    /// stop or found it. A caller with something to report, like an action a person asked for,
    /// says why it could not reach the peer; one that only needs the connection reads the state.
    /// [`Self::recovery`] is the same answer with a live connection and with "no keeper" in front
    /// of it; this one is what a caller about to dial needs, because the policy's moment is what
    /// paces the next call.
    ///
    /// A pair that is up is answered [`Recovery::Connected`], and the one failure reported beside
    /// it is [`ConnectFailure::WrongPeer`]: a network failure is the answer to a dial and the pair
    /// being up is the answer to the pair, but an address that proved a key which is not the
    /// peer's is a security fact the pair's own connection says nothing about. This reports it as
    /// [`Self::connect_with`] does, so the two entry points cannot disagree about the same event.
    ///
    /// A record that refuses trust is a decision, so it stops the pair with the cause this read
    /// found: nothing would dial it again by itself while the file says that, and a keeper would
    /// stop it on its next round anyway. The answer and the readable state therefore name the
    /// same reason. It is not permanent: the next call re-reads the record once the stop's cause
    /// has been re-asked, re-opens the stop when a person has restored trust or an address has
    /// arrived, and dials — which is what makes a restoration the next call's answer. A fault
    /// this machine met this instant is the other way round: the pair is not stopped, the state
    /// keeps whatever reason it had, and the answer is that reason — the deferral itself when
    /// no dial has run — and the file is read again.
    ///
    /// Because a stop's cause is re-asked at most once a round, the crate's own queue waits a
    /// round after a refusal before asking again, and a poll every second does not become a
    /// record read every second. A pair whose next dial is not due is answered from the policy
    /// without asking the record at all, so a queue that calls this once a round costs one read
    /// per gap rather than one per round. The price is that a service path does not re-ask the
    /// record while it waits: a withdrawal is answered when the next dial is due, where a keeper
    /// notices within a round.
    pub async fn ensure(
        &self,
        endpoint: &Endpoint,
        peer: &Fingerprint,
    ) -> (Recovery, Option<ConnectFailure>) {
        let peer_id = peer.peer_id();
        if self.live(&peer_id).is_some() {
            return (Recovery::Connected, None);
        }
        // A dial whose connection died before anybody judged it is settled first, so the
        // policy never answers "dialling" for a dial that is over.
        self.settle_stale(&peer_id);
        let now = self.runtime.now();
        // Nothing is due and nothing has to be decided: answer from the policy without asking
        // the record, which is what makes a queue's poll cost one read per gap rather than one
        // per round. A stop is the exception, because its cause can go with nothing dialling,
        // and it is re-asked at most once a round.
        if !self.take_due(&peer_id, now) {
            return self.answer(&peer_id, None);
        }
        // One read of the record answers both questions: whether this machine trusts the peer,
        // and — from the copy that read refreshed — whether there is now somewhere to dial. An
        // address another handle or the other process wrote is a real address, not a cached
        // one. The same answer is handed to the dial, so one dial costs one read.
        let standing = self.standing(&peer_id);
        let reachable = self.somewhere_to_dial(&peer_id);
        match &standing {
            RecordRead::Trusted(_) => {
                // A stop whose cause has gone is not a stop: a person restored trust, or an
                // address arrived for a pair that had nowhere to dial. The keeper returned
                // when it stopped, so this is the path that starts it over.
                self.transition(peer_id, |state| {
                    state.trust_restored(now);
                    if reachable {
                        state.located(now);
                    }
                });
            }
            RecordRead::Deferred { .. } => {
                // `standing` already folded the deferral into the state, so nothing is written
                // here; the answer is the state's own reason, read with it so the two agree.
                return self.state_and_reason(&peer_id);
            }
            RecordRead::Unreadable(error) => {
                // A refusal is a decision and not a network state that passes: nothing will dial
                // this pair by itself while the record says it, so the state is stopped with the
                // cause this read found — a keeper would stop it on its next round anyway — and
                // the answer and the readable state cannot name two reasons. The next call
                // re-opens it once a person has changed the record. Nothing is live here, so
                // `refused` has nothing to close.
                self.refused(&peer_id, unreadable(error));
                return self.answer(&peer_id, None);
            }
            RecordRead::Refused(cause) => {
                self.refused(&peer_id, cause.clone());
                return self.answer(&peer_id, None);
            }
        }
        // Beginning the dial and marking it in flight are one step under the one lock, and a
        // dial already in flight is never replaced, so two callers cannot both dial.
        let started = {
            let now = self.runtime.now();
            let mut retry = self.retry();
            let watched = retry.entry(peer_id).or_insert_with(Watched::unwatched);
            if watched.dialing.is_some() {
                None
            } else {
                watched.state.begin(now).map(|dial| {
                    let token = watched.token;
                    watched.token = watched.token.wrapping_add(1);
                    watched.dialing = Some(token);
                    watched.dial = dial;
                    (dial, token)
                })
            }
        };
        let Some((_, token)) = started else {
            return self.answer(&peer_id, None);
        };
        // Dropped however the future ends, so a dial nobody finished is given back and the
        // next reader settles it. A dial that runs to its end gives the claim back with its
        // outcome, in [`Self::fold`].
        let dialing = Dialling {
            connections: self,
            peer: peer_id,
            token,
        };
        let outcome = Box::pin(self.try_peer(endpoint, peer, None, Some(standing))).await;
        // A dial that lost the tie-break to a connection the pair already holds carried nothing
        // and is not a failure: the pair is connected.
        let Err(failure) = outcome else {
            self.fold(&dialing, Recovery::adopted);
            return self.answer(&peer_id, None);
        };
        // Read before the recovery map is taken: the connection map is not held while the
        // recovery map is, so a reader of the state cannot wait behind a dial. `adopt` is the
        // one place that holds both, and it takes the connection map first; nothing takes them
        // in the other order, which is what keeps the pair of them from deadlocking. A
        // connection that arrives in the instant between this read and the fold is not lost —
        // its own adoption is what the pair holds — only this dial's count is spent.
        let connected = self.live(&peer_id).is_some();
        let now = self.runtime.now();
        self.fold(&dialing, |state| {
            if connected {
                // The pair came up while this dial was being judged: nothing is counted
                // against it.
                state.adopted();
            } else if matches!(failure, ConnectFailure::Nowhere { .. }) {
                // Nowhere to dial is configuration, not a network state: it is the one stop a
                // service path makes, and an address or a beacon re-opens it. A stop already
                // on file is not replaced by it — a keeper that read the record knows more
                // than this dial does, and the answer follows the state.
                if !matches!(state, Recovery::Stopped { .. }) {
                    state.stop(StopCause::Nowhere);
                }
            } else {
                state.failed(now, failure.clone(), self.recheck);
            }
        });
        self.answer(&peer_id, Some(failure))
    }

    /// Give a dial's claim back and fold its outcome into the policy, under one lock.
    ///
    /// One step, because a reader that found the state still [`Recovery::Dialling`] with the
    /// claim gone would settle this call's dial as an abandoned one and lose the episode it
    /// counted. The claim is this dial's own, so a dial that began after it cannot have its
    /// own claim cleared here.
    fn fold(&self, dialing: &Dialling<'_>, change: impl FnOnce(&mut Recovery)) {
        let mut retry = self.retry();
        let watched = retry.entry(dialing.peer).or_insert_with(Watched::unwatched);
        if watched.dialing == Some(dialing.token) {
            watched.dialing = None;
        }
        change(&mut watched.state);
    }

    /// The answer one call to the manager gives: the policy's state, and the failure this call
    /// has to report — `None` when it has none, or when a connection arrived while the record was
    /// being read or the dial was running, except a wrong key, which outlives the connection that
    /// arrived beside it.
    ///
    /// A stop always names its cause, whether this call wrote it or found it: a caller that
    /// asked for one delivery is owed the reason, and the conversion from a cause to a failure
    /// lives in the policy rather than in the layers above it.
    ///
    /// Nothing else is derived here. A call that only read the policy — a queue polling while
    /// the pair waits out a gap — has met nothing and is answered nothing, rather than the
    /// failure that earned the gap; a call that met something passes it, and a stop on file
    /// still wins over it.
    ///
    /// [`Self::ensure`] has two arms that do not come through here: its deferral arm answers
    /// [`Self::state_and_reason`], because the deferral is already in the state and the answer is
    /// the state's own reason rather than a failure passed in; and a pair that already has a live
    /// connection is answered [`Recovery::Connected`] with no failure before the record is read.
    fn answer(
        &self,
        peer: &PeerId,
        met: Option<ConnectFailure>,
    ) -> (Recovery, Option<ConnectFailure>) {
        if self.live(peer).is_some() {
            // The pair is up, so a network failure is not reported: it is the answer to a dial,
            // and the pair being up is the answer to the pair. A wrong key is not a network
            // failure — it is a security fact about an address, which the pair being up says
            // nothing about — so it is reported beside the connected state.
            let security =
                met.filter(|failure| matches!(failure, ConnectFailure::WrongPeer { .. }));
            return (Recovery::Connected, security);
        }
        let state = self.policy(peer);
        // A stop is the standing answer whatever this call met on the way: a transient record
        // fault does not replace the cause the pair stopped for, and a cause whose detail has
        // moved on is still the stop the caller has to see.
        let failure = match &state {
            Recovery::Stopped { cause } => Some(cause.clone().failure(peer.fingerprint())),
            _ => met,
        };
        (state, failure)
    }

    /// The pair's state, and the reason that state names for being down — `None` when it names
    /// none: a dial in flight, or a pair already connected.
    ///
    /// The state a product reads is the truth, so a caller holding a deferrable fault answers this
    /// reason rather than the fault: a pair whose last dial met a network failure keeps that
    /// reason, and a deferral never stands in for it. A caller with nothing in hand — an ask whose
    /// budget is spent — reads the same reason. The state comes back with it so a caller that
    /// shows both reads it once and the two cannot disagree.
    pub(crate) fn state_and_reason(&self, peer: &PeerId) -> (Recovery, Option<ConnectFailure>) {
        let state = self.recovery(peer);
        let answer = state.down(peer.fingerprint());
        (state, answer)
    }

    /// Wait out a deferrable fault: one keeper round, which is the gap the policy named for the
    /// next dial, and never past `deadline` when the caller has one, so a fault costs the person's
    /// one budget no more than the rounds it took.
    ///
    /// The one way this crate waits for a record it could not read.
    pub(crate) async fn deferral_pause(&self, deadline: Option<Instant>) {
        let round = deadline.map_or(TRUST_POLL, |deadline| {
            deadline.saturating_duration_since(self.runtime.now())
        });
        pause(self, round).await;
    }

    /// Watch one connection for a round: judge the peer's life and — for a connection the
    /// pair has not yet judged — the settle window.
    ///
    /// Trust is not judged here: the keeper asks the record at the top of every round, and
    /// this watches one connection between those reads.
    ///
    /// The round is [`TRUST_POLL`], cut short by the end of [`KEEPER_SETTLE`] so a fresh
    /// connection is judged by the moment the window closes rather than up to a round after
    /// it. A connection that has already been judged is watched for its close only: its
    /// loss is a link failure and not a strike.
    ///
    /// A connection that closed before this round still reaches here, because the manager
    /// keeps the entry of the last connection it adopted: a dial whose connection died
    /// before the keeper looked is judged like any other, which is what bounds a peer that
    /// accepts and drops.
    async fn watch(
        &self,
        peer: &PeerId,
        fingerprint: Fingerprint,
        connection: &Connection,
        watch: &Watch,
    ) {
        let now = self.runtime.now();
        let judged = watch.judged.load(Ordering::SeqCst);
        let settle = if judged {
            Duration::ZERO
        } else {
            Self::settle_left(watch, now)
        };
        // A peer that has not answered for the whole bound is gone, and this machine's own
        // pings are what would have made it answer; see [`Self::vanish_bound`].
        if self.vanished(watch, now) {
            connection.close(0u32.into(), VANISHED_CAUSE.as_bytes());
            if !watch.judged.swap(true, Ordering::SeqCst) {
                let now = self.runtime.now();
                self.transition(*peer, |state| state.settled(now));
            }
            return;
        }
        if let Some(error) = connection.close_reason() {
            self.judge(peer, fingerprint, connection, watch, &error, settle);
            return;
        }
        let round = if settle.is_zero() {
            TRUST_POLL
        } else {
            settle.min(TRUST_POLL)
        };
        let Some(error) = timeout(&*self.runtime, round, connection.closed()).await else {
            // Still open: past the settle window the pair has plainly got to use it.
            if settle.is_zero() && !watch.judged.swap(true, Ordering::SeqCst) {
                let now = self.runtime.now();
                self.transition(*peer, |state| state.settled(now));
            }
            return;
        };
        self.judge(peer, fingerprint, connection, watch, &error, settle);
    }

    /// Fold one connection's death into the pair's recovery.
    ///
    /// A connection the pair got use of, one lost to a peer that went quiet, and one that
    /// had already outlived the settle window are all ordinary churn: the next dial is due
    /// at once. Only a connection that ends before carrying anything, inside the window and
    /// for a reason other than a timeout, is a strike — and a strike is one dial of the
    /// episode like any other, so a peer that accepts and drops is bounded.
    fn judge(
        &self,
        peer: &PeerId,
        fingerprint: Fingerprint,
        connection: &Connection,
        watch: &Watch,
        error: &ConnectionError,
        settle: Duration,
    ) {
        // Whoever judges first writes the outcome. A second caller — the keeper's round and
        // a reader settling the same dial — must not overwrite it: settling twice would
        // reset the episode the first judgement counted.
        if watch.judged.swap(true, Ordering::SeqCst) {
            return;
        }
        let now = self.runtime.now();
        if carried(connection, watch)
            || matches!(error, ConnectionError::TimedOut)
            || settle.is_zero()
        {
            self.transition(*peer, |state| state.settled(now));
            return;
        }
        // Counted even when the pair holds another connection by now: a dial that produced
        // a connection which died at once is the accept-and-drop signature, and a second
        // dialer that happened to win the race does not make it a pair that works. A dial
        // that fails outright is the other way round — see [`Self::ensure`] — because a
        // pair that is connected has nothing to recover from.
        self.transition(*peer, |state| {
            state.failed(
                now,
                ConnectFailure::NoDirectPath {
                    peer: fingerprint,
                    candidates: vec![connection.remote_address()],
                    cause: close_cause(error),
                },
                self.recheck,
            );
        });
    }

    /// How much of [`KEEPER_SETTLE`] is left for a connection adopted at `watch.adopted`.
    fn settle_left(watch: &Watch, now: Instant) -> Duration {
        KEEPER_SETTLE.saturating_sub(now.saturating_duration_since(watch.adopted))
    }

    /// Judge `connection` if it has closed and nobody has judged it yet.
    ///
    /// A connection that died before the keeper looked must not escape the settle window: the
    /// window is measured from its adoption to the moment somebody looks, so a connection that
    /// died inside it and is judged later is settled rather than counted. A keeper looks at
    /// least every [`TRUST_POLL`], which is shorter than the window, so a connection it dialled
    /// is judged inside it; a caller with no keeper has no episode to count, and a connection
    /// it dialled is not a dial the policy made. A connection this machine dropped itself —
    /// losing a tie-break, a withdrawal — is not judged here: that is not a dial that failed.
    fn judge_dead(&self, peer: &PeerId, connection: &Connection, watch: &Watch) {
        if watch.judged.load(Ordering::SeqCst) {
            return;
        }
        let Some(error) = connection.close_reason() else {
            return;
        };
        let now = self.runtime.now();
        let settle = Self::settle_left(watch, now);
        self.judge(peer, peer.fingerprint(), connection, watch, &error, settle);
    }

    /// Fold a dial whose caller went away before anybody judged it into the policy.
    ///
    /// The keeper judges a connection when it watches it, but a caller that dials without a
    /// keeper — a service, an action, a keeper whose own task was cancelled — has nobody to do
    /// that, and a dial nobody finished must not leave the pair reading "dialling" for ever. So
    /// the next reader settles it: the dead connection is judged as the keeper would have judged
    /// it, which may leave a wait or a used-up episode behind because that is what the dial
    /// produced, and a state the judgement did not move is given back as the policy's next wait
    /// when a keeper will act on it and as [`Recovery::Unwatched`] when none will, because a
    /// pair nothing watches must not promise a retry.
    fn settle_stale(&self, peer: &PeerId) {
        // The recovery map is read and released before the connection map is taken: `adopt`
        // holds the connection map while it takes the recovery one, and taking them in the
        // other order here would deadlock the pair.
        let keeper = {
            let retry = self.retry();
            match retry.get(peer) {
                Some(watched)
                    if watched.dialing.is_none()
                        && matches!(watched.state, Recovery::Dialling { .. }) =>
                {
                    watched.keepers > 0
                }
                _ => return,
            }
        };
        // One look at the connection map: a live connection means the dial is not over, and a
        // closed one is what the dial left behind.
        let dead = {
            let pairs = self.pairs();
            match pairs.get(peer) {
                None => None,
                Some(live) => match live.connection.close_reason() {
                    None => return,
                    Some(_) => Some((live.connection.clone(), Arc::clone(&live.watch))),
                },
            }
        };
        if let Some((connection, watch)) = dead {
            self.judge_dead(peer, &connection, &watch);
        }
        // Whether or not there was a connection to judge — it may have been judged already —
        // the state must stop claiming a dial. A state the judgement already moved is left
        // alone: a connection that died after its dial is a strike the policy counted, not an
        // abandoned dial.
        let now = self.runtime.now();
        let mut retry = self.retry();
        if let Some(watched) = retry.get_mut(peer)
            && watched.dialing.is_none()
            && matches!(watched.state, Recovery::Dialling { .. })
        {
            if keeper {
                watched.state.settled(now);
            } else {
                watched.state = Recovery::Unwatched;
            }
        }
    }

    /// Fold one change into `peer`'s recovery state, recording a state for a pair that has none.
    fn transition(&self, peer: PeerId, change: impl FnOnce(&mut Recovery)) {
        let mut retry = self.retry();
        change(&mut retry.entry(peer).or_insert_with(Watched::unwatched).state);
    }

    /// The addresses the record remembers for `peer`, newest first, and empty when it remembers
    /// none.
    ///
    /// A dial tries all of them at once, so the order is the order they are reported in rather
    /// than a schedule; see [`crate::peer::RecordStore::record_address`] for what may be written
    /// and how the list is kept.
    fn remembered(&self, peer: &PeerId) -> Vec<SocketAddr> {
        self.store
            .get(peer)
            .map(|record| record.addresses().to_vec())
            .unwrap_or_default()
    }

    /// Whether this machine has anywhere to dial `peer`: a beacon that could look it up, or an
    /// address the record remembers. One predicate, because the keeper's check before a dial
    /// and [`Self::ensure`]'s answer for a stopped pair must not disagree about the one stop a
    /// service path writes.
    fn somewhere_to_dial(&self, peer: &PeerId) -> bool {
        self.beacon().is_some() || !self.remembered(peer).is_empty()
    }

    /// The beacon this machine can reach, if it has one: the manager's own handle, or the one
    /// its presence speaks to.
    ///
    /// A manager given a presence was given a beacon with it — the presence is one machine's
    /// registration on one — so a manager built without a beacon of its own still has one to ask,
    /// and [`Self::somewhere_to_dial`] must not call that machine's pair unreachable.
    fn beacon(&self) -> Option<&Beacon> {
        self.beacon
            .as_ref()
            .or_else(|| self.presence.as_ref().map(|presence| presence.beacon()))
    }

    /// The generation of the last coordination payload from `peer`, and zero when none arrived.
    ///
    /// The keeper reads this before its trust check and hands it to the wait: a payload that
    /// arrives during the round carries a later generation, so the wait returns at once instead
    /// of sleeping through it.
    fn coordination_generation(&self, peer: &PeerId) -> u64 {
        self.presence
            .as_ref()
            .and_then(|presence| presence.candidates(peer))
            .map_or(0, |(_, generation)| generation)
    }

    /// A coordination payload from `peer` asks for a punch: make the pair's next dial due,
    /// keeping the episode. At most once per [`PUNCH_REARM`]; a pair whose episode is used up is
    /// not re-armed (the slow re-check is not a punch cadence). Never starts a dial of its own.
    ///
    /// Only a wait is moved. A pair that is dialling, connected, stopped or watched by nobody is
    /// left alone: the first is already doing what the payload asks, the second needs nothing,
    /// the third is a decision a payload does not overrule, and the fourth has no episode for a
    /// dial to belong to.
    ///
    /// Every honoured payload stamps, whether or not it moves a wait: the interval is what bounds
    /// how often a payload can move a wait. It bounds nothing else. A payload reaches this method
    /// only when the presence handed this machine a candidate list from that peer, so it comes
    /// from a paired machine; one whose trust has been withdrawn since is refused after the trust
    /// read below, and still costs that one read. The keeper's own read at the top of its round is
    /// the second line, so a peer this machine does not trust cannot turn a payload into a dial
    /// even if this check were missed. A payload also ends the keeper's wait, whose next round
    /// reads the record before it dials — its ordinary business, and the price of never dialling on
    /// a payload's word. The dial pacing is what the interval is for.
    fn rearm(&self, peer: &PeerId) {
        let now = self.runtime.now();
        if self
            .retry()
            .get(peer)
            .and_then(|watched| watched.rearmed)
            .is_some_and(|rearmed| now.saturating_duration_since(rearmed) < PUNCH_REARM)
        {
            return;
        }
        // A payload from a machine this one does not trust is not honoured at all: it can cause
        // no dial and no re-arm, so the record is read before the state is touched. The keeper
        // reads it again on its next round; this is the read that makes the rule true for the
        // instant the payload arrives.
        if !matches!(self.standing(peer), RecordRead::Trusted(_)) {
            return;
        }
        // A dial nobody finished is settled first: the state a payload re-arms must not be one
        // that only still reads "dialling" because its caller went away.
        self.settle_stale(peer);
        let mut retry = self.retry();
        let watched = retry.entry(*peer).or_insert_with(Watched::unwatched);
        watched.rearmed = Some(now);
        if matches!(watched.state, Recovery::Waiting { .. }) {
            watched.state.hurry(now);
        }
    }

    /// Wait one round, or until a coordination payload from `peer` arrives, whichever is first.
    ///
    /// A payload is a request to punch, so the round ends early and [`Self::rearm`] makes the
    /// pair's next dial due; the loop then asks the record and the policy again, which is what
    /// makes a withdrawn peer cause no dial. The wait is the same timer either way: a payload
    /// that never comes costs the round, and a dropped keeper ends both halves.
    async fn pause_or_punch(&self, peer: &PeerId, generation: u64, for_at_most: Duration) {
        let Some(presence) = &self.presence else {
            pause(self, for_at_most).await;
            return;
        };
        let fresh = presence.wait_for_candidates(peer, generation, for_at_most);
        if let traverse::Either::Second(Some(_)) =
            traverse::race2(pause(self, for_at_most), fresh).await
        {
            self.rearm(peer);
        }
    }

    /// What one read of `peer`'s record means for this machine's trust, from the record on disk.
    ///
    /// The one place the crate decides what a record read means: a dial, an accepted connection,
    /// a keeper's round and the action layer all ask here, so they cannot disagree about it. It
    /// costs one small read. A fault that may pass is folded into the pair's state once, here, so
    /// the answer and the readable state cannot disagree.
    ///
    /// A record this build must not trust — insecure, malformed, or too large — is answered with
    /// the read's own refusal: the manager fails closed, the cause points a person at the record
    /// rather than at a pairing that was never made, and the pair's recovery stops.
    ///
    /// A fault that may pass is the other answer. A read the operating system refused this
    /// instant still trusts nothing — nothing is trusted on a file nobody could read — but it is
    /// this machine's fault and not the peer's, so it is deferred rather than counted, and a live
    /// connection stays up.
    pub(crate) fn standing(&self, peer: &PeerId) -> RecordRead {
        let limits = self.store.limits();
        let record = match self.store.reread(peer) {
            Ok(record) => record,
            Err(error) if error.deferrable() => {
                let detail = error.to_string();
                let now = self.runtime.now();
                let failure = ConnectFailure::Deferred {
                    peer: peer.fingerprint(),
                    detail: detail.clone(),
                };
                self.transition(*peer, |state| state.deferred(now, failure));
                return RecordRead::Deferred { detail };
            }
            Err(error) => return RecordRead::Unreadable(error),
        };
        let Some(record) = record else {
            return RecordRead::Refused(NotTrustedCause::NoRecord);
        };
        // One predicate decides whether the record is trust and, when it is not, which of the
        // three reasons it is: a fourth reason becomes a compile error here rather than falling
        // into "no record".
        match record.untrusted(&limits) {
            None => RecordRead::Trusted(record),
            Some(Untrusted::Withdrawn(_)) => RecordRead::Refused(NotTrustedCause::Withdrawn),
            Some(Untrusted::Closed(_)) => RecordRead::Refused(NotTrustedCause::Closed),
            Some(Untrusted::NotPaired(_)) => RecordRead::Refused(NotTrustedCause::NoRecord),
        }
    }

    /// Remember the address a completed handshake proved.
    ///
    /// The rule for what may be written is [`crate::peer::PeerRecord::last_address`]'s: the
    /// source address of an accepted connection, or the address a dial completed at. Both are
    /// authenticated data — the peer answered there with the key this machine trusts — and
    /// neither a hint nor a candidate nor the beacon's observation is, which is why nothing else
    /// calls this.
    ///
    /// Best effort on purpose: the address is a hint that saves a beacon trip, not identity — the
    /// key is checked on every handshake — so a record that cannot be written is a hint lost, not
    /// a connection refused. The write, and the task it runs on, are the module's "Accepting"
    /// note; a dial's write runs on the caller's task, which is already off the accept loop.
    /// [`Self::forget_wrong_keys`] is the other direction: an address the record remembers and
    /// which answers with another machine's key is dropped.
    fn note_address(&self, peer: &PeerId, address: SocketAddr) {
        let _ = self.store.record_address(peer, address);
    }

    /// Stop remembering every address this dial tried that answered with a key which is not the
    /// peer's.
    ///
    /// [`ConnectFailure::WrongPeer`] states the rule and why a failed write costs only the same
    /// answer once more, and [`RecordStore::forget_address`] what dropping one does to the pair;
    /// this is where the addresses that earned it are dropped.
    fn forget_wrong_keys(&self, peer: &PeerId, tried: &[(SocketAddr, AddressError)]) {
        for (address, error) in tried {
            if matches!(error, AddressError::WrongPeer { .. }) {
                let _ = self.store.forget_address(peer, *address);
            }
        }
    }

    /// Start the manager's liveness reader, once per manager, and only when this machine has a
    /// keep-alive: without one nothing this machine sends would make a silent peer answer, so
    /// the reading is never asked for.
    ///
    /// Started on the first adoption rather than in [`Self::new`], so a manager that never gets a
    /// connection never runs a reader with nothing to sample. The reader holds the connection
    /// map weakly, so it ends when the manager is dropped — the moment nothing can ask it again.
    /// Every pass is stamped in [`Self::reader_heard`]'s record, including a pass with no
    /// connections, because a running reader is what makes the bound a reading rather than a
    /// promise.
    fn start_liveness(&self) {
        if self.keep_alive.is_none() {
            return;
        }
        {
            let mut reader = self
                .reader
                .lock()
                .expect("the reader state is not poisoned");
            if reader.started {
                return;
            }
            reader.started = true;
        }
        let pairs = Arc::downgrade(&self.pairs);
        let reader = Arc::clone(&self.reader);
        let runtime = Arc::clone(&self.runtime);
        let polled = Arc::clone(&runtime);
        runtime.spawn(Box::pin(async move {
            loop {
                sleep(&*polled, LIVENESS_POLL).await;
                let Some(pairs) = pairs.upgrade() else {
                    return;
                };
                let now = polled.now();
                // The map is held only to take a copy: sampling happens outside it, so a
                // second of reading never stands between a caller and `live` or `traffic`.
                let sampling: Vec<(Connection, Arc<Watch>)> = {
                    let pairs = pairs.lock().expect("the connection map is not poisoned");
                    pairs
                        .values()
                        .map(|live| (live.connection.clone(), Arc::clone(&live.watch)))
                        .collect()
                };
                for (connection, watch) in sampling {
                    watch
                        .life
                        .lock()
                        .expect("the life count is not poisoned")
                        .sample(&connection, now);
                }
                reader
                    .lock()
                    .expect("the reader state is not poisoned")
                    .pass = Some(now);
            }
        }));
    }

    /// Run this machine's half of the binding exchange on a kept connection, on its
    /// own task.
    ///
    /// The exchange is the manager's handshake, not the pair's traffic: it never delays adoption,
    /// never fails a connection and never closes one. What it writes is measured and kept in the
    /// connection's [`Watch`], so a connection that only exchanged its binding and then died is
    /// judged as one that carried nothing. The local fact is read from the store this manager
    /// holds, which the reach that adopted the connection has just re-read from disk: a binding
    /// written before the connection is what travels. A binding changed while the connection is up
    /// is a reconnection, and [`Self::disconnect`] is how the caller makes it one.
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
            // Marked after the claim is kept: the layers above speak once this is set, and
            // a request offered before the claim landed would find no pair to name.
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
    ///
    /// The connection stays in the manager's map as the last one it adopted, closed, so
    /// the keeper judges its loss like any other: a connection closed this way before it
    /// carried anything is one dial of the pair's recovery, and one that had carried
    /// something ends the run of dials.
    pub fn disconnect(&self, peer: &PeerId) -> bool {
        let pairs = self.pairs();
        // A connection that has already closed is not one there is to close, which is what
        // the answer promises.
        let Some(live) = open(&pairs, peer) else {
            return false;
        };
        live.connection
            .close(0u32.into(), RECONNECT_CAUSE.as_bytes());
        true
    }

    /// Try one address and prove the handshake is the peer this machine asked for.
    ///
    /// One *dial* is [`Self::try_peer`], which may try several addresses; this is the one
    /// address inside it, and its error is [`AddressError`] for that reason.
    async fn try_address(
        &self,
        endpoint: &Endpoint,
        address: SocketAddr,
        peer: &Fingerprint,
        budget: Duration,
    ) -> Result<Connection, AddressError> {
        let connecting = endpoint
            .connect(address, SERVER_NAME)
            .map_err(|error| AddressError::Open(error.to_string()))?;
        let connection = match timeout(&*self.runtime, budget, connecting).await {
            Some(Ok(connection)) => connection,
            Some(Err(error)) => return Err(AddressError::Handshake(error.to_string())),
            None => return Err(AddressError::TimedOut),
        };
        let presented = presented(&connection).ok_or(AddressError::NoIdentity)?;
        if presented != *peer {
            connection.close(0u32.into(), b"not the peer this machine asked for");
            return Err(AddressError::WrongPeer {
                expected: *peer,
                presented,
            });
        }
        Ok(connection)
    }

    /// Keep one connection for the pair, by the rule the module states.
    ///
    /// The answer is the connection the pair kept and whether it is the one this call
    /// passed in; `None` when neither can be kept — the tie-break cannot be computed, or the
    /// connection it kept has already closed. The reason is not carried: both are the same
    /// answer to the caller, and the connection it did not keep is closed with it.
    ///
    /// One thing outranks the rule: a connection that has shown no sign of life for this
    /// machine's liveness bound — [`VANISH_BOUND`], or twice the keep-alive when that is
    /// slower, exactly as the keeper's round applies it — is not a candidate beside a fresh
    /// one. A connection whose peer has vanished looks alive until the transport declares it
    /// dead, and the rule — which reads only who started what — would otherwise keep it and
    /// close a connection that works. The test reads the datagrams the peer has already
    /// sent, sampled by the manager's own reader, as the module's note on liveness requires.
    /// It needs a keep-alive to mean anything — without one nothing this machine sends makes
    /// a silent peer answer — and is applied only when this machine has one, exactly as the
    /// keeper's round applies it.
    fn adopt(
        &self,
        peer: PeerId,
        connection: Connection,
        started_by: Started,
    ) -> Option<(Connection, bool, Arc<Watch>)> {
        self.start_liveness();
        let now = self.runtime.now();
        let preferred = if self.me < peer {
            Started::Here
        } else {
            Started::There
        };
        let mut pairs = self.pairs();
        let Some(existing) = pairs.remove(&peer) else {
            let live = Live::new(connection, started_by, now);
            let answer = (live.connection.clone(), true, live.watch.clone());
            pairs.insert(peer, live);
            return Some(answer);
        };
        // A connection that died before the keeper looked is judged here, before its entry
        // is replaced: a dial whose connection died must not escape the settle window just
        // because another dial finished first. A connection this call is about to drop
        // because the rule prefers the new one is not judged — losing the tie-break is not
        // a failure of the pair.
        self.judge_dead(&peer, &existing.connection, &existing.watch);
        let gone =
            existing.connection.close_reason().is_some() || self.vanished(&existing.watch, now);
        let keep_new = if gone {
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
            return None;
        };
        let (kept, dropped) = if keep_new {
            (Live::new(connection, started_by, now), existing)
        } else {
            (existing, Live::new(connection, started_by, now))
        };
        // A connection that has already closed keeps the reason it ended with: closing it
        // through the handle would rewrite that reason as a local close, and the keeper may not
        // have judged it yet.
        if dropped.connection.close_reason().is_none() {
            // Losing the tie-break is not a failed dial, and a keeper watching the connection this
            // call drops must not count it as one: a punch dials several addresses at once and
            // every one but the pair's is superseded here, so marking it judged is what keeps
            // eight candidates from spending eight dials of the episode.
            dropped.watch.judged.store(true, Ordering::SeqCst);
            dropped
                .connection
                .close(0u32.into(), SUPERSEDED_CAUSE.as_bytes());
        }
        if kept.connection.close_reason().is_some() {
            return None;
        }
        let answer = (kept.connection.clone(), keep_new, kept.watch.clone());
        pairs.insert(peer, kept);
        Some(answer)
    }

    fn pairs(&self) -> MutexGuard<'_, BTreeMap<PeerId, Live>> {
        self.pairs
            .lock()
            .expect("the connection map is not poisoned")
    }

    fn retry(&self) -> MutexGuard<'_, BTreeMap<PeerId, Watched>> {
        self.retry.lock().expect("the recovery map is not poisoned")
    }
}

/// One pair's recovery state, and what the manager knows about the dials around it.
///
/// `dialing` is what tells a state of [`Recovery::Dialling`] that means "a dial is running"
/// from one that means "a dial nobody finished": only the second is settled by the next
/// reader. It is a token rather than a flag because a dial gives its claim back with its
/// outcome in [`Connections::fold`] and its guard is dropped afterwards: a dial that begins
/// in that instant — nothing forbids it once the claim is gone — must not have its own claim
/// cleared by the older dial's end. It lives beside the state under the one lock so the two
/// cannot disagree.
struct Watched {
    state: Recovery,
    /// The dial in flight for this pair, if there is one, by its token.
    dialing: Option<u64>,
    /// Which dial of the episode is in flight; only meaningful while `dialing` is `Some`.
    dial: u32,
    /// The token the next dial takes; never reused.
    token: u64,
    /// How many keepers are running for the pair. A wait nobody watches is not a retry, and a
    /// caller may run the keeper more than once, so this counts rather than flags.
    keepers: usize,
    /// When a stop's cause was last asked about; see [`Connections::stop_due`].
    checked: Option<Instant>,
    /// When a coordination payload last made the next dial due; see [`Connections::rearm`].
    rearmed: Option<Instant>,
}

impl Watched {
    /// A pair nothing has happened to yet.
    fn unwatched() -> Self {
        Self {
            state: Recovery::Unwatched,
            dialing: None,
            dial: 0,
            token: 0,
            keepers: 0,
            checked: None,
            rearmed: None,
        }
    }

    /// What the policy says about the pair, with a dial in flight reported as dialling.
    ///
    /// A stop is a decision and outranks a dial in flight: a service path's dial can end in
    /// one, and the stop is the answer from then on.
    fn report(&self) -> Recovery {
        // `Unwatched` cannot hold a claim: a fresh entry has none, `begin` replaces the state
        // with `Dialling` when it takes one, and the only writer of `Unwatched` is the
        // abandoned-dial settlement, which runs with the claim already given back.
        if self.dialing.is_some()
            && matches!(
                self.state,
                Recovery::Waiting { .. } | Recovery::Exhausted { .. }
            )
        {
            return Recovery::Dialling { dial: self.dial };
        }
        self.state.clone()
    }

    /// Whether a stopped pair's cause is due to be asked about again: at most once a round, so
    /// a queue calling [`Connections::ensure`] every second does not cost a record read a
    /// second.
    fn stop_due(&mut self, now: Instant) -> bool {
        if let Some(checked) = self.checked
            && now.saturating_duration_since(checked) < TRUST_POLL
        {
            return false;
        }
        self.checked = Some(now);
        true
    }
}

/// One dial in flight, given back however its future ends.
///
/// A dial lives across awaits — a handshake, a beacon lookup — and the caller's task can be
/// dropped at any of them: a service that stops, a keeper's task cancelled, a caller's own
/// budget spent. Clearing the claim is what lets the next reader give the pair its next dial
/// instead of leaving it marked as dialling for ever. The token is this dial's own, so a dial
/// that begins after this one has been given its wait cannot have its claim cleared by the
/// older dial's end.
struct Dialling<'a> {
    connections: &'a Connections,
    peer: PeerId,
    token: u64,
}

impl Drop for Dialling<'_> {
    fn drop(&mut self) {
        let mut retry = self.connections.retry();
        if let Some(watched) = retry.get_mut(&self.peer)
            && watched.dialing == Some(self.token)
        {
            watched.dialing = None;
        }
    }
}

/// One keeper's hold on a pair: a state that says a dial is coming is one somebody will make
/// for as long as this exists, and no longer.
///
/// Dropping the keeper — a caller's task cancelled — must stop the pair claiming a retry, so
/// the count is given back however the future ends. It is a count because a caller may run the
/// keeper for one pair more than once; the pair is watched while any of them lives.
struct Kept<'a> {
    connections: &'a Connections,
    peer: PeerId,
}

impl Kept<'_> {
    /// Take a keeper's place for `peer`, starting a fresh episode if this is the pair's first
    /// keeper.
    ///
    /// A caller that runs the keeper again is a person's answer to whatever stopped the last
    /// one, so what stopped it is re-derived from the record and the configuration on the
    /// first round rather than remembered. A second keeper for a pair already watched is not
    /// that answer: it must not reset an episode a peer that keeps dropping a connection is
    /// spending.
    fn new(connections: &Connections, peer: PeerId, now: Instant) -> Kept<'_> {
        let mut retry = connections.retry();
        let watched = retry.entry(peer).or_insert_with(Watched::unwatched);
        if watched.keepers == 0 {
            watched.state.restarted(now);
            watched.checked = None;
        }
        watched.keepers = watched.keepers.saturating_add(1);
        Kept { connections, peer }
    }
}

impl Drop for Kept<'_> {
    fn drop(&mut self) {
        if let Some(watched) = self.connections.retry().get_mut(&self.peer) {
            watched.keepers = watched.keepers.saturating_sub(1);
        }
    }
}

/// One incoming connection's place in [`ACCEPT_IN_FLIGHT`], given back however its task ends.
///
/// A plain decrement at the end of the task would leak a place when the task is aborted —
/// a runtime shutting down — and enough leaks would stop the accept loop for good.
struct InFlight(Arc<Connections>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
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
/// stream frames the binding exchange wrote and those of the last offer or action round.
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
/// The message, action and transfer layers are measured the same way and for the same
/// reason: a request in flight is this machine's own act, and one that finished is measured
/// back to where the frames stood when the round ended, so neither counts as the pair's use.
/// A request the peer *accepted* is different — the peer acted on it, which is the pair being
/// alive — so it counts however the frames are read. An answer that took nothing does not
/// count: see [`Traffic::took`]. A transfer is the same measurement one step later: it counts
/// once a byte has moved, and a refusal, an unreadable frame or a failure before the first
/// byte does not. The receiving half is not measured at all: a stream the peer opened is the
/// peer acting, and answering it is the pair being used, so only this machine's own rounds are
/// discounted.
fn carried(connection: &Connection, watch: &Watch) -> bool {
    if watch.taken.load(Ordering::SeqCst) > 0 {
        return true;
    }
    if watch.rounds.load(Ordering::SeqCst) > 0 {
        return false;
    }
    let quiet = *watch.quiet.lock().expect("the offer round is not poisoned");
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
/// machine's business and is in the [`NotTrustedCause`] the caller is given. A deferral is
/// not a cause: it is closed with [`DEFERRED_CAUSE`], which says what this machine met.
fn cause_text(cause: &NotTrustedCause) -> &'static [u8] {
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
/// it carried anything and inside [`KEEPER_SETTLE`], whatever ended it, and a timeout
/// is not counted at all — it is the detail that says what happened to it.
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

/// What [`Connections::disconnect`] closes the pair's connection with: the connection
/// level changed, and the next connection carries it.
const RECONNECT_CAUSE: &str = "the pair is reconnecting";

/// What a connection is closed with when a person withdrew this machine's trust in the
/// pair.
const NOT_TRUSTED_CAUSE: &str = "this machine's trust in the pair is withdrawn";

/// What a connection is closed with when this machine could not read the peer's record just
/// now.
///
/// Not a refusal: the peer that sees it counts a dial of its own, which is the fault's cost and
/// passes with the fault.
const DEFERRED_CAUSE: &str = "this machine could not read the peer's record just now";

/// What the keeper closes a connection with when the peer has stopped answering for this
/// machine's liveness bound — see [`Connections::vanish_bound`]: the pair will dial again,
/// and the far side learns why.
const VANISHED_CAUSE: &str = "the peer stopped answering";

/// The cause of a failed beacon leg, naming the addresses tried before it.
///
/// The failures are classes; this is the detail a reader acts on, so a
/// remembered address that did not answer is named rather than folded away.
fn cause(tried: &[(SocketAddr, AddressError)], detail: &str) -> String {
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

/// `detail` for a beacon leg that failed, with the blocked-UDP clause added only where the network
/// can explain the failure.
///
/// Only [`BeaconError::Unavailable`] leaves the network as an explanation: the bound passed with
/// no handshake, or the session or the stream ended without an answer. Every other answer — a
/// version mismatch, a malformed frame, a refusal — came from the beacon, and a transport error
/// may be an alert it sent, so neither leaves the network as the cause. A refusal must not name a
/// cause the crate just disproved.
fn unreachable(detail: String, error: &BeaconError) -> String {
    match error {
        BeaconError::Unavailable => format!("{detail}; this network may block UDP"),
        _ => detail,
    }
}

/// The set a punch dials: the beacon's observed address first and unfiltered, then the peer's
/// candidates, filtered by [`traverse::acceptable`] and deduplicated, cut at
/// [`crate::peer::MAX_CANDIDATES`]. Which sources are filtered, and why, is
/// [`Connections::declares`]'s rule.
fn punch_set(
    observed: Option<SocketAddr>,
    theirs: Option<&Candidates>,
    declared: &[SocketAddr],
    local: Option<SocketAddr>,
) -> Vec<SocketAddr> {
    let accepted = theirs
        .into_iter()
        .flat_map(Candidates::addresses)
        .copied()
        .filter(|candidate| traverse::acceptable(*candidate, declared, local));
    // The ceiling and the deduplication are [`Candidates`]'s, so the most a punch may dial is
    // stated once.
    Candidates::new(observed.into_iter().chain(accepted))
        .addresses()
        .to_vec()
}

/// The refusal a punch answers when every address of its set failed.
///
/// The set is every address this dial tried, this stage's included, in the order it tried them: a
/// reader acts on where the peer was not.
fn no_path(
    peer: &Fingerprint,
    tried: &[(SocketAddr, AddressError)],
    completed: bool,
    introduced: &Result<(), BeaconError>,
) -> ConnectFailure {
    ConnectFailure::NoDirectPath {
        peer: *peer,
        // The addresses are the refusal's own field, so the cause does not repeat them:
        // one sentence, one list.
        candidates: tried.iter().map(|(address, _)| *address).collect(),
        cause: punch_cause(tried, completed, introduced),
    }
}

/// The wrong key one of this dial's addresses proved, if one did.
///
/// It outranks every other answer, the pair's own live connection included: the pair being up
/// says nothing about an address this machine was told is the peer's and which answered with
/// another machine's key. [`Connections::try_peer`] applies it once, where every arm of the dial
/// meets it.
fn wrong_key(peer: &Fingerprint, tried: &[(SocketAddr, AddressError)]) -> Option<ConnectFailure> {
    tried.iter().find_map(|(address, error)| match error {
        AddressError::WrongPeer { presented, .. } => Some(ConnectFailure::WrongPeer {
            peer: *peer,
            presented: *presented,
            address: *address,
        }),
        _ => None,
    })
}

/// The sentence a punch that dialled its whole set and reached nothing ends its cause with.
///
/// The beacon answered — a lookup that failed returns before any candidate is dialled — so the
/// reason is never "the beacon is unreachable", and the fact that it has no registration for the
/// peer is a fact about the lookup and not the reason a candidate did not answer. An
/// introduction that was not delivered is named after the sentence rather than as its cause: a
/// candidate list that never arrived is one dial without the peer's addresses, not a path that
/// was tried and refused.
///
/// The blocked-UDP clause belongs only where nothing answered at all: an address whose handshake
/// completed and whose connection the pair kept none of — `completed`, whether the tie-break
/// dropped it or the far side's accept closed it — or one that answered with a failed handshake or
/// no key has not been silent, and naming a blocked network there would name a cause the dial has
/// just ruled out. The advice to try another network belongs with it, for the same reason: it is
/// advice about a network that failed, and a completed handshake is the network working.
fn punch_cause(
    tried: &[(SocketAddr, AddressError)],
    completed: bool,
    introduced: &Result<(), BeaconError>,
) -> String {
    let mut text = if completed {
        // A handshake completed and the pair kept nothing: the tie-break dropped it, or the far
        // side's accept closed it. Either way the network worked, and there is no network to
        // advise a person away from.
        "an address completed a handshake and the pair kept no connection".to_owned()
    } else if !tried.is_empty()
        && tried
            .iter()
            .all(|(_, error)| matches!(error, AddressError::TimedOut))
    {
        "this network may block UDP towards the peer; another network may work".to_owned()
    } else {
        // An address answered, with a handshake that failed or no key: the network is not what is
        // shown to have failed, so no advice aimed at one is given.
        "the addresses did not complete a handshake with the peer".to_owned()
    };
    if let Err(error) = introduced {
        let _ = write!(text, "; the candidate list was not delivered ({error})");
    }
    text
}

/// Keep one address this dial tried, with the first fault it answered with.
///
/// One address can be dialled twice inside one dial — the beacon's observed address may be one
/// the record already remembers — and a refusal names it once: a second fault from the same
/// address says nothing the first does not, and a list of repeats is a list a reader has to
/// deduplicate to act on. The one exception is a wrong key, which replaces an earlier fault
/// rather than being folded away: it is the fault that outranks the rest.
fn note(tried: &mut Vec<(SocketAddr, AddressError)>, address: SocketAddr, error: AddressError) {
    let Some((_, known)) = tried.iter_mut().find(|(known, _)| *known == address) else {
        tried.push((address, error));
        return;
    };
    // A wrong key outranks an earlier fault from the same address: it is the one fault that
    // becomes an answer of its own, and a timeout recorded first must not hide it.
    if matches!(error, AddressError::WrongPeer { .. })
        && !matches!(known, AddressError::WrongPeer { .. })
    {
        *known = error;
    }
}

/// Why a connection manager could not be built.
///
/// Non-exhaustive: a new refusal is a new answer, and a product compiled against an earlier
/// version must still build.
#[non_exhaustive]
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

/// What both refusals say about their reach: they read this machine's transport, while over
/// the wire the effective timeout is the smaller of the two machines'.
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

/// Why one address did not become the pair's connection. Never reported outward as-is:
/// [`Connections::connect`] folds it into one of the failures a dial can decide — a
/// dial is never `NotTrusted`, which is decided before an address is chosen — and
/// [`AddressError::WrongPeer`] is the one that becomes an answer of its own. The word *dial*
/// is the pair's, one whole try; this is one of the addresses inside it.
#[derive(Clone, Debug)]
pub(crate) enum AddressError {
    Open(String),
    Handshake(String),
    /// No handshake within the dial's budget.
    TimedOut,
    NoIdentity,
    WrongPeer {
        expected: Fingerprint,
        presented: Fingerprint,
    },
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open(error) => write!(f, "the connection could not be opened: {error}"),
            Self::Handshake(error) => write!(f, "handshake: {error}"),
            Self::TimedOut => f.write_str("no handshake within the dial's budget"),
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
