//! One machine's presence at the beacon: one registration, kept alive by itself, and the one
//! reader of what the beacon pushes to it.
//!
//! The beacon keeps one registration per peer and the latest wins, so two sessions from one
//! machine displace each other. A registration made for a ceremony and closed with it would
//! leave the machine unfindable until something else registered; a refresh on another session
//! would move the registration to a session nobody reads, so a flight pushed to it would never
//! arrive. One session, held here, is the answer to both: every refresh is a request on the
//! same connection, and one reader takes everything the beacon pushes.
//!
//! # The registration keeps itself alive
//!
//! [`Presence::new`] starts the two tasks below on the runtime the caller handed the endpoint,
//! and they run for as long as the `Presence` exists. Dropping it ends both. A dial already in
//! flight is the one thing a drop does not cancel — it finishes first, within
//! [`BEACON_REQUEST_TIMEOUT`], and the endpoint handle that task carries goes with it. A product
//! that must have the socket back before that drops the presence and then closes and drops its own
//! endpoint handle: the connection and the dial end with it, both tasks finish, and the socket
//! goes. The beacon forgets the registration when the connection goes. Nothing else starts, stops
//! or refreshes it, so a product that pairs and runs no presence loop is still registered, and a
//! person comparing six symbols cannot lose the registration they are comparing under.
//!
//! The beacon forgets a registration when its lifetime passes, so the machine re-registers at a
//! third of the lifetime it was answered with — comfortably before the registration expires and
//! before the session's own idle timeout. A session that closes ends that wait at once, so the
//! next round dials instead of refreshing a connection that answers nothing. A beacon that is
//! down does not end the loop: it waits out the same growing gap a pair's recovery uses —
//! [`crate::peer::recovery`] — and opens a new session, so the machine registers itself again
//! once the beacon answers. [`Registration`] says which of the two is happening, so a product can
//! show "the beacon is not reachable" instead of looking as though nothing is wrong.
//!
//! No request dials. [`Presence::lookup`], [`Presence::observed_address`] and
//! [`Presence::introduce`] ride the machine's registration, and a request that finds no session
//! waits for one until its own bound — [`BEACON_REQUEST_TIMEOUT`] — runs out, and then answers
//! [`BeaconError::Unavailable`] rather than opening a session of its own: the retry cadence is the
//! keeper's, so a caller that asks again and again does not become it.
//!
//! # One reader, and where a payload goes
//!
//! The second task reads every introduction the beacon pushes, and what it does with one is
//! decided by the payload's own bytes before anything acts on it. There are three kinds and no
//! fourth.
//!
//! A *ceremony flight* — one of the closed set of pair messages — goes to the ceremony for the
//! peer it came from: [`Presence::flights`], never to another ceremony and never first-come. A
//! peer's flights wait for its ceremony in the order they arrive, which for this crate's ceremony
//! is the order they were sent — every flight is awaited before the next — [`MAX_PENDING`] of them
//! at most, because the next flight of an exchange is not a peer that gave up: taking the newer
//! one first would lose the step before it and end the ceremony as out of order. An opening from
//! a peer nobody waits on yet is held instead, one per peer, for [`MAX_HELD`] peers at most,
//! because the other machine may start the ceremony before this machine's person does;
//! [`Presence::openings`] takes those newest first, because an opening that has been sitting is
//! one whose initiator is likelier to have given up already. Only an opening is held: no other
//! flight can start a ceremony, so no other flight is worth keeping for one. A cancelled ceremony
//! takes its waiting slot with it, and the flights waiting in it go with the slot.
//!
//! A *coordination payload* is a candidate list, and it is never a ceremony flight: it is stored
//! here under the peer that sent it — 32 peers at most, the oldest evicted — and wakes whoever
//! waits for it, through `candidates` and `wait_for_candidates`. It is not delivered to a
//! ceremony even when one waits on that peer, it does not open one, and it is not written
//! anywhere durable: a candidate list is worth what the moment it arrived is worth, so one older
//! than `COORDINATION_FRESH` is not read at all.
//!
//! Anything else is *unrecognised* and is dropped: it wakes nobody, is stored nowhere and cannot
//! end a ceremony. That is a rule rather than a courtesy. An older build ends its ceremony on any
//! payload outside its closed set, so coordination is never sent to a peer while a ceremony with
//! it is running — `busy_with` is that question, and [`crate::peer::connect`] is the one sender —
//! and a payload this build does not understand has to be as harmless as one that never arrived.
//! A ceremony whose opening is still in flight is the one window this cannot see; it closes as
//! soon as the opening arrives, and the rule is what the crate can enforce rather than a promise
//! about a machine it has not heard from yet.
//!
//! A frame the reader refuses costs it nothing: the beacon relays what any machine hands it,
//! without looking at the signature, so the reader takes such a frame, drops it, and is ready for
//! the next one rather than sleeping out an idle period on a stranger's bad bytes.
//!
//! One rule decides whether a flight is a live one, on every path — handed to a person, or counted
//! as a ceremony the punch must not disturb — and it is the wait its sender is under: a machine
//! flight is dropped once it is older than `PAIR_FLIGHT_TIMEOUT`, while a confirmation is not,
//! because its sender waits for as long as the peer's person compares the same string — the
//! attempt's own lifetime, which the ceremony that claimed the peer bounds.
//!
//! A session a product opens for itself is not prevented from registering, and it would displace
//! the machine's registration: the crate cannot hold one registration per machine without
//! process-global state, which it does not have. The shape it offers is this type — build one
//! per machine, and reach the beacon through it.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use quinn::Runtime;

use crate::beacon::{BEACON_REQUEST_TIMEOUT, Beacon, BeaconError, Introduction, Session, timeout};
use crate::identity::PeerId;
use crate::peer::pair::{PAIR_FLIGHT_TIMEOUT, waits_for_the_attempt};
use crate::peer::recovery::{RECOVERY_DIALS, after, recheck};
use crate::peer::traverse::{self, Candidates};

/// How long a stored candidate list is used.
///
/// A list is worth what the moment it arrived is worth: the peer's mapping can move, so a list
/// older than this is treated as absent and a caller that needs one waits for a fresh one. A
/// minute is longer than any punch window and shorter than a registration's life, which is what
/// keeps a stale list from being dialled in place of the peer's current addresses.
const COORDINATION_FRESH: Duration = Duration::from_secs(60);

/// The shortest refresh interval: a third of a tiny lifetime must not become a
/// busy loop, so the wait never falls below this.
const MIN_REFRESH: Duration = Duration::from_secs(1);

/// How long the reader waits on a live session with nothing pushed before it looks at the
/// session again, so a session that was replaced is noticed.
const READER_IDLE: Duration = Duration::from_secs(10);

/// How many peers a candidate list is kept for: a chosen bound, enough for the peers a machine
/// is actually dialling and small enough that a stranger cannot fill this machine's memory by
/// sending payloads it never answers. The oldest entry is the one evicted, and a peer that sends
/// again replaces its own.
const MAX_COORDINATED: usize = 32;

/// How many peers an opening is held for: a chosen bound, enough for the ceremonies a person can
/// be starting at once and small enough that a stranger cannot fill this machine's memory. The
/// newest openings are the ones kept, and [`Presence::openings`] hands them out newest first.
pub const MAX_HELD: usize = 4;

/// How many of one peer's flights wait for its ceremony: a chosen bound, not a protocol limit.
/// One side of an attempt sends at most three flights, so four leaves room for one attempt plus
/// the first flight of a peer that started again, and a peer that keeps sending cannot grow this
/// machine's memory.
pub const MAX_PENDING: usize = 4;

/// How this machine's registration at the beacon stands, readable at any time.
///
/// Not durable: a restart registers again, which is the same answer a stored state would give and
/// one fewer thing that can be wrong on disk. The moment is the injected runtime's, and
/// [`Display`](fmt::Display) says what the state is rather than when, because an `Instant` has no
/// rendering of its own.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Registration {
    /// No answer has come back yet: the presence has not finished its first connect-and-register.
    /// It leaves this state for [`Self::Registered`] or [`Self::Unreachable`] when a dial answers.
    Idle,
    /// The last round registered on a session that was open then, and the keeper refreshes that
    /// registration before the beacon forgets it — it starts the next round at a third of the
    /// answered lifetime. A beacon that restarted, or lost the registration, is not visible here
    /// until that round answers.
    Registered,
    /// The beacon could not be reached or would not take the registration. `dials` is how many
    /// of this episode have failed and `last` is what the beacon or the transport said. Once the
    /// episode is used up the loop keeps trying at the slow re-check, and the display says the
    /// episode is used up rather than counting past the cap.
    Unreachable {
        /// When the wait after the failure ended. While the next try is in flight it is in the
        /// past, so it names the moment this machine started trying again.
        retry_at: Instant,
        /// How many dials this episode has made, at most [`RECOVERY_DIALS`].
        dials: u32,
        /// What the last one met.
        last: String,
    },
}

impl fmt::Display for Registration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Idle => f.write_str("no answer from the beacon yet"),
            Self::Registered => f.write_str("registered with the beacon"),
            Self::Unreachable { dials, last, .. } => {
                write!(f, "the beacon is not reachable ({last})")?;
                if *dials >= RECOVERY_DIALS {
                    write!(f, "; this episode's {RECOVERY_DIALS} dials are used up")
                } else {
                    write!(
                        f,
                        "; {dials} of this episode's {RECOVERY_DIALS} dials have failed"
                    )
                }
            }
        }
    }
}

/// One machine's registration at the beacon, and the one reader of what it pushes.
///
/// Build one per machine and keep it: it starts its own tasks, registers at once and registers
/// again before the beacon forgets it, for as long as the `Presence` exists. The endpoint the
/// [`Beacon`] was built over is the machine's, so the address the beacon observes is the one peers
/// can dial.
pub struct Presence {
    inner: Arc<Inner>,
}

impl fmt::Debug for Presence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Presence")
            .field("beacon", &self.inner.beacon)
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

impl Presence {
    /// Keep this machine registered from now on, on the runtime the endpoint runs on.
    ///
    /// # Panics
    ///
    /// If the runtime cannot spawn a task — `quinn::TokioRuntime` does when it is called outside
    /// a Tokio runtime.
    #[must_use]
    pub fn new(beacon: Beacon) -> Self {
        let inner = Arc::new(Inner {
            beacon,
            state: Mutex::new(Registration::Idle),
            live: Mutex::new(None),
            mail: Mutex::new(Mail::default()),
            changed: Gate::default(),
            coord: Mutex::new(HashMap::new()),
            coord_changed: Gate::default(),
            next_coord: AtomicU64::new(1),
            stopped: AtomicBool::new(false),
            next_id: AtomicU64::new(0),
        });
        let runtime = inner.runtime();
        runtime.spawn(Box::pin(keep(Arc::clone(&inner))));
        runtime.spawn(Box::pin(read(Arc::clone(&inner))));
        Self { inner }
    }

    /// How this machine's registration stands now.
    ///
    /// This is where a product reads a beacon outage: a ceremony that waits to be called keeps
    /// waiting for as long as its person might still start, so the state — not the ceremony's
    /// failure — is what says this machine cannot be reached by the other side at all.
    #[must_use]
    pub fn state(&self) -> Registration {
        self.inner
            .state
            .lock()
            .expect("the registration is not poisoned")
            .clone()
    }

    /// The runtime that measures every bound of this presence, so a caller can wait on it — the
    /// ceremony's flight bounds do.
    #[must_use]
    pub fn runtime(&self) -> &Arc<dyn Runtime> {
        self.inner.beacon.runtime()
    }

    /// Where `id` currently is, if it is registered at all.
    ///
    /// `Ok(None)` is the beacon's answer that it has no registration for the peer: it says
    /// nothing about the peer itself, and nothing about a payload that was not delivered.
    ///
    /// # Errors
    ///
    /// [`BeaconError::Unavailable`] when no session with the beacon could be had within
    /// [`BEACON_REQUEST_TIMEOUT`], or the beacon's refusal.
    pub async fn lookup(&self, id: &PeerId) -> Result<Option<SocketAddr>, BeaconError> {
        self.session().await?.lookup(id).await
    }

    /// This machine's own address, as the beacon observes it on the machine's session.
    ///
    /// # Errors
    ///
    /// [`BeaconError::Unavailable`] when no session with the beacon could be had within
    /// [`BEACON_REQUEST_TIMEOUT`], or the beacon's refusal.
    pub async fn observed_address(&self) -> Result<SocketAddr, BeaconError> {
        self.session().await?.observed_address().await
    }

    /// Hand `payload` to `to` on the machine's registration, signed by this machine's key.
    ///
    /// The beacon's answer that it did not hand the payload over is [`BeaconError::UnknownPeer`]:
    /// that is the beacon's answer about the delivery, and not a statement that the peer is not
    /// registered or not running. Nothing is kept for a later attempt.
    ///
    /// # Errors
    ///
    /// [`BeaconError::UnknownPeer`], [`BeaconError::PayloadTooLarge`],
    /// [`BeaconError::Unavailable`] when no session with the beacon could be had within
    /// [`BEACON_REQUEST_TIMEOUT`], or the beacon's refusal.
    pub async fn introduce(&self, to: PeerId, payload: &[u8]) -> Result<(), BeaconError> {
        self.session().await?.introduce(to, payload).await
    }

    /// The introductions the beacon pushes from `peer`, for a ceremony that knows who it is
    /// pairing with.
    ///
    /// The handle borrows this presence — it cannot outlive the registration it reads — and is
    /// the ceremony's claim on that peer: dropping the last handle for a peer takes the claim, and
    /// any flight waiting for it, with it. Its flights are handed over in the order the peer sent
    /// them.
    #[must_use]
    pub fn flights(&self, peer: PeerId) -> Flights<'_> {
        self.inner.mail().acquire(peer);
        Flights {
            inner: &self.inner,
            wait: Wait::Peer(peer),
        }
    }

    /// The openings the beacon pushes from peers no ceremony waits on, for a ceremony that does
    /// not know who will start with it.
    ///
    /// Taking one is how a responder learns who is calling, and it takes the newest: an opening
    /// that has been sitting is one whose initiator is likelier to have given up already, so the
    /// freshest gives the person the best chance of a comparison that still completes. The
    /// ceremony then takes [`Self::flights`] for that peer, so every later flight of the same
    /// ceremony arrives there and no flight of another peer's does.
    #[must_use]
    pub fn openings(&self) -> Flights<'_> {
        Flights {
            inner: &self.inner,
            wait: Wait::Any(self.inner.next_id()),
        }
    }

    /// The machine's live session, or a wait for one until [`BEACON_REQUEST_TIMEOUT`]: a request
    /// rides the machine's registration and never dials a second.
    async fn session(&self) -> Result<Session, BeaconError> {
        timeout(&**self.runtime(), BEACON_REQUEST_TIMEOUT, async {
            loop {
                // Read before the check: a session installed between the two moves the gate past
                // what was read, so the wait below returns at once instead of sleeping on it.
                let seen = self.inner.changed.generation();
                if let Some(session) = self.inner.session() {
                    return session;
                }
                self.inner.changed.wait_past(seen).await;
            }
        })
        .await
        .ok_or(BeaconError::Unavailable)
    }

    /// The candidates last heard from `peer`, and the generation they arrived at.
    ///
    /// The generation is what a caller reads before it sends its own list and hands to
    /// [`Self::wait_for_candidates`] afterwards: a payload that arrives between the two carries a
    /// later one, so the wait does not miss it. Nothing here reads the record — the presence has
    /// no store, and whether the peer is trusted is the manager's decision, made where the record
    /// is.
    pub(crate) fn candidates(&self, peer: &PeerId) -> Option<(Candidates, u64)> {
        let now = self.inner.runtime().now();
        self.inner
            .coord()
            .get(peer)
            .filter(|coordinated| {
                now.saturating_duration_since(coordinated.at) < COORDINATION_FRESH
            })
            .map(|coordinated| (coordinated.candidates.clone(), coordinated.generation))
    }

    /// Wait until a coordination payload from `peer` arrives at a generation past `after`, or
    /// until `within` runs out.
    ///
    /// Cancellable: dropping the future leaves nothing behind and wakes nobody. The gate is
    /// opened by every stored payload, another peer's included, so a wake that finds nothing new
    /// for this peer goes back to waiting rather than answering an empty list.
    pub(crate) async fn wait_for_candidates(
        &self,
        peer: &PeerId,
        after: u64,
        within: Duration,
    ) -> Option<Candidates> {
        timeout(&**self.runtime(), within, async {
            loop {
                // Read before the check, so a payload stored between the two moves the gate past
                // what was read and the wait below returns at once.
                let seen = self.inner.coord_changed.generation();
                if let Some((candidates, generation)) = self.candidates(peer)
                    && generation > after
                {
                    return candidates;
                }
                self.inner.coord_changed.wait_past(seen).await;
            }
        })
        .await
    }

    /// Whether a ceremony with `peer` is running here, or a fresh opening from it is held.
    ///
    /// Coordination is never sent to a peer while this is true. An older build ends its ceremony
    /// on any payload outside its closed set, so "must not be driven into aborting its ceremony"
    /// is met by not sending, not by hoping: a candidate list is worth one dial later, and a
    /// person's comparison is not. An opening whose sender has given up is not a ceremony — it is
    /// retired rather than left to hold the punch off for that peer — so the rule costs one
    /// attempt's worth of waiting and no more.
    pub(crate) fn busy_with(&self, peer: &PeerId) -> bool {
        let now = self.inner.runtime().now();
        self.inner.mail().busy_with(peer, now)
    }

    /// The beacon this presence speaks to: one session, one registration, one identity.
    ///
    /// The manager reads it to know that a machine keeping a presence has a beacon to ask, so a
    /// manager built without a beacon handle of its own still has one — and the address the beacon
    /// observes on this presence's registration is the one peers dial.
    pub(crate) fn beacon(&self) -> &Beacon {
        &self.inner.beacon
    }
}

impl Drop for Presence {
    fn drop(&mut self) {
        self.inner.stop();
    }
}

/// The introductions one ceremony waits on: those of one peer, or those of whoever starts.
///
/// It borrows the presence it reads, so a handle cannot outlive the machine's registration. It is
/// also that registration's claim on the peer: dropping it releases the claim, so a cancelled
/// ceremony cannot swallow the next flight of its peer. A handle that never took a peer stops
/// waiting for any opening as it goes, so no wake is delivered to a handle that is gone and a
/// machine that receives no further pushes holds no waker for one.
pub struct Flights<'a> {
    inner: &'a Inner,
    wait: Wait,
}

/// What a [`Flights`] handle waits for: one peer's flights, or whichever opening comes first.
enum Wait {
    /// The flights of one peer. The handle is that peer's claim, and its waker is filed in the
    /// peer's slot.
    Peer(PeerId),
    /// Whichever opening comes first, filed under this handle's id so a dropped handle takes its
    /// waker with it.
    Any(u64),
}

impl fmt::Debug for Flights<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("Flights");
        match self.wait {
            Wait::Peer(peer) => debug.field("peer", &peer),
            Wait::Any(id) => debug.field("any", &id),
        };
        debug.finish_non_exhaustive()
    }
}

impl Flights<'_> {
    /// The next introduction for this handle.
    ///
    /// The wait is the caller's: a ceremony that knows its peer bounds it with its own deadline,
    /// and one that waits to be called waits as long as its person does. One wait at a time: the
    /// handle files one waker for the flight it will take next.
    pub async fn next(&self) -> Introduction {
        std::future::poll_fn(|context| self.inner.poll_next(self, context)).await
    }
}

impl Drop for Flights<'_> {
    fn drop(&mut self) {
        let mut mail = self.inner.mail();
        match self.wait {
            Wait::Peer(peer) => mail.release(peer),
            Wait::Any(id) => mail.forget(id),
        }
    }
}

/// What the two tasks, the handles and the requests share.
struct Inner {
    beacon: Beacon,
    state: Mutex<Registration>,
    /// The live session, once a dial has answered and until it is found closed.
    live: Mutex<Option<Session>>,
    mail: Mutex<Mail>,
    /// Opened whenever the registration or the session changed, so a waiter looks again.
    changed: Gate,
    /// The candidate list each peer last sent, bounded at [`MAX_COORDINATED`].
    coord: Mutex<HashMap<PeerId, Coordinated>>,
    /// Opened whenever a coordination payload is stored, so a waiter looks again. The same gate
    /// as `changed` would do, but a payload is not a registration change and a request waiting
    /// for a session must not be woken by one.
    coord_changed: Gate,
    /// The generation the next stored payload takes; never reused, so "past what I have seen" is
    /// one question a single count can answer for every peer.
    next_coord: AtomicU64,
    stopped: AtomicBool,
    /// The next id for a handle waiting for any opening, so a cancelled one can be found among
    /// the waiters.
    next_id: AtomicU64,
}

/// The candidate list one peer last sent, when it arrived, and the generation it took.
struct Coordinated {
    candidates: Candidates,
    /// The generation this payload was stored at, from [`Inner::next_coord`].
    generation: u64,
    /// When it arrived: the oldest entry is what an eviction takes, and one older than
    /// [`COORDINATION_FRESH`] is not read at all.
    at: Instant,
}

/// The introductions that have arrived and not been taken, by the peer they wait on.
#[derive(Default)]
struct Mail {
    /// The flights of each peer a ceremony waits on, oldest first.
    waiting: HashMap<PeerId, Slot>,
    /// One opening per peer no ceremony waits on, in arrival order, so the newest is at the back.
    held_openings: VecDeque<Held>,
    /// The handles waiting for whichever opening comes first, by handle, so a cancelled one
    /// takes its waker with it.
    any_openings: HashMap<u64, Waker>,
}

#[derive(Default)]
struct Slot {
    /// The peer's flights its ceremony has not taken yet, oldest first. A flight is queued when
    /// it arrives, and the peer awaits each of its flights before it sends the next, so arrival
    /// order is the order they were sent: a second flight is the next step of one exchange as
    /// often as it is a peer that started again, and handing over the newer one first loses the
    /// step before it. [`MAX_PENDING`] bounds them, and [`Held::fresh`] drops the ones whose
    /// sender has given up.
    flights: VecDeque<Held>,
    wakers: Vec<Waker>,
    /// How many handles wait on this peer. The slot is the handles' claim, so it goes when the
    /// last of them does — a second ceremony that failed to start on the same peer must not take
    /// the first one's flights with it.
    waiters: usize,
}

/// A flight waiting for the ceremony it belongs to, with the moment it arrived: [`Held::fresh`]
/// is the one rule that decides whether it is handed over, wherever it waited.
struct Held {
    introduction: Introduction,
    at: Instant,
}

impl Held {
    /// Whether the attempt that sent this flight can still be waiting for the answer: a machine
    /// flight is waited for at most one [`PAIR_FLIGHT_TIMEOUT`], while a confirmation is not aged
    /// here at all — its sender waits for as long as the peer's person compares the same string,
    /// and the ceremony that takes it is what bounds the wait, by the attempt's lifetime.
    fn fresh(&self, now: Instant) -> bool {
        waits_for_the_attempt(self.introduction.payload())
            || now.saturating_duration_since(self.at) < PAIR_FLIGHT_TIMEOUT
    }
}

impl Mail {
    /// The slot of a peer a handle waits on: [`Self::acquire`] creates it and [`Self::release`]
    /// removes it with the last handle, so it exists for as long as a handle polls it.
    fn slot(&mut self, peer: PeerId) -> &mut Slot {
        self.waiting
            .get_mut(&peer)
            .expect("a waiting handle holds its peer's slot")
    }

    /// Hold an opening for a peer no ceremony waits on: the newest one is the one its person can
    /// still act on, and [`MAX_HELD`] is what keeps a stranger from filling this machine's memory.
    /// A peer that starts again replaces its own opening rather than taking a second place.
    fn hold(&mut self, held: Held) {
        let from = held.introduction.from();
        if self.take_held(from).is_none() && self.held_openings.len() >= MAX_HELD {
            self.held_openings.pop_front();
        }
        self.held_openings.push_back(held);
    }

    /// Take the opening held for `peer`, if one is.
    fn take_held(&mut self, peer: PeerId) -> Option<Held> {
        let index = self
            .held_openings
            .iter()
            .position(|held| held.introduction.from() == peer)?;
        self.held_openings.remove(index)
    }

    /// One more handle waits on `peer`, taking any opening held for it before the claim existed.
    fn acquire(&mut self, peer: PeerId) {
        let held = self.take_held(peer);
        let slot = self.waiting.entry(peer).or_default();
        if let Some(held) = held {
            // A held opening exists only while no slot does, so this slot is fresh: the opening
            // arrived before the claim and goes in front of whatever the slot later takes.
            slot.flights.push_front(held);
        }
        slot.waiters += 1;
    }

    /// A handle that never took a peer stops waiting for any opening.
    fn forget(&mut self, id: u64) {
        self.any_openings.remove(&id);
    }

    /// One handle stops waiting on `peer`; the slot goes with the last of them.
    fn release(&mut self, peer: PeerId) {
        let last = match self.waiting.get_mut(&peer) {
            Some(slot) => {
                slot.waiters = slot.waiters.saturating_sub(1);
                slot.waiters == 0
            }
            None => false,
        };
        if last {
            self.waiting.remove(&peer);
        }
    }

    /// Whether a ceremony with `peer` is running here, or a fresh opening from it is held.
    ///
    /// [`Held::fresh`] is the rule here as it is in [`Self::poll_next`]: an opening whose sender
    /// has given up is not a ceremony. A stale one is retired on the way, because a held opening
    /// otherwise leaves only through a [`Flights`] handle, a newer opening from the same peer or
    /// [`MAX_HELD`]'s eviction — so a person who started a pairing, walked away and never
    /// confirmed would hold the punch off for that peer for good.
    fn busy_with(&mut self, peer: &PeerId, now: Instant) -> bool {
        if self.waiting.contains_key(peer) {
            return true;
        }
        let mut busy = false;
        self.held_openings.retain(|held| {
            if held.introduction.from() != *peer {
                return true;
            }
            let fresh = held.fresh(now);
            busy |= fresh;
            fresh
        });
        busy
    }
}

impl Inner {
    fn runtime(&self) -> Arc<dyn Runtime> {
        Arc::clone(self.beacon.runtime())
    }

    fn mail(&self) -> MutexGuard<'_, Mail> {
        self.mail.lock().expect("the beacon's mail is not poisoned")
    }

    fn coord(&self) -> MutexGuard<'_, HashMap<PeerId, Coordinated>> {
        self.coord
            .lock()
            .expect("the coordination store is not poisoned")
    }

    fn stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    /// The next id for a handle waiting for any opening, so a cancelled one can be found among
    /// the waiters.
    fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// The live session, unless it has been closed: a closed connection answers nothing, so
    /// reporting it as live would turn a dead beacon into a silent one.
    fn session(&self) -> Option<Session> {
        self.live
            .lock()
            .expect("the session is not poisoned")
            .as_ref()
            .map(Session::handle)
            .filter(|session| !session.is_closed())
    }

    fn set_session(&self, session: Session) -> bool {
        let mut live = self.live.lock().expect("the session is not poisoned");
        // Under the same guard `stop` takes: a presence dropped while the dial was in flight owns
        // no session, and registering on one it opened would keep the machine findable after its
        // presence is gone.
        if self.stopped() {
            session.close(b"this machine's presence was dropped");
            return false;
        }
        *live = Some(session);
        drop(live);
        self.changed.open();
        true
    }

    /// Close the session that failed to register rather than only dropping it: an open connection
    /// the presence no longer holds is one the beacon still counts as this machine's registration,
    /// so a peer would be told the machine is reachable on a connection nobody reads.
    ///
    /// No case pins this: a failed registration either leaves the beacon's memory unchanged or has
    /// its entry replaced by the next round's, and a close sent to a beacon that is gone is lost
    /// with it. It is worth having because the failure path then leaves nothing behind that
    /// pretends to be a registration.
    fn clear_session(&self) {
        if let Some(session) = self
            .live
            .lock()
            .expect("the session is not poisoned")
            .take()
        {
            session.close(b"this machine's registration failed on this session");
        }
    }

    fn set(&self, state: Registration) {
        *self.state.lock().expect("the registration is not poisoned") = state;
        self.changed.open();
    }

    /// Close the session and stop both tasks: nothing keeps a registration alive once the
    /// presence is gone.
    fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Some(session) = self
            .live
            .lock()
            .expect("the session is not poisoned")
            .take()
        {
            session.close(b"this machine's presence was dropped");
        }
        self.changed.open();
    }

    /// Wait until something changed past `seen`, or for [`READER_IDLE`], whichever comes first.
    async fn pause(&self, seen: u64) {
        timeout(&*self.runtime(), READER_IDLE, self.changed.wait_past(seen)).await;
    }

    /// Where an introduction the beacon pushed goes, by the kind of its payload.
    fn route(&self, introduction: Introduction) {
        let from = introduction.from();
        match traverse::classify(introduction.payload()) {
            traverse::Payload::Coordination(candidates) => {
                self.store_coordination(from, candidates);
            }
            traverse::Payload::Ceremony { opens } => {
                let held = Held {
                    introduction,
                    at: self.runtime().now(),
                };
                self.deliver(from, held, opens);
            }
            traverse::Payload::Unknown => {}
        }
    }

    /// Store the candidate list `from` just sent, and wake whoever waits on one.
    ///
    /// The generation is taken before the entry is written, so a waiter that read the old one
    /// sees the new entry rather than a wake with nothing behind it. A peer that sends again
    /// replaces its own entry; a new peer at the bound takes the place of the oldest arrival. Any
    /// machine can send a list, so strangers can take the places — the cost is one punch window
    /// without the peer's candidates, and the beacon's observed address is dialled either way.
    fn store_coordination(&self, from: PeerId, candidates: Candidates) {
        let at = self.runtime().now();
        let generation = self.next_coord.fetch_add(1, Ordering::Relaxed);
        let mut coord = self.coord();
        if !coord.contains_key(&from) && coord.len() >= MAX_COORDINATED {
            let oldest = coord
                .iter()
                .min_by_key(|(_, coordinated)| coordinated.at)
                .map(|(peer, _)| *peer);
            if let Some(oldest) = oldest {
                coord.remove(&oldest);
            }
        }
        coord.insert(
            from,
            Coordinated {
                candidates,
                generation,
                at,
            },
        );
        drop(coord);
        self.coord_changed.open();
    }

    /// Hand a ceremony flight to the ceremony that waits for it, or hold it for one that may
    /// start, and wake whoever it is for.
    fn deliver(&self, from: PeerId, held: Held, opens: bool) {
        let wakers = {
            let mut mail = self.mail();
            if let Some(slot) = mail.waiting.get_mut(&from) {
                // In the order the peer sent them, and at the bound the oldest goes rather than
                // the newest: a peer that keeps sending has moved on from its oldest flight.
                if slot.flights.len() >= MAX_PENDING {
                    slot.flights.pop_front();
                }
                slot.flights.push_back(held);
                std::mem::take(&mut slot.wakers)
            } else if opens {
                mail.hold(held);
                std::mem::take(&mut mail.any_openings)
                    .into_values()
                    .collect()
            } else {
                // No ceremony waits on this peer, and nothing but an opening can start one, so
                // nothing would ever take it.
                Vec::new()
            }
        };
        for waker in wakers {
            waker.wake();
        }
    }

    fn poll_next(&self, flights: &Flights<'_>, context: &mut Context<'_>) -> Poll<Introduction> {
        let now = self.runtime().now();
        let mut mail = self.mail();
        let peer = match flights.wait {
            Wait::Any(id) => {
                // The newest opening a person can still act on: one that has been sitting is one
                // whose initiator is likelier to have given up already.
                while let Some(held) = mail.held_openings.pop_back() {
                    if held.fresh(now) {
                        return Poll::Ready(held.introduction);
                    }
                }
                mail.any_openings.insert(id, context.waker().clone());
                return Poll::Pending;
            }
            Wait::Peer(peer) => peer,
        };
        let slot = mail.slot(peer);
        // The oldest flight first. A flight whose sender has given up is dropped and the wait goes
        // on, rather than showing its person a comparison they cannot act on.
        while let Some(held) = slot.flights.pop_front() {
            if held.fresh(now) {
                return Poll::Ready(held.introduction);
            }
        }
        listen(&mut slot.wakers, context.waker());
        Poll::Pending
    }
}

/// Record `waker` as one to wake, if it is not already waiting there.
fn listen(wakers: &mut Vec<Waker>, waker: &Waker) {
    if !wakers.iter().any(|known| known.will_wake(waker)) {
        wakers.push(waker.clone());
    }
}

/// Keep the registration alive for as long as the presence exists.
async fn keep(inner: Arc<Inner>) {
    let mut dials = 0u32;
    loop {
        if inner.stopped() {
            return;
        }
        let session = if let Some(session) = inner.session() {
            session
        } else {
            let session = match inner.beacon.connect().await {
                Ok(session) => session,
                Err(error) => {
                    inner.unreachable(&mut dials, &error).await;
                    continue;
                }
            };
            // A drop that happened during the dial: the session it opened is nobody's, and
            // registering on it would keep the machine findable after its presence is gone.
            if !inner.set_session(session.handle()) {
                return;
            }
            session
        };
        match session.register().await {
            Ok(lifetime) => {
                dials = 0;
                inner.set(Registration::Registered);
                // A session that closes ends the wait, so the next round dials instead of
                // refreshing a connection that answers nothing.
                timeout(
                    &*inner.runtime(),
                    (lifetime / 3).max(MIN_REFRESH),
                    session.closed(),
                )
                .await;
            }
            Err(error) => {
                // The session is what failed, not the beacon's memory of it: a registration is
                // made over a connection, and the next round dials a new one.
                inner.clear_session();
                inner.unreachable(&mut dials, &error).await;
            }
        }
    }
}

/// Take everything the beacon pushes, for as long as the presence exists.
async fn read(inner: Arc<Inner>) {
    loop {
        // The generation is read before the checks, not after: a drop that lands between the check
        // and the wait opens the gate, so the wait below returns at once instead of parking for a
        // whole idle period. No case pins this — the harness's runtime cannot interleave a drop
        // inside one poll — and it is what keeps the reader from holding the endpoint handle for
        // that period on a runtime that can.
        let seen = inner.changed.generation();
        if inner.stopped() {
            return;
        }
        let Some(session) = inner.session() else {
            inner.pause(seen).await;
            continue;
        };
        match session.next_introduction_within(READER_IDLE).await {
            Ok(Some(introduction)) => inner.route(introduction),
            // The session could not answer: it closed, or a frame did not arrive in time. Waiting
            // out an idle period ends at once when the keeper replaces the session, so neither
            // case spins the reader nor stalls it past one period.
            Err(BeaconError::Unavailable) => inner.pause(seen).await,
            // Nothing was pushed, or a frame this build refused took its stream with it: the next
            // accept makes progress either way, so the reader does not wait.
            Ok(None) | Err(_) => {}
        }
    }
}

impl Inner {
    /// Wait out the gap after one failed dial of the beacon and record why it failed.
    async fn unreachable(&self, dials: &mut u32, error: &BeaconError) {
        *dials = dials.saturating_add(1).min(RECOVERY_DIALS);
        let wait = after(*dials, recheck(&self.beacon.me()));
        self.set(Registration::Unreachable {
            retry_at: self.runtime().now() + wait,
            dials: *dials,
            last: error.to_string(),
        });
        // The wait ends early for a dropped presence, which is what keeps the task — and the
        // endpoint handle it holds — from outliving the presence for a whole recovery gap. A stop
        // is the only thing that opens the gate while the wait is parked here today, so the loop
        // re-waits once after any other change; collapsing it to a single check would end the gap
        // early the moment anything else can open the gate.
        timeout(&*self.runtime(), wait, async {
            loop {
                let seen = self.changed.generation();
                if self.stopped() {
                    return;
                }
                self.changed.wait_past(seen).await;
            }
        })
        .await;
    }
}

/// A change counter: `open` advances it and wakes everyone waiting, and a waiter completes once
/// the count has moved past the value it read before it checked its condition.
///
/// A count rather than a flag, so one change releases every waiter that saw it: a flag is cleared
/// by whichever waiter polls first, and the rest then wait for an unrelated later change.
#[derive(Default)]
struct Gate {
    state: Mutex<GateState>,
}

#[derive(Default)]
struct GateState {
    generation: u64,
    wakers: Vec<Waker>,
}

impl Gate {
    fn open(&self) {
        let wakers = {
            let mut state = self.state.lock().expect("the gate is not poisoned");
            state.generation = state.generation.wrapping_add(1);
            std::mem::take(&mut state.wakers)
        };
        for waker in wakers {
            waker.wake();
        }
    }

    /// How many changes have been recorded. Read it before checking a condition and hand it to
    /// [`Self::wait_past`], so a change between the check and the wait is not missed.
    fn generation(&self) -> u64 {
        self.state
            .lock()
            .expect("the gate is not poisoned")
            .generation
    }

    /// Complete once a change has been recorded past `seen`.
    async fn wait_past(&self, seen: u64) {
        std::future::poll_fn(|context| {
            let mut state = self.state.lock().expect("the gate is not poisoned");
            if state.generation != seen {
                return Poll::Ready(());
            }
            listen(&mut state.wakers, context.waker());
            Poll::Pending
        })
        .await;
    }
}
