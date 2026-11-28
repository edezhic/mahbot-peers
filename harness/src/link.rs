//! The simulated link: datagrams between machines, with faults a test scripts.
//!
//! This is the seam the crate will use on a real network, not a parallel one: a
//! machine's socket implements `quinn`'s `AsyncUdpSocket`, and the endpoint is
//! built over it exactly as it would be over a UDP socket. What the link adds is
//! control — drop, delay, reorder, duplicate and re-address — and a trace that
//! makes a run reproducible.
//!
//! Faults are scripted or seeded, never probabilistic: a seed picks one
//! datagram's fate by arithmetic, so the same seed over the same traffic
//! produces the same trace, and a recorded trace replays to itself.
//!
//! # Networks
//!
//! The link is also the wire between networks, so a machine can be created behind a
//! NAT and a case can watch what that NAT does: [`Link::attach_on`] hands out an
//! address inside the network, [`nat`] decides where every datagram the machines send
//! goes, and [`Link::traversal`] reports the mappings, the holes and the hairpins the
//! translation left behind. A link with no network on it translates nothing, and every
//! address, trace and fault is exactly what it was before networks existed.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};

use crate::clock::MockClock;

pub mod nat;

pub use nat::{Filtering, Hairpin, Hole, Mapping, Nat, Pooling, Translation, Traversal};

use nat::Nats;

/// One network on the link: the thing two machines are behind when they share a
/// router.
///
/// A handle, not a description: two machines are behind one network when a case asks
/// for it once with [`Link::network`] and attaches both with [`Link::attach_on`]. Two
/// machines behind the same [`Nat`] description are two networks that behave alike.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Network(usize);

/// What the link does to one datagram.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fault {
    Drop,
    Delay(Duration),
    Duplicate,
    /// Hold this datagram until the next one is sent, then deliver both in
    /// reverse order.
    ///
    /// A datagram the plan drops is never sent, so it releases nothing: the held
    /// one waits for the next datagram that is actually sent. Both facts are in
    /// the trace, which records the drop with no deliveries and the held
    /// datagram's own delivery when it is finally released.
    Reorder,
    /// Deliver to another address than the one the sender named.
    Reroute(SocketAddr),
}

/// How often each seeded fault happens, in percent of datagrams.
///
/// Rerouting has no rate: a seed cannot invent a destination, so a wrong address
/// is always an explicit script.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rates {
    pub drop: u8,
    pub delay: u8,
    pub duplicate: u8,
    pub reorder: u8,
}

/// How a run decides each datagram's fate.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum FaultPlan {
    /// Deliver everything, in order, once.
    #[default]
    Clean,
    /// Arithmetic on `(seed, sequence number)`: reproducible without recording.
    Seeded { seed: u64, rates: Rates },
    /// One list of faults per datagram, applied to datagrams 1, 2, 3, …
    Scripted(Vec<Vec<Fault>>),
    /// Every datagram delayed by exactly this much, so a round trip is twice it.
    ///
    /// A constant latency rather than a scripted one: a case that wants to count round
    /// trips on the link says how long one is and lets every datagram cost the same.
    Latency(Duration),
}

impl FaultPlan {
    /// The faults that produced `trace`, as an explicit script: a recorded run
    /// can be pinned without keeping the seed.
    #[must_use]
    pub fn from_trace(trace: &[TraceEvent]) -> Self {
        Self::Scripted(trace.iter().map(|event| event.faults.clone()).collect())
    }

    fn faults_for(&self, seq: u64) -> Vec<Fault> {
        match self {
            Self::Clean => Vec::new(),
            Self::Latency(by) => vec![Fault::Delay(*by)],
            Self::Scripted(script) => usize::try_from(seq.saturating_sub(1))
                .ok()
                .and_then(|index| script.get(index))
                .cloned()
                .unwrap_or_default(),
            Self::Seeded { seed, rates } => {
                let roll = |stream: u64| {
                    mix(*seed
                        ^ seq.wrapping_mul(0x9E37_79B9_7F4A_7C15)
                        ^ stream.wrapping_mul(0xD6E8_FEB8_6659_FD93))
                        % 100
                };
                let mut faults = Vec::new();
                if roll(0) < u64::from(rates.drop) {
                    faults.push(Fault::Drop);
                }
                if roll(1) < u64::from(rates.delay) {
                    faults.push(Fault::Delay(Duration::from_millis(1 + roll(2) % 20)));
                }
                if roll(3) < u64::from(rates.duplicate) {
                    faults.push(Fault::Duplicate);
                }
                if roll(4) < u64::from(rates.reorder) {
                    faults.push(Fault::Reorder);
                }
                faults
            }
        }
    }
}

/// One delivery of one datagram.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivery {
    /// Virtual time since the link was created.
    pub at: Duration,
    pub to: SocketAddr,
}

/// What happened to one datagram.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceEvent {
    pub seq: u64,
    /// The source the datagram carried: the sender's own address, or the endpoint a
    /// network had translated it to when it left.
    pub from: SocketAddr,
    /// The destination the sender named, before any fault moved it and before any
    /// network translated it.
    pub to: SocketAddr,
    /// The link clock's reading when the datagram was sent.
    ///
    /// The other half of [`Delivery::at`]: the two together are what
    /// [`Link::round_trips`] measures, so a case counts a round trip by the link's own
    /// reading rather than by how much virtual time the rig happened to spend.
    pub sent_at: Duration,
    /// The faults applied, in the order the plan listed them.
    pub faults: Vec<Fault>,
    /// One entry per copy the link routed to `to`; whether a socket was
    /// listening there is the test's business.
    pub deliveries: Vec<Delivery>,
}

impl TraceEvent {
    #[must_use]
    pub fn delivered(&self) -> bool {
        !self.deliveries.is_empty()
    }
}

/// A recorded run. Two runs are the same run when their traces are equal.
pub type Trace = Vec<TraceEvent>;

/// An address another live socket already holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressTaken(pub SocketAddr);

impl fmt::Display for AddressTaken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} is already in use on this link", self.0)
    }
}

impl std::error::Error for AddressTaken {}

/// The datagrams a test's machines send each other.
#[derive(Clone)]
pub struct Link {
    inner: Arc<LinkInner>,
}

struct LinkInner {
    clock: MockClock,
    state: Mutex<LinkState>,
}

struct LinkState {
    plan: FaultPlan,
    /// Bumped by `set_plan`, so a delivery queued by an earlier run cannot land
    /// in the next one's trace.
    generation: u64,
    seq: u64,
    sockets: BTreeMap<SocketAddr, Weak<LinkedSocket>>,
    /// Addresses that accept nothing, as a process that is gone does: the socket
    /// still exists, but no datagram reaches it until the address is resumed.
    silenced: BTreeSet<SocketAddr>,
    /// One-directional firewall rules: a datagram from the first address to the
    /// second is sent and reaches nothing.
    blocked: BTreeSet<(SocketAddr, SocketAddr)>,
    /// The networks between the machines, and what they have done.
    nats: Nats,
    held: Option<Datagram>,
    /// Whether `send` records what happened; see [`Link::record_trace`].
    tracing: bool,
    /// How many datagrams were handed to their address, counted whether or not the
    /// trace is recording: see [`Link::delivered`].
    delivered: u64,
    trace: BTreeMap<u64, TraceEvent>,
}

/// One datagram's decided fate: where it goes, when, and how many copies.
struct Datagram {
    /// The run it belongs to; a delivery from an older run is dropped when it
    /// fires, even if it was already on its way.
    generation: u64,
    seq: u64,
    from: SocketAddr,
    to: SocketAddr,
    bytes: Vec<u8>,
    delay: Duration,
    copies: usize,
}

impl fmt::Debug for Link {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state();
        f.debug_struct("Link")
            .field("datagrams", &state.seq)
            .field("sockets", &state.sockets.len())
            .finish_non_exhaustive()
    }
}

impl Link {
    #[must_use]
    pub fn new(clock: MockClock) -> Self {
        Self {
            inner: Arc::new(LinkInner {
                clock,
                state: Mutex::new(LinkState {
                    plan: FaultPlan::Clean,
                    generation: 0,
                    seq: 0,
                    sockets: BTreeMap::new(),
                    silenced: BTreeSet::new(),
                    blocked: BTreeSet::new(),
                    nats: Nats::default(),
                    held: None,
                    tracing: true,
                    delivered: 0,
                    trace: BTreeMap::new(),
                }),
            }),
        }
    }

    fn state(&self) -> MutexGuard<'_, LinkState> {
        self.inner.state.lock().expect("link state is not poisoned")
    }

    /// Replace the fault plan and start a new run: the trace, the sequence
    /// numbers, the held datagram and every socket's queue are cleared, and a
    /// delivery queued by the previous run is dropped when it fires.
    ///
    /// The networks start cold with the run: [`Link::traversal`] is emptied and so
    /// are the mapping tables behind it, so the first datagram of a run makes its
    /// mappings as if the network had just come up. The addresses are not touched —
    /// a machine keeps the address it was created at — and neither are the firewall
    /// rules: a block is a configuration, like a silenced address.
    pub fn set_plan(&self, plan: FaultPlan) {
        let mut state = self.state();
        state.plan = plan;
        state.generation += 1;
        state.seq = 0;
        state.held = None;
        state.nats.clear();
        state.trace.clear();
        let sockets: Vec<Arc<LinkedSocket>> =
            state.sockets.values().filter_map(Weak::upgrade).collect();
        drop(state);
        for socket in sockets {
            socket.clear();
        }
    }

    /// Everything that happened, in sequence order.
    #[must_use]
    pub fn trace(&self) -> Trace {
        self.state().trace.values().cloned().collect()
    }

    /// Start or stop recording what happens to each datagram.
    ///
    /// With recording off, `send` still numbers the datagram, applies the plan and
    /// delivers it — only the trace entry is skipped. A case that wants to prove
    /// traffic without paying for a trace reads [`Self::delivered`] instead.
    pub fn record_trace(&self, on: bool) {
        self.state().tracing = on;
    }

    /// How many datagrams the link has handed to their address since it was created.
    ///
    /// One per copy routed — a duplicated datagram counts twice — counted whether or
    /// not the trace is recording, so a case can prove traffic with the trace off.
    #[must_use]
    pub fn delivered(&self) -> u64 {
        self.state().delivered
    }

    /// How many round trips of `rtt` the link carried after `since_seq`, by the link's own
    /// clock.
    ///
    /// The windows are aligned to the **first delivered datagram after `since_seq`**: each
    /// delivered datagram is placed in the window `(sent_at - first.sent_at) / rtt`, and the
    /// answer is how many windows carried one. A datagram sent and delivered inside one round
    /// trip is 1, and nothing delivered after `since_seq` is 0. An idle gap is no window at
    /// all — no datagram, no window — so the second a service spends between the handshake
    /// and the first byte of the file costs nothing, and the count is the link's own work
    /// rather than the virtual time the rig happened to spend. Aligning to the first datagram
    /// rather than to the link's creation is what keeps the count from moving by one when a
    /// run's start shifts.
    #[must_use]
    pub fn round_trips(&self, since_seq: u64, rtt: Duration) -> u64 {
        if rtt.is_zero() {
            return 0;
        }
        let state = self.state();
        let delivered = state
            .trace
            .values()
            .filter(|event| event.seq > since_seq && !event.deliveries.is_empty());
        let Some(first) = delivered.clone().map(|event| event.sent_at).min() else {
            return 0;
        };
        let mut windows: BTreeSet<u128> = BTreeSet::new();
        for event in delivered {
            windows.insert(event.sent_at.saturating_sub(first).as_nanos() / rtt.as_nanos());
        }
        u64::try_from(windows.len()).unwrap_or(u64::MAX)
    }

    /// Register a socket at `addr`, which no live socket may hold.
    ///
    /// # Errors
    ///
    /// [`AddressTaken`] when another live socket already holds the address.
    pub fn attach(&self, addr: SocketAddr) -> Result<Arc<LinkedSocket>, AddressTaken> {
        let mut state = self.state();
        if state.sockets.get(&addr).and_then(Weak::upgrade).is_some()
            || state.silenced.contains(&addr)
        {
            return Err(AddressTaken(addr));
        }
        Ok(self.insert(&mut state, addr))
    }

    /// Register a socket at the lowest free address.
    ///
    /// # Panics
    ///
    /// When every address the link can hand out is taken.
    pub fn attach_next(&self) -> Arc<LinkedSocket> {
        let mut state = self.state();
        let addr = free_addr(&state, None).expect("the link has no free address");
        self.insert(&mut state, addr)
    }

    /// Make one network of `nat`; two machines are behind it when both are attached
    /// with [`Link::attach_on`].
    ///
    /// # Panics
    ///
    /// When the link has no room for another network.
    #[must_use]
    pub fn network(&self, nat: Nat) -> Network {
        Network(self.state().nats.fresh(nat))
    }

    /// Register a socket inside an existing network, at the lowest free address there.
    ///
    /// # Panics
    ///
    /// When the network has no free address.
    #[must_use]
    pub fn attach_on(&self, network: Network) -> Arc<LinkedSocket> {
        let mut state = self.state();
        let addr = free_addr(&state, Some(network.0)).expect("the network has no free address");
        self.insert(&mut state, addr)
    }

    /// The network a machine at `addr` is behind, by the block it lives in.
    #[must_use]
    pub fn network_of(&self, addr: SocketAddr) -> Option<Network> {
        self.state().nats.network_of(addr).map(Network)
    }

    fn insert(&self, state: &mut LinkState, addr: SocketAddr) -> Arc<LinkedSocket> {
        let socket = Arc::new(LinkedSocket {
            addr: Mutex::new(addr),
            rx: Mutex::new(RxState::default()),
            link: Arc::downgrade(&self.inner),
        });
        state.sockets.insert(addr, Arc::downgrade(&socket));
        socket
    }

    /// Stop delivering anything to `addr`, as a process that is gone does.
    ///
    /// The socket is not closed and its address stays taken: the sender keeps
    /// transmitting into nothing, which is exactly what a killed peer looks like
    /// from the outside. [`Link::resume`] undoes it.
    pub fn silence(&self, addr: SocketAddr) {
        self.state().silenced.insert(addr);
    }

    /// Deliver to `addr` again.
    pub fn resume(&self, addr: SocketAddr) {
        self.state().silenced.remove(&addr);
    }

    /// Stop delivering anything `from` sends to `to`: one firewall rule, one
    /// direction, judged against the address the sender named before any network
    /// translates it.
    ///
    /// The datagram is still sent — the trace records it with the faults the plan
    /// gave it and no deliveries — which is what a machine whose UDP is blocked
    /// towards one peer looks like. Blocking a machine entirely is one rule per
    /// destination it dials.
    pub fn blocks(&self, from: SocketAddr, to: SocketAddr) {
        self.state().blocked.insert((from, to));
    }

    /// The address traffic from `addr` comes from once it has left every network the
    /// machine is behind.
    ///
    /// A machine behind nothing answers with its own address, which is what a peer
    /// dials. A machine behind a network answers with the mapping that network has
    /// made for it — the oldest one, the address the first peer to hear from it was
    /// told — and `None` before it has sent anything, because until then its network
    /// has made no mapping and nothing outside can name it.
    #[must_use]
    pub fn external(&self, addr: SocketAddr) -> Option<SocketAddr> {
        self.state().nats.external(addr)
    }

    /// What the networks have done since the current run began: every mapping made,
    /// every hole a filter opened, every hairpin carried.
    ///
    /// [`Link::set_plan`] empties it, because it starts the run it describes.
    #[must_use]
    pub fn traversal(&self) -> Traversal {
        self.state().nats.traversal()
    }

    /// Move a socket to a new apparent address, as a path change does.
    ///
    /// A delivery still waiting on the clock resolves its destination when it
    /// fires, so it lands wherever the address points by then — the old holder
    /// is gone, and the new one receives it.
    ///
    /// Refused when another live socket already holds the address: silently
    /// stealing it would look like a network fault the test never asked for.
    ///
    /// # Errors
    ///
    /// [`AddressTaken`] when another live socket holds `addr`.
    pub fn rebind(&self, socket: &Arc<LinkedSocket>, addr: SocketAddr) -> Result<(), AddressTaken> {
        let mut state = self.state();
        let taken = state
            .sockets
            .get(&addr)
            .and_then(Weak::upgrade)
            .is_some_and(|holder| !Arc::ptr_eq(&holder, socket));
        if taken {
            return Err(AddressTaken(addr));
        }
        move_socket(&mut state, socket, addr);
        Ok(())
    }

    /// Move a socket to the lowest free address, allocating and moving under one
    /// lock: a concurrent caller cannot be handed the address in between.
    ///
    /// The socket stays on the side of the wire it was on: one behind a network moves
    /// to a free address inside that network, and one behind nothing stays on the
    /// loopback space.
    ///
    /// # Panics
    ///
    /// When every address the link can hand out is taken.
    pub fn rebind_next(&self, socket: &Arc<LinkedSocket>) -> SocketAddr {
        let mut state = self.state();
        let network = state.nats.network_of(socket.addr());
        let addr = free_addr(&state, network).expect("the link has no free address");
        move_socket(&mut state, socket, addr);
        addr
    }

    /// The lowest address on the link that no live socket holds.
    ///
    /// A snapshot: another thread may attach the same address before the caller
    /// uses it, which is why [`Link::attach_next`] and [`Link::rebind_next`]
    /// allocate and attach in one step.
    ///
    /// # Panics
    ///
    /// When every address the link can hand out is taken, which is a test that
    /// created more machines than the link has room for.
    #[must_use]
    pub fn alloc_addr(&self) -> SocketAddr {
        free_addr(&self.state(), None).expect("the link has no free address")
    }

    /// Send one datagram from one machine to another.
    ///
    /// The datagram is what the sender emitted: the faults the plan gives it are
    /// applied to the address it named, and only then are the networks between the
    /// two ends asked where it goes and what source it carries.
    pub fn send(&self, from: SocketAddr, to: SocketAddr, bytes: Vec<u8>) {
        let sent_at = self.inner.clock.elapsed();
        let deliveries = {
            let mut state = self.state();
            state.seq += 1;
            let seq = state.seq;
            let faults = state.plan.faults_for(seq);
            let mut destination = to;
            let mut delay = Duration::ZERO;
            let mut copies = 1usize;
            let mut reorder = false;
            let mut dropped = false;
            for fault in &faults {
                match fault {
                    // A drop wins over every other fault: the datagram was never
                    // sent, so nothing about it can be delivered or held.
                    Fault::Drop => dropped = true,
                    Fault::Delay(by) => delay += *by,
                    Fault::Duplicate => copies += 1,
                    Fault::Reorder => reorder = true,
                    Fault::Reroute(addr) => destination = *addr,
                }
            }
            // A blocked datagram is sent and reaches nothing, as a dropped one is,
            // so no network translates it: a firewall sits in front of the wire.
            let (source, target) = if dropped || state.blocked.contains(&(from, destination)) {
                (from, None)
            } else {
                // Every network between the two ends translates here, once, and the
                // answer is frozen into the datagram: the source a socket reports is
                // the one the sender's networks had already chosen.
                let route = state.nats.route(from, destination);
                (route.source, route.destination)
            };
            if state.tracing {
                state.trace.insert(
                    seq,
                    TraceEvent {
                        seq,
                        from: source,
                        to,
                        sent_at,
                        faults,
                        deliveries: Vec::new(),
                    },
                );
            }
            match target {
                None => Vec::new(),
                Some(target) => {
                    let generation = state.generation;
                    let datagram = Datagram {
                        generation,
                        seq,
                        from: source,
                        to: target,
                        bytes,
                        delay,
                        copies,
                    };
                    if reorder {
                        match state.held.replace(datagram) {
                            // Two holds in a row: the older one is released now.
                            Some(previous) => vec![previous],
                            None => Vec::new(),
                        }
                    } else {
                        match state.held.take() {
                            Some(mut previous) => {
                                // The held datagram can never land before the one
                                // that released it, so it waits for the later of the
                                // two delays; with equal delays both land in the same
                                // instant and the held one arrives second.
                                previous.delay = previous.delay.max(delay);
                                vec![datagram, previous]
                            }
                            None => vec![datagram],
                        }
                    }
                }
            }
        };
        for delivery in deliveries {
            self.deliver(delivery);
        }
    }

    fn deliver(&self, datagram: Datagram) {
        if datagram.delay.is_zero() {
            self.deliver_now(&datagram);
            return;
        }
        let weak = Arc::downgrade(&self.inner);
        self.inner.clock.schedule(datagram.delay, move || {
            if let Some(inner) = weak.upgrade() {
                Link { inner }.deliver_now(&datagram);
            }
        });
    }

    /// Deliver one datagram, holding the link's state across the push: a
    /// `set_plan` in another thread either happens entirely before this delivery
    /// (and the generation check drops it) or entirely after it.
    fn deliver_now(&self, datagram: &Datagram) {
        let at = self.inner.clock.elapsed();
        let mut state = self.state();
        if state.generation != datagram.generation {
            return;
        }
        // A silenced address is a peer that is gone: the datagram is sent into
        // nothing, so the trace records it with no delivery.
        if state.silenced.contains(&datagram.to) {
            return;
        }
        let target = state.sockets.get(&datagram.to).and_then(Weak::upgrade);
        if let Some(socket) = target {
            for _ in 0..datagram.copies {
                socket.push(datagram.from, datagram.bytes.clone());
            }
        }
        // Counted whether or not the trace is recording: a case that proves traffic
        // with tracing off reads this instead.
        state.delivered = state
            .delivered
            .saturating_add(u64::try_from(datagram.copies).unwrap_or(u64::MAX));
        if let Some(event) = state.trace.get_mut(&datagram.seq) {
            for _ in 0..datagram.copies {
                event.deliveries.push(Delivery {
                    at,
                    to: datagram.to,
                });
            }
        }
    }
}

#[derive(Default)]
struct RxState {
    queue: VecDeque<(SocketAddr, Vec<u8>)>,
    waker: Option<Waker>,
}

/// One machine's address on the link: an abstract UDP socket quinn drives.
pub struct LinkedSocket {
    addr: Mutex<SocketAddr>,
    rx: Mutex<RxState>,
    link: Weak<LinkInner>,
}

impl fmt::Debug for LinkedSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LinkedSocket({})", self.addr())
    }
}

impl LinkedSocket {
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        *self.addr_lock()
    }

    fn addr_lock(&self) -> MutexGuard<'_, SocketAddr> {
        self.addr.lock().expect("socket address is not poisoned")
    }

    fn set_addr(&self, addr: SocketAddr) {
        *self.addr_lock() = addr;
    }

    fn rx(&self) -> MutexGuard<'_, RxState> {
        self.rx.lock().expect("receive queue is not poisoned")
    }

    /// Drop everything queued for this socket, waking a reader that was parked
    /// on it so the transport re-polls an empty queue instead of waiting for a
    /// datagram that will never come.
    pub fn clear(&self) {
        let waker = {
            let mut rx = self.rx();
            rx.queue.clear();
            rx.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn push(&self, from: SocketAddr, bytes: Vec<u8>) {
        let waker = {
            let mut rx = self.rx();
            rx.queue.push_back((from, bytes));
            rx.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for LinkedSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // A socket that outlives its link sends into nothing: the datagram is
        // lost, as it would be on a dead network, rather than reported as a
        // socket error the transport would have to interpret.
        let Some(link) = self.link.upgrade() else {
            return Ok(());
        };
        Link { inner: link }.send(
            self.addr(),
            transmit.destination,
            transmit.contents.to_vec(),
        );
        Ok(())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let (Some(buf), Some(meta)) = (bufs.first_mut(), meta.first_mut()) else {
            return Poll::Ready(Ok(0));
        };
        let mut rx = self.rx();
        loop {
            let Some((from, bytes)) = rx.queue.pop_front() else {
                rx.waker = Some(cx.waker().clone());
                return Poll::Pending;
            };
            // A datagram larger than the caller's buffer is dropped, not
            // truncated: a truncated datagram would read as corruption rather
            // than as the loss it is.
            if bytes.len() > buf.len() {
                continue;
            }
            buf[..bytes.len()].copy_from_slice(&bytes);
            *meta = RecvMeta {
                addr: from,
                len: bytes.len(),
                stride: bytes.len(),
                ecn: None,
                dst_ip: None,
            };
            return Poll::Ready(Ok(1));
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.addr())
    }
}

/// The lowest address the link hands out that no live socket holds.
///
/// `None` asks the loopback space every machine behind nothing sits on; `Some` asks
/// the private block of that network.
fn free_addr(state: &LinkState, network: Option<usize>) -> Option<SocketAddr> {
    match network {
        None => (0..ADDRESS_SPAN)
            .map(addr_at)
            .find(|addr| is_free(state, addr)),
        Some(network) => {
            let block = state.nats.private_of(network);
            nat::HOSTS
                .map(|host| nat::host_at(block, host))
                .find(|addr| is_free(state, addr))
        }
    }
}

/// Whether no live socket holds `addr` and nothing has silenced it.
fn is_free(state: &LinkState, addr: &SocketAddr) -> bool {
    state.sockets.get(addr).and_then(Weak::upgrade).is_none() && !state.silenced.contains(addr)
}

/// Point a socket's registry entry at `addr`.
///
/// The socket's own address is written under the link's state lock, so the two
/// never disagree: a concurrent rebind of the same socket sees the new key and
/// moves one entry, and `free_addr` cannot hand out an address a live socket
/// still sends from. The lock order is state then socket, the same order the
/// rest of the link uses.
fn move_socket(state: &mut LinkState, socket: &Arc<LinkedSocket>, addr: SocketAddr) {
    state.sockets.remove(&socket.addr());
    socket.set_addr(addr);
    state.sockets.insert(addr, Arc::downgrade(socket));
}

/// The address the link hands out for `index`. Nothing is ever bound to it.
pub(crate) fn addr_at(index: u64) -> SocketAddr {
    let offset = index % ADDRESS_SPAN;
    let port = FIRST_PORT + u16::try_from(offset).unwrap_or(0);
    SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port))
}

/// The first address the link hands out.
const FIRST_PORT: u16 = 41_000;

/// How many addresses the link cycles through before repeating one.
const ADDRESS_SPAN: u64 = 20_000;

fn mix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}
