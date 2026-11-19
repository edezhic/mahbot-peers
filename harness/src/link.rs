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

use std::collections::{BTreeMap, VecDeque};
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
    pub from: SocketAddr,
    pub to: SocketAddr,
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
    held: Option<Datagram>,
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
                    held: None,
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
    pub fn set_plan(&self, plan: FaultPlan) {
        let mut state = self.state();
        state.plan = plan;
        state.generation += 1;
        state.seq = 0;
        state.held = None;
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

    /// Register a socket at `addr`, which no live socket may hold.
    ///
    /// # Errors
    ///
    /// [`AddressTaken`] when another live socket already holds the address.
    pub fn attach(&self, addr: SocketAddr) -> Result<Arc<LinkedSocket>, AddressTaken> {
        let mut state = self.state();
        if state.sockets.get(&addr).and_then(Weak::upgrade).is_some() {
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
        let addr = free_addr(&state).expect("the link has no free address");
        self.insert(&mut state, addr)
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
    /// # Panics
    ///
    /// When every address the link can hand out is taken.
    pub fn rebind_next(&self, socket: &Arc<LinkedSocket>) -> SocketAddr {
        let mut state = self.state();
        let addr = free_addr(&state).expect("the link has no free address");
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
        free_addr(&self.state()).expect("the link has no free address")
    }

    /// Send one datagram from one machine to another.
    pub fn send(&self, from: SocketAddr, to: SocketAddr, bytes: Vec<u8>) {
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
            state.trace.insert(
                seq,
                TraceEvent {
                    seq,
                    from,
                    to,
                    faults,
                    deliveries: Vec::new(),
                },
            );
            if dropped {
                Vec::new()
            } else {
                let generation = state.generation;
                let datagram = Datagram {
                    generation,
                    seq,
                    from,
                    to: destination,
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
        let target = state.sockets.get(&datagram.to).and_then(Weak::upgrade);
        if let Some(socket) = target {
            for _ in 0..datagram.copies {
                socket.push(datagram.from, datagram.bytes.clone());
            }
        }
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
fn free_addr(state: &LinkState) -> Option<SocketAddr> {
    (0..ADDRESS_SPAN)
        .map(addr_at)
        .find(|addr| state.sockets.get(addr).and_then(Weak::upgrade).is_none())
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
