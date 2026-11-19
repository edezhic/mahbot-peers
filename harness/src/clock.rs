//! The injected clock.
//!
//! Time is a value the test moves. `quinn` reads it and creates its timers
//! through this clock, so a transport timeout fires exactly when the test says
//! so and never because wall time passed. The one wall-clock reading in this
//! workspace's own sources is captured here, at construction, and only to have
//! an `Instant` to add durations to.
//!
//! The runtime built by [`block_on`] has no timer and no I/O driver, and the
//! harness's `tokio` has no `time` feature at all: a timer sleep does not
//! compile, and a thread sleep is forbidden by the single-source-of-time
//! invariant.

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use quinn::{AsyncTimer, AsyncUdpSocket, Runtime};

/// A clock the test owns outright.
#[derive(Clone)]
pub struct MockClock {
    inner: Arc<ClockInner>,
}

struct ClockInner {
    origin: Instant,
    state: Mutex<ClockState>,
}

struct ClockState {
    now: Instant,
    timers: Vec<Weak<TimerInner>>,
    scheduled: BTreeMap<(Instant, u64), Box<dyn FnOnce() + Send>>,
    next_scheduled: u64,
}

impl fmt::Debug for MockClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MockClock")
            .field("elapsed", &self.elapsed())
            .finish_non_exhaustive()
    }
}

impl MockClock {
    #[must_use]
    pub fn new() -> Self {
        let origin = Instant::now();
        Self {
            inner: Arc::new(ClockInner {
                origin,
                state: Mutex::new(ClockState {
                    now: origin,
                    timers: Vec::new(),
                    scheduled: BTreeMap::new(),
                    next_scheduled: 0,
                }),
            }),
        }
    }

    /// The clock's current reading, as a `std::time::Instant` the transport can
    /// compare and subtract. It moves only when the test moves it.
    #[must_use]
    pub fn now(&self) -> Instant {
        self.lock().now
    }

    /// Virtual time since the clock was created.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        let now = self.now();
        now.saturating_duration_since(self.inner.origin)
    }

    /// Run `f` once the clock has advanced by `after`.
    pub fn schedule<F>(&self, after: Duration, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let mut state = self.lock();
        let at = state.now + after;
        let id = state.next_scheduled;
        state.next_scheduled += 1;
        state.scheduled.insert((at, id), Box::new(f));
    }

    /// The transport's clock: every timer quinn creates is registered here.
    #[must_use]
    pub fn runtime(&self) -> Arc<dyn Runtime> {
        Arc::new(MockRuntime {
            clock: Arc::clone(&self.inner),
        })
    }

    /// Move time forward by `by`, firing everything due on the way in deadline
    /// order, and let the transport react. Each instant in between is processed
    /// once, so a delayed datagram lands at the moment it was scheduled for.
    ///
    /// # Panics
    ///
    /// When a callback keeps scheduling another deadline inside the same
    /// advance: see [`MAX_WALK_STEPS`].
    pub async fn advance(&self, by: Duration) {
        let target = self.now() + by;
        let mut cursor: Option<Instant> = None;
        let mut steps = 0;
        while let Some(next) = self.next_deadline(cursor) {
            if next > target {
                break;
            }
            steps += 1;
            assert_walk_is_bounded(steps);
            cursor = Some(next);
            self.advance_to(next);
            self.fire();
            tokio::task::yield_now().await;
        }
        self.advance_to(target);
        self.settle().await;
    }

    /// Let the transport run until nothing is due at the current instant: this
    /// is what turns "the timer was woken" into "the connection observed it".
    ///
    /// Each instant is processed once. A timer re-armed, or a callback queued,
    /// for the instant it just fired at is left to the next `advance`: a clock
    /// that cannot move would otherwise spin forever, and real time always moves.
    ///
    /// # Panics
    ///
    /// When a callback keeps scheduling another deadline inside the same
    /// settle: see [`MAX_WALK_STEPS`].
    pub(crate) async fn settle(&self) {
        let now = self.now();
        let mut cursor: Option<Instant> = None;
        let mut steps = 0;
        while let Some(next) = self.next_deadline(cursor) {
            if next > now {
                break;
            }
            steps += 1;
            assert_walk_is_bounded(steps);
            cursor = Some(next);
            if !self.fire() {
                break;
            }
            tokio::task::yield_now().await;
        }
    }

    fn lock(&self) -> MutexGuard<'_, ClockState> {
        self.inner.state()
    }

    /// Move the reading to `instant`, never back: a timer armed for an instant
    /// already behind the clock must not drag time with it.
    ///
    /// This is the clock's whole monotonic guarantee, and it is public so a case
    /// can aim it at the past and observe that nothing moved.
    pub fn advance_to(&self, now: Instant) {
        let mut state = self.lock();
        if now > state.now {
            state.now = now;
        }
    }

    /// Poll `future` while moving this clock, and give up after `budget` of
    /// virtual time: `None` means it did not resolve within the budget.
    ///
    /// This is how an await that may park forever is bounded. A case that awaits
    /// something that never arrives — a datagram the link dropped — would
    /// otherwise hang the suite, because the poll budget only stops a case that
    /// spins without parking. A handshake on a clean link finishes inside the
    /// first few scheduler turns, so driving it costs no virtual time at all.
    pub async fn drive<F: Future>(&self, budget: Duration, future: F) -> Option<F::Output> {
        tokio::pin!(future);
        let mut spent = Duration::ZERO;
        loop {
            for _ in 0..DRIVE_YIELDS {
                tokio::select! {
                    biased;
                    output = &mut future => return Some(output),
                    () = tokio::task::yield_now() => {}
                }
            }
            if spent >= budget {
                return None;
            }
            let step = DRIVE_STEP.min(budget - spent);
            self.advance(step).await;
            spent += step;
        }
    }

    /// The earliest deadline strictly after `cursor`, or the earliest of all.
    ///
    /// A cursor rather than a "not this instant again" guard: a timer left armed
    /// for an instant already visited must not stop the walk, or every later
    /// deadline would be fired at the end of the jump instead of at its own
    /// instant. For the same reason every scheduled deadline is considered, not
    /// only the earliest: a callback queued for an instant already visited must
    /// not hide the ones still ahead.
    fn next_deadline(&self, cursor: Option<Instant>) -> Option<Instant> {
        let (timers, scheduled) = {
            let mut state = self.lock();
            state.timers.retain(|timer| timer.strong_count() > 0);
            let timers: Vec<Arc<TimerInner>> =
                state.timers.iter().filter_map(Weak::upgrade).collect();
            let scheduled: Vec<Instant> = state.scheduled.keys().map(|(at, _)| *at).collect();
            (timers, scheduled)
        };
        let from_timers = timers.iter().map(|timer| timer.deadline().0);
        from_timers
            .chain(scheduled)
            .filter(|at| cursor.is_none_or(|cursor| *at > cursor))
            .min()
    }

    /// Fire everything due now and report whether anything was: a deadline with
    /// no waker is due but has nobody to tell.
    fn fire(&self) -> bool {
        let now = self.now();
        let due: Vec<Box<dyn FnOnce() + Send>> = {
            let mut state = self.lock();
            let keys: Vec<(Instant, u64)> = state
                .scheduled
                .range(..=(now, u64::MAX))
                .map(|(key, _)| *key)
                .collect();
            keys.into_iter()
                .filter_map(|key| state.scheduled.remove(&key))
                .collect()
        };
        let fired_callback = !due.is_empty();
        for callback in due {
            callback();
        }
        let wakers: Vec<Waker> = {
            let mut state = self.lock();
            state.timers.retain(|timer| timer.strong_count() > 0);
            let timers: Vec<Arc<TimerInner>> =
                state.timers.iter().filter_map(Weak::upgrade).collect();
            drop(state);
            timers
                .into_iter()
                .filter_map(|timer| {
                    let deadline = timer.deadline();
                    if deadline.0 <= now {
                        deadline.1.clone()
                    } else {
                        None
                    }
                })
                .collect()
        };
        let fired_waker = !wakers.is_empty();
        for waker in wakers {
            waker.wake();
        }
        fired_callback || fired_waker
    }
}

impl Default for MockClock {
    fn default() -> Self {
        Self::new()
    }
}

/// Scheduler turns a driven future gets before time is moved: enough for a
/// handshake on a clean link, so driving it costs no virtual time.
pub(crate) const DRIVE_YIELDS: usize = 4;

/// How much virtual time one drive moves per round while it waits.
const DRIVE_STEP: Duration = Duration::from_millis(10);

/// How many instants one walk may process before it is called runaway.
///
/// A callback that schedules another callback for a moment still inside the same
/// advance keeps the walk going: it terminates, but only after one step per
/// scheduled instant, which a millisecond-scale re-arm turns into millions. A
/// test must fail rather than crawl, so the walk is bounded.
pub const MAX_WALK_STEPS: usize = 10_000;

/// See [`MAX_WALK_STEPS`]: the clock walk is running away, and a panic names it
/// instead of leaving the suite to crawl.
fn assert_walk_is_bounded(steps: usize) {
    assert!(
        steps < MAX_WALK_STEPS,
        "the clock walk processed {MAX_WALK_STEPS} instants inside one advance: a callback keeps scheduling another deadline"
    );
}

impl ClockInner {
    fn state(&self) -> MutexGuard<'_, ClockState> {
        self.state.lock().expect("clock state is not poisoned")
    }
}

struct TimerInner {
    clock: Weak<ClockInner>,
    deadline: Mutex<(Instant, Option<Waker>)>,
}

impl TimerInner {
    fn deadline(&self) -> MutexGuard<'_, (Instant, Option<Waker>)> {
        self.deadline.lock().expect("timer is not poisoned")
    }
}

struct MockTimer {
    inner: Arc<TimerInner>,
}

impl fmt::Debug for MockTimer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MockTimer")
    }
}

impl AsyncTimer for MockTimer {
    fn reset(self: Pin<&mut Self>, instant: Instant) {
        self.inner.deadline().0 = instant;
    }

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let now = {
            let clock = self
                .inner
                .clock
                .upgrade()
                .expect("the clock outlives its timers");
            clock.state().now
        };
        let mut deadline = self.inner.deadline();
        if now >= deadline.0 {
            // Clearing the waker matters: a fired timer that kept it would look
            // due forever to `fire`, and `settle` would never finish.
            deadline.1 = None;
            Poll::Ready(())
        } else {
            deadline.1 = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

struct MockRuntime {
    clock: Arc<ClockInner>,
}

impl fmt::Debug for MockRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MockRuntime")
    }
}

impl Runtime for MockRuntime {
    fn new_timer(&self, instant: Instant) -> Pin<Box<dyn AsyncTimer>> {
        let inner = Arc::new(TimerInner {
            clock: Arc::downgrade(&self.clock),
            deadline: Mutex::new((instant, None)),
        });
        self.clock.state().timers.push(Arc::downgrade(&inner));
        Box::pin(MockTimer { inner })
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        tokio::spawn(future);
    }

    fn wrap_udp_socket(&self, _socket: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        Err(io::Error::other(
            "the harness delivers datagrams through its link: build endpoints with an abstract socket",
        ))
    }

    fn now(&self) -> Instant {
        self.clock.state().now
    }
}

/// How many times one case's top-level future may be polled.
///
/// A case that spins without parking never reaches the runtime's park, so a poll
/// count is the one watchdog available without a timer: it turns "hangs forever"
/// into a failure with a message. A legitimate case yields a few thousand times
/// at most.
const POLL_BUDGET: u64 = 100_000;

/// One case under the poll budget: see [`POLL_BUDGET`].
struct Watchdog<F: Future> {
    inner: Pin<Box<F>>,
    polls: u64,
}

impl<F: Future> Future for Watchdog<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        let this = self.get_mut();
        this.polls += 1;
        assert!(
            this.polls < POLL_BUDGET,
            "the case was polled {POLL_BUDGET} times without parking: it cannot make progress"
        );
        this.inner.as_mut().poll(cx)
    }
}

/// Run a future on a current-thread runtime with no timer and no I/O driver.
///
/// Every case and witness goes through here, so a `tokio::time` sleep anywhere in
/// the tested code panics instead of making the suite slow and flaky, a
/// `std::thread::sleep` is caught by the single-source-of-time invariant, and a
/// case that spins is stopped by the poll budget.
///
/// # Panics
///
/// When the future is polled the poll budget's worth of times without parking.
pub fn block_on<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a current-thread runtime builds")
        .block_on(Watchdog {
            inner: Box::pin(future),
            polls: 0,
        })
}
