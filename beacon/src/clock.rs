//! The two things the server needs from the world outside: the time, and a
//! deadline measured by the runtime it was handed.
//!
//! The state machine compares instants and nothing else, so any monotonic origin
//! will do. The binary supplies a process-wide [`std::time::Instant`]; the test
//! rig supplies the clock it drives, so an expiry happens when the test says so
//! and never because wall-clock time passed.

use std::future::Future;
use std::pin::pin;
use std::task::Poll;
use std::time::Duration;

use quinn::Runtime;

/// A monotonic reading. Only differences are used, so the origin is arbitrary.
pub trait Clock: Send + Sync + 'static {
    /// Time since the clock's origin.
    fn now(&self) -> Duration;
}

/// Run `future`, giving up after `after` of the runtime's time. `None` means the
/// deadline passed first.
///
/// The timer is the runtime's, so the server never reads a clock of its own: a
/// test moves time and a real process waits on real time without the server
/// knowing the difference. The library keeps the same helper, private, for its
/// client; publishing it would put a domain-neutral combinator on the beacon's
/// API for this crate's sake alone.
pub async fn timeout<F: Future>(
    runtime: &dyn Runtime,
    after: Duration,
    future: F,
) -> Option<F::Output> {
    let mut timer = runtime.new_timer(runtime.now() + after);
    let mut future = pin!(future);
    std::future::poll_fn(|context| {
        if let Poll::Ready(output) = future.as_mut().poll(context) {
            return Poll::Ready(Some(output));
        }
        timer.as_mut().poll(context).map(|()| None)
    })
    .await
}
