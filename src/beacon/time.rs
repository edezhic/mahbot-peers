//! A deadline measured by the runtime the caller injected.
//!
//! The beacon never reads a clock of its own: the timer comes from the
//! `quinn::Runtime` the endpoint runs on, so a test moves time and a real process
//! waits on real time without the protocol knowing the difference. The one
//! combinator is published as `beacon::timeout`; its documentation says why both
//! halves share one copy instead of each holding its own.

use std::future::Future;
use std::pin::pin;
use std::task::Poll;
use std::time::Duration;

use quinn::Runtime;

/// Run `future`, giving up after `after` of the runtime's time. `None` means the
/// deadline passed first.
///
/// This is the beacon's own bound, not a general-purpose utility: the client's
/// request bound and the server's exchange bound are both measured with it, so the
/// two halves cannot drift apart in how they compute a deadline — one copy, not two.
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
