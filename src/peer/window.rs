//! The per-peer token window both peer services throttle with.
//!
//! A service that answers a peer's requests keeps one window per peer: when the window started
//! and how many requests it admitted. A request beyond the limit is answered with the delay
//! until the window turns, and each service holds its own windows, so a flood of one service's
//! requests cannot throttle the other's.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::Duration;

use crate::identity::PeerId;
use crate::peer::Timestamp;

/// One peer's window: when it started and how many requests it admitted.
#[derive(Clone, Copy, Debug)]
struct Window {
    start: Timestamp,
    count: u32,
}

/// The windows one service keeps, one per peer, in memory only.
pub(crate) struct Windows(Mutex<BTreeMap<PeerId, Window>>);

impl Windows {
    /// An empty set of windows.
    pub(crate) const fn new() -> Self {
        Self(Mutex::new(BTreeMap::new()))
    }

    /// Count one request against `peer`'s window, answering the delay when it is over `limit`.
    ///
    /// The window turns `span` after it started. A request over the limit is not counted, so the
    /// delay it is given does not grow. Counted once the frame's first bytes are read — the
    /// earliest a stream is visible — so a peer that writes a request's first bytes and stalls
    /// still spends one of its window.
    pub(crate) fn admit(
        &self,
        peer: &PeerId,
        now: Timestamp,
        span: Duration,
        limit: u32,
    ) -> Option<Duration> {
        let mut windows = self.0.lock().expect("the windows are not poisoned");
        let window = windows.entry(*peer).or_insert(Window {
            start: now,
            count: 0,
        });
        if now >= window.start.plus(span) {
            *window = Window {
                start: now,
                count: 0,
            };
        }
        if window.count >= limit {
            return Some(window.start.plus(span).remaining(now));
        }
        window.count += 1;
        None
    }
}
