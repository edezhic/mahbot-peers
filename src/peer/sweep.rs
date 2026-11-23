//! The sweep cadence the two per-peer service loops share.

use super::{SWEEP_EVERY, Timestamp};

/// The next sweep's due moment, one per service loop.
///
/// The first round always sweeps, and every [`SWEEP_EVERY`] after that: both services re-read
/// their gate every round, so only the drop of what expired waits for the sweep.
#[derive(Default)]
pub(crate) struct Due(Option<Timestamp>);

impl Due {
    /// Whether a sweep is due at `now`, moving the next one a [`SWEEP_EVERY`] on.
    pub(crate) fn due(&mut self, now: Timestamp) -> bool {
        if self.0.is_none_or(|last| now >= last.plus(SWEEP_EVERY)) {
            self.0 = Some(now);
            true
        } else {
            false
        }
    }
}
