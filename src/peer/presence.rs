//! Keeping a machine findable: its registration at the beacon, refreshed while it
//! runs.
//!
//! The beacon forgets a registration when its lifetime passes, so a machine that
//! wants to be found re-registers at a third of the lifetime it was answered with —
//! comfortably before the registration expires and before the session's own idle
//! timeout, which is half the lifetime. The wait is a timer from the injected
//! runtime, like every other bound in this crate: a test moves the clock and a real
//! process waits on real time without the protocol knowing the difference.
//!
//! This is not a reconnect loop. A peer's address is looked up only when a machine
//! actually needs to dial it; the refresh keeps the answer available and nothing
//! else.

use std::time::Duration;

use crate::beacon::{Beacon, BeaconError, Session, sleep};

/// The shortest refresh interval: a third of a tiny lifetime must not become a
/// busy loop, so the wait never falls below this.
const MIN_REFRESH: Duration = Duration::from_secs(1);

/// One machine's registration at the beacon.
#[derive(Clone, Debug)]
pub struct Presence {
    beacon: Beacon,
}

impl Presence {
    /// Keep `beacon`'s registration alive.
    #[must_use]
    pub fn new(beacon: Beacon) -> Self {
        Self { beacon }
    }

    /// Register on `session` and refresh until the session fails.
    ///
    /// The returned error is the beacon's: a caller that wants to keep the
    /// registration across a beacon restart opens a new session and runs this
    /// again. Cancellation is the caller's too — drop the future — so the library
    /// needs no stop flag of its own.
    pub async fn run(&self, session: &Session) -> Result<(), BeaconError> {
        loop {
            let lifetime = session.register().await?;
            let refresh = (lifetime / 3).max(MIN_REFRESH);
            sleep(&**self.beacon.runtime(), refresh).await;
        }
    }
}
