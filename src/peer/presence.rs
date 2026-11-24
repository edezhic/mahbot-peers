//! Keeping a machine findable: its registration at the beacon, refreshed while it runs
//! and taken up again by itself after the beacon has been away.
//!
//! The beacon forgets a registration when its lifetime passes, so a machine that
//! wants to be found re-registers at a third of the lifetime it was answered with —
//! comfortably before the registration expires and before the session's own idle
//! timeout, which is half the lifetime. The wait is a timer from the injected
//! runtime, like every other bound in this crate: a test moves the clock and a real
//! process waits on real time without the protocol knowing the difference.
//!
//! A beacon that is down does not end this machine's findability: the session fails, the
//! loop waits out the same growing gap a pair's recovery uses — [`crate::peer::recovery`]
//! — and opens a new session. Once the episode is used up the wait is the slow re-check,
//! spread by this machine's own key for the same reason a pair's is — [`crate::peer::recovery`]
//! states it. When the beacon comes back the registration comes back with
//! it, with no person and no restart. [`Registration`] says which of the two is happening,
//! so a product can show "the beacon is not reachable" instead of looking as though
//! nothing is wrong.
//!
//! This is not a reconnect loop for peers. A peer's address is looked up only when a
//! machine actually needs to dial it; the refresh keeps the answer available and nothing
//! else.

use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::beacon::{Beacon, BeaconError, sleep};
use crate::peer::recovery::{RECOVERY_DIALS, after, recheck};

/// The shortest refresh interval: a third of a tiny lifetime must not become a
/// busy loop, so the wait never falls below this.
const MIN_REFRESH: Duration = Duration::from_secs(1);

/// How this machine's registration at the beacon stands, readable at any time.
///
/// Not durable: a restart registers again, which is the same answer a stored state would
/// give and one fewer thing that can be wrong on disk. The moment is the injected
/// runtime's, and [`Display`](fmt::Display) says what the state is rather than when, because
/// an `Instant` has no rendering of its own.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Registration {
    /// No answer has come back yet: either no [`Presence::run`] is in progress, or the one that
    /// is has not finished its first connect-and-register. `run` sets [`Self::Registered`] or
    /// [`Self::Unreachable`] only when a dial answers, and a run whose future is dropped leaves
    /// this. One run per `Presence` is the contract — the state is shared, so a second concurrent
    /// run is not supported: whichever ends first reports this while the other still refreshes.
    Idle,
    /// A session is open and the registration is being refreshed before it expires.
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

/// One machine's registration at the beacon.
pub struct Presence {
    beacon: Beacon,
    state: Mutex<Registration>,
}

impl fmt::Debug for Presence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Presence")
            .field("beacon", &self.beacon)
            .field(
                "state",
                &self.state.lock().expect("the registration is not poisoned"),
            )
            .finish()
    }
}

impl Presence {
    /// Keep `beacon`'s registration alive.
    #[must_use]
    pub fn new(beacon: Beacon) -> Self {
        Self {
            beacon,
            state: Mutex::new(Registration::Idle),
        }
    }

    /// How this machine's registration stands now.
    #[must_use]
    pub fn state(&self) -> Registration {
        self.state
            .lock()
            .expect("the registration is not poisoned")
            .clone()
    }

    /// Register and keep the registration alive until the future is dropped.
    ///
    /// One loop for the whole life of the machine: a beacon that cannot be reached is
    /// waited out with the recovery policy's growing gap and then tried again, so a beacon
    /// that comes back is found without a person and without a restart. The session is
    /// held while the registration is refreshed on it — the beacon forgets a registration
    /// when the connection that made it goes, so a session dropped between two refreshes
    /// would take the registration with it. Cancellation is the caller's — drop the
    /// future — so the library needs no stop flag of its own, and the state goes back to
    /// [`Registration::Idle`] when it is dropped, because nothing is refreshing then.
    pub async fn run(&self) {
        let _running = Running { presence: self };
        let mut dials = 0u32;
        'session: loop {
            let session = match self.beacon.connect().await {
                Ok(session) => session,
                Err(error) => {
                    self.unreachable(&mut dials, &error).await;
                    continue;
                }
            };
            loop {
                match session.register().await {
                    Ok(lifetime) => {
                        dials = 0;
                        self.set(Registration::Registered);
                        sleep(&**self.beacon.runtime(), (lifetime / 3).max(MIN_REFRESH)).await;
                    }
                    Err(error) => {
                        self.unreachable(&mut dials, &error).await;
                        continue 'session;
                    }
                }
            }
        }
    }

    /// Wait out the gap after one failed dial of the beacon and record why it failed.
    async fn unreachable(&self, dials: &mut u32, error: &BeaconError) {
        *dials = dials.saturating_add(1).min(RECOVERY_DIALS);
        let wait = after(*dials, recheck(&self.beacon.me()));
        self.set(Registration::Unreachable {
            retry_at: self.beacon.runtime().now() + wait,
            dials: *dials,
            last: error.to_string(),
        });
        sleep(&**self.beacon.runtime(), wait).await;
    }

    fn set(&self, state: Registration) {
        *self.state.lock().expect("the registration is not poisoned") = state;
    }
}

/// One running [`Presence::run`], which says so for as long as it exists.
///
/// Dropping the future — a caller's task cancelled — is how the loop stops, so the state
/// must not keep claiming a registration nothing is refreshing.
struct Running<'a> {
    presence: &'a Presence,
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        self.presence.set(Registration::Idle);
    }
}
