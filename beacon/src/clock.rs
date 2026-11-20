//! The time the server needs from the world outside.
//!
//! The state machine compares instants and nothing else, so any monotonic origin
//! will do. The binary supplies a process-wide [`std::time::Instant`]; the test
//! rig supplies the clock it drives, so an expiry happens when the test says so
//! and never because wall-clock time passed.

use std::time::Duration;

/// A monotonic reading. Only differences are used, so the origin is arbitrary.
pub trait Clock: Send + Sync + 'static {
    /// Time since the clock's origin.
    fn now(&self) -> Duration;
}
