//! The test harness for `mahbot-peers`.
//!
//! This is the shared rig every later behaviour is proven on. It gives a test
//! two machines in one process with disjoint roots and separate identities, a
//! link that carries datagrams at the same seam a real network would and faults
//! them on script, a clock the test drives (the transport's timers run on it),
//! the real beacon served over that link, and the checks that keep the capability
//! inventory and the cross-cutting invariants honest.
//!
//! Nothing here is process-global: two simulations share no state, and the
//! suite is safe to run in parallel.

pub mod actions;
pub mod beacon;
pub mod clock;
pub mod connect;
pub mod invariants;
pub mod inventory;
pub mod link;
pub mod machine;
pub mod messages;
pub mod pair;
pub mod raw;
pub mod report;
mod root;
pub mod sim;
pub mod transfers;
pub mod witnesses;
