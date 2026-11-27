//! The one clock the peer layer reads, supplied by the caller.
//!
//! The library reads no clock of its own: every moment a record, a queue, an action memory or
//! an audit entry carries is the caller's. The message, action and transfer layers share this
//! trait so a product can hand all of them the same clock; nothing ties them to one instance,
//! and [`crate::peer::inbox::Inbox::new`] states that obligation.

use crate::peer::record::Timestamp;

/// A moment the caller supplies. The library never reads a clock.
pub trait Moment: Send + Sync {
    /// The moment now.
    fn now(&self) -> Timestamp;
}
