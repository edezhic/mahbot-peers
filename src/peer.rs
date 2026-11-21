//! The peer layer: what a machine remembers, how two become acquainted, and how
//! they stay connected.
//!
//! Four pieces, each with one job:
//!
//! - [`record`] is the durable memory: one file per peer under the storage root,
//!   private to the account the product runs as, published atomically, and additive
//!   so a newer record is still read by an older build. The key is the whole
//!   identity — the fingerprint is derived from it, never stored beside it.
//! - [`pair`] is the acquaintance ceremony: commit-then-reveal over the beacon,
//!   six symbols two people compare, flights bound to the attempt, and a record
//!   written only after both people confirmed. It is the one place a peer becomes
//!   trusted.
//! - [`connect`] is the per-machine connection manager: the remembered address
//!   first, the beacon second, then stop; one connection per pair with an
//!   asymmetric tie-break both sides compute the same way; four failures, each
//!   reported as itself; and a keeper that re-dials a lost connection, re-dials one
//!   that carried traffic, and stops when an attempt fails or a peer keeps dropping
//!   the ones it takes.
//! - [`presence`] keeps a machine's registration at the beacon alive while it
//!   runs, so a peer that remembers its address can still find it after a move.
//!
//! The layer reads no ambient state and no wall clock: a caller hands in the
//! storage root, the identity, the beacon, the runtime and the current moment.
//! The beacon introduces and observes addresses; it never carries a ceremony
//! result, never stores one, and is never a path.

pub mod connect;
pub mod pair;
pub mod presence;
pub mod record;

mod address;

pub use connect::{
    ACCEPT_LANES, ConnectFailure, Connections, KEEPER_SETTLE, KEEPER_UNSTABLE_LIMIT, Keeper,
    ManagerError, NotTrustedCause, Started,
};
pub use pair::{Ceremony, Comparison, Opening, Outcome, PairError, Person, Role, Step};
pub use presence::Presence;
pub use record::{Attempt, Limits, PeerRecord, RecordError, RecordStore, Timestamp};
