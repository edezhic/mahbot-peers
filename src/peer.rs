//! The peer layer: what a machine remembers, how two become acquainted, how they
//! stay connected, and what a connected machine may do.
//!
//! Eight pieces, each with one job:
//!
//! - [`record`] is the durable memory: one file per peer under the storage root,
//!   private to the account the product runs as, published atomically, and additive
//!   so a newer record is still read by an older build. The key is the whole
//!   identity — the fingerprint is derived from it, never stored beside it. The file
//!   has two levels: the machine's and the connection's.
//! - [`access`] is the connection level's vocabulary: the account on the instance,
//!   the assistant, the pair, the four capabilities, the rights, and the small
//!   versioned fact the binding travels as.
//! - [`binding`] is the one exchange that carries that fact over a live connection:
//!   best effort, bounded, and measured so it is not mistaken for the pair's traffic.
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
//! - [`rights`] is the decision — may this connection, as this assistant, exercise
//!   this capability on this machine now — with the default, the host's floor and
//!   the trust withdrawal.
//! - [`audit`] is the record of every grant, refusal, ending, withdrawal, return and
//!   attempt-lock clearing, written before the act it describes.
//!
//! The layer reads no ambient state and no wall clock: a caller hands in the
//! storage root, the identity, the beacon, the runtime and the current moment.
//! The beacon introduces and observes addresses; it never carries a ceremony
//! result, never stores one, and is never a path.
//!
//! Every type is re-exported here, so a caller names one path. A constant is too when
//! a caller acts on it — how many accept loops to run, how long the keeper's windows
//! are, how long an exchange or a machine-to-machine flight may take — while a storage
//! format's own sizes stay on the module that owns the format: a caller never sizes a
//! record, a log or a label by hand.
//!
//! One exception to "a public item needs a caller that is not the rig": the functions
//! that name a file on a root without opening or creating it —
//! [`record::RecordStore::path_for`], [`record::RecordStore::dir_in`] and
//! [`audit::AuditLog::path_in`] — stay public, because a person's backup or repair has
//! to be able to name what this crate owns on a root where opening would fail or
//! create it, and the rig uses them for the same reason.

pub mod access;
pub mod audit;
pub mod binding;
pub mod connect;
pub mod pair;
pub mod presence;
pub mod record;
pub mod rights;

mod address;
mod tlv;

pub use access::{
    Account, Authority, Binding, Capability, Claim, Fact, FactError, Instance, Issuer, Label,
    LabelError, Pair, PersonName, Right, Standing,
};
pub use audit::{Act, AuditError, AuditLog, Entry, GrantKind, WriteRefusal};
pub use binding::EXCHANGE_BUDGET;
pub use connect::{
    ACCEPT_LANES, ConnectFailure, Connections, KEEPER_SETTLE, KEEPER_UNSTABLE_LIMIT, Keeper,
    ManagerError, NotTrustedCause, Started, TRUST_POLL,
};
pub use pair::{
    Ceremony, Comparison, Opening, Outcome, PAIR_FLIGHT_TIMEOUT, PairError, Person, Role, Turn,
};
pub use presence::Presence;
pub use record::{Attempt, Limits, Malformed, PeerRecord, RecordError, RecordStore, Timestamp};
pub use rights::{
    Closed, Decision, Floor, NoFloor, Question, Refusal, Restored, Rights, RightsError, Speaker,
    Step,
};
