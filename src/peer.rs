//! The peer layer: what a machine remembers, how two become acquainted, how they
//! stay connected, what a connected machine may do, and what it asks of another.
//!
//! Thirteen pieces, each with one job:
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
//!   first, the beacon second; one connection per pair with an asymmetric tie-break
//!   both sides compute the same way, and a fresh connection preferred over one that
//!   has stopped answering; four failures, each reported as itself; and a keeper that
//!   recovers the pair in paced episodes rather than stopping at the first failed dial.
//! - [`recovery`] is the one retry policy for a pair: episodes with growing gaps, a
//!   stated cap, a slow re-check once an episode is used up, the reasons that start a
//!   new one, the two states that are never retried, and the state a product reads to
//!   show what is happening.
//! - [`presence`] keeps a machine's registration at the beacon alive while it
//!   runs, so a peer that remembers its address can still find it after a move, and
//!   takes the registration up again by itself when a beacon that was down returns.
//! - [`messages`] is what one machine says to another: a body queued durably at the
//!   sender, offered over the pair's live direct connection, decided by the receiver
//!   through the rights layer, deduplicated by envelope, delivered at least once,
//!   dropped after three days, and throttled when a peer floods. A body is opaque
//!   bytes and its author is the connection's attested peer, never a field.
//! - [`actions`] is what one machine asks another to do: an identifier the caller
//!   names, a kind, a bounded body and a bounded result, executed at most once. The
//!   receiver keeps a durable journal of executed identifiers, answers a repeat
//!   "already executed", remembers an identifier before the run it describes, and
//!   hands the body to the product's own [`actions::Executor`]; a request whose result
//!   never came back is marked unknown and never offered again. It has no queue and
//!   no automatic retry.
//! - [`inbox`] is the one place a pair's connection is read: it accepts every stream
//!   after the binding exchange, decides by the frame's magic whether it is a message
//!   or an action, and hands it to the layer that owns it. It runs the message layer's
//!   offer loop in the same task, so one service per peer answers both and one ending
//!   reaches whoever started it.
//! - [`moment`] is the clock both services read: one [`Moment`] the caller supplies, shared
//!   by the message layer and the action layer, so both record the same moments.
//! - [`rights`] is the decision — may this connection, as this assistant, exercise
//!   this capability on this machine now — with the default, the host's floor and
//!   the trust withdrawal.
//! - [`audit`] is the record of every grant, refusal, ending, withdrawal, return,
//!   attempt-lock clearing, refused message, dropped queue and executed action, written
//!   before the act it describes.
//!
//! The layer reads no ambient state and no wall clock: a caller hands in the
//! storage root, the identity, the beacon, the runtime and the current moment.
//! The beacon introduces and observes addresses; it never carries a ceremony
//! result, a message or an action, never stores one, and is never a path.
//!
//! Every type is re-exported here, so a caller names one path. A constant is too when a
//! caller acts on it — how many handshakes may be in flight at once, how long the keeper's
//! windows are, how the retry policy's gaps grow and when it stops trying quickly,
//! how long an exchange or a machine-to-machine flight may take, how many symbols a person
//! is shown, how much a message may carry, how long a message and a taken identifier are
//! kept, how often one may be offered and how many a peer's queue may hold, how much an
//! action and its result may carry, how long its memory is kept, how often one may be
//! asked and how long its execution may take — while a storage format's internal layout
//! stays on the module that owns it: a caller never sizes a record, a log, a label, a
//! queue's fields or an action memory's by hand, and a queue or memory file's byte cap is
//! its own business. The layers' malformed reasons are [`MessageMalformed`] and
//! [`ActionMalformed`] for a file and [`FramingFault`] for a frame: the four faults the
//! framing shares are written once, [`Malformed`] already names the record's, and a frame
//! cannot carry every fault a file can. The message wire types ([`Message`], [`Answer`]) are
//! public like the beacon's closed message set: a case builds one and reads an answer by hand.
//! [`ActionAnswer`] is public because [`Actions::request`] returns it; `Action` itself is
//! crate-private, because no public entry point takes one and the action cases build raw
//! frames. This crate writes the only answers there are.
//!
//! The functions that name what this crate owns on a root without opening or creating
//! it — [`record::RecordStore::path_for`], [`record::RecordStore::dir_in`],
//! [`audit::AuditLog::path_in`], [`messages::Messages::path_for`],
//! [`messages::Messages::lock_path_for`], [`messages::Messages::dir_in`],
//! [`actions::Actions::path_for`], [`actions::Actions::lock_path_for`] and
//! [`actions::Actions::dir_in`] — are public because a person's backup or repair must be
//! able to name it on a root where opening would fail or create it, and, for a queue or
//! a memory, to tell the file a writer locks from the file itself.

use std::time::Duration;

pub mod access;
pub mod actions;
pub mod audit;
pub mod binding;
pub mod connect;
pub mod inbox;
pub mod messages;
pub mod moment;
pub mod pair;
pub mod presence;
pub mod record;
pub mod recovery;
pub mod rights;

mod address;
mod store;
mod stream;
mod sweep;
mod tlv;
mod window;

/// How often a service sweeps the durable state it serves: the message queue's retention and
/// taken identifiers, and the action memory's compaction. The inbox runs one sweep for both.
pub(crate) const SWEEP_EVERY: Duration = Duration::from_secs(30);

pub use access::{
    Account, Authority, Binding, Capability, Claim, Fact, FactError, Instance, Issuer, Label,
    LabelError, Pair, PersonName, Right, Standing,
};
pub use actions::{
    ACTION_BUDGET, ACTION_ID_BYTES, ACTION_MEMORY_RETENTION, ACTION_WINDOW, ActionAnswer,
    ActionError, ActionId, ActionKind, ActionMalformed, ActionMark, Actions, EXECUTION_BUDGET,
    Executed, Execution, ExecutionFuture, Executor, MAX_ACTION_BODY_BYTES, MAX_ACTIONS_PER_WINDOW,
    MAX_RESULT_BYTES,
};
pub use audit::{
    Act, AuditError, AuditLog, DropReason, Dropped, Entry, GrantKind, RefusedReason, WriteRefusal,
};
pub use binding::EXCHANGE_BUDGET;
pub use connect::{
    ACCEPT_IN_FLIGHT, Connections, DIAL_BUDGET, KEEPER_SETTLE, ManagerError, Started, TRUST_POLL,
    Traffic, VANISH_BOUND, Vanish,
};
pub use inbox::{Inbox, InboxError};
pub use messages::{
    Answer, Deliveries, Delivery, Envelope, EnvelopeId, FramingFault, Gap, MAX_BODY_BYTES,
    MAX_OFFERS_PER_WINDOW, MAX_QUEUE, MESSAGE_BUDGET, MESSAGE_RETENTION, MESSAGE_WINDOW, Message,
    MessageError, MessageMalformed, Messages, QueueState, Sweep, TAKEN_RETENTION,
};
pub use moment::Moment;
pub use pair::{
    COMPARISON_SYMBOLS, Ceremony, Comparison, Opening, Outcome, PAIR_FLIGHT_TIMEOUT, PairError,
    Person, Role, Turn,
};
pub use presence::{Presence, Registration};
pub use record::{Attempt, Limits, Malformed, PeerRecord, RecordError, RecordStore, Timestamp};
pub use recovery::{
    ConnectFailure, NotTrustedCause, RECOVERY_DIALS, RECOVERY_FIRST_GAP, RECOVERY_RECHECK,
    Recovery, StopCause,
};
pub use rights::{
    Closed, Decision, Floor, NoFloor, Question, Refusal, Restored, Rights, RightsError, Speaker,
    Step,
};
