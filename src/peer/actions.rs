//! An action: something one machine asks another to do, which must not happen twice.
//!
//! # At most once, and whose identifier it is
//!
//! An action carries an identifier the *caller* names, a kind and a bounded body. The crate
//! never mints one: a caller that repeats the same operation carries the same identifier and
//! is answered "already executed", while a person deliberately running the command again is a
//! new operation with a new identifier and does run. At most once therefore cannot be held by
//! this crate alone, and the obligation is the caller's: **remember an operation's identifier
//! before asking**, because a caller that forgets it and asks again after its own crash has
//! asked for a new operation. An identifier belongs to one operation; using it for a different
//! one is answered as a repeat, and that too is the caller's obligation.
//!
//! The receiving machine keeps a durable journal of the identifiers it has executed. A repeat
//! under a remembered identifier is not executed and is answered [`ActionAnswer::AlreadyExecuted`].
//! The identifier is remembered *before* the run it describes, so an action that ran is never
//! missing from the memory. Nothing is remembered for a refusal, and a decline is forgotten
//! again, because neither executed. The cost is stated rather than hidden: a crash in that
//! window can leave an identifier remembered for an action that did not run, and a repeat is
//! then answered "already executed" for something that never happened. A decline whose
//! identifier another writer holds at that instant is the same cost — the identifier stays
//! spent — and a repeat that arrives while the first run is still in progress gets the same
//! answer as one arriving after it. A decline releases the identifier, so a repeat after it
//! runs again; a memory that cannot release it never changes the answer — the release is
//! attempted, then the decline is answered, and only then does a hard fault end the service.
//!
//! # No queue, and no automatic retry
//!
//! An action runs on the live connection and nowhere else. There is no sender-side
//! queue, no retention and no store-and-forward, because holding an action until a connection
//! appears is a retry wearing another name. If the pair is not connected when a person asks,
//! [`Actions::request`] dials — the plan allows exactly that — and if the dial fails the caller
//! is told the failure it already knows, with the action held nowhere. A request this machine
//! could not get onto the wire — no stream could be opened, or the write did not finish — is
//! [`ActionError::NotSent`], unless the receiver had already answered: that answer is read under
//! a short courtesy bound and handed back, so a request the receiver answered is never reported
//! as unsent. This layer keeps no mark for a request it did not get out, and a frame that may
//! have been whole is stopped from running twice by the receiver's journal. Once the request is
//! on the wire and no answer comes back, the action is marked unknown: the mark is durable, kept
//! per peer, bounded like the rest of what this machine remembers, survives a restart, and is
//! read back by [`Actions::unknown`]. A trace that cannot be kept is not claimed: the caller is
//! answered [`ActionError::Untraced`], which names both the outcome and the storage refusal,
//! and the receiver's journal still stops a repeat. While the mark is kept, the same identifier
//! is never offered again by this crate. The memory keeps the newest marks and drops the oldest
//! to make room; a repeat whose mark was dropped reaches the receiver, whose journal answers
//! "already executed" for as long as it remembers, so at-most-once still holds and only this
//! machine's trace is lost.
//!
//! # What the receiving machine decides, and in what order
//!
//! The connection's attested peer is the author; nothing in the body can change that or choose
//! which right is asked. The order is authenticate, the right, the host's own floor, the kind,
//! the journal, the record of the execution, then the run. A request is refused unless the peer
//! is trusted, the pair is known to this machine and the sender holds "work on me" for that
//! pair's assistant; the pair is the one the message layer uses — this machine's own binding
//! where it decided, and otherwise the claim it was sent. A pair whose binding has not arrived
//! is answered [`ActionAnswer::NotReady`], which is neither a refusal nor an execution. A
//! refusal names the step that refused it and is recorded; it is a refusal of that action and
//! never of the pair. The kind is checked after the right and the floor, so a peer without
//! "work on me" is refused at that step whatever kind it names; a kind this build does not know
//! is then answered [`ActionAnswer::Unsupported`] rather than run as a command, and is not
//! remembered because nothing ran.
//!
//! # The answer never guesses
//!
//! [`ActionAnswer::AlreadyExecuted`] means one thing only: this identifier is spent here and
//! will not be run again. It carries no result, because none is kept, and it makes no claim
//! about how the action ended. An action this machine's own code declines is answered
//! [`ActionAnswer::NotRun`] and is not remembered — a decline and a repeat are different
//! answers and neither is silence. The decline is answered even when the memory cannot release
//! the identifier: another writer leaves it spent, and a hard fault ends the service after the
//! answer. A refusal is never remembered, so a person who grants the right and repeats the
//! operation gets it executed rather than "already executed".
//!
//! # The audit comes before the run
//!
//! The record of an execution is written before the run, as every other act in this crate is:
//! it names the peer, the pair, the right it ran under and the identifier, and it never carries
//! the body — the crate does not write a peer's bytes into the log, so what the command
//! actually was is the product's own record, keyed by the identifier. Nothing is executed
//! unrecorded: if the entry cannot be written, the action does not run and the sender is told so
//! with [`ActionAnswer::NotRecorded`]. A log with no room left therefore stops a peer from
//! acting, visibly and predictably, against an execution nobody recorded.
//!
//! # The memory is durable, per peer and bounded
//!
//! Remembered identifiers live under `actions/` in the storage root, private to the account the
//! product runs as, versioned and additive in the same way as everything else on that root,
//! written atomically and shared safely by every handle and every process on the root. They are
//! kept per peer, so one peer's flood cannot push another peer's identifiers out, and for
//! [`ACTION_MEMORY_RETENTION`] — after it a repeat of an old identifier may execute a second
//! time, which is the honest cost of remembering rather than the alternative. Expired entries
//! are cleared before the memory is called full. When it is full, new actions from that peer are
//! refused with [`ActionAnswer::MemoryFull`] rather than an identifier being forgotten to make
//! room: forgetting one would turn into a command running twice on someone's machine, which is
//! the whole rule's reason to exist. The way out for a machine that has filled it is the one
//! that already exists: a person withdraws trust in that machine. The record keeps the moment of
//! that withdrawal, and every look at the memory treats everything recorded before it as
//! gone, so the clearing does not depend on a service being up to notice it: a product that
//! stops the peer's service for the whole withdrawal and starts it again after the return still
//! forgets.
//!
//! # Executing takes time, and the layer bounds its waits
//!
//! The machine's own code is given [`EXECUTION_BUDGET`] to say whether it ran and what came
//! back. If it cannot answer within that bound, the sender is told
//! [`ActionAnswer::Unknown`] and the identifier stays remembered, because the action may well
//! have run. A slow execution never holds up a different pair, and one that panics tells the
//! sender the outcome is unknown and then ends the service with a visible fault, as a panicking
//! delivery sink already does.
//!
//! # One connection carries both
//!
//! Messages and actions share the pair's connection. An action in flight does not count as the
//! pair having carried traffic for the connection manager, while an answer that means the
//! receiving side accepted the operation does — it ran, ran with a result too large to carry, or
//! the identifier was already spent there. A message counts only the take; an action also counts
//! a repeat, because its journal proves the receiver accepted the operation before. Every other
//! answer means nothing was taken, so a slow-down followed by a dropped connection is not a link
//! failure to be re-dialled.
//!
//! # Nothing acts on a body by itself
//!
//! This module hands the body to the [`Executor`] the product supplied and takes back whether
//! it ran and what came back. It names no capability and asks no question of its own: its one
//! decision is `Rights::may_run_action`, whose inputs are the
//! transport's peer, the host's floor and the moment. The invariant
//! `actions.no_capability_from_a_body` scans these sources to keep it that way, so no path
//! leads from a body to a right, a grant or a capability.

mod store;
mod wire;

use std::fmt;
use std::future::Future;
use std::io;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};

use quinn::{Endpoint, RecvStream, Runtime, SendStream};

use crate::beacon::{sleep, timeout};
use crate::hex;
use crate::identity::PeerId;
use crate::peer::EXCHANGE_BUDGET;
use crate::peer::FramingFault;
use crate::peer::access::Pair;
use crate::peer::audit::{Act, AuditError, AuditLog, Entry};
use crate::peer::connect::{Connections, DIAL_BUDGET, RecordRead, Traffic};
use crate::peer::moment::Moment;
use crate::peer::record::{RecordError, RecordStore, Timestamp};
use crate::peer::recovery::{ConnectFailure, NotTrustedCause, Recovery};
use crate::peer::rights::{Admission, Floor, Rights, RightsError, Step};
use crate::peer::stream::{self, ReadFault};
use crate::peer::window::Windows;

/// The most bytes one action's body may have.
///
/// The action frame's own cap, versioned with the frame: it is deliberately not the message
/// layer's number, because raising that one must not silently grow a version-1 action body
/// past what an older build accepts.
pub const MAX_ACTION_BODY_BYTES: usize = 4096;

/// The most bytes of a result the answer carries.
///
/// A result that does not fit is not carried and is not truncated: the answer says the action
/// ran and the result was too large to carry, so the identifier stays remembered.
pub const MAX_RESULT_BYTES: usize = 4096;

/// The bytes in an action's identifier.
///
/// Public as a format fact: [`ActionId::from_bytes`] and [`ActionId::as_bytes`] name the length
/// in their signatures, so a caller that holds an identifier as bytes need not spell `16` itself.
pub const ACTION_ID_BYTES: usize = 16;

/// The bytes an action request opens with, so the inbox can tell it from a message.
pub(crate) const ACTION_MAGIC: &[u8] = wire::ACTION_MAGIC;

/// The most bytes one action's file may have.
///
/// A file at `MAX_EXECUTED` executed identifiers and `MAX_UNKNOWN` marks sits well under
/// this; the cap keeps a hostile file from being read into memory and refuses a write that
/// would produce a file this build could not read back. It is the format's own number, so it is
/// named here and not re-exported at `peer`, as the record's and the queue's caps are not.
pub const MAX_ACTIONS_BYTES: u64 = 512 * 1024;

/// How many executed identifiers one peer's memory keeps.
pub(crate) const MAX_EXECUTED: usize = 2048;

/// How many unknown marks one peer's memory keeps.
pub(crate) const MAX_UNKNOWN: usize = 2048;

/// How long an executed identifier is remembered, and how long an unknown mark is kept.
///
/// Past it a repeat of an old identifier may execute a second time, which is the honest cost of
/// remembering by identifier and nothing else. It is the message layer's week for its taken
/// identifiers.
pub const ACTION_MEMORY_RETENTION: Duration = Duration::from_hours(7 * 24);

/// The window a receiver counts one peer's actions in.
pub const ACTION_WINDOW: Duration = Duration::from_secs(60);

/// How many actions one peer may send per [`ACTION_WINDOW`].
pub const MAX_ACTIONS_PER_WINDOW: u32 = 30;

/// The one bound on one request, measured by the injected runtime.
///
/// One request has one bound, and everything the crate waits for on the person's behalf is
/// inside it, reading the record included: reaching the pair, opening the stream, writing the
/// frame and reading the answer share this budget, so a caller waits at most this long for one
/// action's outcome. A record fault that clears costs at most the rounds it took, and the read
/// never spends the budget's last dial-length — the time one dial can take, from the caller's
/// hint and the remembered address, through the beacon, to the address the beacon names. A dial
/// started in that length runs to its own end, so the read cannot be why the dial did not happen;
/// a fault still unread when it begins is answered with the pair's own reason, which is the
/// deferral when the state names none other.
///
/// What the crate writes *after* the work is not a wait and is not cut short by the budget: an
/// outcome that may have happened is remembered whatever the clock says, and a memory that
/// could not be written is reported as the fault it is. A receiver's own `unknown` answer for a
/// slow execution arrives only if the dial and the stream open left [`EXECUTION_BUDGET`] of the
/// budget; when they did not, the sender stops waiting first and marks the action unknown
/// itself, which is the same answer.
pub const ACTION_BUDGET: Duration = Duration::from_secs(90);

// The record read reserves one dial of the budget, so a budget that is not longer than a dial
// would leave nothing to reserve: the reservation refuses at compile time rather than reading
// the whole budget and cutting the dial it promised.
const _: () = assert!(
    DIAL_BUDGET.as_nanos() < ACTION_BUDGET.as_nanos(),
    "the action budget is not longer than the dial its record read reserves"
);

/// How long the machine's own code has to say whether it ran and what came back.
pub const EXECUTION_BUDGET: Duration = Duration::from_secs(60);

/// How long one side waits to read a request or write its answer.
///
/// The sender also uses it as the courtesy read after a write that did not finish. A request and
/// an answer are at most a few datagrams, so a peer that stalls either half is given the message
/// layer's bound rather than the sender's whole [`ACTION_BUDGET`]: a stalled stream must not pin
/// its task for the time an execution is allowed to take.
pub(crate) const ACTION_STREAM_BUDGET: Duration = Duration::from_secs(10);

/// How long the receiver drains a request it refused to look at, so the sender's write finishes.
///
/// The rest of a refused request is at most [`MAX_ACTION_FRAME_BYTES`], so a sender that cannot
/// deliver it within this bound is stalled: the stream is dropped rather than pinning the task
/// for the time a request it *would* read is allowed.
const ACTION_DRAIN_BUDGET: Duration = Duration::from_secs(2);

/// How long the sender waits between rounds while a dial or a binding exchange is in progress.
pub(crate) const ACTION_POLL: Duration = Duration::from_secs(1);

/// The most bytes one request may occupy on the wire.
pub(crate) const MAX_ACTION_FRAME_BYTES: usize = MAX_ACTION_BODY_BYTES + 256;

/// How many bytes of an answer this build reads.
///
/// An answer is a magic, a version, a status and at most a result of [`MAX_RESULT_BYTES`] or a
/// four-byte delay. The set grows by appending, so the cap leaves room for a field a newer
/// build adds; an answer longer than this is not read whole, which is no answer at all.
pub(crate) const ACTION_ANSWER_BYTES: usize = MAX_RESULT_BYTES + 256;

/// The name of an operation: [`ACTION_ID_BYTES`] bytes, named once by the caller.
///
/// The identifier is what a receiver deduplicates on. It is not a key and proves nothing: it is
/// a name, and the author is the connection's attested peer. The crate never mints one — see
/// the module documentation for the caller's obligation.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActionId([u8; ACTION_ID_BYTES]);

impl ActionId {
    /// Read an identifier from its bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ACTION_ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// The identifier lowercase hex names, or `None` for anything else.
    #[must_use]
    pub fn from_hex(text: &str) -> Option<Self> {
        let bytes = hex::decode(text)?;
        <[u8; ACTION_ID_BYTES]>::try_from(bytes.as_slice())
            .ok()
            .map(Self)
    }

    /// The identifier's bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ACTION_ID_BYTES] {
        &self.0
    }
}

impl fmt::Display for ActionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::write(f, &self.0)
    }
}

impl fmt::Debug for ActionId {
    /// The identifier's one spelling, not a second one.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// What an action asks for, as a closed list.
///
/// `Command` is the only kind this build knows. A value outside the list exists only in an
/// action a newer build wrote: the receiver answers it as [`ActionAnswer::Unsupported`] rather
/// than run it as a command, and the kind travels with the action to the machine's own code so
/// the seam can carry a second kind later. Screen input is the product's, together with the
/// screen, and is not built here.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActionKind(u8);

impl ActionKind {
    /// Run a command: the plan's "work on me".
    pub const COMMAND: Self = Self(1);

    /// The byte a frame carries.
    #[must_use]
    pub(crate) const fn as_byte(self) -> u8 {
        self.0
    }

    /// The kind a stored byte names, known or not.
    ///
    /// Only a decoder uses this: a kind this build does not know is answered as unsupported,
    /// and no executor is handed one.
    pub(crate) const fn from_raw(byte: u8) -> Self {
        Self(byte)
    }
}

impl fmt::Display for ActionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::COMMAND => f.write_str("run a command"),
            Self(byte) => write!(f, "action kind {byte}"),
        }
    }
}

impl fmt::Debug for ActionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// One action as it travels: its identifier, its kind and its body.
///
/// Crate-private: no public entry point takes one — [`Actions::request`] takes the pieces.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Action {
    id: ActionId,
    kind: ActionKind,
    body: Vec<u8>,
}

impl Action {
    /// Compose an action from its identifier, kind and body.
    ///
    /// # Errors
    ///
    /// [`ActionError::Body`] when the body is longer than [`MAX_ACTION_BODY_BYTES`].
    pub(crate) fn new(
        id: ActionId,
        kind: ActionKind,
        body: impl Into<Vec<u8>>,
    ) -> Result<Self, ActionError> {
        let body = body.into();
        if body.len() > MAX_ACTION_BODY_BYTES {
            return Err(ActionError::Body {
                bytes: body.len(),
                limit: MAX_ACTION_BODY_BYTES,
            });
        }
        Ok(Self { id, kind, body })
    }

    /// The operation's identifier, as the caller named it.
    #[must_use]
    pub(crate) const fn id(&self) -> ActionId {
        self.id
    }

    /// What the action asks for.
    #[must_use]
    pub(crate) const fn kind(&self) -> ActionKind {
        self.kind
    }

    /// The body, exactly as the caller composed it.
    #[must_use]
    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }

    /// The action's bytes, as the request carries them.
    ///
    /// Infallible: [`Self::new`] and [`Self::decode`] both hold the body to
    /// [`MAX_ACTION_BODY_BYTES`], which fits the frame's own length field.
    pub(crate) fn encode(&self) -> Vec<u8> {
        wire::encode_action(self)
    }

    /// One action, from the bytes a request carried.
    ///
    /// # Errors
    ///
    /// [`ActionError::Frame`], naming what is wrong with the bytes.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, ActionError> {
        wire::decode_action(bytes)
    }
}

impl fmt::Debug for Action {
    /// The identifier, the kind and the body's length, never the body.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Action")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// The answer to one action: what the receiving machine tells the sender, and what
/// [`Actions::request`] returns.
///
/// One vocabulary serves both, because the two are one fact: the receiver composes the answer,
/// the sender reads it whole or not at all, and a caller is told exactly what the receiver
/// answered. Every variant is itself — a run, a run whose result was not carried, a repeat, a
/// decline, a refusal, a not-ready, an unsupported kind, an unknown, a slow-down, a full
/// memory, an unrecorded execution, a busy memory and an unreadable frame are never merged
/// into one "no".
#[derive(Clone, PartialEq, Eq)]
pub enum ActionAnswer {
    /// The action ran and its result is here.
    Ran {
        /// What the machine's own code returned.
        result: Vec<u8>,
    },
    /// The action ran, and the result was too large to carry.
    RanNotCarried,
    /// The identifier is one this machine executed before. It carries no result, because none
    /// is kept, and makes no claim about how the action ended.
    AlreadyExecuted,
    /// The machine's own code declined to run it. It is not remembered — unless another writer
    /// holds the memory at that instant, in which case the identifier stays spent, the same
    /// cost as a crash between remembering and running. The decline is answered before any
    /// memory fault can end the service, so it never becomes an unknown.
    NotRun,
    /// The receiver's rights refused it, at this step. The class is all the sender is told:
    /// why is the receiver's business, and its words stay there.
    Refused {
        /// The step that refused.
        step: Step,
    },
    /// Neither a binding this machine decided nor a claim has arrived: the caller may ask
    /// again once one has.
    NotReady,
    /// This build does not know the action's kind; it was not run and is not remembered.
    Unsupported,
    /// The action may have run, and its result did not come back within the bound. A receiver
    /// that took the request keeps the identifier in its journal, so a repeat there is answered
    /// "already executed"; this machine also records the unknown trace, and a restart still
    /// shows it. This crate never offers the identifier again while that mark is kept; the
    /// memory's own bound drops the oldest, and a repeat then reaches the receiver's journal
    /// instead. An answer that never came back says nothing about what the receiver holds: it
    /// may not have seen the request at all.
    Unknown,
    /// Too many actions in the window; wait this long before asking again.
    SlowDown {
        /// How long until the receiver's window turns, never more than [`ACTION_WINDOW`]:
        /// the wire clamps a peer's number to one window when it is read, so a peer cannot hand
        /// this machine an unbounded wait. Only `Windows::admit` composes one here, and it
        /// never returns more than the window, so a delay this machine writes is already
        /// bounded.
        retry_after: Duration,
    },
    /// The journal is full: a new identifier is refused rather than an old one forgotten.
    MemoryFull,
    /// The execution could not be recorded in the log, so it did not run.
    NotRecorded,
    /// Another writer holds this machine's memory for the peer this instant; nothing ran and
    /// nothing was remembered, and the same call is worth making again.
    Busy,
    /// The receiver could not read the frame, so nothing ran and the identifier is not spent.
    ///
    /// A receiver answers it to a frame this build cannot decode — one longer than the layer's
    /// cap, or one whose fields are wrong. A frame whose opening bytes never completed the
    /// action magic is classified as a message by the inbox and answered by the message layer,
    /// so it reaches the sender as [`Self::Unknown`] instead.
    Unreadable,
}

impl ActionAnswer {
    /// Whether this answer means the receiving side accepted the operation: it ran, it ran
    /// with a result too large to carry, or the identifier was already spent there.
    #[must_use]
    pub(crate) const fn accepted(&self) -> bool {
        matches!(
            self,
            Self::Ran { .. } | Self::RanNotCarried | Self::AlreadyExecuted
        )
    }

    /// The answer's bytes.
    pub(crate) fn encode(&self) -> Vec<u8> {
        wire::encode_answer(self)
    }

    /// One answer, from the bytes a reply carried.
    ///
    /// Public like the message layer's own answer: a caller reads an answer off the wire, and
    /// there is no builder to hide it behind, because only a receiver composes one.
    ///
    /// # Errors
    ///
    /// [`ActionError::Frame`], naming what is wrong with the bytes: a frame this build cannot
    /// read, a missing status, or one it does not know.
    pub fn decode(bytes: &[u8]) -> Result<Self, ActionError> {
        wire::decode_answer(bytes)
    }
}

impl fmt::Debug for ActionAnswer {
    /// The variant and a result's length, never the result.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ran { result } => f
                .debug_struct("Ran")
                .field("result_len", &result.len())
                .finish(),
            Self::RanNotCarried => f.write_str("RanNotCarried"),
            Self::AlreadyExecuted => f.write_str("AlreadyExecuted"),
            Self::NotRun => f.write_str("NotRun"),
            Self::Refused { step } => f.debug_struct("Refused").field("step", step).finish(),
            Self::NotReady => f.write_str("NotReady"),
            Self::Unsupported => f.write_str("Unsupported"),
            Self::Unknown => f.write_str("Unknown"),
            Self::SlowDown { retry_after } => f
                .debug_struct("SlowDown")
                .field("retry_after", retry_after)
                .finish(),
            Self::MemoryFull => f.write_str("MemoryFull"),
            Self::NotRecorded => f.write_str("NotRecorded"),
            Self::Busy => f.write_str("Busy"),
            Self::Unreadable => f.write_str("Unreadable"),
        }
    }
}

/// What the machine's own code is handed for one action.
#[derive(Clone, PartialEq, Eq)]
pub struct Execution {
    /// The transport's attested peer: the author, taken from the connection.
    pub peer: PeerId,
    /// The pair the action ran under: the machine and the assistant it is connected to.
    pub pair: Pair,
    /// The operation's identifier, as the sender named it.
    pub id: ActionId,
    /// What the action asks for.
    pub kind: ActionKind,
    /// The body, exactly as the sender composed it.
    pub body: Vec<u8>,
}

impl fmt::Debug for Execution {
    /// The identifiers, the pair and the body's length, never the body.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Execution")
            .field("peer", &self.peer)
            .field("pair", &self.pair)
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// What the machine's own code says it did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Executed {
    /// It ran, and this is what came back.
    Ran {
        /// The result, which the answer carries when it fits [`MAX_RESULT_BYTES`].
        result: Vec<u8>,
    },
    /// It did not run: the command was not one this machine runs, or the person running it
    /// said no. Nothing is remembered for a decline.
    Declined,
}

/// The future one execution returns.
pub type ExecutionFuture<'a> = Pin<Box<dyn Future<Output = Executed> + Send + 'a>>;

/// Where an action goes to be executed.
///
/// The crate never runs anything itself: it hands the body to this and takes back whether it
/// ran and what came back. The future is polled under [`EXECUTION_BUDGET`]; when the budget
/// passes it is dropped and the sender is answered [`ActionAnswer::Unknown`], because the
/// action may already have run. A product that must let the work finish should hand it to its
/// own task and await the outcome here, so a dropped future does not stop the work. A panic —
/// in `execute` itself or in the future it returns — tells the sender the outcome is unknown and
/// ends the service with a visible fault, as a panicking delivery sink does.
pub trait Executor: Send + Sync {
    /// Run one action, answering whether it ran and what came back.
    fn execute(&self, action: Execution) -> ExecutionFuture<'_>;
}

/// One identifier this machine sent to a peer and never heard the result of.
///
/// The mark is durable and survives a restart; [`Actions::unknown`] reads it back. It is not a
/// queue: nothing is held for a retry. While the mark is kept, this crate never offers the
/// identifier again; the memory drops the oldest past its bound, and a repeat whose mark was
/// dropped reaches the receiver's journal instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActionMark {
    /// The operation's identifier.
    pub id: ActionId,
    /// The moment it became unknown.
    pub at: Timestamp,
}

/// The action layer of one machine.
///
/// Built once per storage root, like the records and the log: the store it holds names the
/// root's `actions/` directory, and a second layer over one root shares it rather than copying
/// it.
pub struct Actions {
    rights: Rights,
    floor: Arc<dyn Floor + Send + Sync>,
    moment: Arc<dyn Moment + Send + Sync>,
    executor: Arc<dyn Executor + Send + Sync>,
    runtime: Arc<dyn Runtime>,
    store: store::ActionStore,
    /// The receiver's token buckets, one per peer, in memory only.
    windows: Windows,
}

impl fmt::Debug for Actions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Actions")
            .field("store", &self.store)
            .finish_non_exhaustive()
    }
}

impl Actions {
    /// Open the action layer over `root`.
    ///
    /// The root must exist and is never created: a mistyped or deleted root must fail loudly,
    /// not answer an empty memory that looks like a machine that never acted. The `actions/`
    /// directory is created on the first start and held to the key file's rule.
    ///
    /// The records and the log are the caller's handles — build them over the same root — and
    /// the decision is built from them here. The floor, the clock, the executor and the runtime
    /// are injected: this crate has no runtime of its own, and the layer needs one to measure
    /// its waits and to answer a peer.
    ///
    /// # Errors
    ///
    /// [`ActionError::RootMissing`] when the root is not a directory, and
    /// [`ActionError::Insecure`] when `actions/` is reachable by another account.
    pub fn open(
        root: &Path,
        records: RecordStore,
        audit: AuditLog,
        floor: Arc<dyn Floor + Send + Sync>,
        moment: Arc<dyn Moment + Send + Sync>,
        executor: Arc<dyn Executor + Send + Sync>,
        runtime: Arc<dyn Runtime>,
    ) -> Result<Self, ActionError> {
        let store = store::ActionStore::open(root)?;
        Ok(Self {
            rights: Rights::new(records, audit),
            floor,
            moment,
            executor,
            runtime,
            store,
            windows: Windows::new(),
        })
    }

    /// Ask `peer` to run one action, and answer what became of it.
    ///
    /// The record is read first: a peer this machine no longer remembers, one whose trust it
    /// withdrew, or a pair closed by three failed comparisons is refused before anything is
    /// sent. A body over [`MAX_ACTION_BODY_BYTES`] is refused, and an identifier already marked
    /// unknown for this peer is answered [`ActionAnswer::Unknown`] without being offered again.
    ///
    /// # Errors
    ///
    /// The record's three refusals ([`ActionError::NotPaired`], [`ActionError::Withdrawn`],
    /// [`ActionError::Closed`]), a record whose bytes cannot be read, [`ActionError::Body`], the
    /// dial's own failure — including the deferral a fault still unread when the budget's last
    /// dial-length begins becomes — a request that may not have left, [`ActionError::Untraced`]
    /// when the unknown trace could not be kept, and the log's and the decision's own refusals.
    pub async fn request(
        &self,
        connections: &Connections,
        endpoint: &Endpoint,
        peer: &PeerId,
        id: ActionId,
        kind: ActionKind,
        body: &[u8],
    ) -> Result<ActionAnswer, ActionError> {
        let action = Action::new(id, kind, body)?;
        // One budget for the whole request: the deadline is taken once and every wait below
        // shares it, so a call that reaches a dead connection cannot spend a second one.
        let deadline = self.runtime.now() + ACTION_BUDGET;
        // The read stops one dial short, so the dial this call asked for still fits in what is
        // left and the read cannot be why the dial did not happen. The ordering is a compile-time
        // check, so this cannot fall back to reading the whole budget.
        let reading = deadline
            .checked_sub(DIAL_BUDGET)
            .expect("DIAL_BUDGET is shorter than ACTION_BUDGET, checked at compile time");
        // The record is read through the manager, which is the one place a read is classified: a
        // fault that may pass is deferred there and folded into the pair's state.
        let record = loop {
            match connections.standing(peer) {
                RecordRead::Trusted(record) => break record,
                RecordRead::Unreadable(error) => return Err(error.into()),
                RecordRead::Refused(cause) => return Err(unpaired(*peer, cause)),
                RecordRead::Deferred { detail } => {
                    let failure = ConnectFailure::Deferred {
                        peer: peer.fingerprint(),
                        detail,
                    };
                    if self.runtime.now() >= reading {
                        // The state is the truth, and the answer is derived from it, so a pair
                        // whose last dial met something else keeps that reason.
                        let (_, named) = connections.state_and_reason(peer);
                        return Err(ActionError::Connect(named.unwrap_or(failure)));
                    }
                    connections.deferral_pause(Some(reading)).await;
                }
            }
        };
        let now = self.moment.now();
        let since = record.last_withdrawn_at();
        if self.store.is_unknown(peer, id, now, since)? {
            return Ok(ActionAnswer::Unknown);
        }
        let traffic = self
            .reachable(connections, endpoint, peer, deadline)
            .await?;
        let offered = {
            let _round = traffic.round();
            offer(&*self.runtime, traffic.connection(), &action, deadline).await
        };
        match offered {
            // The frame may be whole on the wire and no answer came back, so the action may
            // have run. The mark is a trace, not the answer.
            Offered::NoAnswer => {
                self.trace(*peer, id, since)?;
                Ok(ActionAnswer::Unknown)
            }
            // The request may not have left this machine: this layer keeps no mark for it.
            Offered::NotSent => Err(ActionError::NotSent { peer: *peer }),
            // The peer answered. A receiver that could not say whether it ran answered
            // `Unknown`; the action may have run, so the sender keeps the same durable trace
            // it keeps for a lost answer, and a restart still shows it.
            Offered::Answer(answer) => {
                if matches!(answer, ActionAnswer::Unknown) {
                    self.trace(*peer, id, since)?;
                }
                // Only an answer that means the receiving side accepted the operation — it
                // ran, ran with a result too large to carry, or the identifier was already
                // spent there — is the pair's traffic; every other answer means nothing was
                // taken. An in-flight action is not the pair's traffic either.
                if answer.accepted() {
                    traffic.took();
                }
                Ok(answer)
            }
        }
    }

    /// The identifiers this machine sent to `peer` and never heard the result of.
    ///
    /// Read back after a restart, so the one trace that something may have run is not lost.
    /// Marks past [`ACTION_MEMORY_RETENTION`] are not returned, and neither is a mark recorded
    /// before this machine's most recent withdrawal of trust in the peer.
    ///
    /// A mark is written when no answer comes back, including when the receiver answers that
    /// it could not tell. It can be lost if another writer holds the memory at that instant —
    /// the same cost as a crash between remembering and running — but the receiver's journal
    /// still stops a second run, so at-most-once does not depend on the mark. The newest marks
    /// are kept and the oldest are dropped past the memory's bound, for the same reason: a
    /// repeat whose mark was dropped reaches the receiver's journal rather than running twice.
    ///
    /// # Errors
    ///
    /// The memory's own refusals.
    pub fn unknown(&self, peer: &PeerId) -> Result<Vec<ActionMark>, ActionError> {
        let since = self
            .rights
            .records()
            .reread(peer)?
            .and_then(|record| record.last_withdrawn_at());
        self.store.unknown(peer, self.moment.now(), since)
    }

    /// Drop the memory a peer's most recent trust withdrawal made moot.
    ///
    /// A product may call it on its own schedule; the inbox calls it once every `SWEEP_EVERY`
    /// for the pairs it serves.
    ///
    /// # Errors
    ///
    /// [`ActionError::Busy`] when another writer holds the memory this instant, and the
    /// memory's and the record's own refusals.
    pub fn sweep(&self, peer: &PeerId) -> Result<(), ActionError> {
        let Some(since) = self
            .rights
            .records()
            .reread(peer)?
            .and_then(|record| record.last_withdrawn_at())
        else {
            return Ok(());
        };
        self.store.sweep(peer, since)
    }

    /// The moment this layer reads, for the inbox's sweep.
    pub(crate) fn now(&self) -> Timestamp {
        self.moment.now()
    }

    /// The directory under `root` that holds the memories.
    ///
    /// Public for the same reason the record's and the queue's are: a backup or a repair must
    /// be able to name it on a root where opening would fail or create it.
    #[must_use]
    pub fn dir_in(root: &Path) -> PathBuf {
        store::dir_in(root)
    }

    /// The path of `peer`'s memory under `root`.
    ///
    /// Public for the same reason [`Self::dir_in`] is: a caller that must name one memory
    /// without opening the store — a repair, a backup — asks here instead of spelling the name.
    #[must_use]
    pub fn path_for(root: &Path, peer: &PeerId) -> PathBuf {
        store::path_in(&Self::dir_in(root), peer)
    }

    /// The lock file a writer of `peer`'s memory holds, beside the memory itself.
    ///
    /// Public for the reason [`Self::path_for`] is: a backup or a repair must be able to tell
    /// the file a writer locks from the memory it writes, and a second process asks here
    /// instead of spelling the name.
    #[must_use]
    pub fn lock_path_for(root: &Path, peer: &PeerId) -> PathBuf {
        store::lock_in(&Self::dir_in(root), peer)
    }

    /// Answer one action request on `send`/`recv`, whose first bytes are `prefix`.
    pub(crate) async fn receive(
        &self,
        peer: PeerId,
        send: SendStream,
        mut recv: RecvStream,
        prefix: Vec<u8>,
    ) -> Result<(), ActionError> {
        let now = self.moment.now();
        if let Some(retry_after) =
            self.windows
                .admit(&peer, now, ACTION_WINDOW, MAX_ACTIONS_PER_WINDOW)
        {
            reply(
                &*self.runtime,
                send,
                &ActionAnswer::SlowDown { retry_after },
            )
            .await;
            // Drain the request so the sender's write completes: a reset here would turn a
            // refusal the receiver made into an unknown mark on the sender's side, which is
            // the one answer this path must not produce. The wait is the short drain bound;
            // the frame's size bounds how much is read, not how long it may take.
            let _ = stream::read_rest(
                &*self.runtime,
                &mut recv,
                prefix,
                MAX_ACTION_FRAME_BYTES,
                ACTION_DRAIN_BUDGET,
            )
            .await;
            return Ok(());
        }
        let bytes = match stream::read_rest(
            &*self.runtime,
            &mut recv,
            prefix,
            MAX_ACTION_FRAME_BYTES,
            ACTION_STREAM_BUDGET,
        )
        .await
        {
            Ok(bytes) => bytes,
            Err(ReadFault::TooLong) => {
                reply(&*self.runtime, send, &ActionAnswer::Unreadable).await;
                return Ok(());
            }
            Err(ReadFault::Stalled) => return Ok(()),
        };
        let Ok(action) = Action::decode(&bytes) else {
            reply(&*self.runtime, send, &ActionAnswer::Unreadable).await;
            return Ok(());
        };
        self.decide_and_run(peer, action, now, send).await
    }

    /// Decide one decoded action and run it if it may be run, answering the sender.
    async fn decide_and_run(
        &self,
        peer: PeerId,
        action: Action,
        now: Timestamp,
        send: SendStream,
    ) -> Result<(), ActionError> {
        let (pair, right, since) = match self.rights.may_run_action(&peer, &*self.floor, now)? {
            Admission::Allowed { pair, right, since } => (pair, right, since),
            Admission::Unbound => {
                reply(&*self.runtime, send, &ActionAnswer::NotReady).await;
                return Ok(());
            }
            Admission::Refused(refusal) => {
                reply(
                    &*self.runtime,
                    send,
                    &ActionAnswer::Refused {
                        step: refusal.step(),
                    },
                )
                .await;
                return Ok(());
            }
        };
        // The right and the floor are settled first, so a peer without "work on me" is refused
        // at that step whatever kind it names. A kind this build does not know is then refused
        // rather than run as a command; it is not remembered, because nothing ran.
        if action.kind() != ActionKind::COMMAND {
            reply(&*self.runtime, send, &ActionAnswer::Unsupported).await;
            return Ok(());
        }
        let id = action.id();
        match self.store.remember(&peer, id, now, since) {
            Ok(store::Remembered::Inserted) => {}
            Ok(store::Remembered::Already) => {
                reply(&*self.runtime, send, &ActionAnswer::AlreadyExecuted).await;
                return Ok(());
            }
            Ok(store::Remembered::Full) => {
                reply(&*self.runtime, send, &ActionAnswer::MemoryFull).await;
                return Ok(());
            }
            Err(ActionError::Busy { .. }) => {
                reply(&*self.runtime, send, &ActionAnswer::Busy).await;
                return Ok(());
            }
            Err(error) => return Err(error),
        }
        // The identifier is remembered before the run it describes, so an action that ran is
        // never missing from the memory. The execution is recorded before the run too: a log
        // with no room stops the peer from acting rather than letting it act unrecorded.
        let entry = Entry {
            at: now,
            act: Act::ActionExecuted {
                pair: pair.clone(),
                capability: right.capability(),
                id: *id.as_bytes(),
                issuer: right.issuer().clone(),
                expires_at: right.expires_at(),
            },
        };
        match self.rights.audit().append(&entry) {
            Ok(()) => {}
            // Nothing ran, so the identifier is released and the sender is told why. A log with
            // no room stops the peer from acting; it does not end the service.
            Err(AuditError::NoRoom { .. } | AuditError::TooLarge { .. }) => {
                return self
                    .release_then_answer(peer, id, since, ActionAnswer::NotRecorded, send)
                    .await;
            }
            Err(error) => {
                // The log's own fault ends the service, but the sender is told the action did
                // not run first, rather than being left to its own budget and marking it
                // unknown. A memory that cannot be released leaves the identifier spent; that
                // is the direction this layer states, and it does not hold up the reply.
                let _ = self
                    .release_then_answer(peer, id, since, ActionAnswer::NotRecorded, send)
                    .await;
                return Err(ActionError::Audit(error));
            }
        }
        self.run(peer, pair, action, id, since, send).await
    }

    /// Run one recorded action and answer what became of it on `send`.
    ///
    /// The identifier is already remembered and the execution already recorded. Every arm
    /// answers exactly once before returning.
    async fn run(
        &self,
        peer: PeerId,
        pair: Pair,
        action: Action,
        id: ActionId,
        since: Option<Timestamp>,
        send: SendStream,
    ) -> Result<(), ActionError> {
        let execution = Execution {
            peer,
            pair,
            id,
            kind: action.kind(),
            body: action.body().to_vec(),
        };
        let ran = timeout(&*self.runtime, EXECUTION_BUDGET, async {
            // The product's `execute` may panic before it returns a future as well as while
            // the future is polled; both are caught here, so neither escapes as a silent
            // task death.
            let Ok(future) =
                panic::catch_unwind(AssertUnwindSafe(|| self.executor.execute(execution)))
            else {
                return Err(());
            };
            CatchUnwind(future).await
        })
        .await;
        match ran {
            Some(Ok(Executed::Ran { result })) => {
                let answer = if result.len() > MAX_RESULT_BYTES {
                    ActionAnswer::RanNotCarried
                } else {
                    ActionAnswer::Ran { result }
                };
                reply(&*self.runtime, send, &answer).await;
                Ok(())
            }
            Some(Ok(Executed::Declined)) => {
                // A decline executed nothing, so the identifier is released before the answer,
                // as `not recorded` releases before its own. The sender is told the decline, not
                // `Busy`, because `Busy` means nothing was remembered and that would be false.
                self.release_then_answer(peer, id, since, ActionAnswer::NotRun, send)
                    .await
            }
            // A panic is a bug in the product's own code. The action may have run, so the
            // identifier stays remembered, the sender is told the outcome is unknown, and the
            // service ends with the fault named.
            Some(Err(())) => {
                reply(&*self.runtime, send, &ActionAnswer::Unknown).await;
                Err(ActionError::Execution { peer })
            }
            // The execution outlived its bound. The identifier stays remembered, because the
            // action may well have run; the sender is told the outcome is unknown.
            None => {
                reply(&*self.runtime, send, &ActionAnswer::Unknown).await;
                Ok(())
            }
        }
    }

    /// Mark one identifier unknown durably, tolerating a memory another writer holds.
    ///
    /// The mark is a trace, not the answer: another writer holding the memory this instant must
    /// not turn an unknown outcome into a busy one. The cost is that this one trace is lost —
    /// the receiver's journal still stops a repeat from running twice, and
    /// [`Self::unknown`] simply will not list it.
    fn mark_unknown(
        &self,
        peer: &PeerId,
        id: ActionId,
        since: Option<Timestamp>,
    ) -> Result<(), ActionError> {
        match self.store.mark_unknown(peer, id, self.moment.now(), since) {
            Ok(()) | Err(ActionError::Busy { .. }) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Keep the unknown trace, naming both the outcome and the storage fault when it cannot be
    /// kept.
    ///
    /// The caller is told the action may have run and that this machine could not record it —
    /// a storage fault alone would hide the outcome, and the answer alone would hide the fault.
    fn trace(
        &self,
        peer: PeerId,
        id: ActionId,
        since: Option<Timestamp>,
    ) -> Result<(), ActionError> {
        self.mark_unknown(&peer, id, since)
            .map_err(|source| ActionError::Untraced {
                peer,
                source: Box::new(source),
            })
    }

    /// Release `id`, then answer, and hand back a hard fault in the release so it ends the
    /// service after the answer.
    async fn release_then_answer(
        &self,
        peer: PeerId,
        id: ActionId,
        since: Option<Timestamp>,
        answer: ActionAnswer,
        send: SendStream,
    ) -> Result<(), ActionError> {
        let released = match self.store.forget(&peer, id, since) {
            Ok(()) | Err(ActionError::Busy { .. }) => Ok(()),
            Err(error) => Err(error),
        };
        reply(&*self.runtime, send, &answer).await;
        released
    }

    /// The pair's live connection, dialling first when there is none.
    ///
    /// Every kept connection has a binding exchange started with it, so a connection whose
    /// exchange has not finished after a whole [`EXCHANGE_BUDGET`] and one poll is one nothing
    /// will speak on. The search shares the call's [`ACTION_BUDGET`] through `deadline`; a
    /// connection that never becomes ready within it is reported as [`ActionError::Unprepared`]
    /// rather than offered, and nothing is held.
    async fn reachable(
        &self,
        connections: &Connections,
        endpoint: &Endpoint,
        peer: &PeerId,
        deadline: Instant,
    ) -> Result<Traffic, ActionError> {
        let left = deadline.saturating_duration_since(self.runtime.now());
        let mut asked = false;
        let traffic = timeout(&*self.runtime, left, async {
            loop {
                let Some(traffic) = connections.traffic(peer) else {
                    if !asked {
                        connections.wake(peer);
                        asked = true;
                    }
                    // The dial this call made is reported in the manager's own words, and a
                    // pair that will not be dialled again is answered with its reason now:
                    // waiting out the budget for a dial nothing will make is not a better
                    // answer than the one the manager already has. A deferral is not that
                    // reason: the policy has moved the next dial to its own moment, which the
                    // wait below reads, and answering it would end a wait the policy is about
                    // to turn into a dial.
                    let (state, failed) = connections.ensure(endpoint, &peer.fingerprint()).await;
                    // The deferral guard below is the one branch no case can stage: it needs the
                    // record to fail between this layer's own read and the manager's, inside one
                    // poll — which the rig cannot arrange, and no operator procedure can reproduce
                    // either. It is here for the second writer on the root that can do it; the
                    // reason a wait that ends without a dial then reports is the state's own, read
                    // by `Connections::state_and_reason`.
                    if let Some(failure) = failed
                        && !matches!(failure, ConnectFailure::Deferred { .. })
                    {
                        return Err(ActionError::Connect(failure));
                    }
                    match state {
                        // The policy is waiting out a gap: wait its own moment rather than
                        // polling, so a pair that is down costs the policy's pace and not a
                        // request a second.
                        Recovery::Waiting { until, .. } | Recovery::Exhausted { until, .. } => {
                            sleep(
                                &*self.runtime,
                                until.saturating_duration_since(self.runtime.now()),
                            )
                            .await;
                        }
                        // A dial that returns without a live pair must not spin: wait one
                        // poll, so the loop is bounded by the budget rather than by a hot
                        // handshake.
                        _ => sleep(&*self.runtime, ACTION_POLL).await,
                    }
                    continue;
                };
                if !connections.is_live(peer, &traffic) {
                    sleep(&*self.runtime, ACTION_POLL).await;
                    continue;
                }
                if traffic.exchange_done() {
                    return Ok(traffic);
                }
                let ready = timeout(&*self.runtime, EXCHANGE_BUDGET + ACTION_POLL, async {
                    while !traffic.exchange_done() {
                        sleep(&*self.runtime, ACTION_POLL).await;
                    }
                })
                .await;
                if ready.is_some() {
                    return Ok(traffic);
                }
                // The manager starts an exchange with every connection it keeps, so one that
                // has not finished after a whole exchange budget is one nothing will speak on.
                // The request was never offered, so nothing is held.
                return Err(ActionError::Unprepared { peer: *peer });
            }
        })
        .await;
        let Some(result) = traffic else {
            // The budget is spent. When the policy knows why the pair is down, that is the honest
            // answer: a person asked for an action, and "no direct path" or "the peer is not
            // registered" is what they need to see rather than "nothing was ready".
            let (_, named) = connections.state_and_reason(peer);
            return match named {
                Some(failure) => Err(ActionError::Connect(failure)),
                None => Err(ActionError::Unprepared { peer: *peer }),
            };
        };
        result
    }
}

/// What became of one offer on the wire.
enum Offered {
    /// The request may not have left this machine: no stream was opened, or the write did not
    /// finish. A stream that never opened wrote nothing; a write that did not finish may have
    /// been whole on the wire, so the receiver's journal is what stops a repeat from running
    /// twice.
    NotSent,
    /// The whole frame went out, and no answer came back, or the answer is not one this build
    /// can read. The action may have run.
    NoAnswer,
    /// The peer answered.
    Answer(ActionAnswer),
}

/// Offer one action over `connection` and read the answer.
async fn offer(
    runtime: &dyn Runtime,
    connection: &quinn::Connection,
    action: &Action,
    deadline: Instant,
) -> Offered {
    let left = || deadline.saturating_duration_since(runtime.now());
    let bytes = action.encode();
    // Opening the stream writes nothing: a budget that passes here, or an open that fails,
    // means no stream was opened and nothing was written.
    let Some(Ok((mut send, mut recv))) = timeout(runtime, left(), connection.open_bi()).await
    else {
        return Offered::NotSent;
    };
    // A write that does not finish is a partial frame, which no receiver decodes as an action.
    match timeout(runtime, left(), send.write_all(&bytes)).await {
        Some(Ok(())) => {}
        // The write did not finish — it failed, or it timed out — so the frame may or may not
        // have been whole. The receiver may also have answered before resetting the stream, so
        // read what it wrote before calling the request unsent. This is a courtesy, not a second
        // try: an answer that had not already arrived never will, so the read gets only what
        // the budget has left — one poll, when the write itself timed out.
        Some(Err(_)) | None => {
            return read_answer(runtime, &mut recv, ACTION_STREAM_BUDGET.min(left()))
                .await
                .map_or(Offered::NotSent, Offered::Answer);
        }
    }
    if send.finish().is_err() {
        return Offered::NoAnswer;
    }
    read_answer(runtime, &mut recv, left())
        .await
        .map_or(Offered::NoAnswer, Offered::Answer)
}

/// Read one answer, or `None` when none came within `budget` or it is not one this build can
/// read.
async fn read_answer(
    runtime: &dyn Runtime,
    recv: &mut RecvStream,
    budget: Duration,
) -> Option<ActionAnswer> {
    let reply = timeout(runtime, budget, recv.read_to_end(ACTION_ANSWER_BYTES)).await?;
    ActionAnswer::decode(&reply.ok()?).ok()
}

/// Write one answer back, bounded like every other wait this crate makes.
async fn reply(runtime: &dyn Runtime, send: SendStream, answer: &ActionAnswer) {
    stream::write_reply(runtime, send, &answer.encode(), ACTION_STREAM_BUDGET).await;
}

/// Catch a panic raised while the machine's own code is running, as an answer rather than as an
/// abort.
///
/// The receiving task is detached, so a panic that unwound through it would leave the pair
/// answering nothing while the service went on looking healthy.
struct CatchUnwind<F>(F);

impl<F: Future + Unpin> Future for CatchUnwind<F> {
    type Output = Result<F::Output, ()>;

    fn poll(self: Pin<&mut Self>, context: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        // The future is a pinned box by the `Executor` contract, so it is `Unpin`; the
        // `AssertUnwindSafe` is the crate's own guarantee that the state behind a panic is
        // discarded with the service.
        let this = self.get_mut();
        let inner = &mut this.0;
        match panic::catch_unwind(AssertUnwindSafe(|| Pin::new(inner).poll(context))) {
            Ok(poll) => poll.map(Ok),
            Err(_) => Poll::Ready(Err(())),
        }
    }
}

/// The refusal a record that does not vouch for the pair is answered with.
///
/// [`RecordRead::Refused`] is only ever "no record", "closed" or "withdrawn": the manager's one
/// read puts a record it could not read in [`RecordRead::Unreadable`], which carries the typed
/// fault and is answered with it. The unreadable cause is mapped here too, so this stays one
/// total mapping of [`NotTrustedCause`] and a new cause cannot be answered by accident.
fn unpaired(peer: PeerId, cause: NotTrustedCause) -> ActionError {
    match cause {
        NotTrustedCause::NoRecord => ActionError::NotPaired { peer },
        NotTrustedCause::Closed => ActionError::Closed { peer },
        NotTrustedCause::Withdrawn => ActionError::Withdrawn { peer },
        NotTrustedCause::Unreadable { detail } => {
            ActionError::Connect(ConnectFailure::NotTrusted {
                peer: peer.fingerprint(),
                cause: NotTrustedCause::Unreadable { detail },
            })
        }
    }
}

/// What is wrong with the bytes of an action's memory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActionMalformed {
    /// The file is empty.
    Empty,
    /// The file is longer than [`MAX_ACTIONS_BYTES`].
    TooLarge {
        /// How many bytes the file has.
        bytes: u64,
    },
    /// A fault the file shares with a frame: the framing's own vocabulary, written once.
    Framing(FramingFault),
}

impl fmt::Display for ActionMalformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("it is empty"),
            Self::TooLarge { bytes } => write!(
                f,
                "the file is {bytes} bytes, more than {MAX_ACTIONS_BYTES}"
            ),
            Self::Framing(reason) => reason.fmt(f),
        }
    }
}

/// Why an action could not be asked, remembered, read or believed.
#[derive(Debug)]
pub enum ActionError {
    /// The storage root does not exist, or is not a directory. It is never created here.
    RootMissing { path: PathBuf },
    /// The operating system could not read or write a file this layer reads or writes: a
    /// memory, or the record or log a decision reads.
    Io { path: PathBuf, source: io::Error },
    /// A file is reachable by an account the rule does not allow.
    Insecure {
        path: PathBuf,
        reason: crate::identity::access::Insecurity,
    },
    /// The bytes of a file in `actions/` are not a memory: its own faults, plus the framing's
    /// for what a file shares with a frame.
    Malformed {
        path: PathBuf,
        reason: ActionMalformed,
    },
    /// The memory would be larger than [`MAX_ACTIONS_BYTES`], so it was not written.
    TooLarge { path: PathBuf, bytes: u64 },
    /// No record says a person paired this machine with the peer.
    NotPaired { peer: PeerId },
    /// This machine's trust in the peer was withdrawn.
    Withdrawn { peer: PeerId },
    /// The pair is closed on this machine — three comparisons failed — until a person clears it.
    Closed { peer: PeerId },
    /// The body is longer than [`MAX_ACTION_BODY_BYTES`].
    Body { bytes: usize, limit: usize },
    /// The dial that the ask was an ordinary reason for failed, or the pair was still down when
    /// the ask's budget ran out — the manager's own words either way, never a bare "nothing was
    /// ready". Nothing was held anywhere: this layer has no queue.
    Connect(ConnectFailure),
    /// The request may not have left this machine: the pair's connection could not open a
    /// stream, or the write did not finish. A stream that never opened certainly wrote nothing;
    /// a write that did not finish may have been whole on the wire, so a repeat is answered by
    /// the receiver's journal rather than run twice. A write that did not finish after the
    /// receiver had already answered is not this: that answer is read under a short courtesy
    /// bound and handed back. Either way this layer keeps no mark, and the same call is worth
    /// making again.
    NotSent { peer: PeerId },
    /// No connection to the pair was ready to carry the action within [`ACTION_BUDGET`]: a kept
    /// connection's binding exchange did not finish, or the dial kept landing on connections that
    /// did not stay live. The request was not offered, and nothing was held.
    Unprepared { peer: PeerId },
    /// Another writer holds this peer's memory this instant: a second process on the root, or a
    /// second [`Actions`] over it. Nothing was changed, and the same call is worth making again.
    /// [`Actions::sweep`] answers it; a request answers [`ActionAnswer::Busy`] instead.
    Busy { peer: PeerId },
    /// The action may have run, and this machine could not keep the unknown trace: its memory
    /// could not be read or written. The receiver's journal still stops a repeat from running
    /// twice, but nothing here can be read back. The memory's own fault is carried inside.
    ///
    /// This is an outcome, not a refusal: a caller that treats it as a request that did not
    /// happen would run the operation again under a new identifier, which is the one thing
    /// at-most-once cannot survive.
    Untraced {
        /// The peer the action was asked of.
        peer: PeerId,
        /// The memory's own fault.
        source: Box<Self>,
    },
    /// The machine's own [`Executor`] panicked. The action may have run, so the identifier stays
    /// remembered and the service that started the receiving task stops: a panic is a bug, and
    /// a pair that went on answering nothing would hide it. A restarted service takes actions
    /// again.
    Execution { peer: PeerId },
    /// The peer's record refused, in the record's own words.
    Record(RecordError),
    /// The log refused, in the log's own words. An append that fails before an execution is
    /// answered [`ActionAnswer::NotRecorded`] first, so the sender is told the action did not
    /// run rather than left to its own budget.
    Audit(AuditError),
    /// The decision refused, in the decision's own words.
    Rights(RightsError),
    /// The bytes are not a frame this layer writes, naming which part of the framing is wrong.
    Frame {
        /// The framing's own fault.
        reason: FramingFault,
    },
}

impl fmt::Display for ActionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootMissing { path } => write!(
                f,
                "{}: the storage root does not exist or is not a directory; it is never created",
                path.display()
            ),
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Insecure { path, reason } => {
                write!(f, "{} is not private: {reason}", path.display())?;
                match reason.remedy(path) {
                    Some(command) => write!(f, "; {command}"),
                    None => Ok(()),
                }
            }
            Self::Malformed { path, reason } => {
                write!(f, "{} is not an action memory: {reason}", path.display())
            }
            Self::TooLarge { path, bytes } => write!(
                f,
                "{}: the memory would be {bytes} bytes, more than {MAX_ACTIONS_BYTES}; it was not written",
                path.display()
            ),
            Self::NotPaired { peer } => write!(
                f,
                "no record says a person paired this machine with {}",
                peer.fingerprint()
            ),
            Self::Withdrawn { peer } => write!(
                f,
                "this machine's trust in {} was withdrawn",
                peer.fingerprint()
            ),
            Self::Closed { peer } => write!(
                f,
                "the pair with {} is closed on this machine until a person clears it",
                peer.fingerprint()
            ),
            Self::Body { bytes, limit } => {
                write!(f, "the body is {bytes} bytes, more than {limit}")
            }
            Self::Connect(failure) => write!(f, "the action could not be sent: {failure}"),
            Self::NotSent { peer } => write!(
                f,
                "the action for {} may not have left this machine: no stream could be opened, or \
                 the write did not finish and no answer had arrived; this layer keeps no mark for \
                 it",
                peer.fingerprint()
            ),
            Self::Unprepared { peer } => write!(
                f,
                "the pair with {} had no connection ready to carry the action within the budget; the action was not sent",
                peer.fingerprint()
            ),
            Self::Busy { peer } => write!(
                f,
                "another writer holds the action memory for {} this instant; try again",
                peer.fingerprint()
            ),
            Self::Untraced { peer, source } => write!(
                f,
                "the action for {} may have run, and this machine could not keep the trace of \
                 it: {source}",
                peer.fingerprint()
            ),
            Self::Execution { peer } => write!(
                f,
                "the machine's own code panicked while running an action for {}, so the service stopped",
                peer.fingerprint()
            ),
            Self::Record(error) => write!(f, "the peer's record: {error}"),
            Self::Audit(error) => write!(f, "the log: {error}"),
            Self::Rights(error) => write!(f, "the decision: {error}"),
            Self::Frame { reason } => {
                write!(f, "the bytes are not what this layer writes: {reason}")
            }
        }
    }
}

impl std::error::Error for ActionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Record(error) => Some(error),
            Self::Audit(error) => Some(error),
            Self::Rights(error) => Some(error),
            Self::Connect(failure) => Some(failure),
            Self::Untraced { source, .. } => Some(source.as_ref()),
            Self::RootMissing { .. }
            | Self::Insecure { .. }
            | Self::Malformed { .. }
            | Self::TooLarge { .. }
            | Self::NotPaired { .. }
            | Self::Withdrawn { .. }
            | Self::Closed { .. }
            | Self::Body { .. }
            | Self::NotSent { .. }
            | Self::Unprepared { .. }
            | Self::Busy { .. }
            | Self::Execution { .. }
            | Self::Frame { .. } => None,
        }
    }
}

impl From<RecordError> for ActionError {
    /// A record's refusal keeps the record's own words: the classes this layer shares with the
    /// record are mapped, and everything else is carried typed.
    fn from(error: RecordError) -> Self {
        match error {
            RecordError::RootMissing { path } => Self::RootMissing { path },
            RecordError::Unreadable { path, source } | RecordError::Io { path, source } => {
                Self::Io { path, source }
            }
            RecordError::Insecure { path, reason } => Self::Insecure { path, reason },
            other => Self::Record(other),
        }
    }
}

impl From<AuditError> for ActionError {
    fn from(error: AuditError) -> Self {
        Self::Audit(error)
    }
}

impl From<RightsError> for ActionError {
    fn from(error: RightsError) -> Self {
        Self::Rights(error)
    }
}
