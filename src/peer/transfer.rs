//! A whole file moved over the pair's connection, at path speed, with resume, integrity
//! and backpressure.
//!
//! # Its own thing
//!
//! A file does not travel as a stream of messages. It is a transfer in its own right: one
//! bidirectional stream per attempt. It does not inherit the message layer's body cap, does not
//! consume its window, its queue, its taken identifiers or its retention, and a transfer frame is
//! never counted as a message. The inbox tells the two apart by the frame's magic; a frame it does
//! not recognise is still handed to the message layer, which is exactly what makes an older peer
//! answer "unreadable" to an offer.
//!
//! # Resume, and the difference between a lost connection and a stopped transfer
//!
//! A transfer whose connection goes away is [`TransferState::Waiting`], not failed: it resumes when
//! the pair reconnects, and the product is not asked to start it again. On resume the receiver
//! states how much it already holds, and the sender continues from there. A transfer with a live
//! connection that stops moving bytes is abandoned after [`TRANSFER_STALL`], on either side — the
//! receiver records the same cause rather than showing it as a wait — and [`TRANSFER_STALL`] states
//! what each kind of answered round spends. One that waits longer than [`TRANSFER_WAIT`] for the
//! pair ends as [`TransferFailure::NoPair`], and the receiving side reports the same for a
//! transfer whose sender never came back, so a dead transfer is never shown as a quiet one. A
//! transfer that is already complete on the receiver is answered complete instead of being sent
//! again.
//!
//! The decision is made once, when the transfer is authorised, and holds for its whole life,
//! including across a reconnect: a right withdrawn afterwards ends future transfers, not
//! this one. Trust withdrawn closes the connection and therefore ends it. The binding to an
//! assistant is re-checked when a transfer resumes, and only then: a machine moved to another
//! assistant leaves the pair the transfer was authorised under, and the resume is refused at
//! the right step rather than continuing under a pair that inherits nothing.
//!
//! # Integrity
//!
//! The digest is SHA-256 over the whole file, and the receiving machine is what verifies it: the
//! product's sink reports what it assembled, and the crate compares that with the digest the
//! sender offered, including the part that was already there from an earlier attempt, so a
//! truncated or corrupted transfer is never answered complete.
//!
//! # The closed answer set
//!
//! Every cause is its own answer, never merged into a neighbour, and a product sees them as
//! [`TransferFailure`]. An offer that arrives before this machine has a pair to decide under is
//! answered nothing at all, and the sender asks again, as the message and action layers leave
//! it — with a wait that doubles after each offer the pair left unanswered, so a pair that never
//! binds is not offered a file once a second for the whole wait bound. Any answer that is not a
//! bare limit — a `running` answer to an offer, or a throttle after the receiving machine took the
//! transfer — starts the count again, so a pair that is there and whose window is full is the
//! limit it met, and says so.
//!
//! The one answer that is not an end is the start limit's throttle: the receiving machine names
//! how long to wait before starting another transfer, the sender shows that as
//! [`TransferState::Throttled`] and asks again when it passes. A limit on running transfers is
//! still terminal, because this machine's own count would have refused a third one locally. The
//! start limit means that one thing wherever it is read — in an answer to an offer, in a word
//! while the bytes are moving, or in the verdict that follows them.
//!
//! An answer that is still arriving is never a refusal: a frame the budget caught half-written
//! is kept and continued by the next look, so a word split across two looks is read once, and a
//! stream that ends inside a frame is a lost attempt rather than "not understood". The same
//! discipline holds on the writing side — a word goes whole or the stream is treated as
//! broken — because half a word left in front of the verdict would be read as the verdict.
//!
//! # What counts as progress
//!
//! Bytes that landed at the receiving side, and nothing else: the offset the receiving machine
//! states, both in its answer to an offer and in the progress word it sends while its sink is
//! slow — and that offset *growing*, because a word repeating an offset this machine has already
//! seen is not the file getting further. Nothing else counts — not bytes handed to the transport,
//! not an attempt that timed out, not a re-send from the receiver's own offset — and nothing
//! takes progress back, because that offset only grows. Which is what lets a slow sink take as
//! long as it takes while a transfer that has genuinely stopped is still abandoned after
//! [`TRANSFER_STALL`], and a peer that repeats one offset for ever is abandoned on the same
//! bound instead of parking the transfer.
//!
//! The progress word exists because the transport returns flow-control credit in large steps: a
//! writer parked at a stream window's edge waits for a fraction of that window before it may
//! write again, however slowly the receiving side is storing. So a chunk whose sink had to be
//! asked twice for is reported to the sending side as a `running` answer carrying the receiver's
//! offset — and so is the file's progress once a poll, so a sender whose own source is slow, or
//! whose write is parked for a moment, has something to go on that is not its own writes. A
//! sender parked on a write, or waiting on its source, reads it rather than calling a working
//! transfer stopped.
//!
//! # The record of an authorised transfer
//!
//! One decision per transfer, not per chunk. A transfer that is about to move bytes is
//! recorded first, as [`Act::TransferAllowed`]: peer-driven, drawing on the log's part for
//! peer-driven acts, so a person is never blocked by a peer — and if that part cannot take the
//! entry the transfer is not run and the sender is told `not recorded`. A name that turns out
//! complete or in conflict was not a transfer and leaves no entry. How often a peer may start
//! a transfer is bounded per peer by [`MAX_TRANSFER_STARTS`] per [`TRANSFER_START_WINDOW`],
//! checked before the rights decision so a peer cannot force a record reread or fill the log
//! at will; a transfer resuming after a reconnect is the same transfer and does not count
//! again.
//!
//! # What it is not
//!
//! No queue, no retention, no journal of its own, no file on disk: the crate holds a transfer's
//! name, its length, its digest and how far it has got in memory while it runs, and nothing of that
//! after a restart. What it does keep is the authorisation, an audit entry like every other allowed
//! act, naming the same name, length and digest.

mod wire;

pub(crate) use wire::OFFER_MAGIC;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use quinn::{Endpoint, ReadError, RecvStream, Runtime, SendStream, VarInt};

use crate::beacon::{sleep, timeout};
use crate::hex;
use crate::identity::PeerId;
use crate::peer::access::{Label, LabelError, Pair, Right};
use crate::peer::audit::{Act, AuditError, AuditLog, Entry};
use crate::peer::connect::{Connections, Traffic};
use crate::peer::moment::Moment;
use crate::peer::record::{RecordError, RecordStore, Timestamp, Untrusted};
use crate::peer::rights::{Admission, FileIngress, Floor, Rights, RightsError, Step};
use crate::peer::stream;
use crate::peer::window::Windows;

/// The most bytes a transfer's name may have: the same bound a [`Label`] has.
///
/// The name is the product's, travels as given and is never interpreted. It is bounded so a
/// peer cannot grow this machine's memory with one field, and because the name rides in the
/// audit entry and in an offer frame that an older peer must be able to read whole as a
/// message body — the offer is far below the message layer's [`crate::peer::MAX_BODY_BYTES`].
pub const MAX_TRANSFER_NAME_BYTES: usize = crate::peer::access::MAX_LABEL_BYTES;

/// How many bytes the sender reads from its source and writes to the stream at a time.
///
/// One chunk is also the most of a file this machine holds while it moves one: the transport
/// holds the rest, under the credit [`crate::net::MAX_STREAM_BYTES`] names.
pub const TRANSFER_CHUNK: usize = 64 * 1024;

/// How long a transfer with a live connection may stop moving bytes before it is abandoned.
///
/// It is a bound on *no progress*, not on a transfer's length: a transfer that keeps the receiving
/// machine's stated offset growing is never abandoned, so a slow link and a slow sink are allowed
/// to take as long as they take — a slow source too, as long as it produces something inside the
/// bound: one that produces nothing for the whole of it is no progress. It is a budget the transfer
/// spends, not an instant it re-anchors: the receiving machine's stated offset growing is the only
/// thing that clears it. A round the receiving machine paced spends neither bound and clears
/// neither; any other answered round buys time only by stating a further offset, which clears both;
/// an answered round that states no further offset is charged the stall bound — the whole of its
/// own duration as well as the pause after it, so a peer that keeps this machine waiting before
/// saying "the same offset" spends the bound at the rate it really passes. Bytes the stream
/// accepted are not growth: a connection that comes back and moves nothing buys the transfer
/// nothing.
pub const TRANSFER_STALL: Duration = Duration::from_secs(60);

/// The margin the sending machine's bound keeps past the receiving machine's worst honest
/// silence: its bound, its one look at the stream and an answer written within it.
///
/// A receiving machine whose sink has answered "not now" for [`TRANSFER_STALL`] looks at the
/// stream once more and then writes its answer — a store failure — and that answer has to reach
/// a sender parked on that side: on a write the receiver has not read, or on the read that waits
/// for the verdict after every byte. [`TRANSFER_STALL`] plus this carries the bound, the look and
/// an answer written within it, so a receiver that spends its whole bound is heard as its own
/// answer rather than timed out as `no progress`: two causes for one event. A peer that blocks the
/// answer's own write outright — past that write's own budget, `TRANSFER_ANSWER_BUDGET` — is
/// outside the margin.
pub const TRANSFER_GRACE: Duration = Duration::from_secs(5);

/// The sending machine's own bound: the receiving machine's worst honest silence plus
/// [`TRANSFER_GRACE`], measured from the last time that side's stated offset grew.
///
/// The one spelling of the number the verdict and the write loop both read, so a change to one
/// cannot leave the other behind.
const TRANSFER_SENDER_BOUND: Duration = TRANSFER_STALL.saturating_add(TRANSFER_GRACE);

/// How long a transfer waits for what it needs — the pair's connection, or this machine's own
/// record — before it ends.
///
/// A budget the transfer spends, added up over every wait, and never an episode that restarts:
/// a transfer that has been moving bytes for an hour has spent none of it, and a pair that drops
/// after that hour is still waited for in full — but a pair that keeps coming back and moving
/// nothing exhausts it rather than parking the transfer.
pub const TRANSFER_WAIT: Duration = Duration::from_secs(600);

/// How often a transfer that can make no progress looks again.
///
/// It paces every wait a transfer has that is measured in looks rather than in a bound, it is the
/// longest a progress word may take to be written, the first and shortest wait between two
/// unanswered offers (see [`TRANSFER_RETRY_CAP`]), and the shortest wait a throttle is clamped to,
/// so a peer that names no delay cannot turn the retry into a spin.
pub(crate) const TRANSFER_POLL: Duration = Duration::from_secs(1);

/// The longest a transfer waits between two offers the pair left unanswered.
///
/// A stated choice: an offer the receiving machine does not answer — no binding yet, a
/// connection that went away before the answer — must not be retried once a second for the
/// whole wait bound, because each attempt costs a start of the receiving machine's
/// [`MAX_TRANSFER_STARTS`] window before the decision is even asked. The wait starts at
/// [`TRANSFER_POLL`], doubles after each offer the pair left unanswered, and is capped here; an
/// offer the pair answered without pacing the transfer puts it back to [`TRANSFER_POLL`], so a
/// transfer that is moving is never slowed by it.
pub(crate) const TRANSFER_RETRY_CAP: Duration = Duration::from_secs(8);

/// The longest a single throttling answer may make this machine wait, and the ceiling a peer's
/// number is clamped to where it is read.
///
/// The delay in a throttling answer comes from the peer, and a number that comes from the peer
/// is bounded once, where a start limit is taken as the throttle it means: no single throttle
/// waits longer than a start window, which is the point at which the receiving machine's own
/// window has room again, and no throttle waits for nothing at all — a delay of zero, and a start
/// limit that names no delay at all, are one look rather than a spin. The streak of them is
/// bounded too, at [`TRANSFER_WAIT`] rather than here: a peer that keeps throttling that long
/// ends the transfer rather than parking it — with the limit it kept meeting if the pair was
/// answering, and as [`TransferFailure::NoPair`] if this machine's own unanswered offers were
/// what filled the window — so neither the transfer nor one of this machine's places for the peer
/// is parked for ever. A throttle that arrives with the receiving machine's stated offset
/// grown ends the streak rather than feeding it: that peer is pacing a transfer that is moving,
/// and only one that throttles while moving nothing is ended by the bound.
pub const TRANSFER_THROTTLE_CAP: Duration = TRANSFER_START_WINDOW;

/// How long the sender waits for the whole of the receiver's answer to an offer.
///
/// A frame still arriving inside the budget is waited for and continued rather than called a
/// refusal; one that does not finish inside it is a lost attempt, and the sender asks again.
///
/// The verdict that follows the bytes is read on a different bound: the receiver's own stall
/// bound plus [`TRANSFER_GRACE`], from the last time its stated offset *grew* — so a sink that is
/// still writing the tail is never timed out, and one that repeats an offset it has already
/// stated is.
pub(crate) const TRANSFER_ANSWER_BUDGET: Duration = Duration::from_secs(30);

/// How many transfers one peer may have running, or waiting for the pair, at once.
///
/// Counted on both sides: the receiver's count produces the `limit` answer on the wire, and
/// the sender's own count is a local [`TransferError::Limit`], because limiting
/// what this machine queues is this machine's own choice.
///
/// The receiver's count and its record of the new transfer are one decision under one lock, so
/// two offers that arrive together cannot both take the last place — which is what keeps
/// [`crate::net::MAX_STREAM_BYTES`] twice over a real bound on the connection's credit.
pub const MAX_RUNNING_TRANSFERS: usize = 2;

/// How many transfers one peer may start per [`TRANSFER_START_WINDOW`].
pub const MAX_TRANSFER_STARTS: u32 = 6;

/// How many offers in a row this machine may write and get nothing back before a throttle it
/// then meets is read as the window it filled itself.
///
/// A pair with no binding to decide under answers every offer with nothing, and every one of
/// those offers spends a start of the receiving machine's [`MAX_TRANSFER_STARTS`] window — so a
/// window this machine filled by itself is exactly that many offers. A throttle met after one is
/// the pair's own limit; a throttle met after a whole window of silence is this machine's own
/// offers coming back as a limit, and ends as [`TransferFailure::NoPair`] instead. It is the same
/// number as [`MAX_TRANSFER_STARTS`] because it is the same window, read from the other end.
pub(crate) const SILENT_OFFERS: u32 = MAX_TRANSFER_STARTS;

/// The window [`MAX_TRANSFER_STARTS`] is counted over.
pub const TRANSFER_START_WINDOW: Duration = Duration::from_secs(60);

/// The code a sender resets its stream with when its own product stops the transfer.
///
/// A reset is the one signal a reader cannot mistake for file bytes, and a transfer's bytes
/// are unframed. The receiver reads it as "the sending side stopped it".
pub(crate) const TRANSFER_STOP_CODE: u32 = 1;

/// The code the receiving machine resets its own half with when it cannot write a word whole.
///
/// Deliberately not [`TRANSFER_STOP_CODE`]: that code means the sending side's own product stopped
/// the transfer, and the two halves of one stream must not say the same thing about a stop and a
/// broken answer. The sending side reads any reset on this half as the attempt being over — the
/// code is not what it acts on — so the difference is one of meaning, kept so that a reader of
/// the wire cannot mistake the receiving machine's broken stream for a person's decision.
const TRANSFER_BROKEN_CODE: u32 = 0;

/// A SHA-256 digest, as a product supplies it and as a transfer carries it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest([u8; 32]);

impl Digest {
    /// The digest these bytes are, when there are exactly thirty-two of them.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok().map(Self)
    }

    /// The digest's bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::write(f, &self.0)
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// The name for one transfer, scoped to one peer.
///
/// On the sending side it is this machine's product's; on the receiving side it is the sending
/// peer's word, and untrusted input (see [`Sink`]). Constructed only through
/// [`TransferName::new`], so a name that reaches an offer or the audit is one a person can be
/// shown. The crate never mints one, never derives one from anything, and reads no meaning into
/// one: it checks that it is a name a person can be shown — not empty, bounded, no character
/// that breaks a line — and otherwise compares two names for equality.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransferName(Label);

impl TransferName {
    /// Read a transfer's name.
    ///
    /// # Errors
    ///
    /// [`LabelError`] when the name is empty or only whitespace, longer than
    /// [`MAX_TRANSFER_NAME_BYTES`], or holds a character that would break or reorder the
    /// line it is shown on.
    pub fn new(text: &str) -> Result<Self, LabelError> {
        Label::new(text).map(Self)
    }

    /// The name's text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// The name's bytes, as an offer frame carries them.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_str().as_bytes()
    }
}

impl fmt::Display for TransferName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// What one read from a [`Source`] produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Read {
    /// This many bytes were written into the caller's buffer, at least one.
    Bytes(usize),
    /// Not now: the source is not ready and the transfer should ask again rather than block.
    NotNow,
    /// The source ended before the file's length did.
    Ended,
    /// The source could not be read. The crate carries the class; the product's own reason is
    /// its own, and the sender learns only that its source failed.
    Failed,
}

/// Where a transfer's bytes come from.
///
/// The crate reads one [`TRANSFER_CHUNK`] at a time and never asks for more than the caller's
/// buffer holds. A read may answer [`Read::NotNow`] instead of blocking, because a source that
/// blocks the runtime would stall the pair's messages and actions as well.
pub trait Source: Send + Sync {
    /// Write up to `into.len()` bytes starting at `offset` into `into`, and answer how many.
    ///
    /// The offset is absolute, so the same source is read from it again after a reconnect.
    fn read(&self, name: &TransferName, offset: u64, into: &mut [u8]) -> Read;
}

/// What a [`Sink`] holds for one name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Held {
    /// How many bytes it holds, from the file's start.
    pub bytes: u64,
    /// The digest those bytes were being assembled toward.
    ///
    /// `None` only when [`Self::bytes`] is zero: a name the sink holds nothing of has no
    /// expectation yet. A name it holds bytes of must name one, or the offer cannot be
    /// continued and is answered `conflict`.
    pub toward: Option<Digest>,
}

impl Held {
    /// A name the sink holds nothing of.
    #[must_use]
    pub const fn nothing() -> Self {
        Self {
            bytes: 0,
            toward: None,
        }
    }
}

/// What one write to a [`Sink`] produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stored {
    /// Every byte was taken, at the offset it was given.
    Accepted,
    /// Not now: the sink is not ready and the transfer should ask again rather than block. A sink
    /// that answers this stops this machine reading, which stops the sender through QUIC's flow
    /// control instead of growing memory, dropping the file or stalling the pair's messages.
    NotNow,
    /// The sink will not take these bytes. The class travels and the sender is answered
    /// `store failed`; the product's own reason is its own, and stays where it is known.
    Refused,
}

/// Where a transfer's bytes land.
///
/// The crate never writes a file: it hands the bytes to this, at the offset they belong at,
/// with the peer that sent them, and takes back whether they were taken. The three questions
/// about a name are what make a conflict detectable before a foreign byte is appended and
/// what makes integrity end to end possible, so none of them is optional.
///
/// Every name handed here is the sending peer's word, not this machine's product's. The only
/// thing it is guaranteed to be is a line a person can be shown: `/`, `\` and `..` are not
/// refused, and it is never a path, so a sink that stores files by name has to treat it as
/// untrusted input.
///
/// All three are **lookups that answer without waiting**, and a product that cannot answer one
/// of them that way has put the wrong thing behind this trait: the crate asks them while the
/// sending machine is waiting on its bound, so a product that hashed on demand, or read a file
/// back to say how much it holds, would answer after the sender had already given up. There is
/// nothing to compute on demand in any case — the product hashes as the bytes land, because it
/// has to produce the digest anyway — so what is left is remembering three numbers and answering.
pub trait Sink: Send + Sync {
    /// How many bytes this sink holds for `name`, and the digest they were assembled toward.
    fn held(&self, peer: &PeerId, name: &TransferName) -> Held;

    /// Take `bytes`, which belong at `offset` in `name`, sent by `peer`.
    ///
    /// `toward` is the digest the whole file must have, so the sink never has to be told it
    /// out of band and never has to remember a name and a digest separately: the first write
    /// of a name is where it learns what the bytes are being assembled toward.
    fn write(
        &self,
        peer: &PeerId,
        name: &TransferName,
        toward: &Digest,
        offset: u64,
        bytes: &[u8],
    ) -> Stored;

    /// The digest of what this sink actually assembled for `name`, once it holds every byte.
    ///
    /// `None` while it holds less than the whole file, or when it cannot answer. The crate asks
    /// once every byte has arrived: a digest other than the one offered is
    /// [`TransferFailure::DigestMismatch`], and `None` is [`TransferFailure::StoreFailed`],
    /// because a product that cannot say what it assembled has not stored the file.
    fn assembled(&self, peer: &PeerId, name: &TransferName) -> Option<Digest>;
}

/// One file a product offers a peer.
pub struct Offering {
    /// The product's name for the transfer, scoped to the peer it is offered to.
    pub name: TransferName,
    /// The file's length in bytes. It is never zero: an empty file is refused locally.
    pub length: u64,
    /// SHA-256 over the whole file.
    pub digest: Digest,
    /// Where the bytes come from.
    pub source: Arc<dyn Source>,
}

impl fmt::Debug for Offering {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Offering")
            .field("name", &self.name)
            .field("length", &self.length)
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

/// Where one of this machine's transfers stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransferState {
    /// Waiting to go on: the pair's connection, or this machine's own record, is not usable
    /// yet. It resumes by itself, and nothing was lost.
    Waiting,
    /// Moving bytes: how far it has got, of the file's length.
    Running {
        /// On the sending side, bytes handed to the transport, which runs ahead of what the
        /// receiver holds by up to the peer's stream window; on the receiving side, bytes
        /// stored.
        moved: u64,
        /// The file's length.
        of: u64,
    },
    /// The receiver has it, and the digest matched.
    Finished {
        /// The file's length.
        bytes: u64,
    },
    /// It ended, and why.
    Failed {
        /// The cause, as its own class.
        failure: TransferFailure,
    },
    /// The receiving machine asked this machine to wait before starting another transfer:
    /// a limit on starts. The transfer asks again when it passes.
    Throttled {
        /// How long this machine waits before asking again.
        retry_after: Duration,
    },
    /// A product stopped it: this machine's own on the sending side, the peer's on the
    /// receiving one, where the sending side's reset of the stream is the word.
    Stopped,
}

impl TransferState {
    /// Whether nothing more will happen to this transfer.
    #[must_use]
    pub const fn is_over(&self) -> bool {
        matches!(
            self,
            Self::Finished { .. } | Self::Failed { .. } | Self::Stopped
        )
    }

    /// How many bytes of the file are accounted for, when this transfer is running.
    ///
    /// On the receiving side that is what its sink holds; on the sending side, what it has
    /// handed to the transport. Zero for a state that says nothing about bytes.
    const fn moved(&self) -> u64 {
        match self {
            Self::Running { moved, .. } => *moved,
            _ => 0,
        }
    }
}

/// Which limit was reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferLimit {
    /// This machine already has [`MAX_RUNNING_TRANSFERS`] transfers with the peer.
    Transfers,
    /// The peer started too many transfers in one [`TRANSFER_START_WINDOW`].
    Starts,
}

impl fmt::Display for TransferLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Transfers => "the limit on running transfers",
            Self::Starts => "the limit on how often transfers may be started",
        })
    }
}

/// Why a transfer did not finish.
///
/// A closed set, and every cause is its own: a refusal is never reported as a failure of the
/// link, a link failure is never reported as a refusal, and an offer the receiver could not
/// understand is never reported as a peer that does not know transfers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransferFailure {
    /// The peer answered with something this build cannot read, or nothing at all: a peer
    /// that does not know transfers, or a frame this build cannot parse.
    NotUnderstood,
    /// The receiving machine could not understand the offer: a malformed frame, or a length
    /// that contradicts what it already holds under that name.
    Malformed,
    /// The receiving machine's rights refused the transfer, at this step.
    Refused {
        /// The step that refused: who you are, the right, or the machine's own floor.
        step: Step,
    },
    /// The receiving machine could not write its own record of the act, so it did not run
    /// the transfer.
    NotRecorded,
    /// A limit was reached.
    Limit {
        /// Which one.
        which: TransferLimit,
        /// How long the receiving machine named as the wait when it refused the start, clamped to
        /// what this machine honours. The transfer has ended, so nothing acts on it here: it is
        /// what a product shows, and a retry started after it is a new transfer. `None` for a
        /// limit that only waits for room — this machine's own count of running transfers, and a
        /// peer's limit on them, carry no delay because nothing acts on one.
        retry_after: Option<Duration>,
    },
    /// A transfer under that name is already running on the receiving machine — a second
    /// transfer this machine started under one name, or a first offer meeting a name another of
    /// this machine's transfers already holds there. The answer names the class only: how far
    /// that transfer has got is the other side's offset and is not carried here. A retry of the
    /// machine's own transfer, which the receiving side is still holding, waits for it to let go
    /// instead, and the offset that side states is what keeps a slow sink from looking like a
    /// stopped one; the stall bound ends that wait if the offset stops growing.
    AlreadyRunning,
    /// The receiving machine holds that name with different content.
    Conflict,
    /// What arrived does not match the digest.
    DigestMismatch,
    /// The receiving machine could not store it, in its own words, which stay there.
    StoreFailed,
    /// The receiving machine's person stopped it.
    StoppedByReceiver,
    /// The connection is live and the transfer made no progress for [`TRANSFER_STALL`], or
    /// this machine could not read its own record for [`TRANSFER_WAIT`]: the transfer was
    /// not moving and nothing this machine could do would move it.
    NoProgress,
    /// The pair never answered: its connection did not come back, its binding exchange never
    /// finished, this machine could not open a stream or write its offer and spent the whole wait
    /// bound doing so, or the offers went unanswered for the rest of the wait bound — either every
    /// offer it made, which is what a pair with no binding to decide under looks like from here, or
    /// every offer after the last one it answered. That last reading is the accepted residual: a
    /// pair that is present and answers nothing is reported this way, and it is not a claim that
    /// the pair was absent. So a pair that answers and then goes silent still ends this way at the
    /// wait bound.
    NoPair,
    /// The sending side's source could not be read: it ended early or failed. On the sending
    /// machine that is its own product; on the receiving one it is the peer's.
    SourceUnreadable,
    /// This machine no longer trusts the peer, so the transfer ended with the trust.
    TrustWithdrawn,
}

impl fmt::Display for TransferFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotUnderstood => f.write_str("the peer answered nothing this build understands"),
            Self::Malformed => f.write_str("the receiving machine could not understand the offer"),
            Self::Refused { step } => write!(f, "refused at {step}"),
            Self::NotRecorded => f.write_str("the receiving machine could not record the act"),
            Self::Limit { which, retry_after } => {
                write!(f, "{which} was reached")?;
                if let Some(after) = retry_after {
                    write!(f, "; ask again in {} s", after.as_secs())?;
                }
                Ok(())
            }
            Self::AlreadyRunning => {
                f.write_str("a transfer under that name is already running there")
            }
            Self::Conflict => f.write_str("that name is already held with different content"),
            Self::DigestMismatch => f.write_str("what arrived does not match the digest"),
            Self::StoreFailed => f.write_str("the receiving machine could not store it"),
            Self::StoppedByReceiver => f.write_str("the receiving machine's person stopped it"),
            Self::NoProgress => f.write_str("the transfer stopped moving bytes"),
            Self::NoPair => f.write_str("the pair never answered"),
            Self::SourceUnreadable => f.write_str("this machine's source could not be read"),
            Self::TrustWithdrawn => f.write_str("this machine no longer trusts the peer"),
        }
    }
}

impl std::error::Error for TransferFailure {}

/// What the receiving machine answers on a transfer's stream.
///
/// The closed set, and all of it is the receiver's word: the sending side's own stop is a
/// stream reset with [`TRANSFER_STOP_CODE`], not a frame, because file bytes are unframed and a
/// frame in the middle of them would be read as bytes. Every cause is its own variant, and a
/// variant added after a build shipped reaches an older sender as "not understood" — the status
/// byte is one that build cannot read, and there is no other word for it.
///
/// A product never names one: what it sees is [`TransferFailure`], which is this set plus the
/// causes of its own side.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TransferAnswer {
    /// It arrived: every byte, and the digest matched.
    Complete,
    /// The receiving machine already had it, complete and matching.
    AlreadyComplete,
    /// A transfer under that name is already running there: a second transfer the sender
    /// started under one name, or its own earlier attempt still holding the name. `have` is how
    /// many bytes the receiving side has stored for it, which is what lets the sender tell a
    /// receiver that is still working from one that stopped.
    Running {
        /// How many bytes the receiving side holds for that name, from the file's start.
        have: u64,
    },
    /// The receiving machine's rights refused it, at this step.
    Refused {
        /// The step that refused.
        step: Step,
    },
    /// The receiving machine could not write its own record of the act, so it did not run.
    NotRecorded,
    /// A limit was reached; `retry_after` is set for the start limit, which throttles.
    Limit {
        /// Which limit.
        which: TransferLimit,
        /// How long to wait before asking again, when the limit throttles.
        retry_after: Option<Duration>,
    },
    /// The name is already held with different content.
    Conflict,
    /// What arrived does not match the digest.
    DigestMismatch,
    /// The receiving machine could not store it. Its own words stay local.
    StoreFailed,
    /// The receiving machine's person stopped it.
    Stopped,
    /// Authorised; the receiver already holds `have` bytes and the rest may follow.
    Resume {
        /// How many bytes the receiver already holds, from the file's start.
        have: u64,
    },
    /// The offer could not be understood: a malformed frame, an empty name, an offset past
    /// the file's end, or a length that contradicts what the sink already holds.
    Malformed,
}

/// The receiving side's half of one attempt's stream.
///
/// The frame a look left half-read travels with the stream it came from: an answer the budget cut
/// in half is continued by the next look rather than read as a new frame's magic, so the two are
/// one thing and are threaded through an attempt together.
struct Words<'a> {
    recv: &'a mut RecvStream,
    partial: Vec<u8>,
}

impl<'a> Words<'a> {
    /// The stream, with the bytes a previous reader left in it — an empty buffer when there are
    /// none.
    fn new(recv: &'a mut RecvStream, partial: Vec<u8>) -> Self {
        Self { recv, partial }
    }
}

/// What one whole frame's bytes turned out to be, before the layer reads them.
enum Frame {
    /// One whole frame, its magic and header included.
    Whole(Vec<u8>),
    /// The budget passed with the stream still open and the frame unfinished; what arrived stays
    /// in the reader's buffer.
    Quiet,
    /// The stream ended or went away inside the frame.
    Gone,
    /// A body past the cap, or bytes that are not this frame's magic.
    Broken,
}

/// What one look at the receiving side's half of a transfer's stream produced.
enum Heard {
    /// A transfer answer this build knows.
    Answer(TransferAnswer),
    /// Bytes that are not an answer this build can read: another vocabulary, or a whole frame
    /// whose status byte this build does not know. An *incomplete* frame is never this.
    Other,
    /// The budget passed with the frame unfinished and the stream still open: the receiving
    /// machine is still writing it. The bytes that arrived are kept by the caller's buffer, so
    /// the next look continues the frame rather than starting over.
    Silent,
    /// The stream ended or was reset: nothing more is coming on it. A frame the stream ended in
    /// the middle of is this and not [`Self::Other`] — a machine that was writing is not a
    /// vocabulary this build cannot speak.
    Gone,
}

/// What one look at the receiving side's half said, in the terms both readers of it need.
enum Word {
    /// The receiver stated an offset further than any it stated before: the file got further.
    Progress,
    /// The receiving machine ended the transfer, with this answer.
    Ended(TransferAnswer),
    /// Nothing this machine has not already seen: a word repeating an offset, or a look that
    /// waited out its budget with the stream still open.
    Quiet,
    /// The stream went away before it said anything that ends the transfer.
    Gone,
    /// A whole frame this build cannot read, or bytes that are not an answer at all.
    Other,
}

/// What one look at the receiving side's half said while a write was parked or a source was not
/// ready.
enum Look {
    /// The receiving side's stated offset grew — the only thing that moves the stall clock.
    Grew,
    /// Nothing that ends the attempt, and nothing this machine had not already seen.
    Quiet,
    /// The attempt is over, with this.
    Over(Sent),
}

/// Why a transfer could not be started, read or believed.
#[derive(Debug)]
pub enum TransferError {
    /// The peer is not one this machine paired with.
    NotPaired { peer: PeerId },
    /// A person withdrew this machine's trust in the peer.
    Withdrawn { peer: PeerId },
    /// The pair is closed by three failed comparisons.
    Closed { peer: PeerId },
    /// This machine already has [`MAX_RUNNING_TRANSFERS`] transfers with the peer.
    Limit { peer: PeerId },
    /// The file is empty. A zero-length file is refused locally, before anything is sent.
    Empty,
    /// The record refused, in its own words.
    Record(RecordError),
    /// The log refused, in its own words.
    Audit(AuditError),
    /// The decision refused, in its own words.
    Rights(RightsError),
}

impl fmt::Display for TransferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPaired { peer } => write!(f, "{peer:?} is not a paired peer"),
            Self::Withdrawn { peer } => write!(f, "trust in {peer:?} is withdrawn"),
            Self::Closed { peer } => {
                write!(
                    f,
                    "the pair with {peer:?} is closed until a person clears it"
                )
            }
            Self::Limit { peer } => write!(
                f,
                "this machine already has {MAX_RUNNING_TRANSFERS} transfers with {peer:?}"
            ),
            Self::Empty => f.write_str("a zero-length file is not a transfer"),
            Self::Record(error) => error.fmt(f),
            Self::Audit(error) => error.fmt(f),
            Self::Rights(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for TransferError {}

impl From<RecordError> for TransferError {
    fn from(error: RecordError) -> Self {
        Self::Record(error)
    }
}

impl From<AuditError> for TransferError {
    fn from(error: AuditError) -> Self {
        Self::Audit(error)
    }
}

impl From<RightsError> for TransferError {
    fn from(error: RightsError) -> Self {
        Self::Rights(error)
    }
}

impl From<Untrusted> for TransferError {
    fn from(why: Untrusted) -> Self {
        match why {
            Untrusted::Withdrawn(peer) => Self::Withdrawn { peer },
            Untrusted::Closed(peer) => Self::Closed { peer },
            Untrusted::NotPaired(peer) => Self::NotPaired { peer },
        }
    }
}

/// One of this machine's outgoing transfers, as the product holds it.
///
/// Cheap to clone: the state is shared with the task that moves the file. Dropping the handle
/// does not stop the transfer; [`Self::stop`] does.
#[derive(Clone)]
pub struct Transfer {
    name: TransferName,
    shared: Arc<Shared>,
}

impl fmt::Debug for Transfer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transfer")
            .field("name", &self.name)
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

impl Transfer {
    /// The product's name for it.
    #[must_use]
    pub const fn name(&self) -> &TransferName {
        &self.name
    }

    /// Where it stands now.
    #[must_use]
    pub fn state(&self) -> TransferState {
        self.shared.lock().clone()
    }

    /// Stop it, as the product's own person stopping it does.
    ///
    /// A transfer waiting for the answer to its offer stops at once — the answer is read in
    /// polls, so it is noticed inside one; one that is moving bytes stops at its next chunk; one
    /// whose bytes are all written stops at its next look at the receiving side's word, so a stop
    /// during a slow sink's tail does not wait for a file nobody wants.
    /// Two waits are not polled, because neither is on the transfer's own clock: a dial already
    /// under way, and a stream the peer has not made room for — opening one at its stream
    /// limit, or writing the offer while the peer takes no bytes. A stop made during one takes
    /// effect when that wait returns: the handle already says stopped, and one of this machine's
    /// places for the peer comes back then. The stream waits are bounded by the answer budget; a
    /// dial is bounded by the connection attempt's own. The receiver reads the stream's reset as
    /// the sending side stopping it. A transfer that already ended is left as it ended, and one
    /// this machine stopped stays stopped: no later answer and no chunk already on the wire
    /// puts it back on its feet.
    pub fn stop(&self) {
        self.shared.stopping.store(true, Ordering::SeqCst);
        let mut state = self.shared.lock();
        if !state.is_over() {
            *state = TransferState::Stopped;
        }
    }
}

/// One transfer this machine is receiving, as the product can see it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Incoming {
    /// The product's name for it.
    pub name: TransferName,
    /// Where it stands now.
    pub state: TransferState,
}

/// What a transfer's task and its handle share.
struct Shared {
    state: Mutex<TransferState>,
    stopping: AtomicBool,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, TransferState> {
        self.state
            .lock()
            .expect("a transfer's state is not poisoned")
    }

    fn set(&self, state: TransferState) {
        let mut current = self.lock();
        // A stop this machine's own product made is final: the task's last write, and the
        // `running` updates of a chunk that was already on the wire when the stop was made,
        // must not put the transfer back on its feet. Only `Stopped` may be written once
        // `stopping` is set, and `stop` has already written it.
        if self.stopped() && state != TransferState::Stopped {
            return;
        }
        *current = state;
    }

    fn stopped(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }
}

/// What one attempt on a live connection produced.
enum Attempt {
    /// The connection could not be used at all: no stream to write the offer on, or the offer
    /// could not be written. Nothing left this machine, so the pair can hold nothing from this
    /// attempt and it is not an offer. Which is why it goes where no connection at all goes, and
    /// why it is not [`Self::Unanswered`]: the pair answered nothing because it was asked nothing.
    Unusable,
    /// The offer was written and nothing came back: no answer, no word, or a stream that went
    /// away before its answer did — what a pair with no binding to decide under looks like from
    /// here.
    Unanswered,
    /// The transfer is over, with this state.
    Done(TransferState),
    /// Try again on the next round. `have` is the furthest the receiving side said it holds —
    /// the only thing that says the file got further, since a re-send from the receiver's own
    /// offset moves bytes without moving the file. Reached only after the pair answered the
    /// offer, so it also says the pair is there.
    Again {
        /// How much of the file the receiving side stated it holds.
        have: u64,
    },
    /// The receiving machine throttled this machine: it named how long to wait before starting
    /// another transfer, and the transfer asks again when that passes. Not an end — a start
    /// limit is the receiving machine pacing the sender, not refusing the file.
    Wait {
        /// How long the receiving machine asked this one to wait.
        after: Duration,
        /// Whether the pair had already taken the transfer when it throttled: every byte of the
        /// offer answered with `resume`. A limit met by a transfer the pair is taking is pacing,
        /// and only one that is the whole answer to an offer can be a window this machine's own
        /// unanswered offers filled.
        took: bool,
        /// How much of the file the receiving side stated it holds before it throttled — `0` for
        /// a throttle that was the whole answer to an offer, which states no offset. Nothing takes
        /// an offset the receiver stated back, so this is carried out of the attempt.
        have: u64,
    },
}

/// What one offer was decided to be.
enum Decided {
    /// It runs, from where the sink has got to, under this pair and right.
    Go(Run),
    /// The sender is answered `answer`. `under` is the pair and right the decision was made
    /// under, when it got that far: a refusal at the right step has none, and nothing is
    /// remembered under a pair that refused.
    Answered {
        /// The pair and right, when the decision reached them.
        under: Option<(Pair, Right)>,
        /// What the sender is owed.
        answer: TransferAnswer,
    },
    /// Nothing is answered at all: the sender asks again.
    Nothing,
}

/// One offer this machine decided to run.
struct Run {
    /// The pair it was authorised under.
    pair: Pair,
    /// The right it was authorised by.
    right: Right,
    /// How many bytes the sink already holds, from the file's start.
    have: u64,
    /// Whether an earlier attempt under this name made the decision, so the act is not recorded
    /// a second time.
    resumed: bool,
}

/// What one pass over the file's bytes produced.
enum Sent {
    /// The stream stopped taking bytes — every byte was written, or it broke part-way. `have` is
    /// the furthest the receiving side said it holds. Either way the receiver may have written
    /// its answer before it stopped reading, so the attempt reads it rather than opening a
    /// stream the receiver would call `running`.
    Moved {
        /// How much of the file the receiving side stated it holds.
        have: u64,
    },
    /// The transfer is over: this machine's source failed, its own person stopped it, the
    /// receiving side answered with something that ends it, or the stream took nothing for
    /// [`TRANSFER_STALL`] and nothing was said on the other half either.
    Over(TransferState),
    /// The receiving machine paced this machine mid-transfer: the attempt is over, and the
    /// transfer waits the delay it named before asking again — the same reading a start limit
    /// gets wherever else it arrives. `have` is the furthest offset that side stated before it
    /// throttled, so the offset is not lost with the attempt.
    Wait {
        /// How long the receiving machine asked this one to wait.
        after: Duration,
        /// How much of the file the receiving side stated it holds.
        have: u64,
    },
}

/// The two budgets a transfer spends, and the one rule that clears them.
///
/// `stalled` is the time this transfer has had a live connection and the receiving machine's
/// offset has not grown: the stall bound. `waited` is the time it has had no pair to move bytes
/// with — no connection, a binding exchange that never finished, offers nothing answers: the
/// wait bound. **The receiving machine's stated offset growing is the only thing that clears
/// either** — [`TRANSFER_STALL`] states what each kind of answered round spends — and this type is
/// the only place either is charged or cleared, so the rule cannot be got round in one arm and
/// kept in another: a connection that comes back and moves nothing buys the transfer no fresh
/// budget, and a peer that cycles one cannot park it — or one of this machine's places for the
/// peer — by coming and going. A round the receiving machine paced is the one thing that neither
/// charges nor clears; [`Self::paced`] says why.
struct Bounds {
    /// How much of the stall bound this transfer has spent.
    stalled: Duration,
    /// How much of the wait bound it has spent.
    waited: Duration,
    /// When the phase now being charged began: an attempt, or a wait for the pair.
    since: Instant,
}

impl Bounds {
    fn new(now: Instant) -> Self {
        Self {
            stalled: Duration::ZERO,
            waited: Duration::ZERO,
            since: now,
        }
    }

    /// The receiving machine's stated offset grew, so the file got further: both budgets start
    /// again. The one place either is cleared.
    fn grew(&mut self, now: Instant) {
        self.stalled = Duration::ZERO;
        self.waited = Duration::ZERO;
        self.since = now;
    }

    /// Charge everything since the phase began — the attempt and the pause after it — to the
    /// stall bound: a live connection that got the file no further. Bytes the stream accepted
    /// are not growth, so an attempt that wrote them is charged like any other that stated
    /// nothing.
    fn spent_stalling(&mut self, now: Instant) {
        self.stalled += now.duration_since(self.since);
        self.since = now;
    }

    /// The same to the wait bound: time with no pair to move bytes with.
    fn spent_waiting(&mut self, now: Instant) {
        self.waited += now.duration_since(self.since);
        self.since = now;
    }

    /// Begin a phase that spends neither bound, because the receiving machine answered: a throttle
    /// is the pair pacing this transfer, not a wait for it and not a stall.
    ///
    /// The offset a throttled attempt states is folded into the caller's `stored` and never taken
    /// back, but it does not clear what earlier rounds spent: the silence before the throttle was
    /// real, and a peer that stalls and then states an offset it already held must not buy itself a
    /// fresh bound with it. The bounds are cleared by growth in the one arm where growth is what
    /// the round was — an answer that ends the attempt without pacing it — so a paced round can
    /// never be read as the one that bought the transfer a fresh budget.
    fn paced(&mut self, now: Instant) {
        self.since = now;
    }

    fn stalled_out(&self) -> bool {
        self.stalled >= TRANSFER_STALL
    }

    fn waited_out(&self) -> bool {
        self.waited >= TRANSFER_WAIT
    }
}

/// The transfer layer of one machine.
///
/// Built once per storage root, like the layers it decides with, and run by the product: the
/// sending side is [`Self::send`], and the receiving side is reached through
/// [`crate::peer::inbox::Inbox`], which is the one reader of a pair's connection.
pub struct Transfers {
    rights: Rights,
    floor: Arc<dyn Floor + Send + Sync>,
    moment: Arc<dyn Moment + Send + Sync>,
    sink: Option<Arc<dyn Sink + Send + Sync>>,
    runtime: Arc<dyn Runtime>,
    /// How many of this machine's own transfers each peer has, waiting or running.
    outgoing: Mutex<BTreeMap<PeerId, usize>>,
    /// The transfers this machine authorised, so a resume is not decided again.
    remembered: Mutex<BTreeMap<(PeerId, TransferName), Authorised>>,
    /// The names one stream is answering right now: a second offer of a name under decision
    /// is answered `running`, so two streams never write one file's offsets.
    deciding: Mutex<BTreeSet<(PeerId, TransferName)>>,
    /// The receiver's start limit, one window per peer, in memory only.
    windows: Windows,
}

impl fmt::Debug for Transfers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transfers")
            .field("sink", &self.sink.is_some())
            .finish_non_exhaustive()
    }
}

/// One transfer this machine authorised, as it remembers it.
#[derive(Clone)]
struct Authorised {
    pair: Pair,
    /// The right the transfer was authorised under, kept so a resume is not decided again
    /// and the record of it names the same permission, issuer and term.
    right: Right,
    length: u64,
    digest: Digest,
    /// The last moment it was seen to move or ask.
    seen: Timestamp,
    state: TransferState,
    /// Whether **this** machine's person stopped it, through [`Transfers::stop_incoming`].
    ///
    /// A stop is not the same act whoever makes it. This machine's person stopping a transfer
    /// keeps the name stopped: a fresh offer under it is answered `stopped` rather than
    /// authorised again. The *sending* side stopping its own transfer is not this machine's
    /// decision, so the name is free — the receiving product is told the transfer stopped, and a
    /// sending product that offers the file again gets a fresh transfer rather than being told
    /// the receiving person stopped something they never saw.
    stopped_here: bool,
}

impl Authorised {
    fn running(&self) -> bool {
        matches!(
            self.state,
            TransferState::Waiting | TransferState::Running { .. }
        )
    }
}

/// One of this machine's places for the peer, given back when the transfer's task ends.
struct Place {
    transfers: Arc<Transfers>,
    peer: PeerId,
}

impl Drop for Place {
    fn drop(&mut self) {
        let mut outgoing = self.transfers.outgoing();
        if let Some(count) = outgoing.get_mut(&self.peer) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                outgoing.remove(&self.peer);
            }
        }
    }
}

/// One stream's hold on a transfer's name, released when the stream's task ends.
struct Claim<'a> {
    transfers: &'a Transfers,
    key: (PeerId, TransferName),
}

impl Drop for Claim<'_> {
    fn drop(&mut self) {
        self.transfers
            .deciding
            .lock()
            .expect("the deciding transfers are not poisoned")
            .remove(&self.key);
    }
}

impl Transfers {
    /// Build the layer over the records and the log the decision reads.
    ///
    /// The records and the log must be built from the **same** storage root, and the floor
    /// and the moment must be the ones the message and action layers were given: a product
    /// that wires a different floor into each gets a host policy that allows messages and
    /// refuses files in one place and not the other. The sink is the product's; `None` is a
    /// product with nowhere to put a file, and a peer that holds the right meets that at the
    /// floor — the crate never reads the product's configuration as a rights fact. That floor is
    /// this layer's own: it refuses `put files on me` when there is no sink, and answers the
    /// product's floor for every other permission.
    #[must_use]
    pub fn open(
        records: RecordStore,
        audit: AuditLog,
        floor: Arc<dyn Floor + Send + Sync>,
        moment: Arc<dyn Moment + Send + Sync>,
        sink: Option<Arc<dyn Sink + Send + Sync>>,
        runtime: Arc<dyn Runtime>,
    ) -> Self {
        // A product with nowhere to put a file has not granted file ingress, and the layer's
        // own floor is where that is decided: the refusal is the same step, and the same
        // recorded entry, as a host floor's, and the crate never reads the product's
        // configuration as a rights fact.
        let has_sink = sink.is_some();
        let floor: Arc<dyn Floor + Send + Sync> = Arc::new(FileIngress::new(floor, has_sink));
        Self {
            rights: Rights::new(records, audit),
            floor,
            moment,
            sink,
            runtime,
            outgoing: Mutex::new(BTreeMap::new()),
            remembered: Mutex::new(BTreeMap::new()),
            deciding: Mutex::new(BTreeSet::new()),
            windows: Windows::new(),
        }
    }

    /// Offer a whole file to `peer`, and return the handle that moves it.
    ///
    /// The file is not read here: the transfer's task reads it, one [`TRANSFER_CHUNK`] at a
    /// time, once the pair's connection is up and the receiver has answered. A pair that is
    /// down is a reason to dial, through the same recovery machinery the message queue uses,
    /// and not a failure. The record is re-read first, so a peer this machine no longer
    /// remembers, or whose trust it withdrew, is refused before anything starts.
    ///
    /// # Errors
    ///
    /// [`TransferError::Empty`] for a zero-length file,
    /// [`TransferError::NotPaired`]/[`TransferError::Withdrawn`]/[`TransferError::Closed`] for
    /// the record's answer, [`TransferError::Limit`] when this machine already has
    /// [`MAX_RUNNING_TRANSFERS`] transfers with the peer, and the record's own refusals.
    pub fn send(
        self: &Arc<Self>,
        connections: &Arc<Connections>,
        endpoint: &Endpoint,
        peer: &PeerId,
        offering: Offering,
    ) -> Result<Transfer, TransferError> {
        if offering.length == 0 {
            return Err(TransferError::Empty);
        }
        let limits = self.rights.records().limits();
        let Some(record) = self.rights.records().reread(peer)? else {
            return Err(TransferError::NotPaired { peer: *peer });
        };
        if let Some(why) = record.untrusted(&limits) {
            return Err(why.into());
        }
        {
            let mut outgoing = self.outgoing();
            let count = outgoing.entry(*peer).or_insert(0);
            if *count >= MAX_RUNNING_TRANSFERS {
                return Err(TransferError::Limit { peer: *peer });
            }
            *count += 1;
        }
        let shared = Arc::new(Shared {
            state: Mutex::new(TransferState::Waiting),
            stopping: AtomicBool::new(false),
        });
        let transfer = Transfer {
            name: offering.name.clone(),
            shared: Arc::clone(&shared),
        };
        let this = Arc::clone(self);
        let connections = Arc::clone(connections);
        let endpoint = endpoint.clone();
        let peer = *peer;
        // The place is given back when the task ends, however it ends: a task that panicked
        // would otherwise hold one of this machine's places for the peer for ever.
        let place = Place {
            transfers: Arc::clone(self),
            peer,
        };
        self.runtime.spawn(Box::pin(async move {
            let _place = place;
            let state = this
                .run(&connections, &endpoint, peer, &offering, &shared)
                .await;
            shared.set(state);
        }));
        Ok(transfer)
    }

    /// Stop a transfer this machine is receiving from `peer`, as its own person stopping it
    /// does.
    ///
    /// The sender is answered `stopped` at the receiver's next chunk, at its next look when its
    /// sink is the thing answering "not now", and at its next offer when the transfer was
    /// waiting for the pair — so each side learns an answer and not an error, and a stopped
    /// name is not authorised afresh while the sender keeps asking. Answers whether there was a
    /// transfer to stop: one that is over, was never authorised, or has been silent for
    /// [`TRANSFER_WAIT`] and is therefore already dead is left as it is.
    pub fn stop_incoming(&self, peer: &PeerId, name: &TransferName) -> bool {
        // The same expiry the product's own view runs, so a transfer that is dead is answered
        // as dead whether or not the product has looked at it.
        let now = self.moment.now();
        self.expire(now);
        let mut remembered = self.remembered();
        match remembered.get_mut(&(*peer, name.clone())) {
            Some(authorised) if authorised.running() => {
                authorised.state = TransferState::Stopped;
                authorised.stopped_here = true;
                // From the stop, not from the last byte: a stopped transfer is visible to the
                // product for the wait bound from the moment it was stopped.
                authorised.seen = now;
                true
            }
            _ => false,
        }
    }

    /// The transfers this machine is receiving from `peer`, as its product can see them.
    ///
    /// A transfer that is quietly waiting for the pair is here, so it is never mistaken for
    /// one that is done — and one that has waited longer than [`TRANSFER_WAIT`] is reported as
    /// [`TransferFailure::NoPair`], because asking for this view is what runs the one expiry
    /// that decides a transfer is dead. An ended transfer stays visible for [`TRANSFER_WAIT`]
    /// after it ended and is forgotten once that has passed — at this view, at the peer's next
    /// offer, or at any other peer's, since the expiry sweeps every entry.
    ///
    /// What is here is a transfer that was authorised, and nothing else: an offer this machine
    /// refused at a step, or answered as the start or running limit, was not a transfer and is
    /// not remembered as one. The refusal is in [`crate::peer::audit`], with the permission and
    /// the step, written before the sender was answered.
    #[must_use]
    pub fn incoming(&self, peer: &PeerId) -> Vec<Incoming> {
        self.expire(self.moment.now());
        self.remembered
            .lock()
            .expect("the remembered transfers are not poisoned")
            .iter()
            .filter(|((each, _), _)| each == peer)
            .map(|((_, name), authorised)| Incoming {
                name: name.clone(),
                state: authorised.state.clone(),
            })
            .collect()
    }

    fn outgoing(&self) -> MutexGuard<'_, BTreeMap<PeerId, usize>> {
        self.outgoing
            .lock()
            .expect("the outgoing transfers are not poisoned")
    }

    fn remembered(&self) -> MutexGuard<'_, BTreeMap<(PeerId, TransferName), Authorised>> {
        self.remembered
            .lock()
            .expect("the remembered transfers are not poisoned")
    }

    /// Claim one name for the stream that is answering it, or answer `None` when another
    /// stream already holds it.
    ///
    /// One lock, so the check and the claim cannot be interleaved: two offers of one name
    /// arriving together are answered by one of them and refused as `running` by the other,
    /// rather than both authorised to write the product's sink at the same offsets. The claim
    /// is released when the stream's task ends, however it ends.
    fn claim(&self, key: (PeerId, TransferName)) -> Option<Claim<'_>> {
        let mut deciding = self
            .deciding
            .lock()
            .expect("the deciding transfers are not poisoned");
        if !deciding.insert(key.clone()) {
            return None;
        }
        drop(deciding);
        Some(Claim {
            transfers: self,
            key,
        })
    }

    /// Decide which transfers are dead, and forget the ones that ended long ago.
    ///
    /// This is the one place a transfer is called dead: a live entry that has not been seen for
    /// [`TRANSFER_WAIT`] becomes [`TransferFailure::NoPair`] here — and its `seen` is set to now,
    /// so an ended transfer stays visible to the product for another [`TRANSFER_WAIT`] before it
    /// is forgotten. Every peer's entries are swept, not only the one being asked about, so the
    /// wait bound really is what bounds the map: at most [`MAX_RUNNING_TRANSFERS`] of a peer's
    /// transfers are live at once, the start limit keeps the count small, and an ended one is
    /// forgotten a wait bound after it ended.
    fn expire(&self, now: Timestamp) {
        let mut remembered = self.remembered();
        for authorised in remembered.values_mut() {
            if authorised.running() && elapsed(now, authorised.seen) >= TRANSFER_WAIT {
                authorised.state = TransferState::Failed {
                    failure: TransferFailure::NoPair,
                };
                authorised.seen = now;
            }
        }
        remembered.retain(|_, authorised| {
            !authorised.state.is_over() || elapsed(now, authorised.seen) < TRANSFER_WAIT
        });
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the loop is the order of the waits: trust, the pair, its binding exchange, the stall bound, then one attempt, each with the bound that ends it"
    )]
    async fn run(
        &self,
        connections: &Arc<Connections>,
        endpoint: &Endpoint,
        peer: PeerId,
        offering: &Offering,
        shared: &Shared,
    ) -> TransferState {
        // The two bounds, as budgets a transfer spends rather than instants it can re-anchor.
        let mut bounds = Bounds::new(self.runtime.now());
        let mut hurried = false;
        // Whether any offer of this transfer has left this machine. The receiver's `running`
        // answer means different things before and after that: a name it holds is another
        // transfer of this machine's only once this one has asked, and an attempt that could not
        // even open a stream asked nothing — so the next attempt is still the first offer.
        let mut offered = false;
        // How much of the file the receiver has stated it holds. The stall bound measures
        // this, not bytes handed to the transport: a re-send from the receiver's own offset
        // moves bytes without moving the file, and nothing takes this back. A `resume` answer
        // states the same thing, and reaches this through the offset the attempt carries out,
        // which is seeded with it.
        let mut stored = 0u64;
        // When the receiving machine first throttled this transfer, for as long as it keeps
        // doing so. The streak has a bound of its own, and what it ends as is read off
        // `unanswered` below.
        let mut throttled: Option<Instant> = None;
        // How long to wait before the next offer when this one produced no answer at all.
        // It starts at `TRANSFER_POLL` and doubles up to `TRANSFER_RETRY_CAP`; an offer the
        // pair answered without pacing the transfer puts it back, so a transfer that is moving
        // is never slowed by it.
        let mut retry = TRANSFER_POLL;
        // How many offers in a row the pair answered with nothing at all, which is what a pair
        // with no binding to decide under does. Any answer clears it, so a throttle met after
        // one is the limit it met — and a throttle met after a whole window of this machine's
        // own unanswered offers is that window, which is the pair's own cause.
        let mut unanswered = 0u32;
        loop {
            if shared.stopped() {
                return TransferState::Stopped;
            }
            // Trust is a file read, not a handle: a withdrawal written through any handle, or
            // by the other process on this root, ends the transfer before its next attempt —
            // and the withdrawal is what closed the connection, so this is asked before the
            // pair's connection is, or the transfer would wait out its whole bound for a
            // connection nobody will make.
            match self.rights.records().reread(&peer) {
                Ok(Some(record)) if record.is_withdrawn() => {
                    return TransferState::Failed {
                        failure: TransferFailure::TrustWithdrawn,
                    };
                }
                Ok(Some(_)) => {}
                Ok(None) => {
                    return TransferState::Failed {
                        failure: TransferFailure::TrustWithdrawn,
                    };
                }
                // A record this machine cannot read is not the peer's fault, so the transfer
                // waits and asks again — but bounded like every other wait here: a record
                // that stays unreadable for the whole wait bound ends it rather than holding
                // one of this machine's places for the peer for ever.
                Err(_) => {
                    if let Some(state) = self
                        .wait_out(
                            shared,
                            &mut bounds,
                            TRANSFER_POLL,
                            TransferFailure::NoProgress,
                        )
                        .await
                    {
                        return state;
                    }
                    continue;
                }
            }
            let Some(traffic) = connections.traffic(&peer) else {
                // The pair's connection is gone: the transfer waits for it rather than
                // failing, and its handle says so instead of showing the offset an attempt
                // that ended had reached.
                if !hurried {
                    connections.hurry(&peer);
                    hurried = true;
                }
                let _ = connections.ensure(endpoint, &peer.fingerprint()).await;
                if let Some(state) = self
                    .wait_out(shared, &mut bounds, TRANSFER_POLL, TransferFailure::NoPair)
                    .await
                {
                    return state;
                }
                continue;
            };
            // A connection whose binding exchange has not finished is not one this machine can
            // offer a file on yet: the receiving side's one reader is what answers the exchange,
            // and a transfer parked here is waiting for it. The wait bound ends it rather than
            // leaving the handle reading `waiting` for ever — the same shape as a pair that is
            // not there at all, because from here the two are the same thing.
            if !traffic.exchange_done() {
                if let Some(state) = self
                    .wait_out(shared, &mut bounds, TRANSFER_POLL, TransferFailure::NoPair)
                    .await
                {
                    return state;
                }
                continue;
            }
            // The stall bound: time on a live connection without the receiving machine's offset
            // growing. A connection coming back does not clear it — that would let a peer that
            // cycles one hold a transfer, and one of this machine's places for the peer, without
            // moving a byte — and neither does anything else but growth.
            if bounds.stalled_out() {
                return TransferState::Failed {
                    failure: TransferFailure::NoProgress,
                };
            }
            let attempt = self.attempt(&traffic, offering, shared, offered).await;
            match attempt {
                Attempt::Done(state) => return state,
                // The pair answered by pacing this transfer, so the pause spends neither bound —
                // see [`Bounds::paced`]. The streak has a bound of its own below, and the wait is
                // outside the attempt, which is what releases the traffic round the attempt held.
                Attempt::Wait { after, took, have } => {
                    offered = true;
                    // Nothing takes the receiver's stated offset back, a throttle included: an
                    // offset this attempt stated is not fresh growth when a later attempt
                    // restates it.
                    let grew = have > stored;
                    stored = stored.max(have);
                    // The pair answered, so the count of offers it did not answer starts again —
                    // unless this limit *is* the whole answer to an offer, which is the window
                    // those unanswered offers filled.
                    if took {
                        unanswered = 0;
                    }
                    if grew {
                        // The file got further, so the streak is over: the receiving machine is
                        // pacing a transfer that is moving.
                        throttled = None;
                    }
                    let now = self.runtime.now();
                    let since_throttle = *throttled.get_or_insert(now);
                    if now.duration_since(since_throttle) >= TRANSFER_WAIT {
                        return TransferState::Failed {
                            failure: if unanswered >= SILENT_OFFERS {
                                // The start window this machine is meeting is the one its own
                                // unanswered offers filled: the pair answered none of them, so
                                // that is what the transfer met.
                                TransferFailure::NoPair
                            } else {
                                TransferFailure::Limit {
                                    which: TransferLimit::Starts,
                                    retry_after: Some(after),
                                }
                            },
                        };
                    }
                    if !shared.stopped() {
                        shared.set(TransferState::Throttled { retry_after: after });
                    }
                    // The longest wait in the layer, and the one a person is most likely to
                    // change their mind during: it is slept in polls, so a stop ends the
                    // transfer instead of holding one of this machine's places for the peer for it.
                    if self.pause(shared, after).await {
                        return TransferState::Stopped;
                    }
                    // Pacing, not stalling: see [`Bounds::paced`].
                    bounds.paced(self.runtime.now());
                }
                // The connection could not be used: nothing left this machine, so this is not a
                // round the pair answered with nothing — the count is left alone, and so is
                // `offered`: if no offer of this transfer has left yet, the next attempt is still
                // the first offer. The time is the wait bound's, exactly as it is with no
                // connection at all.
                Attempt::Unusable => {
                    if let Some(state) = self
                        .wait_out(shared, &mut bounds, TRANSFER_POLL, TransferFailure::NoPair)
                        .await
                    {
                        return state;
                    }
                }
                // The same, and the pair is what did not answer — which is what a pair with no
                // binding to decide under does, and what tells a throttle this machine caused
                // from one the pair meant. The pause grows from one poll to the cap, so a pair
                // that never binds is not offered a file once a second for the whole wait bound.
                Attempt::Unanswered => {
                    offered = true;
                    unanswered += 1;
                    if let Some(state) = self
                        .wait_out(shared, &mut bounds, retry, TransferFailure::NoPair)
                        .await
                    {
                        return state;
                    }
                    // Doubled after the wait, so the first gap is one poll and the schedule
                    // starts where [`TRANSFER_POLL`] says it does.
                    retry = (retry * 2).min(TRANSFER_RETRY_CAP);
                }
                // The pair answered. Any answer ends the count of offers it left unanswered,
                // because a peer that answered is a peer that is there. The receiving machine's
                // own offset is the one thing that says the file got further, so growth — and
                // only growth — is what clears both bounds and ends the throttle streak.
                Attempt::Again { have } => {
                    offered = true;
                    unanswered = 0;
                    retry = TRANSFER_POLL;
                    let grew = have > stored;
                    stored = stored.max(have);
                    if self.pause(shared, retry).await {
                        return TransferState::Stopped;
                    }
                    if grew {
                        bounds.grew(self.runtime.now());
                        throttled = None;
                    } else {
                        // The pair answered and nothing got further: a live connection not
                        // moving, so the whole of the round — the attempt and the pause — is
                        // the stall bound's. A byte the stream accepted is not growth, so a
                        // peer that takes one and resets is charged like any other that stated
                        // nothing.
                        bounds.spent_stalling(self.runtime.now());
                    }
                }
            }
        }
    }

    /// Sleep out `after`, noticing a stop; `true` is stopped.
    async fn pause(&self, shared: &Shared, after: Duration) -> bool {
        let until = self.runtime.now() + after;
        loop {
            if shared.stopped() {
                return true;
            }
            let now = self.runtime.now();
            if now >= until {
                return false;
            }
            sleep(&*self.runtime, (until - now).min(TRANSFER_POLL)).await;
        }
    }

    /// Wait out `pause` in polls, noticing a stop, spend it on the wait bound, and answer the
    /// state that ends the wait once that bound has passed.
    async fn wait_out(
        &self,
        shared: &Shared,
        bounds: &mut Bounds,
        pause: Duration,
        ends: TransferFailure,
    ) -> Option<TransferState> {
        shared.set(TransferState::Waiting);
        if self.pause(shared, pause).await {
            return Some(TransferState::Stopped);
        }
        bounds.spent_waiting(self.runtime.now());
        bounds
            .waited_out()
            .then_some(TransferState::Failed { failure: ends })
    }

    async fn attempt(
        &self,
        traffic: &Traffic,
        offering: &Offering,
        shared: &Shared,
        offered: bool,
    ) -> Attempt {
        // A round for the attempt's whole life: a transfer that has not moved a byte is not
        // the pair's traffic, and one that has says so through `took`.
        let _round = traffic.round();
        let connection = traffic.connection();
        // A stream that cannot be opened, or an offer that cannot be written, is a connection
        // this machine cannot offer a file on — not a round the pair failed to answer.
        let opened = timeout(&*self.runtime, TRANSFER_ANSWER_BUDGET, connection.open_bi()).await;
        let Some(Ok((mut send, mut recv))) = opened else {
            return Attempt::Unusable;
        };
        let offer = wire::encode_offer(&offering.name, offering.length, &offering.digest);
        if !stream::write_whole(&*self.runtime, &mut send, &offer, TRANSFER_ANSWER_BUDGET).await {
            return Attempt::Unusable;
        }
        // The answer to the offer is one small frame, and the whole of it is bounded by the answer
        // budget: a frame that is still arriving is waited for inside that budget rather than
        // called a refusal, and one that does not finish inside it is a lost attempt.
        let started = self.runtime.now();
        let mut words = Words::new(&mut recv, Vec::new());
        let answer = loop {
            // A stop reaches this phase too: the answer budget is half a minute, and a product
            // whose handle already says stopped must not hold one of this machine's places for
            // the peer for it.
            if shared.stopped() {
                let _ = send.reset(VarInt::from_u32(TRANSFER_STOP_CODE));
                return Attempt::Done(TransferState::Stopped);
            }
            let left =
                TRANSFER_ANSWER_BUDGET.saturating_sub(self.runtime.now().duration_since(started));
            if left.is_zero() {
                return Attempt::Unanswered;
            }
            // One poll at a time, so the stop above is noticed inside a second rather than at the
            // end of the budget; a frame cut by the poll is kept and continued by the next look.
            match self.read_answer(&mut words, left.min(TRANSFER_POLL)).await {
                Heard::Answer(answer) => break answer,
                // A whole frame this build cannot read is the sender's "not understood", and
                // nothing else.
                Heard::Other => {
                    return Attempt::Done(TransferState::Failed {
                        failure: TransferFailure::NotUnderstood,
                    });
                }
                // The offer was written and the stream ended before a byte of answer did: what
                // a pair with no binding to decide it under does.
                Heard::Gone => return Attempt::Unanswered,
                Heard::Silent => {}
            }
        };
        match answer {
            TransferAnswer::Resume { have } if have <= offering.length => {
                shared.set(TransferState::Running {
                    moved: have,
                    of: offering.length,
                });
                let pass = self
                    .send_bytes(&mut send, &mut words, offering, shared, have, traffic)
                    .await;
                match pass {
                    Sent::Moved { have } => {
                        let _ = send.finish();
                        self.verdict(&mut send, &mut words, offering.length, have, shared)
                            .await
                    }
                    Sent::Over(state) => Attempt::Done(state),
                    Sent::Wait { after, have } => Attempt::Wait {
                        after,
                        took: true,
                        have,
                    },
                }
            }
            // A resume past the file's end is not a state this crate produces.
            TransferAnswer::Resume { .. } => Attempt::Done(TransferState::Failed {
                failure: TransferFailure::NotUnderstood,
            }),
            // The receiving machine says a transfer under this name is still running there. Once
            // an offer of this transfer has left this machine that is this transfer's own earlier
            // attempt, still holding the name on the receiving side — a stream that died, or a
            // sink that is taking bytes slowly — so the sender waits for it to let go instead of
            // reporting its own transfer back to itself; the offset it states is what keeps a slow
            // sink from looking like a stopped one, and the stall bound ends the wait if the
            // offset stops growing. Before that it is a name another transfer holds there, and
            // `already running` is its answer.
            TransferAnswer::Running { have } if offered => Attempt::Again {
                have: have.min(offering.length),
            },
            // A limit on starts is a throttle wherever it is read; the other limit — this
            // machine's own count of running transfers — is terminal, because the peer's own
            // count would refuse a third one locally anyway.
            other => match throttle_of(&other) {
                Some(after) => Attempt::Wait {
                    after,
                    took: false,
                    // A limit that is the whole answer to an offer states no offset.
                    have: 0,
                },
                None => Attempt::Done(state_of(&other, offering.length)),
            },
        }
    }

    /// Read the receiver's verdict after the file's bytes, and the progress words a slow sink
    /// sends while it stores the tail.
    ///
    /// A peer that floods words cannot buy itself time with them: the bound below is the runtime's
    /// clock, checked on every look, and not a count of looks.
    async fn verdict(
        &self,
        send: &mut SendStream,
        words: &mut Words<'_>,
        length: u64,
        mut landed: u64,
        shared: &Shared,
    ) -> Attempt {
        let mut last = self.runtime.now();
        loop {
            if shared.stopped() {
                // The receiving side learns it the same way it learns a stop during the bytes: a
                // reset, which it cannot mistake for file bytes. A stream already finished may
                // refuse the reset, and then the receiver has the whole file anyway.
                let _ = send.reset(VarInt::from_u32(TRANSFER_STOP_CODE));
                return Attempt::Done(TransferState::Stopped);
            }
            match self.word(words, &mut landed, length).await {
                Word::Progress => last = self.runtime.now(),
                // Nothing this machine has not already seen — a word repeating an offset, or a
                // look that waited out its budget — falls to the bound below.
                Word::Quiet => {}
                Word::Ended(answer) => {
                    return match throttle_of(&answer) {
                        Some(after) => Attempt::Wait {
                            after,
                            took: true,
                            have: landed,
                        },
                        None => Attempt::Done(state_of(&answer, length)),
                    };
                }
                Word::Other => {
                    return Attempt::Done(TransferState::Failed {
                        failure: TransferFailure::NotUnderstood,
                    });
                }
                // The stream ended with no verdict, or the connection went away. The offset the
                // receiver stated is kept: what landed there does not stop having landed.
                Word::Gone => return Attempt::Again { have: landed },
            }
            if self.runtime.now().duration_since(last) >= TRANSFER_SENDER_BOUND {
                return Attempt::Done(TransferState::Failed {
                    failure: TransferFailure::NoProgress,
                });
            }
        }
    }

    /// One look at the receiving side's half, in the terms both readers of it need.
    async fn word(&self, words: &mut Words<'_>, landed: &mut u64, length: u64) -> Word {
        match self.read_answer(words, TRANSFER_POLL).await {
            Heard::Answer(TransferAnswer::Running { have }) => {
                let have = have.min(length);
                if have > *landed {
                    *landed = have;
                    Word::Progress
                } else {
                    Word::Quiet
                }
            }
            Heard::Answer(answer) => Word::Ended(answer),
            Heard::Silent => Word::Quiet,
            Heard::Gone => Word::Gone,
            Heard::Other => Word::Other,
        }
    }

    /// Read one answer frame, bounded, continuing a frame an earlier look left half-read.
    async fn read_answer(&self, words: &mut Words<'_>, budget: Duration) -> Heard {
        let frame = read_frame(
            &*self.runtime,
            words,
            wire::ANSWER_MAGIC,
            wire::ANSWER_HEADER_BYTES,
            wire::ANSWER_CAP,
            budget,
        )
        .await;
        match frame {
            Frame::Whole(bytes) => match wire::decode_answer(&bytes) {
                Some(answer) => Heard::Answer(answer),
                None => Heard::Other,
            },
            Frame::Quiet => Heard::Silent,
            Frame::Gone => Heard::Gone,
            Frame::Broken => Heard::Other,
        }
    }

    /// Move the file's bytes from `have` to its length, one chunk at a time.
    ///
    /// The first byte that reaches the stream is the pair's use, and says so through `took` as
    /// it happens rather than at the end of the chunk: a connection that dies after moving part of
    /// one — with the source answering "not now" when it does — is not a dial that carried
    /// nothing.
    ///
    /// A write that parks is not a stall.
    async fn send_bytes(
        &self,
        send: &mut SendStream,
        words: &mut Words<'_>,
        offering: &Offering,
        shared: &Shared,
        have: u64,
        traffic: &Traffic,
    ) -> Sent {
        let mut offset = have;
        let mut buffer = vec![0u8; TRANSFER_CHUNK];
        // The stall clock: when the receiving side last said the file got further, and nothing
        // else. The receiving machine's own worst honest silence is the bound here too, so a
        // receiver reaching its own bound is heard rather than timed out.
        let mut last = self.runtime.now();
        // The furthest the receiving side has said the file got. Nothing takes it back.
        let mut landed = have;
        // Whether this attempt has already said the pair carried something: the counter counts
        // answers, so it is told once.
        let mut counted = false;
        while offset < offering.length {
            if shared.stopped() {
                let _ = send.reset(VarInt::from_u32(TRANSFER_STOP_CODE));
                return Sent::Over(TransferState::Stopped);
            }
            let room = usize::try_from(offering.length - offset)
                .unwrap_or(TRANSFER_CHUNK)
                .min(TRANSFER_CHUNK);
            match offering
                .source
                .read(&offering.name, offset, &mut buffer[..room])
            {
                Read::Bytes(count) if count > 0 && count <= room => {
                    let mut written = 0;
                    while written < count {
                        // One `write` and not `write_all`: a write that parks part-way through a
                        // chunk must leave the count of what the stream took, or the rest of the
                        // chunk would be sent twice.
                        match timeout(
                            &*self.runtime,
                            TRANSFER_POLL,
                            send.write(&buffer[written..count]),
                        )
                        .await
                        {
                            Some(Ok(taken)) => {
                                // The first byte the stream takes is the pair's use, said as it
                                // happens rather than after the chunk: a connection that dies
                                // after moving part of one — with the source answering "not now"
                                // when it does — is not a dial that carried nothing.
                                if !counted {
                                    counted = true;
                                    traffic.took();
                                }
                                written += taken;
                            }
                            // The stream or the connection went away: the receiver's answer, if
                            // it wrote one, is on the other half of the stream.
                            Some(Err(_)) => return Sent::Moved { have: landed },
                            None => {
                                // Parked. Listen for the receiving side's progress word, and end
                                // the transfer only when the offset it states has not grown for
                                // the bound. A write the stream accepts is not growth, so this is
                                // the one clock a peer cannot move with bytes it never stored.
                                match self.listen(words, &mut landed, offering.length).await {
                                    Look::Grew => last = self.runtime.now(),
                                    Look::Quiet => {}
                                    Look::Over(ended) => return ended,
                                }
                                if shared.stopped() {
                                    let _ = send.reset(VarInt::from_u32(TRANSFER_STOP_CODE));
                                    return Sent::Over(TransferState::Stopped);
                                }
                                if self.runtime.now().duration_since(last) >= TRANSFER_SENDER_BOUND
                                {
                                    return Sent::Over(TransferState::Failed {
                                        failure: TransferFailure::NoProgress,
                                    });
                                }
                            }
                        }
                    }
                    offset += u64::try_from(count).expect("a chunk is far below a u64");
                    shared.set(TransferState::Running {
                        moved: offset,
                        of: offering.length,
                    });
                }
                // A source that ends early, answers nothing or fails is this machine's own
                // fault, and its own answer: the sender learns it, and the receiver reads the
                // stream ending short of the length it was promised as the same class —
                // `SourceUnreadable`. The stream is dropped rather than reset with the stop
                // code, which finishes it: the receiver reads that as a stream that went away,
                // not as this machine's person stopping the transfer.
                Read::Bytes(_) | Read::Ended | Read::Failed => {
                    return Sent::Over(TransferState::Failed {
                        failure: TransferFailure::SourceUnreadable,
                    });
                }
                Read::NotNow => {
                    if shared.stopped() {
                        let _ = send.reset(VarInt::from_u32(TRANSFER_STOP_CODE));
                        return Sent::Over(TransferState::Stopped);
                    }
                    // Nothing from this machine's own source, so look at the receiving side's
                    // half: the offset it states as the bytes already sent land is what moves
                    // the clock, and a source that produces something inside the bound is not a
                    // transfer that stopped.
                    match self.listen(words, &mut landed, offering.length).await {
                        Look::Grew => last = self.runtime.now(),
                        Look::Quiet => {}
                        Look::Over(ended) => return ended,
                    }
                    if self.runtime.now().duration_since(last) >= TRANSFER_SENDER_BOUND {
                        return Sent::Over(TransferState::Failed {
                            failure: TransferFailure::NoProgress,
                        });
                    }
                }
            }
        }
        Sent::Moved { have: landed }
    }

    /// Listen on the receiving side's half of the stream while a write is parked or a source is
    /// not ready.
    async fn listen(&self, words: &mut Words<'_>, landed: &mut u64, length: u64) -> Look {
        match self.word(words, landed, length).await {
            Word::Progress => Look::Grew,
            // A word that was not, and a look that waited out its budget: the caller's bound is
            // what ends the wait.
            Word::Quiet => Look::Quiet,
            // A start limit is a throttle wherever it is read: the receiving machine is pacing
            // this one, not ending the transfer. The offset it stated before it throttled is
            // carried out with it, so a later restatement of that offset is not growth.
            Word::Ended(answer) => Look::Over(match throttle_of(&answer) {
                Some(after) => Sent::Wait {
                    after,
                    have: *landed,
                },
                // The receiving side ended the transfer while this machine was writing: its
                // sink refused, its person stopped it, its record could not be written. Its
                // word is the answer.
                None => Sent::Over(state_of(&answer, length)),
            }),
            Word::Other => Look::Over(Sent::Over(TransferState::Failed {
                failure: TransferFailure::NotUnderstood,
            })),
            // The stream went away: the attempt reads whatever answer it left.
            Word::Gone => Look::Over(Sent::Moved { have: *landed }),
        }
    }

    /// Answer one offer on `send`/`recv`, whose first bytes are `prefix`.
    ///
    /// The connection's presented key was checked by the inbox that called this, so `peer` is
    /// the transport's attested sender.
    pub(crate) async fn receive(
        &self,
        peer: PeerId,
        mut send: SendStream,
        mut recv: RecvStream,
        prefix: Vec<u8>,
    ) -> Result<(), TransferError> {
        // A stream that carried nothing has no frame to answer.
        if prefix.is_empty() {
            return Ok(());
        }
        // An offer this build can see is broken — a body past the cap, a stream that ended before
        // the body its header states, a budget it did not finish inside, an empty name, a
        // zero-length file — is answered, so the sender learns its offer was not understood
        // instead of asking again for ever.
        let mut words = Words::new(&mut recv, prefix);
        let offered = match read_frame(
            &*self.runtime,
            &mut words,
            wire::OFFER_MAGIC,
            wire::HEADER_BYTES,
            wire::OFFER_CAP,
            TRANSFER_ANSWER_BUDGET,
        )
        .await
        {
            Frame::Whole(frame) => wire::decode_offer(&frame).filter(|offer| offer.length > 0),
            Frame::Quiet | Frame::Gone | Frame::Broken => None,
        };
        let Some(offer) = offered else {
            answer(&*self.runtime, send, &TransferAnswer::Malformed).await;
            return Ok(());
        };
        // Taken after the frame is read, not before: reading it is the longest wait here, and a
        // moment that went stale during it would date the act, the start window and the right's
        // term to a time before the offer had even arrived.
        let now = self.moment.now();
        self.expire(now);
        let key = (peer, offer.name.clone());
        // One stream per name: the claim, the decision and the place are taken in one stretch with
        // no await in it, so two offers of one name arriving together are answered by one of them
        // and refused as `running` by the other instead of both being authorised to write the sink
        // at the same offsets.
        let Some(_claim) = self.claim(key.clone()) else {
            // How far the transfer holding the name has got. Only an authorised transfer has an
            // entry, so this tells the sender nothing it did not send.
            let have = self
                .remembered()
                .get(&key)
                .map_or(0, |authorised| authorised.state.moved());
            answer(&*self.runtime, send, &TransferAnswer::Running { have }).await;
            return Ok(());
        };
        // A transfer this machine's own person stopped stays stopped: a fresh offer under that
        // name is answered `stopped` rather than authorised again, however long the sender keeps
        // asking, until the wait bound has passed and the name is free. A transfer the *sending*
        // side stopped is not this machine's decision: the name is free, and a sending product
        // that offers the file again gets a fresh transfer.
        if self.stopped(&key) {
            answer(&*self.runtime, send, &TransferAnswer::Stopped).await;
            return Ok(());
        }
        match self.judge(&peer, now, &offer, &key)? {
            Decided::Go(run) => {
                // This machine's running place for the peer and the record of the transfer are one
                // decision, taken before the first byte moves: two offers arriving together cannot
                // both take the last place. A resume is already holding one, so it does not ask
                // again.
                if !self.occupy(&key, &offer, &run, now) {
                    answer(
                        &*self.runtime,
                        send,
                        &TransferAnswer::Limit {
                            which: TransferLimit::Transfers,
                            retry_after: None,
                        },
                    )
                    .await;
                    return Ok(());
                }
                // Recorded before the first byte moves, on the log's part for peer-driven acts:
                // a name that turns out complete or in conflict was not a transfer and leaves no
                // entry, and a resume is the same transfer, recorded once. A log that cannot
                // take the entry means the transfer is not run, and the sender is told so.
                if !run.resumed
                    && let Err(error) = self.record(&run.pair, &run.right, &offer, now)
                {
                    self.forget(&key);
                    answer(&*self.runtime, send, &TransferAnswer::NotRecorded).await;
                    return match error {
                        AuditError::NoRoom { .. } => Ok(()),
                        other => Err(TransferError::Audit(other)),
                    };
                }
                let have = run.have;
                // The resume leaves the stream open: the bytes and the verdict follow on it.
                if !stream::write_whole(
                    &*self.runtime,
                    &mut send,
                    &wire::encode_answer(&TransferAnswer::Resume { have }),
                    TRANSFER_ANSWER_BUDGET,
                )
                .await
                {
                    return Ok(());
                }
                let sink = self
                    .sink
                    .clone()
                    .expect("the floor refuses file ingress when the product has no sink");
                if let Some(verdict) = self
                    .read_bytes(&offer, &*sink, &mut send, &mut recv, have, &key)
                    .await
                {
                    answer(&*self.runtime, send, &verdict).await;
                }
                Ok(())
            }
            Decided::Answered {
                under,
                answer: owed,
            } => {
                answer(&*self.runtime, send, &owed).await;
                if let Some((pair, right)) = under {
                    let state = state_of(&owed, offer.length);
                    self.remember(&key, pair, right, &offer, state, now);
                }
                Ok(())
            }
            Decided::Nothing => Ok(()),
        }
    }

    /// Judge one offer: whether a transfer runs, and from where.
    ///
    /// The order is the start limit, the running limit, the right, the host's floor (which is
    /// also where a product with no sink is refused), then what the sink already holds — stated
    /// only after the transfer is authorised. A resume asks only whether the pair this transfer
    /// was authorised under is still this machine's pair: a machine moved to another assistant
    /// leaves that pair, so the transfer ends here rather than continuing under a pair that
    /// inherits nothing.
    ///
    /// The running limit is counted here for the order of the answers, and again under the
    /// record's own lock in [`Self::occupy`], which is what makes it hold when two offers arrive
    /// together.
    fn judge(
        &self,
        peer: &PeerId,
        now: Timestamp,
        offer: &wire::Offer,
        key: &(PeerId, TransferName),
    ) -> Result<Decided, TransferError> {
        // A transfer that resumes after a reconnect is the same transfer: the decision stands,
        // and only the binding is asked again. One that is over is not a resume — a failed or
        // refused transfer leaves the name free for a fresh decision.
        let remembered = self.remembered().get(key).cloned().filter(|authorised| {
            authorised.running()
                && authorised.length == offer.length
                && authorised.digest == offer.digest
        });
        let resumed = remembered.is_some();
        let (pair, right) = if let Some(authorised) = remembered {
            if self.same_pair(peer, &authorised.pair)? {
                (authorised.pair, authorised.right)
            } else {
                self.update(
                    key,
                    TransferState::Failed {
                        failure: TransferFailure::Refused { step: Step::Right },
                    },
                );
                return Ok(Decided::Answered {
                    under: None,
                    answer: TransferAnswer::Refused { step: Step::Right },
                });
            }
        } else {
            if let Some(retry_after) =
                self.windows
                    .admit(peer, now, TRANSFER_START_WINDOW, MAX_TRANSFER_STARTS)
            {
                return Ok(Decided::Answered {
                    under: None,
                    answer: TransferAnswer::Limit {
                        which: TransferLimit::Starts,
                        retry_after: Some(retry_after),
                    },
                });
            }
            // The peer's *other* running transfers: a running entry under this very name is what
            // this decision replaces, and an offer of different content under it is a conflict
            // rather than a third transfer.
            if Self::running_elsewhere(&self.remembered(), key) >= MAX_RUNNING_TRANSFERS {
                return Ok(Decided::Answered {
                    under: None,
                    answer: TransferAnswer::Limit {
                        which: TransferLimit::Transfers,
                        retry_after: None,
                    },
                });
            }
            match self.rights.may_take_file(peer, &*self.floor, now)? {
                Admission::Allowed { pair, right, .. } => (pair, right),
                // Neither a binding nor a claim has arrived, so there is no pair to name yet:
                // the sender is told nothing and asks again, as the message and action layers
                // leave it. The claim is released, so the next offer is a fresh one and not a
                // second stream on a name already being answered.
                Admission::Unbound => return Ok(Decided::Nothing),
                Admission::Refused(refusal) => {
                    return Ok(Decided::Answered {
                        under: None,
                        answer: TransferAnswer::Refused {
                            step: refusal.step(),
                        },
                    });
                }
            }
        };
        // A product with nowhere to put the bytes is refused at the floor, which this layer's
        // own floor does — so the refusal is recorded like any other and the crate never reads
        // the product's configuration as a rights fact. That is also why a sink is here: the
        // decision above has already passed the floor, and a resume was authorised by a machine
        // that had one.
        let sink = self
            .sink
            .clone()
            .expect("the floor refuses file ingress when the product has no sink");
        let held = sink.held(peer, &offer.name);
        // What the sink holds decides the answer, and the order is the point: more bytes than
        // the file has is an offer this build cannot believe; a name held toward another digest,
        // or with bytes and nothing to vouch for them, is a conflict and never appended to;
        // every byte toward this digest is the one case where only the sink can say whether it
        // arrived; and anything less is a resume from where it stopped. A file of no bytes never
        // reaches here: the offer is refused before it is decoded.
        let reply = if held.bytes > offer.length {
            TransferAnswer::Malformed
        } else if held.toward.is_some_and(|toward| toward != offer.digest)
            || (held.toward.is_none() && held.bytes > 0)
        {
            TransferAnswer::Conflict
        } else if held.bytes < offer.length {
            TransferAnswer::Resume { have: held.bytes }
        } else {
            match sink.assembled(peer, &offer.name) {
                Some(digest) if digest == offer.digest => TransferAnswer::AlreadyComplete,
                Some(_) => TransferAnswer::DigestMismatch,
                // The sink holds every byte and cannot say what it assembled. The crate has no
                // evidence either way and must not accuse the bytes: "the receiver could not
                // store it" is the class that keeps the two apart.
                None => TransferAnswer::StoreFailed,
            }
        };
        Ok(match reply {
            TransferAnswer::Resume { have } => Decided::Go(Run {
                pair,
                right,
                have,
                resumed,
            }),
            answer => Decided::Answered {
                under: Some((pair, right)),
                answer,
            },
        })
    }

    fn record(
        &self,
        pair: &Pair,
        right: &Right,
        offer: &wire::Offer,
        now: Timestamp,
    ) -> Result<(), AuditError> {
        self.rights.audit().append(&Entry {
            at: now,
            act: Act::TransferAllowed {
                pair: pair.clone(),
                capability: right.capability(),
                name: offer.name.as_bytes().to_vec(),
                length: offer.length,
                digest: *offer.digest.as_bytes(),
                issuer: right.issuer().clone(),
                expires_at: right.expires_at(),
            },
        })
    }

    /// Remember one transfer under its name, as the state it is in.
    ///
    /// For a state that is not a running one: an offer answered as a conflict, already complete,
    /// a digest mismatch or a store failure is remembered so the product can see why it did not
    /// land, and it holds none of this machine's places for the peer.
    fn remember(
        &self,
        key: &(PeerId, TransferName),
        pair: Pair,
        right: Right,
        offer: &wire::Offer,
        state: TransferState,
        now: Timestamp,
    ) {
        self.remembered().insert(
            key.clone(),
            Authorised {
                pair,
                right,
                length: offer.length,
                digest: offer.digest,
                seen: now,
                state,
                stopped_here: false,
            },
        );
    }

    /// How many transfers `key`'s peer has running under *other* names — the ones an offer of
    /// `key` would be a third alongside. The entry under `key` is not counted, because a new
    /// decision replaces it.
    fn running_elsewhere(
        remembered: &BTreeMap<(PeerId, TransferName), Authorised>,
        key: &(PeerId, TransferName),
    ) -> usize {
        remembered
            .iter()
            .filter(|((peer, name), authorised)| {
                *peer == key.0 && *name != key.1 && authorised.running()
            })
            .count()
    }

    /// Take one of this machine's running places for the peer — or, for a resume, keep the one the
    /// transfer already holds — and record it as running from `have`.
    fn occupy(
        &self,
        key: &(PeerId, TransferName),
        offer: &wire::Offer,
        run: &Run,
        now: Timestamp,
    ) -> bool {
        let mut remembered = self.remembered();
        let running = Self::running_elsewhere(&remembered, key);
        if !run.resumed && running >= MAX_RUNNING_TRANSFERS {
            return false;
        }
        remembered.insert(
            key.clone(),
            Authorised {
                pair: run.pair.clone(),
                right: run.right.clone(),
                length: offer.length,
                digest: offer.digest,
                seen: now,
                state: TransferState::Running {
                    moved: run.have,
                    of: offer.length,
                },
                stopped_here: false,
            },
        );
        true
    }

    /// Forget one transfer under its name: the decision to run it was withdrawn before its first
    /// byte moved.
    fn forget(&self, key: &(PeerId, TransferName)) {
        self.remembered().remove(key);
    }

    /// Read the file's bytes into the sink, and answer the verdict the sender is owed.
    ///
    /// `None` is no answer at all: the sending side stopped it, or the connection went away and
    /// the transfer is waiting for the pair — in both cases the sender already knows or will
    /// ask again.
    #[expect(
        clippy::too_many_lines,
        reason = "one chunk's life is the order: the stop, the read, the sink's three answers, the progress word and the one last look at the stream, each with the bound that ends it"
    )]
    async fn read_bytes(
        &self,
        offer: &wire::Offer,
        sink: &(dyn Sink + Send + Sync),
        send: &mut SendStream,
        recv: &mut RecvStream,
        have: u64,
        key: &(PeerId, TransferName),
    ) -> Option<TransferAnswer> {
        let mut offset = have;
        let mut buffer = vec![0u8; TRANSFER_CHUNK];
        let mut last = self.runtime.now();
        // When this machine last told the sending side how far the file has got. A sender parked
        // at the transport's window edge, or with its own source answering "not now", has nothing
        // else to go on: the offset stated here is the only thing that moves its stall clock.
        let mut stated = last;
        while offset < offer.length {
            // A product that stopped this transfer is answered at its next chunk, not at the
            // end of the file. The entry already says `stopped`, so nothing is recorded here.
            if self.stopped(key) {
                return Some(TransferAnswer::Stopped);
            }
            let room = usize::try_from(offer.length - offset)
                .unwrap_or(TRANSFER_CHUNK)
                .min(TRANSFER_CHUNK);
            let read = timeout(
                &*self.runtime,
                TRANSFER_STALL,
                recv.read(&mut buffer[..room]),
            )
            .await;
            let count = match read {
                Some(Ok(Some(count))) if count > 0 => count,
                // The sending side reset with the stop code: its own person stopped it.
                Some(Err(ReadError::Reset(code)))
                    if code == VarInt::from_u32(TRANSFER_STOP_CODE) =>
                {
                    self.update(key, TransferState::Stopped);
                    return None;
                }
                // The sending side's source failed and it dropped the stream, or it finished
                // short: the transfer did not arrive, and the connection is not what stopped
                // it.
                Some(Ok(_) | Err(ReadError::Reset(_))) => {
                    self.update(
                        key,
                        TransferState::Failed {
                            failure: TransferFailure::SourceUnreadable,
                        },
                    );
                    return None;
                }
                // The connection went away: the transfer waits for the pair.
                Some(Err(_)) => {
                    self.update(key, TransferState::Waiting);
                    return None;
                }
                // A live connection that moved nothing for the bound: the transfer stopped
                // moving bytes, which is not the same as waiting for the pair.
                None => {
                    self.update(
                        key,
                        TransferState::Failed {
                            failure: TransferFailure::NoProgress,
                        },
                    );
                    return None;
                }
            };
            let mut waited = false;
            loop {
                // A product that stopped this transfer is answered at its next chunk — or at
                // its next look, when its sink is the thing answering "not now" — and not at
                // the end of the file. The entry already says `stopped`, so nothing is
                // recorded here.
                if self.stopped(key) {
                    return Some(TransferAnswer::Stopped);
                }
                match sink.write(&key.0, &offer.name, &offer.digest, offset, &buffer[..count]) {
                    Stored::Accepted => break,
                    Stored::NotNow => {
                        waited = true;
                        if self.runtime.now().duration_since(last) >= TRANSFER_STALL {
                            // The sink has answered "not now" for the whole stall bound. Before
                            // calling that a store failure, look at the stream once more: a stop
                            // from the sending side is a reset, and a reset is only visible by
                            // reading.
                            if let Some(state) =
                                last_look(&*self.runtime, recv, &mut buffer[..count]).await
                            {
                                self.update(key, state);
                                return None;
                            }
                            self.update(
                                key,
                                TransferState::Failed {
                                    failure: TransferFailure::StoreFailed,
                                },
                            );
                            return Some(TransferAnswer::StoreFailed);
                        }
                        sleep(&*self.runtime, TRANSFER_POLL).await;
                    }
                    // Only the class travels; the product's own reason stays where it is
                    // known.
                    Stored::Refused => {
                        self.update(
                            key,
                            TransferState::Failed {
                                failure: TransferFailure::StoreFailed,
                            },
                        );
                        return Some(TransferAnswer::StoreFailed);
                    }
                }
            }
            offset += u64::try_from(count).expect("a chunk is far below a u64");
            last = self.runtime.now();
            self.update(
                key,
                TransferState::Running {
                    moved: offset,
                    of: offer.length,
                },
            );
            // Tell the sending side how far the file has got: after a chunk its sink made this
            // machine wait for, and at least once a poll while the file keeps getting further.
            // The first is the one time the sender is provably parked with nothing to show for
            // itself; the second is what tells a sender whose own source is slow, or whose write
            // is briefly parked, that the file is still arriving rather than stopped. The word
            // goes whole or not at all: a half-written one would sit in front of the verdict on
            // this stream and be read as the verdict, so a stream that cannot take it whole is
            // broken, and the attempt with it — the sender asks again and this machine states
            // this offset then.
            if waited || self.runtime.now().duration_since(stated) >= TRANSFER_POLL {
                let word = wire::encode_answer(&TransferAnswer::Running { have: offset });
                if !stream::write_whole(&*self.runtime, send, &word, TRANSFER_POLL).await {
                    // A stream that cannot take the word whole is a stream this attempt cannot
                    // go on in, and the sending side is not reading this half any more — so the
                    // attempt is over. Whether the transfer is, the stream says: a reset is only
                    // visible by reading, and a sending side that stopped shows itself there.
                    let _ = send.reset(VarInt::from_u32(TRANSFER_BROKEN_CODE));
                    let state = last_look(&*self.runtime, recv, &mut buffer[..count])
                        .await
                        .unwrap_or(TransferState::Waiting);
                    self.update(key, state);
                    return None;
                }
                stated = self.runtime.now();
            }
        }
        // Only the receiving machine holds the bytes, so only its sink can say what it
        // assembled. A sink that cannot answer is not a digest mismatch — the crate has no
        // evidence either way — and the class for "the receiver could not store it" is the
        // one that keeps them apart.
        let verdict = match sink.assembled(&key.0, &offer.name) {
            Some(digest) if digest == offer.digest => TransferAnswer::Complete,
            Some(_) => TransferAnswer::DigestMismatch,
            None => TransferAnswer::StoreFailed,
        };
        self.update(key, state_of(&verdict, offer.length));
        Some(verdict)
    }

    /// Whether this machine's own person stopped the transfer under `key`.
    fn stopped(&self, key: &(PeerId, TransferName)) -> bool {
        self.remembered()
            .get(key)
            .is_some_and(|authorised| authorised.stopped_here)
    }

    fn update(&self, key: &(PeerId, TransferName), state: TransferState) {
        let now = self.moment.now();
        if let Some(authorised) = self.remembered().get_mut(key) {
            // A transfer this machine's person stopped stays stopped: the chunk that was
            // already on the wire when the stop was made does not restart it, and the sender
            // is answered `stopped` at the next look. A transfer the *sending* side stopped is
            // recorded as stopped too, but it is not this machine's decision and does not hold
            // the name.
            if !authorised.stopped_here {
                authorised.state = state;
            }
            authorised.seen = now;
        }
    }

    /// Whether the pair this transfer was authorised under is still this machine's pair.
    fn same_pair(&self, peer: &PeerId, pair: &Pair) -> Result<bool, TransferError> {
        let Some(record) = self.rights.records().reread(peer)? else {
            return Ok(false);
        };
        let current = record
            .binding()
            .map(|binding| Pair::of_binding(*peer, binding))
            .or_else(|| record.claim().map(|claim| Pair::of_claim(&claim)));
        Ok(current.as_ref() == Some(pair))
    }
}

/// How long has passed between two moments.
fn elapsed(now: Timestamp, earlier: Timestamp) -> Duration {
    Duration::from_secs(now.unix_seconds().saturating_sub(earlier.unix_seconds()))
}

/// The delay a start limit names, when the answer is one.
fn throttle_of(answer: &TransferAnswer) -> Option<Duration> {
    match *answer {
        TransferAnswer::Limit {
            which: TransferLimit::Starts,
            retry_after,
        } => Some(
            retry_after
                .unwrap_or(TRANSFER_POLL)
                .clamp(TRANSFER_POLL, TRANSFER_THROTTLE_CAP),
        ),
        _ => None,
    }
}

/// What an answer leaves the transfer in.
fn state_of(answer: &TransferAnswer, length: u64) -> TransferState {
    match answer {
        TransferAnswer::Complete | TransferAnswer::AlreadyComplete => {
            TransferState::Finished { bytes: length }
        }
        other => TransferState::Failed {
            failure: failure_of(other),
        },
    }
}

/// The failure an answer means.
fn failure_of(answer: &TransferAnswer) -> TransferFailure {
    match answer {
        TransferAnswer::Refused { step } => TransferFailure::Refused { step: *step },
        TransferAnswer::NotRecorded => TransferFailure::NotRecorded,
        // A limit on running transfers, which is terminal and never carries a delay: the wire
        // drops one beside it, and a start limit is a throttle taken by [`throttle_of`] before
        // this is asked.
        TransferAnswer::Limit { which, retry_after } => TransferFailure::Limit {
            which: *which,
            retry_after: *retry_after,
        },
        TransferAnswer::Running { .. } => TransferFailure::AlreadyRunning,
        TransferAnswer::Conflict => TransferFailure::Conflict,
        TransferAnswer::DigestMismatch => TransferFailure::DigestMismatch,
        TransferAnswer::StoreFailed => TransferFailure::StoreFailed,
        TransferAnswer::Stopped => TransferFailure::StoppedByReceiver,
        // The offer arrived and could not be read: its own answer, not a peer that does not
        // know transfers.
        TransferAnswer::Malformed => TransferFailure::Malformed,
        // The receiver's `complete` is the only success, and a `resume` is not an end.
        TransferAnswer::Complete
        | TransferAnswer::AlreadyComplete
        | TransferAnswer::Resume { .. } => TransferFailure::NotUnderstood,
    }
}

/// The one look at the stream a receiver takes before calling a sink's "not now" a store
/// failure.
///
/// A stop from the sending side is a reset, and a reset is only visible by reading: a sink that
/// has answered "not now" for the whole stall bound leaves this the one place the sending side's
/// word can still arrive. `Some(state)` is the transfer ending here with what the stream said;
/// `None` is nothing that ends it, so the store's own failure stands — including a stream that
/// ended cleanly, because a sending side that finished writing while this machine could not
/// store the last chunk is this machine's failure and not the peer's source.
async fn last_look(
    runtime: &dyn Runtime,
    recv: &mut RecvStream,
    buffer: &mut [u8],
) -> Option<TransferState> {
    match timeout(runtime, TRANSFER_POLL, recv.read(buffer)).await {
        Some(Err(ReadError::Reset(code))) if code == VarInt::from_u32(TRANSFER_STOP_CODE) => {
            Some(TransferState::Stopped)
        }
        // Any other reset: the sending side's source failed and it dropped the stream, which is
        // its own answer and not this machine's store.
        Some(Err(ReadError::Reset(_))) => Some(TransferState::Failed {
            failure: TransferFailure::SourceUnreadable,
        }),
        // The connection went away: the transfer waits for the pair.
        Some(Err(_)) => Some(TransferState::Waiting),
        // Nothing arrived inside the poll, more of the file did, or the stream ended cleanly:
        // none of those ends the transfer, so this machine's own store is what does — and it is
        // answered, not left without a word. Bytes still arriving are the sending side's, and
        // the store's failure stands with them.
        Some(Ok(Some(_) | None)) | None => None,
    }
}

/// Write one answer frame and finish the stream: the last word of one attempt.
async fn answer(runtime: &dyn Runtime, send: SendStream, answer: &TransferAnswer) {
    stream::write_reply(
        runtime,
        send,
        &wire::encode_answer(answer),
        TRANSFER_ANSWER_BUDGET,
    )
    .await;
}

/// Read one whole frame, its magic first: the bytes an earlier look left, then the body its
/// header states.
///
/// `magic` is the frame's own opening — an answer's is longer than an offer's, so the reader
/// cannot assume the shorter one — `header` is its magic, version and length, and `cap` the
/// largest body it may carry. What comes back says where the frame got to: [`Frame::Whole`] is
/// one this build may read, [`Frame::Broken`] is a body past `cap` or bytes that do not open
/// with `magic` at all, and [`Frame::Quiet`] and [`Frame::Gone`] are a frame still arriving and a
/// stream that ended inside one. Unlike a message, a transfer's stream carries raw file bytes
/// after the frame, so the frame's own length — not the stream's end — says where it stops.
///
/// The budget covers the whole frame, not one read: a peer that dribbles a byte at a time holds
/// this stream — one of the sixteen the pair's messages and actions share — for the budget and
/// not for a budget per byte.
async fn read_frame(
    runtime: &dyn Runtime,
    words: &mut Words<'_>,
    magic: &[u8],
    header: usize,
    cap: usize,
    budget: Duration,
) -> Frame {
    let started = runtime.now();
    let left = || budget.saturating_sub(runtime.now().duration_since(started));
    let recv = &mut *words.recv;
    let partial = &mut words.partial;
    // The magic first: it is what tells this frame from another vocabulary, and it is shorter
    // than the header.
    let mut ended = stream::read_upto(runtime, recv, partial, magic.len(), left()).await;
    if !wire::is_open_magic(magic, partial) {
        return Frame::Broken;
    }
    if partial.len() < magic.len() {
        return if ended { Frame::Gone } else { Frame::Quiet };
    }
    ended = stream::read_upto(runtime, recv, partial, header, left()).await;
    if partial.len() < header {
        return if ended { Frame::Gone } else { Frame::Quiet };
    }
    let Some(body) = wire::body_length(partial, header) else {
        return Frame::Broken;
    };
    if body > cap {
        return Frame::Broken;
    }
    let total = header + body;
    ended = stream::read_upto(runtime, recv, partial, total, left()).await;
    if partial.len() < total {
        return if ended { Frame::Gone } else { Frame::Quiet };
    }
    Frame::Whole(std::mem::take(partial))
}
