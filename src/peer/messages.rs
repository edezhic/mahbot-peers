//! A message one machine composes for another, and what happens to it on the way.
//!
//! # What a message is
//!
//! A message is a body and an envelope. The body is opaque bytes: this layer never
//! reads one, never parses one, and never turns one into anything. It is stored as it
//! was written and handed over as it was written, and no path leads from a body to a
//! capability — the decision is about the peer, never about what it sent.
//!
//! The envelope names the message and orders it: a 16-byte identifier minted once at
//! the sender, a count that starts at one for the first message to a peer and grows by
//! one for each after it, and the moment the caller says the message was composed. The
//! count is what lets a receiver say how many it missed; the identifier is what lets it
//! say which ones it already took.
//!
//! # Authorship is the connection's
//!
//! A message carries no author. The author is the peer the handshake proved, taken from
//! the connection and never from the bytes: [`Delivery::sender`] is the transport's
//! attested peer, and a frame cannot claim to be from someone else because nothing in it
//! names anyone.
//!
//! # The queue is durable, and the offer is best effort
//!
//! [`Messages::send`] writes the message into this machine's queue for that peer before
//! it returns, so a crash between composing and sending loses nothing. The offer is made
//! over the pair's live direct connection, one bidirectional stream per offer, bounded by
//! [`MESSAGE_BUDGET`], and repeated by `Messages::offer_loop` — run inside
//! [`crate::peer::inbox::Inbox::serve`] — until the receiver answers or the message expires:
//! a connection that drops mid-offer costs a retry, not the message.
//!
//! # At least once, and what "already taken" means
//!
//! The store hands a message to [`Deliveries::deliver`] before it records the identifier,
//! so a caller that stores durably inside that call never loses one; a crash between the
//! call and the record — or another writer holding the queue at that instant — delivers it
//! again, which is what "at least once" means, and the identifier is what a caller
//! deduplicates on. A caller that cannot store answers `false` and the message is offered
//! again, so the answer is never taken on trust.
//!
//! Only a remembered identifier suppresses a message. One this machine took before is
//! answered [`Answer::AlreadyTaken`]: by the peer's own account the message reached a caller,
//! so the sender drops its copy and records nothing. Every other identifier is delivered,
//! whatever its count. The count orders and declares, and it never destroys: a count above
//! the next expected one arrives with [`Gap::Missing`] saying how many are missing, and a
//! count that does not move forward — a sender whose queue was lost or restored, or a retry
//! of a message whose identifier this machine has forgotten — arrives with [`Gap::Rewound`],
//! because that count was used before and nothing is missing. Neither is a promise to find
//! anything; both are declarations the caller can act on.
//!
//! # What a refusal says, and what it does not
//!
//! A refusal on the wire is a class and not a sentence: [`Answer::Refused`] says the
//! receiver's rights refused this message and nothing more. The receiver's words stay on
//! the receiver — the host's floor is local policy — and nothing a peer sends is written
//! into the log: the entry a sender writes when its message is refused or unreadable is
//! this crate's own phrase.
//!
//! # Retention and throttling
//!
//! A queued message is dropped once [`MESSAGE_RETENTION`] has passed since it was queued,
//! and the drop is recorded. The taken identifiers are kept for [`TAKEN_RETENTION`] so a
//! slow retry is still recognised as one this machine took, and the oldest beyond `MAX_TAKEN`
//! are forgotten first. A queue holds at most [`MAX_QUEUE`] messages: a full queue refuses a
//! new message rather than dropping an old one, because only the caller knows which
//! message matters.
//!
//! A receiver throttles: it takes at most [`MAX_OFFERS_PER_WINDOW`] offers from one peer
//! per [`MESSAGE_WINDOW`], and answers the rest with [`Answer::Throttled`] and the delay
//! until the window turns. The sender remembers the delay, clamped to one
//! [`MESSAGE_WINDOW`] when it is applied — a peer that names a century is not believed —
//! and waits it out, so a flooding peer is slowed without its connection being closed and
//! without the receiver doing work it can avoid. The window is in memory only: a restart
//! forgets it, which costs at most one window's worth of offers. A refusal a peer does
//! cause is written in the log's part for peer-driven acts, which stops at its reserve, so
//! a flood cannot take the room a person's own acts need.
//!
//! # What it is not
//!
//! There is no product layer here: what a message means is the product's, and the screen is
//! nowhere in this crate. A message is not a file: a whole file is its own thing on the same
//! connection, [`crate::peer::transfer`], with its own stream, its own decision and its own
//! answer set, and the one reader that tells a message from an action from a transfer on the
//! pair's connection is [`crate::peer::inbox`]. The at-most-once command is
//! [`crate::peer::actions`].
//!
//! # The files
//!
//! One file per peer under `messages/`, named by the 64 lowercase hex characters of the
//! peer's key, private to the account the product runs as, and written by the same atomic
//! publish as the record. The private `store` module states the format. A
//! read-modify-publish holds this process's writer and that peer's lock file for the whole
//! of itself, so the self-update window's second process on a root cannot lose a message
//! this one just queued: the record merges, the log appends, and a queue and an action
//! memory are the files that need the lock. The lock file is per peer, so two processes
//! writing two peers never wait for each other; this process writes one queue at a time. The
//! delivery sink runs with no lock held, so a slow caller delays that peer's later messages
//! and nothing else. All file work is blocking, like the rest of this crate's storage: a
//! caller runs it where blocking is allowed.

mod store;
mod wire;

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use quinn::{Connection, Endpoint, RecvStream, Runtime, SendStream};

use crate::beacon::{sleep, timeout};
use crate::hex;
use crate::identity::PeerId;
use crate::identity::access::Insecurity;
use crate::peer::audit::{Act, AuditError, AuditLog, DropReason, Dropped, Entry, RefusedReason};
use crate::peer::connect::{Connections, TRUST_POLL, Traffic};
use crate::peer::messages::store::{MessageStore, Outcome};
use crate::peer::moment::Moment;
use crate::peer::record::{RecordError, RecordStore, Timestamp, Untrusted};
use crate::peer::recovery::ConnectFailure;
use crate::peer::rights::{Admission, Floor, Refusal, Rights, RightsError, Writing};
use crate::peer::stream::{self, ReadFault};
use crate::peer::sweep::Due;
use crate::peer::window::Windows;

/// The most bytes one message body may have.
pub const MAX_BODY_BYTES: usize = 4096;

/// The bytes in an envelope's identifier.
pub(crate) const ENVELOPE_ID_BYTES: usize = 16;

/// How many messages one peer's queue may hold.
pub const MAX_QUEUE: usize = 64;

/// How many taken identifiers one peer's queue remembers.
pub(crate) const MAX_TAKEN: usize = 2048;

/// The most bytes one peer's queue file may have.
///
/// A queue at [`MAX_QUEUE`] with full bodies, plus the taken identifiers, sits under this;
/// the cap keeps a hostile file from being read into memory and refuses a write that would
/// produce a file this build could not read back. It is the format's own number, so it is
/// named here and not re-exported at `peer`, as the record's and the log's caps are not.
pub const MAX_MESSAGES_BYTES: u64 = 512 * 1024;

/// How long a queued message waits before it is dropped.
pub const MESSAGE_RETENTION: Duration = Duration::from_hours(72);

/// How long a taken identifier is remembered, so a slow retry is still answered as one this
/// machine took. Past it the same message can be delivered again, which is the honest cost of
/// remembering by identifier and nothing else.
pub const TAKEN_RETENTION: Duration = Duration::from_hours(7 * 24);

/// The window a receiver counts one peer's offers in.
pub const MESSAGE_WINDOW: Duration = Duration::from_secs(60);

/// How many offers one peer may make per [`MESSAGE_WINDOW`].
pub const MAX_OFFERS_PER_WINDOW: u32 = 30;

/// How long the service waits between rounds when there is nothing to offer.
pub(crate) const MESSAGE_POLL: Duration = Duration::from_secs(1);

/// How long one offer and its answer may take, measured by the injected runtime.
pub const MESSAGE_BUDGET: Duration = Duration::from_secs(10);

/// The most bytes one message may occupy on the wire.
pub(crate) const MAX_MESSAGE_BYTES: usize = MAX_BODY_BYTES + 256;

/// How many bytes of an answer this build reads.
///
/// An answer is 30 bytes at most — its 18-byte magic, a version, a status and at most one
/// delay — and the set grows by appending, so the cap leaves room for a field a newer build
/// adds. An answer longer than this is not read whole, which is no answer at all: the sender
/// keeps the message and offers it again rather than trusting a frame it could not read.
const ANSWER_WIRE_BYTES: usize = 256;

/// The name of an envelope: 16 bytes, minted once at the sender.
///
/// The identifier is what a receiver deduplicates on. It is not a key and proves nothing:
/// it is a name, and the author is the connection's attested peer.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EnvelopeId([u8; ENVELOPE_ID_BYTES]);

impl EnvelopeId {
    /// Read an identifier from its bytes.
    #[must_use]
    pub(crate) const fn from_bytes(bytes: [u8; ENVELOPE_ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// The identifier's bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ENVELOPE_ID_BYTES] {
        &self.0
    }
}

impl fmt::Display for EnvelopeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::write(f, &self.0)
    }
}

impl fmt::Debug for EnvelopeId {
    /// The identifier's one spelling, not a second one.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// What names and orders one message, without its body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Envelope {
    id: EnvelopeId,
    count: u64,
    composed_at: Timestamp,
}

impl Envelope {
    /// The message's identifier.
    #[must_use]
    pub const fn id(&self) -> EnvelopeId {
        self.id
    }

    /// The message's count: one for the first message to this peer, then one more each.
    #[must_use]
    pub const fn count(&self) -> u64 {
        self.count
    }

    /// The moment the caller says the message was composed.
    #[must_use]
    pub const fn composed_at(&self) -> Timestamp {
        self.composed_at
    }
}

/// One message as it travels: the envelope and the body.
#[derive(Clone, PartialEq, Eq)]
pub struct Message {
    envelope: Envelope,
    body: Vec<u8>,
}

impl Message {
    /// Compose a message from an envelope and a body.
    ///
    /// # Errors
    ///
    /// [`MessageError::Body`] when the body is longer than [`MAX_BODY_BYTES`].
    pub fn new(envelope: Envelope, body: impl Into<Vec<u8>>) -> Result<Self, MessageError> {
        let body = body.into();
        if body.len() > MAX_BODY_BYTES {
            return Err(MessageError::Body {
                bytes: body.len(),
                limit: MAX_BODY_BYTES,
            });
        }
        Ok(Self { envelope, body })
    }

    /// The message's envelope.
    #[must_use]
    pub const fn envelope(&self) -> &Envelope {
        &self.envelope
    }

    /// The message's body, exactly as it was composed.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The message's bytes, as the offer carries them.
    ///
    /// # Errors
    ///
    /// [`MessageError::Body`] when the body is longer than [`MAX_BODY_BYTES`], which
    /// [`Self::new`] already refuses; a message read from a file is checked here too.
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        wire::encode_message(self)
    }

    /// One message, from the bytes an offer carried.
    ///
    /// # Errors
    ///
    /// [`MessageError::Frame`], naming what is wrong with the bytes: a frame this build
    /// cannot read, or fields that do not go together.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, MessageError> {
        wire::decode_message(bytes)
    }
}

impl fmt::Debug for Message {
    /// The envelope and the body's length, never the body.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Message")
            .field("id", &self.envelope.id)
            .field("count", &self.envelope.count)
            .field("composed_at", &self.envelope.composed_at)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// The receiver's answer to one offer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// The message was taken: the caller was handed it and its identifier recorded.
    Taken,
    /// The identifier is one this machine took before. The peer is the only one who can say so:
    /// a receiver that answered this and then discarded the message would leave the sender's log
    /// silent about it.
    AlreadyTaken,
    /// The receiver's rights refused it. The class is all the sender is told: why is the
    /// receiver's business, and its words stay there.
    Refused,
    /// Too many offers in the window; wait this long before offering again.
    Throttled {
        /// How long until the receiver's window turns.
        retry_after: Duration,
    },
    /// The receiver could not read the frame.
    Unreadable,
}

impl Answer {
    /// The answer's bytes.
    pub(crate) fn encode(&self) -> Vec<u8> {
        wire::encode_answer(self)
    }

    /// One answer, from the bytes a reply carried.
    ///
    /// Public like the beacon's own wire: a caller reads an answer off the wire, and there is
    /// no builder to hide it behind, because only a receiver composes one.
    ///
    /// # Errors
    ///
    /// [`MessageError::Frame`], naming what is wrong with the bytes: a frame this build
    /// cannot read, a missing status, or one it does not know.
    pub fn decode(bytes: &[u8]) -> Result<Self, MessageError> {
        wire::decode_answer(bytes)
    }
}

/// What the receiver's caller is handed.
#[derive(Clone, PartialEq, Eq)]
pub struct Delivery {
    /// The transport's attested peer: the author, taken from the connection.
    pub sender: PeerId,
    /// What names and orders the message.
    pub envelope: Envelope,
    /// The body, exactly as it was composed.
    pub body: Vec<u8>,
    /// How the sender's count moved before this message, when it did not move by one.
    pub gap: Option<Gap>,
}

impl fmt::Debug for Delivery {
    /// The envelope and the body's length, never the body.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Delivery")
            .field("sender", &self.sender)
            .field("envelope", &self.envelope)
            .field("body_len", &self.body.len())
            .field("gap", &self.gap)
            .finish()
    }
}

/// How the sender's count moved before the message being delivered.
///
/// A declaration, not a promise: the crate says what it saw and leaves the meaning to the
/// product. Neither kind renumbers anything or stops a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gap {
    /// Counts between the last one delivered and this one are missing.
    Missing {
        /// How many counts are missing.
        count: u64,
    },
    /// The count did not move forward: the sender's queue was lost or restored, so it is
    /// minting counts it used before, or this is a retry of a message whose identifier this
    /// machine has already forgotten. Nothing is missing — the count was used before, by a
    /// message this machine may or may not have been handed.
    Rewound,
}

/// Where a taken message goes.
///
/// `deliver` answers whether the message was taken: `true` when the caller has it durably
/// (or has handed it on), `false` when it could not take it — a full disk, a closed root —
/// and the crate offers it again rather than record an identifier for a message nobody
/// kept. It runs with no lock held, so it may take as long as it must; a caller that cannot
/// answer from here hands the delivery to its own task and answers `true`.
pub trait Deliveries: Send + Sync {
    /// Hand one message over, answering whether it was taken.
    fn deliver(&self, delivery: Delivery) -> bool;
}

/// Why a queue is not offering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QueueState {
    /// There is nothing queued for the peer.
    Empty,
    /// There is something queued, but neither a binding nor a claim has arrived.
    WaitingForBinding,
    /// There is something queued, but this machine does not trust the peer.
    Untrusted,
    /// There is something queued, but the pair's "write to me" is not live.
    NoRight {
        /// The decision's refusal.
        refusal: Refusal,
    },
    /// The receiver asked this machine to wait.
    Throttled {
        /// When the wait ends.
        until: Timestamp,
    },
    /// There is something queued and it may be offered now.
    Ready,
}

/// What one sweep did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sweep {
    /// How many queued messages were dropped for having waited too long.
    pub expired: usize,
    /// How many queued messages were dropped because the peer's trust was withdrawn.
    pub withdrawn: usize,
}

/// The message layer of one machine.
///
/// Built once per storage root, like the records and the log: the store it holds names the
/// root's queues, and a second layer over one root shares them rather than copying them.
pub struct Messages {
    rights: Rights,
    floor: Arc<dyn Floor + Send + Sync>,
    moment: Arc<dyn Moment + Send + Sync>,
    deliveries: Arc<dyn Deliveries + Send + Sync>,
    runtime: Arc<dyn Runtime>,
    store: MessageStore,
    /// The sender's view of each receiver's throttle: when it may offer again.
    throttled: Mutex<BTreeMap<PeerId, Timestamp>>,
    /// The receiver's token buckets, one per peer, in memory only.
    windows: Windows,
}

impl fmt::Debug for Messages {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Messages")
            .field("store", &self.store)
            .finish_non_exhaustive()
    }
}

impl Messages {
    /// Open the message layer over `root`.
    ///
    /// The root must exist and is never created: a mistyped or deleted root must fail
    /// loudly, not answer an empty queue that looks like a machine with nothing to say. The
    /// `messages/` directory is created on the first start and held to the key file's rule.
    ///
    /// The records and the log are the caller's handles — build them over the same root —
    /// and the decision is built from them here. The floor, the clock, the delivery sink and
    /// the runtime are injected: this crate has no runtime of its own, and the layer needs one
    /// to measure its waits and to answer a peer through the inbox.
    ///
    /// # Errors
    ///
    /// [`MessageError::RootMissing`] when the root is not a directory, and
    /// [`MessageError::Insecure`] when `messages/` is reachable by another account.
    pub fn open(
        root: &Path,
        records: RecordStore,
        audit: AuditLog,
        floor: Arc<dyn Floor + Send + Sync>,
        moment: Arc<dyn Moment + Send + Sync>,
        deliveries: Arc<dyn Deliveries + Send + Sync>,
        runtime: Arc<dyn Runtime>,
    ) -> Result<Self, MessageError> {
        let store = MessageStore::open(root)?;
        let rights = Rights::new(records, audit);
        Ok(Self {
            rights,
            floor,
            moment,
            deliveries,
            runtime,
            store,
            throttled: Mutex::new(BTreeMap::new()),
            windows: Windows::new(),
        })
    }

    /// Compose a message for `peer` and queue it.
    ///
    /// The record is re-read first: a peer this machine no longer remembers, one whose
    /// trust it withdrew, or a pair closed by three failed comparisons is refused before
    /// anything is written — a message for a closed pair would otherwise wait out its
    /// retention to be dropped. The body's length is checked and nothing else about it. The
    /// message is published to the queue before this returns, so a crash after it costs
    /// nothing.
    ///
    /// # Errors
    ///
    /// [`MessageError::NotPaired`], [`MessageError::Withdrawn`] and [`MessageError::Closed`]
    /// for the record's answer, [`MessageError::Body`] for a body over [`MAX_BODY_BYTES`],
    /// [`MessageError::Full`] for a full queue, and the store's own refusals.
    pub fn send(
        &self,
        peer: &PeerId,
        composed_at: Timestamp,
        body: &[u8],
    ) -> Result<Envelope, MessageError> {
        let limits = self.rights.records().limits();
        let Some(record) = self.rights.records().reread(peer)? else {
            return Err(MessageError::NotPaired { peer: *peer });
        };
        if let Some(why) = record.untrusted(&limits) {
            return Err(why.into());
        }
        if body.len() > MAX_BODY_BYTES {
            return Err(MessageError::Body {
                bytes: body.len(),
                limit: MAX_BODY_BYTES,
            });
        }
        self.store
            .enqueue(peer, composed_at, self.moment.now(), body)
    }

    /// The messages queued for `peer`, oldest first.
    ///
    /// # Errors
    ///
    /// The store's own refusals.
    pub fn pending(&self, peer: &PeerId) -> Result<Vec<Envelope>, MessageError> {
        self.store.pending(peer)
    }

    /// Why the queue for `peer` is, or is not, offering.
    ///
    /// # Errors
    ///
    /// The store's and the record's own refusals.
    pub fn state(&self, peer: &PeerId) -> Result<QueueState, MessageError> {
        // The gate is read before the queue, so a pair this machine may not speak to is
        // answered by the record's word rather than the queue's contents; the queue is still
        // read, because "nothing to say" outranks "not allowed".
        let now = self.moment.now();
        let writing = self.rights.writing(peer, now)?;
        if self.store.pending(peer)?.is_empty() {
            return Ok(QueueState::Empty);
        }
        match writing {
            Writing::Allowed(_) => match self.throttled_until(peer) {
                Some(until) if until > now => Ok(QueueState::Throttled { until }),
                _ => Ok(QueueState::Ready),
            },
            Writing::Unbound => Ok(QueueState::WaitingForBinding),
            Writing::Untrusted => Ok(QueueState::Untrusted),
            Writing::Refused(refusal) => Ok(QueueState::NoRight { refusal }),
        }
    }

    /// Drop what has expired, and what belongs to a peer whose trust is withdrawn.
    ///
    /// Every peer with a queue is visited; a queue that cannot be swept does not stop the
    /// rest, and the first failure is returned at the end — the same shape as the record
    /// store's own start-up sweep. `Messages::offer_loop` sweeps its own peer every
    /// `SWEEP_EVERY` as well, so a product that runs only the services still expires its
    /// queues and still drops a withdrawn pair's; this call is for start-up, and for the
    /// peers no service is running for.
    ///
    /// # Errors
    ///
    /// The first store, record or log refusal, after the rest were swept.
    pub fn sweep(&self) -> Result<Sweep, MessageError> {
        let mut total = Sweep::default();
        let mut first = None;
        for peer in self.store.peers()? {
            match self.sweep_peer(&peer) {
                Ok(sweep) => {
                    total.expired += sweep.expired;
                    total.withdrawn += sweep.withdrawn;
                }
                // Another writer holds that queue this instant: the next sweep has it.
                Err(MessageError::Busy { .. }) => {}
                Err(error) => {
                    if first.is_none() {
                        first = Some(error);
                    }
                }
            }
        }
        first.map_or(Ok(total), Err)
    }

    /// Offer `peer`'s queue over the pair's live connection, one message at a time.
    ///
    /// A round that did not take the head off the queue — nothing to offer, an offer nobody
    /// answered, another writer holding the queue — waits `MESSAGE_POLL` before the next: a peer
    /// that accepts each stream and resets it costs one round a second, not a spin. The queue is
    /// swept every `SWEEP_EVERY`, not every round, because the offer's own gate is re-read each
    /// time and only the drop of an expired message waits for the sweep.
    ///
    /// The first stream a kept connection carries belongs to the binding exchange, so no
    /// offer is made until that exchange has finished: the receiving side would otherwise
    /// take the exchange's stream for a message.
    ///
    /// # Errors
    ///
    /// A queue that cannot be read or written is not a queue with nothing in it: a refusal
    /// this loop's own queue meets, and one its gate's record or log meets, end the service and
    /// are returned to whoever started it. A queue another writer holds this instant is not a
    /// fault: the round waits and tries again.
    pub(crate) async fn offer_loop(
        self: Arc<Self>,
        connections: Arc<Connections>,
        endpoint: &Endpoint,
        peer: PeerId,
    ) -> Result<(), MessageError> {
        let mut swept = Due::default();
        // Whether this waiting spell has already asked for a dial. A message that is waiting
        // asks once — the ask keeps the episode, so a peer that keeps dropping a connection
        // is still bounded by it — and asking again every round would turn the queue's poll
        // into a dial per second. The flag clears when the queue is empty, not when a
        // connection comes and goes: the same waiting message is not news.
        let mut asked = false;
        loop {
            let now = self.moment.now();
            if swept.due(now) {
                match self.sweep_peer(&peer) {
                    Ok(_) | Err(MessageError::Busy { .. }) => {}
                    Err(error) => return Err(error),
                }
            }
            let Some(traffic) = connections.traffic(&peer) else {
                // A message waiting to be delivered is a reason to dial, and the dial is
                // paced by the pair's retry policy: a queue that asks every second does not
                // dial every second and does not open a beacon session per poll. What the
                // poll does cost while the pair is down is this machine's own queue: a full
                // read and decode of the file to learn its head, not the peer's record, which
                // `ensure` asks only when the policy is due.
                let mut wait = MESSAGE_POLL;
                match self.store.head(&peer) {
                    Ok(Some(_)) => {
                        if !asked {
                            connections.hurry(&peer);
                            asked = true;
                        }
                        let (_, refused) = connections.ensure(endpoint, &peer.fingerprint()).await;
                        if matches!(refused, Some(ConnectFailure::NotTrusted { .. })) {
                            // A record that refuses trust is a decision, not a network state:
                            // asking again every round would only re-read the same file. One
                            // round is when a person's restoration could have landed.
                            wait = TRUST_POLL;
                        }
                    }
                    Ok(None) => asked = false,
                    Err(error) => return Err(error),
                }
                sleep(&*self.runtime, wait).await;
                continue;
            };
            if !traffic.exchange_done() {
                sleep(&*self.runtime, MESSAGE_POLL).await;
                continue;
            }
            // The gate before the queue: a pair that may not be spoken to must not pay for
            // reading and decoding its head every round. A gate that cannot be answered is
            // this machine's record or log refusing, which is the same fault class as a
            // queue that cannot be read, so it ends the service like any other.
            let writing = self.rights.writing(&peer, now)?;
            if !matches!(writing, Writing::Allowed(_)) {
                sleep(&*self.runtime, MESSAGE_POLL).await;
                continue;
            }
            if let Some(until) = self.throttled_until(&peer)
                && until > now
            {
                // One round at a time: the throttle is re-checked every round like everything
                // else, so a refusal a stream task meets is surfaced within a round rather
                // than up to a whole window later.
                sleep(&*self.runtime, MESSAGE_POLL).await;
                continue;
            }
            // A read takes no lock — the queue is published by one rename — so this is the
            // queue's own state and not a writer's: nothing to offer means the next round
            // has it, and a queue that cannot be read ends the service.
            let message = match self.store.head(&peer) {
                Ok(Some(message)) => message,
                Ok(None) => {
                    // Nothing is waiting any more, so the next message is news and may ask
                    // for a dial again.
                    asked = false;
                    sleep(&*self.runtime, MESSAGE_POLL).await;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let answer = {
                let _round = traffic.round();
                timeout(
                    &*self.runtime,
                    MESSAGE_BUDGET,
                    offer(traffic.connection(), &message),
                )
                .await
                .flatten()
            };
            let left = self.settle(&peer, &traffic, &message, answer)?;
            // A round that did not take the head off the queue — an offer nobody answered, a
            // throttle, another writer holding the queue — waits a round before the next: a
            // peer that accepts each stream and resets it, or a writer that lets go and takes
            // the queue again, must cost a round a second, not a spin through this machine's
            // queue files.
            if !left {
                sleep(&*self.runtime, MESSAGE_POLL).await;
            }
        }
    }

    /// The directory under `root` that holds the queues.
    ///
    /// Public for the same reason the record's is: a backup or a repair must be able to name
    /// it on a root where opening would fail or create it.
    #[must_use]
    pub fn dir_in(root: &Path) -> PathBuf {
        store::dir_in(root)
    }

    /// The path of `peer`'s queue under `root`.
    ///
    /// Public for the same reason [`Self::dir_in`] is: a caller that must name one queue
    /// without opening the store — a repair, a backup — asks here instead of spelling the name.
    #[must_use]
    pub fn path_for(root: &Path, peer: &PeerId) -> PathBuf {
        store::path_in(&Self::dir_in(root), peer)
    }

    /// The lock file a writer of `peer`'s queue holds, beside the queue itself.
    ///
    /// Public for the reason [`Self::path_for`] is: a backup or a repair must be able to tell
    /// the file a writer locks from the queue it writes — the two are told apart by their
    /// names, and neither is a queue. A second process names it here instead of spelling the
    /// name.
    #[must_use]
    pub fn lock_path_for(root: &Path, peer: &PeerId) -> PathBuf {
        store::lock_in(&Self::dir_in(root), peer)
    }

    /// Sweep one peer's queue, answering what went.
    fn sweep_peer(&self, peer: &PeerId) -> Result<Sweep, MessageError> {
        let now = self.moment.now();
        let withdrawn = self
            .rights
            .records()
            .reread(peer)?
            .is_some_and(|record| record.is_withdrawn());
        let mut sweep = Sweep::default();
        if withdrawn {
            sweep.withdrawn = self.store.drop_queue(peer, |dropped| {
                self.note(now, dropped_act(peer, dropped, DropReason::TrustWithdrawn));
            })?;
            return Ok(sweep);
        }
        sweep.expired = self.store.drop_expired(peer, now, |expired| {
            self.note(now, dropped_act(peer, expired, DropReason::Expired));
        })?;
        self.store.expire_taken(peer, now)?;
        Ok(sweep)
    }

    /// Write down a message this machine dropped or a receiver refused.
    ///
    /// Best effort, and the only entry this layer appends itself — the refusals the decision
    /// records are the rights layer's, written before they are answered. The message is
    /// dropped or refused either way, so a log that will not take the entry must not keep
    /// bodies on disk and must not stop a drop.
    fn note(&self, at: Timestamp, act: Act) {
        let _ = self.rights.audit().append(&Entry { at, act });
    }

    /// Apply one offer's answer to the queue, answering whether the head left it.
    ///
    /// An answer that takes the message off the queue must be able to: a queue that cannot be
    /// written is not a queue that lost the message, so that refusal ends the service rather
    /// than being stepped over. Another writer holding the queue this instant is not that: the
    /// round is told the message is still there and waits before offering it again, and the
    /// answer it meets then is the same class again (or `already taken` when the message had
    /// been taken), so nothing changes and nothing is lost.
    ///
    /// The entry is written before the message leaves, as every act in this crate is. A
    /// removal that another writer held, or a crash in between, therefore repeats the entry on
    /// the next round — and the entry names the message, so a person reading the log can see
    /// that it is the same one. The other order would trade a repeated line for a drop nobody
    /// recorded, which is the wrong way round.
    fn settle(
        &self,
        peer: &PeerId,
        traffic: &Traffic,
        message: &Message,
        answer: Option<Answer>,
    ) -> Result<bool, MessageError> {
        let now = self.moment.now();
        let id = message.envelope().id();
        let count = message.envelope().count();
        let act = match answer {
            // The peer took it: the pair's use, however the frames are counted, because the
            // round's own measurement ends after the answer arrived. An answer that it took
            // this identifier before counts the same way — by the peer's own account the
            // message reached it — so a take whose answer the sender never sees still counts
            // whenever the answer it does see says so. Nothing is recorded for either: the
            // queue's removal is the record.
            Some(Answer::Taken | Answer::AlreadyTaken) => {
                traffic.took();
                None
            }
            Some(Answer::Refused) => Some(refused_act(peer, id, count, RefusedReason::Rights)),
            Some(Answer::Unreadable) => {
                Some(refused_act(peer, id, count, RefusedReason::Unreadable))
            }
            // Nothing left the queue: the peer asked this machine to wait, or the offer went
            // unanswered.
            Some(Answer::Throttled { retry_after }) => {
                let until = now.plus(retry_after.min(MESSAGE_WINDOW));
                self.throttled().insert(*peer, until);
                return Ok(false);
            }
            None => return Ok(false),
        };
        if let Some(act) = act {
            self.note(now, act);
        }
        self.forget(peer, &id)
    }

    /// Take one answered message off the queue, answering whether it left.
    fn forget(&self, peer: &PeerId, id: &EnvelopeId) -> Result<bool, MessageError> {
        match self.store.remove(peer, id) {
            Ok(()) => Ok(true),
            Err(MessageError::Busy { .. }) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Answer one offer.
    ///
    /// `Ok(None)` is no answer at all: the sender keeps its copy and offers again. `Err` is a
    /// record, a queue or a log this machine cannot read or write, which ends the service that
    /// started the receiver rather than looking like a pair that takes nothing.
    fn handle(&self, peer: &PeerId, bytes: &[u8]) -> Result<Option<Answer>, MessageError> {
        let now = self.moment.now();
        let Ok(message) = Message::decode(bytes) else {
            return Ok(Some(Answer::Unreadable));
        };
        match self.rights.may_take_message(peer, &*self.floor, now) {
            Ok(Admission::Allowed { .. }) => {
                // A caller's panic is caught here and nowhere else: unwinding through this
                // task would leave the pair receiving nothing while the service went on
                // looking healthy, which is the one thing this layer must not do silently.
                // The flag is local to this call: `accept` calls the closure at most once,
                // before the read it guards.
                let panicked = Cell::new(false);
                let accepted = self.store.accept(peer, &message, now, |delivery| {
                    let kept =
                        panic::catch_unwind(AssertUnwindSafe(|| self.deliveries.deliver(delivery)));
                    kept.unwrap_or_else(|_| {
                        panicked.set(true);
                        false
                    })
                });
                if panicked.get() {
                    return Err(MessageError::Delivery { peer: *peer });
                }
                match accepted {
                    Ok(Outcome::Accepted) => Ok(Some(Answer::Taken)),
                    Ok(Outcome::AlreadyTaken) => Ok(Some(Answer::AlreadyTaken)),
                    // The caller could not keep it, or the same message is being handed over
                    // right now: no answer at all, so the sender keeps its copy and offers
                    // again. Another writer holding the queue this instant is the same.
                    Ok(Outcome::Declined | Outcome::Busy) | Err(MessageError::Busy { .. }) => {
                        Ok(None)
                    }
                    // The queue cannot be read or written: that is a fault of this machine,
                    // not a state the next offer changes, so it ends the service.
                    Err(error) => Err(error),
                }
            }
            // A refusal is of this message. The sender is told the class, not the words.
            Ok(Admission::Refused(_)) => Ok(Some(Answer::Refused)),
            // No pair to name yet: nothing to say, and the sender offers again rather than
            // losing the message to a state that is about to change.
            Ok(Admission::Unbound) => Ok(None),
            // The record or the log cannot be read: permanent, like any other such refusal.
            Err(error) => Err(error.into()),
        }
    }

    /// When the receiver last asked this machine to wait until.
    fn throttled_until(&self, peer: &PeerId) -> Option<Timestamp> {
        self.throttled().get(peer).copied()
    }

    fn throttled(&self) -> MutexGuard<'_, BTreeMap<PeerId, Timestamp>> {
        self.throttled
            .lock()
            .expect("the throttle map is not poisoned")
    }
}

impl Messages {
    /// Answer one offer on `send`/`recv`, whose first bytes are `prefix`.
    ///
    /// The offer is counted against the peer's window once the frame's first bytes are read —
    /// the earliest a stream is visible — and before the rest of the frame, so a peer that
    /// writes an offer's first bytes and stalls still spends one offer; a stream that never
    /// completes its prefix is classified as a message by the bytes it did carry and counted
    /// here too. A frame this build cannot read is answered unreadable, so the sender drops it
    /// instead of keeping it for the retention.
    ///
    /// This half does not begin a message round: the keeper's "an offer in flight is not the
    /// pair's traffic" rule is about this machine's own offers, and a peer that opens a stream
    /// is the peer acting. The offer's frames are on the wire beyond the binding exchange, so a
    /// message it takes is the pair's use by the counters alone; the sender's side, whose round
    /// ends after the answer, is the one that needs the take recorded, and does it in
    /// [`Self::settle`].
    pub(crate) async fn receive(
        &self,
        peer: PeerId,
        send: SendStream,
        mut recv: RecvStream,
        prefix: Vec<u8>,
    ) -> Result<(), MessageError> {
        let now = self.moment.now();
        if let Some(retry_after) =
            self.windows
                .admit(&peer, now, MESSAGE_WINDOW, MAX_OFFERS_PER_WINDOW)
        {
            reply(&*self.runtime, send, &Answer::Throttled { retry_after }).await;
            return Ok(());
        }
        let carried = !prefix.is_empty();
        let bytes = match stream::read_rest(
            &*self.runtime,
            &mut recv,
            prefix,
            MAX_MESSAGE_BYTES,
            MESSAGE_BUDGET,
        )
        .await
        {
            Ok(bytes) => bytes,
            Err(ReadFault::TooLong) => {
                reply(&*self.runtime, send, &Answer::Unreadable).await;
                return Ok(());
            }
            // A frame that stalled after its first bytes is one this build cannot read
            // whole: an older peer's transfer offer keeps its stream open for the file, and
            // answering it `unreadable` is what tells that peer the offer was not understood.
            // A stream that carried nothing has nobody to answer.
            Err(ReadFault::Stalled) if carried => {
                reply(&*self.runtime, send, &Answer::Unreadable).await;
                return Ok(());
            }
            Err(ReadFault::Stalled) => return Ok(()),
        };
        if let Some(answer) = self.handle(&peer, &bytes)? {
            reply(&*self.runtime, send, &answer).await;
        }
        Ok(())
    }
}

/// Write one answer back, bounded like every other wait this crate makes.
async fn reply(runtime: &dyn Runtime, send: SendStream, answer: &Answer) {
    stream::write_reply(runtime, send, &answer.encode(), MESSAGE_BUDGET).await;
}

/// The act that records a queue's drop, for the store to append between two holdings of the
/// queue.
fn dropped_act(peer: &PeerId, dropped: &[Envelope], reason: DropReason) -> Act {
    Act::MessagesDropped {
        peer: *peer,
        dropped: dropped
            .iter()
            .map(|envelope| Dropped {
                count: envelope.count(),
                id: *envelope.id().as_bytes(),
            })
            .collect(),
        reason,
    }
}

/// The act that records a message a receiver would not take.
fn refused_act(peer: &PeerId, id: EnvelopeId, count: u64, reason: RefusedReason) -> Act {
    Act::MessageRefused {
        peer: *peer,
        id: *id.as_bytes(),
        count,
        reason,
    }
}

/// Which refusal names a record [`PeerRecord::trusted`] rejects.
///
/// The decision is `trusted`'s alone — one predicate for the handshake, the decision and
/// this layer — and this only says which of the three reasons it was, so a caller sees
/// "not paired", "withdrawn" or "closed" rather than one word for all three.
impl From<Untrusted> for MessageError {
    fn from(why: Untrusted) -> Self {
        match why {
            Untrusted::Withdrawn(peer) => Self::Withdrawn { peer },
            Untrusted::Closed(peer) => Self::Closed { peer },
            Untrusted::NotPaired(peer) => Self::NotPaired { peer },
        }
    }
}

/// Offer one message over `connection` and read the answer; `None` on any failure.
async fn offer(connection: &Connection, message: &Message) -> Option<Answer> {
    let bytes = message.encode().ok()?;
    let (mut send, mut recv) = connection.open_bi().await.ok()?;
    send.write_all(&bytes).await.ok()?;
    send.finish().ok()?;
    let reply = recv.read_to_end(ANSWER_WIRE_BYTES).await.ok()?;
    Answer::decode(&reply).ok()
}

/// Why a message could not be queued, read, offered or believed.
#[derive(Debug)]
pub enum MessageError {
    /// The storage root does not exist, or is not a directory. It is never created here.
    RootMissing { path: PathBuf },
    /// The operating system could not read or write a file this layer reads or writes: a
    /// queue, or the record or log a decision reads.
    Io { path: PathBuf, source: io::Error },
    /// A file is reachable by an account the rule does not allow.
    Insecure { path: PathBuf, reason: Insecurity },
    /// The bytes of a file in `messages/` are not a queue: its own faults, plus the
    /// framing's ([`FramingFault`]) for what a file shares with a frame.
    Malformed {
        path: PathBuf,
        reason: MessageMalformed,
    },
    /// The queue would be larger than `MAX_MESSAGES_BYTES`, so it was not written.
    TooLarge { path: PathBuf, bytes: u64 },
    /// The peer's queue already holds [`MAX_QUEUE`] messages.
    Full { peer: PeerId, limit: usize },
    /// No record says a person paired this machine with the peer.
    NotPaired { peer: PeerId },
    /// This machine's trust in the peer was withdrawn.
    Withdrawn { peer: PeerId },
    /// The pair is closed on this machine — three comparisons failed — until a person
    /// clears it.
    Closed { peer: PeerId },
    /// The body is longer than [`MAX_BODY_BYTES`].
    Body { bytes: usize, limit: usize },
    /// Another writer holds this peer's queue this instant: a second process on the root, or
    /// a second [`Messages`] over it — the rule is per store, not per process, so two layers
    /// in this process meet it too. Nothing was changed, and the same call is worth making
    /// again. One layer's own writes wait for each other instead.
    Busy { peer: PeerId },
    /// The caller's [`Deliveries::deliver`] panicked. The message is still queued and the
    /// service that started the stream task stopped: a panic is a bug, and a pair that
    /// went on receiving nothing would hide it. A restarted service takes messages again.
    Delivery { peer: PeerId },
    /// The peer's record refused, in the record's own words: a record that cannot be read or
    /// parsed keeps its cause instead of becoming an I/O error.
    Record(RecordError),
    /// The log refused, in the log's own words.
    Audit(AuditError),
    /// The decision refused, in the decision's own words.
    Rights(RightsError),
    /// The bytes are not a frame this layer writes, naming which part of the framing is
    /// wrong. The vocabulary is shared with a queue file's [`MessageMalformed::Framing`],
    /// which adds the faults only a file can have; a frame's refusal carries no path.
    Frame { reason: FramingFault },
    /// The system's randomness is unavailable, so no identifier can be minted.
    Random,
}

/// What is wrong with a queue file's bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MessageMalformed {
    /// The file is empty: a write that never landed.
    Empty,
    /// The file is larger than the queue's own byte cap.
    TooLarge { bytes: u64 },
    /// The file name is not a queue name.
    Name { name: String },
    /// A fault the file shares with a frame: the framing's own vocabulary, written once.
    Framing(FramingFault),
}

/// What is wrong with the framing of this layer's bytes: the four faults a file and a frame
/// can share.
///
/// A queue file's refusal adds the faults only a file can have ([`MessageMalformed`]), so a
/// fault a frame cannot produce is not expressible where a frame's reason is expected. The
/// faults themselves are the framing's, written once in `crate::peer::tlv` and shared with
/// the action layer.
pub use crate::peer::tlv::FramingFault;

impl fmt::Display for MessageError {
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
                write!(f, "{} is not a message queue: {reason}", path.display())
            }
            Self::TooLarge { path, bytes } => write!(
                f,
                "{}: the queue would be {bytes} bytes, more than {MAX_MESSAGES_BYTES}; it was not written",
                path.display()
            ),
            Self::Full { peer, limit } => write!(
                f,
                "the queue for {} already holds {limit} messages",
                peer.fingerprint()
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
            Self::Busy { peer } => write!(
                f,
                "another writer holds the queue for {} this instant; try again",
                peer.fingerprint()
            ),
            Self::Frame { reason } => {
                write!(f, "the bytes are not what this layer writes: {reason}")
            }
            Self::Delivery { peer } => write!(
                f,
                "the caller's delivery panicked, so the service stopped taking messages from {}",
                peer.fingerprint()
            ),
            Self::Record(error) => write!(f, "the peer's record: {error}"),
            Self::Audit(error) => write!(f, "the log: {error}"),
            Self::Rights(error) => write!(f, "the decision: {error}"),
            Self::Random => f.write_str("the system's randomness is unavailable"),
        }
    }
}

impl std::error::Error for MessageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Record(error) => Some(error),
            Self::Audit(error) => Some(error),
            Self::Rights(error) => Some(error),
            Self::RootMissing { .. }
            | Self::Insecure { .. }
            | Self::Malformed { .. }
            | Self::TooLarge { .. }
            | Self::Full { .. }
            | Self::NotPaired { .. }
            | Self::Withdrawn { .. }
            | Self::Closed { .. }
            | Self::Body { .. }
            | Self::Busy { .. }
            | Self::Delivery { .. }
            | Self::Frame { .. }
            | Self::Random => None,
        }
    }
}

impl fmt::Display for MessageMalformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the file is empty"),
            Self::TooLarge { bytes } => write!(
                f,
                "the file is {bytes} bytes, more than {MAX_MESSAGES_BYTES}"
            ),
            Self::Name { name } => write!(
                f,
                "`{name}` is not a message name: 64 lowercase hex characters"
            ),
            Self::Framing(reason) => reason.fmt(f),
        }
    }
}

impl From<RecordError> for MessageError {
    /// A record's refusal keeps the record's own words: the classes this layer shares with
    /// the record are mapped, and everything else is carried typed, so a person reading it
    /// sees which layer refused and why.
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

impl From<AuditError> for MessageError {
    /// A log's refusal keeps the log's own words; see [`From::from`] for the record's.
    fn from(error: AuditError) -> Self {
        match error {
            AuditError::RootMissing { path } => Self::RootMissing { path },
            AuditError::Unreadable { path, source } | AuditError::Io { path, source } => {
                Self::Io { path, source }
            }
            AuditError::Insecure { path, reason } => Self::Insecure { path, reason },
            other => Self::Audit(other),
        }
    }
}

impl From<RightsError> for MessageError {
    fn from(error: RightsError) -> Self {
        match error {
            RightsError::Record(error) => error.into(),
            RightsError::Audit(error) => error.into(),
            RightsError::NotPaired { peer } => Self::NotPaired { peer },
            RightsError::Withdrawn { peer } => Self::Withdrawn { peer },
            other => Self::Rights(other),
        }
    }
}
