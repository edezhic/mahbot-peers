//! The durable queue: one file per peer under `messages/`.
//!
//! # The bytes
//!
//! `mahbot-peer-messages`, one version byte, then `[tag][len u16 big-endian][body]`
//! fields: `0x01` the next count to mint (8, big-endian, at least one), `0x02` the
//! highest count ever delivered (8, a high-water mark that is never lowered, and what a gap
//! in either direction is measured from), `0x03` one queued message, repeated in count order,
//! and `0x04` one taken identifier, repeated oldest first.
//!
//! A queued message is itself a field list: `0x01` its identifier (16 bytes), `0x02` its
//! count (8), `0x03` the moment it was composed (8, the caller's), `0x04` the moment it was
//! queued (8, local, never sent) and `0x05` its body. A taken identifier is `0x01` its
//! identifier (16) and `0x03` the moment it was taken (8); `0x02` held its count and is
//! retired — an old one is kept as a field this build does not know.
//!
//! A field this build does not know is kept and written back, after the fields it knows:
//! a rewrite may move it, which changes no meaning. That holds at every level — a queue's
//! own fields and those of a queued message or a taken identifier. A version above this
//! build's is read as this version's prefix and its unknown fields are preserved; a
//! version of zero is not a queue. Tags are appended, never inserted: a tag this build
//! stops writing is retired, not given a new meaning.
//!
//! # What it guarantees
//!
//! - **Atomic publish.** A queue is written beside its own path, flushed, and published
//!   by one rename, so a reader never sees a half-written file and a crash leaves the
//!   previous queue in place. A queue that would pass [`MAX_MESSAGES_BYTES`] is refused
//!   before the temporary file is written, so this build never publishes a file it cannot
//!   read back.
//! - **One writer at a time, on this machine and on the root.** This process writes one
//!   queue at a time: a mutex is held across the whole read-modify-publish, so two tasks
//!   cannot lose each other's work, and two peers written at the same instant wait for one
//!   write and the flush at the end of it. One lock file per peer's queue is held for the
//!   same span, so the self-update window's second process cannot lose a message either;
//!   that lock is per peer, so a second process writing another peer's queue never waits for
//!   this one. The record merges and the log appends; a queue is the one file that must be
//!   locked, because it is rewritten whole.
//! - **A queue is private.** The directory and every file are held to the key file's rule,
//!   and a file reachable by another account is refused rather than read.
//!
//! # Blocking
//!
//! Every operation is a small blocking file operation, like the record's. The delivery sink
//! runs with no lock held — the decision is taken, the lock is let go, the caller is handed
//! the message, and the record is made under the lock again — so a caller's own code never
//! decides how long another peer waits: a slow sink delays that peer's later messages and
//! nothing else.
//!
//! The waits this layer makes are its own and are bounded: another writer's lock file is
//! never waited on at all (it answers [`MessageError::Busy`] and the write is retried), and
//! this process's writer is waited for by every other write and is held across the whole
//! read-modify-publish — a read, a decode, a flush and a rename. Two waits are not this
//! layer's to bound: a caller's own delivery, and the log's cross-process lock, which every
//! append on the root takes. Both are taken with no queue held — a drop's entry is appended
//! between two short holdings of the queue, never inside one — so a slow caller holds this
//! pair's receiving, and a blocked log holds every pair's entry on the root, but neither
//! holds a queue.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File, TryLockError};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use ring::rand::{SecureRandom, SystemRandom};

use crate::hex;
use crate::identity::{PEER_ID_LEN, PeerId};
use crate::peer::messages::{
    Delivery, ENVELOPE_ID_BYTES, Envelope, EnvelopeId, FramingFault, Gap, MAX_BODY_BYTES,
    MAX_MESSAGES_BYTES, MAX_QUEUE, MAX_TAKEN, MESSAGE_RETENTION, Message, MessageError,
    MessageMalformed, TAKEN_RETENTION,
};
use crate::peer::record::Timestamp;
use crate::peer::tlv;
use crate::private::{self, PrivateFileError};

/// The directory under a storage root that holds the queues.
const DIR: &str = "messages";

/// The file a writer locks for one peer's read-modify-publish, so a second process on the
/// same root cannot lose a message. It is never published or replaced, and it is not a
/// queue: [`EXTENSION`] names those.
const LOCK: &str = "lock";

/// A queue file's extension. A file in `messages/` without it is ignored — a desktop's
/// metadata or an operator's note is not a queue — while a file with it must be a queue.
const EXTENSION: &str = "messages";

/// The bytes every queue opens with.
const MAGIC: &[u8] = b"mahbot-peer-messages";

/// The queue format this build writes. A higher version is read as this version's prefix.
const VERSION: u8 = 1;

/// A queue file's field tags. Unknown tags are preserved, not refused.
mod tag {
    pub const NEXT_COUNT: u8 = 0x01;
    pub const LAST_COUNT: u8 = 0x02;
    pub const QUEUED: u8 = 0x03;
    pub const TAKEN: u8 = 0x04;
}

/// A queued message's field tags.
mod queued_tag {
    pub const ID: u8 = 0x01;
    pub const COUNT: u8 = 0x02;
    pub const COMPOSED_AT: u8 = 0x03;
    pub const QUEUED_AT: u8 = 0x04;
    pub const BODY: u8 = 0x05;
}

/// A taken identifier's field tags.
///
/// `0x02` held the identifier's count and is retired: nothing writes it now, and an old one
/// is kept as a field this build does not know. The moment stays at `0x03` so that a queue
/// written before the count went still reads its taken moments where they are.
mod taken_tag {
    pub const ID: u8 = 0x01;
    pub const TAKEN_AT: u8 = 0x03;
}

/// What an acceptance did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// The message was handed over and recorded.
    Accepted,
    /// This machine took this identifier before: by the peer's account the message reached a
    /// caller and is not delivered again.
    AlreadyTaken,
    /// The caller could not take it, so nothing was recorded and nothing is answered.
    Declined,
    /// The same message is being handed over right now, so nothing is answered and the
    /// sender offers it again once the record has landed.
    Busy,
}

/// One peer's queue file, as it is read and rewritten.
struct QueueFile {
    next_count: u64,
    last_count: u64,
    queued: Vec<Queued>,
    taken: Vec<Taken>,
    /// Fields a newer build wrote, kept byte for byte and written back at the end.
    unknown: Vec<(u8, Vec<u8>)>,
}

impl Default for QueueFile {
    fn default() -> Self {
        Self {
            next_count: 1,
            last_count: 0,
            queued: Vec::new(),
            taken: Vec::new(),
            unknown: Vec::new(),
        }
    }
}

/// One queued message.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Queued {
    id: EnvelopeId,
    count: u64,
    composed_at: Timestamp,
    /// The moment it was queued: local, never sent, and what retention is measured from.
    at: Timestamp,
    body: Vec<u8>,
    /// Fields a newer build wrote inside this message, kept and written back.
    unknown: Vec<(u8, Vec<u8>)>,
}

impl Queued {
    fn envelope(&self) -> Envelope {
        Envelope {
            id: self.id,
            count: self.count,
            composed_at: self.composed_at,
        }
    }
}

/// One identifier this machine has delivered.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Taken {
    id: EnvelopeId,
    /// The moment it was taken, which is what its retention is measured from.
    at: Timestamp,
    /// Fields a newer build wrote inside this record, kept and written back.
    unknown: Vec<(u8, Vec<u8>)>,
}

/// The queues of one storage root.
///
/// Cheap to clone: every clone names the same directory and shares the same writer.
pub(crate) struct MessageStore {
    inner: Arc<Inner>,
}

struct Inner {
    dir: PathBuf,
    /// This process's one writer, held across a read-modify-publish so two queues are never
    /// written at once. The lock file below covers a second process.
    writer: Mutex<()>,
    /// The messages being handed to the caller right now, in this process: a second offer
    /// of one of them is answered nothing rather than being delivered twice at once. Two
    /// processes never race here — a connection's receiver lives in one process — and the
    /// lock file covers the record itself.
    inflight: Mutex<BTreeSet<(PeerId, EnvelopeId)>>,
}

impl Clone for MessageStore {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl fmt::Debug for MessageStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageStore")
            .field("dir", &self.inner.dir)
            .finish_non_exhaustive()
    }
}

impl MessageStore {
    /// Open the queues under `root`, creating `messages/` on the first start.
    pub(crate) fn open(root: &Path) -> Result<Self, MessageError> {
        if !root.is_dir() {
            return Err(MessageError::RootMissing {
                path: root.to_owned(),
            });
        }
        let dir = dir_in(root);
        private::create_private_dir(&dir).map_err(|error| mapped(error, &dir))?;
        Ok(Self {
            inner: Arc::new(Inner {
                dir,
                writer: Mutex::new(()),
                inflight: Mutex::new(BTreeSet::new()),
            }),
        })
    }

    /// Queue one message for `peer`, minting its identifier and count.
    pub(crate) fn enqueue(
        &self,
        peer: &PeerId,
        composed_at: Timestamp,
        queued_at: Timestamp,
        body: &[u8],
    ) -> Result<Envelope, MessageError> {
        let _held = self.lock(peer)?;
        let mut file = self.read(peer)?;
        if file.queued.len() >= MAX_QUEUE {
            return Err(MessageError::Full {
                peer: *peer,
                limit: MAX_QUEUE,
            });
        }
        let id = EnvelopeId::from_bytes(random_id()?);
        let count = file.next_count;
        file.next_count = count.saturating_add(1);
        file.queued.push(Queued {
            id,
            count,
            composed_at,
            at: queued_at,
            body: body.to_vec(),
            unknown: Vec::new(),
        });
        self.write(peer, &file)?;
        Ok(Envelope {
            id,
            count,
            composed_at,
        })
    }

    /// The messages queued for `peer`, oldest first.
    pub(crate) fn pending(&self, peer: &PeerId) -> Result<Vec<Envelope>, MessageError> {
        Ok(self
            .read(peer)?
            .queued
            .iter()
            .map(Queued::envelope)
            .collect())
    }

    /// The oldest queued message for `peer`, with its body.
    pub(crate) fn head(&self, peer: &PeerId) -> Result<Option<Message>, MessageError> {
        let file = self.read(peer)?;
        let Some(first) = file.queued.first() else {
            return Ok(None);
        };
        Message::new(first.envelope(), first.body.clone()).map(Some)
    }

    /// Remove one message from `peer`'s queue; nothing happens when it is absent.
    pub(crate) fn remove(&self, peer: &PeerId, id: &EnvelopeId) -> Result<(), MessageError> {
        let _held = self.lock(peer)?;
        let mut file = self.read(peer)?;
        let before = file.queued.len();
        file.queued.retain(|queued| queued.id != *id);
        if file.queued.len() == before {
            return Ok(());
        }
        self.write(peer, &file)
    }

    /// Take one offered message: hand it to `deliver`, then record it if the caller kept it.
    ///
    /// `deliver` runs before the record and answers whether the message was taken: a
    /// caller that could not keep it leaves the queue untouched and the message is offered
    /// again, so no identifier is recorded for a message nobody has. It runs with no lock
    /// held, so a slow caller delays that peer's later messages and nothing else.
    pub(crate) fn accept(
        &self,
        sender: &PeerId,
        message: &Message,
        now: Timestamp,
        deliver: impl FnOnce(Delivery) -> bool,
    ) -> Result<Outcome, MessageError> {
        let envelope = *message.envelope();
        let id = envelope.id();
        let count = envelope.count();
        let (gap, _claim) = {
            let _held = self.lock(sender)?;
            let file = self.read(sender)?;
            // Only an identifier this machine remembers taking suppresses a message. The
            // count orders and declares; it never decides whether a message is delivered,
            // because a sender whose queue was lost mints fresh identifiers under counts it
            // used before, and those are new messages.
            if file.taken.iter().any(|taken| taken.id == id) {
                return Ok(Outcome::AlreadyTaken);
            }
            let Some(claim) = self.claim(sender, id) else {
                return Ok(Outcome::Busy);
            };
            // A count that jumped forward names how many are missing; one that did not move
            // forward — a count already used — is a rewind, and nothing is missing.
            let gap = if count > file.last_count.saturating_add(1) {
                Some(Gap::Missing {
                    count: count - file.last_count - 1,
                })
            } else if count > file.last_count {
                None
            } else {
                Some(Gap::Rewound)
            };
            (gap, claim)
        };
        let delivery = Delivery {
            sender: *sender,
            envelope,
            body: message.body().to_vec(),
            gap,
        };
        // The claim is given back when this function ends, panic or not: one left behind
        // would answer nothing for this message for ever and hold the head of the queue.
        let kept = deliver(delivery);
        let recorded = if kept {
            Some(self.record(sender, id, count, now))
        } else {
            None
        };
        match recorded {
            Some(Ok(())) => Ok(Outcome::Accepted),
            Some(Err(error)) => Err(error),
            None => Ok(Outcome::Declined),
        }
    }

    /// Record one identifier as taken, and raise the high-water count with the count it
    /// carried.
    fn record(
        &self,
        sender: &PeerId,
        id: EnvelopeId,
        count: u64,
        now: Timestamp,
    ) -> Result<(), MessageError> {
        let _held = self.lock(sender)?;
        let mut file = self.read(sender)?;
        if file.taken.iter().any(|taken| taken.id == id) {
            return Ok(());
        }
        file.last_count = file.last_count.max(count);
        file.taken.push(Taken {
            id,
            at: now,
            unknown: Vec::new(),
        });
        trim_taken(&mut file, now);
        self.write(sender, &file)
    }

    /// Drop every queued message whose retention passed at `now`.
    ///
    /// `record` is the audit entry, and it runs with no queue lock held: the queue is read
    /// and let go, the entry is appended, and the queue is read again to remove what is
    /// still there. The log has a cross-process lock of its own, and taking it while a
    /// peer's queue is held would let another process's log write hold every queue this
    /// machine is dropping. It is not called when nothing expired, and it cannot refuse: a
    /// log that will not take the entry must not keep bodies on disk.
    pub(crate) fn drop_expired(
        &self,
        peer: &PeerId,
        now: Timestamp,
        record: impl FnOnce(&[Envelope]),
    ) -> Result<usize, MessageError> {
        self.drop_where(
            peer,
            |queued| queued.at.plus(MESSAGE_RETENTION) > now,
            record,
        )
    }

    /// Drop every queued message for `peer`, recording it before the removal.
    pub(crate) fn drop_queue(
        &self,
        peer: &PeerId,
        record: impl FnOnce(&[Envelope]),
    ) -> Result<usize, MessageError> {
        self.drop_where(peer, |_| false, record)
    }

    /// Drop the queued messages `keep` rejects, recording them before the removal.
    ///
    /// The removal re-reads the queue: a message another writer queued while the entry was
    /// being appended stays, and one it removed already costs nothing. The entry may name a
    /// message that went in between — a recorded drop that did not happen, the direction the
    /// log's ordering already tolerates — and never leaves a drop nobody recorded.
    fn drop_where(
        &self,
        peer: &PeerId,
        keep: impl Fn(&Queued) -> bool,
        record: impl FnOnce(&[Envelope]),
    ) -> Result<usize, MessageError> {
        let dropped: Vec<Envelope> = {
            let _held = self.lock(peer)?;
            let file = self.read(peer)?;
            file.queued
                .iter()
                .filter(|queued| !keep(queued))
                .map(Queued::envelope)
                .collect()
        };
        if dropped.is_empty() {
            return Ok(0);
        }
        record(&dropped);
        let ids: Vec<EnvelopeId> = dropped.iter().map(Envelope::id).collect();
        let _held = self.lock(peer)?;
        let mut file = self.read(peer)?;
        let before = file.queued.len();
        file.queued.retain(|queued| !ids.contains(&queued.id));
        let removed = before - file.queued.len();
        if removed == 0 {
            return Ok(0);
        }
        self.write(peer, &file)?;
        Ok(removed)
    }

    /// Forget taken identifiers whose retention passed, and the oldest beyond
    /// [`MAX_TAKEN`]; answers whether anything changed.
    pub(crate) fn expire_taken(&self, peer: &PeerId, now: Timestamp) -> Result<bool, MessageError> {
        let _held = self.lock(peer)?;
        let mut file = self.read(peer)?;
        let before = file.taken.len();
        trim_taken(&mut file, now);
        if file.taken.len() == before {
            return Ok(false);
        }
        self.write(peer, &file)?;
        Ok(true)
    }

    /// Every peer with a queue file.
    ///
    /// A `.messages` file whose name is not 64 lowercase hex characters is refused: a file
    /// that claims to be a queue and is not one is exactly what must not be silently
    /// skipped.
    pub(crate) fn peers(&self) -> Result<Vec<PeerId>, MessageError> {
        let entries = fs::read_dir(&self.inner.dir).map_err(|source| MessageError::Io {
            path: self.inner.dir.clone(),
            source,
        })?;
        let mut peers = BTreeSet::new();
        for entry in entries {
            let path = entry
                .map_err(|source| MessageError::Io {
                    path: self.inner.dir.clone(),
                    source,
                })?
                .path();
            if path
                .extension()
                .is_none_or(|extension| extension != EXTENSION)
            {
                continue;
            }
            let name = path
                .file_stem()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            let Some(peer) = peer_of_name(&name) else {
                return Err(MessageError::Malformed {
                    path: path.clone(),
                    reason: MessageMalformed::Name { name },
                });
            };
            peers.insert(peer);
        }
        Ok(peers.into_iter().collect())
    }

    /// Read one peer's queue, or an empty one when the file is absent.
    fn read(&self, peer: &PeerId) -> Result<QueueFile, MessageError> {
        read_file(&path_in(&self.inner.dir, peer))
    }

    /// Publish one peer's queue.
    fn write(&self, peer: &PeerId, file: &QueueFile) -> Result<(), MessageError> {
        publish(&self.inner.dir, peer, file)
    }

    fn lock(&self, peer: &PeerId) -> Result<Held<'_>, MessageError> {
        // This process's writer first: a second task waits here for the few file operations
        // the holder is doing, never for a caller's own code.
        let writer = self
            .inner
            .writer
            .lock()
            .expect("a queue's writer is not poisoned");
        let path = lock_in(&self.inner.dir, peer);
        let file = Self::lock_file(&path)?;
        match file.try_lock() {
            Ok(()) => Ok(Held {
                _writer: writer,
                file,
            }),
            // Another writer — the second process a self-update leaves on the root, or a
            // second `Messages` in this one — is publishing this peer's queue this instant.
            // That wait is not this layer's to make: the caller is told and tries again.
            Err(TryLockError::WouldBlock) => Err(MessageError::Busy { peer: *peer }),
            Err(TryLockError::Error(source)) => Err(MessageError::Io { path, source }),
        }
    }

    /// The lock file for one peer's queue, created on the first write.
    fn lock_file(path: &Path) -> Result<File, MessageError> {
        if let Some(file) = private::open_private(path).map_err(|error| mapped(error, path))? {
            return Ok(file);
        }
        private::create_private(path, ".lock.", b"").map_err(|error| mapped(error, path))?;
        private::open_private(path)
            .map_err(|error| mapped(error, path))?
            .ok_or_else(|| MessageError::Io {
                path: path.to_owned(),
                source: io::Error::other("the lock file vanished after it was created"),
            })
    }

    /// Take the in-flight place for `id`, or `None` when it is already taken.
    fn claim(&self, peer: &PeerId, id: EnvelopeId) -> Option<Claimed<'_>> {
        let key = (*peer, id);
        self.inner
            .inflight
            .lock()
            .expect("the in-flight messages are not poisoned")
            .insert(key)
            .then(|| Claimed { store: self, key })
    }
}

/// One in-flight place, given back when it is dropped.
///
/// A guard rather than a paired call: a caller's sink runs between the claim and the record,
/// and a panic there must not leave the message claimed for ever.
struct Claimed<'a> {
    store: &'a MessageStore,
    key: (PeerId, EnvelopeId),
}

impl Drop for Claimed<'_> {
    fn drop(&mut self) {
        self.store
            .inner
            .inflight
            .lock()
            .expect("the in-flight messages are not poisoned")
            .remove(&self.key);
    }
}

/// One writer's hold on one peer's queue: this process's writer and the lock file, held for
/// the whole read-modify-publish.
///
/// The lock is released here rather than by the descriptor's own drop, and the order matters:
/// fields drop in declaration order, so the writer's guard goes first, and a second task could
/// take the writer and `try_lock` a file whose lock this one has not let go yet — a spurious
/// [`MessageError::Busy`] for a queue nobody holds. Unlocking first also means a panic between
/// the read and the publish does not leave the queue locked.
struct Held<'a> {
    _writer: MutexGuard<'a, ()>,
    file: File,
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

/// Forget taken identifiers past their retention, then the oldest beyond [`MAX_TAKEN`].
///
/// The highest count ever delivered is not lowered with them: it is what a jump is measured
/// from, and a pair that forgot its identifiers has still seen every count up to it. What
/// the identifiers *still remember* is the only thing that suppresses a message, so past the
/// retention the same message can be delivered again rather than being dropped on its count.
fn trim_taken(file: &mut QueueFile, now: Timestamp) {
    file.taken
        .retain(|taken| taken.at.plus(TAKEN_RETENTION) > now);
    if file.taken.len() > MAX_TAKEN {
        let excess = file.taken.len() - MAX_TAKEN;
        file.taken.drain(..excess);
    }
}

/// The directory under `root` that holds the queues.
pub(super) fn dir_in(root: &Path) -> PathBuf {
    root.join(DIR)
}

/// The queue file's path for `peer` inside `dir`.
pub(super) fn path_in(dir: &Path, peer: &PeerId) -> PathBuf {
    dir.join(format!("{}.{EXTENSION}", hex::encode(peer.as_bytes())))
}

/// The lock file's path for `peer` inside `dir`.
pub(super) fn lock_in(dir: &Path, peer: &PeerId) -> PathBuf {
    dir.join(format!("{}.{LOCK}", hex::encode(peer.as_bytes())))
}

/// The peer a queue file's stem names, or `None` when it names none.
fn peer_of_name(name: &str) -> Option<PeerId> {
    hex::decode(name).and_then(|bytes| {
        <[u8; PEER_ID_LEN]>::try_from(bytes.as_slice())
            .ok()
            .map(PeerId::from_bytes)
    })
}

/// A fresh identifier.
fn random_id() -> Result<[u8; ENVELOPE_ID_BYTES], MessageError> {
    let mut id = [0u8; ENVELOPE_ID_BYTES];
    SystemRandom::new()
        .fill(&mut id)
        .map_err(|_| MessageError::Random)?;
    Ok(id)
}

/// Read one queue file, or an empty queue when nothing is there.
fn read_file(path: &Path) -> Result<QueueFile, MessageError> {
    let file = match private::open_private(path) {
        Ok(Some(file)) => file,
        Ok(None) => return Ok(QueueFile::default()),
        Err(error) => return Err(mapped(error, path)),
    };
    let (bytes, length) =
        private::read_capped(file, MAX_MESSAGES_BYTES + 1).map_err(|source| MessageError::Io {
            path: path.to_owned(),
            source,
        })?;
    if let Some(length) = length
        && length > MAX_MESSAGES_BYTES
    {
        return Err(malformed_at(
            path,
            MessageMalformed::TooLarge { bytes: length },
        ));
    }
    if bytes.is_empty() {
        return Err(malformed_at(path, MessageMalformed::Empty));
    }
    if bytes.len() as u64 > MAX_MESSAGES_BYTES {
        return Err(malformed_at(
            path,
            MessageMalformed::TooLarge {
                bytes: bytes.len() as u64,
            },
        ));
    }
    decode(&bytes).map_err(|reason| malformed_at(path, reason))
}

/// Publish `file` atomically: a private temporary file beside the destination, flushed,
/// and published by one rename.
fn publish(dir: &Path, peer: &PeerId, file: &QueueFile) -> Result<(), MessageError> {
    let path = path_in(dir, peer);
    let bytes = encode(file).map_err(|reason| malformed_at(&path, reason))?;
    if bytes.len() as u64 > MAX_MESSAGES_BYTES {
        return Err(MessageError::TooLarge {
            path,
            bytes: bytes.len() as u64,
        });
    }
    let mut temp =
        private::private_temp(&path, ".messages.").map_err(|error| mapped(error, &path))?;
    temp.write_all(&bytes).map_err(|source| MessageError::Io {
        path: path.clone(),
        source,
    })?;
    temp.as_file()
        .sync_all()
        .map_err(|source| MessageError::Io {
            path: path.clone(),
            source,
        })?;
    temp.persist(&path).map_err(|error| MessageError::Io {
        path: path.clone(),
        source: error.error,
    })?;
    Ok(())
}

/// The queue's bytes.
///
/// Every body here is bounded — a body is at most [`MAX_BODY_BYTES`], a nested record a few
/// dozen bytes more, and a field read from a file was at most a `u16` — so the framing
/// cannot refuse; the refusal exists for the type, not for a case.
fn encode(file: &QueueFile) -> Result<Vec<u8>, MessageMalformed> {
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(MAGIC);
    bytes.push(VERSION);
    put(&mut bytes, tag::NEXT_COUNT, &file.next_count.to_be_bytes())?;
    put(&mut bytes, tag::LAST_COUNT, &file.last_count.to_be_bytes())?;
    for queued in &file.queued {
        let mut body = Vec::with_capacity(queued.body.len() + 56);
        put(&mut body, queued_tag::ID, queued.id.as_bytes())?;
        put(&mut body, queued_tag::COUNT, &queued.count.to_be_bytes())?;
        put(
            &mut body,
            queued_tag::COMPOSED_AT,
            &queued.composed_at.unix_seconds().to_be_bytes(),
        )?;
        put(
            &mut body,
            queued_tag::QUEUED_AT,
            &queued.at.unix_seconds().to_be_bytes(),
        )?;
        put(&mut body, queued_tag::BODY, &queued.body)?;
        for (tag, unknown) in &queued.unknown {
            put(&mut body, *tag, unknown)?;
        }
        put(&mut bytes, tag::QUEUED, &body)?;
    }
    for taken in &file.taken {
        let mut body = Vec::with_capacity(32);
        put(&mut body, taken_tag::ID, taken.id.as_bytes())?;
        put(
            &mut body,
            taken_tag::TAKEN_AT,
            &taken.at.unix_seconds().to_be_bytes(),
        )?;
        for (tag, unknown) in &taken.unknown {
            put(&mut body, *tag, unknown)?;
        }
        put(&mut bytes, tag::TAKEN, &body)?;
    }
    for (tag, body) in &file.unknown {
        put(&mut bytes, *tag, body)?;
    }
    Ok(bytes)
}

/// Read a queue from its bytes. A version above [`VERSION`] is read as this version's
/// prefix; its unknown fields are preserved.
fn decode(bytes: &[u8]) -> Result<QueueFile, MessageMalformed> {
    let rest = bytes
        .strip_prefix(MAGIC)
        .ok_or(framing(FramingFault::Magic))?;
    let (&version, rest) = rest.split_first().ok_or(framing(FramingFault::Truncated))?;
    if version == 0 {
        return Err(framing(FramingFault::Version { found: version }));
    }
    let mut file = QueueFile::default();
    let mut next = None;
    for field in tlv::Fields::new(rest) {
        let (tag, body) = field.map_err(field_fault)?;
        match tag {
            tag::NEXT_COUNT => next = Some(tlv::u64_of(tag, body).map_err(field_fault)?),
            tag::LAST_COUNT => file.last_count = tlv::u64_of(tag, body).map_err(field_fault)?,
            tag::QUEUED => file.queued.push(read_queued(body)?),
            tag::TAKEN => file.taken.push(read_taken(body)?),
            other => file.unknown.push((other, body.to_vec())),
        }
    }
    let next = next.ok_or_else(|| {
        framing(FramingFault::Field {
            tag: tag::NEXT_COUNT,
            detail: "is missing".to_owned(),
        })
    })?;
    if next == 0 {
        return Err(framing(FramingFault::Field {
            tag: tag::NEXT_COUNT,
            detail: "is zero".to_owned(),
        }));
    }
    file.next_count = next;
    Ok(file)
}

/// Read one queued message.
fn read_queued(body: &[u8]) -> Result<Queued, MessageMalformed> {
    let mut id = None;
    let mut count = None;
    let mut composed_at = None;
    let mut queued_at = None;
    let mut message = None;
    let mut unknown = Vec::new();
    for field in tlv::Fields::new(body) {
        let (tag, body) = field.map_err(field_fault)?;
        match tag {
            queued_tag::ID => {
                id = Some(EnvelopeId::from_bytes(
                    tlv::id_of(tag, body).map_err(field_fault)?,
                ));
            }
            queued_tag::COUNT => count = Some(read_count(tag, body)?),
            queued_tag::COMPOSED_AT => {
                composed_at = Some(Timestamp::from_unix_seconds(
                    tlv::u64_of(tag, body).map_err(field_fault)?,
                ));
            }
            queued_tag::QUEUED_AT => {
                queued_at = Some(Timestamp::from_unix_seconds(
                    tlv::u64_of(tag, body).map_err(field_fault)?,
                ));
            }
            queued_tag::BODY => {
                if body.len() > MAX_BODY_BYTES {
                    return Err(framing(FramingFault::Field {
                        tag,
                        detail: "is longer than the body cap".to_owned(),
                    }));
                }
                message = Some(body.to_vec());
            }
            other => unknown.push((other, body.to_vec())),
        }
    }
    let missing = |tag| {
        framing(FramingFault::Field {
            tag,
            detail: "is missing".to_owned(),
        })
    };
    Ok(Queued {
        id: id.ok_or_else(|| missing(queued_tag::ID))?,
        count: count.ok_or_else(|| missing(queued_tag::COUNT))?,
        composed_at: composed_at.ok_or_else(|| missing(queued_tag::COMPOSED_AT))?,
        at: queued_at.ok_or_else(|| missing(queued_tag::QUEUED_AT))?,
        body: message.ok_or_else(|| missing(queued_tag::BODY))?,
        unknown,
    })
}

/// Read one taken identifier.
fn read_taken(body: &[u8]) -> Result<Taken, MessageMalformed> {
    let mut id = None;
    let mut taken_at = None;
    let mut unknown = Vec::new();
    for field in tlv::Fields::new(body) {
        let (tag, body) = field.map_err(field_fault)?;
        match tag {
            taken_tag::ID => {
                id = Some(EnvelopeId::from_bytes(
                    tlv::id_of(tag, body).map_err(field_fault)?,
                ));
            }
            taken_tag::TAKEN_AT => {
                taken_at = Some(Timestamp::from_unix_seconds(
                    tlv::u64_of(tag, body).map_err(field_fault)?,
                ));
            }
            other => unknown.push((other, body.to_vec())),
        }
    }
    let missing = |tag| {
        framing(FramingFault::Field {
            tag,
            detail: "is missing".to_owned(),
        })
    };
    Ok(Taken {
        id: id.ok_or_else(|| missing(taken_tag::ID))?,
        at: taken_at.ok_or_else(|| missing(taken_tag::TAKEN_AT))?,
        unknown,
    })
}

/// Append one field, refusing a body longer than a field can name.
fn put(bytes: &mut Vec<u8>, tag: u8, body: &[u8]) -> Result<(), MessageMalformed> {
    tlv::put(bytes, tag, body).map_err(|_| {
        framing(FramingFault::Field {
            tag,
            detail: "is longer than 65535 bytes".to_owned(),
        })
    })
}

fn read_count(tag: u8, body: &[u8]) -> Result<u64, MessageMalformed> {
    let count = tlv::u64_of(tag, body).map_err(field_fault)?;
    if count == 0 {
        return Err(framing(FramingFault::Field {
            tag,
            detail: "is zero".to_owned(),
        }));
    }
    Ok(count)
}

/// A framing fault, in the words a queue file's refusal uses.
fn framing(reason: FramingFault) -> MessageMalformed {
    MessageMalformed::Framing(reason)
}

fn field_fault(error: tlv::FieldError) -> MessageMalformed {
    framing(FramingFault::Field {
        tag: error.tag,
        detail: error.detail.to_owned(),
    })
}

fn malformed_at(path: &Path, reason: MessageMalformed) -> MessageError {
    MessageError::Malformed {
        path: path.to_owned(),
        reason,
    }
}

/// A private-file refusal, named with the file it is about.
fn mapped(error: PrivateFileError, path: &Path) -> MessageError {
    match error {
        PrivateFileError::Io(source) => MessageError::Io {
            path: path.to_owned(),
            source,
        },
        PrivateFileError::Insecure(reason) => MessageError::Insecure {
            path: path.to_owned(),
            reason,
        },
    }
}
