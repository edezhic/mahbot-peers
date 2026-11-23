//! The durable action memory: one file per peer under `actions/`.
//!
//! # The bytes
//!
//! `mahbot-peer-actions`, one version byte, then `[tag][len u16 big-endian][body]` fields:
//! `0x01` one executed identifier, repeated oldest first, and `0x02` one unknown mark, repeated
//! oldest first. Both are themselves a field list: `0x01` the identifier (16 bytes) and `0x02`
//! the moment (8, seconds) — for an executed identifier the moment it ran, for a mark the
//! moment the result stopped coming back.
//!
//! A field this build does not know is kept and written back, after the fields it knows: a
//! rewrite may move it, which changes no meaning. That holds at every level. A version above
//! this build's is read as this version's prefix and its unknown fields are preserved; a
//! version of zero is not a memory. Tags are appended, never inserted.
//!
//! # What it guarantees
//!
//! - **Atomic publish.** A memory is written beside its own path, flushed, and published by
//!   one rename, so a reader never sees a half-written file and a crash leaves the previous
//!   memory in place. A file that would pass [`MAX_ACTIONS_BYTES`] is refused before the
//!   temporary file is written, so this build never publishes a file it cannot read back.
//! - **One writer at a time, on this machine and on the root.** This process writes one memory
//!   at a time: a mutex is held across the whole read-modify-publish, and one lock file per
//!   peer is held for the same span, so the self-update window's second process cannot lose an
//!   identifier either. A lock another writer holds answers [`ActionError::Busy`]; it is never
//!   waited on.
//! - **A memory is private.** The directory and every file are held to the key file's rule, and
//!   a file reachable by another account is refused rather than read.
//!
//! # The two halves
//!
//! The executed identifiers are the receiver's journal: they are what makes a repeat "already
//! executed". The unknown marks are the sender's trace: they are what survives a restart after
//! an answer never came. They share a file because they share the peer, but they have separate
//! caps and separate retention, so one peer's flood of actions cannot push another peer's
//! identifiers out and a sender's own marks cannot fill the journal that protects a command
//! from running twice.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::identity::PeerId;
use crate::peer::FramingFault;
use crate::peer::actions::{
    ACTION_MEMORY_RETENTION, ActionError, ActionId, ActionMalformed, ActionMark, MAX_ACTIONS_BYTES,
    MAX_EXECUTED, MAX_UNKNOWN,
};
use crate::peer::record::Timestamp;
use crate::peer::store::{self, Coded, Fault};
use crate::peer::tlv;

/// The directory under a storage root that holds the memories.
const DIR: &str = "actions";

/// A memory file's extension.
const EXTENSION: &str = "actions";

/// The bytes every memory opens with.
const MAGIC: &[u8] = b"mahbot-peer-actions";

/// The format this build writes. A higher version is read as this version's prefix.
const VERSION: u8 = 1;

/// A memory file's field tags. Unknown tags are preserved, not refused.
mod tag {
    pub const EXECUTED: u8 = 0x01;
    pub const UNKNOWN: u8 = 0x02;
}

/// One identifier's field tags.
mod entry_tag {
    pub const ID: u8 = 0x01;
    pub const AT: u8 = 0x02;
}

/// What remembering one identifier did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Remembered {
    /// It was not there, and is now.
    Inserted,
    /// This machine executed it before: the repeat is answered, not run.
    Already,
    /// The journal is full: a new identifier is refused rather than an old one forgotten.
    Full,
}

/// One peer's memory, as it is read and rewritten.
#[derive(Default)]
struct MemoryFile {
    executed: Vec<Entry>,
    unknown: Vec<Entry>,
    /// Fields a newer build wrote, kept byte for byte and written back at the end.
    fields: Vec<(u8, Vec<u8>)>,
}

impl MemoryFile {
    /// Drop everything recorded before `since`, a withdrawal's moment.
    ///
    /// A moment equal to the withdrawal is kept: the two are whole seconds, and keeping a
    /// same-second identifier is the only choice that cannot let a command run twice.
    fn forget_before(&mut self, since: Option<Timestamp>) {
        let Some(since) = since else {
            return;
        };
        self.executed.retain(|entry| entry.at >= since);
        self.unknown.retain(|entry| entry.at >= since);
    }

    /// The unknown marks recorded at or after `since`, oldest first.
    fn unknown_from(&self, since: Option<Timestamp>) -> impl Iterator<Item = &Entry> {
        self.unknown
            .iter()
            .filter(move |entry| since.is_none_or(|since| entry.at >= since))
    }
}

/// Whether `file` holds anything a withdrawal at `since` would drop.
fn holds_before(file: &MemoryFile, since: Timestamp) -> bool {
    file.executed
        .iter()
        .chain(&file.unknown)
        .any(|entry| entry.at < since)
}

/// One remembered identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    id: ActionId,
    /// The moment it was executed, or the moment its result stopped coming back.
    at: Timestamp,
    /// Fields a newer build wrote inside this entry, kept and written back.
    unknown: Vec<(u8, Vec<u8>)>,
}

/// The action memories of one storage root.
pub(crate) struct ActionStore {
    files: Arc<store::Files>,
}

impl fmt::Debug for ActionStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ActionStore")
            .field("dir", &self.files.dir())
            .finish_non_exhaustive()
    }
}

impl ActionStore {
    /// Open the memories under `root`, creating `actions/` on the first start.
    pub(crate) fn open(root: &Path) -> Result<Self, ActionError> {
        Ok(Self {
            files: Arc::new(store::Files::open(root, DIR).map_err(MemoryFile::fault)?),
        })
    }

    /// Remember one identifier as executed, answering what it was.
    ///
    /// Expired entries and everything recorded before `since` — the peer's most recent
    /// withdrawal — are cleared before the journal is called full. The insert is published
    /// before this returns, so a run that follows it is never missing from the memory.
    pub(crate) fn remember(
        &self,
        peer: &PeerId,
        id: ActionId,
        now: Timestamp,
        since: Option<Timestamp>,
    ) -> Result<Remembered, ActionError> {
        let _held = self.lock(peer)?;
        let mut file = self.read(peer)?;
        file.forget_before(since);
        trim(&mut file.executed, now);
        if file.executed.iter().any(|entry| entry.id == id) {
            return Ok(Remembered::Already);
        }
        if file.executed.len() >= MAX_EXECUTED {
            return Ok(Remembered::Full);
        }
        file.executed.push(Entry {
            id,
            at: now,
            unknown: Vec::new(),
        });
        self.write(peer, &file)?;
        Ok(Remembered::Inserted)
    }

    /// Forget one executed identifier; nothing happens when it is absent.
    pub(crate) fn forget(
        &self,
        peer: &PeerId,
        id: ActionId,
        since: Option<Timestamp>,
    ) -> Result<(), ActionError> {
        let _held = self.lock(peer)?;
        let mut file = self.read(peer)?;
        let before = (file.executed.len(), file.unknown.len());
        file.forget_before(since);
        file.executed.retain(|entry| entry.id != id);
        if (file.executed.len(), file.unknown.len()) == before {
            return Ok(());
        }
        self.write(peer, &file)
    }

    /// Mark one identifier unknown for this peer.
    ///
    /// A mark already there keeps its first moment: retention is measured from when the result
    /// stopped coming back, not from the last time the caller asked. Past [`MAX_UNKNOWN`] the
    /// oldest mark is dropped — it is the trace nearest its own expiry, not a safety guarantee:
    /// the receiving machine's journal is what stops a repeat from running twice.
    pub(crate) fn mark_unknown(
        &self,
        peer: &PeerId,
        id: ActionId,
        now: Timestamp,
        since: Option<Timestamp>,
    ) -> Result<(), ActionError> {
        let _held = self.lock(peer)?;
        let mut file = self.read(peer)?;
        file.forget_before(since);
        trim(&mut file.unknown, now);
        if file.unknown.iter().any(|entry| entry.id == id) {
            return Ok(());
        }
        file.unknown.push(Entry {
            id,
            at: now,
            unknown: Vec::new(),
        });
        if file.unknown.len() > MAX_UNKNOWN {
            let excess = file.unknown.len() - MAX_UNKNOWN;
            file.unknown.drain(..excess);
        }
        self.write(peer, &file)
    }

    /// Whether `id` is marked unknown for `peer` and still inside its retention.
    pub(crate) fn is_unknown(
        &self,
        peer: &PeerId,
        id: ActionId,
        now: Timestamp,
        since: Option<Timestamp>,
    ) -> Result<bool, ActionError> {
        Ok(self
            .read(peer)?
            .unknown_from(since)
            .any(|entry| entry.id == id && entry.at.plus(ACTION_MEMORY_RETENTION) > now))
    }

    /// Every unknown mark for `peer` inside its retention, oldest first.
    pub(crate) fn unknown(
        &self,
        peer: &PeerId,
        now: Timestamp,
        since: Option<Timestamp>,
    ) -> Result<Vec<ActionMark>, ActionError> {
        Ok(self
            .read(peer)?
            .unknown_from(since)
            .filter(|entry| entry.at.plus(ACTION_MEMORY_RETENTION) > now)
            .map(|entry| ActionMark {
                id: entry.id,
                at: entry.at,
            })
            .collect())
    }

    /// Drop everything recorded before `since`, the peer's most recent withdrawal.
    ///
    /// The read-time filter already makes those entries absent; this is the compaction that
    /// keeps the file from holding them for ever. A memory with nothing before the withdrawal is
    /// neither locked nor rewritten, so a withdrawn peer that never acted gains no memory file
    /// and no writer's `<hex>.lock` beside it.
    pub(crate) fn sweep(&self, peer: &PeerId, since: Timestamp) -> Result<(), ActionError> {
        // A lock-free look first: the sweep runs every 30 s for every peer that was ever
        // withdrawn, and `last_withdrawn_at` stays after a return, so most rounds have nothing
        // to drop. A task that took its moment before the withdrawal can still write an entry
        // stamped before it just after the withdrawal; every read filters such an entry out and
        // the next sweep drops it, so skipping the lock here loses nothing.
        let seen = self.read(peer)?;
        if !holds_before(&seen, since) {
            return Ok(());
        }
        let _held = self.lock(peer)?;
        let mut file = self.read(peer)?;
        let before = (file.executed.len(), file.unknown.len());
        file.forget_before(Some(since));
        if (file.executed.len(), file.unknown.len()) == before {
            return Ok(());
        }
        self.write(peer, &file)
    }

    /// Read one peer's memory, or an empty one when the file is absent.
    fn read(&self, peer: &PeerId) -> Result<MemoryFile, ActionError> {
        store::read_coded(&self.files.path(peer))
    }

    /// Publish one peer's memory.
    fn write(&self, peer: &PeerId, file: &MemoryFile) -> Result<(), ActionError> {
        self.files.write_coded(peer, file)
    }

    fn lock(&self, peer: &PeerId) -> Result<store::Held<'_>, ActionError> {
        self.files.lock(peer).map_err(MemoryFile::fault)
    }
}

impl store::Coded for MemoryFile {
    const CAP: u64 = MAX_ACTIONS_BYTES;
    type Error = ActionError;

    fn absent() -> Self {
        Self::default()
    }

    fn encode(&self, path: &Path) -> Result<Vec<u8>, ActionError> {
        encode(self).map_err(|reason| malformed_at(path, reason))
    }

    fn decode(path: &Path, bytes: &[u8]) -> Result<Self, ActionError> {
        decode(bytes).map_err(|reason| malformed_at(path, reason))
    }

    fn malformed(path: &Path, reason: store::Malformed) -> ActionError {
        malformed_at(path, reason.into())
    }

    fn too_large(path: &Path, bytes: u64) -> ActionError {
        ActionError::TooLarge {
            path: path.to_owned(),
            bytes,
        }
    }

    fn fault(fault: Fault) -> ActionError {
        match fault {
            Fault::RootMissing(path) => ActionError::RootMissing { path },
            Fault::Io { path, source } => ActionError::Io { path, source },
            Fault::Insecure { path, reason } => ActionError::Insecure { path, reason },
            Fault::Busy(peer) => ActionError::Busy { peer },
        }
    }
}

impl From<store::Malformed> for ActionMalformed {
    fn from(reason: store::Malformed) -> Self {
        match reason {
            store::Malformed::Empty => Self::Empty,
            store::Malformed::TooLarge { bytes } => Self::TooLarge { bytes },
        }
    }
}

/// Forget entries past their retention.
fn trim(entries: &mut Vec<Entry>, now: Timestamp) {
    entries.retain(|entry| entry.at.plus(ACTION_MEMORY_RETENTION) > now);
}

/// The directory under `root` that holds the memories.
pub(super) fn dir_in(root: &Path) -> PathBuf {
    store::dir_in(root, DIR)
}

/// The memory file's path for `peer` inside `dir`.
pub(super) fn path_in(dir: &Path, peer: &PeerId) -> PathBuf {
    store::path_in(dir, peer, EXTENSION)
}

/// The lock file's path for `peer` inside `dir`.
pub(super) fn lock_in(dir: &Path, peer: &PeerId) -> PathBuf {
    store::lock_in(dir, peer)
}

/// The memory's bytes.
fn encode(file: &MemoryFile) -> Result<Vec<u8>, ActionMalformed> {
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(MAGIC);
    bytes.push(VERSION);
    for entry in &file.executed {
        put(&mut bytes, tag::EXECUTED, &entry_bytes(entry)?)?;
    }
    for entry in &file.unknown {
        put(&mut bytes, tag::UNKNOWN, &entry_bytes(entry)?)?;
    }
    for (tag, body) in &file.fields {
        put(&mut bytes, *tag, body)?;
    }
    Ok(bytes)
}

/// One entry's bytes.
fn entry_bytes(entry: &Entry) -> Result<Vec<u8>, ActionMalformed> {
    let mut body = Vec::with_capacity(32);
    put(&mut body, entry_tag::ID, entry.id.as_bytes())?;
    put(
        &mut body,
        entry_tag::AT,
        &entry.at.unix_seconds().to_be_bytes(),
    )?;
    for (tag, unknown) in &entry.unknown {
        put(&mut body, *tag, unknown)?;
    }
    Ok(body)
}

/// Read a memory from its bytes. A version above [`VERSION`] is read as this version's prefix;
/// its unknown fields are preserved.
fn decode(bytes: &[u8]) -> Result<MemoryFile, ActionMalformed> {
    let rest = bytes
        .strip_prefix(MAGIC)
        .ok_or(framing(FramingFault::Magic))?;
    let (&version, rest) = rest.split_first().ok_or(framing(FramingFault::Truncated))?;
    if version == 0 {
        return Err(framing(FramingFault::Version { found: version }));
    }
    let mut file = MemoryFile::default();
    for field in tlv::Fields::new(rest) {
        let (tag, body) = field.map_err(field_fault)?;
        match tag {
            tag::EXECUTED => file.executed.push(read_entry(body)?),
            tag::UNKNOWN => file.unknown.push(read_entry(body)?),
            _ => file.fields.push((tag, body.to_vec())),
        }
    }
    Ok(file)
}

/// One entry, from its bytes.
fn read_entry(bytes: &[u8]) -> Result<Entry, ActionMalformed> {
    let mut id = None;
    let mut at = None;
    let mut unknown = Vec::new();
    for field in tlv::Fields::new(bytes) {
        let (tag, body) = field.map_err(field_fault)?;
        match tag {
            entry_tag::ID => {
                id = Some(ActionId::from_bytes(
                    tlv::id_of(tag, body).map_err(field_fault)?,
                ));
            }
            entry_tag::AT => {
                at = Some(Timestamp::from_unix_seconds(
                    tlv::u64_of(tag, body).map_err(field_fault)?,
                ));
            }
            _ => unknown.push((tag, body.to_vec())),
        }
    }
    Ok(Entry {
        id: id.ok_or_else(|| {
            field_fault(tlv::FieldError {
                tag: entry_tag::ID,
                detail: "is missing",
            })
        })?,
        at: at.ok_or_else(|| {
            field_fault(tlv::FieldError {
                tag: entry_tag::AT,
                detail: "is missing",
            })
        })?,
        unknown,
    })
}

/// Append one field, refusing a body longer than a field can name.
fn put(bytes: &mut Vec<u8>, tag: u8, body: &[u8]) -> Result<(), ActionMalformed> {
    tlv::put(bytes, tag, body).map_err(|_| {
        framing(FramingFault::Field {
            tag,
            detail: "is longer than a field can name".to_owned(),
        })
    })
}

/// A framing fault as the file's own malformed reason.
fn framing(reason: FramingFault) -> ActionMalformed {
    ActionMalformed::Framing(reason)
}

/// One field's framing fault, in the file's vocabulary.
fn field_fault(error: tlv::FieldError) -> ActionMalformed {
    framing(FramingFault::Field {
        tag: error.tag,
        detail: error.detail.to_owned(),
    })
}

/// `reason` at `path`.
fn malformed_at(path: &Path, reason: ActionMalformed) -> ActionError {
    ActionError::Malformed {
        path: path.to_owned(),
        reason,
    }
}
