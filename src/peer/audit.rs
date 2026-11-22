//! The record of what happened: one append-only log under the storage root.
//!
//! # What it holds
//!
//! Every grant, every refusal, every ending, every withdrawal, every return, and the
//! clearing of a pairing attempt lock: what was decided, under whose rights, and
//! when. The moment is the caller's, like every other moment this crate records.
//!
//! # Why append-only
//!
//! A record is written before the thing it describes takes effect, so a crash may
//! leave a recorded act that did not happen and must never leave an act nobody
//! recorded. That order is what makes the log usable as the answer to "who allowed
//! this": a grant that is on file was decided, even if the write it preceded did not
//! land. Rewriting the file would lose that: a whole-file publish can lose a
//! concurrent writer's entry, and the record's own merge rules are for facts that
//! only ever grow.
//!
//! # The bytes
//!
//! `mahbot-peer-audit`, one version byte, then entries of `[len u32 big-endian]
//! [body]`, each body `[tag][len u16 big-endian][body]` fields: `0x01` the moment
//! (8, seconds) and `0x02` the act, itself `[code u8]` followed by the same field
//! form. An entry is written once and never touched again, so an older build loses
//! nothing by ignoring what it does not know: an unknown field is read past, an
//! unknown act code is kept as [`Act::Unrecognised`], and a code this build knows but
//! whose fields it cannot read — a newer build's shape of that act, or a capability
//! this build does not know — is kept as its code too. Only the frame decides what is
//! torn: a length that runs past the end of the file is a half-written entry, and
//! everything framed is complete.
//!
//! # The torn tail
//!
//! A crash can leave the last entry half written. Both places the log is opened for
//! writing find the first entry that is incomplete or malformed: opening the log, and
//! every append, under the same exclusive lock the write takes. If nothing follows
//! that entry it is a torn tail and the file is cut back to the last complete one — a
//! process that died mid-append must not make the next process's entry the corruption
//! that hides every entry after it. A malformed entry with complete entries after it
//! is corruption, not a torn write, and is refused rather than quietly skipped. An
//! entry whose length runs past the end of the file is a torn tail too: the length is
//! written in the same call as the body, and a partial write can stop anywhere. A
//! crash inside the log's own first write leaves less than the header, and the bytes
//! there are the header's prefix: the file is given a whole header, because a
//! half-written header that refused for ever would make the log — and with it every
//! right — impossible to open.
//!
//! # Privacy and concurrency
//!
//! The file is private to the account the product runs as, with the key file's rule,
//! and a file reachable by another account is refused. It is created through the same
//! private temporary file and publish as the key and the record, so it carries the
//! rule before its first byte lands. Every open — the create, the repair, each append,
//! each read — is held to the rule on the descriptor it then uses, so a log swapped
//! for a link or re-permissioned after it was created is refused instead of receiving
//! the next grant, refusal or person's name. Appends take an exclusive lock on the
//! file, so the two processes the self-update window keeps on one root cannot
//! interleave a write; reads take it shared, so a read cannot see an append half
//! written. The storage root's own privacy is the product's, and a root another
//! account can write is outside this crate's rule.
//!
//! # The cap, and the room a person keeps
//!
//! The log is not compacted or rotated. It holds at most [`MAX_FILE_BYTES`], and a
//! file past it is refused rather than read into memory. Within it, the bytes above
//! [`RESERVED_FOR_PERSON_BYTES`] below the cap are kept for a person's acts. The
//! entries a peer causes by asking — a refusal, a refused write, the ending a question
//! notices — are not written once they would reach into that reserve, while a grant, a
//! withdrawal, a trust withdrawal, a return and an attempt-lock clearing still are. So
//! a peer cannot fill the log and take away the acts that stop it, and a refusal that
//! cannot be written is still answered: nothing changes when a question is refused, so
//! the answer does not depend on the entry. An ending that cannot be written leaves its
//! row unmarked and refuses all the same — the term passed, and the row's own
//! `expires_at` names it. Nothing frees that room: the log is never compacted, so the
//! part a peer may fill only shrinks, and an ending or refusal skipped for want of room
//! stays unrecorded. A product at the cap must decide what to keep before a person's own
//! acts fill the reserve.
//!
//! A read is not a repair. [`AuditLog::open`] and every append cut a torn tail before
//! they judge the cap, because they hold the file for writing; [`AuditLog::entries`]
//! holds it shared and refuses a file past the cap instead. So a log another process
//! pushed past its cap by a torn write is readable again after the next open or append,
//! and not before.

use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::identity::PeerId;
use crate::identity::access::Insecurity;
use crate::peer::access::{Capability, Issuer, Label, Pair, PersonName};
use crate::peer::record::Timestamp;
use crate::peer::rights::{Refusal, Step};
use crate::peer::tlv;
use crate::private;

/// The file's name under the storage root.
const FILE_NAME: &str = "audit.log";

/// The bytes the log opens with.
const MAGIC: &[u8] = b"mahbot-peer-audit";

/// The log format this build writes. A higher version is read as this version's
/// prefix.
const VERSION: u8 = 1;

/// The most bytes one entry may have. A floor's reason is the only text that grows,
/// and it is the host's own sentence, not a document.
const MAX_ENTRY_BYTES: u32 = 16 * 1024;

/// The most bytes the whole log may have.
///
/// Past this the log is refused rather than read into memory, and a person's own act
/// that would pass it is refused until the product makes room; see the module docs.
pub const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// The bytes below [`MAX_FILE_BYTES`] that the entries a peer can cause may not use.
///
/// A peer causes an entry by asking — a refusal, a refused write, an ending a question
/// notices — and it can ask again and again, so those stop here, while a person's
/// grant, withdrawal, trust withdrawal, return or attempt-lock clearing may use the
/// whole file. One mebibyte is thousands of acts: far more than a person performs, and
/// small enough that the volume a peer can write is bounded.
pub const RESERVED_FOR_PERSON_BYTES: u64 = 1024 * 1024;

/// The most bytes of a floor's reason the log keeps.
///
/// The reason is the host's own sentence, not a document. A longer one is cut on a
/// character boundary for the record; the refusal the caller gets carries it whole.
const MAX_DETAIL_BYTES: usize = 1024;

/// The most bytes an opening reads: the cap, plus room for the one entry a torn write
/// can leave past it.
///
/// A crash can leave a partial entry, and a log that was just under the cap would then
/// be just over it. The tail is cut before the cap is judged, so the read has to reach
/// past the cap by as much as one entry and its length word.
const READ_LIMIT: u64 = MAX_FILE_BYTES + MAX_ENTRY_BYTES as u64 + 4;

/// The act codes. An unknown code is kept as [`Act::Unrecognised`].
mod code {
    pub const GRANTED: u8 = 1;
    pub const REFUSED: u8 = 2;
    pub const ENDED: u8 = 3;
    pub const WITHDRAWN: u8 = 4;
    pub const TRUST_WITHDRAWN: u8 = 5;
    pub const TRUST_RESTORED: u8 = 6;
    pub const ATTEMPT_LOCK_CLEARED: u8 = 7;
    pub const WRITE_REFUSED: u8 = 8;
}

/// The act body's field tags.
mod field_tag {
    pub const PEER: u8 = 0x01;
    pub const ASSISTANT: u8 = 0x02;
    pub const CAPABILITY: u8 = 0x03;
    pub const ISSUER: u8 = 0x04;
    pub const EXPIRY: u8 = 0x05;
    pub const PERSON: u8 = 0x06;
    pub const AT: u8 = 0x07;
    pub const STEP: u8 = 0x08;
    pub const REASON: u8 = 0x09;
    pub const DETAIL: u8 = 0x0a;
    pub const KIND: u8 = 0x0b;
    pub const REMOVED: u8 = 0x0c;
    pub const REMOTE: u8 = 0x0d;
    pub const WRITE_REFUSAL: u8 = 0x0e;
}

/// The entry body's field tags.
mod entry_tag {
    pub const AT: u8 = 0x01;
    pub const ACT: u8 = 0x02;
}

/// One thing that happened, and when the caller says it did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The moment, supplied by the caller.
    pub at: Timestamp,
    /// What was decided.
    pub act: Act,
}

/// What a write or a question decided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Act {
    /// A right was created, widened or restored.
    Granted {
        pair: Pair,
        capability: Capability,
        issuer: Issuer,
        expires_at: Option<Timestamp>,
        kind: GrantKind,
    },
    /// A question was refused, naming the step and the reason.
    Refused {
        pair: Pair,
        capability: Capability,
        refusal: Refusal,
    },
    /// A right's term passed and the ending is now on file.
    Ended { pair: Pair, capability: Capability },
    /// A person withdrew a right. The row stays, which is what stops the default
    /// re-creating it.
    Withdrawn {
        pair: Pair,
        capability: Capability,
        by: PersonName,
    },
    /// A person withdrew trust in a machine; `rights` is how many rows it held.
    TrustWithdrawn {
        peer: PeerId,
        by: PersonName,
        rights: usize,
    },
    /// A person restored a withdrawn machine, and the default issued again.
    TrustRestored { peer: PeerId, by: PersonName },
    /// A person cleared the pairing attempt lock.
    AttemptLockCleared { peer: PeerId, by: PersonName },
    /// A write was refused before it changed anything.
    WriteRefused {
        pair: Pair,
        capability: Capability,
        reason: WriteRefusal,
    },
    /// An act a newer build wrote: kept so nothing hides, never acted on.
    Unrecognised { code: u8 },
}

impl Act {
    /// Whether a question or a peer's write can cause this act.
    ///
    /// A refused question, a refused write and the ending a question notices are the
    /// acts a peer causes by asking: none of them changes a right, and a peer that
    /// keeps asking can cause another one each time — an ending that cannot be marked
    /// on the row is noticed again by the next question. Every other act is a person's,
    /// or the default's at a pair's coming-into-being, and is bounded by what the record
    /// holds. Only these stop at [`RESERVED_FOR_PERSON_BYTES`].
    #[must_use]
    pub(crate) const fn is_peer_driven(&self) -> bool {
        matches!(
            self,
            Self::Refused { .. } | Self::WriteRefused { .. } | Self::Ended { .. }
        )
    }
}

/// How a grant changed the pair's rights.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantKind {
    /// The pair had no row for the capability.
    Created,
    /// A live row's term or issuer changed.
    Widened,
    /// A withdrawn or ended row was restored.
    Restored,
    /// The default acted for a pair that already held the capability: nothing was
    /// written, and the marker is what stops it acting again.
    AlreadyHeld,
}

/// Why a write was refused.
///
/// One reason today, and a vocabulary rather than a bare key so a further reason costs
/// a variant and a byte without reshaping the record: the log keeps the reason, and a
/// reason a newer build wrote is kept as the act's code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WriteRefusal {
    /// The write was attributed to a peer. Only this machine's person may write a
    /// right.
    RemoteAuthority { peer: PeerId },
}

impl fmt::Display for WriteRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RemoteAuthority { peer } => write!(
                f,
                "a right cannot be attributed to {peer:?}: only this machine's own person may write one"
            ),
        }
    }
}

/// The append-only log of one storage root.
///
/// Cheap to clone: every clone names the same file. Nothing is held open between
/// calls, so a restart and a second process see the same log. Each handle remembers
/// the length it last left the log at, which is how an append checks only what
/// another writer added since instead of walking the whole file.
#[derive(Clone, Debug)]
pub struct AuditLog {
    path: PathBuf,
    /// The length this handle last saw the log whole at, or `None` when it does not
    /// know. An append reads only what follows it: a torn tail another process left
    /// is in that window, and the bytes before it were complete when this handle left
    /// them.
    known: Arc<Mutex<Option<u64>>>,
}

impl PartialEq for AuditLog {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
    }
}

impl Eq for AuditLog {}

impl AuditLog {
    /// The log's path under `root`.
    ///
    /// The log's name is this module's, so a caller that must name it without opening
    /// it — a repair, a backup, a case that tears it on purpose — asks here instead of
    /// spelling `audit.log`. Opening would create the file when it is absent and repair
    /// it when it is torn, which is not what such a caller is doing.
    #[must_use]
    pub fn path_in(root: &Path) -> PathBuf {
        root.join(FILE_NAME)
    }

    /// Open the log under `root`, creating it on the first start and cutting a torn
    /// tail back to the last complete entry.
    ///
    /// The root must exist and is never created. The file is created through a
    /// private temporary file and a publish that never replaces, so it carries the
    /// rule before its first byte lands and a log another process created in the same
    /// instant is that process's; a log that is already there is not replaced. Opening
    /// repairs, so it takes the write access a repair needs — a log on a read-only mount
    /// is refused, and [`Self::entries`] is the read that does not.
    ///
    /// A log reachable by another account is refused, never trusted.
    pub fn open(root: &Path) -> Result<Self, AuditError> {
        if !root.is_dir() {
            return Err(AuditError::RootMissing {
                path: root.to_owned(),
            });
        }
        let path = Self::path_in(root);
        // Created only when it is not there: an existing log is never replaced, and a
        // create that loses the race to another process leaves that process's file.
        if private::open_private(&path)
            .map_err(|error| opened_error(&path, error))?
            .is_none()
        {
            private::create_private(&path, ".audit.", &header())
                .map_err(|error| created_error(&path, error))?;
        }
        let log = Self {
            path,
            known: Arc::new(Mutex::new(None)),
        };
        log.repair()?;
        Ok(log)
    }

    /// The log's path under the root.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one entry, durably, before returning.
    ///
    /// The file is opened through the privacy rule and locked for the write, so the
    /// self-update window's two processes cannot interleave one and a log another
    /// account can reach is refused before a grant, a refusal or a person's name is
    /// written into it; the entry is flushed before the call returns, which is what
    /// puts it before the act it describes.
    ///
    /// A tail another process left half written is cut back before this one writes
    /// past it, so the entry this call writes is never the corruption that hides it.
    ///
    /// A refusal stops at [`RESERVED_FOR_PERSON_BYTES`] below the cap and is answered
    /// with [`AuditError::NoRoom`], which a caller that only answers a question may
    /// ignore: nothing changes when a question is refused, so the answer does not
    /// depend on the entry. A person's act may use the whole file, and one that would
    /// pass [`MAX_FILE_BYTES`] is refused with [`AuditError::TooLarge`] until the
    /// product makes room — an unrecorded withdrawal would be an act nobody recorded.
    pub(crate) fn append(&self, entry: &Entry) -> Result<(), AuditError> {
        let body = encode_entry(entry).map_err(|detail| AuditError::Malformed {
            path: self.path.clone(),
            detail,
        })?;
        let length = u32::try_from(body.len()).map_err(|_| AuditError::TooLarge {
            path: self.path.clone(),
            bytes: body.len() as u64,
            cap: u64::from(MAX_ENTRY_BYTES),
        })?;
        if length > MAX_ENTRY_BYTES {
            return Err(AuditError::TooLarge {
                path: self.path.clone(),
                bytes: u64::from(length),
                cap: u64::from(MAX_ENTRY_BYTES),
            });
        }
        let mut framed = Vec::with_capacity(body.len() + 4);
        framed.extend_from_slice(&length.to_be_bytes());
        framed.extend_from_slice(&body);
        let mut file = self.opened(private::repair_private(&self.path))?;
        file.lock().map_err(|source| AuditError::Io {
            path: self.path.clone(),
            source,
        })?;
        let real = self.length(&file)?;
        // A log longer than one torn entry past its cap is not a torn write: it is
        // refused rather than walked, so a hostile file cannot make this allocate.
        if real > READ_LIMIT {
            return Err(AuditError::TooLarge {
                path: self.path.clone(),
                bytes: real,
                cap: MAX_FILE_BYTES,
            });
        }
        let whole = self.whole(&mut file, real, self.delta(real))?;
        // What the walk found whole is the baseline whatever happens next: a tail it
        // cut is gone, so the next append must not walk past it again.
        self.remember(whole);
        let total = whole.saturating_add(framed.len() as u64);
        if total > MAX_FILE_BYTES {
            return Err(AuditError::TooLarge {
                path: self.path.clone(),
                bytes: total,
                cap: MAX_FILE_BYTES,
            });
        }
        if entry.act.is_peer_driven() && total > MAX_FILE_BYTES - RESERVED_FOR_PERSON_BYTES {
            return Err(AuditError::NoRoom {
                path: self.path.clone(),
                kept: RESERVED_FOR_PERSON_BYTES,
            });
        }
        file.seek(SeekFrom::Start(whole))
            .map_err(|source| AuditError::Io {
                path: self.path.clone(),
                source,
            })?;
        if let Err(source) = file.write_all(&framed) {
            // A partial write would leave a torn entry with nothing after it, which the
            // next append or open cuts back; cutting it here keeps the log readable for
            // the appends that follow if the space is freed.
            let _ = file.set_len(whole);
            return Err(AuditError::Io {
                path: self.path.clone(),
                source,
            });
        }
        file.sync_all().map_err(|source| AuditError::Io {
            path: self.path.clone(),
            source,
        })?;
        self.remember(total);
        Ok(())
    }

    /// Every complete entry, in the order they were written.
    pub fn entries(&self) -> Result<Vec<Entry>, AuditError> {
        let file = self.opened(private::open_private(&self.path))?;
        // Shared: a read that raced an append would see the entry half written and
        // report a tail the writer is about to complete.
        file.lock_shared().map_err(|source| AuditError::Io {
            path: self.path.clone(),
            source,
        })?;
        let bytes = capped(file, MAX_FILE_BYTES, &self.path)?;
        let (_, body) = split_header(&bytes, &self.path)?;
        let (entries, _) = walk_entries(body, &self.path, true)?;
        Ok(entries)
    }

    /// Cut a torn tail back to the last complete entry, and refuse corruption.
    ///
    /// A file that holds less than the header is a create that was interrupted inside
    /// the header — the bytes written so far are the header's own prefix, because one
    /// `write_all` wrote them — and it holds no entry, so it is given the header rather
    /// than refused. A file whose bytes are not the header's prefix is corruption.
    ///
    /// The cut comes before the cap is judged: a torn tail can push a log that was
    /// under the cap past it, and refusing that log would make it unopenable for ever.
    /// The file is read up to [`READ_LIMIT`], which is as far past the cap as a torn
    /// write can reach.
    fn repair(&self) -> Result<(), AuditError> {
        let mut file = self.opened(private::repair_private(&self.path))?;
        file.lock().map_err(|source| AuditError::Io {
            path: self.path.clone(),
            source,
        })?;
        let real = self.length(&file)?;
        if real > READ_LIMIT {
            return Err(AuditError::TooLarge {
                path: self.path.clone(),
                bytes: real,
                cap: MAX_FILE_BYTES,
            });
        }
        let whole = self.whole(&mut file, real, 0)?;
        self.remember(whole);
        if whole > MAX_FILE_BYTES {
            return Err(AuditError::TooLarge {
                path: self.path.clone(),
                bytes: whole,
                cap: MAX_FILE_BYTES,
            });
        }
        Ok(())
    }

    /// Cut what follows `from` back to the last complete entry, and answer the length
    /// the log is whole at.
    ///
    /// `from` is a length this handle last saw the log whole at, or zero to walk the
    /// whole file, and `length` is where the file ends — both callers hold the lock and
    /// refuse a file past [`READ_LIMIT`] first, so the walk always reaches the end. A
    /// file shorter than the header whose bytes are the header's own prefix is a create
    /// that was interrupted inside it: it holds no entry, so it is given a whole header
    /// rather than refused. A file whose bytes are not the header's prefix is corruption.
    fn whole(&self, file: &mut File, length: u64, from: u64) -> Result<u64, AuditError> {
        let tail = length.saturating_sub(from);
        let mut bytes = Vec::with_capacity(usize::try_from(tail).unwrap_or(0));
        file.seek(SeekFrom::Start(from))
            .map_err(|source| AuditError::Io {
                path: self.path.clone(),
                source,
            })?;
        (&mut *file)
            .take(tail)
            .read_to_end(&mut bytes)
            .map_err(|source| AuditError::Unreadable {
                path: self.path.clone(),
                source,
            })?;
        if from == 0 && bytes.len() < MAGIC.len() + 1 && MAGIC.starts_with(&bytes) {
            let header = header();
            file.set_len(0).map_err(|source| AuditError::Io {
                path: self.path.clone(),
                source,
            })?;
            file.seek(SeekFrom::Start(0))
                .map_err(|source| AuditError::Io {
                    path: self.path.clone(),
                    source,
                })?;
            file.write_all(&header).map_err(|source| AuditError::Io {
                path: self.path.clone(),
                source,
            })?;
            file.sync_all().map_err(|source| AuditError::Io {
                path: self.path.clone(),
                source,
            })?;
            return Ok(header.len() as u64);
        }
        let (base, body) = if from == 0 {
            let (header, body) = split_header(&bytes, &self.path)?;
            (header as u64, body)
        } else {
            (from, &bytes[..])
        };
        let (_, torn) = walk_entries(body, &self.path, false)?;
        let Some(offset) = torn else {
            return Ok(length);
        };
        let whole = base + offset as u64;
        file.set_len(whole).map_err(|source| AuditError::Io {
            path: self.path.clone(),
            source,
        })?;
        file.sync_all().map_err(|source| AuditError::Io {
            path: self.path.clone(),
            source,
        })?;
        Ok(whole)
    }

    /// The log's length on disk.
    fn length(&self, file: &File) -> Result<u64, AuditError> {
        file.metadata()
            .map(|metadata| metadata.len())
            .map_err(|source| AuditError::Io {
                path: self.path.clone(),
                source,
            })
    }

    /// Where this handle's own check of the log starts: the length it last left the
    /// log at, or the start of the file when it does not know, when that length is
    /// gone or when the file shrank under it.
    fn delta(&self, length: u64) -> u64 {
        match *self.known.lock().expect("the log's length is not poisoned") {
            Some(known) if known <= length => known,
            _ => 0,
        }
    }

    /// Remember the length this handle last saw the log whole at.
    fn remember(&self, length: u64) {
        *self.known.lock().expect("the log's length is not poisoned") = Some(length);
    }

    /// Open the log through the privacy rule, naming this module's errors.
    ///
    /// Every open — the read, the append, the repair — goes through the rule on the
    /// descriptor it then uses, so a log swapped for a link or re-permissioned after
    /// it was created is refused rather than read from or written into.
    fn opened(
        &self,
        opening: Result<Option<File>, private::PrivateFileError>,
    ) -> Result<File, AuditError> {
        match opening {
            Ok(Some(file)) => Ok(file),
            Ok(None) => Err(AuditError::Unreadable {
                path: self.path.clone(),
                source: io::Error::new(io::ErrorKind::NotFound, "the log is gone"),
            }),
            Err(error) => Err(opened_error(&self.path, error)),
        }
    }
}

/// The log's bytes, held to `cap`: one byte more is read, so a file past the cap is
/// refused with the size it holds.
fn capped(file: File, cap: u64, path: &Path) -> Result<Vec<u8>, AuditError> {
    let (bytes, length) =
        private::read_capped(file, cap + 1).map_err(|source| AuditError::Unreadable {
            path: path.to_owned(),
            source,
        })?;
    if length.is_some_and(|length| length > cap) || bytes.len() as u64 > cap {
        return Err(AuditError::TooLarge {
            path: path.to_owned(),
            bytes: length.unwrap_or(bytes.len() as u64),
            cap,
        });
    }
    Ok(bytes)
}

/// A private open's refusal, named as this module's.
fn opened_error(path: &Path, error: private::PrivateFileError) -> AuditError {
    match error {
        private::PrivateFileError::Insecure(reason) => AuditError::Insecure {
            path: path.to_owned(),
            reason,
        },
        private::PrivateFileError::Io(source) => AuditError::Unreadable {
            path: path.to_owned(),
            source,
        },
    }
}

/// A private create's refusal, named as this module's: a create that failed could not
/// write, which is not the same as a log that cannot be read.
fn created_error(path: &Path, error: private::PrivateFileError) -> AuditError {
    match error {
        private::PrivateFileError::Insecure(reason) => AuditError::Insecure {
            path: path.to_owned(),
            reason,
        },
        private::PrivateFileError::Io(source) => AuditError::Io {
            path: path.to_owned(),
            source,
        },
    }
}

/// The bytes the log opens with: the magic and this build's version.
fn header() -> Vec<u8> {
    let mut header = Vec::with_capacity(MAGIC.len() + 1);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header
}

/// Split the header off, answering its length and the entries' bytes.
fn split_header<'a>(bytes: &'a [u8], path: &Path) -> Result<(usize, &'a [u8]), AuditError> {
    let rest = bytes
        .strip_prefix(MAGIC)
        .ok_or_else(|| AuditError::Malformed {
            path: path.to_owned(),
            detail: "the file does not open with the log magic".to_owned(),
        })?;
    let (&version, body) = rest.split_first().ok_or_else(|| AuditError::Malformed {
        path: path.to_owned(),
        detail: "the file has no version byte".to_owned(),
    })?;
    if version == 0 {
        return Err(AuditError::Malformed {
            path: path.to_owned(),
            detail: format!("the version byte is {version}, which is not a log"),
        });
    }
    Ok((MAGIC.len() + 1, body))
}

/// Walk every complete entry, validating each, and answer them when `keep` says so plus
/// the offset of a torn tail.
///
/// A malformed entry with complete entries after it is corruption: it is refused. Only
/// the last entry may be incomplete, and its offset is what [`AuditLog::repair`] cuts
/// back to. A caller that only needs the offset passes `keep: false`, so a dense log —
/// hundreds of thousands of small entries — is validated without a vector of them.
fn walk_entries(
    body: &[u8],
    path: &Path,
    keep: bool,
) -> Result<(Vec<Entry>, Option<usize>), AuditError> {
    let mut entries = Vec::new();
    let mut rest = body;
    let mut offset = 0;
    while !rest.is_empty() {
        let Some((&length, after)) = rest.split_first_chunk::<4>() else {
            return Ok((entries, Some(offset)));
        };
        let length = u32::from_be_bytes(length);
        if length == 0 || length > MAX_ENTRY_BYTES {
            // A complete length word this build never writes is corruption: a partial
            // write can only leave fewer than four bytes, or a body short of the length
            // those four name.
            return Err(AuditError::Malformed {
                path: path.to_owned(),
                detail: format!("the entry at byte {offset} names a length of {length}"),
            });
        }
        let length = length as usize;
        let Some((entry, after)) = after.split_at_checked(length) else {
            return Ok((entries, Some(offset)));
        };
        let entry = decode_entry(entry).map_err(|detail| AuditError::Malformed {
            path: path.to_owned(),
            detail,
        })?;
        if keep {
            entries.push(entry);
        }
        rest = after;
        offset += 4 + length;
    }
    Ok((entries, None))
}

/// Append one `[tag][len u16 big-endian][body]` field.
fn put_field(bytes: &mut Vec<u8>, tag: u8, body: &[u8]) -> Result<(), String> {
    tlv::put(bytes, tag, body).map_err(|_| "a field is longer than 65535 bytes".to_owned())
}

/// The fields one act body carries, as they were read.
#[derive(Default)]
struct Fields {
    peer: Option<PeerId>,
    assistant: Option<Label>,
    capability: Option<Capability>,
    issuer: Option<Issuer>,
    expiry: Option<Timestamp>,
    person: Option<PersonName>,
    at: Option<Timestamp>,
    step: Option<Step>,
    reason: Option<u8>,
    detail: Option<String>,
    kind: Option<GrantKind>,
    removed: Option<usize>,
    remote: Option<PeerId>,
    write_refusal: Option<u8>,
}

impl Fields {
    fn decode(body: &[u8]) -> Result<Self, String> {
        let mut fields = Self::default();
        for field in tlv::Fields::new(body) {
            let (tag, body) = field.map_err(|error| field_detail(error.tag, error.detail))?;
            match tag {
                field_tag::PEER => fields.peer = Some(read_peer(tag, body)?),
                field_tag::ASSISTANT => fields.assistant = Some(read_label(tag, body)?),
                field_tag::CAPABILITY => {
                    fields.capability = Some(Capability::from_raw(one_byte(tag, body)?));
                }
                field_tag::ISSUER => {
                    let (&kind, rest) = body
                        .split_first()
                        .ok_or_else(|| field_detail(tag, "is empty"))?;
                    fields.issuer = Some(match kind {
                        1 => Issuer::Default,
                        2 => Issuer::Person(PersonName::from_label(read_label(tag, rest)?)),
                        other => {
                            return Err(field_detail(tag, &format!("has kind {other}")));
                        }
                    });
                }
                field_tag::EXPIRY => fields.expiry = Some(read_moment(tag, body)?),
                field_tag::PERSON => {
                    fields.person = Some(PersonName::from_label(read_label(tag, body)?));
                }
                field_tag::AT => fields.at = Some(read_moment(tag, body)?),
                field_tag::STEP => {
                    fields.step = match one_byte(tag, body)? {
                        1 => Some(Step::Authenticate),
                        2 => Some(Step::Right),
                        3 => Some(Step::Floor),
                        other => return Err(field_detail(tag, &format!("is {other}"))),
                    };
                }
                field_tag::REASON => {
                    fields.reason = Some(one_byte(tag, body)?);
                }
                field_tag::DETAIL => {
                    fields.detail = Some(
                        std::str::from_utf8(body)
                            .map_err(|_| field_detail(tag, "is not UTF-8"))?
                            .to_owned(),
                    );
                }
                field_tag::KIND => {
                    fields.kind = Some(match one_byte(tag, body)? {
                        1 => GrantKind::Created,
                        2 => GrantKind::Widened,
                        3 => GrantKind::Restored,
                        4 => GrantKind::AlreadyHeld,
                        other => return Err(field_detail(tag, &format!("is {other}"))),
                    });
                }
                field_tag::REMOVED => {
                    let bytes: [u8; 4] = body
                        .try_into()
                        .map_err(|_| field_detail(tag, "is not four bytes"))?;
                    fields.removed = Some(u32::from_be_bytes(bytes) as usize);
                }
                field_tag::REMOTE => fields.remote = Some(read_peer(tag, body)?),
                field_tag::WRITE_REFUSAL => {
                    fields.write_refusal = Some(one_byte(tag, body)?);
                }
                // An act field a newer build wrote: read past it, keep the rest.
                _ => {}
            }
        }
        Ok(fields)
    }

    fn pair(&self) -> Result<Pair, String> {
        let peer = self.peer.ok_or("the act names no machine")?;
        let assistant = self.assistant.clone().ok_or("the act names no assistant")?;
        Ok(Pair::from_parts(peer, assistant))
    }

    fn capability(&self) -> Result<Capability, String> {
        self.capability
            .ok_or_else(|| "the act names no capability".to_owned())
    }

    fn person(&self) -> Result<PersonName, String> {
        self.person
            .clone()
            .ok_or_else(|| "the act names no person".to_owned())
    }

    fn at(&self) -> Result<Timestamp, String> {
        self.at.ok_or_else(|| "the act names no moment".to_owned())
    }
}

fn field_detail(tag: u8, detail: &str) -> String {
    format!("act field {tag:#04x} {detail}")
}

/// One byte, or the act field's refusal naming the tag.
fn one_byte(tag: u8, body: &[u8]) -> Result<u8, String> {
    let [byte] = body else {
        return Err(field_detail(tag, "is not one byte"));
    };
    Ok(*byte)
}

fn read_peer(tag: u8, body: &[u8]) -> Result<PeerId, String> {
    let bytes: [u8; crate::identity::PEER_ID_LEN] = body
        .try_into()
        .map_err(|_| field_detail(tag, "is not a 32-byte key"))?;
    Ok(PeerId::from_bytes(bytes))
}

/// One label field whole, or the act field's refusal naming the tag.
fn read_label(tag: u8, body: &[u8]) -> Result<Label, String> {
    Label::decode_whole(body).map_err(|detail| field_detail(tag, &detail))
}

fn read_moment(tag: u8, body: &[u8]) -> Result<Timestamp, String> {
    let bytes: [u8; 8] = body
        .try_into()
        .map_err(|_| field_detail(tag, "is not eight bytes"))?;
    Ok(Timestamp::from_unix_seconds(u64::from_be_bytes(bytes)))
}

/// One entry's body: the moment and the act.
fn encode_entry(entry: &Entry) -> Result<Vec<u8>, String> {
    let mut body = Vec::with_capacity(48);
    put_field(
        &mut body,
        entry_tag::AT,
        &entry.at.unix_seconds().to_be_bytes(),
    )?;
    let mut act = Vec::with_capacity(40);
    match &entry.act {
        Act::Granted {
            pair,
            capability,
            issuer,
            expires_at,
            kind,
        } => {
            act.push(code::GRANTED);
            put_capability(&mut act, pair, *capability)?;
            put_issuer(&mut act, issuer)?;
            if let Some(expires_at) = expires_at {
                put_field(
                    &mut act,
                    field_tag::EXPIRY,
                    &expires_at.unix_seconds().to_be_bytes(),
                )?;
            }
            put_field(&mut act, field_tag::KIND, &[grant_kind_byte(*kind)])?;
        }
        Act::Refused {
            pair,
            capability,
            refusal,
        } => {
            act.push(code::REFUSED);
            put_refusal(&mut act, pair, *capability, refusal)?;
        }
        Act::Ended { pair, capability } => {
            act.push(code::ENDED);
            put_capability(&mut act, pair, *capability)?;
        }
        Act::Withdrawn {
            pair,
            capability,
            by,
        } => {
            act.push(code::WITHDRAWN);
            put_capability(&mut act, pair, *capability)?;
            put_person(&mut act, by)?;
        }
        Act::TrustWithdrawn { peer, by, rights } => {
            act.push(code::TRUST_WITHDRAWN);
            put_field(&mut act, field_tag::PEER, peer.as_bytes())?;
            put_person(&mut act, by)?;
            let removed = u32::try_from(*rights).unwrap_or(u32::MAX);
            put_field(&mut act, field_tag::REMOVED, &removed.to_be_bytes())?;
        }
        Act::TrustRestored { peer, by } => {
            act.push(code::TRUST_RESTORED);
            put_field(&mut act, field_tag::PEER, peer.as_bytes())?;
            put_person(&mut act, by)?;
        }
        Act::AttemptLockCleared { peer, by } => {
            act.push(code::ATTEMPT_LOCK_CLEARED);
            put_field(&mut act, field_tag::PEER, peer.as_bytes())?;
            put_person(&mut act, by)?;
        }
        Act::WriteRefused {
            pair,
            capability,
            reason,
        } => {
            act.push(code::WRITE_REFUSED);
            put_capability(&mut act, pair, *capability)?;
            let (refusal, remote) = match reason {
                WriteRefusal::RemoteAuthority { peer } => (1, Some(peer)),
            };
            put_field(&mut act, field_tag::WRITE_REFUSAL, &[refusal])?;
            if let Some(remote) = remote {
                put_field(&mut act, field_tag::REMOTE, remote.as_bytes())?;
            }
        }
        Act::Unrecognised { code } => act.push(*code),
    }
    put_field(&mut body, entry_tag::ACT, &act)?;
    Ok(body)
}

/// Append a refusal: its step, its reason, and the moment or the floor's words.
fn put_refusal(
    act: &mut Vec<u8>,
    pair: &Pair,
    capability: Capability,
    refusal: &Refusal,
) -> Result<(), String> {
    put_capability(act, pair, capability)?;
    put_field(act, field_tag::STEP, &[step_byte(refusal.step())])?;
    let reason = match refusal {
        Refusal::NotAuthenticated => 1,
        Refusal::Untrusted => 2,
        Refusal::NoRight => 3,
        Refusal::Withdrawn { .. } => 4,
        Refusal::Ended { .. } => 5,
        Refusal::Floor { .. } => 6,
    };
    put_field(act, field_tag::REASON, &[reason])?;
    match refusal {
        Refusal::Withdrawn { at } | Refusal::Ended { at } => {
            put_field(act, field_tag::AT, &at.unix_seconds().to_be_bytes())?;
        }
        Refusal::Floor { reason } => {
            put_field(act, field_tag::DETAIL, detail_bytes(reason))?;
        }
        Refusal::NotAuthenticated | Refusal::Untrusted | Refusal::NoRight => {}
    }
    Ok(())
}

/// A reason as the log keeps it: at most [`MAX_DETAIL_BYTES`], cut on a character
/// boundary.
fn detail_bytes(reason: &str) -> &[u8] {
    if reason.len() <= MAX_DETAIL_BYTES {
        return reason.as_bytes();
    }
    let mut end = MAX_DETAIL_BYTES;
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    &reason.as_bytes()[..end]
}

fn put_pair(bytes: &mut Vec<u8>, pair: &Pair) -> Result<(), String> {
    put_field(bytes, field_tag::PEER, pair.peer().as_bytes())?;
    let mut label = Vec::new();
    pair.assistant().encode_into(&mut label);
    put_field(bytes, field_tag::ASSISTANT, &label)
}

/// Append the pair and the capability the act names.
fn put_capability(bytes: &mut Vec<u8>, pair: &Pair, capability: Capability) -> Result<(), String> {
    put_pair(bytes, pair)?;
    put_field(bytes, field_tag::CAPABILITY, &[capability.as_byte()])
}

/// Append the acting person's label as the act's person field.
fn put_person(bytes: &mut Vec<u8>, person: &PersonName) -> Result<(), String> {
    let mut label = Vec::new();
    person.label().encode_into(&mut label);
    put_field(bytes, field_tag::PERSON, &label)
}

fn put_issuer(bytes: &mut Vec<u8>, issuer: &Issuer) -> Result<(), String> {
    let mut body = Vec::new();
    match issuer {
        Issuer::Default => body.push(1),
        Issuer::Person(person) => {
            body.push(2);
            person.label().encode_into(&mut body);
        }
    }
    put_field(bytes, field_tag::ISSUER, &body)
}

const fn grant_kind_byte(kind: GrantKind) -> u8 {
    match kind {
        GrantKind::Created => 1,
        GrantKind::Widened => 2,
        GrantKind::Restored => 3,
        GrantKind::AlreadyHeld => 4,
    }
}

const fn step_byte(step: Step) -> u8 {
    match step {
        Step::Authenticate => 1,
        Step::Right => 2,
        Step::Floor => 3,
    }
}

/// One entry's body, back to an [`Entry`].
fn decode_entry(body: &[u8]) -> Result<Entry, String> {
    let mut at = None;
    let mut act = None;
    for field in tlv::Fields::new(body) {
        let (tag, body) =
            field.map_err(|error| format!("entry field {:#04x} {}", error.tag, error.detail))?;
        match tag {
            entry_tag::AT => at = Some(read_moment(tag, body)?),
            entry_tag::ACT => act = Some(decode_act(body)?),
            _ => {}
        }
    }
    Ok(Entry {
        at: at.ok_or("the entry names no moment")?,
        act: act.ok_or("the entry names no act")?,
    })
}

fn decode_act(body: &[u8]) -> Result<Act, String> {
    let (&code, fields) = body.split_first().ok_or("the act names no code")?;
    if code == 0 {
        return Err("the act code is zero".to_owned());
    }
    if !(code::GRANTED..=code::WRITE_REFUSED).contains(&code) {
        return Ok(Act::Unrecognised { code });
    }
    // A code this build knows but whose fields it cannot read is a newer build's
    // shape of that act: it is kept as its code, never guessed and never dropped.
    Ok(decode_known_act(code, fields).unwrap_or(Act::Unrecognised { code }))
}

/// One act this build knows, from the fields it wrote.
fn decode_known_act(code: u8, fields: &[u8]) -> Result<Act, String> {
    let fields = Fields::decode(fields)?;
    match code {
        code::GRANTED => Ok(Act::Granted {
            pair: fields.pair()?,
            capability: fields.capability()?,
            issuer: fields.issuer.clone().ok_or("the grant names no issuer")?,
            expires_at: fields.expiry,
            kind: fields.kind.ok_or("the grant names no kind")?,
        }),
        code::REFUSED => {
            let step = fields.step.ok_or("the refusal names no step")?;
            let reason = fields.reason.ok_or("the refusal names no reason")?;
            let refusal = match (step, reason) {
                (Step::Authenticate, 1) => Refusal::NotAuthenticated,
                (Step::Authenticate, 2) => Refusal::Untrusted,
                (Step::Right, 3) => Refusal::NoRight,
                (Step::Right, 4) => Refusal::Withdrawn { at: fields.at()? },
                (Step::Right, 5) => Refusal::Ended { at: fields.at()? },
                (Step::Floor, 6) => Refusal::Floor {
                    reason: fields.detail.clone().unwrap_or_default(),
                },
                (step, reason) => {
                    return Err(format!(
                        "the refusal's step {step:?} and reason {reason} do not go together"
                    ));
                }
            };
            Ok(Act::Refused {
                pair: fields.pair()?,
                capability: fields.capability()?,
                refusal,
            })
        }
        code::ENDED => Ok(Act::Ended {
            pair: fields.pair()?,
            capability: fields.capability()?,
        }),
        code::WITHDRAWN => Ok(Act::Withdrawn {
            pair: fields.pair()?,
            capability: fields.capability()?,
            by: fields.person()?,
        }),
        code::TRUST_WITHDRAWN => Ok(Act::TrustWithdrawn {
            peer: fields.peer.ok_or("the act names no machine")?,
            by: fields.person()?,
            rights: fields.removed.ok_or("the act names no count")?,
        }),
        code::TRUST_RESTORED => Ok(Act::TrustRestored {
            peer: fields.peer.ok_or("the act names no machine")?,
            by: fields.person()?,
        }),
        code::ATTEMPT_LOCK_CLEARED => Ok(Act::AttemptLockCleared {
            peer: fields.peer.ok_or("the act names no machine")?,
            by: fields.person()?,
        }),
        code::WRITE_REFUSED => {
            let reason = match fields.write_refusal.ok_or("the refusal names no reason")? {
                1 => WriteRefusal::RemoteAuthority {
                    peer: fields.remote.ok_or("the refusal names no machine")?,
                },
                other => return Err(format!("the write refusal is {other}")),
            };
            Ok(Act::WriteRefused {
                pair: fields.pair()?,
                capability: fields.capability()?,
                reason,
            })
        }
        _ => Ok(Act::Unrecognised { code }),
    }
}

/// Why the log could not be read, written or believed.
#[derive(Debug)]
pub enum AuditError {
    /// The storage root does not exist. It is never created here.
    RootMissing { path: PathBuf },
    /// The operating system could not read the file.
    Unreadable { path: PathBuf, source: io::Error },
    /// The file is reachable by an account the rule does not allow.
    Insecure { path: PathBuf, reason: Insecurity },
    /// The bytes are not a log, or an entry is corrupt.
    Malformed { path: PathBuf, detail: String },
    /// A write or a read failed.
    Io { path: PathBuf, source: io::Error },
    /// The file or one entry is past its cap.
    ///
    /// `bytes` is what the file holds, or what it would hold with the entry the caller
    /// tried to write; `cap` is the limit it passes.
    TooLarge { path: PathBuf, bytes: u64, cap: u64 },
    /// The entry would use bytes the log keeps for a person's acts.
    ///
    /// Only an entry a peer causes by asking — a refusal, a refused write, an ending a
    /// question notices — is refused this way, and nothing a peer asks changes anything,
    /// so a caller that only answers a question may carry on without the entry.
    NoRoom { path: PathBuf, kept: u64 },
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootMissing { path } => write!(
                f,
                "{} does not exist: the storage root is never created here",
                path.display()
            ),
            Self::Unreadable { path, source } => {
                write!(f, "{} cannot be read: {source}", path.display())
            }
            Self::Insecure { path, reason } => {
                write!(f, "{} is not private: {reason}", path.display())?;
                if let Some(remedy) = reason.remedy(path) {
                    write!(f, "; {remedy}")?;
                }
                Ok(())
            }
            Self::Malformed { path, detail } => {
                write!(
                    f,
                    "{} cannot be framed as an audit log: {detail}",
                    path.display()
                )
            }
            Self::Io { path, source } => {
                write!(f, "{} cannot be written: {source}", path.display())
            }
            Self::TooLarge { path, bytes, cap } => write!(
                f,
                "{} needs {bytes} bytes, more than the {cap} it may have",
                path.display()
            ),
            Self::NoRoom { path, kept } => write!(
                f,
                "{} has no room for a peer's entry: {kept} bytes are kept for a person's acts",
                path.display()
            ),
        }
    }
}

impl std::error::Error for AuditError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Unreadable { source, .. } | Self::Io { source, .. } => Some(source),
            Self::RootMissing { .. }
            | Self::Insecure { .. }
            | Self::Malformed { .. }
            | Self::TooLarge { .. }
            | Self::NoRoom { .. } => None,
        }
    }
}
