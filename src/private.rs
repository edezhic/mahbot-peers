//! The one way this crate publishes a private file: a temporary file beside the
//! destination, given the rule and checked, flushed, and published by one rename.
//!
//! The key file, the peer record, the audit log's creation, the message queues and the
//! action memories all write this way, and all read through the same checked open, so the
//! ordering that keeps a private half out of the wrong access has one spelling: a file is
//! private before its first byte lands, not made private afterwards. The log is only
//! *created* this way — it is appended in place, because an append-only record cannot be
//! rewritten without losing a concurrent writer's entry, so its appends are opened,
//! checked and written through the same descriptor, and `peer::audit` states the lock
//! and the flush that make them safe. The rule itself is `identity::access`; this
//! module only applies it around the write and the read.
//!
//! The directories this crate keeps under a root — `peers/`, `messages/` and `actions/` —
//! are made and checked by the one function here too: a directory another account can
//! write lets it delete what this crate keeps, which is a silent un-pairing, so a directory
//! this crate creates is hardened before it is checked and one it finds is checked.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

use crate::identity::access::{self, Insecurity, Opening};

/// A private file could not be opened, checked or created: the operating system's
/// refusal, or the access rule's.
///
/// One type for both, so the one open-check-and-create sequence the crate uses for
/// its private files has one spelling and each caller maps it to its own error.
pub(crate) enum PrivateFileError {
    Io(io::Error),
    Insecure(Insecurity),
}

/// Open a private file and hold it to the rule; `None` when nothing is there.
pub(crate) fn open_private(path: &Path) -> Result<Option<File>, PrivateFileError> {
    held(access::open(path, OpenOptions::new().read(true)))
}

/// The open the audit log uses for both its repair and its append: the log is cut
/// back and written through the descriptor the rule was checked on.
///
/// An append is a write at the end after the lock is taken, and a torn tail another
/// process left is cut before this one writes past it, so the handle needs write as
/// well as read. It is opened for reading because the check reads the file's own
/// access list from the handle, which a write-only handle on Windows does not grant.
pub(crate) fn repair_private(path: &Path) -> Result<Option<File>, PrivateFileError> {
    held(access::open(
        path,
        OpenOptions::new().read(true).write(true),
    ))
}

/// Hold an opened descriptor to the rule, so what is checked and what is used are
/// the same file whatever a link or a rename did in between.
fn held(opening: io::Result<Opening>) -> Result<Option<File>, PrivateFileError> {
    let file = match opening {
        Ok(Opening::File(file)) => file,
        Ok(Opening::Absent) => return Ok(None),
        Ok(Opening::Refused(reason)) => return Err(PrivateFileError::Insecure(reason)),
        Err(source) => return Err(PrivateFileError::Io(source)),
    };
    match access::check(&file) {
        Ok(Some(reason)) => Err(PrivateFileError::Insecure(reason)),
        Ok(None) => Ok(Some(file)),
        Err(source) => Err(PrivateFileError::Io(source)),
    }
}

/// A temporary file beside `path`, already carrying the rule and checked.
///
/// Nothing is written into it until this returns: on Windows the temporary file
/// inherits the directory's list until `access::make_private` replaces it, and the
/// private half must not sit behind that list even for an instant.
pub(crate) fn private_temp(
    path: &Path,
    prefix: &str,
) -> Result<tempfile::NamedTempFile, PrivateFileError> {
    let dir = path.parent().ok_or_else(|| {
        PrivateFileError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the path has no directory",
        ))
    })?;
    let temp = tempfile::Builder::new()
        .prefix(prefix)
        .tempfile_in(dir)
        .map_err(PrivateFileError::Io)?;
    access::make_private(temp.as_file(), temp.path()).map_err(PrivateFileError::Io)?;
    match access::check(temp.as_file()) {
        Ok(Some(reason)) => Err(PrivateFileError::Insecure(reason)),
        Ok(None) => Ok(temp),
        Err(source) => Err(PrivateFileError::Io(source)),
    }
}

/// How many times a directory that carries a half-made shape is re-checked before it is
/// refused: a creator that started at the same instant is a moment from applying the rule.
#[cfg(not(unix))]
const SETTLE_ATTEMPTS: usize = 1000;

/// Create `dir` if it is missing, and hold it to the key file's rule.
///
/// A directory another account can write lets it delete a record or a queue, which is
/// a silent un-pairing, so an existing directory is checked as well as a new one. The
/// check is the same on both platforms: unix reads the mode, the owner and (on macOS)
/// the extended list from a descriptor opened without following a link; Windows reads
/// the directory's access list and owner from a handle opened for the directory.
///
/// A directory this crate creates is hardened before it is checked: a fresh directory
/// inherits its parent's access list on Windows and the umask's mode on unix, and the
/// rule would refuse what it inherited. Nothing is repaired: a directory that really is
/// reachable by another account is refused, with its remedy. See [`settle`] for the one
/// window the platforms differ on.
pub(crate) fn create_private_dir(dir: &Path) -> Result<(), PrivateFileError> {
    if !dir.is_dir() {
        match create_directory(dir) {
            Ok(()) => access::make_directory_private(dir).map_err(PrivateFileError::Io)?,
            // Something is at the path and is not a directory — a regular file, or a
            // link to one. The check below refuses a link as a link; a regular file
            // fails its `O_DIRECTORY` open and surfaces as `Io`.
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(source) => return Err(PrivateFileError::Io(source)),
        }
    }
    settle(dir)
}

/// Check `dir`, refusing at once on unix and re-checking a half-made shape on Windows.
///
/// Unix creates the directory with its final mode in the one `mkdir`, so a second process
/// never sees it half-made and a directory that does not pass is refused without a retry:
/// an operator's directory left at 0755 costs one check, not a thousand descriptor opens.
/// Windows applies the access list after the creation, so a directory that carries a
/// merely half-made shape is re-checked a bounded number of times before it is refused.
#[cfg(unix)]
fn settle(dir: &Path) -> Result<(), PrivateFileError> {
    match access::check_directory(dir).map_err(PrivateFileError::Io)? {
        None => Ok(()),
        Some(reason) => Err(PrivateFileError::Insecure(reason)),
    }
}

#[cfg(not(unix))]
fn settle(dir: &Path) -> Result<(), PrivateFileError> {
    let mut half_made = None;
    for _ in 0..SETTLE_ATTEMPTS {
        match access::check_directory(dir).map_err(PrivateFileError::Io)? {
            None => return Ok(()),
            Some(reason) if matches!(&reason, Insecurity::AccessList { .. }) => {
                half_made = Some(reason);
                std::thread::yield_now();
            }
            Some(reason) => return Err(PrivateFileError::Insecure(reason)),
        }
    }
    Err(PrivateFileError::Insecure(half_made.expect(
        "a half-made directory was found before the last attempt",
    )))
}

/// Make `dir`, carrying the final mode from its first instant where the platform can.
#[cfg(unix)]
fn create_directory(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    fs::DirBuilder::new().mode(0o700).create(dir)
}

#[cfg(not(unix))]
fn create_directory(dir: &Path) -> io::Result<()> {
    fs::create_dir(dir)
}

/// Read at most `max` bytes from `file`, and answer the length the file claimed.
///
/// The length is what the file's own metadata says, which is more than was read when
/// the file is past the cap; a caller that refuses an oversized file names it.
pub(crate) fn read_capped(file: File, max: u64) -> io::Result<(Vec<u8>, Option<u64>)> {
    let length = file.metadata().map(|metadata| metadata.len()).ok();
    let mut bytes = Vec::new();
    file.take(max).read_to_end(&mut bytes)?;
    Ok((bytes, length))
}

/// Create `path` holding `bytes`, privately.
///
/// The bytes land in a temporary file that already carries the rule, and the publish
/// is the one that never replaces: a file another process created in the same instant
/// is that process's, and the caller reads it instead. Creating a private file in
/// place would leave it reachable by another account until the mode was set, which is
/// the window this closes.
pub(crate) fn create_private(
    path: &Path,
    prefix: &str,
    bytes: &[u8],
) -> Result<(), PrivateFileError> {
    let mut temp = private_temp(path, prefix)?;
    temp.write_all(bytes).map_err(PrivateFileError::Io)?;
    temp.as_file().sync_all().map_err(PrivateFileError::Io)?;
    match temp.persist_noclobber(path) {
        Ok(_) => Ok(()),
        Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(PrivateFileError::Io(error.error)),
    }
}
