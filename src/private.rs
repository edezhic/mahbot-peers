//! The one way this crate publishes a private file: a temporary file beside the
//! destination, given the rule and checked, flushed, and published by one rename.
//!
//! The key file, the peer record and the audit log's creation all write this way, and
//! all read through the same checked open, so the ordering that keeps a private half
//! out of the wrong access has one spelling: a file is private before its first byte
//! lands, not made private afterwards. The log is only *created* this way — it is
//! appended in place, because an append-only record cannot be rewritten without losing
//! a concurrent writer's entry, so its appends are opened, checked and written through
//! the same descriptor, and `peer::audit` states the lock and the flush that make them
//! safe. The rule itself is `identity::access`; this module only applies it around the
//! write and the read.

use std::fs::{File, OpenOptions};
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
