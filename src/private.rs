//! The one way this crate publishes a private file: a temporary file beside the
//! destination, given the rule and checked, flushed, and published by one rename.
//!
//! The key file and the peer record both write this way, and both read through the
//! same checked open, so the ordering that keeps a private half out of the wrong
//! access has one spelling. The rule itself is `identity::access`; this module only
//! applies it around the write and the read.

use std::fs::File;
use std::io::{self, Read};
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
    let file = match access::open(path) {
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
