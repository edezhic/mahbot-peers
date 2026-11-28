//! One spelling for the per-peer private files a layer keeps under a root.
//!
//! The message queues and the action memories are the same shape: a directory under the
//! storage root, one file per peer named by the peer's hex, one lock file beside it, one
//! writer in this process, and a read and a publish that both go through [`crate::private`].
//! Only the name and the bytes differ, so the plumbing is here once and each layer keeps
//! its own format.
//!
//! # What it guarantees
//!
//! - **Atomic publish.** A file is written beside its own path, flushed, and published by
//!   one rename, so a reader never sees a half-written file and a crash leaves the previous
//!   one in place.
//! - **One writer at a time, on this machine and on the root.** This process writes one
//!   file at a time: a mutex is held across the whole read-modify-publish, so two tasks
//!   cannot lose each other's work. One lock file per peer is held for the same span, so the
//!   self-update window's second process cannot lose a write either; that lock is per peer,
//!   so a second process writing another peer's file never waits for this one.
//! - **The files are private.** The directory and every file are held to the key file's
//!   rule, and a file reachable by another account is refused rather than read.

use std::fs::{File, TryLockError};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use crate::hex;
use crate::identity::PeerId;
use crate::identity::access::Insecurity;
use crate::private::{self, PrivateFileError};

/// The extension of the file a writer locks for one peer's read-modify-publish. It is never
/// published or replaced, and it is not one of the layer's files: [`Files`]'s name is their
/// extension.
const LOCK: &str = "lock";

/// Why one peer's file could not be opened, read, locked or published.
pub(crate) enum Fault {
    /// The storage root is not a directory.
    RootMissing(PathBuf),
    /// The operating system refused.
    Io { path: PathBuf, source: io::Error },
    /// The file, or the directory holding it, is reachable by another account.
    Insecure { path: PathBuf, reason: Insecurity },
    /// Another writer holds this peer's lock file this instant.
    Busy(PeerId),
}

/// A file the layer refuses before it decodes it: empty, or past the layer's cap.
pub(crate) enum Malformed {
    /// The file is empty.
    Empty,
    /// The file is longer than the layer's cap.
    TooLarge { bytes: u64 },
}

/// A layer's per-peer file: its cap, its error and its own bytes.
pub(crate) trait Coded: Sized {
    /// The most bytes the file may have.
    const CAP: u64;
    /// The layer's error.
    type Error;
    /// The empty file an absent one reads as.
    fn absent() -> Self;
    /// The file's bytes.
    fn encode(&self, path: &Path) -> Result<Vec<u8>, Self::Error>;
    /// One file, from its bytes.
    fn decode(path: &Path, bytes: &[u8]) -> Result<Self, Self::Error>;
    /// An empty or oversized file, in the layer's words.
    fn malformed(path: &Path, reason: Malformed) -> Self::Error;
    /// A file that would pass the cap, in the layer's words.
    fn too_large(path: &Path, bytes: u64) -> Self::Error;
    /// A fault this module met, in the layer's words.
    fn fault(fault: Fault) -> Self::Error;
}

/// The directory one layer keeps under a storage root, and this process's writer for it.
pub(crate) struct Files {
    dir: PathBuf,
    /// The layer's name: the directory's, and the extension of every file in it.
    name: &'static str,
    /// This process's one writer, held across a read-modify-publish so two files are never
    /// written at once.
    writer: Mutex<()>,
}

impl Files {
    /// Open `name` under `root`, creating it on the first start.
    pub(crate) fn open(root: &Path, name: &'static str) -> Result<Self, Fault> {
        if !root.is_dir() {
            return Err(Fault::RootMissing(root.to_owned()));
        }
        let dir = dir_in(root, name);
        private::create_private_dir(&dir).map_err(|error| mapped(error, &dir))?;
        Ok(Self {
            dir,
            name,
            writer: Mutex::new(()),
        })
    }

    /// The directory these files live in.
    pub(crate) fn dir(&self) -> &Path {
        &self.dir
    }

    /// One peer's file.
    pub(crate) fn path(&self, peer: &PeerId) -> PathBuf {
        path_in(&self.dir, peer, self.name)
    }

    /// One peer's lock file.
    fn lock_path(&self, peer: &PeerId) -> PathBuf {
        lock_in(&self.dir, peer)
    }

    /// Take this process's writer and one peer's lock file, or answer [`Fault::Busy`].
    pub(crate) fn lock(&self, peer: &PeerId) -> Result<Held<'_>, Fault> {
        // This process's writer first: a second task waits here for the few file operations
        // the holder is doing, never for a caller's own code.
        let writer = self
            .writer
            .lock()
            .expect("a store's writer is not poisoned");
        let path = self.lock_path(peer);
        let file = lock_file(&path)?;
        match file.try_lock() {
            Ok(()) => Ok(Held {
                _writer: writer,
                file,
            }),
            // Another writer — the second process a self-update leaves on the root, or a
            // second store in this one — is publishing this peer's file this instant. That
            // wait is not this layer's to make: the caller is told and tries again.
            Err(TryLockError::WouldBlock) => Err(Fault::Busy(*peer)),
            Err(TryLockError::Error(source)) => Err(Fault::Io { path, source }),
        }
    }

    /// Publish one peer's file atomically.
    fn write(&self, peer: &PeerId, bytes: &[u8]) -> Result<(), Fault> {
        let path = self.path(peer);
        let prefix = format!(".{}.", self.name);
        let mut temp =
            private::private_temp(&path, &prefix).map_err(|error| mapped(error, &path))?;
        temp.write_all(bytes).map_err(|source| Fault::Io {
            path: path.clone(),
            source,
        })?;
        temp.as_file().sync_all().map_err(|source| Fault::Io {
            path: path.clone(),
            source,
        })?;
        temp.persist(&path).map_err(|error| Fault::Io {
            path,
            source: error.error,
        })?;
        Ok(())
    }

    /// Publish one coded file, refusing one past its own cap before anything is written.
    pub(crate) fn write_coded<T: Coded>(&self, peer: &PeerId, file: &T) -> Result<(), T::Error> {
        let path = self.path(peer);
        let bytes = file.encode(&path)?;
        if bytes.len() as u64 > T::CAP {
            return Err(T::too_large(&path, bytes.len() as u64));
        }
        self.write(peer, &bytes).map_err(T::fault)
    }
}

/// One writer's hold on one peer's file: this process's writer and the lock file, held for
/// the whole read-modify-publish.
///
/// The lock is released here rather than by the descriptor's own drop, and the order matters:
/// fields drop in declaration order, so the writer's guard goes first, and a second task could
/// take the writer and `try_lock` a file whose lock this one has not let go yet — a spurious
/// [`Fault::Busy`] for a file nobody holds. Unlocking first also means a panic between the
/// read and the publish does not leave the file locked.
pub(crate) struct Held<'a> {
    _writer: MutexGuard<'a, ()>,
    file: File,
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

/// What a read answered: the bytes, and the length the file's own metadata claimed beside
/// them, which is more than was read when the file is past the cap.
type Bytes = (Vec<u8>, Option<u64>);

/// Read one peer's file, or `None` when nothing is there.
///
/// At most `max` bytes are read, and the length the file claimed comes back beside them: a
/// caller that refuses an oversized file names it.
fn read(path: &Path, max: u64) -> Result<Option<Bytes>, Fault> {
    let Some(file) = private::open_private(path).map_err(|error| mapped(error, path))? else {
        return Ok(None);
    };
    let (bytes, length) = private::read_capped(file, max).map_err(|source| Fault::Io {
        path: path.to_owned(),
        source,
    })?;
    Ok(Some((bytes, length)))
}

/// Read one peer's coded file, or its empty value when nothing is there.
///
/// At most one byte past the cap is read, so an oversized file is refused by its own length
/// rather than read whole; an empty one is refused too, because a write that never landed is
/// not an empty file.
pub(crate) fn read_coded<T: Coded>(path: &Path) -> Result<T, T::Error> {
    let Some((bytes, length)) = read(path, T::CAP + 1).map_err(T::fault)? else {
        return Ok(T::absent());
    };
    if let Some(length) = length
        && length > T::CAP
    {
        return Err(T::malformed(path, Malformed::TooLarge { bytes: length }));
    }
    if bytes.is_empty() {
        return Err(T::malformed(path, Malformed::Empty));
    }
    if bytes.len() as u64 > T::CAP {
        return Err(T::malformed(
            path,
            Malformed::TooLarge {
                bytes: bytes.len() as u64,
            },
        ));
    }
    T::decode(path, &bytes)
}

/// The directory under `root` that holds one layer's files.
pub(crate) fn dir_in(root: &Path, name: &str) -> PathBuf {
    root.join(name)
}

/// One peer's file path inside `dir`.
pub(crate) fn path_in(dir: &Path, peer: &PeerId, name: &str) -> PathBuf {
    dir.join(format!("{}.{name}", hex::encode(peer.as_bytes())))
}

/// One peer's lock file path inside `dir`.
pub(crate) fn lock_in(dir: &Path, peer: &PeerId) -> PathBuf {
    dir.join(format!("{}.{LOCK}", hex::encode(peer.as_bytes())))
}

/// The lock file for one peer, created on the first write.
fn lock_file(path: &Path) -> Result<File, Fault> {
    if let Some(file) = private::open_private(path).map_err(|error| mapped(error, path))? {
        return Ok(file);
    }
    private::create_private(path, ".lock.", b"").map_err(|error| mapped(error, path))?;
    private::open_private(path)
        .map_err(|error| mapped(error, path))?
        .ok_or_else(|| Fault::Io {
            path: path.to_owned(),
            source: io::Error::other("the lock file vanished after it was created"),
        })
}

/// A private-file refusal, named with the file it is about.
fn mapped(error: PrivateFileError, path: &Path) -> Fault {
    match error {
        PrivateFileError::Io(source) => Fault::Io {
            path: path.to_owned(),
            source,
        },
        PrivateFileError::Insecure(reason) => Fault::Insecure {
            path: path.to_owned(),
            reason,
        },
    }
}
