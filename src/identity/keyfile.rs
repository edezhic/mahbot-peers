//! The key file: one ed25519 identity under one storage root.
//!
//! # The contract
//!
//! Two things here are a compatibility contract with every installation that
//! already exists, because a key is never rotated and there is no migration:
//!
//! - **The name**: the key file is `<root>/identity.key`, the one
//!   [`file_in`](crate::identity::keyfile::file_in) builds. Reaching the key takes
//!   that function, or the literal name in a file no crate but this one ships; both
//!   are source-scan invariants.
//! - **The format**: the key's PKCS#8 DER, v2, 83 bytes — the private key and its
//!   public key in one structure, which is what `ring` writes and what `ring`
//!   checks before it hands back a key. The older v1 form (48 bytes, no public key)
//!   is refused rather than accepted with the public key unchecked: this crate has
//!   never written one, and a key file it cannot verify is a key file it must not
//!   use.
//!
//! # What it guarantees
//!
//! - The key is created once. Two creators racing on one root end with one
//!   identity: the key is written beside the file, flushed, and published by an
//!   operation that fails if the name already exists, so a half-written file is
//!   never visible at the key's path. A creator that loses reads the winner's key.
//! - The key is never replaced. There is no rotation, no renewal and no timer
//!   anywhere in the crate; an existing file is read or refused, never rewritten,
//!   and a zero-length or unparsable file is a refusal rather than a silent
//!   re-key. Becoming a new machine is therefore always a deliberate act: deleting
//!   the file. That is the whole cost of losing the key: a new identity, unknown
//!   to every other machine, and a fresh acquaintance with each of them.
//! - No account but the owner can reach it, and on Windows the two system accounts a
//!   backup needs: on unix the mode and the owning account, on macOS also the
//!   extended access list, on Windows a protected list naming the owner, `SYSTEM` and
//!   `Administrators` — chosen so an operator is never pushed into loosening the
//!   check — and the file owned by the account the process runs as, because an owner
//!   may rewrite the list of what it owns. Any other reach is a
//!   [`KeyFileError::Insecure`](crate::identity::keyfile::KeyFileError::Insecure),
//!   which is distinct from "missing" and from "not a key", so a caller cannot
//!   confuse it with either and cannot continue silently. Its message names the
//!   accounts involved — or says that no account can be named — and, where the
//!   platform has one, the command that repairs the file; `identity::access` lists
//!   every refusal with its platform and its words.
//!   When the storage root itself hands a new file an access its mode cannot
//!   override, the refusal is
//!   [`KeyFileError::RootNotPrivate`](crate::identity::keyfile::KeyFileError::RootNotPrivate):
//!   it happens before a key is minted, names the root, and says what about the root
//!   has to change.
//! - A copy of a storage root is the same identity. That is how a restored backup
//!   keeps its machine, and it is also a clone: the transport refuses a peer that
//!   presents this machine's own key ([`crate::tls::Refusal::OwnIdentity`]).
//! - The file is flushed before it is published. The directory entry itself is not
//!   fsynced, so a power loss in the instant after a first start can lose the key —
//!   which is the documented "the key is gone, so this is a new machine" case, not
//!   a replacement of one key by another.
//!
//! The root arrives from outside and is never resolved here: this module reads no
//! configuration and no ambient state. The root must exist; it is not created.

use std::fmt;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use ring::rand::SystemRandom;

use super::Identity;
use super::access::{self, Insecurity};

/// The key file's name inside a storage root. Permanent: see the module docs.
///
/// Private on purpose: [`file_in`] is the one way to build the path, and the name
/// invariant scans for both it and the literal. A public constant would be a third
/// way in that no scan can see — enough to delete or rewrite the key without ever
/// naming `identity.key`.
const FILE_NAME: &str = "identity.key";

/// The most bytes a key file may have: a key is tens of bytes, and the cap is what
/// keeps a hostile file from being read into memory.
const MAX_BYTES: u64 = 1024;

/// The key file's path inside `root`.
#[must_use]
pub fn file_in(root: &Path) -> PathBuf {
    root.join(FILE_NAME)
}

/// Load the identity stored under `root`, creating it if nothing is there.
///
/// # Errors
///
/// Any [`KeyFileError`]: the file is reachable by another account, it holds
/// something that is not a key, or it could not be read or created. A refusal
/// never writes a key of its own.
pub fn load_or_create(root: &Path) -> Result<Identity, KeyFileError> {
    let path = file_in(root);
    match read(&path)? {
        Some(identity) => Ok(identity),
        None => create(root),
    }
}

/// Why the identity under a storage root could not be loaded or created.
#[derive(Debug)]
pub enum KeyFileError {
    /// An existing key file is reachable by somebody other than its owner. Distinct
    /// from a missing file and from a malformed one: this is a refusal, not an
    /// absence.
    Insecure { path: PathBuf, reason: Insecurity },
    /// A new key file could not be made private inside the storage root, so no key
    /// was minted and nothing was written. The file does not exist: what has to change
    /// is the root — the access it gives the files created under it, or the account a
    /// new file ends up belonging to. The message names the root and, when one command
    /// repairs the directory in place, that command: a macOS entry and an inherited
    /// Windows list do, every other cause does not.
    RootNotPrivate { root: PathBuf, reason: Insecurity },
    /// The file exists and holds something that is not a key this crate can read.
    /// Nothing was written in its place.
    ///
    /// Access is read before contents: a file that is both reachable by another
    /// account and not a key is refused as [`Self::Insecure`] first, because its access
    /// is what has to be repaired before its bytes matter. A file whose access is
    /// already right is refused here, as [`Malformed`].
    Malformed { path: PathBuf, reason: Malformed },
    /// The key file could not be read or published, a key could not be minted for it,
    /// or the access of a file could not be read — an unavailable entropy source, or an
    /// owner the platform can neither name nor spell, for instance. `path` is the key
    /// file's, even when the failure was reading the temporary file a create writes
    /// beside it.
    Io { path: PathBuf, source: io::Error },
}

/// What is wrong with a file that is not a key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Malformed {
    /// The file is empty: a write that never landed, not a key.
    Empty,
    /// The file has bytes and they are not a PKCS#8 ed25519 key.
    NotAKey {
        /// How many bytes were found.
        bytes: usize,
    },
}

impl fmt::Display for KeyFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Insecure { path, reason } => {
                write!(f, "{} is not private: {reason}", path.display())?;
                // The message is the one an operator acts on, so the command names
                // this file: a command with "it" in place of a path is not a command.
                match reason.remedy(path) {
                    Some(command) => write!(f, "; {command}"),
                    None => Ok(()),
                }
            }
            Self::RootNotPrivate { root, reason } => {
                write!(
                    f,
                    "the storage root {} gives a new key file an access that is not private: ",
                    root.display()
                )?;
                reason.write_fact(f)?;
                f.write_str(match reason {
                    Insecurity::Owner { .. } | Insecurity::ForeignOwner { .. } => {
                        "; no key was written, and the account the new file belongs to is \
                         what has to change"
                    }
                    Insecurity::Unowned => {
                        "; no key was written, and the ownership of the new file is what \
                         has to change"
                    }
                    _ => "; no key was written, and the directory is what has to change",
                })?;
                // The root exists, unlike the key file a `RootNotPrivate` is about, so
                // the cause's repair is worth printing when it is about the directory:
                // an access list is repaired in place, while a mode on a directory is
                // not `chmod 600`'s business and would strip its traverse bit.
                match reason {
                    Insecurity::AccessList { .. } => match reason.remedy(root) {
                        Some(command) => write!(f, "; {command}"),
                        None => Ok(()),
                    },
                    _ => Ok(()),
                }
            }
            Self::Malformed { path, reason } => match reason {
                Malformed::Empty => write!(
                    f,
                    "{} is empty; a zero-length key file is refused, not re-keyed",
                    path.display()
                ),
                Malformed::NotAKey { bytes } => write!(
                    f,
                    "{} holds {bytes} bytes that are not a PKCS#8 ed25519 key; \
                     refusing rather than replacing this machine's identity",
                    path.display()
                ),
            },
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
        }
    }
}

impl std::error::Error for KeyFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Insecure { .. } | Self::RootNotPrivate { .. } | Self::Malformed { .. } => None,
        }
    }
}

/// Read the key at `path`, or `None` if nothing is there.
fn read(path: &Path) -> Result<Option<Identity>, KeyFileError> {
    let file = match access::open(path).map_err(|source| KeyFileError::Io {
        path: path.to_owned(),
        source,
    })? {
        access::Opening::File(file) => file,
        access::Opening::Absent => return Ok(None),
        access::Opening::Refused(reason) => {
            return Err(KeyFileError::Insecure {
                path: path.to_owned(),
                reason,
            });
        }
    };
    if let Some(reason) = access::check(&file).map_err(|source| KeyFileError::Io {
        path: path.to_owned(),
        source,
    })? {
        return Err(KeyFileError::Insecure {
            path: path.to_owned(),
            reason,
        });
    }
    let length = file.metadata().map(|metadata| metadata.len()).ok();
    let mut bytes = Vec::new();
    file.take(MAX_BYTES)
        .read_to_end(&mut bytes)
        .map_err(|source| KeyFileError::Io {
            path: path.to_owned(),
            source,
        })?;
    if bytes.is_empty() {
        return Err(KeyFileError::Malformed {
            path: path.to_owned(),
            reason: Malformed::Empty,
        });
    }
    match Identity::from_pkcs8(&bytes) {
        Some(identity) => Ok(Some(identity)),
        // The file's own length, which is more than was read when it is past the cap.
        None => Err(KeyFileError::Malformed {
            path: path.to_owned(),
            reason: Malformed::NotAKey {
                bytes: length.map_or(bytes.len(), |length| {
                    usize::try_from(length).unwrap_or(usize::MAX)
                }),
            },
        }),
    }
}

/// Mint a key and publish it under `root` unless another creator already did.
fn create(root: &Path) -> Result<Identity, KeyFileError> {
    let path = file_in(root);
    let io_error = |source| KeyFileError::Io {
        path: path.clone(),
        source,
    };
    // Beside the destination, so publishing is a rename within one directory: a
    // copy of the key never exists under a name a reader of the key would use.
    let mut temp = tempfile::Builder::new()
        .prefix(".identity.key.")
        .tempfile_in(root)
        .map_err(|source| match source.kind() {
            // The root arrives from the caller and is never created here: a missing
            // one is the caller's bug, and it deserves a message that says so.
            io::ErrorKind::NotFound => io_error(io::Error::new(
                io::ErrorKind::NotFound,
                "the storage root does not exist",
            )),
            _ => io_error(source),
        })?;
    // The access first: on Windows the temporary file inherits the directory's
    // list until this replaces it, and the private half must not be written into a
    // window where that list is still the directory's.
    access::make_private(temp.as_file(), temp.path()).map_err(io_error)?;
    // Verified before a key byte exists in the file: on Windows the list and the
    // owner were applied by path, so a path swapped between the calls leaves the
    // handle's file with the directory's own list and owner, and this refuses instead
    // of writing into it. The refusal names the root, because the root is the directory
    // that handed the temporary file the access and the owner that were found.
    if let Some(reason) = access::check(temp.as_file()).map_err(io_error)? {
        return Err(KeyFileError::RootNotPrivate {
            root: root.to_owned(),
            reason,
        });
    }
    // Minted last, so a refused root never has a key generated for it: nothing
    // private exists, even in memory, until the file it would live in is known to
    // be one only its owner can read.
    let identity = mint(&path)?;
    temp.write_all(identity.pkcs8()).map_err(io_error)?;
    temp.as_file().sync_all().map_err(io_error)?;
    match temp.persist_noclobber(&path) {
        Ok(_) => Ok(identity),
        // A racing creator published first. Its key is the identity of this root;
        // publishing over it would turn both machines into different peers.
        Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
            read(&path)?.ok_or_else(|| io_error(error.error))
        }
        Err(error) => Err(io_error(error.error)),
    }
}

/// A fresh ed25519 key. The only place in the crate a key is minted, and it runs
/// only when the key file is absent.
///
/// An unavailable entropy source or an unparsable generated key is a typed
/// [`KeyFileError::Io`]: the caller cannot mint its way around it, and it must not
/// be a panic inside library code.
fn mint(path: &Path) -> Result<Identity, KeyFileError> {
    let failure = |detail: &str| KeyFileError::Io {
        path: path.to_owned(),
        source: io::Error::other(detail.to_owned()),
    };
    let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| failure("the system randomness source is unavailable"))?;
    Identity::from_pkcs8(pkcs8.as_ref())
        .ok_or_else(|| failure("the generated key does not parse as PKCS#8"))
}
