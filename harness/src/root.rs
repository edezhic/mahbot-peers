//! One machine's storage root: a private temporary directory and its id.
//!
//! Everything that touches a filesystem path lives here, and nothing here is
//! public. `machine.rs` holds the handle a test is given, and that file does not
//! name a path at all — the invariant table checks it.

use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use mahbot_peers::identity::Identity;
use mahbot_peers::identity::keyfile;
use tempfile::TempDir;

use crate::machine::RootId;

/// A root directory owned by exactly one machine, removed when it is dropped.
pub(crate) struct Root {
    id: RootId,
    dir: TempDir,
}

impl Root {
    pub(crate) fn create(id: RootId, parent: &Path) -> io::Result<Self> {
        let dir = tempfile::Builder::new()
            .prefix("root-")
            .tempdir_in(parent)?;
        Ok(Self { id, dir })
    }

    pub(crate) fn id(&self) -> RootId {
        self.id
    }

    /// The machine's identity: the key file under this root, created if this is
    /// the first start. Machines get their identity the way an installation does,
    /// so no case runs on a key that could not exist here.
    pub(crate) fn load_identity(&self) -> io::Result<Identity> {
        keyfile::load_or_create(self.dir.path()).map_err(io::Error::other)
    }

    /// Copy this root's key into another root, as restoring a backup onto a second
    /// machine does. The copy is the same identity: that is what a clone is.
    pub(crate) fn copy_key_into(&self, target: &Self) -> io::Result<()> {
        copy_key(self.dir.path(), target.dir.path())
    }

    pub(crate) fn write(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        let path = self.resolve(name)?;
        self.ensure_alive()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, bytes)
    }

    pub(crate) fn read(&self, name: &str) -> io::Result<Vec<u8>> {
        let path = self.resolve(name)?;
        self.ensure_alive()?;
        fs::read(path)
    }

    /// A root whose directory is gone is never recreated: a machine whose
    /// simulation is gone must fail loudly instead of quietly leaving a
    /// directory behind or answering "no such file" for a root that vanished.
    fn ensure_alive(&self) -> io::Result<()> {
        if self.dir.path().is_dir() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                crate::machine::GONE_ROOT,
            ))
        }
    }

    /// Resolve a relative name under this root, refusing everything that could
    /// leave it: an absolute path, a parent component, a prefix or a root.
    fn resolve(&self, name: &str) -> io::Result<PathBuf> {
        if name.is_empty() {
            return Err(invalid("a storage name cannot be empty"));
        }
        let relative = Path::new(name);
        if relative.is_absolute() {
            return Err(invalid(
                "a storage name is relative to the machine's own root",
            ));
        }
        if relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(invalid(
                "a storage name cannot contain `.`, `..` or a path prefix",
            ));
        }
        Ok(self.dir.path().join(relative))
    }
}

fn invalid(detail: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, detail.to_owned())
}

/// A throwaway storage root: the directory a case that needs an identity and no
/// machine behind it creates one in.
pub(crate) fn identity_dir() -> io::Result<tempfile::TempDir> {
    tempfile::Builder::new().prefix("identity-").tempdir()
}

/// An identity with no machine behind it, for a case that needs a key and not a
/// machine: a beacon's own identity, an impostor's, an endpoint built over a raw
/// socket.
///
/// It is created through the real key-file path in a root this helper throws away,
/// so the harness never mints a key in any way an installation cannot.
pub(crate) fn detached_identity() -> io::Result<Identity> {
    let dir = identity_dir()?;
    keyfile::load_or_create(dir.path()).map_err(io::Error::other)
}

/// Put `from`'s key into the root at `to`: what restoring a backup onto a second
/// machine leaves behind.
///
/// The key is written through the crate's own create and then given `from`'s bytes,
/// not copied with `fs::copy`: what a restored backup restores is the file *and its
/// access*, and whether a copy API carries a Windows DACL is not something this rig
/// should be betting a suite on. The destination is private before the bytes land.
pub(crate) fn copy_key(from: &Path, to: &Path) -> io::Result<()> {
    let key = fs::read(keyfile::file_in(from))?;
    keyfile::load_or_create(to).map_err(io::Error::other)?;
    fs::write(keyfile::file_in(to), key)
}
