//! One machine's storage root: a private temporary directory and its id.
//!
//! Everything that touches a filesystem path lives here, and nothing here is
//! public. `machine.rs` holds the handle a test is given, and that file does not
//! name a path at all — the invariant table checks it.

use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

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
