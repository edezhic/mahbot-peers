//! One machine's storage root: a private temporary directory and its id.
//!
//! Everything that touches a filesystem path lives here, and nothing here is
//! public. `machine.rs` holds the handle a test is given, and that file does not
//! name a path at all — the invariant table checks it.

use std::fs::{self, File};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use mahbot_peers::identity::keyfile;
use mahbot_peers::identity::{Identity, PeerId};
use mahbot_peers::peer::{
    AuditError, AuditLog, Deliveries, Floor, Limits, Messages, Moment, RecordError, RecordStore,
};
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

    /// This root's peer records, opened over the real directory.
    ///
    /// The store's refusal is text because every case that reads one treats it as
    /// the failure it is about: a record that cannot be read is never a record to
    /// trust.
    pub(crate) fn records(&self) -> Result<RecordStore, String> {
        self.records_with(Limits::default())
    }

    /// This root's peer records under explicit limits, for a case that has to make
    /// an attempt expire without spending the default lifetime.
    pub(crate) fn records_with(&self, limits: Limits) -> Result<RecordStore, String> {
        self.ensure_alive().map_err(|error| error.to_string())?;
        RecordStore::open(self.dir.path(), limits).map_err(|error| error.to_string())
    }

    /// This root's records, answering the store's own refusal: the typed error a case
    /// that asserts *why* an open failed needs.
    pub(crate) fn records_typed(&self) -> Result<RecordStore, RecordError> {
        self.ensure_alive().map_err(|_| RecordError::RootMissing {
            path: self.dir.path().to_owned(),
        })?;
        RecordStore::open(self.dir.path(), Limits::default())
    }

    /// This root's audit log, opened over the real file.
    pub(crate) fn audit(&self) -> Result<AuditLog, String> {
        self.audit_typed().map_err(|error| error.to_string())
    }

    /// This root's audit log, answering the log's own refusal: the typed error a case
    /// that asserts *why* an open failed needs.
    pub(crate) fn audit_typed(&self) -> Result<AuditLog, AuditError> {
        self.ensure_alive().map_err(|_| AuditError::RootMissing {
            path: self.dir.path().to_owned(),
        })?;
        AuditLog::open(self.dir.path())
    }

    /// Give `peer`'s record a mode, as an installation whose root was never hardened
    /// leaves it reachable by another account. The record's own module names the file,
    /// so this works on a record the store itself would refuse.
    #[cfg(unix)]
    pub(crate) fn set_record_mode(&self, peer: &PeerId, mode: u32) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let path = self.resolve(&self.record_name(peer)?)?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
    }

    /// `peer`'s record, read as this root's bytes.
    pub(crate) fn read_record(&self, peer: &PeerId) -> io::Result<Vec<u8>> {
        self.read(&self.record_name(peer)?)
    }

    /// `peer`'s record, replaced as this root's bytes.
    pub(crate) fn write_record(&self, peer: &PeerId, bytes: &[u8]) -> io::Result<()> {
        self.write(&self.record_name(peer)?, bytes)
    }

    /// `peer`'s record, removed as a restored backup or a deleted file removes it.
    pub(crate) fn remove_record(&self, peer: &PeerId) -> io::Result<()> {
        self.ensure_alive()?;
        fs::remove_file(self.resolve(&self.record_name(peer)?)?)
    }

    /// Whether `peer`'s record is a file under this root, for a case that asserts a file
    /// was created or removed without reading it.
    pub(crate) fn record_exists(&self, peer: &PeerId) -> io::Result<bool> {
        self.ensure_alive()?;
        Ok(self.resolve(&self.record_name(peer)?)?.is_file())
    }

    /// The directory holding this root's records, as the record module spells it.
    fn records_dir(&self) -> io::Result<PathBuf> {
        self.ensure_alive()?;
        Ok(RecordStore::dir_in(self.dir.path()))
    }

    /// The mode of the records directory.
    #[cfg(unix)]
    pub(crate) fn records_dir_mode(&self) -> io::Result<u32> {
        use std::os::unix::fs::PermissionsExt;
        Ok(fs::metadata(self.records_dir()?)?.permissions().mode() & 0o777)
    }

    /// Give the records directory a mode, as a root that was never hardened leaves it.
    #[cfg(unix)]
    pub(crate) fn set_records_dir_mode(&self, mode: u32) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(self.records_dir()?, fs::Permissions::from_mode(mode))
    }

    /// Turn the records directory into a symbolic link to a directory beside it, as a
    /// backup tool that moved it leaves it.
    #[cfg(unix)]
    pub(crate) fn replace_records_dir_with_a_link(&self) -> io::Result<()> {
        let dir = self.records_dir()?;
        let elsewhere = dir.with_file_name("peers-elsewhere");
        fs::rename(&dir, &elsewhere)?;
        std::os::unix::fs::symlink(&elsewhere, &dir)
    }

    /// The name `peer`'s record has under this root, as the record module spells it, so
    /// a case never writes a record's name itself.
    pub(crate) fn record_name(&self, peer: &PeerId) -> io::Result<String> {
        self.ensure_alive()?;
        self.relative(&RecordStore::path_for(self.dir.path(), peer))
    }

    /// This root's message layer, opened over the real directory.
    ///
    /// The records and the log are the machine's own handles, so the queues, the
    /// decision and the record of it come from one root.
    pub(crate) fn messages(
        &self,
        records: RecordStore,
        audit: AuditLog,
        floor: Arc<dyn Floor + Send + Sync>,
        moment: Arc<dyn Moment + Send + Sync>,
        deliveries: Arc<dyn Deliveries + Send + Sync>,
        runtime: Arc<dyn quinn::Runtime>,
    ) -> Result<Messages, String> {
        self.ensure_alive().map_err(|error| error.to_string())?;
        Messages::open(
            self.dir.path(),
            records,
            audit,
            floor,
            moment,
            deliveries,
            runtime,
        )
        .map_err(|error| error.to_string())
    }

    /// The name `peer`'s queue has under this root, as the message module spells it.
    pub(crate) fn message_name(&self, peer: &PeerId) -> io::Result<String> {
        self.ensure_alive()?;
        self.relative(&Messages::path_for(self.dir.path(), peer))
    }

    /// `peer`'s queue file, read as this root's bytes.
    pub(crate) fn read_message(&self, peer: &PeerId) -> io::Result<Vec<u8>> {
        self.read(&self.message_name(peer)?)
    }

    /// `peer`'s queue file, replaced as this root's bytes.
    pub(crate) fn write_message(&self, peer: &PeerId, bytes: &[u8]) -> io::Result<()> {
        self.write(&self.message_name(peer)?, bytes)
    }

    /// `peer`'s queue file, removed as a deleted file or a restored backup removes it.
    pub(crate) fn remove_message(&self, peer: &PeerId) -> io::Result<()> {
        self.ensure_alive()?;
        fs::remove_file(self.resolve(&self.message_name(peer)?)?)
    }

    /// The name of the file a writer locks for `peer`'s queue: beside the queue, as the
    /// message module spells it.
    pub(crate) fn message_lock_name(&self, peer: &PeerId) -> io::Result<String> {
        self.ensure_alive()?;
        self.relative(&Messages::lock_path_for(self.dir.path(), peer))
    }

    /// Hold `peer`'s queue lock, as the self-update window's second process does for the span
    /// of one read-modify-publish. The file is created privately, by the crate's own rule, so
    /// the lock the case holds is one the crate would take itself.
    pub(crate) fn lock_message(&self, peer: &PeerId) -> io::Result<File> {
        let name = self.message_lock_name(peer)?;
        self.write(&name, b"")?;
        let file = File::options()
            .read(true)
            .write(true)
            .open(self.resolve(&name)?)?;
        file.lock()?;
        Ok(file)
    }

    /// The directory holding this root's queues, removed whole, as a cleaner or a botched
    /// restore removes it.
    pub(crate) fn remove_message_dir(&self) -> io::Result<()> {
        self.ensure_alive()?;
        fs::remove_dir_all(Messages::dir_in(self.dir.path()))
    }

    /// The directory holding this root's queues, as the message module spells it.
    #[cfg(unix)]
    fn messages_dir(&self) -> io::Result<PathBuf> {
        self.ensure_alive()?;
        Ok(Messages::dir_in(self.dir.path()))
    }

    /// The mode of the messages directory.
    #[cfg(unix)]
    pub(crate) fn message_dir_mode(&self) -> io::Result<u32> {
        use std::os::unix::fs::PermissionsExt;
        Ok(fs::metadata(self.messages_dir()?)?.permissions().mode() & 0o777)
    }

    /// Give the messages directory a mode, as a root that was never hardened leaves it.
    #[cfg(unix)]
    pub(crate) fn set_message_dir_mode(&self, mode: u32) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(self.messages_dir()?, fs::Permissions::from_mode(mode))
    }

    /// Give `peer`'s queue file a mode, as an installation whose root was never hardened
    /// leaves it reachable by another account.
    #[cfg(unix)]
    pub(crate) fn set_message_file_mode(&self, peer: &PeerId, mode: u32) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let path = self.resolve(&self.message_name(peer)?)?;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
    }

    /// Turn the messages directory into a symbolic link to a directory beside it, as a
    /// backup tool that moved it leaves it.
    #[cfg(unix)]
    pub(crate) fn replace_message_dir_with_a_link(&self) -> io::Result<()> {
        let dir = self.messages_dir()?;
        let elsewhere = dir.with_file_name("messages-elsewhere");
        fs::rename(&dir, &elsewhere)?;
        std::os::unix::fs::symlink(&elsewhere, &dir)
    }

    /// The audit log's bytes, as this root's file.
    pub(crate) fn read_audit(&self) -> io::Result<Vec<u8>> {
        self.read(&self.audit_name()?)
    }

    /// Replace the audit log's bytes, as a torn write or a damaged file leaves them.
    pub(crate) fn write_audit(&self, bytes: &[u8]) -> io::Result<()> {
        self.write(&self.audit_name()?, bytes)
    }

    /// The name the audit log has under this root, as the audit module spells it.
    fn audit_name(&self) -> io::Result<String> {
        self.ensure_alive()?;
        self.relative(&AuditLog::path_in(self.dir.path()))
    }

    /// A path the crate named under this root, as the storage name `resolve` takes.
    fn relative(&self, path: &Path) -> io::Result<String> {
        path.strip_prefix(self.dir.path())
            .ok()
            .and_then(Path::to_str)
            .map(str::to_owned)
            .ok_or_else(|| invalid("a crate-named path is not a name under this root"))
    }

    /// Write `bytes` to `name`, privately: the file is a temporary one carrying the
    /// crate's rule and is published by one rename, so a record a case crafts by hand is
    /// judged by its bytes and not refused for the mode this rig left it with.
    pub(crate) fn write(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        let path = self.resolve(name)?;
        self.ensure_alive()?;
        if let Some(dir) = path.parent()
            && !dir.is_dir()
        {
            fs::create_dir_all(dir)?;
            make_private(dir)?;
        }
        write_private(&path, bytes)
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

/// Write `bytes` to `path` through a private temporary file beside it and one rename: a
/// file a case creates carries the crate's rule before its first byte, and a record a
/// case crafts is judged by its bytes rather than refused for the mode a plain write
/// would leave.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;

    let dir = path
        .parent()
        .ok_or_else(|| invalid("a written file has a directory"))?;
    let mut temp = tempfile::Builder::new().prefix(".case.").tempfile_in(dir)?;
    temp.write_all(bytes)?;
    temp.persist(path).map_err(|error| error.error)?;
    Ok(())
}

/// Give a directory this rig created the rule the crate gives one it creates: another
/// account must not be able to write into it.
fn make_private(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
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
