//! One machine: its own root, its own identity, its own address on the link.
//!
//! The handle is a capability, not a directory name. It exposes no filesystem
//! path and no operation that reaches another machine's root, and there is no
//! ambient fallback behind it — no current root, no environment lookup, no
//! working directory. Storage is reached through [`Storage`], which belongs to
//! exactly one root; asking it for a different root by id is refused and the
//! refusal names both ids.
//!
//! Public key material is the one thing that crosses the boundary, because peers
//! exchange it by design: a machine's fingerprint is how another machine
//! recognises it.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use mahbot_peers::identity::{Fingerprint, Identity, PeerId};
use mahbot_peers::peer::{
    Actions, AuditError, AuditLog, Executor, Floor, Moment, RecordError, RecordStore,
};

use crate::connect::Unclaimed;
use crate::link::{Link, LinkedSocket};
#[cfg(unix)]
use crate::root::Hidden;
use crate::root::Root;

/// The name of one machine's root, unique across every simulation in a process.
///
/// The simulation half is a random nonce, so two simulations numbering their
/// machines from zero cannot produce the same name: a root id that arrives from
/// outside the handle is checked against this value alone.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RootId {
    simulation: u64,
    machine: u64,
}

impl RootId {
    pub(crate) const fn new(simulation: u64, machine: u64) -> Self {
        Self {
            simulation,
            machine,
        }
    }
}

impl fmt::Debug for RootId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "root#{:04x}.{:04x}", self.simulation, self.machine)
    }
}

impl fmt::Display for RootId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "root#{:04x}.{:04x}", self.simulation, self.machine)
    }
}

/// The refusal a storage capability gives when asked for a root that is not its
/// own. It carries both ids so a test can assert the refusal is about the right
/// pair and not a generic failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IsolationRefused {
    pub asked: RootId,
    pub own: RootId,
}

impl fmt::Display for IsolationRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} is not reachable from {}: a storage capability opens only its own root",
            self.asked, self.own
        )
    }
}

impl std::error::Error for IsolationRefused {}

/// How long a restart waits for the transport to let go of the old socket.
pub const RESTART_BUDGET: Duration = Duration::from_secs(45);

/// The message a storage capability gives when its root no longer exists.
///
/// A test matches on it to tell "the root is gone" from "the file is missing",
/// which a bare `NotFound` cannot: a gone root must refuse loudly, not answer
/// "no such file" for a root that vanished.
pub const GONE_ROOT: &str = "the machine's root is gone";

/// One machine as a test holds it.
pub struct Machine {
    pub(crate) identity: Identity,
    pub(crate) root: Root,
    pub(crate) socket: Arc<LinkedSocket>,
    pub(crate) link: Link,
    pub(crate) clock: crate::clock::MockClock,
    pub(crate) transport: mahbot_peers::net::Transport,
    pub(crate) trust: Arc<crate::connect::TrustSet>,
    pub(crate) records: RecordStore,
    pub(crate) unclaimed: Arc<Unclaimed>,
    /// The task accepting on this machine's endpoint, once it has started.
    pub(crate) accepting: Mutex<Option<tokio::task::JoinHandle<()>>>,
    pub(crate) endpoint: Mutex<Option<quinn::Endpoint>>,
}

impl Machine {
    pub(crate) fn new(
        identity: Identity,
        root: Root,
        records: RecordStore,
        socket: Arc<LinkedSocket>,
        link: Link,
        clock: crate::clock::MockClock,
    ) -> Self {
        Self {
            identity,
            root,
            records,
            socket,
            link,
            clock,
            transport: mahbot_peers::net::Transport::default(),
            trust: Arc::new(crate::connect::TrustSet::default()),
            unclaimed: Arc::new(Unclaimed::default()),
            accepting: Mutex::new(None),
            endpoint: Mutex::new(None),
        }
    }

    /// The machine's public identity: what a peer remembers and pins.
    #[must_use]
    pub fn peer_id(&self) -> PeerId {
        self.identity.peer_id()
    }

    /// The 44-byte fingerprint of the machine's key.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        self.identity.fingerprint()
    }

    /// The name of this machine's root. A name, not a location.
    #[must_use]
    pub fn root_id(&self) -> RootId {
        self.root.id()
    }

    /// Where this machine currently appears on the link.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.socket.addr()
    }

    /// The capability to this machine's own storage, and to nothing else.
    #[must_use]
    pub fn storage(&self) -> Storage<'_> {
        Storage { root: &self.root }
    }

    /// This machine's durable peer records.
    ///
    /// Every clone shares one map, and the machine's endpoint trusts what it says:
    /// a store the case writes through is the store the handshake reads. A restart
    /// reopens it from the root, which is what proves the record survives.
    #[must_use]
    pub fn records(&self) -> RecordStore {
        self.records.clone()
    }

    /// Open a second store over the same root, reading what is on disk now.
    ///
    /// This is how a case proves durability: the machine's own store holds what
    /// this process wrote, and a fresh open holds only what the files say.
    ///
    /// # Errors
    ///
    /// The record store's refusal, as text: an unreadable, insecure or malformed
    /// record.
    pub fn reopen_records(&self) -> Result<RecordStore, String> {
        self.root.records()
    }

    /// A fresh store over this machine's root under explicit limits.
    ///
    /// The limits are recorded with each attempt, so a case can shorten an attempt's
    /// lifetime without changing what the default store applies.
    ///
    /// # Errors
    ///
    /// The record store's refusal, as text.
    pub fn records_with(&self, limits: mahbot_peers::peer::Limits) -> Result<RecordStore, String> {
        self.root.records_with(limits)
    }

    /// This machine's audit log.
    ///
    /// Opened over the root's own file, so a case reads exactly what a restart would:
    /// nothing is held open between calls.
    ///
    /// # Errors
    ///
    /// The log's refusal, as text.
    pub fn audit(&self) -> Result<mahbot_peers::peer::AuditLog, String> {
        self.root.audit()
    }

    /// This machine's rights: its records and its audit log.
    ///
    /// The decision and the record of it therefore come from one root.
    ///
    /// # Errors
    ///
    /// The log's refusal, as text.
    pub fn rights(&self) -> Result<mahbot_peers::peer::Rights, String> {
        Ok(mahbot_peers::peer::Rights::new(
            self.records.clone(),
            self.audit()?,
        ))
    }

    /// This machine's message layer, over its own root.
    ///
    /// The records and the log are this machine's, so the queues, the decision about a
    /// peer and the record of it come from one root. The floor, the clock the layer
    /// reads moments from and the sink a delivery goes to are the case's; the runtime
    /// is this machine's own, because the layer's waits and its receiving tasks belong
    /// to the runtime the endpoint runs on.
    ///
    /// # Errors
    ///
    /// The layer's refusal, as text: a gone root, an unreadable or insecure queue.
    pub fn messages(
        &self,
        floor: Arc<dyn mahbot_peers::peer::Floor + Send + Sync>,
        moment: Arc<dyn mahbot_peers::peer::Moment + Send + Sync>,
        deliveries: Arc<dyn mahbot_peers::peer::Deliveries + Send + Sync>,
    ) -> Result<mahbot_peers::peer::Messages, String> {
        self.root.messages(
            self.records.clone(),
            self.audit()?,
            floor,
            moment,
            deliveries,
            self.clock.runtime(),
        )
    }

    /// This machine's action layer, over its own root.
    ///
    /// The records and the log are this machine's, so the memory, the decision about a peer
    /// and the record of it come from one root. The floor, the clock the layer reads moments
    /// from and the executor an action goes to are the case's; the runtime is this machine's
    /// own, because the layer's waits and its receiving tasks belong to the runtime the
    /// endpoint runs on.
    ///
    /// # Errors
    ///
    /// The layer's refusal, as text: a gone root, an unreadable or insecure memory.
    pub fn actions(
        &self,
        floor: Arc<dyn Floor + Send + Sync>,
        moment: Arc<dyn Moment + Send + Sync>,
        executor: Arc<dyn Executor + Send + Sync>,
    ) -> Result<Actions, String> {
        self.root.actions(
            self.records.clone(),
            self.audit()?,
            floor,
            moment,
            executor,
            self.clock.runtime(),
        )
    }

    /// Remember `peer` as a machine this one may talk to.
    pub fn trust(&self, peer: &Machine) {
        self.trust.insert(peer.fingerprint());
    }

    /// Change this machine's apparent address mid-run, as a network path change
    /// does. The connection keeps its identity; only the address moves.
    ///
    /// # Errors
    ///
    /// [`crate::link::AddressTaken`] when another live machine already holds the
    /// address.
    pub fn rebind(&self, addr: SocketAddr) -> Result<(), crate::link::AddressTaken> {
        self.link.rebind(&self.socket, addr)
    }

    /// Change this machine's apparent address to a free one on the link.
    ///
    /// # Panics
    ///
    /// When every address the link can hand out is taken.
    pub fn rebind_next(&self) -> SocketAddr {
        self.link.rebind_next(&self.socket)
    }

    /// Set the transport's idle timeout before the endpoint is first built.
    #[must_use]
    pub fn with_idle_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.transport.idle_timeout = timeout;
        self
    }

    /// Set the transport's keep-alive before the endpoint is first built.
    #[must_use]
    pub fn with_keep_alive(mut self, keep_alive: Option<std::time::Duration>) -> Self {
        self.transport.keep_alive = keep_alive;
        self
    }

    /// Restart this machine over its own storage root.
    ///
    /// The endpoint is closed, the accept task is stopped, and the helper waits —
    /// advancing the clock, because nothing else moves time — until the transport
    /// has let go of the socket. Then the machine comes back with a fresh socket
    /// at a new address, the identity read from the root again, and no unclaimed
    /// connections: everything a process restart keeps is the root, and everything it
    /// loses is in memory.
    ///
    /// Every endpoint, connection and manager handle a case holds must be dropped
    /// before this call: they keep the old socket alive, and the wait would end in
    /// the budget expiring instead of a restart. A record store holds no socket and
    /// may be kept; the restart reopens the machine's own anyway.
    ///
    /// # Errors
    ///
    /// The transport did not release the socket within [`RESTART_BUDGET`], or the
    /// root no longer holds a key.
    pub async fn restart(&mut self) -> Result<SocketAddr, String> {
        if let Some(endpoint) = self.endpoint_slot().take() {
            endpoint.close(0u32.into(), b"machine restarting");
        }
        if let Some(task) = self.accepting().take() {
            task.abort();
        }
        let mut waited = Duration::ZERO;
        while Arc::strong_count(&self.socket) > 1 {
            if waited >= RESTART_BUDGET {
                return Err(format!(
                    "the transport still holds the socket after {RESTART_BUDGET:?} of virtual time"
                ));
            }
            self.clock.advance(Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
            waited += Duration::from_secs(1);
        }
        // A new address, as a machine that came back on another network has: the
        // remembered one is now stale, which is what the beacon is for.
        self.socket = self.link.attach_next();
        self.identity = self
            .root
            .load_identity()
            .map_err(|error| error.to_string())?;
        self.records = self.root.records()?;
        self.trust = Arc::new(crate::connect::TrustSet::default());
        self.unclaimed = Arc::new(Unclaimed::default());
        Ok(self.socket.addr())
    }

    /// The endpoint slot: `None` until the first connection, then the endpoint
    /// every later attempt reuses.
    pub(crate) fn endpoint_slot(&self) -> MutexGuard<'_, Option<quinn::Endpoint>> {
        self.endpoint.lock().expect("endpoint slot is not poisoned")
    }

    /// The accept task's slot, `None` until the first connect.
    pub(crate) fn accepting(&self) -> MutexGuard<'_, Option<tokio::task::JoinHandle<()>>> {
        self.accepting
            .lock()
            .expect("accept task slot is not poisoned")
    }
}

impl fmt::Debug for Machine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Machine")
            .field("peer", &self.peer_id())
            .field("root", &self.root_id())
            .field("addr", &self.addr())
            .finish_non_exhaustive()
    }
}

impl Drop for Machine {
    fn drop(&mut self) {
        // Closing the endpoint stops the accept task on its next poll and asks
        // every connection to close. The linked socket is released only when the
        // last holder lets go — the endpoint, the accept task, every `Connection`
        // handle and the drivers they own — so a machine that never connected
        // gives its address back at once and one with live connections does not.
        //
        // A poisoned slot means an earlier panic is already unwinding; a second
        // panic here would abort the process and hide it, so this one is quiet.
        if let Ok(mut slot) = self.endpoint.lock()
            && let Some(endpoint) = slot.take()
        {
            endpoint.close(0u32.into(), b"machine dropped");
        }
    }
}

/// A capability to exactly one machine's storage root.
///
/// It is `Copy` and borrows the machine, so it cannot outlive it and cannot be
/// constructed without it. Every name it takes is relative to that root;
/// [`Storage::open`] is the one operation that names a root, and it answers only
/// for its own.
#[derive(Clone, Copy)]
pub struct Storage<'a> {
    root: &'a Root,
}

impl<'a> Storage<'a> {
    /// Open the root named by `root`, if this capability is that root's.
    ///
    /// The check exists because a root id can arrive from outside the handle — a
    /// stored record, a peer's claim, a configuration row — and this is the one
    /// place such an id is resolved. A capability is a boundary, not a lookup
    /// table.
    ///
    /// # Errors
    ///
    /// [`IsolationRefused`] for any other root.
    pub fn open(self, root: RootId) -> Result<Self, IsolationRefused> {
        if root == self.root.id() {
            Ok(self)
        } else {
            Err(IsolationRefused {
                asked: root,
                own: self.root.id(),
            })
        }
    }

    /// Write `bytes` to `name` under this root, privately, creating the directories above
    /// it if a case needs a file where the crate has not written one yet.
    ///
    /// # Errors
    ///
    /// The filesystem's refusal.
    pub fn write(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        self.root.write(name, bytes)
    }

    /// Read the file at `name` under this root.
    ///
    /// # Errors
    ///
    /// The filesystem's refusal.
    pub fn read(&self, name: &str) -> io::Result<Vec<u8>> {
        self.root.read(name)
    }

    /// Open this root's audit log, answering the log's own refusal.
    ///
    /// # Errors
    ///
    /// The log's refusal.
    pub fn audit(&self) -> Result<AuditLog, AuditError> {
        self.root.audit_typed()
    }

    /// This root's records, answering the store's own refusal: the typed error a case
    /// that asserts *why* an open failed needs.
    ///
    /// # Errors
    ///
    /// The store's refusal.
    pub fn records_typed(&self) -> Result<RecordStore, RecordError> {
        self.root.records_typed()
    }

    /// The audit log's bytes, as this root's file.
    ///
    /// # Errors
    ///
    /// The filesystem's refusal.
    pub fn read_audit(&self) -> io::Result<Vec<u8>> {
        self.root.read_audit()
    }

    /// Replace the audit log's bytes, as a torn write or a damaged file leaves them.
    ///
    /// # Errors
    ///
    /// The filesystem's refusal.
    pub fn write_audit(&self, bytes: &[u8]) -> io::Result<()> {
        self.root.write_audit(bytes)
    }

    /// Turn the audit log into a directory, so the next append is refused: a hard fault rather
    /// than the cap's refusal.
    ///
    /// # Errors
    ///
    /// The filesystem's refusal.
    pub fn replace_audit_with_a_directory(&self) -> io::Result<()> {
        self.root.replace_audit_with_a_directory()
    }

    /// Give `peer`'s record a mode, as an installation whose root was never hardened
    /// leaves it reachable by another account.
    ///
    /// The record's own module names the file, so a case never spells a record's path.
    ///
    /// # Errors
    ///
    /// The filesystem's refusal.
    #[cfg(unix)]
    pub fn set_record_mode(&self, peer: &PeerId, mode: u32) -> io::Result<()> {
        self.root.set_record_mode(peer, mode)
    }

    /// `peer`'s record, read through this root's handle.
    ///
    /// A case that asserts on a record's bytes reads them here, the way it reads the
    /// audit log, rather than through a path.
    ///
    /// # Errors
    ///
    /// The filesystem's refusal.
    pub fn read_record(&self, peer: &PeerId) -> io::Result<Vec<u8>> {
        self.root.read_record(peer)
    }

    /// `peer`'s record, replaced through this root's handle.
    ///
    /// # Errors
    ///
    /// The filesystem's refusal.
    pub fn write_record(&self, peer: &PeerId, bytes: &[u8]) -> io::Result<()> {
        self.root.write_record(peer, bytes)
    }

    /// Remove `peer`'s record, as a restored backup or a deleted file does.
    ///
    /// # Errors
    ///
    /// The filesystem's refusal.
    pub fn remove_record(&self, peer: &PeerId) -> io::Result<()> {
        self.root.remove_record(peer)
    }

    /// Whether `peer`'s record is a file under this root.
    ///
    /// # Errors
    ///
    /// The filesystem's refusal.
    pub fn record_exists(&self, peer: &PeerId) -> io::Result<bool> {
        self.root.record_exists(peer)
    }

    /// The mode of the records directory.
    ///
    /// # Errors
    ///
    /// The filesystem's refusal.
    #[cfg(unix)]
    pub fn records_dir_mode(&self) -> io::Result<u32> {
        self.root.records_dir_mode()
    }

    /// Give the records directory a mode, as a root that was never hardened leaves it.
    ///
    /// # Errors
    ///
    /// The filesystem's refusal.
    #[cfg(unix)]
    pub fn set_records_dir_mode(&self, mode: u32) -> io::Result<()> {
        self.root.set_records_dir_mode(mode)
    }

    /// Turn the records directory into a symbolic link to a directory beside it, as a
    /// backup tool that moved it leaves it.
    ///
    /// # Errors
    ///
    /// The filesystem's refusal.
    #[cfg(unix)]
    pub fn replace_records_dir_with_a_link(&self) -> io::Result<()> {
        self.root.replace_records_dir_with_a_link()
    }

    /// Replace the records directory with a regular file of the same name, so every record
    /// read through this root fails the way an operating-system fault does: the bytes are not
    /// seen at all, rather than a file being refused.
    ///
    /// This is the harness's way to an operating-system fault, so a case never names a path.
    ///
    /// # Errors
    ///
    /// The filesystem's refusal.
    #[cfg(unix)]
    pub(crate) fn hide_records_dir(&self) -> io::Result<Hidden<'a>> {
        self.root.hide_records_dir()
    }

    /// The name `peer`'s record has under this root, as the record module spells it: a
    /// name, not a path, so a case can compare it with what a refusal says.
    ///
    /// # Errors
    ///
    /// The filesystem's refusal.
    pub fn record_name(&self, peer: &PeerId) -> io::Result<String> {
        self.root.record_name(peer)
    }

    /// The name `peer`'s message queue has under this root, as the message module spells
    /// it: a name, not a path, so a case can compare it with what a refusal says.
    ///
    /// # Errors
    ///
    /// The filesystem's refusal.
    pub fn message_name(&self, peer: &PeerId) -> io::Result<String> {
        self.root.message_name(peer)
    }

    /// `peer`'s message queue, read through this root's handle.
    ///
    /// A case that asserts on a queue's bytes reads them here, the way it reads a
    /// record, rather than through a path.
    ///
    /// # Errors
    ///
    /// The filesystem's refusal.
    pub fn read_message(&self, peer: &PeerId) -> io::Result<Vec<u8>> {
        self.root.read_message(peer)
    }

    /// `peer`'s message queue, replaced through this root's handle.
    ///
    /// # Errors
    ///
    /// The filesystem's refusal.
    pub fn write_message(&self, peer: &PeerId, bytes: &[u8]) -> io::Result<()> {
        self.root.write_message(peer, bytes)
    }

    /// The name of the file a writer locks for `peer`'s queue, as the message module spells
    /// it: a name, not a path, so a case can compare it with what a refusal says.
    ///
    /// # Errors
    ///
    /// The filesystem's refusal.
    pub fn message_lock_name(&self, peer: &PeerId) -> io::Result<String> {
        self.root.message_lock_name(peer)
    }

    /// The whole `messages/` directory, removed as a cleaner or a botched restore removes it.
    ///
    /// # Errors
    ///
    /// The filesystem's refusal.
    pub fn remove_message_dir(&self) -> io::Result<()> {
        self.root.remove_message_dir()
    }

    /// `peer`'s message queue, removed as a lost or restored-over queue file is.
    ///
    /// # Errors
    ///
    /// The filesystem's refusal.
    pub fn remove_message(&self, peer: &PeerId) -> io::Result<()> {
        self.root.remove_message(peer)
    }

    /// Hold `peer`'s queue lock, as a second process on the same root does for the span of
    /// one read-modify-publish.
    ///
    /// # Errors
    ///
    /// The filesystem's refusal.
    pub fn lock_message(&self, peer: &PeerId) -> io::Result<std::fs::File> {
        self.root.lock_message(peer)
    }

    /// Give `peer`'s queue file a mode, as an installation whose root was never
    /// hardened leaves it reachable by another account.
    ///
    /// # Errors
    ///
    /// The filesystem's refusal.
    #[cfg(unix)]
    pub fn set_message_mode(&self, peer: &PeerId, mode: u32) -> io::Result<()> {
        self.root.set_message_file_mode(peer, mode)
    }

    /// The mode of the messages directory.
    ///
    /// # Errors
    ///
    /// The filesystem's refusal.
    #[cfg(unix)]
    pub fn message_dir_mode(&self) -> io::Result<u32> {
        self.root.message_dir_mode()
    }

    /// Give the messages directory a mode, as a root that was never hardened leaves it.
    ///
    /// # Errors
    ///
    /// The filesystem's refusal.
    #[cfg(unix)]
    pub fn set_message_dir_mode(&self, mode: u32) -> io::Result<()> {
        self.root.set_message_dir_mode(mode)
    }

    /// Turn the messages directory into a symbolic link to a directory beside it, as a
    /// backup tool that moved it leaves it.
    ///
    /// # Errors
    ///
    /// The filesystem's refusal.
    #[cfg(unix)]
    pub fn replace_message_dir_with_a_link(&self) -> io::Result<()> {
        self.root.replace_message_dir_with_a_link()
    }
}

impl fmt::Debug for Storage<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Storage").field(&self.root.id()).finish()
    }
}
