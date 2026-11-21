//! The durable peer record: one file per peer under the storage root.
//!
//! # What a record is
//!
//! One file per peer, named by the 64 hex characters of the peer's key, in a
//! `peers/` directory beside the key file. It holds the peer's key, when a person
//! made the comparison, the last address authenticated data arrived from, the
//! failures counted so far and any unfinished attempt with its expiry. The key is
//! the whole identity: the fingerprint is derived from it, never stored beside it
//! as a second fact, so a record cannot claim a key and a fingerprint that
//! disagree.
//!
//! # The bytes
//!
//! `mahbot-peer-record`, one version byte, then fields: `[tag][len u16 big-endian]
//! [body]`. Version 1's tags are `0x01` the key (32 bytes), `0x02` the pairing
//! moment (8, seconds), `0x03` the address (family, address, port, and for IPv6 the
//! flow info and scope id), `0x04` the failures (1) and `0x05` the attempt (8 expiry,
//! 4 lifetime seconds). A field this build does not know is kept and written back,
//! after the fields it knows: a rewrite may move it, which changes no meaning. The
//! file is named by the 64 lowercase hex characters of the key.
//!
//! # The format is a compatibility surface
//!
//! A change to it silently un-pairs every machine, so it is versioned and
//! **additive**: a reader ignores fields it does not know and writes them back
//! untouched, so a record written by a newer build is read by an older one and
//! survives being rewritten by it. The only refusals are a record that cannot be
//! parsed and a record reachable by accounts other than the product's. In
//! particular a version this build does not know is not a refusal: the fields it
//! knows are read from the prefix, and the rest is preserved. A version of zero is
//! not a record.
//!
//! # What it guarantees
//!
//! - **Atomic publish.** A record is written beside its own path, flushed, and
//!   published by one rename, so a reader never sees a half-written file and a
//!   crash leaves the previous record in place. Every write is flushed before the
//!   rename, the address hint included: a rename of an unflushed file can leave an
//!   empty or torn record that this build then refuses to open. The directory entry
//!   itself is not fsynced, as the key file's is not: a power loss in the instant
//!   after a publish can lose the record, which costs a comparison, not a wrong one.
//! - **A write never removes a completed pairing.** Every write re-reads the file
//!   first and merges conservatively: a pairing is never removed, a failure count
//!   never decreases, and a writer never overwrites a peer it did not touch — one
//!   file per peer is what makes that structural. The merge has no cross-process
//!   lock, so it holds when a writer's publish lands before the other's re-read;
//!   that is the order the self-update window's contract asks for, where the caller
//!   calls [`RecordStore::reload`] before it decides to trust a peer. A record that
//!   cannot be read is a typed refusal; the store does not open over it.
//! - **A write never produces a file this build cannot read.** A record that would
//!   grow past `MAX_BYTES` is refused before anything is written, so an additive
//!   rewrite of a record a newer build left near the cap cannot turn into a file the
//!   next open refuses.
//! - **A ceremony with a stranger leaves nothing behind.** An unfinished attempt is
//!   recorded on the peer's record so it can expire; when the attempt ends and the
//!   record holds nothing else — no pairing, no failure, no address, no field a
//!   newer build wrote — the file is removed. The product drops expired attempts with
//!   [`RecordStore::prune_expired`] at start-up, which removes a record left holding
//!   nothing: a machine with a beacon session can therefore start many ceremonies but
//!   cannot grow `peers/` one file per invented identity, and a crash leaves one
//!   behind only until the next `prune_expired` call.
//! - **Privacy.** A record is reachable only by the account the product runs as,
//!   with the key file's rule, Windows allowed set included; the `peers/` directory
//!   is held to the same rule, because a directory another account can write lets it
//!   delete a record. The directory is created here, so it is hardened here before
//!   the rule reads it — a fresh directory inherits what the platform gave it. A
//!   record or directory reachable by anyone else is refused loudly, never trusted.
//! - **The root must exist.** It is never created, and a `peers/` directory that is
//!   not private is never used: a mistyped or deleted root fails loudly instead of
//!   answering an empty set that looks like a machine which knows nobody.
//! - **No silent trust.** A record that cannot be read, that is insecure, or whose
//!   bytes are not a record is a typed refusal naming the file; it never becomes a
//!   pairing. A one-sided record is not a contradiction to be resolved here: the
//!   ceremony sees that the other side does not hold the pair and runs the comparison
//!   again.
//! - **The library never reads a clock.** Every moment is a [`Timestamp`] the
//!   caller supplies; an attempt's lifetime is recorded with the attempt, so the
//!   expiry a record carries is the one it was made with, not one recomputed from a
//!   configuration that may have changed since.
//!
//! The store's writes are small blocking file operations, like the key file's one
//! create: a caller runs them where blocking is allowed. The manager's one write per
//! changed accepted address is the case to look at; `peer::connect` says where it
//! runs.
//!
//! Who the person was is the product's fact, not the network's: the record says that
//! a comparison happened and when, and the product says which person made it.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::hex;
use crate::identity::access::{self, Insecurity};
use crate::identity::{Fingerprint, PEER_ID_LEN, PeerId};
use crate::peer::address;
use crate::private;
use crate::tls::PeerPolicy;

/// The directory under a storage root that holds the records.
const PEERS_DIR: &str = "peers";

/// The record file's extension. A file in `peers/` without it is ignored — a
/// desktop's metadata or an operator's note is not a record. A file with it must be
/// a record: a name that is not a key, or bytes that are not a record, are refused,
/// because a file that claims to be a record and is not one is exactly what must not
/// be silently trusted.
const RECORD_EXTENSION: &str = "record";

/// The bytes every record opens with.
const MAGIC: &[u8] = b"mahbot-peer-record";

/// The record format this build writes. A record of a higher version is read as
/// this version's prefix and its unknown fields are preserved; see the module docs.
const VERSION: u8 = 1;

/// The most bytes a record may have. A record is under a hundred bytes; the cap
/// keeps a hostile file from being read into memory, and a write that would pass
/// it is refused rather than producing a file the next open cannot read.
const MAX_BYTES: u64 = 4096;

/// The field tags of version 1. Unknown tags are preserved, not refused.
mod tag {
    pub const KEY: u8 = 0x01;
    pub const PAIRED_AT: u8 = 0x02;
    pub const LAST_ADDRESS: u8 = 0x03;
    pub const FAILURES: u8 = 0x04;
    pub const ATTEMPT: u8 = 0x05;
}

/// A moment the caller supplies. The library never reads a clock.
///
/// Whole seconds since the Unix epoch, because that is what a record can carry
/// portably and what the product already stores. A caller with a finer clock
/// rounds; a lifetime below one second is therefore recorded as zero and an
/// attempt made with it has already expired.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(u64);

impl Timestamp {
    /// Read a moment from whole seconds since the Unix epoch.
    #[must_use]
    pub const fn from_unix_seconds(seconds: u64) -> Self {
        Self(seconds)
    }

    /// The moment as whole seconds since the Unix epoch.
    #[must_use]
    pub const fn unix_seconds(self) -> u64 {
        self.0
    }

    /// This moment moved forward by `after`, saturating at the end of time.
    #[must_use]
    pub fn plus(self, after: Duration) -> Self {
        Self(self.0.saturating_add(after.as_secs()))
    }

    /// How much time is left until this moment, at `now`; zero once it has passed.
    #[must_use]
    pub(crate) fn remaining(self, now: Self) -> Duration {
        Duration::from_secs(self.0.saturating_sub(now.0))
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The limits a store applies, stated once so a record and a ceremony agree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// How many failed comparisons close the pair on this machine. Three: each
    /// failed attempt is one where a person compared the strings and did not
    /// confirm them.
    pub max_failures: u8,
    /// How long an unfinished attempt stays unfinished. Fifteen minutes, a stated
    /// default rather than a value read from anywhere; the value an attempt was made
    /// with is recorded beside its expiry.
    pub attempt_lifetime: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_failures: 3,
            attempt_lifetime: Duration::from_mins(15),
        }
    }
}

/// An unfinished acquaintance, as the record carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attempt {
    /// When this attempt stops being one.
    pub expires_at: Timestamp,
    /// The lifetime it was made with, so a reader sees the value the expiry was
    /// computed from.
    pub lifetime: Duration,
}

impl Attempt {
    /// Whether the attempt has expired at `now`.
    fn expired(self, now: Timestamp) -> bool {
        now >= self.expires_at
    }
}

/// One peer as this machine remembers it.
///
/// Constructed by [`RecordStore`] only: a record is what a file says, and the
/// store is the one place that reads and writes one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerRecord {
    key: PeerId,
    /// The version the file was written under. A rewrite keeps it, so a record a
    /// newer build wrote is still that build's after an older one touched it.
    version: u8,
    paired_at: Option<Timestamp>,
    last_address: Option<SocketAddr>,
    failures: u8,
    attempt: Option<Attempt>,
    /// Fields this build does not know, kept in file order and written back
    /// untouched. This is what makes the format additive in both directions.
    unknown: Vec<(u8, Vec<u8>)>,
}

impl PeerRecord {
    /// A record for `key` with nothing remembered yet.
    fn empty(key: PeerId) -> Self {
        Self {
            key,
            version: VERSION,
            paired_at: None,
            last_address: None,
            failures: 0,
            attempt: None,
            unknown: Vec::new(),
        }
    }

    /// The peer's fingerprint, derived from the key and never stored.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        self.key.fingerprint()
    }

    /// When a person made the comparison, if they did.
    #[must_use]
    pub const fn paired_at(&self) -> Option<Timestamp> {
        self.paired_at
    }

    /// Whether a person on this machine made the comparison.
    ///
    /// This is this machine's half of the pair. Whether the other machine holds it
    /// too is the ceremony's question: a one-sided record is still a record, and the
    /// ceremony runs the comparison again rather than treating it as both sides.
    #[must_use]
    pub const fn is_paired(&self) -> bool {
        self.paired_at.is_some()
    }

    /// The last address authenticated data arrived from that peer.
    ///
    /// The source address of an accepted connection: the address the peer can be
    /// dialed back at. It is never the address this machine dialed — that says
    /// nothing about where the peer is — and never this machine's own appearance.
    #[must_use]
    pub const fn last_address(&self) -> Option<SocketAddr> {
        self.last_address
    }

    /// How many failed comparisons this machine has counted.
    #[must_use]
    pub const fn failures(&self) -> u8 {
        self.failures
    }

    /// The unfinished attempt, if one is recorded.
    #[must_use]
    pub const fn attempt(&self) -> Option<Attempt> {
        self.attempt
    }

    /// Whether the record says nothing worth keeping.
    ///
    /// A record that only ever held an unfinished attempt becomes this when the
    /// attempt ends, and the store removes it: a ceremony with a stranger leaves no
    /// file behind.
    fn is_empty(&self) -> bool {
        self.paired_at.is_none()
            && self.last_address.is_none()
            && self.failures == 0
            && self.attempt.is_none()
            && self.unknown.is_empty()
    }
}

/// The durable records of one storage root, and the trust they answer for.
///
/// Cheap to clone: every clone shares one map and one directory. The store is
/// also the [`PeerPolicy`] the transport asks during a handshake, so a peer is
/// trusted exactly when a record says a person paired it.
#[derive(Clone)]
pub struct RecordStore {
    inner: Arc<Inner>,
}

struct Inner {
    dir: PathBuf,
    limits: Limits,
    /// The loaded records. The write guard is also the writer lock: a mutation
    /// holds it across its re-read and publish, so two writers in one process
    /// cannot interleave.
    records: RwLock<BTreeMap<PeerId, PeerRecord>>,
}

impl fmt::Debug for RecordStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordStore")
            .field("dir", &self.inner.dir)
            .field("limits", &self.inner.limits)
            .field("records", &self.records())
            .finish()
    }
}

impl RecordStore {
    /// Open the records under `root`, creating the `peers/` directory if this is
    /// the first start.
    ///
    /// The root itself must exist and is never created: a mistyped or deleted root
    /// must fail loudly, not answer an empty set that looks like a machine which
    /// knows nobody. Every record in the directory is read now; a record that cannot
    /// be read, is reachable by another account, or is not a record is a typed
    /// refusal naming the file.
    ///
    /// Opening writes nothing but a first-run `peers/`: expired attempts are dropped
    /// by [`Self::prune_expired`], which the product calls at start-up, so a live
    /// attempt another process is running survives this open.
    pub fn open(root: &Path, limits: Limits) -> Result<Self, RecordError> {
        if !root.is_dir() {
            return Err(RecordError::RootMissing {
                path: root.to_owned(),
            });
        }
        let dir = root.join(PEERS_DIR);
        create_private_dir(&dir)?;
        let records = load(&dir)?;
        Ok(Self {
            inner: Arc::new(Inner {
                dir,
                limits,
                records: RwLock::new(records),
            }),
        })
    }

    /// Drop every attempt that has expired at `now`, and remove a record left
    /// holding nothing.
    ///
    /// A product calls this at start-up. Only an expired attempt goes: an attempt
    /// belongs to the process that made it, and one still running — the self-update
    /// window keeps two processes on one root — keeps its guard against a second
    /// ceremony for one peer. Each file is re-read under the write guard and its
    /// attempt checked again there, so an attempt another process started after this
    /// store loaded it is kept. The walk covers the records this store has loaded; a
    /// record another process wrote after this open is pruned by that process's own
    /// start-up call.
    ///
    /// This is the one operation a start-up needs a writable `peers/` for: opening
    /// and reading do not. A record that cannot be re-read or published does not
    /// stop the sweep — the rest are still pruned, and the first failure is returned
    /// at the end.
    pub fn prune_expired(&self, now: Timestamp) -> Result<(), RecordError> {
        let peers: Vec<PeerId> = self
            .records()
            .iter()
            .filter(|(_, record)| record.attempt.is_some_and(|attempt| attempt.expired(now)))
            .map(|(peer, _)| *peer)
            .collect();
        let mut first_error = None;
        for peer in peers {
            let pruned = self.update_existing(&peer, |record, _| {
                Ok(match record.attempt {
                    Some(attempt) if attempt.expired(now) => drop_attempt(record),
                    _ => Change::Nothing,
                })
            });
            if let Err(error) = pruned
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// The limits this store applies.
    #[must_use]
    pub fn limits(&self) -> Limits {
        self.inner.limits
    }

    /// The record for `peer`, if this machine remembers anything about it.
    #[must_use]
    pub fn get(&self, peer: &PeerId) -> Option<PeerRecord> {
        self.records().get(peer).cloned()
    }

    /// Whether a person on this machine made the comparison for `peer`.
    ///
    /// This is this machine's half of the pair; whether the other machine holds it is
    /// the ceremony's question. Trust is [`Self::trusts`], which also asks whether the
    /// pair is closed.
    #[must_use]
    pub fn is_paired(&self, peer: &PeerId) -> bool {
        self.records().get(peer).is_some_and(PeerRecord::is_paired)
    }

    /// Whether failed comparisons have closed the pair on this machine.
    #[must_use]
    pub fn is_closed(&self, peer: &PeerId) -> bool {
        self.records()
            .get(peer)
            .is_some_and(|record| record.failures >= self.inner.limits.max_failures)
    }

    /// Whether this machine trusts `peer`: a person paired it and the pair is not
    /// closed.
    ///
    /// This is the one trust predicate, and it is local: the far side's refusal text
    /// is diagnostic and may be forged, so nothing outward-facing reads it. A pair
    /// that reached the failure limit is closed even if it was paired before, and a
    /// closed pair is not trusted until a person clears it.
    #[must_use]
    pub fn trusts(&self, peer: &PeerId) -> bool {
        self.records().get(peer).is_some_and(|record| {
            record.is_paired() && record.failures < self.inner.limits.max_failures
        })
    }

    /// Re-read every record from disk, replacing the loaded map.
    ///
    /// The self-update window keeps two processes on one root for a few seconds; a
    /// process that is about to decide whether to trust a peer calls this so it sees
    /// what the other wrote. The caller owns the moment: nothing in this crate calls
    /// it behind a caller's back. A record that has become unreadable is a typed
    /// refusal like [`RecordStore::open`]'s.
    pub fn reload(&self) -> Result<(), RecordError> {
        let records = load(&self.inner.dir)?;
        *self.write_map() = records;
        Ok(())
    }

    /// Record that a person paired this machine with `peer` at `at`.
    ///
    /// An existing pairing keeps the moment it was made: a re-comparison repairs a
    /// one-sided pair, it does not re-date the acquaintance. A closed pair is
    /// refused; a person must [`RecordStore::clear`] it first.
    pub fn record_pairing(&self, peer: &PeerId, at: Timestamp) -> Result<PeerRecord, RecordError> {
        self.update(peer, |record, limits| {
            if record.failures >= limits.max_failures {
                return Err(RecordError::Closed { peer: *peer });
            }
            let changed = record.paired_at.is_none() || record.attempt.is_some();
            if record.paired_at.is_none() {
                record.paired_at = Some(at);
            }
            record.attempt = None;
            Ok(if changed {
                Change::Write
            } else {
                Change::Nothing
            })
        })
        .map(|record| record.expect("a pairing creates the record"))
    }

    /// Record `address` as the last address authenticated data arrived from.
    ///
    /// The address is a hint that saves a beacon trip, not identity; it is
    /// published and flushed like any other write, and an address that did not
    /// change is not rewritten.
    pub fn record_address(
        &self,
        peer: &PeerId,
        address: SocketAddr,
    ) -> Result<PeerRecord, RecordError> {
        self.update(peer, |record, _| {
            if record.last_address == Some(address) {
                return Ok(Change::Nothing);
            }
            record.last_address = Some(address);
            Ok(Change::Write)
        })
        .map(|record| record.expect("an address hint creates the record"))
    }

    /// Count one failed comparison for `peer`, saturating at the limit.
    ///
    /// Returns the record, so a caller sees whether the pair is now closed.
    pub fn record_failure(&self, peer: &PeerId) -> Result<PeerRecord, RecordError> {
        self.update(peer, |record, limits| {
            record.failures = record.failures.saturating_add(1).min(limits.max_failures);
            record.attempt = None;
            Ok(Change::Write)
        })
        .map(|record| record.expect("a failure creates the record"))
    }

    /// A person's reset on this machine: forget the failures and any unfinished
    /// attempt. It does not un-pair, a peer this machine remembers nothing about is
    /// left absent rather than given an empty record, and a record whose only facts
    /// were the failures and the attempt is removed rather than rewritten empty.
    pub fn clear(&self, peer: &PeerId) -> Result<(), RecordError> {
        self.update_existing(peer, |record, _| {
            if record.failures == 0 && record.attempt.is_none() {
                return Ok(Change::Nothing);
            }
            record.failures = 0;
            record.attempt = None;
            Ok(kept(record))
        })
        .map(drop)
    }

    /// Start an unfinished attempt for `peer` at `now`.
    ///
    /// Refused while the pair is closed and while an attempt that has not expired
    /// is still recorded; an expired one is replaced.
    pub fn begin_attempt(&self, peer: &PeerId, now: Timestamp) -> Result<Attempt, RecordError> {
        self.attempt(peer, now, |record, now| match record.attempt {
            Some(live) if !live.expired(now) => Err(RecordError::AttemptInProgress {
                peer: *peer,
                expires_at: live.expires_at,
            }),
            _ => Ok(()),
        })
    }

    /// Replace the unfinished attempt for `peer` with one starting at `now`.
    ///
    /// This is the simultaneous-start case: this machine's own attempt yields to the
    /// other machine's opening flight, and the attempt it records is restarted, not
    /// ended and begun — one write and one rule. A closed pair is still refused.
    pub fn restart_attempt(&self, peer: &PeerId, now: Timestamp) -> Result<Attempt, RecordError> {
        self.attempt(peer, now, |_, _| Ok(()))
    }

    /// Record an attempt for `peer`, after `guard` accepts the one already there.
    fn attempt<G>(&self, peer: &PeerId, now: Timestamp, guard: G) -> Result<Attempt, RecordError>
    where
        G: FnOnce(&PeerRecord, Timestamp) -> Result<(), RecordError>,
    {
        let lifetime = self.inner.limits.attempt_lifetime;
        let attempt = Attempt {
            expires_at: now.plus(lifetime),
            lifetime,
        };
        self.update(peer, |record, limits| {
            if record.failures >= limits.max_failures {
                return Err(RecordError::Closed { peer: *peer });
            }
            guard(record, now)?;
            record.attempt = Some(attempt);
            Ok(Change::Write)
        })?;
        Ok(attempt)
    }

    /// Clear the unfinished attempt for `peer`, if one is recorded.
    ///
    /// A ceremony that reached an outcome calls this, and one that failed before
    /// reaching one calls it too: an attempt that ended without a comparison
    /// counts against nobody and must not block a retry. A record that does not
    /// exist is left absent — this never creates one — and a record with no
    /// attempt is not rewritten. A record left holding nothing but the attempt is
    /// removed: a ceremony with a stranger leaves no file behind.
    pub fn end_attempt(&self, peer: &PeerId) -> Result<(), RecordError> {
        self.update_existing(peer, |record, _| Ok(drop_attempt(record)))
            .map(drop)
    }

    /// The path of `peer`'s record under this root.
    #[must_use]
    pub fn path_for(&self, peer: &PeerId) -> PathBuf {
        path_in(&self.inner.dir, peer)
    }

    fn records(&self) -> std::sync::RwLockReadGuard<'_, BTreeMap<PeerId, PeerRecord>> {
        self.inner
            .records
            .read()
            .expect("the record map is not poisoned")
    }

    fn write_map(&self) -> std::sync::RwLockWriteGuard<'_, BTreeMap<PeerId, PeerRecord>> {
        self.inner
            .records
            .write()
            .expect("the record map is not poisoned")
    }

    /// Read the file again, apply `change`, publish it if the record changed, and
    /// update the map. A missing file becomes an empty record: the caller is writing
    /// something about a peer it remembers nothing about.
    fn update<F>(&self, peer: &PeerId, change: F) -> Result<Option<PeerRecord>, RecordError>
    where
        F: FnOnce(&mut PeerRecord, &Limits) -> Result<Change, RecordError>,
    {
        self.write(peer, true, change)
    }

    /// [`Self::update`] for a change that must not create the record: a missing file
    /// is left missing and `None` is answered.
    fn update_existing<F>(
        &self,
        peer: &PeerId,
        change: F,
    ) -> Result<Option<PeerRecord>, RecordError>
    where
        F: FnOnce(&mut PeerRecord, &Limits) -> Result<Change, RecordError>,
    {
        self.write(peer, false, change)
    }

    /// Read the file again, apply `change`, publish or remove it, and update the map.
    ///
    /// Holding the write guard across the whole read-modify-publish is what keeps
    /// two writers in one process from losing each other's pairing; re-reading the
    /// file is what keeps a writer from overwriting a pairing another process
    /// completed. The merge is conservative: `change` only ever sees the record the
    /// file holds now, so a pairing, a failure count and an unknown field cannot be
    /// dropped by a writer that did not touch them. `create` decides whether a
    /// missing file becomes an empty record. `None` is a peer with no file and
    /// nothing written: the caller asked for nothing to be written about a peer it
    /// remembers nothing about.
    fn write<F>(
        &self,
        peer: &PeerId,
        create: bool,
        change: F,
    ) -> Result<Option<PeerRecord>, RecordError>
    where
        F: FnOnce(&mut PeerRecord, &Limits) -> Result<Change, RecordError>,
    {
        let mut map = self.write_map();
        let (mut record, from_file) = match read_file(&self.path_for(peer), peer)? {
            Some(record) => (record, true),
            None if create => (PeerRecord::empty(*peer), false),
            None => return Ok(None),
        };
        match change(&mut record, &self.inner.limits)? {
            Change::Write => {
                publish(&self.inner.dir, &record)?;
                map.insert(*peer, record.clone());
                Ok(Some(record))
            }
            Change::Remove => {
                let path = self.path_for(peer);
                match fs::remove_file(&path) {
                    Ok(()) => {}
                    // Another process removed it first: the record it held is gone
                    // either way, and this is not an error.
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(source) => return Err(RecordError::Io { path, source }),
                }
                map.remove(peer);
                Ok(None)
            }
            Change::Nothing if from_file => {
                map.insert(*peer, record.clone());
                Ok(Some(record))
            }
            Change::Nothing => Ok(None),
        }
    }
}

/// What a mutation wants done with the record it read.
enum Change {
    /// Publish the record.
    Write,
    /// Remove the file and the map entry: the record holds nothing worth keeping.
    Remove,
    /// Nothing changed, so nothing is written.
    Nothing,
}

/// Remove the record when it now holds nothing, publish it otherwise.
fn kept(record: &PeerRecord) -> Change {
    if record.is_empty() {
        Change::Remove
    } else {
        Change::Write
    }
}

/// Drop the attempt `record` holds, removing the record when that was all it had.
fn drop_attempt(record: &mut PeerRecord) -> Change {
    if record.attempt.take().is_none() {
        return Change::Nothing;
    }
    kept(record)
}

impl PeerPolicy for RecordStore {
    fn trusts(&self, peer: &Fingerprint) -> bool {
        self.trusts(&peer.peer_id())
    }
}

/// Why a record could not be read, written, or believed.
#[derive(Debug)]
pub enum RecordError {
    /// The storage root does not exist, or is not a directory. It is never created
    /// here: a mistyped or deleted root must fail loudly instead of answering an
    /// empty set that looks like a machine which knows nobody.
    RootMissing { path: PathBuf },
    /// The operating system could not read the file. Distinct from
    /// [`Self::Malformed`]: the bytes were not seen at all.
    Unreadable { path: PathBuf, source: io::Error },
    /// The record is reachable by an account the rule does not allow. Distinct
    /// from every other cause: this is a refusal to trust the file, not an absence
    /// and not a parse failure.
    Insecure { path: PathBuf, reason: Insecurity },
    /// The file is there and its bytes are not a record this build can read.
    Malformed { path: PathBuf, reason: Malformed },
    /// The record could not be written, or the `peers/` directory could not be
    /// made or read.
    Io { path: PathBuf, source: io::Error },
    /// The record would be larger than `MAX_BYTES`, so it was not written. The
    /// file on disk is left as it was.
    TooLarge { path: PathBuf, bytes: u64 },
    /// An attempt that has not expired is already recorded for this peer.
    AttemptInProgress { peer: PeerId, expires_at: Timestamp },
    /// Failed comparisons have closed the pair on this machine. A person must
    /// clear it here; a restart does not.
    Closed { peer: PeerId },
}

/// What is wrong with a file that is not a record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Malformed {
    /// The file is empty: a write that never landed.
    Empty,
    /// The file is larger than `MAX_BYTES`.
    TooLarge { bytes: u64 },
    /// The file does not open with the record magic.
    Magic,
    /// The version is zero, which is not a record. A version this build does not
    /// know is read, not refused: see the module docs.
    Version { found: u8 },
    /// A known field has the wrong shape or length.
    Field { tag: u8, detail: String },
    /// A known field appears twice.
    Duplicate { tag: u8 },
    /// There is no key field, so the record names no peer.
    NoKey,
    /// The key in the file is not the key the file name names.
    KeyMismatch { named: PeerId, found: PeerId },
    /// The file name is not a record name.
    Name { name: String },
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootMissing { path } => write!(
                f,
                "{}: the storage root does not exist or is not a directory; it is never created",
                path.display()
            ),
            Self::Unreadable { path, source } => {
                write!(
                    f,
                    "{}: the peer record cannot be read: {source}",
                    path.display()
                )
            }
            Self::Insecure { path, reason } => {
                write!(f, "{} is not private: {reason}", path.display())?;
                match reason.remedy(path) {
                    Some(command) => write!(f, "; {command}"),
                    None => Ok(()),
                }
            }
            Self::Malformed { path, reason } => {
                write!(f, "{} is not a peer record: {reason}", path.display())
            }
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::TooLarge { path, bytes } => write!(
                f,
                "{}: the record would be {bytes} bytes, more than {MAX_BYTES}; it was not written",
                path.display()
            ),
            Self::AttemptInProgress { peer, expires_at } => write!(
                f,
                "an unfinished acquaintance with {} is recorded until {expires_at}",
                peer.fingerprint()
            ),
            Self::Closed { peer } => write!(
                f,
                "the pair with {} is closed on this machine until a person clears it",
                peer.fingerprint()
            ),
        }
    }
}

impl std::error::Error for RecordError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Unreadable { source, .. } | Self::Io { source, .. } => Some(source),
            Self::RootMissing { .. }
            | Self::Insecure { .. }
            | Self::Malformed { .. }
            | Self::TooLarge { .. }
            | Self::AttemptInProgress { .. }
            | Self::Closed { .. } => None,
        }
    }
}

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the file is empty"),
            Self::TooLarge { bytes } => {
                write!(f, "the file holds {bytes} bytes, more than {MAX_BYTES}")
            }
            Self::Magic => f.write_str("the file does not open with the record magic"),
            Self::Version { found } => {
                write!(f, "the version byte is {found}, which is not a record")
            }
            Self::Field { tag, detail } => write!(f, "field {tag:#04x} {detail}"),
            Self::Duplicate { tag } => write!(f, "field {tag:#04x} appears twice"),
            Self::NoKey => f.write_str("the record names no key"),
            Self::KeyMismatch { named, found } => write!(
                f,
                "the file is named for {} but holds {}",
                named.fingerprint(),
                found.fingerprint()
            ),
            Self::Name { name } => {
                write!(
                    f,
                    "`{name}` is not a record name: 64 lowercase hex characters"
                )
            }
        }
    }
}

/// Create `dir` if it is missing, and hold it to the key file's rule.
///
/// A directory another account can write lets it delete a record, which is a silent
/// un-pairing, so an existing directory is checked as well as a new one. The check
/// is the same on both platforms: unix reads the mode, the owner and (on macOS) the
/// extended list from a descriptor opened without following a link; Windows reads
/// the directory's access list and owner from a handle opened for the directory.
///
/// A directory this crate creates is hardened before it is checked: a fresh
/// directory inherits its parent's access list on Windows and the umask's mode on
/// unix, and the rule would refuse what it inherited.
fn create_private_dir(dir: &Path) -> Result<(), RecordError> {
    if !dir.is_dir() {
        match fs::create_dir(dir) {
            Ok(()) => {
                access::make_directory_private(dir).map_err(|source| RecordError::Io {
                    path: dir.to_owned(),
                    source,
                })?;
            }
            // Something is at the path and is not a directory — a regular file, or a
            // link to one. The check below refuses a link as a link; a regular file
            // fails its `O_DIRECTORY` open and surfaces as `Io`.
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(RecordError::Io {
                    path: dir.to_owned(),
                    source,
                });
            }
        }
    }
    if let Some(reason) = access::check_directory(dir).map_err(|source| RecordError::Io {
        path: dir.to_owned(),
        source,
    })? {
        return Err(RecordError::Insecure {
            path: dir.to_owned(),
            reason,
        });
    }
    Ok(())
}

/// Read every record in `dir`.
fn load(dir: &Path) -> Result<BTreeMap<PeerId, PeerRecord>, RecordError> {
    let mut records = BTreeMap::new();
    let entries = fs::read_dir(dir).map_err(|source| RecordError::Io {
        path: dir.to_owned(),
        source,
    })?;
    for entry in entries {
        let path = entry
            .map_err(|source| RecordError::Io {
                path: dir.to_owned(),
                source,
            })?
            .path();
        if path
            .extension()
            .is_none_or(|extension| extension != RECORD_EXTENSION)
        {
            continue;
        }
        let name = path
            .file_stem()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let key = hex::decode(&name).and_then(|bytes| {
            <[u8; PEER_ID_LEN]>::try_from(bytes.as_slice())
                .ok()
                .map(PeerId::from_bytes)
        });
        let Some(key) = key else {
            return Err(RecordError::Malformed {
                path: path.clone(),
                reason: Malformed::Name { name },
            });
        };
        // A record that vanished between the listing and the read is not a
        // malformed one: another process published or removed it.
        let Some(record) = read_file(&path, &key)? else {
            continue;
        };
        records.insert(key, record);
    }
    Ok(records)
}

/// The record file's path for `peer` inside `dir`.
fn path_in(dir: &Path, peer: &PeerId) -> PathBuf {
    dir.join(format!(
        "{}.{RECORD_EXTENSION}",
        hex::encode(peer.as_bytes())
    ))
}

/// Read one record, or `None` when nothing is at `path`.
fn read_file(path: &Path, expected: &PeerId) -> Result<Option<PeerRecord>, RecordError> {
    let file = match private::open_private(path) {
        Ok(Some(file)) => file,
        Ok(None) => return Ok(None),
        Err(private::PrivateFileError::Insecure(reason)) => {
            return Err(RecordError::Insecure {
                path: path.to_owned(),
                reason,
            });
        }
        Err(private::PrivateFileError::Io(source)) => {
            return Err(RecordError::Unreadable {
                path: path.to_owned(),
                source,
            });
        }
    };
    let (bytes, length) =
        private::read_capped(file, MAX_BYTES + 1).map_err(|source| RecordError::Unreadable {
            path: path.to_owned(),
            source,
        })?;
    if let Some(length) = length
        && length > MAX_BYTES
    {
        return Err(RecordError::Malformed {
            path: path.to_owned(),
            reason: Malformed::TooLarge { bytes: length },
        });
    }
    if bytes.is_empty() {
        return Err(RecordError::Malformed {
            path: path.to_owned(),
            reason: Malformed::Empty,
        });
    }
    if bytes.len() as u64 > MAX_BYTES {
        return Err(RecordError::Malformed {
            path: path.to_owned(),
            reason: Malformed::TooLarge {
                bytes: bytes.len() as u64,
            },
        });
    }
    decode(&bytes, expected)
        .map(Some)
        .map_err(|reason| RecordError::Malformed {
            path: path.to_owned(),
            reason,
        })
}

/// Publish `record` atomically: a private temporary file beside the destination,
/// flushed, and published by one rename.
///
/// Every write is flushed, the address hint included: a rename of an unflushed
/// file can leave an empty or torn record, which the next open refuses. A record
/// that would pass `MAX_BYTES` is refused before the temporary file is written,
/// so this build never publishes a file it cannot read back.
fn publish(dir: &Path, record: &PeerRecord) -> Result<(), RecordError> {
    let path = path_in(dir, &record.key);
    let bytes = encode(record, &path)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(RecordError::TooLarge {
            path,
            bytes: bytes.len() as u64,
        });
    }
    let mut temp = private::private_temp(&path, ".peer.").map_err(|error| match error {
        private::PrivateFileError::Io(source) => RecordError::Io {
            path: path.clone(),
            source,
        },
        private::PrivateFileError::Insecure(reason) => RecordError::Insecure {
            path: path.clone(),
            reason,
        },
    })?;
    temp.write_all(&bytes).map_err(|source| RecordError::Io {
        path: path.clone(),
        source,
    })?;
    temp.as_file()
        .sync_all()
        .map_err(|source| RecordError::Io {
            path: path.clone(),
            source,
        })?;
    temp.persist(&path).map_err(|error| RecordError::Io {
        path: path.clone(),
        source: error.error,
    })?;
    Ok(())
}

/// The record's bytes, or the refusal a body too large for the field length would
/// be. [`publish`] reports that as [`RecordError::TooLarge`] and writes nothing.
fn encode(record: &PeerRecord, path: &Path) -> Result<Vec<u8>, RecordError> {
    let mut bytes = Vec::with_capacity(128);
    bytes.extend_from_slice(MAGIC);
    bytes.push(record.version);
    field(&mut bytes, tag::KEY, record.key.as_bytes(), path)?;
    if let Some(at) = record.paired_at {
        field(
            &mut bytes,
            tag::PAIRED_AT,
            &at.unix_seconds().to_be_bytes(),
            path,
        )?;
    }
    if let Some(address) = record.last_address {
        let mut body = Vec::with_capacity(27);
        address::encode(&mut body, Some(address));
        field(&mut bytes, tag::LAST_ADDRESS, &body, path)?;
    }
    field(&mut bytes, tag::FAILURES, &[record.failures], path)?;
    if let Some(attempt) = record.attempt {
        let mut body = Vec::with_capacity(12);
        body.extend_from_slice(&attempt.expires_at.unix_seconds().to_be_bytes());
        body.extend_from_slice(
            &u32::try_from(attempt.lifetime.as_secs())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        field(&mut bytes, tag::ATTEMPT, &body, path)?;
    }
    for (tag, body) in &record.unknown {
        field(&mut bytes, *tag, body, path)?;
    }
    Ok(bytes)
}

/// Append one `[tag][len u16 big-endian][body]` field.
///
/// A body over `u16::MAX` has no length it could write, and writing a truncated
/// length would produce a file this build cannot read back; it is refused instead.
fn field(bytes: &mut Vec<u8>, tag: u8, body: &[u8], path: &Path) -> Result<(), RecordError> {
    let total = bytes.len() as u64 + 3 + body.len() as u64;
    let length = u16::try_from(body.len()).map_err(|_| RecordError::TooLarge {
        path: path.to_owned(),
        bytes: total,
    })?;
    bytes.push(tag);
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(body);
    Ok(())
}

/// Read a record from its bytes. A version above [`VERSION`] is read as this
/// version's prefix; its unknown fields are preserved in `unknown`.
fn decode(bytes: &[u8], expected: &PeerId) -> Result<PeerRecord, Malformed> {
    let rest = bytes.strip_prefix(MAGIC).ok_or(Malformed::Magic)?;
    let (&version, mut rest) = rest.split_first().ok_or(Malformed::Magic)?;
    if version == 0 {
        return Err(Malformed::Version { found: version });
    }
    let mut record = PeerRecord::empty(*expected);
    record.version = version;
    let mut seen = Vec::new();
    while !rest.is_empty() {
        let (&tag, after_tag) = rest.split_first().ok_or(Malformed::Magic)?;
        if after_tag.len() < 2 {
            return Err(Malformed::Field {
                tag,
                detail: "has no length".to_owned(),
            });
        }
        let length = usize::from(u16::from_be_bytes([after_tag[0], after_tag[1]]));
        let body = after_tag.get(2..2 + length).ok_or(Malformed::Field {
            tag,
            detail: "runs past the end of the file".to_owned(),
        })?;
        rest = &after_tag[2 + length..];
        if matches!(
            tag,
            tag::KEY | tag::PAIRED_AT | tag::LAST_ADDRESS | tag::FAILURES | tag::ATTEMPT
        ) {
            if seen.contains(&tag) {
                return Err(Malformed::Duplicate { tag });
            }
            seen.push(tag);
        }
        match tag {
            tag::KEY => {
                let key: [u8; PEER_ID_LEN] = body.try_into().map_err(|_| Malformed::Field {
                    tag,
                    detail: "is not a 32-byte key".to_owned(),
                })?;
                record.key = PeerId::from_bytes(key);
            }
            tag::PAIRED_AT => {
                record.paired_at = Some(Timestamp::from_unix_seconds(read_u64(tag, body)?));
            }
            tag::LAST_ADDRESS => {
                record.last_address = Some(decode_address(tag, body)?);
            }
            tag::FAILURES => {
                let [failures] = body else {
                    return Err(Malformed::Field {
                        tag,
                        detail: "is not one byte".to_owned(),
                    });
                };
                record.failures = *failures;
            }
            tag::ATTEMPT => {
                if body.len() != 12 {
                    return Err(Malformed::Field {
                        tag,
                        detail: "is not twelve bytes".to_owned(),
                    });
                }
                let expires = Timestamp::from_unix_seconds(u64::from_be_bytes(
                    body[..8].try_into().expect("eight bytes"),
                ));
                let lifetime = Duration::from_secs(u64::from(u32::from_be_bytes(
                    body[8..].try_into().expect("four bytes"),
                )));
                record.attempt = Some(Attempt {
                    expires_at: expires,
                    lifetime,
                });
            }
            other => record.unknown.push((other, body.to_vec())),
        }
    }
    if !seen.contains(&tag::KEY) {
        return Err(Malformed::NoKey);
    }
    if record.key != *expected {
        return Err(Malformed::KeyMismatch {
            named: *expected,
            found: record.key,
        });
    }
    Ok(record)
}

fn read_u64(tag: u8, body: &[u8]) -> Result<u64, Malformed> {
    let bytes: [u8; 8] = body.try_into().map_err(|_| Malformed::Field {
        tag,
        detail: "is not eight bytes".to_owned(),
    })?;
    Ok(u64::from_be_bytes(bytes))
}

/// The record's address field: exactly one IPv4 or IPv6 address and port.
fn decode_address(tag: u8, body: &[u8]) -> Result<SocketAddr, Malformed> {
    let (address, rest) = address::decode(body).ok_or(Malformed::Field {
        tag,
        detail: "is not an IPv4 or IPv6 address and port".to_owned(),
    })?;
    match (address, rest) {
        (Some(address), []) => Ok(address),
        (None, _) => Err(Malformed::Field {
            tag,
            detail: "has no address".to_owned(),
        }),
        (Some(_), _) => Err(Malformed::Field {
            tag,
            detail: "has bytes after the address".to_owned(),
        }),
    }
}
