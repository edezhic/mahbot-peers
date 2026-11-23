//! The durable peer record: one file per peer under the storage root.
//!
//! # What a record is
//!
//! One file per peer, named by the 64 hex characters of the peer's key, in a
//! `peers/` directory beside the key file. It has two levels. The machine's is the
//! peer's key, when a person made the comparison, the last address authenticated data
//! arrived from, the failures counted so far, any unfinished attempt with its expiry,
//! and whether a person withdrew this machine's trust. The connection's, whose
//! vocabulary is [`crate::peer::access`], is the account on the instance and the
//! assistant the peer is bound to, the claim the other side's decision left here, the
//! pairs the default has acted for, and one right per pair and capability. The key is
//! the whole identity: the fingerprint is derived from it, never stored beside it
//! as a second fact, so a record cannot claim a key and a fingerprint that
//! disagree.
//!
//! # The bytes
//!
//! `mahbot-peer-record`, one version byte, then fields: `[tag][len u16 big-endian]
//! [body]`. Version 1's tags are `0x01` the key (32 bytes), `0x02` the pairing
//! moment (8, seconds), `0x03` the address (family, address, port, and for IPv6 the
//! flow info and scope id), `0x04` the failures (1), `0x05` the attempt (8 expiry,
//! 4 lifetime seconds), `0x06` the trust withdrawal's moment (8), `0x07` the binding
//! (`peer::access`'s body), `0x08` the claim (the other side's fact, byte for byte),
//! `0x09` one pair's default marker (the assistant's label and 8 seconds), `0x0a`
//! one right (`peer::access`'s body), and `0x0b` the most recent withdrawal's moment
//! (8), kept after a return so the action memory knows what to forget. A field this
//! build does not know is kept and
//! written back, after the fields it knows: a rewrite may move it, which changes no
//! meaning. A right naming a capability this build does not know is kept the same way
//! and satisfies nothing. The file is named by the 64 lowercase hex characters of the
//! key.
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
//!   that is the order the self-update window's contract asks for, and the decision
//!   and the connection manager re-read the one record they are about to act on, so
//!   neither answers from a view another process has moved past. A record that
//!   cannot be read is a typed refusal; the store does not open over it.
//! - **A write never produces a file this build cannot read.** A record that would
//!   grow past `MAX_RECORD_BYTES` is refused before anything is written, so an additive
//!   rewrite of a record a newer build left near the cap cannot turn into a file the
//!   next open refuses. The cap is not part of the format, so a build that raised it
//!   reads what an older one wrote, but not the reverse: a record that grew past the
//!   older build's cap is a record that build refuses, and with it the store. The two
//!   processes a self-update window keeps on one root are the only place that can meet,
//!   and there the older one is on its way out.
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
//! # The connection level's own rules
//!
//! - **The binding is the deciding machine's, the claim is a claim.** [`Binding`] is
//!   written only by the machine that decided which assistant the peer is connected
//!   to. The other side keeps the fact it was shown as a claim, byte for byte, and
//!   nothing reads it to decide: it names the pair for a person, and a right is this
//!   machine's own.
//! - **A claim keeps the newer decision.** A fact whose moment is older than the one
//!   on file is ignored, so a re-delivered stale fact cannot undo a rebind.
//! - **The default acts once per pair.** Its marker is written with its one grant, and
//!   a right a person withdrew or one that ended stays on file — its presence is what
//!   stops the default re-creating it. A trust withdrawal removes the rights and the
//!   markers, which is what lets a return issue the default again.
//! - **A withdrawal is not a right's withdrawal.** A trust withdrawal makes the peer
//!   untrusted, which refuses its next handshake and stops the connection manager
//!   reaching for it; the removal of the rights it held is the same act's other half,
//!   and [`crate::peer::rights::Rights::withdraw_trust`] is the only caller of both.
//!   The rights layer is the only writer of rights and of the binding, so no right
//!   changes without its entry in `peer::audit`. The received claim is the connection
//!   manager's write — [`RecordStore::record_claim`] — and it is never a right.
//! - **A decision re-reads.** [`RecordStore::reread`] is what
//!   [`crate::peer::rights::Rights`] calls before every question and every write, so a
//!   right withdrawn by another process on this root refuses the next question on this
//!   one. The merge above is conservative for facts that only grow; a right can stop,
//!   so the read is what keeps the answer fresh.
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
use crate::identity::access::Insecurity;
use crate::identity::{Fingerprint, PEER_ID_LEN, PeerId};
use crate::peer::access::{Binding, Capability, Claim, Fact, Label, Pair, Right, Standing};
use crate::peer::address;
use crate::peer::tlv;
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

/// The most bytes a record may have. The machine level alone is under a hundred
/// bytes; the connection level adds a binding, a claim, one default marker per pair
/// and four rights per pair, and a machine moved between assistants keeps the pairs
/// it left. The cap keeps a hostile file from being read into memory, and a write
/// that would pass it is refused rather than producing a file the next open cannot
/// read.
pub const MAX_RECORD_BYTES: u64 = 16 * 1024;

/// The field tags of version 1. Unknown tags are preserved, not refused.
mod tag {
    pub const KEY: u8 = 0x01;
    pub const PAIRED_AT: u8 = 0x02;
    pub const LAST_ADDRESS: u8 = 0x03;
    pub const FAILURES: u8 = 0x04;
    pub const ATTEMPT: u8 = 0x05;
    // The connection level, `peer::access`: trust withdrawn, the binding this
    // machine decided, the claim the other side's decision left here, one default
    // marker per pair, and one right per pair and capability.
    pub const WITHDRAWN: u8 = 0x06;
    pub const BINDING: u8 = 0x07;
    pub const CLAIM: u8 = 0x08;
    pub const DEFAULT: u8 = 0x09;
    pub const RIGHT: u8 = 0x0a;
    /// The most recent withdrawal's moment, kept after a return. Tag 0x0b, appended.
    pub const LAST_WITHDRAWN: u8 = 0x0b;
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

/// Why a pair is not trusted, when [`PeerRecord::trusted`] says it is not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Untrusted {
    /// A person withdrew this machine's trust in the peer.
    Withdrawn(PeerId),
    /// Three failed comparisons closed the pair.
    Closed(PeerId),
    /// No person on this machine made the comparison.
    NotPaired(PeerId),
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
    /// When this machine withdrew its trust in the peer. The rights the peer held
    /// are removed by the same act; the binding is kept, because a return restores
    /// the acquaintance without a new comparison.
    withdrawn_at: Option<Timestamp>,
    /// The moment of the most recent withdrawal, kept after a return.
    ///
    /// A withdrawal is the repair for a full action memory, and a product may stop the
    /// peer's service for the whole withdrawal. What the action layer must forget is
    /// therefore read from here, not from a service that happened to notice: anything
    /// recorded before this moment is gone whenever the layer next looks.
    last_withdrawn_at: Option<Timestamp>,
    /// The connection level this machine decided: which account on which instance,
    /// and to which assistant.
    binding: Option<Binding>,
    /// The other side's fact as it arrived, kept byte for byte so a newer build's
    /// fact survives an older build's rewrite. Decoded by [`Self::claim`].
    claim: Option<Vec<u8>>,
    /// The pairs the default has acted for, with the moment it did. The marker is
    /// what makes "the default never acts again" structural: a right a person
    /// withdrew stays on file and its marker with it, so no default re-creates it.
    defaults: Vec<(Label, Timestamp)>,
    /// One right per pair and capability, the pair being the record's key and the
    /// right's assistant.
    rights: Vec<Right>,
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
            withdrawn_at: None,
            last_withdrawn_at: None,
            binding: None,
            claim: None,
            defaults: Vec::new(),
            rights: Vec::new(),
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

    /// When this machine withdrew its trust in the peer, if it did.
    ///
    /// A withdrawn machine is not trusted: its next handshake is refused, the
    /// connection manager does not reach for it, and the rights it held are gone.
    #[must_use]
    pub const fn withdrawn_at(&self) -> Option<Timestamp> {
        self.withdrawn_at
    }

    /// Whether this machine has withdrawn its trust in the peer.
    #[must_use]
    pub const fn is_withdrawn(&self) -> bool {
        self.withdrawn_at.is_some()
    }

    /// The moment of the most recent withdrawal, kept after the trust returns.
    ///
    /// The action memory forgets everything recorded before it, so a person's
    /// withdrawal clears that peer's journal even across a stop of the service.
    #[must_use]
    pub const fn last_withdrawn_at(&self) -> Option<Timestamp> {
        self.last_withdrawn_at
    }

    /// The connection level this machine decided, if it decided one.
    #[must_use]
    pub const fn binding(&self) -> Option<&Binding> {
        self.binding.as_ref()
    }

    /// The other side's fact, as this machine keeps it: a claim its person may be
    /// shown, never authority.
    ///
    /// `None` when no claim arrived, or when the bytes are a fact this build cannot
    /// read; the bytes are kept either way.
    #[must_use]
    pub fn claim(&self) -> Option<Claim> {
        let bytes = self.claim.as_deref()?;
        Fact::decode(bytes).ok().map(|fact| fact.claim(self.key))
    }

    /// Every right on file, for every pair.
    #[must_use]
    pub fn rights(&self) -> &[Right] {
        &self.rights
    }

    /// The rights on file for one pair.
    pub fn rights_of(&self, pair: &Pair) -> impl Iterator<Item = &Right> {
        self.rights
            .iter()
            .filter(move |right| right.assistant() == pair.assistant())
    }

    /// The right for one pair and capability, if one is on file.
    #[must_use]
    pub fn right(&self, pair: &Pair, capability: Capability) -> Option<&Right> {
        self.rights
            .iter()
            .find(|right| right.assistant() == pair.assistant() && right.capability() == capability)
    }

    /// When the default acted for the pair, if it did.
    #[must_use]
    pub fn default_spent(&self, pair: &Pair) -> Option<Timestamp> {
        self.defaults
            .iter()
            .find(|(assistant, _)| assistant == pair.assistant())
            .map(|(_, at)| *at)
    }

    /// Whether this machine trusts the peer at `limits`: a person paired it, the pair
    /// is not closed, and its trust was not withdrawn.
    ///
    /// This is `untrusted` with the reason dropped: one predicate, so the handshake's
    /// read of the record on disk and the decision's read of the record it just re-read cannot
    /// drift apart.
    #[must_use]
    pub fn trusted(&self, limits: &Limits) -> bool {
        self.untrusted(limits).is_none()
    }

    /// Whether failed comparisons have closed the pair at `limits`.
    #[must_use]
    pub const fn is_closed(&self, limits: &Limits) -> bool {
        self.failures >= limits.max_failures
    }

    /// Which of the three reasons [`Self::trusted`] rejected the pair, when it did.
    ///
    /// [`Self::trusted`] is this predicate with the reason dropped, so the message and action
    /// layers cannot disagree about what an untrusted pair is.
    #[must_use]
    pub(crate) const fn untrusted(&self, limits: &Limits) -> Option<Untrusted> {
        if self.is_withdrawn() {
            Some(Untrusted::Withdrawn(self.key))
        } else if self.is_closed(limits) {
            Some(Untrusted::Closed(self.key))
        } else if self.is_paired() {
            None
        } else {
            Some(Untrusted::NotPaired(self.key))
        }
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
            && self.withdrawn_at.is_none()
            && self.binding.is_none()
            && self.claim.is_none()
            && self.defaults.is_empty()
            && self.rights.is_empty()
            && self.unknown.is_empty()
    }
}

/// The durable records of one storage root, and the trust they answer for.
///
/// Cheap to clone: every clone shares one map and one directory. The store is
/// also the [`PeerPolicy`] the transport asks during a handshake, so a peer is
/// trusted exactly when a record says a person paired it.
///
/// The map is a cache of the files. [`Self::get`], [`Self::is_paired`] and
/// [`Self::is_closed`] answer from it; a caller that must
/// see what another handle over the same root, or another process, wrote re-reads the
/// record it is about with [`Self::reread`] — which is what the decision and the
/// connection manager do before acting, and what [`PeerPolicy`] does for the
/// handshake.
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
        private::create_private_dir(&dir).map_err(|error| match error {
            private::PrivateFileError::Io(source) => RecordError::Io {
                path: dir.clone(),
                source,
            },
            private::PrivateFileError::Insecure(reason) => RecordError::Insecure {
                path: dir.clone(),
                reason,
            },
        })?;
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

    /// Every peer this store has loaded.
    ///
    /// A sweep over the rights — a term that passed with no question asked — walks
    /// this, then re-reads each record so the sweep sees what another process wrote.
    /// A record another process created after this store opened is that process's to
    /// sweep.
    #[must_use]
    pub fn peers(&self) -> Vec<PeerId> {
        self.records().keys().copied().collect()
    }

    /// Whether a person on this machine made the comparison for `peer`.
    ///
    /// This is this machine's half of the pair; whether the other machine holds it is
    /// the ceremony's question. Trust is [`PeerRecord::trusted`], which also asks
    /// whether the pair is closed.
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

    /// Whether this machine trusts `peer` now, read from the record on disk.
    ///
    /// The file is what answers it: a withdrawal written through any handle of the
    /// root — or by the other process the self-update window keeps — refuses the next
    /// handshake, the next dial and the next keeper round. A record that cannot be read
    /// is not trusted: the caller fails closed. [`crate::peer::PeerRecord::trusted`] is
    /// the rule, and [`crate::tls::PeerPolicy::trusts`] is the public question, so the
    /// handshake and the manager ask one thing; the manager adds the cause on top.
    pub(crate) fn trusted(&self, peer: &PeerId) -> bool {
        self.reread(peer)
            .ok()
            .flatten()
            .is_some_and(|record| record.trusted(&self.inner.limits))
    }

    /// Re-read every record from disk, replacing the loaded map.
    ///
    /// A caller that wants the whole set as the files have it — a screen listing the
    /// peers, a start-up sweep — calls this. The decision and the connection manager do
    /// not need it: each re-reads the one record it is about to act on, so a write by
    /// another process on the same root is seen at that reach. The caller owns the
    /// moment: nothing in this crate calls it behind a caller's back. A record that has
    /// become unreadable is a typed refusal like [`RecordStore::open`]'s.
    pub fn reload(&self) -> Result<(), RecordError> {
        let records = load(&self.inner.dir)?;
        *self.write_map() = records;
        Ok(())
    }

    /// Record that a person paired this machine with `peer` at `at`.
    ///
    /// An existing pairing keeps the moment it was made: a re-comparison repairs a
    /// one-sided pair, it does not re-date the acquaintance. A closed pair is
    /// refused; a person must clear it first, through
    /// [`crate::peer::rights::Rights::clear_attempt_lock`]. A pairing does not
    /// restore a withdrawn trust either: the key never changed, and returning is the
    /// separate act [`crate::peer::rights::Rights::restore_trust`] records.
    pub fn record_pairing(&self, peer: &PeerId, at: Timestamp) -> Result<(), RecordError> {
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
        .map(drop)
    }

    /// Record `address` as the last address authenticated data arrived from.
    ///
    /// The address is a hint that saves a beacon trip, not identity; it is
    /// published and flushed like any other write, and an address that did not
    /// change is not rewritten.
    pub fn record_address(&self, peer: &PeerId, address: SocketAddr) -> Result<(), RecordError> {
        self.update(peer, |record, _| {
            if record.last_address == Some(address) {
                return Ok(Change::Nothing);
            }
            record.last_address = Some(address);
            Ok(Change::Write)
        })
        .map(drop)
    }

    /// Count one failed comparison for `peer`, saturating at the limit.
    ///
    /// [`RecordStore::get`] is how a caller sees whether the pair is now closed.
    pub fn record_failure(&self, peer: &PeerId) -> Result<(), RecordError> {
        self.update(peer, |record, limits| {
            record.failures = record.failures.saturating_add(1).min(limits.max_failures);
            record.attempt = None;
            Ok(Change::Write)
        })
        .map(drop)
    }

    /// A person's reset on this machine: forget the failures and any unfinished
    /// attempt. It does not un-pair, a peer this machine remembers nothing about is
    /// left absent rather than given an empty record, and a record whose only facts
    /// were the failures and the attempt is removed rather than rewritten empty.
    ///
    /// This is the pairing attempt lock's storage step. The act a product calls is
    /// [`crate::peer::rights::Rights::clear_attempt_lock`], which writes the clearing
    /// down first; this is the unaudited half of it, and it is not public for that
    /// reason.
    pub(crate) fn clear(&self, peer: &PeerId) -> Result<(), RecordError> {
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

    /// Re-read `peer`'s record from disk, so a decision sees what another process
    /// wrote.
    ///
    /// The self-update window keeps two processes on one root, and a right withdrawn
    /// by the other one must refuse the next question. A record that vanished is
    /// removed from the map and answered as absent; a record that has become
    /// unreadable is the typed refusal [`Self::open`] would give.
    pub fn reread(&self, peer: &PeerId) -> Result<Option<PeerRecord>, RecordError> {
        let mut map = self.write_map();
        let record = read_file(&path_in(&self.inner.dir, peer), peer)?;
        match &record {
            Some(record) => {
                map.insert(*peer, record.clone());
            }
            None => {
                map.remove(peer);
            }
        }
        Ok(record)
    }

    /// Record the connection level this machine decided: the account on the
    /// instance, and the assistant the peer is bound to.
    ///
    /// A new binding replaces the old one. The old pair's rights stay on file — they
    /// are the record of what was granted, and the pair they belong to is no longer
    /// the pair the machine is bound to — so nothing is inherited and nothing is
    /// unmade.
    pub(crate) fn set_binding(&self, peer: &PeerId, binding: Binding) -> Result<(), RecordError> {
        self.update(peer, |record, _| {
            if record.binding.as_ref() == Some(&binding) {
                return Ok(Change::Nothing);
            }
            record.binding = Some(binding);
            Ok(Change::Write)
        })
        .map(drop)
    }

    /// Keep the other side's fact, as it arrived.
    ///
    /// This is the storage step of a received claim, and the connection manager is its
    /// one caller in this crate: the bytes are kept verbatim, so a fact a newer build
    /// wrote survives this build's rewrite and this build's decoder reads its known
    /// fields. It is public because a claim is data a caller may receive by any
    /// transport and keep here; it decides nothing, and nothing reads a claim to allow
    /// anything. A fact older than the one already kept is ignored: the claim is the
    /// deciding machine's latest decision, and a re-delivered stale one does not undo
    /// it.
    ///
    /// An empty body is no fact at all — a peer with no binding writes nothing — and is
    /// answered as kept with nothing written: a caller that received no bytes does not
    /// have to special-case them, and an empty stream never becomes a refusal.
    ///
    /// # Errors
    ///
    /// [`RecordError::Claim`] when the bytes are not a fact at all. The refusal names
    /// the peer that sent them, not this machine's record: nothing here is corrupt.
    pub fn record_claim(&self, peer: &PeerId, fact: &[u8]) -> Result<(), RecordError> {
        if fact.is_empty() {
            return Ok(());
        }
        let decided_at = Fact::decode(fact)
            .map_err(|error| RecordError::Claim {
                peer: *peer,
                detail: error.to_string(),
            })?
            .decided_at();
        self.update(peer, |record, _| {
            let stored = record
                .claim
                .as_deref()
                .and_then(|bytes| Fact::decode(bytes).ok())
                .map(|fact| fact.decided_at());
            if stored.is_some_and(|stored| stored > decided_at) {
                return Ok(Change::Nothing);
            }
            if record.claim.as_deref() == Some(fact) {
                return Ok(Change::Nothing);
            }
            record.claim = Some(fact.to_vec());
            Ok(Change::Write)
        })
        .map(drop)
    }

    /// Put one right on file, replacing the right for the same pair and capability.
    ///
    /// The store keeps one row per pair and capability: the four capabilities are
    /// granted separately, and a grant, a widening and a restore all write the one
    /// row the pair has for that capability.
    pub(crate) fn put_right(&self, peer: &PeerId, right: Right) -> Result<(), RecordError> {
        self.update(peer, |record, _| {
            match record.rights.iter_mut().find(|stored| {
                stored.assistant() == right.assistant() && stored.capability() == right.capability()
            }) {
                Some(stored) if *stored == right => return Ok(Change::Nothing),
                Some(stored) => *stored = right,
                None => record.rights.push(right),
            }
            Ok(Change::Write)
        })
        .map(drop)
    }

    /// Record that the default acted for `pair`, so it never acts for it again.
    pub(crate) fn mark_default(
        &self,
        peer: &PeerId,
        pair: &Pair,
        at: Timestamp,
    ) -> Result<(), RecordError> {
        self.update(peer, |record, _| {
            if record.default_spent(pair).is_some() {
                return Ok(Change::Nothing);
            }
            record.defaults.push((pair.assistant().clone(), at));
            Ok(Change::Write)
        })
        .map(drop)
    }

    /// Record that a right's term passed, so the ending is on file once.
    ///
    /// A right that is absent, or whose ending is already recorded, changes nothing.
    pub(crate) fn mark_ended(
        &self,
        peer: &PeerId,
        pair: &Pair,
        capability: Capability,
        at: Timestamp,
    ) -> Result<(), RecordError> {
        self.update_existing(peer, |record, _| {
            let Some(right) = record.rights.iter_mut().find(|right| {
                right.assistant() == pair.assistant() && right.capability() == capability
            }) else {
                return Ok(Change::Nothing);
            };
            // The row is read again here, so a grant that landed since the question was
            // asked is not ended by it: only a row that still stands ended is stamped.
            if right.ended_at().is_some() || !matches!(right.standing(at), Standing::Ended(_)) {
                return Ok(Change::Nothing);
            }
            *right = right.clone().ended(at);
            Ok(kept(record))
        })
        .map(drop)
    }

    /// Withdraw this machine's trust in `peer`: the flag, every right and every default
    /// marker, in one publish.
    ///
    /// One publish is what makes the withdrawal one act. The flag without the removal
    /// would be a withdrawal whose rights still stand, and a return from it would clear
    /// the flag and find the default already spent — the person's rights back with
    /// nobody's grant. So the two halves are one record change: either both land or
    /// neither does, and a caller that fails here retries the whole act.
    ///
    /// A right a person withdrew stays on file, because its presence is what stops the
    /// default re-creating it; a *withdrawal of trust* removes the rows, which is what
    /// lets a return issue the default again — the plan's one exception. A right a newer
    /// build wrote for a capability this build does not know is kept as an opaque field
    /// and is removed too, or a newer build would resurrect what the person withdrew.
    ///
    /// The latest withdrawal's moment is kept: a repeated one only finishes a removal an
    /// older build left undone. Answers whether there was a record to withdraw: `false`
    /// is a peer whose file is gone, which the rights layer reports rather than claiming
    /// a withdrawal that changed nothing.
    pub(crate) fn withdraw_trust(&self, peer: &PeerId, at: Timestamp) -> Result<bool, RecordError> {
        let record = self.update_existing(peer, |record, _| {
            let unknown_right = record.unknown.iter().any(|(tag, _)| *tag == tag::RIGHT);
            let last = record.last_withdrawn_at.map_or(at, |old| old.max(at));
            if record.withdrawn_at.is_some()
                && record.rights.is_empty()
                && record.defaults.is_empty()
                && !unknown_right
                && record.last_withdrawn_at == Some(last)
            {
                return Ok(Change::Nothing);
            }
            record.withdrawn_at = Some(record.withdrawn_at.unwrap_or(at));
            record.last_withdrawn_at = Some(last);
            record.rights.clear();
            record.defaults.clear();
            record.unknown.retain(|(tag, _)| *tag != tag::RIGHT);
            Ok(kept(record))
        })?;
        Ok(record.is_some())
    }

    /// Restore this machine's trust in `peer`: the same key, no new comparison.
    ///
    /// Nothing else is restored here. The rights layer issues the default again for
    /// the pair the machine is bound to, and writes the return down.
    pub(crate) fn restore_trust(&self, peer: &PeerId) -> Result<(), RecordError> {
        self.update_existing(peer, |record, _| {
            if record.withdrawn_at.is_none() {
                return Ok(Change::Nothing);
            }
            record.withdrawn_at = None;
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

    /// The directory under `root` that holds the records.
    ///
    /// Public for the same reason [`Self::path_for`] is: a caller that must name the
    /// records without opening the store — a backup, a repair, a case that makes the
    /// directory unreadable — asks here instead of spelling `peers`.
    #[must_use]
    pub fn dir_in(root: &Path) -> PathBuf {
        root.join(PEERS_DIR)
    }

    /// The path of `peer`'s record under `root`.
    ///
    /// A record's name is this module's, so a caller that must name one without
    /// opening the store — a repair, a backup, a case that corrupts a record on
    /// purpose — asks here instead of spelling the directory and the extension. Opening
    /// a store would fail on exactly the record such a caller is about, and would
    /// create `peers/` under a root that has none.
    #[must_use]
    pub fn path_for(root: &Path, peer: &PeerId) -> PathBuf {
        path_in(&Self::dir_in(root), peer)
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
        let (mut record, from_file) = match read_file(&path_in(&self.inner.dir, peer), peer)? {
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
                let path = path_in(&self.inner.dir, peer);
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
    /// The handshake asks the record on disk, not this process's copy of it.
    ///
    /// A store is a handle, and a product may hold more than one over one root — the
    /// connection manager one, the rights layer another. Asking the file is what makes
    /// a withdrawal written through any of them refuse the next handshake, and what
    /// makes the refusal the far side sees the same one the decision gives. A record
    /// that cannot be read is not trusted: the handshake fails closed.
    fn trusts(&self, peer: &Fingerprint) -> bool {
        self.trusted(&peer.peer_id())
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
    /// The record would be larger than `MAX_RECORD_BYTES`, so it was not written. The
    /// file on disk is left as it was.
    TooLarge { path: PathBuf, bytes: u64 },
    /// An attempt that has not expired is already recorded for this peer.
    AttemptInProgress { peer: PeerId, expires_at: Timestamp },
    /// Failed comparisons have closed the pair on this machine. A person must
    /// clear it here; a restart does not.
    Closed { peer: PeerId },
    /// The other side's connection fact cannot be read. The peer's bytes are the
    /// fault, not this machine's record, and the refusal says so.
    Claim { peer: PeerId, detail: String },
    /// The connection level this machine holds could not be written: a fact field is
    /// longer than a record field can name. A value this machine produced, so it is
    /// not [`Self::Malformed`], which is about a file that is there and cannot be read.
    Binding { detail: String },
}

/// What is wrong with a file that is not a record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Malformed {
    /// The file is empty: a write that never landed.
    Empty,
    /// The file is larger than `MAX_RECORD_BYTES`.
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
                "{}: the record would be {bytes} bytes, more than {MAX_RECORD_BYTES}; it was not written",
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
            Self::Claim { peer, detail } => write!(
                f,
                "the connection fact {} sent cannot be read: {detail}",
                peer.fingerprint()
            ),
            Self::Binding { detail } => write!(
                f,
                "the connection level this machine holds cannot be written: {detail}"
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
            | Self::Closed { .. }
            | Self::Claim { .. }
            | Self::Binding { .. } => None,
        }
    }
}

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the file is empty"),
            Self::TooLarge { bytes } => {
                write!(
                    f,
                    "the file holds {bytes} bytes, more than {MAX_RECORD_BYTES}"
                )
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
    let (bytes, length) = private::read_capped(file, MAX_RECORD_BYTES + 1).map_err(|source| {
        RecordError::Unreadable {
            path: path.to_owned(),
            source,
        }
    })?;
    if let Some(length) = length
        && length > MAX_RECORD_BYTES
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
    if bytes.len() as u64 > MAX_RECORD_BYTES {
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
/// that would pass `MAX_RECORD_BYTES` is refused before the temporary file is written,
/// so this build never publishes a file it cannot read back.
fn publish(dir: &Path, record: &PeerRecord) -> Result<(), RecordError> {
    let path = path_in(dir, &record.key);
    let bytes = encode(record, &path)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
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
    if let Some(at) = record.withdrawn_at {
        field(
            &mut bytes,
            tag::WITHDRAWN,
            &at.unix_seconds().to_be_bytes(),
            path,
        )?;
    }
    if let Some(at) = record.last_withdrawn_at {
        field(
            &mut bytes,
            tag::LAST_WITHDRAWN,
            &at.unix_seconds().to_be_bytes(),
            path,
        )?;
    }
    if let Some(binding) = &record.binding {
        let body = binding
            .encode_body()
            .map_err(|detail| RecordError::Binding { detail })?;
        field(&mut bytes, tag::BINDING, &body, path)?;
    }
    if let Some(claim) = &record.claim {
        field(&mut bytes, tag::CLAIM, claim, path)?;
    }
    for (assistant, at) in &record.defaults {
        let mut body = Vec::with_capacity(12);
        assistant.encode_into(&mut body);
        body.extend_from_slice(&at.unix_seconds().to_be_bytes());
        field(&mut bytes, tag::DEFAULT, &body, path)?;
    }
    for right in &record.rights {
        field(&mut bytes, tag::RIGHT, &right.encode_body(), path)?;
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
    tlv::put(bytes, tag, body).map_err(|_| RecordError::TooLarge {
        path: path.to_owned(),
        bytes: bytes.len() as u64 + 3 + body.len() as u64,
    })
}

/// Read a record from its bytes. A version above [`VERSION`] is read as this
/// version's prefix; its unknown fields are preserved in `unknown`.
fn decode(bytes: &[u8], expected: &PeerId) -> Result<PeerRecord, Malformed> {
    let rest = bytes.strip_prefix(MAGIC).ok_or(Malformed::Magic)?;
    let (&version, rest) = rest.split_first().ok_or(Malformed::Magic)?;
    if version == 0 {
        return Err(Malformed::Version { found: version });
    }
    let mut record = PeerRecord::empty(*expected);
    record.version = version;
    let mut seen = Vec::new();
    for field in tlv::Fields::new(rest) {
        let (tag, body) = field.map_err(|error| malformed(error.tag, error.detail))?;
        if matches!(
            tag,
            tag::KEY
                | tag::PAIRED_AT
                | tag::LAST_ADDRESS
                | tag::FAILURES
                | tag::ATTEMPT
                | tag::WITHDRAWN
                | tag::LAST_WITHDRAWN
                | tag::BINDING
                | tag::CLAIM
        ) {
            if seen.contains(&tag) {
                return Err(Malformed::Duplicate { tag });
            }
            seen.push(tag);
        }
        match tag {
            tag::KEY => {
                let key: [u8; PEER_ID_LEN] = body
                    .try_into()
                    .map_err(|_| malformed(tag, "is not a 32-byte key"))?;
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
                    return Err(malformed(tag, "is not one byte"));
                };
                record.failures = *failures;
            }
            tag::ATTEMPT => {
                record.attempt = Some(read_attempt(tag, body)?);
            }
            tag::WITHDRAWN => {
                record.withdrawn_at = Some(Timestamp::from_unix_seconds(read_u64(tag, body)?));
            }
            tag::LAST_WITHDRAWN => {
                record.last_withdrawn_at = Some(Timestamp::from_unix_seconds(read_u64(tag, body)?));
            }
            tag::BINDING => {
                record.binding =
                    Some(Binding::decode_body(body).map_err(|detail| malformed(tag, detail))?);
            }
            tag::CLAIM => {
                Fact::decode(body).map_err(|error| malformed(tag, error.to_string()))?;
                record.claim = Some(body.to_vec());
            }
            tag::DEFAULT => read_default(&mut record, tag, body)?,
            tag::RIGHT => read_right(&mut record, tag, body)?,
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

/// A malformed record field, naming the tag it was found under.
fn malformed(tag: u8, detail: impl Into<String>) -> Malformed {
    Malformed::Field {
        tag,
        detail: detail.into(),
    }
}

/// Read one `ATTEMPT` field: a moment and the lifetime it was made with.
fn read_attempt(tag: u8, body: &[u8]) -> Result<Attempt, Malformed> {
    let not_twelve = || malformed(tag, "is not twelve bytes");
    let (expires, rest) = body.split_first_chunk::<8>().ok_or_else(not_twelve)?;
    let (lifetime, rest) = rest.split_first_chunk::<4>().ok_or_else(not_twelve)?;
    if !rest.is_empty() {
        return Err(not_twelve());
    }
    Ok(Attempt {
        expires_at: Timestamp::from_unix_seconds(u64::from_be_bytes(*expires)),
        lifetime: Duration::from_secs(u64::from(u32::from_be_bytes(*lifetime))),
    })
}

/// Read one `DEFAULT` field: the pair's assistant and the moment the default acted.
fn read_default(record: &mut PeerRecord, tag: u8, body: &[u8]) -> Result<(), Malformed> {
    let (assistant, rest) = Label::decode_from(body).map_err(|detail| malformed(tag, detail))?;
    let seconds: [u8; 8] = rest
        .try_into()
        .map_err(|_| malformed(tag, "does not end in a moment"))?;
    if record
        .defaults
        .iter()
        .any(|(stored, _)| *stored == assistant)
    {
        return Err(malformed(
            tag,
            format!("repeats the pair with `{assistant}`"),
        ));
    }
    record.defaults.push((
        assistant,
        Timestamp::from_unix_seconds(u64::from_be_bytes(seconds)),
    ));
    Ok(())
}

/// Read one `RIGHT` field. A capability this build does not know is kept as it
/// arrived, and no question this build can ask matches it.
fn read_right(record: &mut PeerRecord, tag: u8, body: &[u8]) -> Result<(), Malformed> {
    let Some(right) = Right::decode_body(body).map_err(|detail| malformed(tag, detail))? else {
        record.unknown.push((tag, body.to_vec()));
        return Ok(());
    };
    if record.rights.iter().any(|stored| {
        stored.assistant() == right.assistant() && stored.capability() == right.capability()
    }) {
        return Err(malformed(
            tag,
            format!(
                "repeats `{}` for `{}`",
                right.capability(),
                right.assistant()
            ),
        ));
    }
    record.rights.push(right);
    Ok(())
}

fn read_u64(tag: u8, body: &[u8]) -> Result<u64, Malformed> {
    let bytes: [u8; 8] = body
        .try_into()
        .map_err(|_| malformed(tag, "is not eight bytes"))?;
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
