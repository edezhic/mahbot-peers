//! The transfer rig: a source that is a function of the offset, sinks that hash or keep
//! what they are handed, and the wait that drives a transfer to its end.
//!
//! A file is never held in memory here unless a case asks for it. [`Generated`] produces
//! its bytes from the absolute offset, so a resumed transfer reads the same bytes the
//! first attempt did and a 256 KiB file costs nothing to offer; [`Store::hashing`] folds what
//! it is handed into a SHA-256 and keeps only the count, which is enough to prove a file
//! arrived byte for byte; [`Store::holding`] keeps the bytes themselves, for the small cases
//! that have to look at them or damage one.
//!
//! Nothing here reads a clock or starts a task: the transfer layer is given the
//! simulation's clock and runtime, and a case moves time through
//! [`drive_transfer`].

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use mahbot_peers::identity::PeerId;
use mahbot_peers::peer::{
    Digest, Held, Offering, Read, Sink, Source, Stored, Transfer, TransferName, TransferState,
};
use ring::digest::{Context, SHA256};

use crate::clock::DRIVE_STEP;
use crate::sim::Sim;

/// How many bytes [`Generated`] hashes, and a source reads, at a time.
const STEP: u64 = 64 * 1024;

/// The byte at `offset` in any generated source.
///
/// A deterministic function of the absolute offset alone, so the bytes a resumed transfer
/// reads from where the receiver stopped are the bytes the first attempt would have read
/// there, and no state has to survive a reconnect for that to hold.
const fn byte_at(offset: u64) -> u8 {
    // Masked to a byte, so the truncation is the whole of the conversion.
    (offset.wrapping_mul(31).wrapping_add(7) & 0xff) as u8
}

/// The 256 bytes [`byte_at`] names, in the order it names them.
///
/// `byte_at` adds 31 modulo 256 for each offset, and 31 is odd, so the byte sequence repeats
/// every 256 offsets and the phase is `offset & 0xff`. A large file is then a few copies of the
/// cycle rather than a call per byte, which is what keeps the largest case inside the suite's
/// budget; the bytes are exactly the ones `byte_at` names.
const CYCLE: [u8; 256] = {
    let mut cycle = [0u8; 256];
    let mut offset = 0usize;
    while offset < 256 {
        cycle[offset] = byte_at(offset as u64);
        offset += 1;
    }
    cycle
};

/// A source whose bytes are a function of the offset and are never held in memory.
pub struct Generated {
    name: TransferName,
    length: u64,
    digest: Digest,
    /// How many more reads answer [`Read::NotNow`].
    stalls: AtomicUsize,
    /// How many reads answer [`Read::NotNow`] before every read this source answers.
    every: AtomicUsize,
    /// How many of those waits the current read has had.
    waited: AtomicUsize,
    /// The offset at or past which reads answer [`Read::Ended`].
    end_at: AtomicU64,
    /// The offset at or past which reads answer [`Read::Failed`].
    fail_at: AtomicU64,
}

impl Generated {
    /// A source of `length` bytes called `name`, hashed now by streaming it in
    /// 64 KiB steps.
    ///
    /// # Panics
    ///
    /// When `name` is not a name a transfer may carry: the rig's own names are its
    /// literals, so a refusal here is a mistake in the case.
    #[must_use]
    pub fn new(name: &str, length: u64) -> Arc<Self> {
        let mut context = Context::new(&SHA256);
        let mut offset = 0;
        while offset < length {
            let step = STEP.min(length - offset);
            context.update(&Self::at(offset, step));
            offset += step;
        }
        Arc::new(Self {
            name: TransferName::new(name).expect("the rig's transfer name is a name"),
            length,
            digest: Digest::from_slice(context.finish().as_ref())
                .expect("a SHA-256 digest is 32 bytes"),
            stalls: AtomicUsize::new(0),
            every: AtomicUsize::new(0),
            waited: AtomicUsize::new(0),
            end_at: AtomicU64::new(u64::MAX),
            fail_at: AtomicU64::new(u64::MAX),
        })
    }

    /// `len` bytes of the file starting at `offset`.
    ///
    /// Copied a slice at a time out of [`CYCLE`]: the bytes are the ones [`byte_at`] names, and
    /// a large file costs its own size in copies instead of a call per byte.
    fn at(offset: u64, len: u64) -> Vec<u8> {
        let len = usize::try_from(len).unwrap_or(usize::MAX);
        let mut out = Vec::with_capacity(len);
        let mut phase = usize::try_from(offset & 0xff).expect("a phase below 256");
        while out.len() < len {
            let take = (CYCLE.len() - phase).min(len - out.len());
            out.extend_from_slice(&CYCLE[phase..phase + take]);
            phase = (phase + take) & 0xff;
        }
        out
    }

    /// The product's name for it.
    #[must_use]
    pub const fn name(&self) -> &TransferName {
        &self.name
    }

    /// SHA-256 over the whole file, as the source computed it at construction.
    #[must_use]
    pub const fn digest(&self) -> Digest {
        self.digest
    }

    /// The offer a product makes of this file, with the source behind it.
    #[must_use]
    pub fn offering(self: &Arc<Self>) -> Offering {
        let source: Arc<dyn Source> = Arc::<Self>::clone(self);
        Offering {
            name: self.name.clone(),
            length: self.length,
            digest: self.digest,
            source,
        }
    }

    /// The file's bytes from `offset`, `len` of them, for a sink to compare against.
    #[must_use]
    pub fn bytes(&self, offset: u64, len: usize) -> Vec<u8> {
        Self::at(offset, u64::try_from(len).unwrap_or(u64::MAX))
    }

    /// Answer [`Read::NotNow`] to the next `reads` reads, as a source that is not ready.
    pub fn stall_reads(&self, reads: usize) {
        self.stalls.store(reads, Ordering::SeqCst);
    }

    /// Answer [`Read::NotNow`] to `reads` reads before every read this source answers, as a
    /// source that is slow between chunks is.
    ///
    /// The sender asks again once a poll, so `n` is also `n` seconds of virtual time a chunk:
    /// a case that wants a transfer to last longer than the stall bound while it keeps moving
    /// sets this rather than racing the sender to its own reads.
    pub fn stall_every(&self, reads: usize) {
        self.every.store(reads, Ordering::SeqCst);
        self.waited.store(0, Ordering::SeqCst);
    }

    /// Answer [`Read::Ended`] at or past `offset`, as a source shorter than it said.
    pub fn end_after(&self, offset: u64) {
        self.end_at.store(offset, Ordering::SeqCst);
    }

    /// Answer [`Read::Failed`] at or past `offset`, as a source the disk went away from.
    pub fn fail_at(&self, offset: u64) {
        self.fail_at.store(offset, Ordering::SeqCst);
    }
}

impl Source for Generated {
    fn read(&self, _name: &TransferName, offset: u64, into: &mut [u8]) -> Read {
        let stalls = self.stalls.load(Ordering::SeqCst);
        if stalls > 0 {
            self.stalls.store(stalls - 1, Ordering::SeqCst);
            return Read::NotNow;
        }
        let every = self.every.load(Ordering::SeqCst);
        if every > 0 {
            let waited = self.waited.load(Ordering::SeqCst);
            if waited < every {
                self.waited.store(waited + 1, Ordering::SeqCst);
                return Read::NotNow;
            }
            self.waited.store(0, Ordering::SeqCst);
        }
        if offset >= self.fail_at.load(Ordering::SeqCst) {
            return Read::Failed;
        }
        if offset >= self.end_at.load(Ordering::SeqCst) || offset >= self.length {
            return Read::Ended;
        }
        let room = usize::try_from(self.length - offset)
            .unwrap_or(into.len())
            .min(into.len());
        into[..room].copy_from_slice(&Self::at(offset, u64::try_from(room).unwrap_or(u64::MAX)));
        Read::Bytes(room)
    }
}

/// SHA-256 over `bytes`, as a sink that keeps them assembles a digest.
fn digest_of(bytes: &[u8]) -> Digest {
    let mut context = Context::new(&SHA256);
    context.update(bytes);
    digest_of_context(context)
}

/// The digest a running context has folded so far.
fn digest_of_context(context: Context) -> Digest {
    Digest::from_slice(context.finish().as_ref()).expect("a SHA-256 digest is 32 bytes")
}

/// What one sink holds for one name.
struct Assembled {
    /// The bytes, when the sink keeps them; empty otherwise.
    bytes: Vec<u8>,
    /// The running digest of everything it took, which is how a sink that keeps no bytes
    /// answers.
    context: Context,
    count: u64,
    /// The digest the first write said the bytes were being assembled toward.
    toward: Digest,
    /// Whether [`Sink::assembled`] has been asked, which the crate does only once it holds
    /// every byte.
    asked: bool,
}

/// A sink that remembers what it was handed, and answers the three questions the layer asks.
///
/// [`Self::hashing`] folds the bytes into a SHA-256 and keeps only the count, so a large file
/// costs no memory; [`Self::holding`] keeps the bytes themselves, for the small cases that have
/// to look at them or damage one. Both take everything until a case says otherwise.
pub struct Store {
    /// Whether the bytes are kept, or only their digest.
    keep: bool,
    accepting: AtomicBool,
    refusing: AtomicBool,
    writes: AtomicUsize,
    /// How many more writes this sink takes before it answers [`Stored::NotNow`] again.
    burst: AtomicUsize,
    /// How many write calls this sink has seen, for [`Self::slow`].
    calls: AtomicUsize,
    /// The length of the file [`Self::fill_short_of`] was told about, and how far from its end
    /// this sink stops taking bytes.
    length: AtomicU64,
    short: AtomicU64,
    /// Take one write in every this many calls, answering [`Stored::NotNow`] to the rest.
    every: AtomicUsize,
    /// How many times the crate asked what this sink holds for a name.
    held_asks: AtomicUsize,
    /// Whether [`Sink::held`] answers without the digest it was assembling toward, as a
    /// product that kept the bytes and lost the record of what they were for does.
    forgotten: AtomicBool,
    /// Whether [`Sink::assembled`] answers "cannot say", as a product that holds the bytes but
    /// cannot tell what they are does.
    silent: AtomicBool,
    files: Mutex<BTreeMap<(PeerId, TransferName), Assembled>>,
}

impl Store {
    /// A sink that hashes what it is handed and keeps no file.
    #[must_use]
    pub fn hashing() -> Arc<Self> {
        Self::new(false)
    }

    /// A sink that keeps the bytes themselves, for a file of a mebibyte or less.
    #[must_use]
    pub fn holding() -> Arc<Self> {
        Self::new(true)
    }

    fn new(keep: bool) -> Arc<Self> {
        Arc::new(Self {
            keep,
            accepting: AtomicBool::new(true),
            refusing: AtomicBool::new(false),
            writes: AtomicUsize::new(0),
            burst: AtomicUsize::new(usize::MAX),
            calls: AtomicUsize::new(0),
            length: AtomicU64::new(0),
            short: AtomicU64::new(0),
            every: AtomicUsize::new(0),
            held_asks: AtomicUsize::new(0),
            forgotten: AtomicBool::new(false),
            silent: AtomicBool::new(false),
            files: Mutex::new(BTreeMap::new()),
        })
    }

    /// Take `writes` more writes and then answer [`Stored::NotNow`], as a product that can
    /// write a little at a time does.
    ///
    /// A case that grants a burst, lets it be used up and grants another keeps a transfer
    /// moving while it takes as long as the case wants; a case that grants one and waits holds
    /// a transfer in the middle of the file without racing the receiving task to its end.
    pub fn accept_burst(&self, writes: usize) {
        self.burst.store(writes, Ordering::SeqCst);
    }

    /// Answer [`Stored::NotNow`], as a product that cannot write this instant does.
    pub fn stop_accepting(&self) {
        self.accepting.store(false, Ordering::SeqCst);
    }

    /// Take one write in every `every` calls and answer [`Stored::NotNow`] to the rest, as a
    /// disk that stores one chunk every few polls does.
    ///
    /// The receiving side asks again once a poll — a second of virtual time — after each "not
    /// now", and takes the next call at once when it is accepted, so `slow(2)` stores a chunk
    /// every other call, about one a second, and a larger `every` slows it further. A transfer
    /// therefore keeps moving while it crosses a minute-long bound.
    pub fn slow(&self, every: usize) {
        self.calls.store(0, Ordering::SeqCst);
        self.every.store(every, Ordering::SeqCst);
    }

    /// Take every write that keeps the file `short` bytes from its end, and answer
    /// [`Stored::NotNow`] to the rest, as a disk that fills up one chunk short does.
    ///
    /// The receiver then holds the file's last bytes unstored while the sending side has already
    /// finished its stream, which is the one shape where its last look at the stream finds it
    /// ended.
    pub fn fill_short_of(&self, length: u64, short: u64) {
        self.length.store(length, Ordering::SeqCst);
        self.short.store(short, Ordering::SeqCst);
    }

    /// Answer [`Sink::held`] with the count but without the digest those bytes were being
    /// assembled toward, as a product that holds part of a name and lost what it was for does.
    pub fn forget_toward(&self) {
        self.forgotten.store(true, Ordering::SeqCst);
    }

    /// Take bytes again.
    pub fn start_accepting(&self) {
        self.accepting.store(true, Ordering::SeqCst);
    }

    /// Answer [`Stored::Refused`], as a product whose disk is full does.
    pub fn refuse(&self) {
        self.refusing.store(true, Ordering::SeqCst);
    }

    /// How many bytes this sink holds for `name` from `peer`.
    #[must_use]
    pub fn held_bytes(&self, peer: &PeerId, name: &TransferName) -> u64 {
        self.lock()
            .get(&(*peer, name.clone()))
            .map_or(0, |held| held.count)
    }

    /// The bytes this sink keeps for `name` from `peer`; empty for a hashing sink.
    #[must_use]
    pub fn bytes(&self, peer: &PeerId, name: &TransferName) -> Vec<u8> {
        self.lock()
            .get(&(*peer, name.clone()))
            .map_or_else(Vec::new, |held| held.bytes.clone())
    }

    /// Whether the crate asked what this sink assembled for `name` from `peer`, which it
    /// does only once every byte has arrived.
    #[must_use]
    pub fn finished(&self, peer: &PeerId, name: &TransferName) -> bool {
        self.lock()
            .get(&(*peer, name.clone()))
            .is_some_and(|held| held.asked)
    }

    /// How many writes this sink accepted.
    #[must_use]
    pub fn writes(&self) -> usize {
        self.writes.load(Ordering::SeqCst)
    }

    /// How many times the crate asked this sink what it holds for a name.
    #[must_use]
    pub fn held_asks(&self) -> usize {
        self.held_asks.load(Ordering::SeqCst)
    }

    /// Answer [`Sink::assembled`] with "cannot say", as a product that holds every byte and
    /// still cannot tell what it assembled does.
    pub fn cannot_answer(&self) {
        self.silent.store(true, Ordering::SeqCst);
    }

    /// Flip the byte at `at` in what this sink holds for `name`, as a damaged file is
    /// damaged.
    pub fn corrupt(&self, peer: &PeerId, name: &TransferName, at: u64) {
        if let Some(held) = self.lock().get_mut(&(*peer, name.clone()))
            && let Some(byte) = usize::try_from(at)
                .ok()
                .and_then(|at| held.bytes.get_mut(at))
        {
            *byte ^= 0xff;
        }
    }

    fn lock(&self) -> MutexGuard<'_, BTreeMap<(PeerId, TransferName), Assembled>> {
        self.files
            .lock()
            .expect("the transfer sink is not poisoned")
    }
}

impl Sink for Store {
    fn held(&self, peer: &PeerId, name: &TransferName) -> Held {
        self.held_asks.fetch_add(1, Ordering::SeqCst);
        self.lock()
            .get(&(*peer, name.clone()))
            .filter(|held| held.count > 0)
            .map_or(Held::nothing(), |held| Held {
                bytes: held.count,
                toward: (!self.forgotten.load(Ordering::SeqCst)).then_some(held.toward),
            })
    }

    fn write(
        &self,
        peer: &PeerId,
        name: &TransferName,
        toward: &Digest,
        offset: u64,
        bytes: &[u8],
    ) -> Stored {
        let mut files = self.lock();
        let held = files
            .entry((*peer, name.clone()))
            .or_insert_with(|| Assembled {
                bytes: Vec::new(),
                context: Context::new(&SHA256),
                count: 0,
                toward: *toward,
                asked: false,
            });
        assert!(
            offset == held.count,
            "the sink holds {} bytes of `{name}` and was handed offset {offset}",
            held.count
        );
        if !self.accepting.load(Ordering::SeqCst) {
            return Stored::NotNow;
        }
        if self.refusing.load(Ordering::SeqCst) {
            return Stored::Refused;
        }
        let short = self.short.load(Ordering::SeqCst);
        if short > 0
            && held
                .count
                .saturating_add(u64::try_from(bytes.len()).expect("a chunk is far below a u64"))
                .saturating_add(short)
                > self.length.load(Ordering::SeqCst)
        {
            return Stored::NotNow;
        }
        let every = self.every.load(Ordering::SeqCst);
        if every > 0 {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if !(call - 1).is_multiple_of(every) {
                return Stored::NotNow;
            }
        }
        let burst = self.burst.load(Ordering::SeqCst);
        if burst == 0 {
            return Stored::NotNow;
        }
        if burst != usize::MAX {
            self.burst.store(burst - 1, Ordering::SeqCst);
        }
        held.context.update(bytes);
        held.count += u64::try_from(bytes.len()).expect("a chunk is far below a u64");
        if self.keep {
            held.bytes.extend_from_slice(bytes);
        }
        self.writes.fetch_add(1, Ordering::SeqCst);
        Stored::Accepted
    }

    fn assembled(&self, peer: &PeerId, name: &TransferName) -> Option<Digest> {
        let mut files = self.lock();
        let held = files.get_mut(&(*peer, name.clone()))?;
        if held.count == 0 {
            return None;
        }
        held.asked = true;
        if self.silent.load(Ordering::SeqCst) {
            return None;
        }
        Some(if self.keep {
            digest_of(&held.bytes)
        } else {
            digest_of_context(held.context.clone())
        })
    }
}

/// Move the clock until `transfer` is over, and answer how it ended.
///
/// # Errors
///
/// The transfer did not end within `budget` of virtual time, in the state it was last
/// in: the case's budget is the only bound on a transfer that never moves.
pub async fn drive_transfer(
    sim: &Sim,
    budget: Duration,
    transfer: &Transfer,
) -> Result<TransferState, String> {
    drive_transfer_in(sim, budget, DRIVE_STEP, transfer).await
}

/// The same, moving the clock in `step`-sized jumps: a case crossing a minute-long bound
/// hands in a step of seconds.
///
/// # Errors
///
/// As [`drive_transfer`].
pub async fn drive_transfer_in(
    sim: &Sim,
    budget: Duration,
    step: Duration,
    transfer: &Transfer,
) -> Result<TransferState, String> {
    if !sim
        .clock()
        .advance_until(budget, step, || transfer.state().is_over())
        .await
    {
        return Err(format!(
            "the transfer did not end within {budget:?} of virtual time: it reads `{:?}`",
            transfer.state()
        ));
    }
    Ok(transfer.state())
}
