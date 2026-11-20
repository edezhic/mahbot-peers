//! The simulated world: one clock, one link, and the machines on it.
//!
//! A simulation owns a temporary parent directory; each machine gets its own
//! root inside it and removes it when the machine is dropped. Nothing here is
//! process-wide: two simulations in one test process share no state, which is
//! what makes the suite safe to run in parallel.
//!
//! A simulation belongs to the runtime that created it — one `block_on` call.
//! The endpoints it hands out are driven by tasks on that runtime, so a case
//! keeps its whole simulation inside one `block_on`.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};

use ring::rand::SecureRandom;
use tempfile::TempDir;

use crate::clock::MockClock;
use crate::link::Link;
use crate::machine::{Machine, RootId};
use crate::root::Root;

/// One clock, one link, and every machine a test creates on them.
pub struct Sim {
    clock: MockClock,
    link: Link,
    dir: TempDir,
    nonce: u64,
    next: AtomicU64,
}

impl Sim {
    pub fn new() -> io::Result<Self> {
        let dir = tempfile::Builder::new().prefix("mahbot-peers-").tempdir()?;
        let clock = MockClock::new();
        let link = Link::new(clock.clone());
        let mut nonce = [0u8; 8];
        ring::rand::SystemRandom::new()
            .fill(&mut nonce)
            .expect("system randomness is available");
        Ok(Self {
            clock,
            link,
            dir,
            nonce: u64::from_le_bytes(nonce),
            next: AtomicU64::new(0),
        })
    }

    /// The clock every machine here shares. Advancing it is the only way time
    /// moves in a test.
    #[must_use]
    pub fn clock(&self) -> &MockClock {
        &self.clock
    }

    /// The link every machine here shares.
    #[must_use]
    pub fn link(&self) -> &Link {
        &self.link
    }

    /// Create a machine: its own root with a key file in it, and its own address.
    pub fn machine(&self) -> io::Result<Machine> {
        self.machine_on(self.root()?)
    }

    /// Create a machine whose key is a copy of `original`'s, as restoring a backup
    /// of one machine onto another gives: the same identity, a second machine.
    ///
    /// Two roots are two peers, and this is the one way they can share a key. The
    /// transport refuses a peer that presents this machine's own key, so such a
    /// pair never connects; that refusal is a case of its own.
    pub fn clone_of(&self, original: &Machine) -> io::Result<Machine> {
        let root = self.root()?;
        original.root.copy_key_into(&root)?;
        self.machine_on(root)
    }

    fn root(&self) -> io::Result<Root> {
        let index = self.next.fetch_add(1, Ordering::Relaxed);
        Root::create(RootId::new(self.nonce, index), self.dir.path())
    }

    fn machine_on(&self, root: Root) -> io::Result<Machine> {
        Ok(Machine::new(
            root.load_identity()?,
            root,
            self.link.attach_next(),
            self.link.clone(),
            self.clock.clone(),
        ))
    }

    /// Two machines that already trust each other, ready to connect.
    pub fn trusting_pair(&self) -> io::Result<(Machine, Machine)> {
        let first = self.machine()?;
        let second = self.machine()?;
        first.trust(&second);
        second.trust(&first);
        Ok((first, second))
    }

    /// How many machine roots still exist. A test's observation of the
    /// simulation's own temporary area — not a machine's location.
    #[must_use]
    pub fn live_roots(&self) -> usize {
        std::fs::read_dir(self.dir.path()).map_or(0, Iterator::count)
    }
}
