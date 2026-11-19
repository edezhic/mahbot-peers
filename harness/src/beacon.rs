//! The stand-in for the one global service: an in-memory rendezvous.
//!
//! It implements the library's [`Rendezvous`] seam and nothing else: register an
//! id at an address, look an id up, hand an opaque blob between two parties. It
//! defines no wire protocol — how a client reaches the real service is the
//! service's own concern — and it is reachable only through the seam, so a
//! test's client code cannot tell it from the real thing.
//!
//! A test can start it, stop it and wipe it, and a stopped one refuses every
//! request: the "beacon is down" case is expressible.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use async_trait::async_trait;
use mahbot_peers::beacon::{BeaconError, Introduction, Rendezvous};
use mahbot_peers::identity::PeerId;

/// An in-memory rendezvous service.
#[derive(Clone, Debug)]
pub struct FakeBeacon {
    inner: Arc<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    running: AtomicBool,
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    addresses: HashMap<PeerId, SocketAddr>,
    introductions: HashMap<PeerId, VecDeque<Introduction>>,
}

impl FakeBeacon {
    /// Start a service with nothing in it.
    #[must_use]
    pub fn start() -> Self {
        let beacon = Self {
            inner: Arc::new(Inner::default()),
        };
        beacon.inner.running.store(true, Ordering::SeqCst);
        beacon
    }

    /// The seam, and only the seam: what a client is handed.
    #[must_use]
    pub fn handle(&self) -> Arc<dyn Rendezvous> {
        Arc::new(self.clone())
    }

    /// Stop answering. Every request from now on fails with
    /// [`BeaconError::Unavailable`], and nothing already registered is lost —
    /// a restart would still know it.
    pub fn stop(&self) {
        self.inner.running.store(false, Ordering::SeqCst);
    }

    /// Start answering again after [`FakeBeacon::stop`].
    pub fn restart(&self) {
        self.inner.running.store(true, Ordering::SeqCst);
    }

    /// Forget every registration and every pending introduction.
    pub fn wipe(&self) {
        let mut state = self.state();
        state.addresses.clear();
        state.introductions.clear();
    }

    #[must_use]
    pub fn is_running(&self) -> bool {
        self.inner.running.load(Ordering::SeqCst)
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.inner
            .state
            .lock()
            .expect("beacon state is not poisoned")
    }

    fn check(&self) -> Result<(), BeaconError> {
        if self.is_running() {
            Ok(())
        } else {
            Err(BeaconError::Unavailable)
        }
    }
}

#[async_trait]
impl Rendezvous for FakeBeacon {
    async fn register(&self, id: PeerId, addr: SocketAddr) -> Result<(), BeaconError> {
        self.check()?;
        self.state().addresses.insert(id, addr);
        Ok(())
    }

    async fn lookup(&self, id: &PeerId) -> Result<Option<SocketAddr>, BeaconError> {
        self.check()?;
        Ok(self.state().addresses.get(id).copied())
    }

    async fn introduce(
        &self,
        from: PeerId,
        to: PeerId,
        payload: Vec<u8>,
    ) -> Result<(), BeaconError> {
        self.check()?;
        let introduction = Introduction::new(from, payload)?;
        let mut state = self.state();
        if !state.addresses.contains_key(&to) {
            return Err(BeaconError::UnknownPeer(to));
        }
        state
            .introductions
            .entry(to)
            .or_default()
            .push_back(introduction);
        Ok(())
    }

    async fn take_introduction(&self, me: &PeerId) -> Result<Option<Introduction>, BeaconError> {
        self.check()?;
        Ok(self
            .state()
            .introductions
            .get_mut(me)
            .and_then(VecDeque::pop_front))
    }
}
