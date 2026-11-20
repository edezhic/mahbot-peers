//! The beacon, in-process: the real server over the simulated link.
//!
//! There is no stand-in for the protocol here. The server is `mahbot-beacon`'s,
//! served over the harness's abstract socket and driven by the harness's clock;
//! the clients are the library's. A test can start it, stop it, kill it and
//! restart it, and a stopped one answers nothing — the "beacon is down" case is
//! expressible without a network.
//!
//! The server's whole memory is exposed as a [`Registry`] so a case can assert
//! what the beacon does *not* hold: there is no mailbox and no payload in it.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use mahbot_beacon::config::server_config;
use mahbot_beacon::core::Registry;
use mahbot_beacon::server::{BeaconServer, DEFAULT_MAX_CONNECTIONS};
use mahbot_peers::beacon::Beacon;
use mahbot_peers::identity::{Fingerprint, Identity};
use quinn::{AsyncUdpSocket, Endpoint, EndpointConfig};

use crate::clock::MockClock;
use crate::link::{Link, LinkedSocket};
use crate::machine::Machine;
use crate::sim::Sim;

/// An endpoint over the link's socket, carrying the server's TLS configuration.
pub(crate) fn endpoint(
    socket: &Arc<LinkedSocket>,
    config: quinn::ServerConfig,
    runtime: Arc<dyn quinn::Runtime>,
) -> io::Result<Endpoint> {
    Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        Some(config),
        Arc::clone(socket) as Arc<dyn AsyncUdpSocket>,
        runtime,
    )
}

/// A running beacon and everything needed to restart it.
pub struct TestBeacon {
    identity: Identity,
    socket: Arc<LinkedSocket>,
    link: Link,
    clock: MockClock,
    runtime: Arc<dyn quinn::Runtime>,
    max_connections: usize,
    endpoint: Mutex<Option<Endpoint>>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    registry: Mutex<Option<Arc<Mutex<Registry>>>>,
}

impl TestBeacon {
    /// Start a beacon with a fresh identity at the next free address.
    pub fn start(sim: &Sim) -> io::Result<Self> {
        Self::start_with_limit(sim, DEFAULT_MAX_CONNECTIONS)
    }

    /// Start a beacon that serves at most `max` connections at once.
    pub fn start_with_limit(sim: &Sim, max: usize) -> io::Result<Self> {
        let beacon = Self {
            identity: Identity::generate(),
            socket: sim.link().attach_next(),
            link: sim.link().clone(),
            clock: sim.clock().clone(),
            runtime: sim.clock().runtime(),
            max_connections: max,
            endpoint: Mutex::new(None),
            task: Mutex::new(None),
            registry: Mutex::new(None),
        };
        beacon.spawn()?;
        Ok(beacon)
    }

    /// Where it listens: the address a client pins.
    #[must_use]
    pub fn address(&self) -> SocketAddr {
        self.socket.addr()
    }

    /// The key a client pins.
    #[must_use]
    pub fn key(&self) -> Fingerprint {
        self.identity.fingerprint()
    }

    /// The identity itself, for a rogue server that must pass the pin.
    #[must_use]
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// What the beacon remembers: the run in progress, or the last run's memory
    /// once it is stopped.
    #[must_use]
    pub fn registry(&self) -> Arc<Mutex<Registry>> {
        Arc::clone(
            self.registry
                .lock()
                .expect("beacon registry is not poisoned")
                .as_ref()
                .expect("a beacon has a registry"),
        )
    }

    /// A client for `machine`, on the endpoint the machine also uses for peers.
    pub fn client(&self, machine: &Machine) -> Result<Beacon, String> {
        let endpoint = machine.endpoint().map_err(|error| error.to_string())?;
        Ok(Beacon::new(
            endpoint,
            Arc::clone(&self.runtime),
            self.address(),
            self.key(),
            machine.identity.clone(),
        ))
    }

    /// Stop answering: the endpoint closes and every connection on it goes.
    pub fn stop(&self) {
        self.teardown(true);
    }

    /// Stop as a killed process does: nothing is delivered to it any more and its
    /// endpoint is dropped without a `CONNECTION_CLOSE`, so a client only learns
    /// the beacon is gone from its own request bound.
    ///
    /// The server's connection tasks and the transport's state for them survive
    /// until the idle timeout — a real process death would take them with it — so
    /// a restart has to wait that out before it can take the socket back.
    pub fn kill(&self) {
        self.link.silence(self.address());
        self.teardown(false);
    }

    /// Stop and start again at the same address with the same key, as a process
    /// restart does. Everything registered is gone: there is no disk and no
    /// recovery.
    ///
    /// # Errors
    ///
    /// When the stopped endpoint will not release its socket, so the restart
    /// cannot be honest.
    pub async fn restart(&mut self) -> Result<(), String> {
        self.stop();
        // The wait covers a killed beacon too: its connection tasks and transport
        // state go only when the idle timeout expires.
        let steps = mahbot_peers::beacon::BEACON_IDLE_TIMEOUT.as_secs() / 5 + 2;
        for _ in 0..steps {
            if Arc::strong_count(&self.socket) == 1 {
                break;
            }
            self.clock.advance(Duration::from_secs(5)).await;
            tokio::task::yield_now().await;
        }
        let holders = Arc::strong_count(&self.socket);
        if holders != 1 {
            return Err(format!(
                "the stopped beacon still holds its socket ({holders} references)"
            ));
        }
        self.spawn().map_err(|error| error.to_string())
    }

    fn spawn(&self) -> io::Result<()> {
        self.link.resume(self.address());
        let config = server_config(&self.identity).map_err(io::Error::other)?;
        let endpoint = endpoint(&self.socket, config, Arc::clone(&self.runtime))?;
        let registry = Arc::new(Mutex::new(Registry::new()));
        let server = BeaconServer::new(
            endpoint.clone(),
            Arc::clone(&self.runtime),
            Arc::new(self.clock.clone()),
            Arc::clone(&registry),
        )
        .with_max_connections(self.max_connections);
        *self.endpoint() = Some(endpoint);
        *self.task() = Some(tokio::spawn(server.run()));
        *self
            .registry
            .lock()
            .expect("beacon registry slot is not poisoned") = Some(registry);
        Ok(())
    }

    fn teardown(&self, close: bool) {
        // A poisoned slot means an earlier panic is already unwinding; a second
        // panic here would abort the process and hide it.
        if let Ok(mut slot) = self.endpoint.lock()
            && let Some(endpoint) = slot.take()
            && close
        {
            endpoint.close(0u32.into(), b"beacon stopped");
        }
        if let Ok(mut slot) = self.task.lock()
            && let Some(task) = slot.take()
        {
            task.abort();
        }
    }

    fn endpoint(&self) -> MutexGuard<'_, Option<Endpoint>> {
        self.endpoint
            .lock()
            .expect("beacon endpoint slot is not poisoned")
    }

    fn task(&self) -> MutexGuard<'_, Option<tokio::task::JoinHandle<()>>> {
        self.task.lock().expect("beacon task slot is not poisoned")
    }
}

impl Drop for TestBeacon {
    fn drop(&mut self) {
        self.teardown(true);
    }
}
