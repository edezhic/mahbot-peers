//! Connection cases: the manager's two sources, the four failures, the address
//! rule, the tie-break, the keeper's two stops, the registration refresh, and the
//! restart that keeps only the root.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use mahbot_peers::identity::PeerId;
use mahbot_peers::peer::{
    ActionError, ActionId, ActionKind, ConnectFailure, Connections, KEEPER_SETTLE, ManagerError,
    NoFloor, NotTrustedCause, Presence, RECOVERY_DIALS, RECOVERY_FIRST_GAP, RECOVERY_RECHECK,
    RecordStore, Recovery, Registration, Rights, Started, StopCause, TRUST_POLL, VANISH_BOUND,
    Vanish,
};
use mahbot_peers::tls::PeerPolicy;

use crate::beacon::TestBeacon;
use crate::clock::block_on;
use crate::connect::TrustSet;
use crate::machine::Machine;
use crate::sim::Sim;

use super::peer::{NOW, Shown, pair_together, paired, session};
use super::rights::{label, person};
use super::support::{io_error, keep_findable, pair, spawn_keeper, within};

/// A machine's manager, its endpoint and the accept loop the case spawned.
///
/// The loop is the case's own task: the library returns the future and the
/// caller keeps the handle, which is what lets this case stop it.
pub(super) struct Managed {
    pub(super) connections: Arc<Connections>,
    pub(super) endpoint: quinn::Endpoint,
    accept: tokio::task::JoinHandle<()>,
}

impl Managed {
    pub(super) fn start(
        sim: &Sim,
        beacon: &TestBeacon,
        machine: &Machine,
        store: &RecordStore,
    ) -> Result<Self, String> {
        Self::start_over(sim.clock().runtime(), beacon, machine, store)
    }

    /// The same manager over a runtime the caller names: a case that has to make the manager's
    /// own reader unable to run hands in a runtime that drops the tasks spawned through it.
    pub(super) fn start_over(
        runtime: Arc<dyn quinn::Runtime>,
        beacon: &TestBeacon,
        machine: &Machine,
        store: &RecordStore,
    ) -> Result<Self, String> {
        let endpoint = machine.endpoint().map_err(|error| error.to_string())?;
        let connections = Arc::new(
            Connections::new(
                &machine.identity,
                store.clone(),
                Some(beacon.client(machine)?),
                runtime,
                &machine.transport,
            )
            .map_err(|error| error.to_string())?,
        );
        // One accept loop: it hands each incoming connection to a task of its own, so a
        // stalled handshake never blocks the next accept.
        let accept = tokio::spawn(Arc::clone(&connections).serve(endpoint.clone()));
        Ok(Self {
            connections,
            endpoint,
            accept,
        })
    }
}

impl Drop for Managed {
    fn drop(&mut self) {
        self.accept.abort();
        self.endpoint.close(0u32.into(), b"the case is done");
    }
}

/// Two machines a person already paired, each remembering the other's address.
fn paired_machines(sim: &Sim) -> Result<(Machine, Machine, RecordStore, RecordStore), String> {
    let left = sim.machine().map_err(io_error)?;
    let right = sim.machine().map_err(io_error)?;
    let left_store = pair_records(&left, &right)?;
    let right_store = right.records();
    Ok((left, right, left_store, right_store))
}

pub(crate) fn pairing_then_direct_connection() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let left = sim.machine().map_err(io_error)?;
        let right = sim.machine().map_err(io_error)?;
        let left_store = left.records();
        let right_store = right.records();
        let (left_outcome, right_outcome) = pair_together(
            &sim,
            &beacon,
            super::peer::Pairing {
                left: &left,
                right: &right,
                left_opens: mahbot_peers::peer::Opening::Initiate(right.fingerprint()),
                right_opens: mahbot_peers::peer::Opening::Respond,
                left_person: &Shown::accepting(),
                right_person: &Shown::accepting(),
                left_store: &left_store,
                right_store: &right_store,
            },
        )
        .await?;
        if !paired(&left_outcome) || !paired(&right_outcome) {
            return Err("the ceremony did not pair both sides".to_owned());
        }
        let managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        // The peer keeps itself findable, as a running machine does; the pairing
        // wrote no address, so the first connect needs the beacon's answer.
        let presence_task = keep_findable(&sim, &beacon, &right).await?;
        // The ceremony's sessions are dropped and their closes flushed. The pairing
        // wrote no address, so this first connect asks the beacon for one — a
        // lookup, which is the beacon's part. The data path that follows must not
        // touch it.
        sim.clock().advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        let connection = within(
            &sim,
            Duration::from_secs(60),
            managed_left
                .connections
                .connect(&managed_left.endpoint, &right.fingerprint()),
        )
        .await?
        .map_err(|error| error.to_string())?;
        if connection.remote_address() != right.addr() {
            return Err(format!(
                "the connection reached {} instead of {}",
                connection.remote_address(),
                right.addr()
            ));
        }
        // The lookup's session is dropped and its close flushed; from here the
        // connection must add no datagram to the beacon.
        sim.clock().advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        let mark = sim.link().trace().len();
        // It is a real connection: a datagram crosses it, machine to machine.
        connection
            .send_datagram(b"hello".as_slice().into())
            .map_err(|error| error.to_string())?;
        let live = managed_right
            .connections
            .live(&left.peer_id())
            .ok_or("the accepting side adopted no connection")?;
        let received = within(&sim, Duration::from_secs(5), live.read_datagram())
            .await?
            .map_err(|error| error.to_string())?;
        if &received[..] != b"hello" {
            return Err(format!("the datagram arrived as {received:?}"));
        }
        let trace = sim.link().trace();
        if trace[mark..]
            .iter()
            .any(|event| event.to == beacon.address())
        {
            return Err("the direct data path touched the beacon".to_owned());
        }
        presence_task.abort();
        Ok(())
    })
}

pub(crate) fn reconnect_uses_remembered_address_first() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right, left_store, right_store) = paired_machines(&sim)?;
        // Give the accepting side a wrong address for the left, so the assertion below
        // cannot pass on what the pairing wrote: only the accept can correct it.
        let wrong = sim.link().alloc_addr();
        right_store
            .record_address(&left.peer_id(), wrong)
            .map_err(|error| error.to_string())?;
        let _managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        let mark = sim.link().trace().len();
        let connection = within(
            &sim,
            Duration::from_secs(60),
            managed_left
                .connections
                .connect(&managed_left.endpoint, &right.fingerprint()),
        )
        .await?
        .map_err(|error| error.to_string())?;
        if connection.remote_address() != right.addr() {
            return Err("the remembered address was not the one dialed".to_owned());
        }
        let trace = sim.link().trace();
        if trace[mark..]
            .iter()
            .any(|event| event.to == beacon.address())
        {
            return Err(
                "the beacon was consulted although the remembered address worked".to_owned(),
            );
        }
        // The accepting side learned the address authenticated data arrived from.
        let recorded = right_store
            .get(&left.peer_id())
            .and_then(|record| record.last_address());
        if recorded != Some(left.addr()) {
            return Err(format!(
                "the accepted side recorded {recorded:?} instead of {:?}",
                left.addr()
            ));
        }
        Ok(())
    })
}

pub(crate) fn reconnect_falls_back_to_the_beacon() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, mut right, left_store, _right_store) = paired_machines(&sim)?;
        let stale = right.addr();
        // The restart always comes back at a fresh address.
        right.restart().await?;
        let fresh = right.addr();
        // The machine that came back registers itself; the side that stayed up
        // does not poll for it.
        let right_store = right.records();
        let _managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        // The machine keeps itself findable the way it does in a running process:
        // the registration is refreshed while it runs, not held by one request.
        let presence_task = keep_findable(&sim, &beacon, &right).await?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        let mark = sim.link().trace().len();
        let connection = within(
            &sim,
            Duration::from_secs(120),
            managed_left
                .connections
                .connect(&managed_left.endpoint, &right.fingerprint()),
        )
        .await?
        .map_err(|error| error.to_string())?;
        if connection.remote_address() != fresh {
            return Err(format!(
                "the connection reached {} instead of the fresh {fresh}",
                connection.remote_address()
            ));
        }
        let trace = sim.link().trace();
        let fresh_events = &trace[mark..];
        let first_stale = fresh_events
            .iter()
            .position(|event| event.to == stale)
            .ok_or("the remembered address was not tried first")?;
        let first_beacon = fresh_events
            .iter()
            .position(|event| event.to == beacon.address())
            .ok_or("the beacon was not asked after the stale address")?;
        if first_beacon < first_stale {
            return Err("the beacon was asked before the remembered address".to_owned());
        }
        // The dialing side does not write the address it dialed: only an accept
        // records where authenticated data came from. The record keeps the stale
        // address, which is what a later reconnect tries first.
        if left_store
            .get(&right.peer_id())
            .and_then(|record| record.last_address())
            != Some(stale)
        {
            return Err("the dialing side rewrote the address it dialed".to_owned());
        }
        presence_task.abort();
        Ok(())
    })
}

pub(crate) fn reconnect_stops_after_both_fail() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let left = sim.machine().map_err(io_error)?;
        let left_store = left.records();
        let peer = sim.machine().map_err(io_error)?;
        // A paired peer whose remembered address answers nothing and which the
        // beacon does not know.
        let silent = sim.link().attach_next();
        let silent_addr = silent.addr();
        left_store
            .record_pairing(&peer.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        left_store
            .record_address(&peer.peer_id(), silent_addr)
            .map_err(|error| error.to_string())?;
        let managed = Managed::start(&sim, &beacon, &left, &left_store)?;
        let failure = within(
            &sim,
            Duration::from_secs(120),
            managed
                .connections
                .connect(&managed.endpoint, &peer.fingerprint()),
        )
        .await?;
        match failure {
            Err(ConnectFailure::PeerUnknown { cause, .. })
                if cause.contains(&silent_addr.to_string()) && cause.contains("not registered") => {
            }
            other => return Err(format!("the failure reads {other:?}")),
        }
        // The beacon session the dial opened is dropped and its close flushed;
        // from here nothing may move.
        sim.clock().advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        let mark = sim.link().trace().len();
        sim.clock().advance(Duration::from_secs(600)).await;
        tokio::task::yield_now().await;
        let trace = sim.link().trace();
        if !trace[mark..].is_empty() {
            return Err(format!(
                "the manager moved {} time(s) after both sources failed",
                trace[mark..].len()
            ));
        }
        drop(silent);
        Ok(())
    })
}

pub(crate) fn four_failures_are_distinct() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let left = sim.machine().map_err(io_error)?;
        let left_store = left.records();
        let endpoint = left.endpoint().map_err(|error| error.to_string())?;

        // Not trusted: no record at all.
        let stranger = sim.machine().map_err(io_error)?;
        let manager = Connections::new(
            &left.identity,
            left_store.clone(),
            Some(beacon.client(&left)?),
            sim.clock().runtime(),
            &left.transport,
        )
        .map_err(|error| error.to_string())?;
        let not_trusted = manager.connect(&endpoint, &stranger.fingerprint()).await;

        // The beacon is configured and does not answer.
        let unreachable_peer = sim.machine().map_err(io_error)?;
        left_store
            .record_pairing(&unreachable_peer.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        let dead_beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let dead_manager = Connections::new(
            &left.identity,
            left_store.clone(),
            Some(dead_beacon.client(&left)?),
            sim.clock().runtime(),
            &left.transport,
        )
        .map_err(|error| error.to_string())?;
        dead_beacon.stop();
        let unreachable = within(
            &sim,
            Duration::from_secs(60),
            dead_manager.connect(&endpoint, &unreachable_peer.fingerprint()),
        )
        .await?;

        // The beacon does not know the peer.
        let unknown_peer = sim.machine().map_err(io_error)?;
        left_store
            .record_pairing(&unknown_peer.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        let unknown = manager
            .connect(&endpoint, &unknown_peer.fingerprint())
            .await;

        // The beacon knows the peer and gives its address, and no connection can be
        // made to it: the peer's path answers nothing.
        let pathless_peer = sim.machine().map_err(io_error)?;
        let pathless_session = session(&beacon, &pathless_peer).await?;
        left_store
            .record_pairing(&pathless_peer.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        sim.link().silence(pathless_peer.addr());
        let no_path = within(
            &sim,
            Duration::from_secs(120),
            manager.connect(&endpoint, &pathless_peer.fingerprint()),
        )
        .await?;

        let reported = [
            ("not trusted", &not_trusted, "not trusted"),
            (
                "beacon unreachable",
                &unreachable,
                "beacon is not available",
            ),
            ("peer unknown", &unknown, "the beacon does not know"),
            ("no direct path", &no_path, "no direct path"),
        ];
        for (what, failure, expected) in reported {
            let Err(error) = failure else {
                return Err(format!("{what} was reported as success"));
            };
            if !error.to_string().contains(expected) {
                return Err(format!("{what} reads `{error}`, not `{expected}`"));
            }
        }
        let variants = [
            matches!(not_trusted, Err(ConnectFailure::NotTrusted { .. })),
            matches!(unreachable, Err(ConnectFailure::BeaconUnreachable { .. })),
            matches!(unknown, Err(ConnectFailure::PeerUnknown { .. })),
            matches!(no_path, Err(ConnectFailure::NoDirectPath { .. })),
        ];
        if variants.iter().any(|found| !found) {
            return Err("a failure was reported as another".to_owned());
        }
        drop(pathless_session);
        Ok(())
    })
}

/// A transport the keeper could not watch cannot build a manager: neither a silence
/// deadline no longer than the keeper's window nor a keep-alive that cannot fire
/// before the timeout is accepted, so a caller cannot turn an ordinary silent drop
/// into a strike by configuring this machine's transport.
pub(crate) fn manager_refuses_an_unwatchable_transport() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;
        let store = machine.records();
        for idle in [KEEPER_SETTLE, KEEPER_SETTLE - Duration::from_secs(1)] {
            let transport = mahbot_peers::net::Transport {
                idle_timeout: idle,
                keep_alive: None,
            };
            match Connections::new(
                &machine.identity,
                store.clone(),
                None,
                sim.clock().runtime(),
                &transport,
            ) {
                Err(ManagerError::IdleTimeoutTooShort { idle_timeout }) if idle_timeout == idle => {
                    continue;
                }
                Err(error) => {
                    return Err(format!(
                        "a transport with a {idle:?} idle timeout was refused as `{error}`"
                    ));
                }
                Ok(_) => {
                    return Err(format!(
                        "a transport with a {idle:?} idle timeout built a manager"
                    ));
                }
            }
        }
        // A keep-alive at or past the timeout could never fire: a quiet pair would be
        // closed and re-dialled on every timeout.
        let idle = KEEPER_SETTLE + Duration::from_secs(1);
        for keep_alive in [idle, idle + Duration::from_secs(1)] {
            let transport = mahbot_peers::net::Transport {
                idle_timeout: idle,
                keep_alive: Some(keep_alive),
            };
            match Connections::new(
                &machine.identity,
                store.clone(),
                None,
                sim.clock().runtime(),
                &transport,
            ) {
                Err(ManagerError::KeepAliveNotBelowIdle {
                    keep_alive: reported,
                    idle_timeout: reported_idle,
                }) if reported == keep_alive && reported_idle == idle => continue,
                Err(error) => {
                    return Err(format!(
                        "a {keep_alive:?} keep-alive under a {idle:?} idle timeout was refused as \
                         `{error}`"
                    ));
                }
                Ok(_) => {
                    return Err(format!(
                        "a {keep_alive:?} keep-alive under a {idle:?} idle timeout built a manager"
                    ));
                }
            }
        }
        let transport = mahbot_peers::net::Transport {
            idle_timeout: idle,
            keep_alive: Some(idle - Duration::from_secs(1)),
        };
        Connections::new(
            &machine.identity,
            store,
            None,
            sim.clock().runtime(),
            &transport,
        )
        .map_err(|error| error.to_string())?;
        Ok(())
    })
}

/// A keep-alive slower than half of `VANISH_BOUND` is not refused: it raises this machine's
/// own liveness bound to twice the keep-alive, so a live quiet peer is still not declared gone
/// between two pings. The bound is stated per manager, and a pair that carries nothing for
/// longer than the fixed bound stays the connection it was.
pub(crate) fn a_slow_keep_alive_raises_the_bound() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let idle = Duration::from_secs(90);
        let keep_alive = Duration::from_secs(40);
        let left = sim
            .machine()
            .map_err(io_error)?
            .with_idle_timeout(idle)
            .with_keep_alive(Some(keep_alive));
        let right = sim
            .machine()
            .map_err(io_error)?
            .with_idle_timeout(idle)
            .with_keep_alive(Some(keep_alive));
        let left_store = pair_records(&left, &right)?;
        let right_store = right.records();
        let managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        // Two pings are further apart than the fixed bound, so the bound is the keep-alive's.
        let stated = keep_alive * 2 + 2 * TRUST_POLL;
        if stated <= VANISH_BOUND + 2 * TRUST_POLL {
            return Err("the case's keep-alive does not raise the bound".to_owned());
        }
        let keeper = spawn_keeper(&managed_left, &right);
        let first = wait_live(&sim, &managed_left.connections, &right.peer_id(), None).await?;
        // Read once the manager's own reader has been heard from: before that nothing measures
        // the peer's silence and the reading is unmeasured.
        let read = measured_bound(&sim, &managed_left.connections).await?;
        if read != stated {
            return Err(format!(
                "a {keep_alive:?} keep-alive states a {read:?} bound, not {stated:?}"
            ));
        }
        let id = first.stable_id();
        // Nothing is carried for longer than the fixed bound: with the fixed one the keeper
        // would declare this live peer gone before its first ping.
        let total = VANISH_BOUND + 2 * TRUST_POLL;
        let mut spent = Duration::ZERO;
        while spent < total {
            sim.clock().advance(TRUST_POLL).await;
            sim.clock().settle().await;
            spent += TRUST_POLL;
        }
        if keeper.is_finished() {
            return Err("the keeper of a quiet pair stopped".to_owned());
        }
        let live = managed_left
            .connections
            .live(&right.peer_id())
            .ok_or("a slow keep-alive let the keeper declare a live quiet peer gone")?;
        if live.stable_id() != id {
            return Err("the quiet pair was re-dialled to a different connection".to_owned());
        }
        if managed_left.connections.recovery(&right.peer_id()) != Recovery::Connected {
            return Err("a live quiet pair does not read connected".to_owned());
        }
        let there = managed_right
            .connections
            .live(&left.peer_id())
            .ok_or("the far side of a quiet pair lost its connection")?;
        if there.remote_address() != left.addr() {
            return Err(format!(
                "the far side holds {} instead of the quiet peer at {}",
                there.remote_address(),
                left.addr()
            ));
        }
        Ok(())
    })
}

pub(crate) fn one_connection_per_pair() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right, left_store, right_store) = paired_machines(&sim)?;
        let managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        let left_fingerprint = left.fingerprint();
        let right_fingerprint = right.fingerprint();
        let (left_out, right_out) = within(&sim, Duration::from_secs(120), async {
            tokio::join!(
                managed_left
                    .connections
                    .connect(&managed_left.endpoint, &right_fingerprint),
                managed_right
                    .connections
                    .connect(&managed_right.endpoint, &left_fingerprint),
            )
        })
        .await?;
        left_out.map_err(|error| error.to_string())?;
        right_out.map_err(|error| error.to_string())?;
        // Both sides kept the connection started by the smaller fingerprint.
        let expected_left = if left.peer_id() < right.peer_id() {
            Started::Here
        } else {
            Started::There
        };
        let expected_right = if right.peer_id() < left.peer_id() {
            Started::Here
        } else {
            Started::There
        };
        // The two accept loops apply the tie-break after the dials return, so wait
        // until both sides have answered, then name the side that kept the wrong one.
        let (left_started, right_started) = within(&sim, Duration::from_secs(60), async {
            loop {
                if let (Some(left), Some(right)) = (
                    managed_left.connections.started_by(&right.peer_id()),
                    managed_right.connections.started_by(&left.peer_id()),
                ) {
                    return (left, right);
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;
        if left_started != expected_left {
            return Err(format!(
                "the left kept the connection started {left_started:?}, not {expected_left:?}"
            ));
        }
        if right_started != expected_right {
            return Err(format!(
                "the right kept the connection started {right_started:?}, not {expected_right:?}"
            ));
        }
        let left_live = managed_left
            .connections
            .live(&right.peer_id())
            .ok_or("the left side kept no connection")?;
        let right_live = managed_right
            .connections
            .live(&left.peer_id())
            .ok_or("the right side kept no connection")?;
        // It is one connection, not two halves of different ones: both sides' keepers
        // are a direct path to each other, and a datagram crosses them.
        if left_live.remote_address() != right.addr() || right_live.remote_address() != left.addr()
        {
            return Err("a keeper is not a direct path to the peer".to_owned());
        }
        left_live
            .send_datagram(b"pair".as_slice().into())
            .map_err(|error| error.to_string())?;
        let received = within(&sim, Duration::from_secs(5), right_live.read_datagram())
            .await?
            .map_err(|error| error.to_string())?;
        if &received[..] != b"pair" {
            return Err(format!("the datagram arrived as {received:?}"));
        }
        Ok(())
    })
}

pub(crate) fn same_starter_tie_break_keeps_one() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right, left_store, right_store) = paired_machines(&sim)?;
        let managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        let right_fingerprint = right.fingerprint();
        // Both connections are started by the same machine: the exporter rule, not
        // the fingerprint rule, decides, and both sides compute the same value.
        let (first, second) = within(&sim, Duration::from_secs(120), async {
            tokio::join!(
                managed_left
                    .connections
                    .connect(&managed_left.endpoint, &right_fingerprint),
                managed_left
                    .connections
                    .connect(&managed_left.endpoint, &right_fingerprint),
            )
        })
        .await?;
        first.map_err(|error| error.to_string())?;
        second.map_err(|error| error.to_string())?;
        let left_live = managed_left
            .connections
            .live(&right.peer_id())
            .ok_or("the dialing side kept no connection")?;
        let right_live = managed_right
            .connections
            .live(&left.peer_id())
            .ok_or("the accepting side kept no connection")?;
        if managed_left.connections.started_by(&right.peer_id()) != Some(Started::Here) {
            return Err("the dialing side did not keep its own connection".to_owned());
        }
        if managed_right.connections.started_by(&left.peer_id()) != Some(Started::There) {
            return Err("the accepting side did not keep the dialer's connection".to_owned());
        }
        // One connection, not two: a datagram sent on one side's keeper arrives on
        // the other side's keeper.
        left_live
            .send_datagram(b"one".as_slice().into())
            .map_err(|error| error.to_string())?;
        let received = within(&sim, Duration::from_secs(5), right_live.read_datagram())
            .await?
            .map_err(|error| error.to_string())?;
        if &received[..] != b"one" {
            return Err(format!("the datagram arrived as {received:?}"));
        }
        Ok(())
    })
}

/// The tie-break closes the connection it does not keep: a dial the manager adopts
/// and drops reports closed with the tie-break's reason, and one connection is left.
pub(crate) fn tie_break_closes_the_dropped_connection() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (first, second, first_store, second_store) = paired_machines(&sim)?;
        // The rule keeps the connection the smaller fingerprint started, so the
        // smaller machine keeps its own and drops the larger one's.
        let (small, large, small_store, large_store) = if first.peer_id() < second.peer_id() {
            (first, second, first_store, second_store)
        } else {
            (second, first, second_store, first_store)
        };
        let managed_small = Managed::start(&sim, &beacon, &small, &small_store)?;
        let managed_large = Managed::start(&sim, &beacon, &large, &large_store)?;
        let kept = within(
            &sim,
            Duration::from_secs(60),
            managed_small
                .connections
                .connect(&managed_small.endpoint, &large.fingerprint()),
        )
        .await?
        .map_err(|error| error.to_string())?;
        // A second dial, made outside the manager so the case keeps its handle: the
        // small side adopts it and drops it as the tie-break says.
        let connecting = managed_large
            .endpoint
            .connect(small.addr(), mahbot_peers::net::SERVER_NAME)
            .map_err(|error| error.to_string())?;
        let dropped = within(&sim, Duration::from_secs(60), connecting)
            .await?
            .map_err(|error| error.to_string())?;
        let end = within(&sim, Duration::from_secs(10), dropped.closed())
            .await
            .map_err(|_| "the dropped dial stayed open".to_owned())?;
        // The dropped dial ends with the tie-break's words. The substring is enough:
        // the other tie-break close is the exporter failure, and that one keeps
        // neither connection, while this case leaves the kept one carrying a datagram.
        match end {
            quinn::ConnectionError::ApplicationClosed(close)
                if std::str::from_utf8(&close.reason)
                    .is_ok_and(|text| text.contains("tie-break")) => {}
            other => return Err(format!("the dropped dial closed with {other:?}")),
        }
        if managed_small.connections.started_by(&large.peer_id()) != Some(Started::Here) {
            return Err("the small side did not keep its own connection".to_owned());
        }
        let there = wait_live(&sim, &managed_large.connections, &small.peer_id(), None).await?;
        if there.stable_id() == dropped.stable_id() {
            return Err("the manager kept the connection the rule dropped".to_owned());
        }
        kept.send_datagram(b"kept".as_slice().into())
            .map_err(|error| error.to_string())?;
        let received = within(&sim, Duration::from_secs(5), there.read_datagram())
            .await?
            .map_err(|error| error.to_string())?;
        if &received[..] != b"kept" {
            return Err(format!("the datagram arrived as {received:?}"));
        }
        Ok(())
    })
}

/// A dial whose connection loses the tie-break teaches no address: the record keeps
/// the last address authenticated data arrived from, never the address this machine
/// dialled.
pub(crate) fn tie_break_drop_records_no_address() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right, left_store, right_store) = paired_machines(&sim)?;
        let managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        let (small, large, small_managed, large_managed, small_store) =
            if left.peer_id() < right.peer_id() {
                (&left, &right, &managed_left, &managed_right, &left_store)
            } else {
                (&right, &left, &managed_right, &managed_left, &right_store)
            };
        // The smaller fingerprint's dial is the one the tie-break keeps.
        within(
            &sim,
            Duration::from_secs(60),
            small_managed
                .connections
                .connect(&small_managed.endpoint, &large.fingerprint()),
        )
        .await?
        .map_err(|error| error.to_string())?;
        let dialled = large.addr();
        // The larger machine moves, and the record learns where its authenticated data
        // now arrives from, as a previous accept would have written it.
        let moved = large.rebind_next();
        if moved == dialled {
            return Err("the rebind did not move the machine".to_owned());
        }
        small_store
            .record_address(&large.peer_id(), moved)
            .map_err(|error| error.to_string())?;
        // The larger dials from its new address. Its dial loses the tie-break to the
        // connection the smaller started, so the smaller keeps that connection — the
        // one it dialled to `dialled` — and must not copy that address into the record.
        within(
            &sim,
            Duration::from_secs(60),
            large_managed
                .connections
                .connect(&large_managed.endpoint, &small.fingerprint()),
        )
        .await?
        .map_err(|error| error.to_string())?;
        sim.clock().advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        // The drop this case is about really happened: the smaller still holds the
        // connection it dialled, not the larger machine's incoming one.
        if small_managed.connections.started_by(&large.peer_id()) != Some(Started::Here) {
            return Err(
                "the tie-break kept the larger machine's dial, so no drop was produced".to_owned(),
            );
        }
        let record = small_store
            .get(&large.peer_id())
            .ok_or("the smaller machine kept no record")?;
        if record.last_address() != Some(moved) {
            return Err(format!(
                "the record holds {:?}, not the address authenticated data arrived from {moved}",
                record.last_address()
            ));
        }
        Ok(())
    })
}

pub(crate) fn closed_connection_is_not_live() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right, left_store, right_store) = paired_machines(&sim)?;
        let _managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        let connection = within(
            &sim,
            Duration::from_secs(60),
            managed_left
                .connections
                .connect(&managed_left.endpoint, &right.fingerprint()),
        )
        .await?
        .map_err(|error| error.to_string())?;
        if managed_left.connections.live(&right.peer_id()).is_none() {
            return Err("the manager did not report its live connection".to_owned());
        }
        connection.close(0u32.into(), b"the case closes it");
        if managed_left.connections.live(&right.peer_id()).is_some()
            || managed_left
                .connections
                .started_by(&right.peer_id())
                .is_some()
        {
            return Err("a closed connection is still reported as live".to_owned());
        }
        Ok(())
    })
}

pub(crate) fn reconnect_cause_names_the_remembered_address() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let left = sim.machine().map_err(io_error)?;
        let left_store = left.records();
        let peer = sim.machine().map_err(io_error)?;
        let silent = sim.link().attach_next();
        let silent_addr = silent.addr();
        left_store
            .record_pairing(&peer.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        left_store
            .record_address(&peer.peer_id(), silent_addr)
            .map_err(|error| error.to_string())?;
        let endpoint = left.endpoint().map_err(|error| error.to_string())?;
        // No beacon at all: the remembered address was tried, and the failure must
        // say so rather than claim no address was remembered.
        let manager = Connections::new(
            &left.identity,
            left_store.clone(),
            None,
            sim.clock().runtime(),
            &left.transport,
        )
        .map_err(|error| error.to_string())?;
        let failure = within(
            &sim,
            Duration::from_secs(120),
            manager.connect(&endpoint, &peer.fingerprint()),
        )
        .await?;
        match failure {
            Err(ConnectFailure::BeaconUnreachable { cause, .. })
                if cause.contains(&silent_addr.to_string()) && cause.contains("no beacon") => {}
            other => {
                return Err(format!(
                    "a failed remembered dial was reported as {other:?}"
                ));
            }
        }
        drop(silent);
        Ok(())
    })
}

pub(crate) fn presence_keeps_registration_alive() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;
        let watcher = sim.machine().map_err(io_error)?;
        let watcher_session = session(&beacon, &watcher).await?;
        // A registration that is never refreshed is forgotten on its own lifetime
        // while the session stays open: keep-alive traffic holds the connection, and
        // the registration is what expires.
        let idle_session = session(&beacon, &machine).await?;
        if watcher_session
            .lookup(&machine.peer_id())
            .await
            .map_err(|error| error.to_string())?
            .is_none()
        {
            return Err("a fresh registration was not visible".to_owned());
        }
        sim.clock().advance(Duration::from_secs(400)).await;
        tokio::task::yield_now().await;
        if watcher_session
            .lookup(&machine.peer_id())
            .await
            .map_err(|error| error.to_string())?
            .is_some()
        {
            return Err("an unrefreshed registration outlived its lifetime".to_owned());
        }
        // The session is still open: it is the registration, not the connection,
        // that expired.
        if idle_session.lookup(&watcher.peer_id()).await.is_err() {
            return Err("the session expired instead of the registration".to_owned());
        }
        // A machine that wants to be found refreshes, and its registration outlives
        // the beacon's lifetime.
        let task = keep_findable(&sim, &beacon, &machine).await?;
        sim.clock().advance(Duration::from_secs(400)).await;
        // The refresh is a session and a registration on the clean link: what the advance
        // starts, a few scheduler turns finish. Ask until the answer is there rather than
        // counting turns.
        let answer = within(&sim, Duration::from_secs(120), async {
            loop {
                match watcher_session.lookup(&machine.peer_id()).await {
                    Ok(Some(address)) => return Ok::<_, String>(address),
                    Ok(None) => tokio::task::yield_now().await,
                    Err(error) => return Err(error.to_string()),
                }
            }
        })
        .await??;
        task.abort();
        if answer != machine.addr() {
            return Err("the refreshed registration was forgotten".to_owned());
        }
        drop(idle_session);
        Ok(())
    })
}

pub(crate) fn machine_restarts_over_the_same_root() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let mut machine = sim.machine().map_err(io_error)?;
        let peer = sim.machine().map_err(io_error)?;
        let fingerprint = machine.fingerprint();
        let root = machine.root_id();
        let first = machine.addr();
        let store = machine.records();
        store
            .record_pairing(&peer.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        store
            .record_address(&peer.peer_id(), peer.addr())
            .map_err(|error| error.to_string())?;
        let second = machine.restart().await?;
        if machine.root_id() != root {
            return Err("the restart changed the root".to_owned());
        }
        if machine.fingerprint() != fingerprint {
            return Err("the restart changed the identity".to_owned());
        }
        if second == first {
            return Err("the restart kept the address it had before".to_owned());
        }
        if !machine.records().is_paired(&peer.peer_id()) {
            return Err("the restart lost the pairing".to_owned());
        }
        Ok(())
    })
}

/// Neither side recorded an unfinished attempt: the reconnection ran no ceremony.
fn no_second_ceremony(
    left_store: &RecordStore,
    right: &PeerId,
    right_store: &RecordStore,
    left: &PeerId,
) -> Result<(), String> {
    let recorded = |store: &RecordStore, peer: &PeerId| {
        store
            .get(peer)
            .and_then(|record| record.attempt())
            .is_some()
    };
    if recorded(left_store, right) || recorded(right_store, left) {
        return Err("the reconnection ran a ceremony".to_owned());
    }
    Ok(())
}

/// Two machines paired by a real ceremony, with a manager and its accept loop on
/// the left. The right is left un-managed, so a case can restart it first.
async fn paired_by_ceremony(
    sim: &Sim,
    beacon: &TestBeacon,
) -> Result<(Machine, Machine, RecordStore, Managed), String> {
    let left = sim.machine().map_err(io_error)?;
    let right = sim.machine().map_err(io_error)?;
    let left_store = left.records();
    let right_store = right.records();
    // A real ceremony, not a record written by hand.
    let (left_outcome, right_outcome) = pair_together(
        sim,
        beacon,
        super::peer::Pairing {
            left: &left,
            right: &right,
            left_opens: mahbot_peers::peer::Opening::Initiate(right.fingerprint()),
            right_opens: mahbot_peers::peer::Opening::Respond,
            left_person: &Shown::accepting(),
            right_person: &Shown::accepting(),
            left_store: &left_store,
            right_store: &right_store,
        },
    )
    .await?;
    if !paired(&left_outcome) || !paired(&right_outcome) {
        return Err("the ceremony did not pair both sides".to_owned());
    }
    let managed_left = Managed::start(sim, beacon, &left, &left_store)?;
    Ok((left, right, left_store, managed_left))
}

pub(crate) fn pairing_then_reconnect_after_restart() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, mut right, left_store, managed_left) = paired_by_ceremony(&sim, &beacon).await?;
        // The peer goes away and comes back over the same root. The pairing
        // ceremony wrote no address, so the left has no remembered one to try: the
        // beacon is its first source, and it is still a lookup, not a path.
        right.restart().await?;
        let right_store = right.records();
        let _managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        let presence_task = keep_findable(&sim, &beacon, &right).await?;
        // Flush the ceremony sessions' closes, then watch the reconnection alone.
        sim.clock().advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        let second = within(
            &sim,
            Duration::from_secs(120),
            managed_left
                .connections
                .connect(&managed_left.endpoint, &right.fingerprint()),
        )
        .await?
        .map_err(|error| error.to_string())?;
        if second.remote_address() != right.addr() {
            return Err(format!(
                "the reconnection reached {} instead of {}",
                second.remote_address(),
                right.addr()
            ));
        }
        if !left_store.is_paired(&right.peer_id()) || !right_store.is_paired(&left.peer_id()) {
            return Err("the reconnection changed the pairing".to_owned());
        }
        no_second_ceremony(&left_store, &right.peer_id(), &right_store, &left.peer_id())?;
        presence_task.abort();
        Ok(())
    })
}

/// A real ceremony, then a restart, then the keeper alone: the pair comes back with
/// no human action, no second ceremony and no caller dialling.
pub(crate) fn pairing_restart_then_keeper_reconnects() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, mut right, left_store, managed_left) = paired_by_ceremony(&sim, &beacon).await?;
        let right_store = right.records();
        let managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        // The right keeps itself findable while it runs, so the left's first dial has
        // a beacon answer to use.
        let right_presence_task = keep_findable(&sim, &beacon, &right).await?;
        // The left dials once, so the right learns the address authenticated data
        // arrives from — the one its keeper tries first after the restart.
        let first = within(
            &sim,
            Duration::from_secs(120),
            managed_left
                .connections
                .connect(&managed_left.endpoint, &right.fingerprint()),
        )
        .await?
        .map_err(|error| error.to_string())?;
        let learned = right_store
            .get(&left.peer_id())
            .and_then(|record| record.last_address());
        if learned != Some(left.addr()) {
            return Err(format!(
                "the right learned {learned:?} instead of {}",
                left.addr()
            ));
        }
        // The peer goes away and comes back over the same root at a fresh address,
        // as a machine that restarted does; everything in memory is gone.
        drop(first);
        right_presence_task.abort();
        drop(managed_right);
        right.restart().await?;
        let right_store = right.records();
        let managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        let right_presence_task = keep_findable(&sim, &beacon, &right).await?;
        // No caller dials: the restarted machine's own start is the trigger, and its
        // keeper works through the remembered address by itself.
        let keeper = spawn_keeper(&managed_right, &left);
        let after = wait_live(&sim, &managed_right.connections, &left.peer_id(), None).await?;
        if after.remote_address() != left.addr() {
            return Err(format!(
                "the keeper reconnected to {} instead of {}",
                after.remote_address(),
                left.addr()
            ));
        }
        if keeper.is_finished() {
            let end = keeper.await.map_err(|error| error.to_string())?;
            return Err(format!("the keeper stopped after the restart: {end}"));
        }
        after
            .send_datagram(b"back".as_slice().into())
            .map_err(|error| error.to_string())?;
        let there = wait_live(&sim, &managed_left.connections, &right.peer_id(), None).await?;
        let received = within(&sim, Duration::from_secs(10), there.read_datagram())
            .await?
            .map_err(|error| error.to_string())?;
        if &received[..] != b"back" {
            return Err(format!("the datagram arrived as {received:?}"));
        }
        if !left_store.is_paired(&right.peer_id()) || !right_store.is_paired(&left.peer_id()) {
            return Err("the reconnection changed the pairing".to_owned());
        }
        no_second_ceremony(&left_store, &right.peer_id(), &right_store, &left.peer_id())?;
        keeper.abort();
        right_presence_task.abort();
        Ok(())
    })
}

/// A fresh address from an introduction is tried before the remembered one.
pub(crate) fn connect_with_tries_the_hint_first() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right, left_store, right_store) = paired_machines(&sim)?;
        // The remembered address is stale: a machine that never answers. The hint is
        // where the peer is now.
        let stale = sim.machine().map_err(io_error)?.addr();
        left_store
            .record_address(&right.peer_id(), stale)
            .map_err(|error| error.to_string())?;
        let _managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        // No beacon on the dialing side: only the hint can make this work.
        let endpoint = left.endpoint().map_err(|error| error.to_string())?;
        let manager = Connections::new(
            &left.identity,
            left_store.clone(),
            None,
            sim.clock().runtime(),
            &left.transport,
        )
        .map_err(|error| error.to_string())?;
        let mark = sim.link().trace().len();
        let connection = within(
            &sim,
            Duration::from_secs(60),
            manager.connect_with(&endpoint, &right.fingerprint(), Some(right.addr())),
        )
        .await?
        .map_err(|error| error.to_string())?;
        if connection.remote_address() != right.addr() {
            return Err("the hint was not the address dialed".to_owned());
        }
        if sim.link().trace()[mark..]
            .iter()
            .any(|event| event.to == stale)
        {
            return Err("the stale remembered address was tried before the hint".to_owned());
        }
        Ok(())
    })
}

/// A pair that was paired and then closed by rejections is not trusted: not by the
/// manager and not by the handshake.
pub(crate) fn closed_pair_is_not_trusted() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right, left_store, right_store) = paired_machines(&sim)?;
        // The right needs an accept task for the reconnection below.
        let _managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        for _ in 0..3 {
            left_store
                .record_failure(&right.peer_id())
                .map_err(|error| error.to_string())?;
        }
        if !left_store.is_paired(&right.peer_id()) || !left_store.is_closed(&right.peer_id()) {
            return Err("the record is not both paired and closed".to_owned());
        }
        let endpoint = left.endpoint().map_err(|error| error.to_string())?;
        let manager = Connections::new(
            &left.identity,
            left_store.clone(),
            None,
            sim.clock().runtime(),
            &left.transport,
        )
        .map_err(|error| error.to_string())?;
        match manager.connect(&endpoint, &right.fingerprint()).await {
            Err(ConnectFailure::NotTrusted {
                cause: NotTrustedCause::Closed,
                ..
            }) => {}
            other => return Err(format!("a paired but closed pair connected as {other:?}")),
        }
        // The handshake reads the same predicate: the endpoint trusts the record, not
        // the key alone.
        if crate::connect::connect(&right, &left).await.is_ok() {
            return Err("the transport completed a handshake with a closed pair".to_owned());
        }
        // A person's clear on this machine reopens it, through the audited act.
        Rights::new(left_store.clone(), left.audit()?)
            .clear_attempt_lock(&right.peer_id(), person("egor")?, NOW)
            .map_err(|error| error.to_string())?;
        if !left_store.trusts(&right.fingerprint()) {
            return Err("a person's clear did not reopen the pair".to_owned());
        }
        within(
            &sim,
            Duration::from_secs(60),
            manager.connect(&endpoint, &right.fingerprint()),
        )
        .await?
        .map_err(|error| error.to_string())?;
        Ok(())
    })
}

/// A record that is there and cannot be read is not a machine this one never paired:
/// the manager fails closed and names the record, so a person looks at the file that
/// exists rather than for a pairing that was never made.
#[cfg(unix)]
pub(crate) fn an_unreadable_record_is_not_an_unpaired_machine() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (left, right, left_store, _right_store) = paired_machines(&sim)?;
        let record = left
            .storage()
            .record_name(&right.peer_id())
            .map_err(io_error)?;
        left.storage()
            .set_record_mode(&right.peer_id(), 0o644)
            .map_err(io_error)?;
        let endpoint = left.endpoint().map_err(|error| error.to_string())?;
        let manager = Connections::new(
            &left.identity,
            left_store.clone(),
            None,
            sim.clock().runtime(),
            &left.transport,
        )
        .map_err(|error| error.to_string())?;
        match within(
            &sim,
            Duration::from_secs(60),
            manager.connect(&endpoint, &right.fingerprint()),
        )
        .await?
        {
            Err(ConnectFailure::NotTrusted {
                cause: NotTrustedCause::Unreadable { detail },
                ..
            }) => {
                if !detail.contains(&record) {
                    return Err(format!("the refusal does not name the record: {detail}"));
                }
            }
            other => {
                return Err(format!(
                    "an unreadable record was reported as {other:?}, not as unreadable"
                ));
            }
        }
        // The handshake reads the same predicate, and fails closed the same way.
        if within(
            &sim,
            Duration::from_secs(60),
            crate::connect::connect(&right, &left),
        )
        .await?
        .is_ok()
        {
            return Err("the transport completed a handshake over an unreadable record".to_owned());
        }
        Ok(())
    })
}

/// A close one side has not observed does not wedge the pair: whichever connection
/// the rule names, the loser is closed and the next dial reconnects the pair with
/// one connection that carries a datagram.
pub(crate) fn asymmetric_liveness_does_not_split_the_pair() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right, left_store, right_store) = paired_machines(&sim)?;
        let managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        let first = within(
            &sim,
            Duration::from_secs(60),
            managed_left
                .connections
                .connect(&managed_left.endpoint, &right.fingerprint()),
        )
        .await?
        .map_err(|error| error.to_string())?;
        // The close never reaches the right: the link drops everything addressed to it
        // while the left closes, then delivers again.
        sim.link().silence(right.addr());
        first.close(0u32.into(), b"the case closes it");
        sim.clock().advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        sim.link().resume(right.addr());
        if managed_left.connections.live(&right.peer_id()).is_some() {
            return Err("the left still reports a connection it closed".to_owned());
        }
        if managed_right.connections.live(&left.peer_id()).is_none() {
            return Err("the right observed a close the link dropped".to_owned());
        }
        // The right dials while only it still believes the old connection is alive.
        // Whether that dial is adopted or loses the tie-break is not the point: what
        // matters is that the pair does not end up with two different live keepers.
        let _ = within(
            &sim,
            Duration::from_secs(60),
            managed_right
                .connections
                .connect(&managed_right.endpoint, &left.fingerprint()),
        )
        .await?;
        // Whichever connection the rule named, the two sides either hold that same
        // one or one of them holds none; never two different live ones.
        sim.clock().advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        if let (Some(left_live), Some(right_live)) = (
            managed_left.connections.live(&right.peer_id()),
            managed_right.connections.live(&left.peer_id()),
        ) {
            left_live
                .send_datagram(b"agree".as_slice().into())
                .map_err(|error| error.to_string())?;
            let received = within(&sim, Duration::from_secs(5), right_live.read_datagram())
                .await?
                .map_err(|error| format!("the sides' keepers disagree: {error}"))?;
            if &received[..] != b"agree" {
                return Err("the two sides hold different connections".to_owned());
            }
        }
        // The stale connection times out; the next dial reconnects the pair.
        sim.clock().advance(Duration::from_secs(40)).await;
        tokio::task::yield_now().await;
        within(
            &sim,
            Duration::from_secs(60),
            managed_right
                .connections
                .connect(&managed_right.endpoint, &left.fingerprint()),
        )
        .await?
        .map_err(|error| error.to_string())?;
        let left_live = managed_left
            .connections
            .live(&right.peer_id())
            .ok_or("the left kept no connection after the retry")?;
        let right_live = managed_right
            .connections
            .live(&left.peer_id())
            .ok_or("the right kept no connection after the retry")?;
        left_live
            .send_datagram(b"back".as_slice().into())
            .map_err(|error| error.to_string())?;
        let received = within(&sim, Duration::from_secs(5), right_live.read_datagram())
            .await?
            .map_err(|error| error.to_string())?;
        if &received[..] != b"back" {
            return Err("the reconnection is not one connection".to_owned());
        }
        Ok(())
    })
}

/// Await the pair's live connection while the clock moves, optionally one whose
/// `stable_id` differs from `different_from`.
async fn wait_live(
    sim: &Sim,
    connections: &Connections,
    peer: &PeerId,
    different_from: Option<usize>,
) -> Result<quinn::Connection, String> {
    within(sim, Duration::from_secs(60), async {
        loop {
            if let Some(connection) = connections.live(peer)
                && Some(connection.stable_id()) != different_from
            {
                return connection;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| "no live connection within the budget".to_owned())
}

/// The bound `connections` states once its own liveness reader has been heard from.
///
/// [`Connections::vanish_bound`] answers [`Vanish::Unmeasured`] until the manager's reader has
/// made its first pass, and the pass is a [`TRUST_POLL`]-scale wait after the connection the
/// reader samples was adopted. A case that asserts a bound drives the clock until the reading
/// is measured, and answers what it read if it never is.
async fn measured_bound(sim: &Sim, connections: &Connections) -> Result<Duration, String> {
    let mut spent = Duration::ZERO;
    loop {
        let reading = connections.vanish_bound();
        if reading.measured() {
            return Ok(reading.bound());
        }
        if spent >= TRUST_POLL {
            return Err(format!(
                "the manager's own reader was never heard from: after {spent:?} of virtual time \
                 the bound still reads `{reading}`"
            ));
        }
        sim.clock().advance(Duration::from_millis(100)).await;
        tokio::task::yield_now().await;
        spent += Duration::from_millis(100);
    }
}

/// The default transport pings, so a pair with nothing to carry stays connected for
/// twice the idle timeout.
pub(crate) fn quiet_pair_stays_connected() -> Result<(), String> {
    // The manager refuses a keep-alive that is not below the timeout; that the
    // default has one at all is this case's own assertion.
    if mahbot_peers::net::Transport::default().keep_alive.is_none() {
        return Err("the default transport has no keep-alive".to_owned());
    }
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right, left_store, right_store) = paired_machines(&sim)?;
        let managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        within(
            &sim,
            Duration::from_secs(30),
            managed_left
                .connections
                .connect(&managed_left.endpoint, &right.fingerprint()),
        )
        .await?
        .map_err(|error| error.to_string())?;
        // Twice the idle timeout with nothing to carry: only the keep-alive keeps
        // this connection.
        sim.clock()
            .advance(mahbot_peers::net::DEFAULT_IDLE_TIMEOUT * 2)
            .await;
        tokio::task::yield_now().await;
        let live = managed_left
            .connections
            .live(&right.peer_id())
            .ok_or("the quiet pair was closed")?;
        let there = managed_right
            .connections
            .live(&left.peer_id())
            .ok_or("the quiet pair was closed on the other side")?;
        live.send_datagram(b"still here".to_vec().into())
            .map_err(|error| error.to_string())?;
        let received = within(&sim, Duration::from_secs(10), there.read_datagram())
            .await
            .map_err(|_| "the datagram did not cross".to_owned())?
            .map_err(|error| error.to_string())?;
        if received.as_ref() != b"still here" {
            return Err("the datagram crossed with different bytes".to_owned());
        }
        Ok(())
    })
}

/// A quiet, live pair is not declared gone by its own bound: with the default transport both
/// keepers run over a connection that carries nothing for longer than `vanish_bound()`, the
/// connection is the same one afterwards, both keepers are still running, the state reads
/// connected, and a datagram still crosses.
pub(crate) fn a_quiet_pair_outlives_the_vanish_bound() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right, left_store, right_store) = paired_machines(&sim)?;
        let managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        let left_keeper = spawn_keeper(&managed_left, &right);
        let right_keeper = spawn_keeper(&managed_right, &left);
        let first = wait_live(&sim, &managed_left.connections, &right.peer_id(), None).await?;
        wait_live(&sim, &managed_right.connections, &left.peer_id(), None).await?;
        let stated = VANISH_BOUND + 2 * TRUST_POLL;
        let read = measured_bound(&sim, &managed_left.connections).await?;
        if read != stated {
            return Err(format!(
                "with a keep-alive the bound is {read:?}, not {stated:?}"
            ));
        }
        let id = first.stable_id();
        // Nothing is sent: only each side's own keep-alive can keep the pair alive. The clock
        // moves in keeper rounds, and every timer due on the way fires, so the bound is crossed
        // with both keepers running rather than jumped over in one step.
        let total = Duration::from_secs(90);
        if total < read + 2 * TRUST_POLL {
            return Err("the case does not run past the bound it proves".to_owned());
        }
        let mut spent = Duration::ZERO;
        while spent < total {
            sim.clock().advance(TRUST_POLL).await;
            sim.clock().settle().await;
            spent += TRUST_POLL;
        }
        // The same connection is still the pair's, and the state says so.
        let live = managed_left
            .connections
            .live(&right.peer_id())
            .ok_or("a quiet, live pair was declared gone by its own bound")?;
        if live.stable_id() != id {
            return Err("the quiet pair was re-dialled to a different connection".to_owned());
        }
        if managed_left.connections.recovery(&right.peer_id()) != Recovery::Connected {
            return Err(format!(
                "the quiet pair reads `{}`, not connected",
                managed_left.connections.recovery(&right.peer_id())
            ));
        }
        if left_keeper.is_finished() || right_keeper.is_finished() {
            return Err("a keeper stopped while the quiet pair was still live".to_owned());
        }
        let there = managed_right
            .connections
            .live(&left.peer_id())
            .ok_or("the quiet pair was closed on the other side")?;
        live.send_datagram(b"still here".to_vec().into())
            .map_err(|error| error.to_string())?;
        let received = within(&sim, Duration::from_secs(10), there.read_datagram())
            .await
            .map_err(|_| "the datagram did not cross".to_owned())?
            .map_err(|error| error.to_string())?;
        if received.as_ref() != b"still here" {
            return Err("the datagram crossed with different bytes".to_owned());
        }
        left_keeper.abort();
        right_keeper.abort();
        Ok(())
    })
}

/// A machine that cannot measure a peer's silence does not conclude it.
///
/// The left's manager is built over a runtime that drops every task spawned through it, so its
/// liveness reader was started when the connection was adopted and never heard from again.
/// With a keep-alive and a reader that cannot be heard from, [`Connections::vanish_bound`]
/// answers [`Vanish::Unmeasured`] with the transport's idle timeout plus one keeper round, and
/// the keeper judges nothing vanished: however long the peer stays quiet — past the bound this
/// machine would apply if it could measure — the connection is the same one, it still carries,
/// the keeper is still running and the pair still reads connected.
///
/// The contrast that makes the reading mean something is the same machine's second manager over
/// the ordinary runtime: its reader runs, and the bound it states is [`Vanish::Measured`] at the
/// fixed value plus two keeper rounds.
pub(crate) fn an_unmeasured_silence_is_not_concluded() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right, left_store, right_store) = paired_machines(&sim)?;
        let managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        let managed_left =
            Managed::start_over(sim.clock().quiet_runtime(), &beacon, &left, &left_store)?;
        let keeper = spawn_keeper(&managed_left, &right);
        let first = wait_live(&sim, &managed_left.connections, &right.peer_id(), None).await?;
        // The reader this manager started has not been heard from, so nothing here measures
        // the peer's silence and the reading says so.
        let unmeasured = left.transport.idle_timeout + TRUST_POLL;
        let reading = managed_left.connections.vanish_bound();
        let Vanish::Unmeasured { bound } = reading else {
            return Err(format!(
                "a manager whose reader cannot run reads `{reading}`, not an unmeasured bound"
            ));
        };
        if bound != unmeasured {
            return Err(format!(
                "an unmeasured bound reads {bound:?}, not the transport's idle timeout plus one \
                 round ({unmeasured:?})"
            ));
        }
        let id = first.stable_id();
        // The clock is walked a second at a time, with every timer due on the way fired, past
        // the bound this machine would apply if it could measure: nothing may be concluded.
        let stated = VANISH_BOUND + 2 * TRUST_POLL;
        let mut spent = Duration::ZERO;
        while spent <= stated {
            sim.clock().advance(Duration::from_secs(1)).await;
            sim.clock().settle().await;
            tokio::task::yield_now().await;
            spent += Duration::from_secs(1);
        }
        let live = managed_left
            .connections
            .live(&right.peer_id())
            .ok_or_else(|| {
                format!(
                    "a machine that cannot measure a silence closed the connection after \
                     {spent:?}, past the {stated:?} bound it would apply if it could"
                )
            })?;
        if live.stable_id() != id {
            return Err(format!(
                "the pair re-dialled to connection {} from {id} on a silence nothing measured",
                live.stable_id()
            ));
        }
        if keeper.is_finished() {
            let end = keeper.await.map_err(|error| error.to_string())?;
            return Err(format!(
                "the keeper stopped on a silence nothing measured: {end}"
            ));
        }
        let state = managed_left.connections.recovery(&right.peer_id());
        if state != Recovery::Connected {
            return Err(format!(
                "the pair reads `{state}` after a silence nothing measured, not connected"
            ));
        }
        live.send_datagram(b"still here".as_slice().into())
            .map_err(|error| error.to_string())?;
        let there = managed_right
            .connections
            .live(&left.peer_id())
            .ok_or("the far side lost its connection on a silence nothing measured")?;
        let received = within(&sim, Duration::from_secs(10), there.read_datagram())
            .await?
            .map_err(|error| error.to_string())?;
        if &received[..] != b"still here" {
            return Err(format!("the datagram arrived as {received:?}"));
        }
        keeper.abort();
        // The contrast: the same machine's manager over the ordinary runtime. The unmeasured
        // manager's keeper is stopped and its connection dropped first, so nothing it does can
        // re-dial beside the second manager's dial.
        managed_left.connections.disconnect(&right.peer_id());
        sim.clock().advance(TRUST_POLL).await;
        sim.clock().settle().await;
        let measured = Managed::start(&sim, &beacon, &left, &left_store)?;
        within(
            &sim,
            Duration::from_secs(30),
            measured
                .connections
                .connect(&measured.endpoint, &right.fingerprint()),
        )
        .await?
        .map_err(|error| error.to_string())?;
        wait_live(&sim, &measured.connections, &right.peer_id(), None).await?;
        // Driven until the reader has been heard from, then the reading must be the measured
        // one, and its bound the fixed bound plus the two keeper rounds.
        measured_bound(&sim, &measured.connections).await?;
        let reading = measured.connections.vanish_bound();
        if !matches!(reading, Vanish::Measured { .. }) {
            return Err(format!(
                "a manager whose reader runs reads `{reading}`, not a measured bound"
            ));
        }
        let stated = VANISH_BOUND + 2 * TRUST_POLL;
        if reading.bound() != stated {
            return Err(format!(
                "a manager whose reader runs states {:?}, not {stated:?}",
                reading.bound()
            ));
        }
        Ok(())
    })
}

/// The manager owns recovery: its keeper re-dials the pair when the link fails,
/// with no caller dialling, and keeps the new connection.
pub(crate) fn keeper_reconnects_without_a_caller() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right, left_store, right_store) = paired_machines(&sim)?;
        let managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        let keeper = spawn_keeper(&managed_left, &right);
        let first = wait_live(&sim, &managed_left.connections, &right.peer_id(), None).await?;
        // The link fails: the far side closes the pair's connection.
        let there = managed_right
            .connections
            .live(&left.peer_id())
            .ok_or("the far side holds no connection")?;
        there.close(0u32.into(), b"the link failed");
        // The close reaches this side first, and only then does the keeper dial.
        let second = wait_live(
            &sim,
            &managed_left.connections,
            &right.peer_id(),
            Some(first.stable_id()),
        )
        .await?;
        // The new connection carries traffic, and the keeper is still running.
        second
            .send_datagram(b"back".to_vec().into())
            .map_err(|error| error.to_string())?;
        let there = managed_right
            .connections
            .live(&left.peer_id())
            .ok_or("the far side did not adopt the new connection")?;
        let received = within(&sim, Duration::from_secs(10), there.read_datagram())
            .await
            .map_err(|_| "the datagram did not cross the new connection".to_owned())?
            .map_err(|error| error.to_string())?;
        if received.as_ref() != b"back" {
            return Err("the new connection carried different bytes".to_owned());
        }
        if keeper.is_finished() {
            return Err("the keeper stopped while the pair was connected".to_owned());
        }
        keeper.abort();
        Ok(())
    })
}

/// A peer that accepts and closes a fresh connection does not turn the keeper into a
/// handshake loop, and does not end the pair either: the episode is used up after the
/// stated number of dials, the pair waits a stated re-check, the keeper keeps running,
/// and when the peer stops doing it the pair comes back with nobody acting.
pub(crate) fn keeper_bounds_a_peer_that_keeps_closing() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right, left_store, right_store) = paired_machines(&sim)?;
        // The far side completes the handshake but keeps each connection only for a
        // moment — shorter than the keeper's settle window — so every dial is a fresh
        // connection the peer then drops.
        let (closer, _accepted) = closing_peer(&sim, &right, |_, _| Duration::from_secs(1))?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        let keeper = spawn_keeper(&managed_left, &right);
        let state = wait_exhausted(&sim, &managed_left.connections, &right.peer_id()).await?;
        let Recovery::Exhausted { until, dials, last } = &state else {
            return Err(format!(
                "the pair's recovery reads `{state}`, not an episode used up"
            ));
        };
        if *dials != RECOVERY_DIALS {
            return Err(format!(
                "the episode was used up after {dials} dials, not {RECOVERY_DIALS}"
            ));
        }
        match last {
            ConnectFailure::NoDirectPath { peer, cause, .. } if *peer == right.fingerprint() => {
                if cause.is_empty() {
                    return Err("the failure names no cause for the last close".to_owned());
                }
            }
            other => {
                return Err(format!(
                    "the used-up episode names `{other}`, not the last connection that carried \
                     nothing"
                ));
            }
        }
        // The wait is the stated re-check, not the next gap of a run of dials.
        let now = sim.clock().now();
        let wait = until.saturating_duration_since(now);
        if wait > RECOVERY_RECHECK {
            return Err(format!(
                "the pair waits {wait:?} after its episode, longer than {RECOVERY_RECHECK:?}"
            ));
        }
        let words = state.to_string();
        if !words.contains("not connected") || !words.contains("the episode is used up") {
            return Err(format!("a used-up episode reads `{words}`"));
        }
        // A sentence a product may show states a condition and never a schedule: a reason to
        // dial can move the moment, so a sentence about the moment cannot stay true.
        if words.contains("next") || words.contains("re-check") {
            return Err(format!(
                "a used-up episode predicts its next dial: `{words}`"
            ));
        }
        // Bounded, and not finished: the keeper is still running.
        if keeper.is_finished() {
            return Err("the keeper stopped after a peer that keeps closing".to_owned());
        }
        // The peer stops closing and keeps what it is given: the pair recovers by itself,
        // inside one re-check, with no caller dialling and no keeper restarted.
        closer.abort();
        let _managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        within(&sim, RECOVERY_RECHECK + Duration::from_secs(60), async {
            loop {
                if managed_left.connections.live(&right.peer_id()).is_some() {
                    return Ok::<(), String>(());
                }
                tokio::task::yield_now().await;
            }
        })
        .await??;
        keeper.abort();
        Ok(())
    })
}

/// The wait a used-up episode names, read at the instant the state was sampled.
fn exhausted_wait(sim: &Sim, state: &Recovery) -> Result<Duration, String> {
    let Recovery::Exhausted { until, .. } = state else {
        return Err(format!("the pair reads `{state}`, not an episode used up"));
    };
    Ok(until.saturating_duration_since(sim.clock().now()))
}

/// One machine's used-up episode, and the wait it names.
///
/// The pair is the shape `keeper_bounds_a_peer_that_keeps_closing` uses: the machine runs a
/// manager and a keeper, and the far side only accepts and closes, so every dial is the
/// dialling machine's own.
async fn recheck_wait(
    sim: &Sim,
    beacon: &TestBeacon,
    dialler: &Machine,
) -> Result<Duration, String> {
    let far = sim.machine().map_err(io_error)?;
    let store = pair_records(dialler, &far)?;
    let (closer, _accepted) = closing_peer(sim, &far, |_, _| Duration::from_secs(1))?;
    let managed = Managed::start(sim, beacon, dialler, &store)?;
    let keeper = spawn_keeper(&managed, &far);
    let state = wait_exhausted(sim, &managed.connections, &far.peer_id()).await?;
    let wait = exhausted_wait(sim, &state)?;
    keeper.abort();
    closer.abort();
    Ok(wait)
}

/// The slow re-check is spread by the machine, so two machines that lost the same peer do not
/// come back at the same instant, and the stated bound is still the bound.
///
/// Three properties, and no copy of the derivation: a used-up episode waits no longer than
/// [`RECOVERY_RECHECK`], the same machine names the same wait each time, and two machines name
/// different ones. The wait is read immediately after the state became used up, so it is at most
/// one [`SAMPLE`] short of the moment itself; that sampling step is the tolerance below, not
/// padding on the bound.
///
/// The episodes are run one after the other because the clock is shared: a second keeper running
/// while the first episode is sampled would leave its own moment already in the past.
pub(crate) fn a_recheck_is_spread_by_the_machine() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let first = sim.machine().map_err(io_error)?;
        let one = recheck_wait(&sim, &beacon, &first).await?;
        if one > RECOVERY_RECHECK {
            return Err(format!(
                "a machine waits {one:?} after its episode, longer than the {RECOVERY_RECHECK:?} \
                 bound"
            ));
        }
        let again = recheck_wait(&sim, &beacon, &first).await?;
        if one.abs_diff(again) > SAMPLE {
            return Err(format!(
                "the same machine named {one:?} and then {again:?}: the re-check is not its own \
                 key's"
            ));
        }
        // Two keys can land within one `SAMPLE` of each other with probability around one in
        // thirteen, so a near-collision draws a fresh second machine rather than failing a case
        // that has nothing to do with the keys it drew. Eight draws make the chance that every one
        // of them is within the tolerance about one in seven hundred million.
        for _ in 0..8 {
            let second = sim.machine().map_err(io_error)?;
            let two = recheck_wait(&sim, &beacon, &second).await?;
            if two > RECOVERY_RECHECK {
                return Err(format!(
                    "a machine waits {two:?} after its episode, longer than the \
                     {RECOVERY_RECHECK:?} bound"
                ));
            }
            if two.abs_diff(one) > SAMPLE {
                return Ok(());
            }
        }
        Err(
            "nine machines drew the same re-check moment as the first: the re-check is not spread"
                .to_owned(),
        )
    })
}

/// Advance the clock until the pair's recovery is used up, and answer that state.
///
/// The clock is moved in steps rather than polled: a run of dials takes a minute of
/// virtual time, and one poll per instant would spend the case's whole poll budget on it.
async fn wait_exhausted(
    sim: &Sim,
    connections: &Connections,
    peer: &PeerId,
) -> Result<Recovery, String> {
    let mut spent = Duration::ZERO;
    loop {
        let state = connections.recovery(peer);
        if matches!(state, Recovery::Exhausted { .. }) {
            return Ok(state);
        }
        if spent > Duration::from_secs(600) {
            return Err(format!(
                "the pair never used up its episode: it reads `{state}` after {spent:?}"
            ));
        }
        sim.clock().advance(Duration::from_millis(200)).await;
        tokio::task::yield_now().await;
        spent += Duration::from_millis(200);
    }
}

/// A keeper whose dial fails with the pair holding nothing does not stop: the failure
/// keeps its own name in the state, the pause before each next dial is the gap that dial
/// earned, the episode is used up, and the pair is then tried once a re-check — bounded, paced
/// and readable the whole time.
pub(crate) fn keeper_retries_a_failed_dial() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        // The far side is paired but never runs: its address answers nothing, and the
        // beacon has no registration for it either, so every dial ends with `PeerUnknown`.
        let (left, right, left_store, _) = paired_machines(&sim)?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        let keeper = spawn_keeper(&managed_left, &right);
        // The first dial fails and the state says which failure, in its own name, and
        // names the remembered address that did not answer.
        let (dial, failure) = within(&sim, Duration::from_secs(600), async {
            loop {
                match managed_left.connections.recovery(&right.peer_id()) {
                    Recovery::Waiting {
                        last: Some(failure),
                        dial,
                        ..
                    } => return Ok::<_, String>((dial, failure)),
                    _ => tokio::task::yield_now().await,
                }
            }
        })
        .await??;
        if dial != 1 {
            return Err(format!("the first failed dial is numbered {dial}, not 1"));
        }
        let ConnectFailure::PeerUnknown { peer, cause } = &failure else {
            return Err(format!(
                "a failed dial is reported as `{failure}`, not peer unknown"
            ));
        };
        if *peer != right.fingerprint() {
            return Err("the failure names another peer".to_owned());
        }
        if !cause.contains(&right.addr().to_string()) {
            return Err(format!(
                "the failure does not name the remembered address {}: {cause}",
                right.addr()
            ));
        }
        // The episode is used up at the stated cap, and its pacing is read rather than counted:
        // the pause between the end of one dial and the start of the next is the gap that dial
        // earned. A keeper that paused one round instead of the gap would add a round to every
        // pause, and the dials would be far enough apart for the growth check below to pass
        // while the policy's own pacing was not being kept at all.
        let mut starts: Vec<Duration> = Vec::new();
        let mut ends: Vec<Duration> = Vec::new();
        let mut dialling = false;
        let mut spent = Duration::ZERO;
        let state = loop {
            let state = managed_left.connections.recovery(&right.peer_id());
            if matches!(state, Recovery::Exhausted { .. }) {
                break state;
            }
            let now_dialling = matches!(state, Recovery::Dialling { .. });
            if now_dialling && !dialling {
                starts.push(spent);
            } else if dialling && matches!(state, Recovery::Waiting { .. }) {
                ends.push(spent);
            }
            dialling = now_dialling;
            if spent >= Duration::from_secs(600) {
                return Err(format!(
                    "the episode was never used up: the pair reads `{state}` after {spent:?}"
                ));
            }
            sim.clock().advance(SAMPLE).await;
            tokio::task::yield_now().await;
            spent += SAMPLE;
        };
        if ends.len() < 3 || starts.len() < 4 {
            return Err(format!(
                "the episode's dials were sampled {} times: starts {starts:?}, ends {ends:?}",
                starts.len()
            ));
        }
        for (k, (end, next)) in ends.iter().zip(starts.iter().skip(1)).enumerate() {
            let pause = *next - *end;
            // The first dial's failure was already folded in when the sampling began, so the
            // first pause read here is the one dial 2 earned.
            let expected = RECOVERY_FIRST_GAP * (1 << (k + 1));
            if pause + SAMPLE * 3 < expected || pause > expected + SAMPLE * 3 {
                return Err(format!(
                    "the pause before dial {} reads {pause:?}, not the {expected:?} its \
                     predecessor earned",
                    k + 3
                ));
            }
        }
        let Recovery::Exhausted { dials, last, .. } = &state else {
            return Err(format!("the pair reads `{state}`, not an episode used up"));
        };
        if *dials != RECOVERY_DIALS {
            return Err(format!(
                "the episode was used up after {dials} dials, not {RECOVERY_DIALS}"
            ));
        }
        if !matches!(last, ConnectFailure::PeerUnknown { .. }) {
            return Err(format!("the used-up episode names `{last}`"));
        }
        if keeper.is_finished() {
            return Err("the keeper stopped after one failed dial".to_owned());
        }
        // And the peer that was never there is not hammered: a whole re-check window adds
        // one dial, not a run of them, and never restarts the episode. A re-check goes
        // `Exhausted -> begin(dial = RECOVERY_DIALS) -> failed -> Exhausted`, so the count
        // stays at the cap and only the moment moves.
        let before = managed_left.connections.recovery(&right.peer_id());
        let Recovery::Exhausted {
            until: before_until,
            dials: before_dials,
            ..
        } = before
        else {
            return Err(format!("the pair reads `{before}`, not an episode used up"));
        };
        sim.clock().advance(RECOVERY_RECHECK).await;
        // The re-check's one dial takes its connect budget to fail, so drive only until its
        // outcome is folded in — never far enough for a second re-check.
        let mut waited = Duration::ZERO;
        let after = loop {
            let state = managed_left.connections.recovery(&right.peer_id());
            if matches!(state, Recovery::Exhausted { .. }) {
                break state;
            }
            if waited >= Duration::from_secs(30) {
                return Err(format!(
                    "the re-check never settled: the pair reads `{state}`"
                ));
            }
            sim.clock().advance(Duration::from_secs(1)).await;
            sim.clock().settle().await;
            tokio::task::yield_now().await;
            waited += Duration::from_secs(1);
        };
        let Recovery::Exhausted { dials, until, .. } = &after else {
            return Err(format!(
                "a re-check left the pair at `{after}`, not the used-up episode"
            ));
        };
        if *dials != before_dials || *dials > RECOVERY_DIALS {
            return Err(format!(
                "a re-check changed the episode's dial count from {before_dials} to {dials}"
            ));
        }
        if *until <= before_until {
            return Err(format!(
                "a re-check did not schedule the next one: the moment stayed at {before_until:?}"
            ));
        }
        if keeper.is_finished() {
            return Err("the keeper stopped when its re-check failed".to_owned());
        }
        // A caller's own one-shot dial does not move the keeper's wait: it leaves the policy
        // alone and folds only what its dial produced, so a caller dialling every round does
        // not make the keeper dial every round as well.
        let Recovery::Exhausted { until: wait, .. } =
            managed_left.connections.recovery(&right.peer_id())
        else {
            return Err("the pair left its used-up episode before the caller dialled".to_owned());
        };
        let _ = within(
            &sim,
            Duration::from_secs(30),
            managed_left
                .connections
                .connect(&managed_left.endpoint, &right.fingerprint()),
        )
        .await?;
        let Recovery::Exhausted { until, .. } = managed_left.connections.recovery(&right.peer_id())
        else {
            return Err("a caller's own dial moved the pair out of its used-up episode".to_owned());
        };
        if until != wait {
            return Err(format!(
                "a caller's own dial moved the keeper's next one from {wait:?} to {until:?}"
            ));
        }
        keeper.abort();
        Ok(())
    })
}

/// A dial that fails while an inbound connection has already been accepted does not
/// stop the keeper: it asks whether the pair is connected before it reports the failure.
pub(crate) fn keeper_survives_a_failed_dial_while_the_pair_connects() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right, left_store, right_store) = paired_machines(&sim)?;
        // The left's remembered address for the right goes stale, and the beacon does
        // not know the right, so the left's dial ends with `PeerUnknown`.
        right.rebind_next();
        let managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        // The left dials the stale address first; the right's dial reaches the left's
        // accept loop while that dial is still in flight.
        let left_keeper = spawn_keeper(&managed_left, &right);
        let right_keeper = spawn_keeper(&managed_right, &left);
        within(&sim, Duration::from_secs(30), async {
            loop {
                if managed_left.connections.live(&right.peer_id()).is_some() {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;
        // Past the left's connect budget its dial fails, with the pair connected.
        sim.clock().advance(Duration::from_secs(20)).await;
        tokio::task::yield_now().await;
        if left_keeper.is_finished() {
            let end = left_keeper.await.map_err(|error| error.to_string())?;
            right_keeper.abort();
            return Err(format!(
                "the keeper stopped on a failed dial while the pair was connected: {end}"
            ));
        }
        // The pair really is the one the inbound connection took, and it carries.
        let live = managed_left
            .connections
            .live(&right.peer_id())
            .ok_or("the pair lost its connection")?;
        live.send_datagram(b"connected".as_slice().into())
            .map_err(|error| error.to_string())?;
        let there = managed_right
            .connections
            .live(&left.peer_id())
            .ok_or("the far side lost its connection")?;
        let received = within(&sim, Duration::from_secs(10), there.read_datagram())
            .await?
            .map_err(|error| error.to_string())?;
        if &received[..] != b"connected" {
            return Err(format!("the datagram arrived as {received:?}"));
        }
        left_keeper.abort();
        right_keeper.abort();
        Ok(())
    })
}

/// Write the pairing and the other's address on both sides, as a completed
/// comparison would, and answer the left's store.
fn pair_records(left: &Machine, right: &Machine) -> Result<RecordStore, String> {
    let left_store = left.records();
    let right_store = right.records();
    for (store, peer, address) in [
        (&left_store, right.peer_id(), right.addr()),
        (&right_store, left.peer_id(), left.addr()),
    ] {
        store
            .record_pairing(&peer, NOW)
            .map_err(|error| error.to_string())?;
        store
            .record_address(&peer, address)
            .map_err(|error| error.to_string())?;
    }
    Ok(left_store)
}

/// A far side that accepts every connection and closes it after `script(connection,
/// index)` of virtual time, counting the accepts: the peer the keeper's bound cases
/// script. The closure receives the accepted connection, so a case can make it carry
/// a datagram before it closes.
pub(super) fn closing_peer(
    sim: &Sim,
    right: &Machine,
    script: impl Fn(&quinn::Connection, usize) -> Duration + Send + 'static,
) -> Result<(tokio::task::JoinHandle<()>, Arc<AtomicUsize>), String> {
    let endpoint = right.endpoint().map_err(|error| error.to_string())?;
    let clock = sim.clock().clone();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    let task = tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let Ok(connection) = incoming.await else {
                continue;
            };
            let after = script(&connection, counter.fetch_add(1, Ordering::SeqCst));
            clock.schedule(after, move || connection.close(0u32.into(), b"draining"));
        }
    });
    Ok((task, accepted))
}

/// Two keepers that start at the same moment both dial — the link is silenced until
/// each side's dial is in the trace — and the pair converges on one connection that
/// carries a datagram while both keepers keep running: the tie-break resolves the
/// collision without stopping either keeper.
pub(crate) fn keeper_survives_a_supersession() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right, left_store, right_store) = paired_machines(&sim)?;
        let managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        // Neither side holds a connection. Silence both machines so neither dial can
        // reach the other, start both keepers, and wait until each has sent its own
        // dial: a datagram in the trace with no delivery can only be that side's
        // first handshake packet, because the remembered addresses leave no beacon
        // lookup to send anything else.
        let (left_addr, right_addr) = (left.addr(), right.addr());
        sim.link().silence(left_addr);
        sim.link().silence(right_addr);
        let left_keeper = spawn_keeper(&managed_left, &right);
        let right_keeper = spawn_keeper(&managed_right, &left);
        within(&sim, Duration::from_secs(5), async {
            loop {
                let trace = sim.link().trace();
                let left_dialled = trace.iter().any(|event| {
                    event.from == left_addr && event.to == right_addr && !event.delivered()
                });
                let right_dialled = trace.iter().any(|event| {
                    event.from == right_addr && event.to == left_addr && !event.delivered()
                });
                if left_dialled && right_dialled {
                    return Ok::<(), String>(());
                }
                tokio::task::yield_now().await;
            }
        })
        .await??;
        // Both dials are in flight: the collision is produced, not assumed.
        sim.link().resume(left_addr);
        sim.link().resume(right_addr);
        let left_live = wait_live(&sim, &managed_left.connections, &right.peer_id(), None).await?;
        let right_live = wait_live(&sim, &managed_right.connections, &left.peer_id(), None).await?;
        if left_keeper.is_finished() {
            let end = left_keeper.await.map_err(|error| error.to_string())?;
            right_keeper.abort();
            return Err(format!("the left keeper stopped on a collision: {end}"));
        }
        if right_keeper.is_finished() {
            let end = right_keeper.await.map_err(|error| error.to_string())?;
            left_keeper.abort();
            return Err(format!("the right keeper stopped on a collision: {end}"));
        }
        // Both machines kept the connection the smaller fingerprint started: the
        // collision was resolved by the rule, not by whichever dial happened to finish.
        let (small, large, small_managed, large_managed) = if left.peer_id() < right.peer_id() {
            (&left, &right, &managed_left, &managed_right)
        } else {
            (&right, &left, &managed_right, &managed_left)
        };
        match small_managed.connections.started_by(&large.peer_id()) {
            Some(Started::Here) => {}
            other => {
                return Err(format!(
                    "the smaller machine kept a connection started {other:?}, not its own"
                ));
            }
        }
        match large_managed.connections.started_by(&small.peer_id()) {
            Some(Started::There) => {}
            other => {
                return Err(format!(
                    "the larger machine kept a connection started {other:?}, not the smaller's"
                ));
            }
        }
        // The pair is one connection and it carries.
        left_live
            .send_datagram(b"paired".as_slice().into())
            .map_err(|error| error.to_string())?;
        let received = within(&sim, Duration::from_secs(10), right_live.read_datagram())
            .await?
            .map_err(|error| error.to_string())?;
        if &received[..] != b"paired" {
            return Err(format!("the datagram arrived as {received:?}"));
        }
        left_keeper.abort();
        right_keeper.abort();
        Ok(())
    })
}

/// A connection the peer kept past the settle window is not a strike: when it is lost
/// to an idle timeout, the keeper re-dials, three times over, and keeps running.
pub(crate) fn keeper_redials_a_link_failure() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        // Both sides time out together, so neither keeps a dead connection it would
        // hold against the new one. The idle timeout is past the keeper's settle
        // window, so each connection is one the peer kept: its loss is ordinary churn
        // and clears the count.
        let idle = KEEPER_SETTLE + Duration::from_secs(2);
        let left = sim
            .machine()
            .map_err(io_error)?
            .with_idle_timeout(idle)
            .with_keep_alive(None);
        let right = sim
            .machine()
            .map_err(io_error)?
            .with_idle_timeout(idle)
            .with_keep_alive(None);
        let left_store = pair_records(&left, &right)?;
        let right_store = right.records();
        let managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        let keeper = spawn_keeper(&managed_left, &right);
        let mut live = wait_live(&sim, &managed_left.connections, &right.peer_id(), None).await?;
        for round in 0..3 {
            // Nothing is carried and no keep-alive pings, so both idle timers fire
            // on a clean link: a link failure, not the peer closing.
            sim.clock().advance(idle + Duration::from_secs(1)).await;
            live = wait_live(
                &sim,
                &managed_left.connections,
                &right.peer_id(),
                Some(live.stable_id()),
            )
            .await
            .map_err(|error| format!("round {round}: the keeper did not re-dial: {error}"))?;
            if keeper.is_finished() {
                let end = keeper.await.map_err(|error| error.to_string())?;
                return Err(format!(
                    "the keeper stopped after link failure {round}: {end}"
                ));
            }
        }
        live.send_datagram(b"after three link failures".as_slice().into())
            .map_err(|error| error.to_string())?;
        let there = managed_right
            .connections
            .live(&left.peer_id())
            .ok_or("the far side holds no connection after the link failures")?;
        let received = within(&sim, Duration::from_secs(10), there.read_datagram())
            .await?
            .map_err(|error| error.to_string())?;
        if &received[..] != b"after three link failures" {
            return Err(format!("the datagram arrived as {received:?}"));
        }
        keeper.abort();
        Ok(())
    })
}

/// A connection that carried a datagram and then died is a link failure, not a
/// strike: the keeper re-dials it more times than the episode's cap of dials and keeps
/// running.
pub(crate) fn keeper_redials_a_used_connection() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right, left_store, _) = paired_machines(&sim)?;
        // Every connection carries one datagram from the far side and is then closed
        // inside the settle window. Under a lifetime rule these would be strikes in a
        // row; carrying traffic makes each one a link failure.
        let (closer, accepted) = closing_peer(&sim, &right, |connection, _| {
            let _ = connection.send_datagram(b"used".as_slice().into());
            Duration::from_secs(1)
        })?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        let keeper = spawn_keeper(&managed_left, &right);
        let enough = RECOVERY_DIALS as usize + 2;
        within(&sim, Duration::from_secs(600), async {
            loop {
                if keeper.is_finished() || accepted.load(Ordering::SeqCst) >= enough {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;
        closer.abort();
        if keeper.is_finished() {
            let end = keeper.await.map_err(|error| error.to_string())?;
            return Err(format!(
                "the keeper stopped on a connection that carried traffic: {end}"
            ));
        }
        keeper.abort();
        Ok(())
    })
}

/// A connection the pair got to use restarts the episode, so ordinary churn never adds up
/// to the slow state: six closes across two settled connections are re-dialled inside the
/// settle window and the pair never reads an episode used up.
///
/// The run is longer than one episode: two closes, a connection the peer keeps past
/// [`KEEPER_SETTLE`], two more closes, another settled connection, and two closes again —
/// six strikes, which is [`RECOVERY_DIALS`]. A keeper that counted them in a row would use
/// the episode up at the sixth and wait [`RECOVERY_RECHECK`] before dialling again; this case
/// therefore fails if the pair ever reads an episode used up, or if a close is not followed by
/// a live connection well inside the re-check.
pub(crate) fn keeper_resets_after_a_settled_connection() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right, left_store, _) = paired_machines(&sim)?;
        // Six of the eight connections are closed a second after the peer takes them —
        // inside the settle window, so each is a strike — and the third and sixth are kept
        // past the window, so the pair got to use them and the episode starts over.
        let (closer, accepted) = closing_peer(&sim, &right, |_, index| {
            if index == 2 || index == 5 {
                KEEPER_SETTLE + Duration::from_secs(1)
            } else {
                Duration::from_secs(1)
            }
        })?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        let keeper = spawn_keeper(&managed_left, &right);
        // A close must be followed by a live connection inside this: the keeper's own round
        // plus the gap before the next dial, and far short of the re-check a used-up episode
        // waits.
        let allowance = KEEPER_SETTLE + RECOVERY_RECHECK / 2;
        let mut live_seen = false;
        let mut dark_since: Option<Duration> = None;
        let mut spent = Duration::ZERO;
        loop {
            let state = managed_left.connections.recovery(&right.peer_id());
            if matches!(state, Recovery::Exhausted { .. }) {
                return Err(format!(
                    "a connection the pair used did not restart the episode: after {spent:?} \
                     the pair reads `{state}`"
                ));
            }
            if managed_left.connections.live(&right.peer_id()).is_some() {
                live_seen = true;
                dark_since = None;
            } else if live_seen && dark_since.is_none() {
                dark_since = Some(spent);
            }
            if let Some(since) = dark_since
                && spent - since > allowance
            {
                return Err(format!(
                    "a close was not followed by a live connection within {allowance:?}: the \
                     pair held none for {:?} and reads `{state}`",
                    spent - since
                ));
            }
            // The ninth connection is the one after the last of the six closes, so every
            // close the script makes has been followed by a dial the pair took.
            if accepted.load(Ordering::SeqCst) >= 9
                && managed_left.connections.live(&right.peer_id()).is_some()
            {
                break;
            }
            if keeper.is_finished() {
                let end = keeper.await.map_err(|error| error.to_string())?;
                return Err(format!("the keeper stopped after {end}"));
            }
            if spent >= Duration::from_secs(900) {
                return Err(format!(
                    "the churn never reached its ninth connection: the peer took {} and the \
                     pair reads `{state}` after {spent:?}",
                    accepted.load(Ordering::SeqCst)
                ));
            }
            sim.clock().advance(SAMPLE).await;
            tokio::task::yield_now().await;
            spent += SAMPLE;
        }
        closer.abort();
        if keeper.is_finished() {
            let end = keeper.await.map_err(|error| error.to_string())?;
            return Err(format!("the keeper stopped after {end}"));
        }
        keeper.abort();
        Ok(())
    })
}

/// A dial whose task is cancelled gives the pair its next dial back instead of leaving it
/// marked as dialling for ever.
///
/// The state the case produces: a service asks for a dial to a peer whose address answers
/// nothing, so the dial stays in flight for the whole connect budget; the task is then
/// dropped mid-handshake, as a product that gave up or was shut down would drop it. The pair
/// must read a state a dial is due from — not `Dialling`, which nothing dials out of — and a
/// keeper started afterwards must dial, with the pair coming up once the link answers again.
///
/// The same must hold after the pair has already had and lost a connection that the keeper
/// judged, which is the case where the connection map still holds a dead entry: that entry
/// is not the dial in flight, and settling the cancelled dial must not stop at it.
///
/// The same must hold for a keeper's own dial, cancelled by dropping the keeper: no keeper
/// runs afterwards, so the pair must read a state its next dial is due from, and a keeper
/// started again must dial it.
pub(crate) fn a_cancelled_dial_is_given_back() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right, left_store, right_store) = paired_machines(&sim)?;
        let managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        // Nothing addressed to the peer is delivered, so a dial to it stays in flight and
        // there is one to cancel.
        sim.link().silence(right.addr());
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        let connections = Arc::clone(&managed_left.connections);
        let endpoint = managed_left.endpoint.clone();
        let peer = right.fingerprint();
        let dial = tokio::spawn(async move { connections.ensure(&endpoint, &peer).await });
        within(&sim, Duration::from_secs(30), async {
            loop {
                if matches!(
                    managed_left.connections.recovery(&right.peer_id()),
                    Recovery::Dialling { .. }
                ) {
                    return Ok::<(), String>(());
                }
                tokio::task::yield_now().await;
            }
        })
        .await??;
        dial.abort();
        if dial.await.is_ok() {
            return Err("the cancelled dial ran to its answer instead of being dropped".to_owned());
        }
        // Given back, not left in flight: no keeper runs for this pair, so it reads exactly
        // that — not a wait nothing would act on.
        let state = managed_left.connections.recovery(&right.peer_id());
        if state != Recovery::Unwatched {
            return Err(format!(
                "a cancelled dial left the pair reading `{state}`, which nothing dials"
            ));
        }
        // A keeper started afterwards dials, and the pair comes up once the peer answers.
        sim.link().resume(right.addr());
        let keeper = spawn_keeper(&managed_left, &right);
        let live = wait_live(&sim, &managed_left.connections, &right.peer_id(), None).await?;
        live.send_datagram(b"after a cancelled dial".as_slice().into())
            .map_err(|error| error.to_string())?;
        let there = managed_right
            .connections
            .live(&left.peer_id())
            .ok_or("the far side holds no connection after the cancelled dial")?;
        let received = within(&sim, Duration::from_secs(10), there.read_datagram())
            .await?
            .map_err(|error| error.to_string())?;
        if &received[..] != b"after a cancelled dial" {
            return Err(format!("the datagram arrived as {received:?}"));
        }
        keeper.abort();
        // The same must hold when the pair has already had a connection and lost one the
        // keeper judged: past the settle window the connection the pair used is judged, and
        // closing it leaves a dead entry in the manager's map. Settling the cancelled dial
        // must not stop at that entry.
        sim.clock().advance(KEEPER_SETTLE + TRUST_POLL).await;
        if !managed_left.connections.disconnect(&right.peer_id()) {
            return Err("the pair held no live connection to close".to_owned());
        }
        sim.clock()
            .advance(TRUST_POLL + Duration::from_secs(1))
            .await;
        // The read is the judgement: the dead connection is folded into the policy as one the
        // pair used, and the map keeps it, closed, exactly as a keeper's own judgement would.
        let judged = managed_left.connections.recovery(&right.peer_id());
        if matches!(judged, Recovery::Dialling { .. }) {
            return Err(format!(
                "the pair reads `{judged}` after its judged connection was closed"
            ));
        }
        // A dial to a peer that answers nothing stays in flight and is dropped mid-handshake
        // again — this time with that dead entry still in the map.
        sim.link().silence(right.addr());
        let connections = Arc::clone(&managed_left.connections);
        let endpoint = managed_left.endpoint.clone();
        let peer = right.fingerprint();
        let dial = tokio::spawn(async move { connections.ensure(&endpoint, &peer).await });
        within(&sim, Duration::from_secs(30), async {
            loop {
                if matches!(
                    managed_left.connections.recovery(&right.peer_id()),
                    Recovery::Dialling { .. }
                ) {
                    return Ok::<(), String>(());
                }
                tokio::task::yield_now().await;
            }
        })
        .await??;
        dial.abort();
        if dial.await.is_ok() {
            return Err("the cancelled dial ran to its answer instead of being dropped".to_owned());
        }
        let state = managed_left.connections.recovery(&right.peer_id());
        if state != Recovery::Unwatched {
            return Err(format!(
                "the pair was left reading `{state}` after a judged connection, which nothing \
                 dials"
            ));
        }
        // Not merely readable: a keeper dials it, and the pair comes up and carries again.
        sim.link().resume(right.addr());
        let keeper = spawn_keeper(&managed_left, &right);
        let live = wait_live(&sim, &managed_left.connections, &right.peer_id(), None).await?;
        let there = wait_live(&sim, &managed_right.connections, &left.peer_id(), None).await?;
        live.send_datagram(b"after a judged connection".as_slice().into())
            .map_err(|error| error.to_string())?;
        let received = within(&sim, Duration::from_secs(10), there.read_datagram())
            .await?
            .map_err(|error| error.to_string())?;
        if &received[..] != b"after a judged connection" {
            return Err(format!("the datagram arrived as {received:?}"));
        }
        keeper.abort();
        // A keeper whose own task is cancelled mid-dial gives the pair back as well: no keeper
        // runs any more, so the pair must not keep claiming the dial.
        sim.link().silence(right.addr());
        managed_left.connections.disconnect(&right.peer_id());
        sim.clock().advance(KEEPER_SETTLE + TRUST_POLL).await;
        let keeper = spawn_keeper(&managed_left, &right);
        within(&sim, Duration::from_secs(30), async {
            loop {
                if matches!(
                    managed_left.connections.recovery(&right.peer_id()),
                    Recovery::Dialling { .. }
                ) {
                    return Ok::<(), String>(());
                }
                tokio::task::yield_now().await;
            }
        })
        .await??;
        keeper.abort();
        if keeper.await.is_ok() {
            return Err("the cancelled keeper answered instead of being dropped".to_owned());
        }
        let state = managed_left.connections.recovery(&right.peer_id());
        if state != Recovery::Unwatched {
            return Err(format!(
                "a cancelled keeper left the pair reading `{state}`, which nothing dials"
            ));
        }
        if managed_left.connections.watched(&right.peer_id()) {
            return Err("a cancelled keeper left the pair reading watched".to_owned());
        }
        // And a keeper started again dials it: the pair is not stuck, only unwatched.
        sim.link().resume(right.addr());
        let keeper = spawn_keeper(&managed_left, &right);
        let live = wait_live(&sim, &managed_left.connections, &right.peer_id(), None).await?;
        live.send_datagram(b"after a cancelled keeper".as_slice().into())
            .map_err(|error| error.to_string())?;
        keeper.abort();
        Ok(())
    })
}

/// A keeper that is gone is not a retry: who makes the next dial is readable beside what the
/// policy is doing.
///
/// The state the case produces: a keeper dials a silenced peer, fails, and waits out the gap
/// its failure earned. While it runs, the pair reads watched and the state is the wait the
/// keeper will act on. Its task is then cancelled, and the pair must stop saying that: nothing
/// will dial it next, while what the episode has done stays on record — the count is not thrown
/// away, because a peer that keeps dropping a connection is bounded by it. A keeper started
/// again dials at once and the pair comes up.
pub(crate) fn a_keeper_that_stops_is_not_a_retry() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right, left_store, right_store) = paired_machines(&sim)?;
        let managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        let peer = right.peer_id();
        if managed_left.connections.watched(&peer) {
            return Err("a pair no keeper has run for reads watched".to_owned());
        }
        // Nothing addressed to the peer is delivered, so the keeper's dial fails and the pair
        // waits out the gap the failure earned.
        sim.link().silence(right.addr());
        let keeper = spawn_keeper(&managed_left, &right);
        drive_until(&sim, Duration::from_secs(60), || {
            let state = managed_left.connections.recovery(&peer);
            if managed_left.connections.watched(&peer)
                && matches!(state, Recovery::Waiting { .. } | Recovery::Exhausted { .. })
            {
                Ok(())
            } else {
                Err(format!(
                    "a keeper waiting out a gap left the pair reading `{state}`"
                ))
            }
        })
        .await?;
        let running = managed_left.connections.recovery(&peer);
        let dial = match &running {
            Recovery::Waiting { dial, .. } => *dial,
            Recovery::Exhausted { dials, .. } => *dials,
            other => {
                return Err(format!(
                    "a keeper waiting out a gap left the pair reading `{other}`"
                ));
            }
        };
        keeper.abort();
        if keeper.await.is_ok() {
            return Err("the cancelled keeper answered instead of being dropped".to_owned());
        }
        if managed_left.connections.watched(&peer) {
            return Err("a cancelled keeper left the pair reading watched".to_owned());
        }
        // What the episode did is still true: the wait, and the dials it has made, are the
        // policy's record and are not thrown away with the keeper.
        let after = managed_left.connections.recovery(&peer);
        match &after {
            Recovery::Waiting { dial: count, .. } if *count == dial => {}
            Recovery::Exhausted { dials, .. } if *dials == dial => {}
            other => {
                return Err(format!(
                    "a cancelled keeper threw the episode away: the pair read `{other}` after \
                     `{running}`"
                ));
            }
        }
        // A keeper started again is what makes the wait a dial: the pair comes up and carries.
        sim.link().resume(right.addr());
        let keeper = spawn_keeper(&managed_left, &right);
        let live = wait_live(&sim, &managed_left.connections, &peer, None).await?;
        if !managed_left.connections.watched(&peer) {
            return Err("a pair a keeper runs for does not read watched".to_owned());
        }
        live.send_datagram(b"a keeper started again".as_slice().into())
            .map_err(|error| error.to_string())?;
        let there = wait_live(&sim, &managed_right.connections, &left.peer_id(), None).await?;
        let received = within(&sim, Duration::from_secs(10), there.read_datagram())
            .await?
            .map_err(|error| error.to_string())?;
        if &received[..] != b"a keeper started again" {
            return Err(format!("the datagram arrived as {received:?}"));
        }
        keeper.abort();
        Ok(())
    })
}

/// A second keeper for a pair already watched does not hand it a second episode.
///
/// The state the case produces: the left's keeper is the only dialer and the peer is paired
/// but never answers, so the episode is being spent on `PeerUnknown`. A caller starts a second
/// keeper for the same pair — nothing in the crate forbids it — and the count must stay where
/// it was: a keeper starting is a person's answer to whatever stopped the last one, so only
/// the pair's *first* keeper starts the episode over, or an accept-and-drop peer could be
/// given a fresh episode by starting another keeper.
pub(crate) fn a_second_keeper_does_not_restart_the_episode() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        // The far side is paired but never runs, so every dial ends with `PeerUnknown`.
        let (left, right, left_store, _) = paired_machines(&sim)?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        let first = spawn_keeper(&managed_left, &right);
        let mut dial = 0;
        drive_until(&sim, Duration::from_secs(600), || {
            match managed_left.connections.recovery(&right.peer_id()) {
                Recovery::Waiting {
                    dial: reached,
                    last: Some(_),
                    ..
                } if reached >= 2 => {
                    dial = reached;
                    Ok(())
                }
                state => Err(format!("the episode is not under way: it reads `{state}`")),
            }
        })
        .await?;
        // The second keeper starts while the first is mid-dial: the narrowest interleaving,
        // where a keeper's own entry could otherwise start the episode over in the middle of a
        // dial that is already spending one of its numbers.
        drive_until(&sim, Duration::from_secs(600), || {
            match managed_left.connections.recovery(&right.peer_id()) {
                Recovery::Dialling { dial: reached } if reached > dial => {
                    dial = reached;
                    Ok(())
                }
                state => Err(format!("the episode is not dialling: it reads `{state}`")),
            }
        })
        .await?;
        let second = spawn_keeper(&managed_left, &right);
        // The dial that was in flight finishes under the second keeper, and its outcome is the
        // episode's own: the number it hands on is the one the episode had reached, not the
        // first of a run the second keeper started. Sampling only while the dial is in flight
        // would not see it — a dial in flight is reported as its own number whatever the state
        // under it says — so the wait is for that dial to end.
        drive_until(&sim, Duration::from_secs(600), || {
            match managed_left.connections.recovery(&right.peer_id()) {
                Recovery::Dialling { .. } => Err("the dial is still in flight".to_owned()),
                _ => Ok(()),
            }
        })
        .await?;
        let reached = match managed_left.connections.recovery(&right.peer_id()) {
            Recovery::Waiting { dial: reached, .. }
            | Recovery::Exhausted { dials: reached, .. } => reached,
            state => return Err(format!("the dial ended as `{state}`")),
        };
        if reached < dial {
            return Err(format!(
                "a second keeper restarted the episode mid-dial: it reads {reached} of {dial} \
                 dials after the dial that was in flight"
            ));
        }
        // And from here on no state may show fewer dials than the episode had — the second
        // keeper dialling is a dial of the same episode, not the first of a new one.
        for _ in 0..10 {
            sim.clock().advance(SAMPLE).await;
            tokio::task::yield_now().await;
            let now = match managed_left.connections.recovery(&right.peer_id()) {
                Recovery::Dialling { dial }
                | Recovery::Waiting { dial, .. }
                | Recovery::Exhausted { dials: dial, .. } => dial,
                _ => continue,
            };
            if now < dial {
                return Err(format!(
                    "a second keeper restarted the episode: it reads {now} of {dial} dials"
                ));
            }
        }
        if !managed_left.connections.watched(&right.peer_id()) {
            return Err("the pair stopped reading watched while a keeper ran".to_owned());
        }
        second.abort();
        first.abort();
        Ok(())
    })
}

/// An inbound connection keeps a used-up episode used up, and a one-shot dial promises
/// nothing on a pair no keeper runs for.
///
/// The state the case produces: the left's keeper is the only dialer and its remembered
/// address for the right is stale, so the left uses its whole episode up on `PeerUnknown`.
/// The right then dials in — its own remembered address for the left is still good — and the
/// left must keep the count at the cap: an authenticated inbound connection is not a reason
/// to speed the pair up again, or a peer that accepts and drops and also dials in would
/// escape the bound. The right's own one-shot `Connections::connect` runs no keeper, so once
/// its connection is gone it reads `Unwatched`: no retry was promised, and none is shown.
pub(crate) fn a_peer_dialling_in_does_not_restart_a_used_up_episode() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right, left_store, right_store) = paired_machines(&sim)?;
        // The left's remembered address for the right goes stale, and the beacon does not
        // know the right, so every dial the left makes ends with `PeerUnknown`.
        right.rebind_next();
        let managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        // Only the left's keeper dials, and it uses the episode up.
        let keeper = spawn_keeper(&managed_left, &right);
        let state = wait_exhausted(&sim, &managed_left.connections, &right.peer_id()).await?;
        let Recovery::Exhausted { dials, .. } = &state else {
            return Err(format!("the pair reads `{state}`, not an episode used up"));
        };
        if *dials != RECOVERY_DIALS {
            return Err(format!(
                "the episode was used up after {dials} dials, not {RECOVERY_DIALS}"
            ));
        }
        // The keeper goes, so nothing but the right's own dial touches the pair from here.
        keeper.abort();
        if keeper.await.is_ok() {
            return Err("the keeper ran to its answer instead of being dropped".to_owned());
        }
        sim.clock().advance(Duration::from_secs(1)).await;
        // The right dials in: its remembered address for the left never moved.
        within(
            &sim,
            Duration::from_secs(60),
            managed_right
                .connections
                .connect(&managed_right.endpoint, &left.fingerprint()),
        )
        .await?
        .map_err(|error| error.to_string())?;
        wait_live(&sim, &managed_left.connections, &right.peer_id(), None).await?;
        // The dialling side holds the connection it dialled.
        let held = managed_right.connections.recovery(&left.peer_id());
        if held != Recovery::Connected {
            return Err(format!(
                "the dialling side reads `{held}` while it holds the connection"
            ));
        }
        // An inbound connection does not restart the episode: the count stays at the cap,
        // and the loss of that connection is judged inside it.
        if !managed_left.connections.disconnect(&right.peer_id()) {
            return Err("the left held no live connection to close".to_owned());
        }
        let after = managed_left.connections.recovery(&right.peer_id());
        let Recovery::Exhausted { dials, .. } = &after else {
            return Err(format!(
                "an inbound connection restarted the episode: the pair reads `{after}`"
            ));
        };
        if *dials != RECOVERY_DIALS {
            return Err(format!(
                "an inbound connection moved the dial count to {dials}, not {RECOVERY_DIALS}"
            ));
        }
        // And the one-shot dial promised nothing it cannot keep: the dialling side ran no
        // keeper, so once its connection is gone it reads `Unwatched` rather than a retry
        // nothing will make.
        sim.clock().advance(TRUST_POLL).await;
        let gone = managed_right.connections.recovery(&left.peer_id());
        if gone != Recovery::Unwatched {
            return Err(format!(
                "a one-shot dial on a pair no keeper runs for left the pair reading `{gone}`, \
                 not unwatched"
            ));
        }
        Ok(())
    })
}

/// A peer that stops answering is noticed within [`Connections::vanish_bound`] and
/// re-dialled, and its silence is not counted as a strike against the pair.
///
/// The state the case produces: both machines' addresses are silenced on the link, so
/// neither this machine's pings reach the peer nor the peer's own keep-alives reach this
/// machine. That is a peer whose process is gone, which both answers nothing and sends
/// nothing. Silencing only the peer's address is not the same state and does not prove
/// this bound: the link's silence drops datagrams *addressed to* one machine, and a peer
/// that is merely deaf still sends its own pings, so this machine's reading of the peer's
/// life keeps moving and the connection is not called vanished until the transport itself
/// gives up. What is asserted here is the keeper's own close, not the transport's timeout:
/// the connection ends locally (a `LocallyClosed`), before the idle timeout could end it
/// with `TimedOut`.
pub(crate) fn a_vanished_peer_is_noticed_within_the_bound() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right, left_store, right_store) = paired_machines(&sim)?;
        let _managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        // The default transport pings, so the stated bound is the one the case proves.
        // With a keep-alive the bound is the peer's silence plus the two keeper rounds it
        // takes to notice and to close; the branch without one is its own case, which measures
        // it rather than asserting the arithmetic.
        let stated = VANISH_BOUND + 2 * TRUST_POLL;
        let keeper = spawn_keeper(&managed_left, &right);
        let first = wait_live(&sim, &managed_left.connections, &right.peer_id(), None).await?;
        // Read once the manager's own reader has been heard from: before that nothing measures
        // the peer's silence and the reading is unmeasured.
        let read = measured_bound(&sim, &managed_left.connections).await?;
        if read != stated {
            return Err(format!(
                "with a keep-alive the bound is {read:?}, not {stated:?}"
            ));
        }
        // The peer's process is gone: nothing addressed to either machine is delivered.
        sim.link().silence(right.addr());
        sim.link().silence(left.addr());
        // The bound the crate states, and nothing more: a bound a case has to pad is not a
        // bound a product can show.
        let allowance = read;
        let mut spent = Duration::ZERO;
        let state = loop {
            if managed_left.connections.live(&right.peer_id()).is_none() {
                break managed_left.connections.recovery(&right.peer_id());
            }
            if spent >= allowance {
                sim.link().resume(right.addr());
                sim.link().resume(left.addr());
                return Err(format!(
                    "a vanished peer was not noticed within {allowance:?}: the connection \
                     still reads live after {spent:?}"
                ));
            }
            sim.clock().advance(Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
            spent += Duration::from_secs(1);
        };
        // The manager closed it, not the transport: a peer that went quiet is noticed by
        // this machine's own reading of the peer's life.
        match first.close_reason() {
            Some(quinn::ConnectionError::LocallyClosed) => {}
            other => {
                sim.link().resume(right.addr());
                sim.link().resume(left.addr());
                return Err(format!(
                    "the vanished connection ended as `{other:?}`, not by the manager's close"
                ));
            }
        }
        // A silence is a redial, not a failure counted against the pair: the episode is
        // not used up and the dial count is the one the redial is, not a run of strikes.
        let dial = match &state {
            Recovery::Waiting { dial, .. } | Recovery::Dialling { dial } => *dial,
            Recovery::Exhausted { dials, .. } => {
                sim.link().resume(right.addr());
                sim.link().resume(left.addr());
                return Err(format!(
                    "a vanished peer was counted as {dials} failed dials in one episode"
                ));
            }
            other => {
                sim.link().resume(right.addr());
                sim.link().resume(left.addr());
                return Err(format!(
                    "after the peer vanished the pair reads `{other}`, not a dial due again"
                ));
            }
        };
        if dial > 1 {
            sim.link().resume(right.addr());
            sim.link().resume(left.addr());
            return Err(format!(
                "the redial after a vanished peer is numbered {dial}, not the first dial"
            ));
        }
        keeper.abort();
        sim.link().resume(right.addr());
        sim.link().resume(left.addr());
        Ok(())
    })
}

/// A peer built with a shorter idle timeout than this machine's does not turn a quiet drop
/// into a failure counted against the pair.
///
/// The right machine advertises the shortest idle timeout the manager accepts — anything at
/// or below [`KEEPER_SETTLE`] is refused — with a keep-alive that fires well inside it. Both
/// addresses are then silenced, so the pair goes quiet in both directions: nothing either
/// side sends arrives, and the connection ends from that silence — the transport's own timeout,
/// or the keeper's reading of the peer's life, whichever notices first — inside the peer's
/// shorter timeout and before this machine's own 30 s could have fired.
/// A timeout is a peer that went quiet, not a dial that produced nothing, so the keeper
/// re-dials at once and the pair comes back with nobody acting.
pub(crate) fn a_shorter_peer_timeout_is_not_a_strike() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let left = sim.machine().map_err(io_error)?;
        let right = sim
            .machine()
            .map_err(io_error)?
            .with_idle_timeout(Duration::from_secs(11))
            .with_keep_alive(Some(Duration::from_secs(4)));
        let left_store = pair_records(&left, &right)?;
        let right_store = right.records();
        let managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        let keeper = spawn_keeper(&managed_left, &right);
        let first = wait_live(&sim, &managed_left.connections, &right.peer_id(), None).await?;
        // The pair goes quiet: nothing either side sends is delivered.
        sim.link().silence(right.addr());
        sim.link().silence(left.addr());
        // The stated bound, which covers the peer's own shorter timeout and the one reset this
        // machine's keep-alive gives it: a bound a case has to pad is not one a product can
        // show. It is read once the manager's own reader has been heard from, which is what
        // makes it a measured bound rather than an unmeasured one.
        let allowance = measured_bound(&sim, &managed_left.connections).await?;
        let mut spent = Duration::ZERO;
        let state = loop {
            if managed_left.connections.live(&right.peer_id()).is_none() {
                break managed_left.connections.recovery(&right.peer_id());
            }
            if spent >= allowance {
                sim.link().resume(right.addr());
                sim.link().resume(left.addr());
                return Err(format!(
                    "the quiet pair was still connected after {spent:?}, longer than the stated \
                     {allowance:?}"
                ));
            }
            sim.clock().advance(Duration::from_secs(1)).await;
            // The transport has to observe the timers the walk fired before the next step
            // decides whether the connection is still live.
            sim.clock().settle().await;
            tokio::task::yield_now().await;
            spent += Duration::from_secs(1);
        };
        // The drop is the silence, noticed either by this machine's own transport — the peer's
        // shorter timeout taking effect — or by the keeper's reading of the peer's life, which
        // is the same silence. Neither is a strike, which is what the rest of the case proves;
        // what must not happen is the peer having said goodbye, because it was silenced.
        match first.close_reason() {
            Some(quinn::ConnectionError::TimedOut) => {}
            Some(quinn::ConnectionError::LocallyClosed) => {}
            other => {
                sim.link().resume(right.addr());
                sim.link().resume(left.addr());
                return Err(format!(
                    "the quiet connection ended as `{other:?}`, not from the silence"
                ));
            }
        }
        // Not a strike: the episode is not used up, and the count is the redial's.
        let dial = match &state {
            Recovery::Waiting { dial, .. } | Recovery::Dialling { dial } => *dial,
            Recovery::Exhausted { dials, .. } => {
                sim.link().resume(right.addr());
                sim.link().resume(left.addr());
                return Err(format!(
                    "a timeout inside the peer's own shorter timeout was counted as \
                     {dials} failed dials in one episode"
                ));
            }
            other => {
                sim.link().resume(right.addr());
                sim.link().resume(left.addr());
                return Err(format!(
                    "after the timeout the pair reads `{other}`, not a dial due again"
                ));
            }
        };
        if dial > 1 {
            sim.link().resume(right.addr());
            sim.link().resume(left.addr());
            return Err(format!(
                "the redial after a timeout is numbered {dial}, not the first dial"
            ));
        }
        // The keeper re-dials: the pair comes back on a fresh connection, with no caller
        // dialling, and the new connection carries.
        sim.link().resume(right.addr());
        sim.link().resume(left.addr());
        let second = wait_live(
            &sim,
            &managed_left.connections,
            &right.peer_id(),
            Some(first.stable_id()),
        )
        .await?;
        second
            .send_datagram(b"back".as_slice().into())
            .map_err(|error| error.to_string())?;
        let there = managed_right
            .connections
            .live(&left.peer_id())
            .ok_or("the far side did not adopt the connection the keeper re-dialled")?;
        let received = within(&sim, Duration::from_secs(10), there.read_datagram())
            .await?
            .map_err(|error| error.to_string())?;
        if &received[..] != b"back" {
            return Err(format!("the datagram arrived as {received:?}"));
        }
        keeper.abort();
        Ok(())
    })
}

/// Without a keep-alive the stated bound is the transport's own idle timeout plus the round that
/// sees the close, and this case measures it rather than asserting the arithmetic.
///
/// Neither machine pings, so nothing this machine sends would make a silent peer answer and the
/// only thing that can notice the silence is the transport. Both advertise the shortest idle
/// timeout the manager accepts, so the bound is that timeout plus one keeper round. The loss is
/// a redial and never a strike: the peer was there all along and comes back with nobody acting.
pub(crate) fn a_silent_pair_without_a_keep_alive_is_noticed_within_the_bound() -> Result<(), String>
{
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        // The shortest idle timeout the manager accepts, and no pings at all on either side.
        let idle = KEEPER_SETTLE + Duration::from_secs(1);
        let left = sim
            .machine()
            .map_err(io_error)?
            .with_idle_timeout(idle)
            .with_keep_alive(None);
        let right = sim
            .machine()
            .map_err(io_error)?
            .with_idle_timeout(idle)
            .with_keep_alive(None);
        let left_store = pair_records(&left, &right)?;
        let right_store = right.records();
        let managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        // Without a keep-alive nothing this machine sends would make a silent peer answer, so
        // the reading is unmeasured whatever the reader does, and the bound is the transport's
        // own idle timeout plus the one round that sees the close.
        let reading = managed_left.connections.vanish_bound();
        let Vanish::Unmeasured { bound: stated } = reading else {
            return Err(format!(
                "without a keep-alive the bound reads `{reading}`, not an unmeasured one"
            ));
        };
        if stated != idle + TRUST_POLL {
            return Err(format!(
                "without a keep-alive the bound is {stated:?}, not the idle timeout plus one \
                 round ({:?})",
                idle + TRUST_POLL
            ));
        }
        let keeper = spawn_keeper(&managed_left, &right);
        let first = wait_live(&sim, &managed_left.connections, &right.peer_id(), None).await?;
        // Neither machine says anything: the pair is quiet, as one behind an expired NAT
        // mapping is, and nothing but the transport's own timeout can notice. The keeper
        // re-dials at once when it does, so the signal is the first connection ending rather
        // than the pair being down.
        let mut spent = Duration::ZERO;
        loop {
            if first.close_reason().is_some() {
                break;
            }
            if spent >= stated {
                return Err(format!(
                    "a silent pair was still connected after {spent:?}, longer than the stated \
                     {stated:?}"
                ));
            }
            sim.clock().advance(Duration::from_secs(1)).await;
            sim.clock().settle().await;
            tokio::task::yield_now().await;
            spent += Duration::from_secs(1);
        }
        // The transport's timeout, not a goodbye: the peer was there the whole time.
        match first.close_reason() {
            Some(quinn::ConnectionError::TimedOut) => {}
            other => {
                return Err(format!(
                    "the silent connection ended as `{other:?}`, not from the transport's idle \
                     timeout"
                ));
            }
        }
        // A silence is a redial and not a strike: the episode is not used up, and the keeper
        // dials again with nobody acting.
        let state = managed_left.connections.recovery(&right.peer_id());
        if matches!(state, Recovery::Exhausted { .. }) {
            return Err(format!(
                "a silent pair was counted against: the pair reads `{state}`"
            ));
        }
        let second = wait_live(
            &sim,
            &managed_left.connections,
            &right.peer_id(),
            Some(first.stable_id()),
        )
        .await?;
        second
            .send_datagram(b"after the silence".as_slice().into())
            .map_err(|error| error.to_string())?;
        let there = managed_right
            .connections
            .live(&left.peer_id())
            .ok_or("the far side did not adopt the connection the keeper re-dialled")?;
        let received = within(&sim, Duration::from_secs(10), there.read_datagram())
            .await?
            .map_err(|error| error.to_string())?;
        if &received[..] != b"after the silence" {
            return Err(format!("the datagram arrived as {received:?}"));
        }
        keeper.abort();
        Ok(())
    })
}

/// A held connection that has stopped answering does not keep a working one out.
///
/// The state the case produces: the left dials the right and both sides adopt. Both machines
/// then move, as a laptop that changed networks and a peer that reconnected on a fresh port do,
/// and the peer gives its own copy of the connection up — but the close goes to the address the
/// left has left, so the left is never told. The held connection is silent but alive: past
/// [`VANISH_BOUND`] it has shown no sign of life and the transport has not declared it dead.
/// The peer then dials the left's new address, and `Connections::adopt` on both sides must
/// prefer the fresh connection over the silent one, which the tie-break alone — who started
/// what — would have kept.
///
/// The examined machine is the one with the smaller peer id, so the tie-break's preference is
/// the held connection's: a fresh dial that won by the tie-break could not prove this.
pub(crate) fn a_stale_connection_does_not_outrank_a_fresh_one() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let first_machine = sim.machine().map_err(io_error)?;
        let second_machine = sim.machine().map_err(io_error)?;
        let (left, right) = if first_machine.peer_id() < second_machine.peer_id() {
            (first_machine, second_machine)
        } else {
            (second_machine, first_machine)
        };
        // A long idle timeout, so the held connection is still open when the bound is crossed:
        // this case is about the liveness rule, not about the transport's own timeout.
        let left = left.with_idle_timeout(Duration::from_secs(120));
        let left_store = pair_records(&left, &right)?;
        let right_store = right.records();
        let managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        let first = within(
            &sim,
            Duration::from_secs(60),
            managed_left
                .connections
                .connect(&managed_left.endpoint, &right.fingerprint()),
        )
        .await?
        .map_err(|error| error.to_string())?;
        wait_live(&sim, &managed_left.connections, &right.peer_id(), None).await?;
        wait_live(&sim, &managed_right.connections, &left.peer_id(), None).await?;
        // The held connection is the one the tie-break prefers — this machine started it,
        // and it has the smaller peer id — so a fresh dial can win only by the liveness rule.
        if managed_left.connections.started_by(&right.peer_id()) != Some(Started::Here) {
            return Err("the held connection is not the one the tie-break prefers".to_owned());
        }
        // Both machines move. Nothing is delivered to the held connection's addresses from
        // here on, so nothing can revive it and the transport never sees it die.
        //
        // A second of quiet first, so the last datagram the peer sent is dated by the
        // manager's own reader rather than by the moment somebody happens to look: a reading
        // taken only when the fresh dial adopts would call the whole silence fresh, and the
        // rule would then depend on this machine's reading cadence instead of on the peer.
        sim.clock().advance(Duration::from_secs(1)).await;
        sim.link().silence(left.addr());
        // The left moves first: an address that was just freed must not be handed back to it,
        // or it would end up at the address the held connection is talking to.
        let moved = left.rebind_next();
        let fresh_addr = right.rebind_next();
        // The peer gives its own copy up — a reconnection — and the close goes to the address
        // this machine has left, so this machine is never told.
        if !managed_right.connections.disconnect(&left.peer_id()) {
            return Err("the peer held no connection to give up".to_owned());
        }
        // Past this machine's liveness bound: the held connection has shown no sign of life
        // for longer than the rule allows, and the transport has not declared it dead.
        for _ in 0..21 {
            sim.clock().advance(Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
        }
        // The held connection is silent but alive: the transport has not declared it dead.
        let held = managed_left
            .connections
            .live(&right.peer_id())
            .ok_or_else(|| {
                format!(
                    "the held connection timed out before the fresh dial arrived: it ended as `{:?}`",
                    first.close_reason()
                )
            })?;
        if held.stable_id() != first.stable_id() {
            return Err("the pair replaced its connection before the fresh dial".to_owned());
        }
        if held.close_reason().is_some() {
            return Err(format!(
                "the held connection was already closed as `{:?}`",
                held.close_reason()
            ));
        }
        // The peer dials the left's new address, over the same manager: on both sides the
        // held connection is the one it would keep by the tie-break.
        let fresh = within(
            &sim,
            Duration::from_secs(60),
            managed_right.connections.connect_with(
                &managed_right.endpoint,
                &left.fingerprint(),
                Some(moved),
            ),
        )
        .await?
        .map_err(|error| error.to_string())?;
        let kept = managed_left
            .connections
            .live(&right.peer_id())
            .ok_or("the left holds no connection after the peer dialled")?;
        if kept.stable_id() == first.stable_id() {
            return Err("the stale connection outranked the fresh one".to_owned());
        }
        if kept.remote_address() != fresh_addr {
            return Err(format!(
                "the kept connection reached {} instead of the fresh {fresh_addr}",
                kept.remote_address()
            ));
        }
        if managed_left.connections.started_by(&right.peer_id()) != Some(Started::There) {
            return Err(format!(
                "the kept connection was started {:?}, not by the peer that dialled",
                managed_left.connections.started_by(&right.peer_id())
            ));
        }
        if first.close_reason().is_none() {
            return Err("the stale connection was not superseded".to_owned());
        }
        // The fresh connection is the pair's path: a datagram from the peer crosses it.
        fresh
            .send_datagram(b"fresh".as_slice().into())
            .map_err(|error| error.to_string())?;
        let received = within(&sim, Duration::from_secs(10), kept.read_datagram())
            .await?
            .map_err(|error| error.to_string())?;
        if &received[..] != b"fresh" {
            return Err(format!("the datagram arrived as {received:?}"));
        }
        Ok(())
    })
}

/// A burst of half-finished handshakes does not stop the machine accepting a working one.
///
/// Eight strangers whose addresses are silenced start a handshake each with the left: their
/// Initials arrive, the left answers, and the answer never reaches them, so each handshake
/// stays unfinished at the left. The case asserts that the Initials and the left's unanswered
/// flights are in the trace — the burst really is in flight — and then that a properly paired
/// peer still connects and carries a datagram within a couple of seconds, which a serial
/// accept loop could not do: the first stalled handshake would hold the place for the whole
/// connect budget.
pub(crate) fn a_burst_of_stalled_handshakes_is_accepted() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right, left_store, right_store) = paired_machines(&sim)?;
        let managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        // Eight strangers, each with its own address silenced, so the server's flight never
        // reaches the client and the handshake stays half-finished.
        let mut stalled = Vec::new();
        let mut strangers: Vec<Machine> = Vec::new();
        for _ in 0..8 {
            let stranger = sim.machine().map_err(io_error)?;
            sim.link().silence(stranger.addr());
            let policy = TrustSet::default();
            policy.insert(left.fingerprint());
            let tls = mahbot_peers::tls::client_config(
                &stranger.identity,
                Arc::new(policy),
                mahbot_peers::tls::ALPN,
            )
            .map_err(|error| error.to_string())?;
            let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls))
                .map_err(|error| format!("the case's TLS configuration was refused: {error:?}"))?;
            let config = quinn::ClientConfig::new(Arc::new(crypto));
            let endpoint = stranger.endpoint().map_err(|error| error.to_string())?;
            let connecting = endpoint
                .connect_with(config, left.addr(), mahbot_peers::net::SERVER_NAME)
                .map_err(|error| error.to_string())?;
            stalled.push(connecting);
            strangers.push(stranger);
        }
        // A moment for the Initials to arrive and the left to answer each.
        sim.clock()
            .drive(Duration::from_millis(5), std::future::pending::<()>())
            .await;
        let trace = sim.link().trace();
        for stranger in &strangers {
            if !trace
                .iter()
                .any(|event| event.from == stranger.addr() && event.to == left.addr())
            {
                return Err(format!(
                    "the stalled client at {} sent no Initial",
                    stranger.addr()
                ));
            }
        }
        let unanswered = trace
            .iter()
            .filter(|event| {
                strangers.iter().any(|stranger| stranger.addr() == event.to) && !event.delivered()
            })
            .count();
        if unanswered < strangers.len() {
            return Err(format!(
                "the left answered {unanswered} of {} stalled handshakes, so the burst was not \
                 in flight",
                strangers.len()
            ));
        }
        // A paired peer dials while the burst is in flight: the accept loop is free.
        let keeper = spawn_keeper(&managed_left, &right);
        let live = within(&sim, Duration::from_secs(2), async {
            loop {
                if let Some(connection) = managed_left.connections.live(&right.peer_id()) {
                    return Ok::<_, String>(connection);
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(|_| {
            "a paired peer did not connect within two seconds of a burst of stalled handshakes"
                .to_owned()
        })??;
        live.send_datagram(b"accepted".as_slice().into())
            .map_err(|error| error.to_string())?;
        let there = managed_right
            .connections
            .live(&left.peer_id())
            .ok_or("the accepting side adopted no connection during the burst")?;
        let received = within(&sim, Duration::from_secs(2), there.read_datagram())
            .await
            .map_err(|_| "the datagram did not cross within two seconds of the burst".to_owned())?
            .map_err(|error| error.to_string())?;
        if &received[..] != b"accepted" {
            return Err(format!("the datagram arrived as {received:?}"));
        }
        keeper.abort();
        Ok(())
    })
}

/// A record the operating system cannot read defers the dial, and does not end the pair.
///
/// The records directory is replaced by a regular file, so every record read under this root
/// fails the way an operating-system fault does — the bytes are not seen at all, rather than a
/// file being refused. The manager classifies the fault as one that may pass, and the answer it
/// reports is [`ConnectFailure::Deferred`] rather than a record that is insecure or malformed.
/// Nothing is decided about the peer — the file is one a person must repair, and until they do
/// the dial is deferred by one keeper round. The keeper therefore keeps running, the dial count
/// does not advance (a deferred dial is not counted, so a fault that lasts an hour does not use
/// up an episode), and a caller that dials anyway still gets the fail-closed answer, with the
/// record's own fault in it.
///
/// A pair whose last dial met a network failure keeps that reason through the same fault: the
/// state still names it, and the answer a caller gets names the same reason rather than the
/// fault — asked of the policy for one dial, or dialled once — so the deferral never stands in
/// for the reason the pair is down for.
#[cfg(unix)]
pub(crate) fn a_transient_record_fault_defers_the_dial() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right, left_store, _right_store) = paired_machines(&sim)?;
        let record = left
            .storage()
            .record_name(&right.peer_id())
            .map_err(io_error)?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        // Every record read under the root meets an operating-system fault: unreadable, not
        // insecure and not malformed.
        let hidden = left.storage().hide_records_dir().map_err(io_error)?;
        // The answer is a deferral, not a refusal: the fault is this machine's, and nothing is
        // decided about the peer.
        match within(
            &sim,
            Duration::from_secs(60),
            managed_left
                .connections
                .connect(&managed_left.endpoint, &right.fingerprint()),
        )
        .await?
        {
            Err(ConnectFailure::Deferred { peer, detail }) => {
                if peer != right.fingerprint() {
                    return Err(format!(
                        "a deferred dial names {peer}, not the peer that was dialled"
                    ));
                }
                if !detail.contains(&record) {
                    return Err(format!("the deferral does not name the record: {detail}"));
                }
            }
            other => {
                return Err(format!(
                    "a record the OS refused was reported as {other:?}, not as deferred"
                ));
            }
        }
        // The keeper runs, and every round defers rather than counting a failure.
        let keeper = spawn_keeper(&managed_left, &right);
        let mut dials = Vec::new();
        for _ in 0..4 {
            sim.clock().advance(TRUST_POLL).await;
            tokio::task::yield_now().await;
            let state = managed_left.connections.recovery(&right.peer_id());
            // The sentence a person reads names this machine's own fault: never a trust decision,
            // and never a dial that did not happen. `Deferred` is the outcome's name, not a word
            // its sentence uses: what is put off is a reading, and the words say what it is.
            let words = state.to_string();
            if words.contains("not trusted") || words.contains("deferred") {
                return Err(format!("a deferred wait's sentence reads `{words}`"));
            }
            let Recovery::Waiting {
                dial,
                last: Some(ConnectFailure::Deferred { detail, .. }),
                ..
            } = state
            else {
                return Err(format!(
                    "a deferred dial reads `{state}`, not a wait after an unreadable record"
                ));
            };
            if !detail.contains(&record) {
                return Err(format!(
                    "the deferred state does not name the record: {detail}"
                ));
            }
            dials.push(dial);
        }
        if keeper.is_finished() {
            let end = keeper.await.map_err(|error| error.to_string())?;
            return Err(format!(
                "the keeper stopped on a record the OS refused: {end}"
            ));
        }
        let [first, .., last] = &dials[..] else {
            return Err("the case observed no dial".to_owned());
        };
        if first != last || *last >= RECOVERY_DIALS {
            return Err(format!(
                "the deferred dial was counted: {dials:?}, with {RECOVERY_DIALS} using up an \
                 episode"
            ));
        }
        keeper.abort();
        // A deferral over a pair whose last dial met something else keeps that reason, in the
        // state and in the answer: the fault is this machine's and does not replace what the
        // network said. The records are readable again, so the keeper's next dial is a real one
        // and the far side — which serves nothing — gives it a failure of its own.
        hidden.restore().map_err(io_error)?;
        let dialling = spawn_keeper(&managed_left, &right);
        let mut real = None;
        drive_until(&sim, Duration::from_secs(120), || {
            let state = managed_left.connections.recovery(&right.peer_id());
            match &state {
                Recovery::Waiting {
                    last: Some(last), ..
                } if !matches!(last, ConnectFailure::Deferred { .. }) => {
                    real = Some(last.clone());
                    Ok(())
                }
                _ => Err(format!(
                    "the pair's first real dial has not failed yet: it reads `{state}`"
                )),
            }
        })
        .await?;
        let Some(real) = real else {
            return Err("the pair never named the failure its first real dial met".to_owned());
        };
        dialling.abort();
        // The fault returns before the next dial is due, and a caller asks for one. The state
        // keeps the reason the last dial met, and the answer is that reason: a deferral over a
        // pair that has already dialled is not a reason of its own, and a caller is never told
        // "deferred" while the state says something else.
        let hidden = left.storage().hide_records_dir().map_err(io_error)?;
        sim.clock().advance(TRUST_POLL).await;
        let (state, named) = managed_left
            .connections
            .ensure(&managed_left.endpoint, &right.fingerprint())
            .await;
        let state_last = match &state {
            Recovery::Waiting { last, .. } => last.clone(),
            Recovery::Exhausted { last, .. } => Some(last.clone()),
            _ => None,
        };
        if state_last.as_ref() != Some(&real) {
            return Err(format!(
                "a local record fault replaced the reason the last dial met: the state reads \
                 `{state}`, not `{real}`"
            ));
        }
        // The ask really did read the record — a caller that did not ask it is answered
        // nothing — and the answer is the state's own reason, not the fault it met.
        if named.as_ref() != Some(&real) {
            return Err(format!(
                "the ask was deferred, but the answer names `{named:?}` while the state reads \
                 `{state}`"
            ));
        }
        // The deferral moved the wait on, and to a short one: a fault that counted as a failed
        // dial would park the pair for the slow re-check instead.
        let moved = match &state {
            Recovery::Waiting { until, .. } => until.saturating_duration_since(sim.clock().now()),
            _ => Duration::ZERO,
        };
        if moved.is_zero() || moved >= RECOVERY_RECHECK {
            return Err(format!(
                "the ask left a {moved:?} wait, not the short one a deferral earns: the state \
                 reads `{state}`"
            ));
        }
        // A one-shot dial over the same pair is answered the same way: it meets the same fault,
        // and it reports the reason the state names rather than the fault. A caller that dialled
        // once is never told "deferred" while the state says something else.
        match managed_left
            .connections
            .connect(&managed_left.endpoint, &right.fingerprint())
            .await
        {
            Err(named) if named == real => {}
            other => {
                return Err(format!(
                    "a one-shot dial under a record fault was answered `{other:?}`, not \
                     `{real}`: the answer is not the reason the pair is down"
                ));
            }
        }
        hidden.restore().map_err(io_error)?;
        Ok(())
    })
}

/// The same record fault while a connection is up is a deferral, not a refusal.
///
/// The records directory is replaced by a regular file, so every record read fails the way an
/// operating-system fault does on a unix host, and the left's keeper asks it every round. A dial a
/// caller asks for anyway is answered [`ConnectFailure::Deferred`] naming the record, and that
/// answer tears nothing down: the pair still holds the same connection. The keeper's own rounds
/// defer too — nothing is trusted on a file nobody could read, and nothing is torn down for it
/// either — so the connection stays the one the pair holds and still carries, the state names
/// no stop, and the keeper goes on asking. A terminal refusal would have closed the connection
/// and returned `StopCause::NotTrusted`. Once the records directory is back the pair is still
/// connected and still carries.
#[cfg(unix)]
pub(crate) fn a_transient_record_fault_keeps_the_connection() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right, left_store, right_store) = paired_machines(&sim)?;
        let record = left
            .storage()
            .record_name(&right.peer_id())
            .map_err(io_error)?;
        let managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        let keeper = spawn_keeper(&managed_left, &right);
        let first = wait_live(&sim, &managed_left.connections, &right.peer_id(), None).await?;
        // Every record read under the left's root meets an operating-system fault.
        let hidden = left.storage().hide_records_dir().map_err(io_error)?;
        // The read really is failing, and it is the transient fault: a dial asked for anyway
        // fails closed with the record's own fault, so the connection below is kept despite a
        // fault the manager has seen, not because nothing was asked.
        match within(
            &sim,
            Duration::from_secs(10),
            managed_left
                .connections
                .connect(&managed_left.endpoint, &right.fingerprint()),
        )
        .await?
        {
            Err(ConnectFailure::Deferred { detail, .. }) => {
                if !detail.contains(&record) {
                    return Err(format!("the deferral does not name the record: {detail}"));
                }
            }
            other => {
                return Err(format!(
                    "a record the OS refused was reported as {other:?} while the pair was \
                     connected"
                ));
            }
        }
        // The answer tore nothing down: the pair still holds the connection it had.
        let held = managed_left
            .connections
            .live(&right.peer_id())
            .ok_or("the answer to a dial tore the live connection down")?;
        if held.stable_id() != first.stable_id() {
            return Err(format!(
                "the answer to a dial replaced the pair's connection ({} for {})",
                held.stable_id(),
                first.stable_id()
            ));
        }
        // The keeper's own rounds read the record too, and none of them concludes anything: the
        // pair is never stopped, the connection stays the one the pair holds, and the keeper goes
        // on asking.
        for _ in 0..4 {
            sim.clock().advance(TRUST_POLL).await;
            tokio::task::yield_now().await;
            let state = managed_left.connections.recovery(&right.peer_id());
            if matches!(state, Recovery::Stopped { .. }) {
                return Err(format!(
                    "a deferred fault stopped the pair: it reads `{state}`"
                ));
            }
        }
        let live = managed_left
            .connections
            .live(&right.peer_id())
            .ok_or("a record the OS refused tore the live connection down")?;
        if live.stable_id() != first.stable_id() {
            return Err(format!(
                "the pair replaced its connection ({} for {}) on a local record fault",
                live.stable_id(),
                first.stable_id()
            ));
        }
        live.send_datagram(b"still here".as_slice().into())
            .map_err(|error| error.to_string())?;
        let there = managed_right
            .connections
            .live(&left.peer_id())
            .ok_or("the far side lost its connection on a local record fault")?;
        let received = within(&sim, Duration::from_secs(10), there.read_datagram())
            .await?
            .map_err(|error| error.to_string())?;
        if &received[..] != b"still here" {
            return Err(format!("the datagram arrived as {received:?}"));
        }
        // A refusal would have ended the keeper; a deferral leaves it asking every round.
        if keeper.is_finished() {
            let end = keeper.await.map_err(|error| error.to_string())?;
            return Err(format!(
                "the keeper stopped on a record the OS refused while the pair was connected: {end}"
            ));
        }
        // The record is readable again: the pair is still connected on the connection it held,
        // and still carries, with nobody acting.
        hidden.restore().map_err(io_error)?;
        let after = managed_left
            .connections
            .live(&right.peer_id())
            .ok_or("the pair lost its connection after the record was readable again")?;
        if after.stable_id() != first.stable_id() {
            return Err(format!(
                "the pair replaced its connection once the record was readable ({} for {})",
                after.stable_id(),
                first.stable_id()
            ));
        }
        after
            .send_datagram(b"after the fault".as_slice().into())
            .map_err(|error| error.to_string())?;
        let there = managed_right
            .connections
            .live(&left.peer_id())
            .ok_or("the far side lost its connection once the record was readable again")?;
        let received = within(&sim, Duration::from_secs(10), there.read_datagram())
            .await?
            .map_err(|error| error.to_string())?;
        if &received[..] != b"after the fault" {
            return Err(format!("the datagram arrived as {received:?}"));
        }
        keeper.abort();
        Ok(())
    })
}

/// How far the clock is moved between two samples of a state that only changes with time.
///
/// The retry policy's shortest gap is a second, and the states a case samples last at
/// least that long, so a step this size sees each of them without spending the case's poll
/// budget on one poll per instant.
const SAMPLE: Duration = Duration::from_millis(200);

/// Move the clock in [`SAMPLE`] steps until `done` answers, or fail with what it last
/// observed once `budget` of virtual time is spent.
///
/// A run of dials takes minutes of virtual time, and [`within`] would spend the case's
/// poll budget driving every 10 ms of it; a case that only samples between advances asks
/// here.
async fn drive_until(
    sim: &Sim,
    budget: Duration,
    mut done: impl FnMut() -> Result<(), String>,
) -> Result<(), String> {
    let mut spent = Duration::ZERO;
    loop {
        let observed = match done() {
            Ok(()) => return Ok(()),
            Err(observed) => observed,
        };
        if spent >= budget {
            return Err(format!("{observed}, {spent:?} of virtual time later"));
        }
        sim.clock().advance(SAMPLE).await;
        tokio::task::yield_now().await;
        spent += SAMPLE;
    }
}

/// The pair's recovery is readable at any time, and it names each thing it is doing: the
/// dial in flight, the wait before the next one with the moment it is due, and the episode
/// used up with its stated re-check. The gap between dials doubles from
/// [`RECOVERY_FIRST_GAP`] — 1, 2, 4, 8 and 16 seconds for the episode's dials — and a peer
/// that comes back is then found again by the keeper's own re-check, with nobody dialling.
///
/// The far side is paired and never runs: its remembered address answers nothing and the
/// beacon holds no registration for it, so every dial meets `PeerUnknown` — the honest
/// failure for a machine that is not there, not a silence.
pub(crate) fn the_recovery_state_is_readable() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right, left_store, right_store) = paired_machines(&sim)?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        // No keeper has run for the pair, and the state says exactly that.
        let untouched = managed_left.connections.recovery(&right.peer_id());
        if untouched != Recovery::Unwatched {
            return Err(format!(
                "a pair no keeper has run for reads `{untouched}`, not unwatched"
            ));
        }
        let keeper = spawn_keeper(&managed_left, &right);
        // Sample the episode while it runs: the dial in flight, the wait after it with the
        // moment the next one is due, and the count growing.
        let mut saw_dialling = false;
        let mut saw_waiting = false;
        let mut wait_ahead = false;
        let mut counts: Vec<u32> = Vec::new();
        // The wait after each dial, as first sampled: the gap doubles from the first one.
        let mut gaps: Vec<(u32, Duration)> = Vec::new();
        let mut spent = Duration::ZERO;
        let exhausted = loop {
            let state = managed_left.connections.recovery(&right.peer_id());
            match &state {
                Recovery::Dialling { dial } => {
                    saw_dialling = true;
                    counts.push(*dial);
                }
                Recovery::Waiting {
                    until,
                    dial,
                    last: Some(failure),
                } => {
                    if !matches!(failure, ConnectFailure::PeerUnknown { .. }) {
                        return Err(format!(
                            "a dial to a machine that never ran met `{failure}`"
                        ));
                    }
                    saw_waiting = true;
                    if *until > sim.clock().now() {
                        wait_ahead = true;
                    }
                    counts.push(*dial);
                    if *dial >= 1 && !gaps.iter().any(|(seen, _)| seen == dial) {
                        gaps.push((*dial, until.saturating_duration_since(sim.clock().now())));
                    }
                }
                Recovery::Exhausted { .. } => break state,
                Recovery::Connected => {
                    return Err("the pair connected to a machine that never ran".to_owned());
                }
                _ => {}
            }
            if spent >= Duration::from_secs(600) {
                return Err(format!(
                    "the episode was never used up: the pair reads `{state}` after {spent:?}"
                ));
            }
            sim.clock().advance(SAMPLE).await;
            tokio::task::yield_now().await;
            spent += SAMPLE;
        };
        if !saw_dialling {
            return Err("the state never named the dial in flight".to_owned());
        }
        if !saw_waiting {
            return Err("the state never named the wait after a failed dial".to_owned());
        }
        if !wait_ahead {
            return Err("a wait named a moment that was not in the future".to_owned());
        }
        let (first, last) = match (counts.first(), counts.last()) {
            (Some(first), Some(last)) => (*first, *last),
            _ => return Err("the state named no dial at all".to_owned()),
        };
        if counts.windows(2).any(|pair| pair[1] < pair[0]) {
            return Err(format!("the dial count went backwards: {counts:?}"));
        }
        if last <= first {
            return Err(format!(
                "the dial count did not grow: it reads {first} and then {last}"
            ));
        }
        // The gap doubles from one second to sixteen: dials one to five of the episode wait
        // 1, 2, 4, 8 and 16 seconds, and there is no cap below the episode's own end. Each is
        // measured from the sample that first saw the wait, so it reads at most one sample
        // short of the gap the policy set.
        for dial in 1..RECOVERY_DIALS {
            let expected = RECOVERY_FIRST_GAP * (1 << (dial - 1));
            let Some((_, gap)) = gaps.iter().find(|(seen, _)| *seen == dial) else {
                return Err(format!(
                    "the wait after dial {dial} was never sampled: the pair named {gaps:?}"
                ));
            };
            if !(*gap > expected - SAMPLE && *gap <= expected) {
                return Err(format!(
                    "the wait after dial {dial} reads {gap:?}, not about {expected:?}"
                ));
            }
        }
        let Recovery::Exhausted {
            until,
            dials,
            last: failure,
        } = &exhausted
        else {
            return Err(format!(
                "the pair reads `{exhausted}`, not an episode used up"
            ));
        };
        if *dials != RECOVERY_DIALS {
            return Err(format!(
                "the episode was used up after {dials} dials, not {RECOVERY_DIALS}"
            ));
        }
        if !matches!(failure, ConnectFailure::PeerUnknown { .. }) {
            return Err(format!(
                "the used-up episode names `{failure}`, not the peer the beacon does not know"
            ));
        }
        // The wait is the slow re-check, not the next gap of a run of dials: longer than every
        // gap this episode's own dials earned, and no longer than the stated bound. The state is
        // sampled every `SAMPLE`, so the wait observed is at most one sample short.
        let wait = until.saturating_duration_since(sim.clock().now());
        let longest = gaps.iter().map(|(_, gap)| *gap).max().unwrap_or_default();
        if wait <= longest || wait > RECOVERY_RECHECK {
            return Err(format!(
                "the pair waits {wait:?} after its episode, not the slow re-check: its longest \
                 gap was {longest:?} and the bound is {RECOVERY_RECHECK:?}"
            ));
        }
        let words = exhausted.to_string();
        if !words.contains("not connected") || !words.contains("the episode is used up") {
            return Err(format!("a used-up episode reads `{words}`"));
        }
        if words.contains("next") || words.contains("re-check") {
            return Err(format!(
                "a used-up episode predicts its next dial: `{words}`"
            ));
        }
        // Bounded, and not finished: the keeper still runs for the pair.
        if keeper.is_finished() {
            return Err("the keeper stopped when the episode was used up".to_owned());
        }
        // The peer comes back and nobody dials: the keeper's own re-check finds it.
        let _managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        drive_until(&sim, RECOVERY_RECHECK + Duration::from_secs(30), || {
            let state = managed_left.connections.recovery(&right.peer_id());
            if state == Recovery::Connected {
                Ok(())
            } else {
                Err(format!(
                    "the pair did not come back after its peer did: it reads `{state}`"
                ))
            }
        })
        .await?;
        keeper.abort();
        Ok(())
    })
}

/// A pair with no beacon and no remembered address stops the keeper with `Nowhere` and
/// dials nothing: there is nowhere to dial, which is configuration rather than a network
/// state that can pass.
///
/// The two records hold the comparison and no address, as a pairing made over a link that
/// carried no address does, and the manager is built without a beacon.
pub(crate) fn nowhere_to_dial_stops_the_keeper() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let left = sim.machine().map_err(io_error)?;
        let right = sim.machine().map_err(io_error)?;
        let left_store = left.records();
        let right_store = right.records();
        for (store, peer) in [
            (&left_store, right.peer_id()),
            (&right_store, left.peer_id()),
        ] {
            store
                .record_pairing(&peer, NOW)
                .map_err(|error| error.to_string())?;
        }
        // No beacon is configured, so the record is the only place an address could come
        // from — and it holds none.
        let connections = Connections::new(
            &left.identity,
            left_store.clone(),
            None,
            sim.clock().runtime(),
            &left.transport,
        )
        .map_err(|error| error.to_string())?;
        let endpoint = left.endpoint().map_err(|error| error.to_string())?;
        let mark = sim.link().trace().len();
        let end = within(
            &sim,
            Duration::from_secs(10),
            connections.keep_connected(&endpoint, &right.fingerprint()),
        )
        .await?;
        match &end {
            StopCause::Nowhere => {}
            other => {
                return Err(format!(
                    "the keeper ended `{other}`, not a stop with nowhere to dial"
                ));
            }
        }
        match connections.recovery(&right.peer_id()) {
            Recovery::Stopped {
                cause: StopCause::Nowhere,
            } => {}
            other => {
                return Err(format!(
                    "a pair with nowhere to dial reads `{other}`, not a stop"
                ));
            }
        }
        // A direct dial of a pair with nowhere to go answers that failure itself, and does not
        // silently un-stop the pair.
        match connections.connect(&endpoint, &right.fingerprint()).await {
            Err(ConnectFailure::Nowhere { peer }) if peer == right.fingerprint() => {}
            Err(other) => {
                return Err(format!(
                    "a direct connect to a pair with nowhere to dial answered `{other}`"
                ));
            }
            Ok(_) => {
                return Err("a direct connect to a pair with nowhere to dial connected".to_owned());
            }
        }
        match connections.recovery(&right.peer_id()) {
            Recovery::Stopped {
                cause: StopCause::Nowhere,
            } => {}
            other => {
                return Err(format!(
                    "a direct connect left the pair reading `{other}`, not a stop"
                ));
            }
        }
        // A service asking for one delivery is answered the stop and no dial, and the stop
        // stays in place: nothing has changed the cause. The answer names the cause whether the
        // stop was written by this call or found by it, so a caller is never told only that
        // nothing happened.
        let (state, failure) = connections.ensure(&endpoint, &right.fingerprint()).await;
        if !matches!(
            state,
            Recovery::Stopped {
                cause: StopCause::Nowhere
            }
        ) {
            return Err(format!(
                "ensure on a pair with nowhere to dial answered `{state}`, not the stop"
            ));
        }
        match failure {
            Some(ConnectFailure::Nowhere { peer }) if peer == right.fingerprint() => {}
            other => {
                return Err(format!(
                    "ensure on a pair with nowhere to dial reported `{other:?}`, not the stop's \
                     own cause"
                ));
            }
        }
        match connections.recovery(&right.peer_id()) {
            Recovery::Stopped {
                cause: StopCause::Nowhere,
            } => {}
            other => {
                return Err(format!(
                    "ensure left the pair reading `{other}`, not the stop in place"
                ));
            }
        }
        // A person's action asked for on that pair answers the same failure: nothing will
        // dial it, and "nowhere to dial" is what a person needs to see rather than a bare
        // "nothing was ready".
        let messaging = crate::messages::Messaging::open(&sim, &left, Arc::new(NoFloor))
            .map_err(|error| error.to_string())?;
        let asked = messaging
            .actions
            .request(
                &connections,
                &endpoint,
                &right.peer_id(),
                ActionId::from_bytes([7u8; 16]),
                ActionKind::COMMAND,
                b"a command",
            )
            .await;
        match asked {
            Err(ActionError::Connect(ConnectFailure::Nowhere { peer }))
                if peer == right.fingerprint() => {}
            other => {
                return Err(format!(
                    "an action to a pair with nowhere to dial was answered `{other:?}`, not the \
                     same failure"
                ));
            }
        }
        // Nothing was dialled: the record answered no address and there is no beacon to ask.
        let trace = sim.link().trace();
        if let Some(event) = trace[mark..]
            .iter()
            .find(|event| event.from == left.addr() && event.to == right.addr())
        {
            return Err(format!(
                "a pair with nowhere to dial sent {} -> {} anyway",
                event.from, event.to
            ));
        }
        // A service path that meets the same state makes the same stop rather than counting it
        // as a failed dial: a manager no keeper has run for dials once, finds nothing to dial,
        // and stops with the reason. A second ask is answered the stop and dials nothing.
        let fresh = Connections::new(
            &left.identity,
            left_store.clone(),
            None,
            sim.clock().runtime(),
            &left.transport,
        )
        .map_err(|error| error.to_string())?;
        let mark = sim.link().trace().len();
        let (state, failure) = fresh.ensure(&endpoint, &right.fingerprint()).await;
        if !matches!(
            state,
            Recovery::Stopped {
                cause: StopCause::Nowhere
            }
        ) {
            return Err(format!(
                "a service's first dial with nowhere to go left the pair reading `{state}`, not \
                 the stop"
            ));
        }
        match failure {
            Some(ConnectFailure::Nowhere { peer }) if peer == right.fingerprint() => {}
            other => {
                return Err(format!(
                    "a service's first dial with nowhere to go reported `{other:?}`, not the \
                     same failure"
                ));
            }
        }
        // A second ask inside the same round is answered from the policy — a stop's cause is
        // re-asked at most once a round — and it still names the cause and dials nothing.
        let (again, failure) = fresh.ensure(&endpoint, &right.fingerprint()).await;
        if !matches!(
            again,
            Recovery::Stopped {
                cause: StopCause::Nowhere
            }
        ) || !matches!(failure, Some(ConnectFailure::Nowhere { .. }))
        {
            return Err(format!(
                "a second ask on a stopped pair answered `{again}` / `{failure:?}`, not the stop \
                 with no dial"
            ));
        }
        if sim.link().trace()[mark..]
            .iter()
            .any(|event| event.from == left.addr() && event.to == right.addr())
        {
            return Err("a pair with nowhere to dial was dialled anyway".to_owned());
        }
        Ok(())
    })
}

/// A stop that outlives the proof of an address is the pair dead for good, and that is what
/// the retry policy exists to prevent: a hint that reaches the peer, and an address the peer's
/// own connection taught the record, both re-open a pair that had nowhere to dial.
///
/// The state the case produces: two paired machines, no beacon anywhere, and a record that
/// remembers no address — so the left's keeper stops with [`StopCause::Nowhere`]. The left then
/// dials with a hint, which is somewhere to dial and re-opens the stop. The hinted address is
/// not written to the record (it is self-asserted), so the left has nowhere to go again once
/// that connection is gone and stops again — and this time the right dials in, which teaches
/// the left's record a real address and re-opens the stop for good: a keeper the caller starts
/// afterwards brings the pair up with nobody supplying an address.
pub(crate) fn a_learned_address_reopens_a_stop() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let left = sim.machine().map_err(io_error)?;
        let right = sim.machine().map_err(io_error)?;
        let left_store = left.records();
        let right_store = right.records();
        for (store, peer) in [
            (&left_store, right.peer_id()),
            (&right_store, left.peer_id()),
        ] {
            store
                .record_pairing(&peer, NOW)
                .map_err(|error| error.to_string())?;
        }
        // No beacon is configured on either side, so the record is the only place an address
        // could come from — and neither record holds one.
        let left_manager = Arc::new(
            Connections::new(
                &left.identity,
                left_store.clone(),
                None,
                sim.clock().runtime(),
                &left.transport,
            )
            .map_err(|error| error.to_string())?,
        );
        let right_manager = Arc::new(
            Connections::new(
                &right.identity,
                right_store,
                None,
                sim.clock().runtime(),
                &right.transport,
            )
            .map_err(|error| error.to_string())?,
        );
        let left_endpoint = left.endpoint().map_err(|error| error.to_string())?;
        let right_endpoint = right.endpoint().map_err(|error| error.to_string())?;
        let left_accept = tokio::spawn(Arc::clone(&left_manager).serve(left_endpoint.clone()));
        let right_accept = tokio::spawn(Arc::clone(&right_manager).serve(right_endpoint.clone()));
        // The keeper stops: nowhere to dial.
        let end = within(
            &sim,
            Duration::from_secs(10),
            left_manager.keep_connected(&left_endpoint, &right.fingerprint()),
        )
        .await?;
        if !matches!(end, StopCause::Nowhere) {
            return Err(format!(
                "the keeper ended `{end}`, not a stop with nowhere to dial"
            ));
        }
        // A hint that reaches the peer is somewhere to dial: the stop is open again. The state
        // is read with the connection gone, because a live pair answers `Connected` whatever
        // the policy says, and a stop that is still there afterwards is one nothing re-opened.
        left_manager
            .connect_with(&left_endpoint, &right.fingerprint(), Some(right.addr()))
            .await
            .map_err(|error| format!("a hinted dial to a reachable peer failed: {error}"))?;
        wait_live(&sim, &right_manager, &left.peer_id(), None).await?;
        left_manager.disconnect(&right.peer_id());
        sim.clock().advance(KEEPER_SETTLE + TRUST_POLL).await;
        if matches!(
            left_manager.recovery(&right.peer_id()),
            Recovery::Stopped { .. }
        ) {
            return Err(
                "the stop came back once the hinted connection went: a hint that reached \
                        the peer is an address"
                    .to_owned(),
            );
        }
        // The hint is not the record's: with that connection gone the left has nowhere to go
        // again, and stops again.
        let (state, failure) = left_manager
            .ensure(&left_endpoint, &right.fingerprint())
            .await;
        if !matches!(
            state,
            Recovery::Stopped {
                cause: StopCause::Nowhere
            }
        ) || !matches!(failure, Some(ConnectFailure::Nowhere { .. }))
        {
            return Err(format!(
                "after a hinted connection went, the pair read `{state}` / `{failure:?}`, not a \
                 stop with nowhere to dial"
            ));
        }
        // The right learned the left's address from accepting, so its dial reaches the left —
        // and the left's record learns the right's address from that connection. The stop has
        // no cause left.
        right_manager
            .connect(&right_endpoint, &left.fingerprint())
            .await
            .map_err(|error| format!("the right could not dial the left: {error}"))?;
        wait_live(&sim, &left_manager, &right.peer_id(), None).await?;
        // And the stop does not come back once that connection goes: the address it taught the
        // record is the pair's, so there is somewhere to dial again. This is the read that
        // shows the inbound connection re-opened the stop — while it was live the answer would
        // have been `Connected` whatever the policy said.
        left_manager.disconnect(&right.peer_id());
        sim.clock().advance(KEEPER_SETTLE + TRUST_POLL).await;
        if matches!(
            left_manager.recovery(&right.peer_id()),
            Recovery::Stopped { .. }
        ) {
            return Err("a stop came back once the inbound connection went".to_owned());
        }
        // The record is rebuilt without an address, as a restored backup that predates one
        // leaves it, and the pair has nowhere to dial again.
        left.storage()
            .remove_record(&right.peer_id())
            .map_err(io_error)?;
        left.reopen_records()
            .map_err(|error| error.to_string())?
            .record_pairing(&right.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        left_manager.disconnect(&right.peer_id());
        sim.clock().advance(KEEPER_SETTLE + TRUST_POLL).await;
        let (state, _) = left_manager
            .ensure(&left_endpoint, &right.fingerprint())
            .await;
        if !matches!(
            state,
            Recovery::Stopped {
                cause: StopCause::Nowhere
            }
        ) {
            return Err(format!(
                "a record rebuilt without an address left the pair reading `{state}`, not a stop \
                 with nowhere to dial"
            ));
        }
        // An address another handle writes to the same root is a real address: the stop has no
        // cause left, and the ask after that must find it in the file rather than in a cached
        // record. The store the manager holds is a different handle from this one, so nothing
        // but the read can tell it. A stop's cause is re-asked once a round, so the clock moves
        // one on.
        left.reopen_records()
            .map_err(|error| error.to_string())?
            .record_address(&right.peer_id(), right.addr())
            .map_err(|error| error.to_string())?;
        sim.clock().advance(TRUST_POLL).await;
        let (state, failure) = left_manager
            .ensure(&left_endpoint, &right.fingerprint())
            .await;
        if failure.is_some() || state != Recovery::Connected {
            return Err(format!(
                "an address written by another handle did not re-open the stop: the pair read \
                 `{state}` / `{failure:?}`"
            ));
        }
        // And it is a real address, not the moment: a keeper started now brings the pair up
        // with nobody handing it one.
        left_manager.disconnect(&right.peer_id());
        right_manager.disconnect(&left.peer_id());
        sim.clock().advance(KEEPER_SETTLE + TRUST_POLL).await;
        let keeper = tokio::spawn({
            let connections = Arc::clone(&left_manager);
            let endpoint = left_endpoint.clone();
            let peer = right.fingerprint();
            async move { connections.keep_connected(&endpoint, &peer).await }
        });
        wait_live(&sim, &left_manager, &right.peer_id(), None).await?;
        keeper.abort();
        left_accept.abort();
        right_accept.abort();
        left_endpoint.close(0u32.into(), b"the case is done");
        right_endpoint.close(0u32.into(), b"the case is done");
        Ok(())
    })
}

/// A pair this machine does not trust is never retried: the keeper closes what is live and
/// stops naming the withdrawal, the state reads `Stopped` with the same cause, and no
/// re-check of any length puts a datagram back on the wire.
pub(crate) fn a_withdrawn_pair_is_never_retried() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right, left_store, right_store) = paired_machines(&sim)?;
        let _managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        let keeper = spawn_keeper(&managed_left, &right);
        wait_live(&sim, &managed_left.connections, &right.peer_id(), None).await?;
        // A person on the left withdraws the machine it is connected to.
        left.rights()?
            .withdraw_trust(&right.peer_id(), person("egor")?, NOW)
            .map_err(|error| error.to_string())?;
        // The keeper closes what is live and stops, naming the withdrawal rather than a
        // lost path.
        let end = within(&sim, Duration::from_secs(120), keeper)
            .await?
            .map_err(|error| format!("the keeper's task did not finish: {error}"))?;
        match &end {
            StopCause::NotTrusted(NotTrustedCause::Withdrawn) => {}
            other => {
                return Err(format!(
                    "the keeper ended `{other}`, not a refusal naming the withdrawal"
                ));
            }
        }
        if managed_left.connections.live(&right.peer_id()).is_some() {
            return Err("the withdrawn pair still has a live connection".to_owned());
        }
        match managed_left.connections.recovery(&right.peer_id()) {
            Recovery::Stopped {
                cause: StopCause::NotTrusted(NotTrustedCause::Withdrawn),
            } => {}
            other => {
                return Err(format!(
                    "a withdrawn pair's recovery reads `{other}`, not a stop naming the \
                     withdrawal"
                ));
            }
        }
        // A stop's cause is taken from the record the ask just read, not from the state's
        // memory of it: the record this stop named is removed — a restored backup or a
        // deleted file does that — and the next ask must answer, and store, the cause the
        // file now gives, so the answer and the readable state cannot name two reasons.
        left.storage()
            .remove_record(&right.peer_id())
            .map_err(io_error)?;
        sim.clock().advance(TRUST_POLL).await;
        let (state, failure) = managed_left
            .connections
            .ensure(&managed_left.endpoint, &right.fingerprint())
            .await;
        if !matches!(
            failure,
            Some(ConnectFailure::NotTrusted {
                cause: NotTrustedCause::NoRecord,
                ..
            })
        ) {
            return Err(format!(
                "a stop whose record was removed was answered `{failure:?}`, not the cause the \
                 file now gives"
            ));
        }
        if !matches!(
            state,
            Recovery::Stopped {
                cause: StopCause::NotTrusted(NotTrustedCause::NoRecord)
            }
        ) {
            return Err(format!(
                "the answer named one cause and the readable state `{state}` another"
            ));
        }
        // The close is flushed and its retransmissions are done before the mark: from here
        // nothing this machine sends may be aimed at the peer again.
        sim.clock().advance(2 * RECOVERY_RECHECK).await;
        tokio::task::yield_now().await;
        let mark = sim.link().trace().len();
        for _ in 0..3 {
            sim.clock().advance(RECOVERY_RECHECK).await;
            tokio::task::yield_now().await;
        }
        let trace = sim.link().trace();
        if let Some(event) = trace[mark..]
            .iter()
            .find(|event| event.from == left.addr() && event.to == right.addr())
        {
            return Err(format!(
                "a withdrawn pair was dialled again: {} -> {}",
                event.from, event.to
            ));
        }
        Ok(())
    })
}

/// A service's dial to a pair this machine does not trust is answered with the refusal, the
/// pair is stopped naming the same cause, and a trust a person restores is dialled by the next
/// call rather than refused for ever.
///
/// The state the case produces: a person withdraws this machine's trust in the peer, a
/// service with something to deliver asks for a dial, and the ask is answered
/// [`ConnectFailure::NotTrusted`] with the withdrawal as its cause while the pair's readable
/// state is [`Recovery::Stopped`] with that same cause — one reason, not two. The person then
/// restores trust, and the same call re-opens the stop and dials: the pair becomes live and
/// carries a datagram.
pub(crate) fn a_restored_trust_is_dialled_again() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right, left_store, right_store) = paired_machines(&sim)?;
        let managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        let egor = person("egor")?;
        left.rights()?
            .withdraw_trust(&right.peer_id(), egor.clone(), NOW)
            .map_err(|error| error.to_string())?;
        // A service asks for a dial: it is told why the pair cannot be dialled, and the
        // state it is told about is the stop this call wrote.
        let (state, failed) = within(
            &sim,
            Duration::from_secs(30),
            managed_left
                .connections
                .ensure(&managed_left.endpoint, &right.fingerprint()),
        )
        .await?;
        match &failed {
            Some(ConnectFailure::NotTrusted {
                peer,
                cause: NotTrustedCause::Withdrawn,
            }) if *peer == right.fingerprint() => {}
            other => {
                return Err(format!(
                    "a dial to a withdrawn peer was answered `{other:?}`, not the withdrawal"
                ));
            }
        }
        // The answer and the readable state name the same thing: a refusal is a decision, so
        // the ask stops the pair with the cause it read rather than leaving a stale reason
        // behind. It is not permanent — the next call after a restoration re-opens it.
        if !matches!(
            state,
            Recovery::Stopped {
                cause: StopCause::NotTrusted(NotTrustedCause::Withdrawn)
            }
        ) {
            return Err(format!(
                "a service's ask to a withdrawn pair reads `{state}`, not the stop its answer names"
            ));
        }
        // A person restores the trust.
        left.rights()?
            .restore_trust(&pair(&right, &label("admin")?), egor, NOW)
            .map_err(|error| error.to_string())?;
        // The next ask dials, and the pair is live and carries.
        let (state, failed) = within(
            &sim,
            Duration::from_secs(60),
            managed_left
                .connections
                .ensure(&managed_left.endpoint, &right.fingerprint()),
        )
        .await?;
        if let Some(failure) = failed {
            return Err(format!(
                "a restored trust was still refused: the dial met `{failure}`"
            ));
        }
        if state != Recovery::Connected {
            return Err(format!(
                "the pair reads `{state}` after a restored trust, not connected"
            ));
        }
        let live = managed_left
            .connections
            .live(&right.peer_id())
            .ok_or("a restored trust dialled but the pair holds no connection")?;
        live.send_datagram(b"trusted again".as_slice().into())
            .map_err(|error| error.to_string())?;
        let there = managed_right
            .connections
            .live(&left.peer_id())
            .ok_or("the far side holds no connection after the trust was restored")?;
        let received = within(&sim, Duration::from_secs(10), there.read_datagram())
            .await?
            .map_err(|error| error.to_string())?;
        if &received[..] != b"trusted again" {
            return Err(format!("the datagram arrived as {received:?}"));
        }
        // A stop a keeper wrote is the state a person's restoration has to get past: the
        // keeper stops the pair naming the withdrawal, and the next ask re-opens it and dials
        // with no keeper running.
        let keeper = spawn_keeper(&managed_left, &right);
        left.rights()?
            .withdraw_trust(
                &right.peer_id(),
                person("egor")?,
                NOW.plus(Duration::from_secs(1)),
            )
            .map_err(|error| error.to_string())?;
        let stopped = within(&sim, Duration::from_secs(30), keeper)
            .await?
            .map_err(|error| error.to_string())?;
        if !matches!(stopped, StopCause::NotTrusted(NotTrustedCause::Withdrawn)) {
            return Err(format!(
                "the keeper ended `{stopped}`, not a stop naming the withdrawal"
            ));
        }
        let held = managed_left.connections.recovery(&right.peer_id());
        if !matches!(
            held,
            Recovery::Stopped {
                cause: StopCause::NotTrusted(NotTrustedCause::Withdrawn)
            }
        ) {
            return Err(format!(
                "a keeper's stop reads `{held}`, not the stop with its cause"
            ));
        }
        left.rights()?
            .restore_trust(
                &pair(&right, &label("admin")?),
                person("egor")?,
                NOW.plus(Duration::from_secs(2)),
            )
            .map_err(|error| error.to_string())?;
        let (state, failed) = within(
            &sim,
            Duration::from_secs(60),
            managed_left
                .connections
                .ensure(&managed_left.endpoint, &right.fingerprint()),
        )
        .await?;
        if let Some(failure) = failed {
            return Err(format!(
                "a stop left by a keeper outlived the restored trust: the dial met `{failure}`"
            ));
        }
        if state != Recovery::Connected {
            return Err(format!(
                "the pair reads `{state}` after a keeper's stop was re-opened, not connected"
            ));
        }
        // A plain dial is the other way a stop's cause is disproved: the record said the pair
        // is trusted and the peer answered, so a stop a keeper left does not outlive that
        // either, even though no `ensure` re-opened it.
        managed_left.connections.disconnect(&right.peer_id());
        left.rights()?
            .withdraw_trust(
                &right.peer_id(),
                person("egor")?,
                NOW.plus(Duration::from_secs(3)),
            )
            .map_err(|error| error.to_string())?;
        let keeper = spawn_keeper(&managed_left, &right);
        let stopped = within(&sim, Duration::from_secs(30), keeper)
            .await?
            .map_err(|error| error.to_string())?;
        if !matches!(stopped, StopCause::NotTrusted(NotTrustedCause::Withdrawn)) {
            return Err(format!("the second keeper ended `{stopped}`, not a stop"));
        }
        left.rights()?
            .restore_trust(
                &pair(&right, &label("admin")?),
                person("egor")?,
                NOW.plus(Duration::from_secs(4)),
            )
            .map_err(|error| error.to_string())?;
        managed_left
            .connections
            .connect(&managed_left.endpoint, &right.fingerprint())
            .await
            .map_err(|error| format!("a plain dial after a restored trust failed: {error}"))?;
        managed_left.connections.disconnect(&right.peer_id());
        sim.clock().advance(KEEPER_SETTLE + TRUST_POLL).await;
        let after = managed_left.connections.recovery(&right.peer_id());
        if matches!(after, Recovery::Stopped { .. }) {
            return Err(format!(
                "a plain dial that reached the peer left the pair reading `{after}`"
            ));
        }
        Ok(())
    })
}

/// A beacon that was down and comes back recovers the pair with no person and no restart.
///
/// Both machines keep themselves findable and both keepers run, so either side may be the
/// one that re-checks first. The records are made to remember addresses that answer
/// nothing — a pair whose path changed — so the beacon is the only thing that knows where
/// the machines are; the case therefore proves the keepers' beacon leg across an outage,
/// and says nothing about an outage on a pair whose remembered address still works, which
/// needs no beacon at all.
pub(crate) fn pair_recovers_after_the_beacon_returns() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let mut beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right, left_store, right_store) = paired_machines(&sim)?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        let managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        let left_presence = keep_findable(&sim, &beacon, &left).await?;
        let right_presence = keep_findable(&sim, &beacon, &right).await?;
        let left_keeper = spawn_keeper(&managed_left, &right);
        let right_keeper = spawn_keeper(&managed_right, &left);
        drive_until(&sim, Duration::from_secs(120), || {
            if managed_left.connections.live(&right.peer_id()).is_some() {
                Ok(())
            } else {
                Err("the pair did not connect over the beacon to begin with".to_owned())
            }
        })
        .await?;
        // Both records now remember an address that answers nothing, as a pair whose path
        // changed does: only the beacon can say where the machines are.
        let stale_for_left = sim.link().alloc_addr();
        let stale_for_right = sim.link().alloc_addr();
        sim.link().silence(stale_for_left);
        sim.link().silence(stale_for_right);
        left_store
            .record_address(&right.peer_id(), stale_for_left)
            .map_err(|error| error.to_string())?;
        right_store
            .record_address(&left.peer_id(), stale_for_right)
            .map_err(|error| error.to_string())?;
        // The beacon goes away, and both sides lose the connection they held.
        beacon.stop();
        managed_left.connections.disconnect(&right.peer_id());
        managed_right.connections.disconnect(&left.peer_id());
        // Neither side can reach the other and neither can reach the beacon: the state names
        // the beacon, which is the honest failure, and not a silence.
        drive_until(&sim, Duration::from_secs(900), || {
            let here = managed_left.connections.recovery(&right.peer_id());
            let there = managed_right.connections.recovery(&left.peer_id());
            let names_the_beacon = |state: &Recovery| {
                matches!(
                    state,
                    Recovery::Waiting {
                        last: Some(ConnectFailure::BeaconUnreachable { .. }),
                        ..
                    } | Recovery::Exhausted {
                        last: ConnectFailure::BeaconUnreachable { .. },
                        ..
                    }
                )
            };
            if names_the_beacon(&here) && names_the_beacon(&there) {
                Ok(())
            } else {
                Err(format!(
                    "with the beacon down the pair reads `{here}` here and `{there}` there"
                ))
            }
        })
        .await?;
        // The beacon comes back at the same address with the same key, and remembers
        // nothing: both machines register again by themselves.
        beacon.restart().await?;
        drive_until(&sim, 3 * RECOVERY_RECHECK, || {
            let held = beacon
                .registry()
                .lock()
                .expect("the beacon registry is not poisoned")
                .snapshot();
            let registered = |peer: &PeerId| held.iter().any(|(id, _)| *id == *peer);
            if registered(&left.peer_id()) && registered(&right.peer_id()) {
                Ok(())
            } else {
                Err("the restarted beacon did not hold both machines again".to_owned())
            }
        })
        .await?;
        // Nobody dials: the keepers' own re-check finds the pair.
        let mark = sim.link().trace().len();
        drive_until(&sim, RECOVERY_RECHECK + Duration::from_secs(60), || {
            let here = managed_left.connections.live(&right.peer_id());
            let there = managed_right.connections.live(&left.peer_id());
            if here.is_some() && there.is_some() {
                Ok(())
            } else {
                Err(format!(
                    "the pair did not come back after the beacon did: it reads `{}` here",
                    managed_left.connections.recovery(&right.peer_id())
                ))
            }
        })
        .await?;
        // An address a record remembers answered nothing on the way back, so the beacon is
        // what brought the pair together: whichever keeper re-checked first had to find the
        // peer there.
        let after = sim.link().trace();
        let tried_what_was_remembered = |from: SocketAddr, to: SocketAddr| {
            after[mark..]
                .iter()
                .any(|event| event.from == from && event.to == to && !event.delivered())
        };
        if !tried_what_was_remembered(left.addr(), stale_for_left)
            && !tried_what_was_remembered(right.addr(), stale_for_right)
        {
            return Err(
                "the pair came back without trying the address its record remembers".to_owned(),
            );
        }
        // It is a real connection: a datagram crosses it.
        let here = managed_left
            .connections
            .live(&right.peer_id())
            .ok_or("the pair lost its connection the moment it came back")?;
        here.send_datagram(b"back again".as_slice().into())
            .map_err(|error| error.to_string())?;
        let there = managed_right
            .connections
            .live(&left.peer_id())
            .ok_or("the far side did not adopt the recovered connection")?;
        let received = within(&sim, Duration::from_secs(10), there.read_datagram())
            .await?
            .map_err(|error| error.to_string())?;
        if &received[..] != b"back again" {
            return Err(format!("the datagram arrived as {received:?}"));
        }
        left_presence.abort();
        right_presence.abort();
        left_keeper.abort();
        right_keeper.abort();
        Ok(())
    })
}

/// A peer that restarted on a new port is found again through the beacon by the other
/// machine's own re-check: the remembered address answers nothing, the beacon answers with
/// the new one, and the pair connects with nobody dialling.
///
/// What the record learns is the accepting side's business. The dialling side never writes
/// the address it dialled, so the left's record still remembers the stale port after the
/// pair is back; the case then lets the right dial — its own record has the left's address,
/// which never moved — and shows the left's record corrected by its own accept, which is
/// where an address comes from.
pub(crate) fn pair_recovers_after_the_peer_moves() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right, left_store, right_store) = paired_machines(&sim)?;
        // The right comes back on a fresh port, as a machine that restarted does, so the
        // address the left's record remembers is stale from here on.
        let stale = right.addr();
        let fresh = right.rebind_next();
        // Nothing answers on the port the peer left, as with a process that is gone.
        sim.link().silence(stale);
        let managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        // Both machines keep themselves findable, so the beacon knows where the right is
        // now.
        let left_presence = keep_findable(&sim, &beacon, &left).await?;
        let right_presence = keep_findable(&sim, &beacon, &right).await?;
        // Only the left's keeper dials: the beacon is what has to answer for the peer that
        // moved, and the right's own keeper would reach the left at the address that never
        // moved.
        let keeper = spawn_keeper(&managed_left, &right);
        drive_until(&sim, Duration::from_secs(300), || {
            let state = managed_left.connections.recovery(&right.peer_id());
            if state == Recovery::Connected {
                Ok(())
            } else {
                Err(format!(
                    "the pair did not come back after the peer moved: it reads `{state}`"
                ))
            }
        })
        .await?;
        // The stale address was tried first and answered nothing, and the beacon was asked
        // after it.
        let trace = sim.link().trace();
        let tried_stale = trace
            .iter()
            .position(|event| event.from == left.addr() && event.to == stale && !event.delivered())
            .ok_or("the remembered address was not tried")?;
        if !trace[tried_stale..]
            .iter()
            .any(|event| event.from == left.addr() && event.to == beacon.address())
        {
            return Err("the beacon was not asked after the remembered address failed".to_owned());
        }
        let live = managed_left
            .connections
            .live(&right.peer_id())
            .ok_or("the pair lost its connection the moment it came back")?;
        if live.remote_address() != fresh {
            return Err(format!(
                "the connection reached {} instead of the fresh {fresh}",
                live.remote_address()
            ));
        }
        // It is a real connection: a datagram crosses it.
        live.send_datagram(b"moved".as_slice().into())
            .map_err(|error| error.to_string())?;
        let there = managed_right
            .connections
            .live(&left.peer_id())
            .ok_or("the far side did not adopt the connection")?;
        let received = within(&sim, Duration::from_secs(10), there.read_datagram())
            .await?
            .map_err(|error| error.to_string())?;
        if &received[..] != b"moved" {
            return Err(format!("the datagram arrived as {received:?}"));
        }
        // The dialling side wrote nothing: the record still remembers the port the peer
        // left.
        let remembered = left
            .reopen_records()?
            .get(&right.peer_id())
            .and_then(|record| record.last_address());
        if remembered != Some(stale) {
            return Err(format!(
                "the dialling side rewrote the address it dialled: the record remembers \
                 {remembered:?}, not the stale {stale}"
            ));
        }
        // The accepting side is what teaches an address. The pair holds nothing, so the
        // right's own connection is the one the left keeps — and records.
        managed_left.connections.disconnect(&right.peer_id());
        let right_keeper = spawn_keeper(&managed_right, &left);
        drive_until(&sim, Duration::from_secs(120), || {
            let address = left
                .reopen_records()?
                .get(&right.peer_id())
                .and_then(|record| record.last_address());
            if address == Some(fresh) {
                Ok(())
            } else {
                Err(format!(
                    "the accepting side did not record where the peer came from: the record \
                     remembers {address:?}, not the fresh {fresh}"
                ))
            }
        })
        .await?;
        left_presence.abort();
        right_presence.abort();
        keeper.abort();
        right_keeper.abort();
        Ok(())
    })
}

/// This machine's own registration comes back by itself when the beacon does: a beacon that
/// is killed — silenced with no close — makes the presence report it as unreachable with the
/// attempt count growing, and a beacon that comes back at the same address with the same
/// key finds the registration made again, with the run still going. A run that is dropped —
/// how a caller stops it — leaves the state idle rather than claiming a registration nothing
/// refreshes.
pub(crate) fn presence_returns_after_the_beacon_restarts() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let mut beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;
        let presence = Arc::new(Presence::new(beacon.client(&machine)?));
        let task = {
            let presence = Arc::clone(&presence);
            tokio::spawn(async move { presence.run().await })
        };
        // The registration is made before anything is taken away.
        drive_until(&sim, Duration::from_secs(120), || {
            let held = beacon
                .registry()
                .lock()
                .expect("the beacon registry is not poisoned")
                .snapshot();
            if held.iter().any(|(id, _)| *id == machine.peer_id()) {
                Ok(())
            } else {
                Err("the beacon never held the machine".to_owned())
            }
        })
        .await?;
        if presence.state() != Registration::Registered {
            return Err(format!("a registered machine reads `{}`", presence.state()));
        }
        // A process death: the link is silenced and no close is sent, so the machine only
        // learns the beacon is gone from its own request bound.
        beacon.kill();
        let mut grown = 0;
        drive_until(&sim, Duration::from_secs(600), || match presence.state() {
            Registration::Unreachable { dials, last, .. } => {
                if !last.contains("beacon") {
                    return Err(format!("a beacon that is gone is reported as `{last}`"));
                }
                grown = dials;
                if dials >= 2 {
                    Ok(())
                } else {
                    Err(format!(
                        "the machine still counts {dials} failed registration dials"
                    ))
                }
            }
            other => Err(format!(
                "a machine whose beacon was killed reads `{other}`, not an unreachable one"
            )),
        })
        .await?;
        if grown < 2 {
            return Err("the dial count did not grow".to_owned());
        }
        // The beacon comes back at the same address with the same key. Its memory is new,
        // so the registry is read again rather than held across the restart.
        beacon.restart().await?;
        drive_until(&sim, RECOVERY_RECHECK + Duration::from_secs(60), || {
            let held = beacon
                .registry()
                .lock()
                .expect("the beacon registry is not poisoned")
                .snapshot();
            let registered = held
                .iter()
                .any(|(id, address)| *id == machine.peer_id() && *address == machine.addr());
            match presence.state() {
                Registration::Registered if registered => Ok(()),
                state => Err(format!(
                    "the registration did not come back after the beacon did: the machine \
                     reads `{state}`"
                )),
            }
        })
        .await?;
        if task.is_finished() {
            return Err("the presence stopped instead of registering again".to_owned());
        }
        // Dropping the run is how a caller stops it, and the state must not keep claiming a
        // registration nothing is refreshing.
        task.abort();
        let _ = task.await;
        if presence.state() != Registration::Idle {
            return Err(format!(
                "a stopped presence reads `{}`, not idle",
                presence.state()
            ));
        }
        Ok(())
    })
}
