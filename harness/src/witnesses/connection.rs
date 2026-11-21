//! Connection cases: the manager's two sources, the four failures, the address
//! rule, the tie-break, the keeper's two stops, the registration refresh, and the
//! restart that keeps only the root.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use mahbot_peers::identity::PeerId;
use mahbot_peers::peer::{
    ConnectFailure, Connections, KEEPER_SETTLE, KEEPER_UNSTABLE_LIMIT, Keeper, ManagerError,
    NotTrustedCause, Presence, RecordStore, Started,
};

use crate::beacon::TestBeacon;
use crate::clock::block_on;
use crate::machine::Machine;
use crate::sim::Sim;

use super::peer::{NOW, Shown, pair_together, paired, session};
use super::support::{io_error, within};

/// A machine's manager, its endpoint and the accept loops the case spawned.
///
/// The loops are the case's own tasks: the library returns the future and the
/// caller keeps the handle, which is what lets this case stop them.
struct Managed {
    connections: Arc<Connections>,
    endpoint: quinn::Endpoint,
    lanes: Vec<tokio::task::JoinHandle<()>>,
}

impl Managed {
    fn start(
        sim: &Sim,
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
                sim.clock().runtime(),
                &machine.transport,
            )
            .map_err(|error| error.to_string())?,
        );
        let lanes = (0..mahbot_peers::peer::ACCEPT_LANES)
            .map(|_| tokio::spawn(Arc::clone(&connections).serve(endpoint.clone())))
            .collect();
        Ok(Self {
            connections,
            endpoint,
            lanes,
        })
    }
}

impl Drop for Managed {
    fn drop(&mut self) {
        for lane in self.lanes.drain(..) {
            lane.abort();
        }
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
        let right_session = session(&beacon, &right).await?;
        let presence = Presence::new(beacon.client(&right)?);
        let presence_task = tokio::spawn(async move {
            let _ = presence.run(&right_session).await;
        });
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
        let right_session = session(&beacon, &right).await?;
        let presence = Presence::new(beacon.client(&right)?);
        let presence_task = tokio::spawn(async move {
            let _ = presence.run(&right_session).await;
        });
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
        // The beacon session the attempt opened is dropped and its close flushed;
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
        // The two accept lanes apply the tie-break after the dials return, so wait
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
        let presence_session = session(&beacon, &machine).await?;
        let presence = Presence::new(beacon.client(&machine)?);
        let task = tokio::spawn(async move {
            let _ = presence.run(&presence_session).await;
        });
        sim.clock().advance(Duration::from_secs(400)).await;
        tokio::task::yield_now().await;
        let answer = watcher_session
            .lookup(&machine.peer_id())
            .await
            .map_err(|error| error.to_string())?;
        task.abort();
        if answer != Some(machine.addr()) {
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

/// Two machines paired by a real ceremony, with a manager and its accept lanes on
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
        let right_session = session(&beacon, &right).await?;
        let presence = Presence::new(beacon.client(&right)?);
        let presence_task = tokio::spawn(async move {
            let _ = presence.run(&right_session).await;
        });
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
        let right_session = session(&beacon, &right).await?;
        let right_presence = Presence::new(beacon.client(&right)?);
        let right_presence_task = tokio::spawn(async move {
            let _ = right_presence.run(&right_session).await;
        });
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
        let right_session = session(&beacon, &right).await?;
        let right_presence = Presence::new(beacon.client(&right)?);
        let right_presence_task = tokio::spawn(async move {
            let _ = right_presence.run(&right_session).await;
        });
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
        // A person's clear on this machine reopens it.
        left_store
            .clear(&right.peer_id())
            .map_err(|error| error.to_string())?;
        if !left_store.trusts(&right.peer_id()) {
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
/// handshake loop: after a run of such closes it stops and says so.
pub(crate) fn keeper_stops_when_the_peer_keeps_closing() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right, left_store, _) = paired_machines(&sim)?;
        // The far side completes the handshake but keeps each connection only for a
        // moment — shorter than the keeper's settle window — so every dial is a fresh
        // connection the peer then drops.
        let (closer, _accepted) = closing_peer(&sim, &right, |_, _| Duration::from_secs(1))?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        let end = within(&sim, Duration::from_secs(600), async {
            managed_left
                .connections
                .keep_connected(&managed_left.endpoint, &right.fingerprint())
                .await
        })
        .await?;
        closer.abort();
        match &end {
            Keeper::Unstable { peer, cause } if *peer == right.fingerprint() => {
                if cause.is_empty() {
                    return Err("the keeper named no cause for the last close".to_owned());
                }
                let words = end.to_string();
                if !words.contains("stopped trying")
                    || !words.contains("carried anything")
                    || !words.contains(cause)
                {
                    return Err(format!(
                        "an unstable keeper reads `{words}`, which does not say it stopped after \
                         dials carried nothing for {cause}"
                    ));
                }
                Ok(())
            }
            other => Err(format!(
                "a peer that keeps closing ended the keeper `{other}`"
            )),
        }
    })
}

/// A keeper whose attempt fails with the pair holding nothing stops at once and says
/// so in the words of that failure, not as a run of dials that carried nothing.
pub(crate) fn keeper_stops_when_a_dial_fails() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        // The far side is paired but never runs: its address answers nothing, and the
        // beacon has no registration for it either, so the keeper's one attempt ends
        // with `PeerUnknown`.
        let (left, right, left_store, _) = paired_machines(&sim)?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        let end = within(&sim, Duration::from_secs(600), async {
            managed_left
                .connections
                .keep_connected(&managed_left.endpoint, &right.fingerprint())
                .await
        })
        .await?;
        let Keeper::Failed(ConnectFailure::PeerUnknown { peer, cause }) = &end else {
            return Err(format!("a failed attempt ended the keeper `{end}`"));
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
        let words = end.to_string();
        if !words.contains("stopped trying") || !words.contains("the beacon does not know") {
            return Err(format!("a failed keeper reads `{words}`"));
        }
        Ok(())
    })
}

/// A dial that fails while the accept lane has already connected does not stop the
/// keeper: it asks whether the pair is connected before it reports the failure.
pub(crate) fn keeper_survives_a_failed_dial_while_the_pair_connects() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right, left_store, right_store) = paired_machines(&sim)?;
        // The left's remembered address for the right goes stale, and the beacon does
        // not know the right, so the left's attempt ends with `PeerUnknown`.
        right.rebind_next();
        let managed_right = Managed::start(&sim, &beacon, &right, &right_store)?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        // The left dials the stale address first; the right's dial reaches the left's
        // accept lane while that attempt is still in flight.
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
        // Past the left's connect budget its attempt fails, with the pair connected.
        sim.clock().advance(Duration::from_secs(20)).await;
        tokio::task::yield_now().await;
        if left_keeper.is_finished() {
            let end = left_keeper.await.map_err(|error| error.to_string())?;
            right_keeper.abort();
            return Err(format!(
                "the keeper stopped on a failed dial while the pair was connected: {end}"
            ));
        }
        // The pair really is the one the accept lane took, and it carries.
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
fn closing_peer(
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

/// Run the manager's keeper for `peer` on its own task, as a caller does.
fn spawn_keeper(managed: &Managed, peer: &Machine) -> tokio::task::JoinHandle<Keeper> {
    let connections = Arc::clone(&managed.connections);
    let endpoint = managed.endpoint.clone();
    let peer = peer.fingerprint();
    tokio::spawn(async move { connections.keep_connected(&endpoint, &peer).await })
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
/// strike: the keeper re-dials it more times than the unstable limit and keeps
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
        let enough = usize::from(KEEPER_UNSTABLE_LIMIT) + 2;
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

/// A connection the peer keeps past the settle window clears the keeper's strikes, so
/// ordinary churn never adds up to a stopped keeper.
pub(crate) fn keeper_resets_after_a_settled_connection() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right, left_store, _) = paired_machines(&sim)?;
        // Two closes at once, then one connection kept past the settle window, then
        // two more closes at once: two strikes, a reset, two strikes. Without the
        // reset the fourth close would already be the third strike in a row.
        let (closer, accepted) = closing_peer(&sim, &right, |_, index| {
            if index == 2 {
                KEEPER_SETTLE + Duration::from_secs(1)
            } else {
                Duration::from_secs(1)
            }
        })?;
        let managed_left = Managed::start(&sim, &beacon, &left, &left_store)?;
        let keeper = spawn_keeper(&managed_left, &right);
        // Wait until the fifth connection has been accepted *and* adopted: counting
        // accepts alone would race the keeper's dial.
        within(&sim, Duration::from_secs(600), async {
            loop {
                if keeper.is_finished()
                    || (accepted.load(Ordering::SeqCst) >= 5
                        && managed_left.connections.live(&right.peer_id()).is_some())
                {
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
                "the keeper stopped after {end}, short of {KEEPER_UNSTABLE_LIMIT} strikes in a row"
            ));
        }
        keeper.abort();
        Ok(())
    })
}
