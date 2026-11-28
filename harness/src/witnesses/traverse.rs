//! Traversal cases: the punch, the candidate filter, the address list and the outcome
//! table.
//!
//! A punch is two machines dialling each other's beacon-observed address in the same
//! round trip. These cases run it through [`Connections`], so what they prove is the
//! crate's own behaviour, and they read the rig's [`Traversal`] to tell a punch from a
//! dial that happened to work.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use mahbot_peers::beacon::{Beacon, Refusal, Response};
use mahbot_peers::peer::{
    ConnectFailure, Connections, NotTrustedCause, PAIR_FLIGHT_TIMEOUT, Recovery, StopCause,
};
use quinn::{Connection, Endpoint};

use crate::beacon::TestBeacon;
use crate::clock::block_on;
use crate::link::{Filtering, Mapping, Nat, Pooling, Traversal};
use crate::machine::Machine;
use crate::raw::{Rogue, RogueBeacon};
use crate::sim::Sim;

use super::peer::NOW;
use super::support::{Woken, io_error, keep_findable, poll_once, within};

/// What one punch produced, kept alive for the case to read.
struct Punched {
    left: Machine,
    right: Machine,
    left_manager: Arc<Connections>,
    right_manager: Arc<Connections>,
    left_endpoint: Endpoint,
    right_endpoint: Endpoint,
    accepts: Vec<tokio::task::JoinHandle<()>>,
    /// What each side's `connect` answered.
    answers: (
        Result<Connection, ConnectFailure>,
        Result<Connection, ConnectFailure>,
    ),
}

impl Drop for Punched {
    fn drop(&mut self) {
        for accept in &self.accepts {
            accept.abort();
        }
        self.left_endpoint.close(0u32.into(), b"the case is done");
        self.right_endpoint.close(0u32.into(), b"the case is done");
    }
}

/// Pair two machines in their records and punch, both sides dialling at once.
///
/// `declares` makes each side declare its own address, which is what the local-network
/// row needs; the records are given no address at all, so the only addresses either
/// side can dial come from the beacon or from the other side's payload.
async fn punch(
    sim: &Sim,
    beacon: &TestBeacon,
    left: Machine,
    right: Machine,
    declares: bool,
) -> Result<Punched, String> {
    let prepared = prepare(sim, beacon, left, right, declares).await?;
    run(sim, prepared).await
}

/// Two machines ready to punch: paired in their records, registered, with their managers and
/// accept loops running. Nothing is dialled yet, so a case can take the world away between the
/// two halves — block a network, silence a machine — and then [`run`] the punch.
struct Prepared {
    left: Machine,
    right: Machine,
    left_manager: Arc<Connections>,
    right_manager: Arc<Connections>,
    left_endpoint: Endpoint,
    right_endpoint: Endpoint,
    accepts: Vec<tokio::task::JoinHandle<()>>,
}

async fn prepare(
    sim: &Sim,
    beacon: &TestBeacon,
    left: Machine,
    right: Machine,
    declares: bool,
) -> Result<Prepared, String> {
    for (store, peer) in [
        (left.records(), right.peer_id()),
        (right.records(), left.peer_id()),
    ] {
        store
            .record_pairing(&peer, NOW)
            .map_err(|error| error.to_string())?;
    }
    let left_presence = keep_findable(sim, beacon, &left).await?;
    let right_presence = keep_findable(sim, beacon, &right).await?;
    let left_manager = Connections::new(
        &left.identity,
        left.records(),
        Some(beacon.client(&left)?),
        sim.clock().runtime(),
        &left.transport,
    )
    .map_err(|error| error.to_string())?;
    let right_manager = Connections::new(
        &right.identity,
        right.records(),
        Some(beacon.client(&right)?),
        sim.clock().runtime(),
        &right.transport,
    )
    .map_err(|error| error.to_string())?;
    if declares {
        left_manager.declares([left.addr()]);
        right_manager.declares([right.addr()]);
    }
    let left_manager = Arc::new(left_manager.with_presence(Arc::new(left_presence)));
    let right_manager = Arc::new(right_manager.with_presence(Arc::new(right_presence)));
    let left_endpoint = left.endpoint().map_err(|error| error.to_string())?;
    let right_endpoint = right.endpoint().map_err(|error| error.to_string())?;
    let accepts = vec![
        tokio::spawn(Arc::clone(&left_manager).serve(left_endpoint.clone())),
        tokio::spawn(Arc::clone(&right_manager).serve(right_endpoint.clone())),
    ];
    Ok(Prepared {
        left,
        right,
        left_manager,
        right_manager,
        left_endpoint,
        right_endpoint,
        accepts,
    })
}

/// Dial both sides at once and answer what each one's `connect` said.
async fn run(sim: &Sim, prepared: Prepared) -> Result<Punched, String> {
    let Prepared {
        left,
        right,
        left_manager,
        right_manager,
        left_endpoint,
        right_endpoint,
        accepts,
    } = prepared;
    // What each side dials: the other machine's fingerprint.
    let left_dials = right.fingerprint();
    let right_dials = left.fingerprint();
    let answers = within(sim, Duration::from_secs(180), async {
        tokio::join!(
            left_manager.connect(&left_endpoint, &left_dials),
            right_manager.connect(&right_endpoint, &right_dials),
        )
    })
    .await?;
    Ok(Punched {
        left,
        right,
        left_manager,
        right_manager,
        left_endpoint,
        right_endpoint,
        accepts,
        answers,
    })
}

/// Whether a punch between these two networks connects, by the rule the `connect`
/// module's outcome table states.
fn connects(left: Nat, right: Nat) -> bool {
    admitted(right, left) || admitted(left, right)
}

/// Whether `to`'s network lets a mapping of `from` in through the address it observed:
/// its mapping has to be endpoint-independent (so the observed address is valid for
/// any source), and its filter has to admit the mapping `from` uses for it.
fn admitted(to: Nat, from: Nat) -> bool {
    if to.mapping() != Mapping::EndpointIndependent {
        return false;
    }
    match to.filtering() {
        Filtering::EndpointIndependent => true,
        // The address is the one observed only when one external address is pooled for
        // every destination.
        Filtering::AddressDependent => from.pooling() == Pooling::Shared,
        // The endpoint is the one observed only when the mapping does not depend on the
        // destination.
        Filtering::AddressAndPortDependent => from.mapping() == Mapping::EndpointIndependent,
    }
}

/// The one connection the pair ended with, per side, or why it did not end with one.
fn one_connection(punched: &Punched) -> Result<(Connection, Connection), String> {
    let left = punched.left_manager.live(&punched.right.peer_id());
    let right = punched.right_manager.live(&punched.left.peer_id());
    match (left, right) {
        (Some(left), Some(right)) => Ok((left, right)),
        (left, right) => Err(format!(
            "the pair did not end with one connection each: left {left:?}, right {right:?}"
        )),
    }
}

/// The punch is the handshake: a pair behind two ordinary home routers connects on the
/// first dial, the connection carries application data, and the rig shows that both
/// sides had sent to the other before either was let in.
pub(crate) fn a_home_router_punch_is_the_handshake() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let left = sim.machine_behind(Nat::full_cone()).map_err(io_error)?;
        let right = sim.machine_behind(Nat::full_cone()).map_err(io_error)?;
        let punched = punch(&sim, &beacon, left, right, false).await?;
        let (left_live, right_live) = one_connection(&punched)?;
        for (side, answer) in ["left", "right"]
            .iter()
            .zip([&punched.answers.0, &punched.answers.1])
        {
            if let Err(failure) = answer {
                return Err(format!(
                    "the {side} dial answered `{failure}`, not a connection"
                ));
            }
        }
        // The connection reached the peer's external address, not its private one: the
        // path really went through both networks.
        let left_external = sim
            .link()
            .external(punched.left.addr())
            .ok_or("the left's network made no mapping")?;
        let right_external = sim
            .link()
            .external(punched.right.addr())
            .ok_or("the right's network made no mapping")?;
        if left_live.remote_address() != right_external {
            return Err(format!(
                "the left reached {} instead of the right's external {right_external}",
                left_live.remote_address()
            ));
        }
        if right_live.remote_address() != left_external {
            return Err(format!(
                "the right reached {} instead of the left's external {left_external}",
                right_live.remote_address()
            ));
        }
        // Application data crosses it, and the check was the handshake: nothing else was
        // sent to the peer before the connection existed. The binding exchange runs first
        // on its own task, so the clock is moved past it before the word is written.
        sim.clock().advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        within(
            &sim,
            Duration::from_secs(10),
            super::support::round_trip(&left_live, &right_live),
        )
        .await??;
        // The observable: each side's filter admitted the other from an address it had
        // itself sent to, which is what makes this a punch and not a lucky redial.
        let traversal: Traversal = sim.link().traversal();
        for (side, internal, destination) in [
            ("left", punched.left.addr(), right_external),
            ("right", punched.right.addr(), left_external),
        ] {
            if !traversal
                .holes
                .iter()
                .any(|hole| hole.internal == internal && hole.destination == destination)
            {
                return Err(format!(
                    "the {side} never sent to the other's external address, so this was not a punch"
                ));
            }
        }
        // And each side's network recorded the mapping that address is.
        for (side, internal, external) in [
            ("left", punched.left.addr(), left_external),
            ("right", punched.right.addr(), right_external),
        ] {
            if !traversal
                .mappings
                .iter()
                .any(|mapping| mapping.internal == internal && mapping.external == external)
            {
                return Err(format!(
                    "the {side}'s network recorded no mapping {internal} -> {external}"
                ));
            }
        }
        // Remembering the punch is not optional: the address it completed from is authenticated
        // data, so each side's record holds the other's external address and the next dial needs
        // no beacon.
        for (side, machine, peer, external) in [
            (
                "left",
                &punched.left,
                punched.right.peer_id(),
                right_external,
            ),
            (
                "right",
                &punched.right,
                punched.left.peer_id(),
                left_external,
            ),
        ] {
            let record = machine
                .records()
                .get(&peer)
                .ok_or_else(|| format!("the {side} keeps no record for the peer"))?;
            if !record.addresses().contains(&external) {
                return Err(format!(
                    "the {side}'s record does not hold {external}, the address the punch \
                     completed from: {:?}",
                    record.addresses()
                ));
            }
        }
        // A punch is not a person's decision: nothing about it reaches the audit log, on either
        // side of the pair.
        for (side, machine) in [("left", &punched.left), ("right", &punched.right)] {
            let log = machine.audit()?;
            let entries = log.entries().map_err(|error| error.to_string())?;
            if !entries.is_empty() {
                return Err(format!(
                    "the {side}'s audit log holds {} entries for a punch nobody decided",
                    entries.len()
                ));
            }
        }
        Ok(())
    })
}

/// The outcome table's matrix rows — 1 to 11 — with at least one entry each, in the crate's own
/// numbering: each mapping and filtering pair the rig can model either connects or refuses, and
/// the crate's own answer matches the rule its documentation states. A row whose claim covers
/// more than one configuration — a range of filterings or poolings, both destination-scoped
/// mapping kinds, or both orientations — carries an entry for each. The guard below
/// checks that every row 1 to 11 is recorded; it cannot check the crate's table text against
/// this list, so a row added to the documentation without a case here is a reader's catch, not
/// the guard's.
///
/// The table's other rows are their own cases, and each is a witness the inventory requires: 12
/// is [`the_local_network_row`], 13 [`the_hairpin_row`], 14
/// [`without_a_hairpin_the_pair_does_not_connect`], 15 [`double_translation_connects`], 16
/// [`udp_blocked_towards_the_peer_is_no_direct_path`], 17
/// [`udp_blocked_entirely_names_the_beacon`], and 18 is unproducible here.
pub(crate) fn the_outcome_table() -> Result<(), String> {
    block_on(async {
        let mut rows: Vec<(&str, Nat, Nat, bool)> = vec![
            (
                "row 1: both keep one mapping",
                Nat::full_cone(),
                Nat::full_cone(),
                true,
            ),
            (
                "row 2: a full cone answers a restricted peer",
                Nat::full_cone(),
                Nat::restricted_cone(),
                true,
            ),
            (
                "row 3: a full cone answers a port-restricted peer",
                Nat::full_cone(),
                Nat::port_restricted_cone(),
                true,
            ),
            (
                "row 4: restricted peers answer each other",
                Nat::restricted_cone(),
                Nat::restricted_cone(),
                true,
            ),
            (
                "row 5: restricted answers port-restricted",
                Nat::restricted_cone(),
                Nat::port_restricted_cone(),
                true,
            ),
            (
                "row 6: port-restricted peers answer each other",
                Nat::port_restricted_cone(),
                Nat::port_restricted_cone(),
                true,
            ),
        ];
        let dependent = Nat::full_cone().with_mapping(Mapping::AddressDependent);
        let unpooled = dependent.with_pooling(Pooling::PerDestination);
        rows.extend([
            // Row 7: the destination-dependent side's filtering never decides — the other
            // side's dial does not survive its mapping — so the row is tried at both ends of
            // the filtering range.
            (
                "row 7: a destination-dependent peer reaches a full cone",
                dependent,
                Nat::full_cone(),
                true,
            ),
            (
                "row 7: the same with the most restrictive filtering",
                dependent.with_filtering(Filtering::AddressAndPortDependent),
                Nat::full_cone(),
                true,
            ),
            (
                "row 7: and with an address per destination",
                unpooled,
                Nat::full_cone(),
                true,
            ),
            // Row 8: one shared external address is what address-dependent filtering admits.
            (
                "row 8: with one shared address a destination-dependent peer reaches a restricted peer",
                dependent,
                Nat::restricted_cone(),
                true,
            ),
            // Row 9: an address per destination is not the one the peer wrote to.
            (
                "row 9: with an address per destination a destination-dependent peer cannot reach a restricted peer",
                unpooled,
                Nat::restricted_cone(),
                false,
            ),
            // Row 10: a port-restricted filter admits only the observed endpoint, and the other
            // orientation dies on the destination-scoped mapping.
            (
                "row 10: a destination-dependent peer cannot reach a port-restricted peer",
                dependent,
                Nat::port_restricted_cone(),
                false,
            ),
            (
                "row 10: nor can a port-restricted peer reach a destination-dependent one",
                Nat::port_restricted_cone(),
                dependent,
                false,
            ),
            // Row 11, in both destination-scoped mapping kinds.
            (
                "row 11: two destination-dependent peers cannot reach each other",
                dependent,
                dependent,
                false,
            ),
            (
                "row 11: nor can two symmetric peers",
                Nat::symmetric(),
                Nat::symmetric(),
                false,
            ),
        ]);
        // Every row of the matrix — the table's 1 to 11 — has at least one entry, and no entry
        // names a row the table does not have: a row that lost its case fails here.
        let named: std::collections::BTreeSet<u32> = rows
            .iter()
            .filter_map(|(name, ..)| name.strip_prefix("row ")?.split(':').next()?.parse().ok())
            .collect();
        if named != (1..=11).collect() {
            return Err(format!(
                "the matrix rows recorded are {named:?}, not the table's 1 to 11"
            ));
        }
        for (name, left_nat, right_nat, expected) in rows {
            if connects(left_nat, right_nat) != expected {
                return Err(format!(
                    "the rig's own rule disagrees with the table at `{name}`"
                ));
            }
            let sim = Sim::new().map_err(io_error)?;
            let beacon = TestBeacon::start(&sim).map_err(io_error)?;
            let left = sim.machine_behind(left_nat).map_err(io_error)?;
            let right = sim.machine_behind(right_nat).map_err(io_error)?;
            let prepared = prepare(&sim, &beacon, left, right, false).await?;
            let started = sim.clock().elapsed();
            let punched = run(&sim, prepared).await?;
            let reached = one_connection(&punched);
            match (expected, reached) {
                (true, Ok(_)) => {}
                (false, Err(_)) => {}
                (true, Err(why)) => {
                    return Err(format!("`{name}` should connect and did not: {why}"));
                }
                (false, Ok(_)) => {
                    return Err(format!(
                        "`{name}` should not connect, and the pair ended with a connection"
                    ));
                }
            }
            if !expected {
                // A person waits no longer than the stated bound, and the punch fits inside it
                // rather than extending it.
                let waited = sim.clock().elapsed().saturating_sub(started);
                if waited > mahbot_peers::peer::DIAL_BUDGET {
                    return Err(format!(
                        "`{name}` answered after {waited:?}, past the stated bound {DIAL_BUDGET:?}",
                        DIAL_BUDGET = mahbot_peers::peer::DIAL_BUDGET
                    ));
                }
                // The refusal is the honest one: no direct path, never a beacon claim.
                for (side, answer) in [("left", &punched.answers.0), ("right", &punched.answers.1)]
                {
                    match answer {
                        Err(ConnectFailure::NoDirectPath { .. }) => {}
                        Err(other) => {
                            return Err(format!(
                                "`{name}` refused the {side} dial as `{other}`, not as no direct path"
                            ));
                        }
                        Ok(_) => {
                            return Err(format!(
                                "`{name}` refused the {side} dial and answered a connection"
                            ));
                        }
                    }
                }
            }
        }
        Ok(())
    })
}

/// Push `payload` from `sender` to `target` over the beacon, as a peer's presence does.
async fn push(
    sim: &Sim,
    beacon: &TestBeacon,
    sender: &Machine,
    target: &Machine,
    payload: &[u8],
) -> Result<(), String> {
    within(sim, Duration::from_secs(120), async {
        beacon
            .client(sender)?
            .connect()
            .await
            .map_err(|error| error.to_string())?
            .introduce(target.peer_id(), payload)
            .await
            .map_err(|error| error.to_string())
    })
    .await?
}

/// `count` documentation addresses that answer nothing, one per host number.
fn dead_addresses(count: usize) -> Vec<SocketAddr> {
    (1..=count)
        .map(|host| {
            SocketAddr::from((
                [
                    198,
                    51,
                    100,
                    u8::try_from(host).expect("a case names at most 255 candidates"),
                ],
                1,
            ))
        })
        .collect()
}

/// The bytes a coordination payload carries for `addresses`, built by hand so a case can send
/// what the crate would never produce — too many candidates, a refused address, a payload an
/// older build would not understand.
fn coordination_payload(addresses: &[std::net::SocketAddr]) -> Vec<u8> {
    let mut bytes = b"mahbot-peers coordinate v1".to_vec();
    bytes.push(1);
    bytes.push(u8::try_from(addresses.len()).expect("a payload names at most 255 addresses"));
    for address in addresses {
        match address {
            std::net::SocketAddr::V4(v4) => {
                bytes.push(4);
                bytes.extend_from_slice(&v4.ip().octets());
                bytes.extend_from_slice(&v4.port().to_be_bytes());
            }
            std::net::SocketAddr::V6(v6) => {
                bytes.push(6);
                bytes.extend_from_slice(&v6.ip().octets());
                bytes.extend_from_slice(&v6.port().to_be_bytes());
                bytes.extend_from_slice(&v6.flowinfo().to_be_bytes());
                bytes.extend_from_slice(&v6.scope_id().to_be_bytes());
            }
        }
    }
    bytes
}

/// Two machines in one room, behind one network: with the product's declared local address
/// they connect through the network's own side, and the hairpin is never asked for.
pub(crate) fn the_local_network_row() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right) = sim
            .machines_behind_one(Nat::full_cone().with_hairpin(false))
            .map_err(io_error)?;
        let punched = punch(&sim, &beacon, left, right, true).await?;
        // Four handshakes may complete at once; the accept tasks finish the tie-break on their
        // own, so the pair's one connection is read after they have had a round to do it.
        sim.clock().advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        let (left_live, right_live) = one_connection(&punched)?;
        if left_live.remote_address() != punched.right.addr() {
            return Err(format!(
                "the left reached {} instead of the right's local address {}",
                left_live.remote_address(),
                punched.right.addr()
            ));
        }
        if right_live.remote_address() != punched.left.addr() {
            return Err(format!(
                "the right reached {} instead of the left's local address {}",
                right_live.remote_address(),
                punched.left.addr()
            ));
        }
        if !sim.link().traversal().hairpins.is_empty() {
            return Err("the local path depended on the network's hairpin".to_owned());
        }
        Ok(())
    })
}

/// Two machines behind one network with no declared address: the hairpin is what carries
/// them, and the rig shows it did.
pub(crate) fn the_hairpin_row() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right) = sim
            .machines_behind_one(Nat::full_cone().with_hairpin(true))
            .map_err(io_error)?;
        let punched = punch(&sim, &beacon, left, right, false).await?;
        one_connection(&punched)?;
        if sim.link().traversal().hairpins.is_empty() {
            return Err(
                "the pair connected without a hairpin, so the local path was used \
                        without a declared address"
                    .to_owned(),
            );
        }
        Ok(())
    })
}

/// The same pair with no declared address and no hairpin: nothing carries it, and both dials
/// refuse with no direct path.
pub(crate) fn without_a_hairpin_the_pair_does_not_connect() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right) = sim
            .machines_behind_one(Nat::full_cone().with_hairpin(false))
            .map_err(io_error)?;
        let punched = punch(&sim, &beacon, left, right, false).await?;
        if one_connection(&punched).is_ok() {
            return Err(
                "the pair connected with neither a hairpin nor a declared address".to_owned(),
            );
        }
        for (side, answer) in [("left", &punched.answers.0), ("right", &punched.answers.1)] {
            if !matches!(answer, Err(ConnectFailure::NoDirectPath { .. })) {
                return Err(format!(
                    "the {side} dial answered {answer:?}, not a refusal with no direct path"
                ));
            }
        }
        Ok(())
    })
}

/// One machine behind two networks in a row still reaches a machine behind one.
pub(crate) fn double_translation_connects() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let left = sim
            .machine_behind(Nat::full_cone().twice())
            .map_err(io_error)?;
        let right = sim.machine_behind(Nat::full_cone()).map_err(io_error)?;
        let punched = punch(&sim, &beacon, left, right, false).await?;
        one_connection(&punched)?;
        Ok(())
    })
}

/// A network that blocks UDP towards the peer only: the beacon answers, the path does not, and
/// the refusal is `NoDirectPath` with the set it tried — never a claim about the beacon.
pub(crate) fn udp_blocked_towards_the_peer_is_no_direct_path() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let left = sim.machine_behind(Nat::full_cone()).map_err(io_error)?;
        let right = sim.machine_behind(Nat::full_cone()).map_err(io_error)?;
        let prepared = prepare(&sim, &beacon, left, right, false).await?;
        let right_external = sim
            .link()
            .external(prepared.right.addr())
            .ok_or("the right's network made no mapping")?;
        sim.link().blocks(prepared.left.addr(), right_external);
        let punched = run(&sim, prepared).await?;
        if one_connection(&punched).is_ok() {
            return Err("a blocked pair connected".to_owned());
        }
        for (side, answer) in [("left", &punched.answers.0), ("right", &punched.answers.1)] {
            let Err(failure) = answer else {
                return Err(format!("the {side} dial answered a connection"));
            };
            let ConnectFailure::NoDirectPath { candidates, .. } = failure else {
                return Err(format!(
                    "the {side} dial answered {failure:?}, not a refusal with no direct path"
                ));
            };
            if candidates.is_empty() {
                return Err(format!("the {side} refusal names no address it tried"));
            }
            // The beacon answered this punch, so the refusal must not mention it at all: the
            // addresses are the whole answer.
            if failure.to_string().contains("beacon") {
                return Err(format!(
                    "the {side} refusal names the beacon, which answered: {failure}"
                ));
            }
        }
        Ok(())
    })
}

/// A network that blocks UDP entirely: the beacon is unreachable, and that is what is reported
/// — with both facts the crate cannot rule out.
pub(crate) fn udp_blocked_entirely_names_the_beacon() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let left = sim.machine_behind(Nat::full_cone()).map_err(io_error)?;
        let peer = sim.machine().map_err(io_error)?;
        left.records()
            .record_pairing(&peer.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        sim.link().silence(left.addr());
        let manager = Connections::new(
            &left.identity,
            left.records(),
            Some(beacon.client(&left)?),
            sim.clock().runtime(),
            &left.transport,
        )
        .map_err(|error| error.to_string())?;
        let endpoint = left.endpoint().map_err(|error| error.to_string())?;
        let answer = within(
            &sim,
            Duration::from_secs(120),
            manager.connect(&endpoint, &peer.fingerprint()),
        )
        .await?;
        match answer {
            Err(ConnectFailure::BeaconUnreachable { cause, .. }) => {
                if !cause.contains("block UDP") {
                    return Err(format!(
                        "the refusal does not name the other cause it cannot rule out: {cause}"
                    ));
                }
                if cause.contains("does not know") {
                    return Err(format!(
                        "the refusal claims the beacon answered when it did not: {cause}"
                    ));
                }
            }
            other => {
                return Err(format!(
                    "a machine whose UDP is blocked entirely answered {other:?}, not that the \
                     beacon is unreachable"
                ));
            }
        }
        Ok(())
    })
}

/// A candidate that arrived from the peer is filtered — a loopback one always, a private one
/// unless the product declared an address in the same RFC 1918 block — while the caller's hint
/// is dialled as it stands.
pub(crate) fn a_candidate_from_the_network_is_filtered() -> Result<(), String> {
    block_on(async {
        // A loopback candidate is refused; the same address as a caller's hint is dialled.
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let left = sim.machine_behind(Nat::full_cone()).map_err(io_error)?;
        let right = sim.machine_behind(Nat::full_cone()).map_err(io_error)?;
        let bait: SocketAddr = "127.0.0.1:9".parse().expect("a valid address");
        let prepared = prepare(&sim, &beacon, left, right, false).await?;
        prepared.right_manager.declares([bait]);
        let mark = sim.link().trace().len();
        let punched = run(&sim, prepared).await?;
        if sim.link().trace()[mark..]
            .iter()
            .any(|event| event.to == bait)
        {
            return Err("a loopback candidate the peer named was dialled".to_owned());
        }
        let mark = sim.link().trace().len();
        let _ = within(
            &sim,
            Duration::from_secs(60),
            punched.left_manager.connect_with(
                &punched.left_endpoint,
                &punched.right.fingerprint(),
                Some(bait),
            ),
        )
        .await?;
        if !sim.link().trace()[mark..]
            .iter()
            .any(|event| event.to == bait)
        {
            return Err("the caller's hint was filtered, and it must not be".to_owned());
        }
        // A private candidate is refused without a declared address in its block ...
        for (declared, dialled) in [(None, false), (Some("10.9.9.8:1"), true)] {
            let sim = Sim::new().map_err(io_error)?;
            let beacon = TestBeacon::start(&sim).map_err(io_error)?;
            let left = sim.machine_behind(Nat::full_cone()).map_err(io_error)?;
            let right = sim.machine_behind(Nat::full_cone()).map_err(io_error)?;
            let private: SocketAddr = "10.9.9.9:1".parse().expect("a valid address");
            let prepared = prepare(&sim, &beacon, left, right, false).await?;
            prepared.right_manager.declares([private]);
            if let Some(declared) = declared {
                prepared
                    .left_manager
                    .declares([declared.parse().expect("a valid address")]);
            }
            let mark = sim.link().trace().len();
            let _ = run(&sim, prepared).await?;
            let reached = sim.link().trace()[mark..]
                .iter()
                .any(|event| event.to == private);
            if reached != dialled {
                return Err(format!(
                    "a private candidate was {} with the product declaring {declared:?}",
                    if reached { "dialled" } else { "refused" }
                ));
            }
        }
        Ok(())
    })
}

/// The address list is newest first, bounded at `MAX_REMEMBERED_ADDRESSES`, and an older
/// build's single-address update lands at its head.
pub(crate) fn the_address_list_is_newest_first_and_bounded() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;
        let peer = sim.machine().map_err(io_error)?;
        let store = machine.records();
        store
            .record_pairing(&peer.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        let addresses: Vec<SocketAddr> = (1..=6)
            .map(|last| SocketAddr::from(([10, 0, 0, last], 41_000)))
            .collect();
        for address in &addresses {
            store
                .record_address(&peer.peer_id(), *address)
                .map_err(|error| error.to_string())?;
        }
        let record = machine
            .reopen_records()
            .map_err(|error| error.to_string())?
            .get(&peer.peer_id())
            .ok_or("the record vanished")?;
        let expected: Vec<SocketAddr> = addresses.iter().rev().take(4).copied().collect();
        if record.addresses() != expected.as_slice() {
            return Err(format!(
                "the list is {:?}, not the newest four {:?}",
                record.addresses(),
                expected
            ));
        }
        if record.last_address() != Some(addresses[5]) {
            return Err(format!(
                "the single address is {:?}, not the newest",
                record.last_address()
            ));
        }
        // An older build writes only the single-address field: its update is the newest one and
        // the list a newer build wrote survives behind it.
        let older = SocketAddr::from(([10, 0, 0, 7], 41_000));
        let mut body = vec![4];
        body.extend_from_slice(&[10, 0, 0, 7]);
        body.extend_from_slice(&41_000u16.to_be_bytes());
        let mut bytes = b"mahbot-peer-record".to_vec();
        bytes.push(1);
        bytes.extend_from_slice(&super::support::field(0x01, peer.peer_id().as_bytes()));
        bytes.extend_from_slice(&super::support::field(0x03, &body));
        bytes.extend_from_slice(&super::support::field(0x04, &[0]));
        machine
            .storage()
            .write_record(&peer.peer_id(), &bytes)
            .map_err(io_error)?;
        let record = machine
            .reopen_records()
            .map_err(|error| error.to_string())?
            .get(&peer.peer_id())
            .ok_or("the record vanished")?;
        if record.addresses() != [older] {
            return Err(format!(
                "a record with one single address reads as {:?}",
                record.addresses()
            ));
        }
        store
            .record_address(&peer.peer_id(), addresses[5])
            .map_err(|error| error.to_string())?;
        let record = machine
            .reopen_records()
            .map_err(|error| error.to_string())?
            .get(&peer.peer_id())
            .ok_or("the record vanished")?;
        if record.addresses() != [addresses[5], older] {
            return Err(format!(
                "an older build's address did not compose with the list: {:?}",
                record.addresses()
            ));
        }
        // A list and a single address that disagree: the single address is the older build's
        // newest, so it goes in front and the list keeps its own order behind it.
        let listed = [addresses[1], addresses[2]];
        let mut body = vec![4];
        body.extend_from_slice(&[10, 0, 0, 7]);
        body.extend_from_slice(&41_000u16.to_be_bytes());
        let mut list =
            vec![u8::try_from(listed.len()).expect("a case names at most 255 addresses")];
        for address in &listed {
            let SocketAddr::V4(v4) = address else {
                return Err("the case's list is not IPv4".to_owned());
            };
            list.push(4);
            list.extend_from_slice(&v4.ip().octets());
            list.extend_from_slice(&v4.port().to_be_bytes());
        }
        let mut bytes = b"mahbot-peer-record".to_vec();
        bytes.push(1);
        bytes.extend_from_slice(&super::support::field(0x01, peer.peer_id().as_bytes()));
        bytes.extend_from_slice(&super::support::field(0x03, &body));
        bytes.extend_from_slice(&super::support::field(0x04, &[0]));
        bytes.extend_from_slice(&super::support::field(0x0c, &list));
        machine
            .storage()
            .write_record(&peer.peer_id(), &bytes)
            .map_err(io_error)?;
        let record = machine
            .reopen_records()
            .map_err(|error| error.to_string())?
            .get(&peer.peer_id())
            .ok_or("the record vanished")?;
        let expected = [older, listed[0], listed[1]];
        if record.addresses() != expected {
            return Err(format!(
                "a single address that disagreed with the list read as {:?}, not {:?}",
                record.addresses(),
                expected
            ));
        }
        Ok(())
    })
}

/// A coordination payload is never handed to a ceremony, and an unrecognised payload is not
/// either: only a ceremony flight reaches the ceremony waiting for that peer.
pub(crate) fn a_coordination_payload_never_reaches_a_ceremony() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let target = sim.machine().map_err(io_error)?;
        let presence = keep_findable(&sim, &beacon, &target).await?;
        let sender = sim.machine().map_err(io_error)?;
        let claim = presence.flights(sender.peer_id());
        let woken = Woken::default();
        if poll_once(claim.next(), &woken).is_ready() {
            return Err("a claim was handed a payload before anything was pushed".to_owned());
        }
        push(
            &sim,
            &beacon,
            &sender,
            &target,
            &coordination_payload(&["198.51.100.7:1".parse().expect("a valid address")]),
        )
        .await?;
        sim.clock().advance(Duration::from_secs(2)).await;
        if woken.wakes() != 0 {
            return Err("a coordination payload woke a ceremony".to_owned());
        }
        push(
            &sim,
            &beacon,
            &sender,
            &target,
            b"not a payload this build knows",
        )
        .await?;
        sim.clock().advance(Duration::from_secs(2)).await;
        if woken.wakes() != 0 {
            return Err("an unrecognised payload woke a ceremony".to_owned());
        }
        // The control: a real ceremony flight reaches the same claim.
        let (_, opening) = mahbot_peers::peer::Ceremony::initiate(
            sender.peer_id(),
            target.fingerprint(),
            None,
            false,
        )
        .map_err(|error| error.to_string())?;
        push(&sim, &beacon, &sender, &target, &opening).await?;
        sim.clock().advance(Duration::from_secs(2)).await;
        let flight = within(&sim, Duration::from_secs(30), claim.next()).await?;
        if flight.payload() != opening.as_slice() {
            return Err("the claim took something other than the ceremony flight".to_owned());
        }
        Ok(())
    })
}

/// A coordination payload re-arms a waiting pair's next dial at most once per `PUNCH_REARM`,
/// and never a pair whose episode is used up.
///
/// Every dial of the episode fails in one round trip — the beacon has no registration for the
/// peer and the record remembers no address — so the pair is back in its wait a few milliseconds
/// after a re-arm. That is what makes the interval testable: a dial that waited out the ten-second
/// budget would put the next payload outside the interval, and the duplicate would legitimately
/// re-arm, which is a different rule.
pub(crate) fn a_coordination_payload_rearms_a_wait_at_most_once() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let left = sim.machine().map_err(io_error)?;
        let peer = sim.machine().map_err(io_error)?;
        // The payloads come from the peer and are signed by it; the peer registers nothing, so
        // the punch's lookup answers "not registered" in one round trip.
        left.records()
            .record_pairing(&peer.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        let left_presence = keep_findable(&sim, &beacon, &left).await?;
        let left_presence = Arc::new(left_presence);
        let manager = Arc::new(
            Connections::new(
                &left.identity,
                left.records(),
                Some(beacon.client(&left)?),
                sim.clock().runtime(),
                &left.transport,
            )
            .map_err(|error| error.to_string())?
            .with_presence(Arc::clone(&left_presence)),
        );
        let endpoint = left.endpoint().map_err(|error| error.to_string())?;
        let accept = tokio::spawn(Arc::clone(&manager).serve(endpoint.clone()));
        let keeper = tokio::spawn({
            let manager = Arc::clone(&manager);
            let endpoint = endpoint.clone();
            let peer = peer.fingerprint();
            async move { manager.keep_connected(&endpoint, &peer).await }
        });
        // The fourth dial of the episode: its wait is the eight-second gap.
        let (dial, until) = within(&sim, Duration::from_secs(120), async {
            loop {
                if let Recovery::Waiting {
                    dial,
                    until,
                    last: Some(ConnectFailure::PeerUnknown { .. }),
                    ..
                } = manager.recovery(&peer.peer_id())
                    && dial >= 4
                {
                    return (dial, until);
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;
        // A payload re-arms it now, not at the wait's own moment.
        push(
            &sim,
            &beacon,
            &peer,
            &left,
            &coordination_payload(&["127.0.0.1:1".parse().expect("a valid address")]),
        )
        .await?;
        let (next, next_until) = within(&sim, Duration::from_secs(30), async {
            loop {
                if let Recovery::Waiting {
                    dial: later, until, ..
                } = manager.recovery(&peer.peer_id())
                    && later > dial
                {
                    return (later, until);
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;
        if sim.clock().now() >= until {
            return Err(format!(
                "the payload re-armed the pair at {:?}, not before the wait at {until:?}",
                sim.clock().now()
            ));
        }
        // A duplicate immediately does not re-arm it again: the interval has not passed, so the
        // moment the pair is waiting for is the one the first payload produced. A re-arm would
        // move it to now, which is strictly earlier.
        push(
            &sim,
            &beacon,
            &peer,
            &left,
            &coordination_payload(&["127.0.0.1:1".parse().expect("a valid address")]),
        )
        .await?;
        sim.clock().advance(Duration::from_secs(1)).await;
        match manager.recovery(&peer.peer_id()) {
            Recovery::Waiting {
                dial: still,
                until: moment,
                ..
            } if still == next => {
                if moment != next_until {
                    return Err(format!(
                        "a duplicate payload re-armed the pair again: the wait moved to {moment:?}, \
                         not {next_until:?}"
                    ));
                }
            }
            other => {
                return Err(format!(
                    "a duplicate payload changed the pair's state: it now reads `{other}`"
                ));
            }
        }
        // An exhausted episode is not re-armed at all: the slow re-check is not a punch cadence.
        let exhausted = within(&sim, Duration::from_secs(600), async {
            loop {
                if let state @ Recovery::Exhausted { .. } = manager.recovery(&peer.peer_id()) {
                    return state;
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;
        push(
            &sim,
            &beacon,
            &peer,
            &left,
            &coordination_payload(&["127.0.0.1:2".parse().expect("a valid address")]),
        )
        .await?;
        sim.clock().advance(Duration::from_secs(1)).await;
        if manager.recovery(&peer.peer_id()) != exhausted {
            return Err(format!(
                "a payload moved a used-up episode: it now reads `{}`",
                manager.recovery(&peer.peer_id())
            ));
        }
        keeper.abort();
        accept.abort();
        endpoint.close(0u32.into(), b"the case is done");
        Ok(())
    })
}

/// A beacon that answered without an address — it speaks another version — is not called
/// unreachable, and the refusal does not name a network that blocks UDP, which the answer has
/// just ruled out.
pub(crate) fn a_beacon_that_answered_is_not_unreachable() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let left = sim.machine().map_err(io_error)?;
        let peer = sim.machine().map_err(io_error)?;
        left.records()
            .record_pairing(&peer.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        // A rogue at the beacon's key that refuses every request under another version: the
        // handshake succeeds, so only the protocol can say what happened.
        let rogue = RogueBeacon::start(
            &sim,
            beacon.identity(),
            Rogue::Reply(Response::Refused(Refusal::VersionMismatch).encode()),
        )
        .map_err(|error| error.to_string())?;
        let manager = Connections::new(
            &left.identity,
            left.records(),
            Some(Beacon::new(
                left.endpoint().map_err(|error| error.to_string())?,
                sim.clock().runtime(),
                rogue.address(),
                beacon.key(),
                left.identity.clone(),
            )),
            sim.clock().runtime(),
            &left.transport,
        )
        .map_err(|error| error.to_string())?;
        let endpoint = left.endpoint().map_err(|error| error.to_string())?;
        let answer = within(
            &sim,
            Duration::from_secs(120),
            manager.connect(&endpoint, &peer.fingerprint()),
        )
        .await?;
        let Err(failure) = answer else {
            return Err("a beacon that refused the lookup answered a connection".to_owned());
        };
        let ConnectFailure::BeaconUnreachable { cause, .. } = &failure else {
            return Err(format!(
                "a beacon that answered was reported as `{failure}`, not as the beacon's answer"
            ));
        };
        if !cause.contains("refused") {
            return Err(format!("the cause is not the beacon's answer: {cause}"));
        }
        // The one cause it has just ruled out: the beacon was reached.
        for (what, text) in [
            ("cause", cause.as_str()),
            ("sentence", &failure.to_string()),
        ] {
            if text.contains("block UDP") {
                return Err(format!(
                    "the {what} names a blocked network after the beacon answered: {text}"
                ));
            }
        }
        Ok(())
    })
}

/// A key that is not the peer's, at an address the record remembered, is its own answer: a
/// security fact and not a network one, and not a claim that the peer is out of reach.
///
/// The same answer is owed when the pair came up while this dial was trying — the peer's own dial
/// reached this machine first — because the pair being up says nothing about the address that
/// answered with another machine's key. That is the one case where "it worked out" would be a
/// lie, and the second half of this case is it.
pub(crate) fn a_wrong_key_is_its_own_answer() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let left = sim.machine().map_err(io_error)?;
        let peer = sim.machine().map_err(io_error)?;
        let impostor = sim.machine().map_err(io_error)?;
        // This machine paired with both, so the handshake completes and the key it proves is
        // what says whose connection it is. The record for the peer remembers the impostor's
        // address, as a stale mapping would.
        for other in [&peer, &impostor] {
            left.records()
                .record_pairing(&other.peer_id(), NOW)
                .map_err(|error| error.to_string())?;
            impostor
                .records()
                .record_pairing(&left.peer_id(), NOW)
                .map_err(|error| error.to_string())?;
        }
        left.records()
            .record_address(&peer.peer_id(), impostor.addr())
            .map_err(|error| error.to_string())?;
        // The impostor answers the handshake — it is a machine this one trusts, so only the key
        // it proves can say it is not the peer.
        let impostor_manager = Arc::new(
            Connections::new(
                &impostor.identity,
                impostor.records(),
                None,
                sim.clock().runtime(),
                &impostor.transport,
            )
            .map_err(|error| error.to_string())?,
        );
        let impostor_endpoint = impostor.endpoint().map_err(|error| error.to_string())?;
        let accept = tokio::spawn(Arc::clone(&impostor_manager).serve(impostor_endpoint.clone()));
        let manager = Arc::new(
            Connections::new(
                &left.identity,
                left.records(),
                Some(beacon.client(&left)?),
                sim.clock().runtime(),
                &left.transport,
            )
            .map_err(|error| error.to_string())?,
        );
        let endpoint = left.endpoint().map_err(|error| error.to_string())?;
        let serve = tokio::spawn(Arc::clone(&manager).serve(endpoint.clone()));
        let answer = within(
            &sim,
            Duration::from_secs(120),
            manager.connect(&endpoint, &peer.fingerprint()),
        )
        .await?;
        // The refusal a person reads is pinned here the way the other two refusals' texts are: the
        // variants' fields are checked below, and the sentence is what a product shows.
        let sentence = match &answer {
            Err(failure) => failure.to_string(),
            Ok(_) => {
                return Err("an address that proved another machine's key was reached".to_owned());
            }
        };
        let expected = format!(
            "the address {} proved {}, not {}: something other than the peer is at an address \
             this machine was told is the peer's",
            impostor.addr(),
            impostor.fingerprint(),
            peer.fingerprint()
        );
        if sentence != expected {
            return Err(format!("the refusal reads {sentence:?}, not {expected:?}"));
        }
        match answer {
            Err(ConnectFailure::WrongPeer {
                peer: asked,
                presented,
                address,
            }) => {
                if asked != peer.fingerprint() {
                    return Err(format!("the refusal names {asked}, not the peer asked for"));
                }
                if presented != impostor.fingerprint() {
                    return Err(format!(
                        "the refusal names {presented}, not the key that answered"
                    ));
                }
                if address != impostor.addr() {
                    return Err(format!(
                        "the refusal names {address}, not the address that answered"
                    ));
                }
            }
            other => {
                return Err(format!(
                    "an address that proved another machine's key was reported as {other:?}"
                ));
            }
        }
        // The record's claim about that address has been disproved, so it is no longer
        // remembered: the answer is given once, not on every later call.
        let record = left
            .reopen_records()?
            .get(&peer.peer_id())
            .ok_or("the peer's record vanished")?;
        if record.addresses().contains(&impostor.addr()) {
            return Err(format!(
                "the record still remembers {}, which proved another machine's key",
                impostor.addr()
            ));
        }
        // The second half: the peer's own dial reaches this machine while this one is still
        // trying the impostor's address. The pair comes up, and the wrong key is still the
        // answer — the two entry points agree, and neither drops the fact. The record has
        // dropped the address that answered with another machine's key, so it is written
        // again here: a stale mapping is learned again the way it was learned the first time.
        left.records()
            .record_address(&peer.peer_id(), impostor.addr())
            .map_err(|error| error.to_string())?;
        peer.records()
            .record_pairing(&left.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        peer.records()
            .record_address(&left.peer_id(), left.addr())
            .map_err(|error| error.to_string())?;
        let peer_manager = Arc::new(
            Connections::new(
                &peer.identity,
                peer.records(),
                Some(beacon.client(&peer)?),
                sim.clock().runtime(),
                &peer.transport,
            )
            .map_err(|error| error.to_string())?,
        );
        let peer_endpoint = peer.endpoint().map_err(|error| error.to_string())?;
        let peer_serve = tokio::spawn(Arc::clone(&peer_manager).serve(peer_endpoint.clone()));
        let asked = peer.fingerprint();
        let mine = left.fingerprint();
        // The peer's own dial reaches this machine first, so the pair is up before this one
        // starts trying the impostor's address: the fact has to survive a pair that is already
        // connected, which is the case "it worked out" would hide.
        within(
            &sim,
            Duration::from_secs(120),
            peer_manager.connect(&peer_endpoint, &mine),
        )
        .await?
        .map_err(|failure| format!("the peer's own dial answered {failure}"))?;
        within(&sim, Duration::from_secs(30), async {
            loop {
                if manager.live(&peer.peer_id()).is_some() {
                    return Ok::<_, String>(());
                }
                tokio::task::yield_now().await;
            }
        })
        .await??;
        let answer = within(
            &sim,
            Duration::from_secs(120),
            manager.connect(&endpoint, &asked),
        )
        .await?;
        match answer {
            Err(ConnectFailure::WrongPeer { .. }) => {}
            other => {
                return Err(format!(
                    "the wrong key was dropped while the pair was up: {other:?}"
                ));
            }
        }
        // And the pair is not refused for it: the answer is the wrong key, not a teardown.
        if manager.live(&peer.peer_id()).is_none() {
            return Err("the wrong key's answer took the pair's connection with it".to_owned());
        }
        serve.abort();
        peer_serve.abort();
        accept.abort();
        endpoint.close(0u32.into(), b"the case is done");
        peer_endpoint.close(0u32.into(), b"the case is done");
        impostor_endpoint.close(0u32.into(), b"the case is done");
        Ok(())
    })
}

/// The wrong key is the answer a pace call gives too, when the pair came up while its own dial
/// was still trying.
///
/// [`Connections::ensure`] answers `Connected` with no failure while the pair already holds a
/// connection, so its half of the contract is only observable through a dial that brings the pair
/// up itself: one remembered address answers with another machine's key and the other completes a
/// handshake with the peer. Both dials run in the one call, so the pair is up when the call is
/// judged, and the security fact is still reported beside the connected state.
pub(crate) fn the_wrong_key_reaches_a_pair_that_came_up_while_dialling() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let left = sim.machine().map_err(io_error)?;
        let peer = sim.machine().map_err(io_error)?;
        let impostor = sim.machine().map_err(io_error)?;
        // This machine paired with both, and both with this one, so each handshake completes and
        // only the key it proves says whose connection it is.
        for other in [&peer, &impostor] {
            left.records()
                .record_pairing(&other.peer_id(), NOW)
                .map_err(|error| error.to_string())?;
            other
                .records()
                .record_pairing(&left.peer_id(), NOW)
                .map_err(|error| error.to_string())?;
        }
        // The one dial's set: the peer's own address, which answers with the peer's key, and the
        // impostor's, which a stale mapping left in the record.
        for address in [peer.addr(), impostor.addr()] {
            left.records()
                .record_address(&peer.peer_id(), address)
                .map_err(|error| error.to_string())?;
        }
        let manager = Arc::new(
            Connections::new(
                &left.identity,
                left.records(),
                None,
                sim.clock().runtime(),
                &left.transport,
            )
            .map_err(|error| error.to_string())?,
        );
        let endpoint = left.endpoint().map_err(|error| error.to_string())?;
        let mut tasks = vec![tokio::spawn(Arc::clone(&manager).serve(endpoint.clone()))];
        for machine in [&peer, &impostor] {
            let serving = Arc::new(
                Connections::new(
                    &machine.identity,
                    machine.records(),
                    None,
                    sim.clock().runtime(),
                    &machine.transport,
                )
                .map_err(|error| error.to_string())?,
            );
            let serving_endpoint = machine.endpoint().map_err(|error| error.to_string())?;
            tasks.push(tokio::spawn(
                Arc::clone(&serving).serve(serving_endpoint.clone()),
            ));
        }
        let (state, failure) = within(
            &sim,
            Duration::from_secs(120),
            manager.ensure(&endpoint, &peer.fingerprint()),
        )
        .await?;
        if state != Recovery::Connected {
            return Err(format!(
                "the pace call answered {state:?} for a pair its own dial connected"
            ));
        }
        match failure {
            Some(ConnectFailure::WrongPeer {
                peer: asked,
                presented,
                address,
            }) => {
                if asked != peer.fingerprint()
                    || presented != impostor.fingerprint()
                    || address != impostor.addr()
                {
                    return Err(format!(
                        "the pace call named {asked} / {presented} / {address}, not the peer, the \
                         key that answered and its address"
                    ));
                }
            }
            other => {
                return Err(format!(
                    "a wrong key met while the pair came up was answered as {other:?}"
                ));
            }
        }
        if manager.live(&peer.peer_id()).is_none() {
            return Err("the wrong key's answer took the pair's connection with it".to_owned());
        }
        // The address that proved the other machine's key is gone from the record, so the next
        // pace call does not meet it again; the peer's own address stays.
        let record = left
            .reopen_records()?
            .get(&peer.peer_id())
            .ok_or("the peer's record vanished")?;
        if record.addresses() != [peer.addr()] {
            return Err(format!(
                "the record remembers {:?}, not the peer's own address alone",
                record.addresses()
            ));
        }
        for task in &tasks {
            task.abort();
        }
        endpoint.close(0u32.into(), b"the case is done");
        Ok(())
    })
}

/// Every candidate the peer names is dialled at once and the pair still ends with exactly one
/// connection.
pub(crate) fn several_dials_end_with_one_connection() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right) = sim
            .machines_behind_one(Nat::full_cone().with_hairpin(true))
            .map_err(io_error)?;
        let punched = punch(&sim, &beacon, left, right, true).await?;
        let (left_live, right_live) = one_connection(&punched)?;
        // Both sides dialled two addresses: the peer's external one and its declared local one.
        let right_local = punched.right.addr();
        let left_local = punched.left.addr();
        let trace = sim.link().trace();
        let left_dialled_local = trace
            .iter()
            .any(|event| event.from == left_local && event.to == right_local);
        let right_dialled_local = trace
            .iter()
            .any(|event| event.from == right_local && event.to == left_local);
        if !left_dialled_local || !right_dialled_local {
            return Err(
                "each side did not dial the other's declared address beside its external one"
                    .to_owned(),
            );
        }
        // The two halves are one connection: a word crosses it.
        sim.clock().advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        within(
            &sim,
            Duration::from_secs(10),
            super::support::round_trip(&left_live, &right_live),
        )
        .await??;
        // And the set is exactly the two addresses it was given: several dials, one connection.
        // A dial that leaves the network is traced under the network's address, the one that
        // stays inside it under the machine's own, so both are the left's.
        let left_external = sim
            .link()
            .external(left_local)
            .ok_or("the left's network made no mapping")?;
        let dialled: std::collections::BTreeSet<SocketAddr> = trace
            .iter()
            .filter(|event| {
                (event.from == left_local || event.from == left_external)
                    && event.to != beacon.address()
            })
            .map(|event| event.to)
            .collect();
        if dialled.len() != 2 {
            return Err(format!(
                "one punch dialled {} addresses, not the two it was given (the peer's external one and its declared local one)",
                dialled.len()
            ));
        }
        Ok(())
    })
}

/// Three handshakes complete at once and the pair still ends with one connection.
///
/// One identity answering at three addresses is three machines sharing a key — [`Sim::clone_of`],
/// the same way a restored backup is — and the left remembers all three, so one dial dials them
/// together. The trace shows each of the three answering the left, which is three completed
/// handshakes and not one live address beside dead ones; the tie-break then has to leave exactly
/// one, so the left keeps one and closes the other two, and the two machines whose connections it
/// closed hold nothing afterwards.
pub(crate) fn more_than_two_completed_dials_end_with_one_connection() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let left = sim.machine().map_err(io_error)?;
        let first = sim.machine().map_err(io_error)?;
        let second = sim.clone_of(&first).map_err(io_error)?;
        let third = sim.clone_of(&first).map_err(io_error)?;
        let identity = first.peer_id();
        let peer = first.fingerprint();
        left.records()
            .record_pairing(&identity, NOW)
            .map_err(|error| error.to_string())?;
        for copy in [&first, &second, &third] {
            copy.records()
                .record_pairing(&left.peer_id(), NOW)
                .map_err(|error| error.to_string())?;
            // The one dial's set: every address the left remembers for that identity.
            left.records()
                .record_address(&identity, copy.addr())
                .map_err(|error| error.to_string())?;
        }
        let manager = Arc::new(
            Connections::new(
                &left.identity,
                left.records(),
                None,
                sim.clock().runtime(),
                &left.transport,
            )
            .map_err(|error| error.to_string())?,
        );
        let endpoint = left.endpoint().map_err(|error| error.to_string())?;
        let mut tasks = vec![tokio::spawn(Arc::clone(&manager).serve(endpoint.clone()))];
        let mut copies = Vec::new();
        for copy in [first, second, third] {
            let manager = Arc::new(
                Connections::new(
                    &copy.identity,
                    copy.records(),
                    None,
                    sim.clock().runtime(),
                    &copy.transport,
                )
                .map_err(|error| error.to_string())?,
            );
            let endpoint = copy.endpoint().map_err(|error| error.to_string())?;
            tasks.push(tokio::spawn(Arc::clone(&manager).serve(endpoint.clone())));
            copies.push((copy, manager, endpoint));
        }
        let kept = within(&sim, Duration::from_secs(60), async {
            manager.connect(&endpoint, &peer).await
        })
        .await?
        .map_err(|failure| format!("the dial of three addresses answered {failure}"))?;
        if manager.live(&identity).is_none() {
            return Err("the dial answered a connection the pair does not hold".to_owned());
        }
        // Three handshakes, not one: every copy answered the left, and a copy answers only a
        // handshake it is part of.
        let trace = sim.link().trace();
        let left_address = left.addr();
        for (copy, _, _) in &copies {
            if !trace
                .iter()
                .any(|event| event.from == copy.addr() && event.to == left_address)
            {
                return Err(format!(
                    "{} never answered a handshake, so fewer than three completed",
                    copy.addr()
                ));
            }
        }
        // Every copy adopts its own handshake and the left's two closes reach them: the clock is
        // stepped until the pair has settled on one, bounded so a case that never settles fails
        // rather than spending its budget on steps.
        let holds =
            |copy: &(Machine, Arc<Connections>, Endpoint)| copy.1.live(&left.peer_id()).is_some();
        let settled = sim
            .clock()
            .advance_until(Duration::from_secs(10), Duration::from_millis(100), || {
                copies.iter().filter(|copy| holds(copy)).count() == 1
            })
            .await;
        let holding: Vec<&(Machine, Arc<Connections>, Endpoint)> =
            copies.iter().filter(|copy| holds(copy)).collect();
        if !settled {
            return Err(format!(
                "three handshakes completed and {} of the three machines still hold a \
                 connection after ten seconds of virtual time, not one",
                holding.len()
            ));
        }
        // The surviving copy holds the same connection the left kept: a word crosses it.
        let survivor = holding[0]
            .1
            .live(&left.peer_id())
            .ok_or("the surviving machine lost its connection between two reads")?;
        within(
            &sim,
            Duration::from_secs(10),
            super::support::round_trip(&kept, &survivor),
        )
        .await??;
        for task in &tasks {
            task.abort();
        }
        endpoint.close(0u32.into(), b"the case is done");
        for (_, _, copy_endpoint) in &copies {
            copy_endpoint.close(0u32.into(), b"the case is done");
        }
        Ok(())
    })
}

/// A candidate list past the ceiling is not a list this build reads: the whole payload is
/// dropped, and the punch dials only what the beacon observed. At the ceiling, the eight
/// candidates one side dials still end the pair with exactly one connection per side.
pub(crate) fn the_candidate_ceiling_is_enforced() -> Result<(), String> {
    block_on(async {
        for (count, expected) in [
            (
                mahbot_peers::peer::MAX_CANDIDATES,
                mahbot_peers::peer::MAX_CANDIDATES,
            ),
            (mahbot_peers::peer::MAX_CANDIDATES + 1, 1),
        ] {
            let sim = Sim::new().map_err(io_error)?;
            let beacon = TestBeacon::start(&sim).map_err(io_error)?;
            let left = sim.machine_behind(Nat::full_cone()).map_err(io_error)?;
            let right = sim.machine_behind(Nat::full_cone()).map_err(io_error)?;
            let prepared = prepare(&sim, &beacon, left, right, false).await?;
            let candidates = dead_addresses(count);
            push(
                &sim,
                &beacon,
                &prepared.right,
                &prepared.left,
                &coordination_payload(&candidates),
            )
            .await?;
            // The presence reader is a task: it needs the runtime to run before the punch reads
            // what it stored.
            within(&sim, Duration::from_secs(5), async {
                for _ in 0..32 {
                    tokio::task::yield_now().await;
                }
            })
            .await?;
            let left_external = sim
                .link()
                .external(prepared.left.addr())
                .ok_or("the left's network made no mapping")?;
            let left_local = prepared.left.addr();
            let mark = sim.link().trace().len();
            let punched = run(&sim, prepared).await?;
            // However many candidates one side dials, the pair ends with exactly one connection
            // each — the ceiling case is also the several-dials case, at the ceiling.
            one_connection(&punched)?;
            // Everything the left sent except to the beacon is a candidate dial; its source on
            // the wire is the network's address, or its own for a dial the network drops at its
            // external side, and either is what identifies it.
            let dialled: std::collections::BTreeSet<SocketAddr> = sim.link().trace()[mark..]
                .iter()
                .filter(|event| {
                    (event.from == left_external || event.from == left_local)
                        && event.to != beacon.address()
                })
                .map(|event| event.to)
                .collect();
            if dialled.len() != expected {
                return Err(format!(
                    "a payload naming {count} candidates made the punch dial {} addresses, not \
                     {expected}",
                    dialled.len()
                ));
            }
        }
        Ok(())
    })
}

/// A candidate list is not sent to a peer while a ceremony with that peer is running: an older
/// build would end its ceremony on a payload outside its closed set.
///
/// The observable is the peer's own dial set: the left declares a distinctive address, and the
/// right — which punches at the same time — dials it only when the left's candidate list reached
/// it. The control is the same pair with no ceremony running, where the right does dial it.
pub(crate) fn coordination_is_not_sent_while_a_ceremony_runs() -> Result<(), String> {
    block_on(async {
        for ceremony in [true, false] {
            let sim = Sim::new().map_err(io_error)?;
            let beacon = TestBeacon::start(&sim).map_err(io_error)?;
            let left = sim.machine_behind(Nat::full_cone()).map_err(io_error)?;
            let right = sim.machine_behind(Nat::full_cone()).map_err(io_error)?;
            let left_records = left.records();
            let right_records = right.records();
            for (store, peer) in [
                (&left_records, right.peer_id()),
                (&right_records, left.peer_id()),
            ] {
                store
                    .record_pairing(&peer, NOW)
                    .map_err(|error| error.to_string())?;
            }
            let right_presence = keep_findable(&sim, &beacon, &right).await?;
            let left_presence = Arc::new(keep_findable(&sim, &beacon, &left).await?);
            // With `ceremony`, the left is comparing with the right for as long as the claim is
            // held, and the manager shares the same registration.
            let claim = ceremony.then(|| left_presence.flights(right.peer_id()));
            let left_manager = Arc::new(
                Connections::new(
                    &left.identity,
                    left_records,
                    Some(beacon.client(&left)?),
                    sim.clock().runtime(),
                    &left.transport,
                )
                .map_err(|error| error.to_string())?
                .with_presence(Arc::clone(&left_presence)),
            );
            let left_endpoint = left.endpoint().map_err(|error| error.to_string())?;
            let _accept = tokio::spawn(Arc::clone(&left_manager).serve(left_endpoint.clone()));
            let right_manager = Arc::new(
                Connections::new(
                    &right.identity,
                    right_records,
                    Some(beacon.client(&right)?),
                    sim.clock().runtime(),
                    &right.transport,
                )
                .map_err(|error| error.to_string())?
                .with_presence(Arc::new(right_presence)),
            );
            let right_endpoint = right.endpoint().map_err(|error| error.to_string())?;
            let _right_accept =
                tokio::spawn(Arc::clone(&right_manager).serve(right_endpoint.clone()));
            // The left declares a distinctive address; the right dials it only if the left's
            // candidate list reached it.
            let bait: SocketAddr = "198.51.100.77:1".parse().expect("a valid address");
            left_manager.declares([bait]);
            let (left_dials, right_dials) = (right.fingerprint(), left.fingerprint());
            let mark = sim.link().trace().len();
            let _ = within(&sim, Duration::from_secs(180), async {
                tokio::join!(
                    left_manager.connect(&left_endpoint, &left_dials),
                    right_manager.connect(&right_endpoint, &right_dials),
                )
            })
            .await?;
            let dialled = sim.link().trace()[mark..]
                .iter()
                .any(|event| event.to == bait);
            if dialled != !ceremony {
                return Err(format!(
                    "with a ceremony {}, the peer {} the candidate list",
                    if ceremony { "running" } else { "not running" },
                    if dialled {
                        "received"
                    } else {
                        "never received"
                    }
                ));
            }
            drop(claim);
        }
        Ok(())
    })
}

/// A pairing that was started and never finished does not hold the punch off: a held opening whose
/// sender has given up is not a running ceremony, so the candidate exchange goes ahead once it is
/// older than a machine waits for the other side's flight.
///
/// The left never polls `openings()`, so nothing but the flight's own age can take the held opening
/// away — which is what a person who starts a pairing, walks away and never confirms leaves behind.
pub(crate) fn a_stale_opening_does_not_hold_the_punch_off() -> Result<(), String> {
    block_on(async {
        for stale in [false, true] {
            let sim = Sim::new().map_err(io_error)?;
            let beacon = TestBeacon::start(&sim).map_err(io_error)?;
            let left = sim.machine_behind(Nat::full_cone()).map_err(io_error)?;
            let right = sim.machine_behind(Nat::full_cone()).map_err(io_error)?;
            let prepared = prepare(&sim, &beacon, left, right, false).await?;
            // The left declares a distinctive address; the right dials it only if the left's
            // candidate list reached it.
            let bait: SocketAddr = "198.51.100.78:1".parse().expect("a valid address");
            prepared.left_manager.declares([bait]);
            // The right starts a pairing and walks away: its opening is held by the left's reader,
            // and the left's person never looks at it.
            super::presence::push_opening(&sim, &beacon, &prepared.right, &prepared.left).await?;
            sim.clock()
                .advance(if stale {
                    PAIR_FLIGHT_TIMEOUT + Duration::from_secs(1)
                } else {
                    Duration::from_secs(2)
                })
                .await;
            let mark = sim.link().trace().len();
            let _punched = run(&sim, prepared).await?;
            let dialled = sim.link().trace()[mark..]
                .iter()
                .any(|event| event.to == bait);
            if dialled == !stale {
                return Err(format!(
                    "with the opening {}, the peer {} the candidate list",
                    if stale { "stale" } else { "fresh" },
                    if dialled {
                        "received"
                    } else {
                        "never received"
                    }
                ));
            }
        }
        Ok(())
    })
}

/// A punch that tries many candidates is one dial of the recovery episode, not one per
/// candidate: eight addresses that answer nothing spend one dial, not eight.
pub(crate) fn a_punch_of_many_candidates_is_one_dial() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let left = sim.machine_behind(Nat::full_cone()).map_err(io_error)?;
        let peer = sim.machine_behind(Nat::full_cone()).map_err(io_error)?;
        left.records()
            .record_pairing(&peer.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        let peer_presence = keep_findable(&sim, &beacon, &peer).await?;
        let left_presence = keep_findable(&sim, &beacon, &left).await?;
        let manager = Connections::new(
            &left.identity,
            left.records(),
            Some(beacon.client(&left)?),
            sim.clock().runtime(),
            &left.transport,
        )
        .map_err(|error| error.to_string())?
        .with_presence(Arc::new(left_presence));
        let endpoint = left.endpoint().map_err(|error| error.to_string())?;
        // Eight candidates that answer nothing, and the peer's own observed address blocked:
        // the punch has nowhere to reach the peer.
        let candidates = dead_addresses(mahbot_peers::peer::MAX_CANDIDATES);
        push(
            &sim,
            &beacon,
            &peer,
            &left,
            &coordination_payload(&candidates),
        )
        .await?;
        within(&sim, Duration::from_secs(5), async {
            for _ in 0..32 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        let peer_external = sim
            .link()
            .external(peer.addr())
            .ok_or("the peer's network made no mapping")?;
        sim.link().blocks(left.addr(), peer_external);
        let (state, failure) = within(
            &sim,
            Duration::from_secs(120),
            manager.ensure(&endpoint, &peer.fingerprint()),
        )
        .await?;
        match state {
            Recovery::Waiting { dial: 1, .. } | Recovery::Exhausted { dials: 1, .. } => {}
            other => {
                return Err(format!(
                    "a punch of {} candidates counted `{other}` / `{failure:?}`, not one dial \
                     of the episode",
                    candidates.len()
                ));
            }
        }
        drop(peer_presence);
        endpoint.close(0u32.into(), b"the case is done");
        Ok(())
    })
}

/// A handshake that completed and whose connection the pair did not keep is not a network
/// failure: the refusal says so, and carries no advice to change networks.
///
/// The rig stages it at the far side's accept, which is deterministic rather than a race between
/// two handshakes: the right's endpoint policy admits the left's certificate, so the handshake
/// completes, while its record knows nothing of the left, so its accept closes the connection the
/// moment it takes it. An address that answers nothing keeps the punch's dial set alive past that
/// close, so the close is known before the pair is asked what it kept.
pub(crate) fn a_completed_handshake_the_pair_did_not_keep_is_not_a_network_failure()
-> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let left = sim.machine().map_err(io_error)?;
        let right = sim.machine().map_err(io_error)?;
        // The left trusts the right, and the right's endpoint trusts the left's certificate, so
        // the handshake completes; the right's record still knows nothing of the left, so its
        // accept closes what the handshake proved.
        left.records()
            .record_pairing(&right.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        right.trust(&left);
        let dead: SocketAddr = "198.51.100.91:1".parse().expect("a valid address");
        left.records()
            .record_address(&right.peer_id(), dead)
            .map_err(|error| error.to_string())?;
        let _right_presence = keep_findable(&sim, &beacon, &right).await?;
        let right_manager = Arc::new(
            Connections::new(
                &right.identity,
                right.records(),
                None,
                sim.clock().runtime(),
                &right.transport,
            )
            .map_err(|error| error.to_string())?,
        );
        let right_endpoint = right.endpoint().map_err(|error| error.to_string())?;
        let right_accept = tokio::spawn(Arc::clone(&right_manager).serve(right_endpoint.clone()));
        let left_presence = Arc::new(keep_findable(&sim, &beacon, &left).await?);
        // The peer's candidate list, handed over the way a punch hands it: the same address that
        // answers nothing, so the punch's set outlives the peer's close.
        push(&sim, &beacon, &right, &left, &coordination_payload(&[dead])).await?;
        let manager = Arc::new(
            Connections::new(
                &left.identity,
                left.records(),
                Some(beacon.client(&left)?),
                sim.clock().runtime(),
                &left.transport,
            )
            .map_err(|error| error.to_string())?
            .with_presence(Arc::clone(&left_presence)),
        );
        let endpoint = left.endpoint().map_err(|error| error.to_string())?;
        let accept = tokio::spawn(Arc::clone(&manager).serve(endpoint.clone()));
        let answer = within(
            &sim,
            Duration::from_secs(120),
            manager.connect(&endpoint, &right.fingerprint()),
        )
        .await?;
        let failure = match answer {
            Err(failure) => failure,
            Ok(_) => {
                return Err("a peer that closed every handshake answered a connection".to_owned());
            }
        };
        let ConnectFailure::NoDirectPath {
            candidates, cause, ..
        } = &failure
        else {
            return Err(format!("the refusal is {failure:?}, not no direct path"));
        };
        if !cause.contains("an address completed a handshake") {
            return Err(format!(
                "the cause does not name the handshake that completed: {cause}"
            ));
        }
        if candidates.is_empty() {
            return Err("the refusal names no address it tried".to_owned());
        }
        // The network worked: one handshake completed and the pair kept none of it. Naming a
        // blocked network, or advising another one, would name a cause this dial has ruled out.
        let sentence = failure.to_string();
        if sentence.contains("block UDP") || sentence.contains("another network") {
            return Err(format!(
                "a completed handshake is refused as a blocked network: {sentence}"
            ));
        }
        accept.abort();
        right_accept.abort();
        endpoint.close(0u32.into(), b"the case is done");
        right_endpoint.close(0u32.into(), b"the case is done");
        Ok(())
    })
}

/// A peer this machine no longer trusts cannot turn a coordination payload into a dial.
///
/// The payload path is shown working first, while the pair is trusted: the same push ends the
/// wait and the keeper dials. Only then does a person withdraw trust, and the next push must
/// produce no datagram to the peer at all — the pair stops naming the withdrawal instead.
///
/// Two lines hold that, and this case witnesses the second: the re-arm's own trust check refuses
/// the payload as it arrives, and the keeper reads the record again at the top of its next round
/// and stops before dialling. The assertions below hold on the keeper's read alone, so the case
/// pins the rule rather than the check that enforces it first.
pub(crate) fn a_withdrawn_peer_s_payload_causes_no_dial() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let left = sim.machine().map_err(io_error)?;
        let right = sim.machine().map_err(io_error)?;
        left.records()
            .record_pairing(&right.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        // The right registers, so the beacon has an address for it; nothing serves that address,
        // so every dial the left makes fails and the pair waits.
        let _right_presence = keep_findable(&sim, &beacon, &right).await?;
        let left_presence = Arc::new(keep_findable(&sim, &beacon, &left).await?);
        let manager = Arc::new(
            Connections::new(
                &left.identity,
                left.records(),
                Some(beacon.client(&left)?),
                sim.clock().runtime(),
                &left.transport,
            )
            .map_err(|error| error.to_string())?
            .with_presence(Arc::clone(&left_presence)),
        );
        let endpoint = left.endpoint().map_err(|error| error.to_string())?;
        let keeper = tokio::spawn({
            let manager = Arc::clone(&manager);
            let endpoint = endpoint.clone();
            let peer = right.fingerprint();
            async move { manager.keep_connected(&endpoint, &peer).await }
        });
        let bait: SocketAddr = "198.51.100.92:1".parse().expect("a valid address");
        // The moment the pair is first waiting for; the second wait below is told from it.
        wait_for_state(
            &sim,
            &manager,
            &right.peer_id(),
            "a wait for the next dial",
            |state| matches!(state, Recovery::Waiting { .. }),
        )
        .await?;
        let Recovery::Waiting { until: first, .. } = manager.recovery(&right.peer_id()) else {
            return Err("the pair stopped waiting between two reads".to_owned());
        };
        // The path works: the same push ends the wait, and the keeper dials.
        push(&sim, &beacon, &right, &left, &coordination_payload(&[bait])).await?;
        wait_for_state(
            &sim,
            &manager,
            &right.peer_id(),
            "a dial after a payload",
            |state| matches!(state, Recovery::Dialling { .. }),
        )
        .await?;
        // The payload re-armed the pair: the keeper dials, fails, and waits for a moment it was
        // not waiting for before.
        wait_for_state(
            &sim,
            &manager,
            &right.peer_id(),
            "a second wait after a payload",
            |state| matches!(state, Recovery::Waiting { until, .. } if *until != first),
        )
        .await?;
        // A person withdraws trust while the keeper waits again. The re-arm interval has long
        // passed — the dial took longer than it — so trust is the only thing left to refuse it.
        left.rights()
            .map_err(|error| error.to_string())?
            .withdraw_trust(&right.peer_id(), super::rights::person("egor")?, NOW)
            .map_err(|error| error.to_string())?;
        let mark = sim.link().trace().len();
        push(&sim, &beacon, &right, &left, &coordination_payload(&[bait])).await?;
        wait_for_state(
            &sim,
            &manager,
            &right.peer_id(),
            "a stop naming the withdrawal",
            |state| {
                matches!(
                    state,
                    Recovery::Stopped {
                        cause: StopCause::NotTrusted(NotTrustedCause::Withdrawn),
                    }
                )
            },
        )
        .await?;
        // The beacon relaying the payload to the peer is not a dial: only this machine's own
        // endpoint sending to the peer's address is.
        let dialled = sim.link().trace()[mark..]
            .iter()
            .any(|event| event.from == left.addr() && event.to == right.addr());
        if dialled {
            return Err("a withdrawn peer's payload caused a dial".to_owned());
        }
        keeper.abort();
        endpoint.close(0u32.into(), b"the case is done");
        Ok(())
    })
}

/// A refusal is answered as itself even when the pair holds a connection: a live connection does
/// not change a decision this machine made, and the refusal does not take it down.
pub(crate) fn a_refusal_is_answered_beside_a_live_connection() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let left = sim.machine().map_err(io_error)?;
        let right = sim.machine().map_err(io_error)?;
        for (store, peer) in [
            (left.records(), right.peer_id()),
            (right.records(), left.peer_id()),
        ] {
            store
                .record_pairing(&peer, NOW)
                .map_err(|error| error.to_string())?;
        }
        // No beacon: the record's address is the whole path, so the pair is connected before
        // anything is withdrawn.
        left.records()
            .record_address(&right.peer_id(), right.addr())
            .map_err(|error| error.to_string())?;
        let right_manager = Arc::new(
            Connections::new(
                &right.identity,
                right.records(),
                None,
                sim.clock().runtime(),
                &right.transport,
            )
            .map_err(|error| error.to_string())?,
        );
        let right_endpoint = right.endpoint().map_err(|error| error.to_string())?;
        let right_accept = tokio::spawn(Arc::clone(&right_manager).serve(right_endpoint.clone()));
        let manager = Arc::new(
            Connections::new(
                &left.identity,
                left.records(),
                None,
                sim.clock().runtime(),
                &left.transport,
            )
            .map_err(|error| error.to_string())?,
        );
        let endpoint = left.endpoint().map_err(|error| error.to_string())?;
        let accept = tokio::spawn(Arc::clone(&manager).serve(endpoint.clone()));
        within(
            &sim,
            Duration::from_secs(60),
            manager.connect(&endpoint, &right.fingerprint()),
        )
        .await?
        .map_err(|failure| format!("the first dial answered {failure}"))?;
        // A person withdraws trust; no keeper runs, so the connection stays live.
        left.rights()
            .map_err(|error| error.to_string())?
            .withdraw_trust(&right.peer_id(), super::rights::person("egor")?, NOW)
            .map_err(|error| error.to_string())?;
        let answer = within(
            &sim,
            Duration::from_secs(60),
            manager.connect(&endpoint, &right.fingerprint()),
        )
        .await?;
        match answer {
            Err(ConnectFailure::NotTrusted { .. }) => {}
            other => {
                return Err(format!(
                    "a refusal beside a live connection answered {other:?}, not itself"
                ));
            }
        }
        if manager.live(&right.peer_id()).is_none() {
            return Err("the refusal took the pair's live connection with it".to_owned());
        }
        accept.abort();
        right_accept.abort();
        endpoint.close(0u32.into(), b"the case is done");
        right_endpoint.close(0u32.into(), b"the case is done");
        Ok(())
    })
}

/// Step the clock until the pair's recovery reads something `matches` accepts, bounded so a case
/// that never gets there fails instead of spending its budget on steps.
async fn wait_for_state(
    sim: &Sim,
    connections: &Connections,
    peer: &mahbot_peers::identity::PeerId,
    what: &str,
    matches: impl Fn(&Recovery) -> bool,
) -> Result<(), String> {
    let reached = sim
        .clock()
        .advance_until(Duration::from_secs(300), Duration::from_millis(100), || {
            matches(&connections.recovery(peer))
        })
        .await;
    if reached {
        return Ok(());
    }
    Err(format!(
        "the pair never reached {what}: it reads `{}` after five minutes of virtual time",
        connections.recovery(peer)
    ))
}
