//! The action layer over the link: the connection it shares with messages, the format's own
//! answers on the wire, the throttle, the beacon's silence, the dial a request makes, and what
//! the keeper makes of a dial that carried an action.
//!
//! Every case runs over the simulated link and the injected clock, and every execution is read
//! from the [`Executions`](crate::actions::Executions) rig the machine's layer was built with.
//! An action travels over the pair's own direct connection, on the same stream reader a message
//! uses; nothing here opens a socket or starts a process.
//!
//! # What a case may not assume
//!
//! The layer reads no clock, so a window or a budget is measured in [`NOW`] plus the virtual
//! time the case has moved, and a case that advances the clock advances it for both machines.
//! A dial is slow only because the link is: silencing an address is what makes a request wait,
//! never a sleep.

use std::sync::Arc;
use std::time::Duration;

use mahbot_peers::peer::{
    ACTION_BUDGET, ACTION_WINDOW, Act, ActionAnswer, ActionError, ActionKind, Authority,
    Capability, ConnectFailure, EXECUTION_BUDGET, MAX_ACTION_BODY_BYTES, MAX_ACTIONS_PER_WINDOW,
    NoFloor, Recovery,
};
#[cfg(unix)]
use mahbot_peers::peer::{ActionId, DIAL_BUDGET, TRUST_POLL};

use crate::beacon::TestBeacon;
use crate::clock::block_on;
use crate::link::{Fault, FaultPlan, Rates};
use crate::messages::{Messaging, wait_for};
use crate::sim::Sim;

use super::super::connection::Managed;
use super::super::peer::session;
use super::super::rights::{label, person};
#[cfg(unix)]
use super::super::support::Ready;
use super::super::support::counted_dial;
use super::super::support::{
    field, io_error, main_binding, pair, single_ending, socket, spawn_keeper, wait_live, within,
};
use super::{
    ACTION_MAGIC, ACTION_VERSION, LONG, NOW, id, offer_bytes, ran_with, ready, request,
    wait_for_executions,
};

/// The bytes every answer frame opens with.
const ANSWER_MAGIC: &[u8] = b"mahbot-peer-action-answer";

/// A request frame: the magic, this build's version and the fields a case writes.
fn frame(fields: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = ACTION_MAGIC.to_vec();
    bytes.push(ACTION_VERSION);
    for field in fields {
        bytes.extend_from_slice(field);
    }
    bytes
}

/// A message and an action travel the one connection the pair holds, in both directions, over
/// a link that drops and reorders: the receiver's message sink is handed the message and its
/// executor the action, and neither is taken for the other.
pub(crate) fn a_message_and_an_action_share_one_connection() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        // The laptop's claim names the main's pair; "write to me" on that side is what lets
        // the main's message reach the laptop, the same right the receiver's decision asks.
        ready
            .laptop
            .rights()?
            .grant(
                &pair(&ready.main, &label("admin")?),
                Capability::WRITE,
                Authority::Person(person("egor")?),
                None,
                NOW,
            )
            .map_err(|error| error.to_string())?;
        // Losses and reordering on the one connection both layers use.
        sim.link().set_plan(FaultPlan::Seeded {
            seed: 7,
            rates: Rates {
                drop: 5,
                delay: 5,
                duplicate: 0,
                reorder: 10,
            },
        });
        ready
            .laptop_messages
            .messages
            .send(&ready.main.peer_id(), NOW, b"a message")
            .map_err(|error| error.to_string())?;
        ready
            .main_messages
            .messages
            .send(&ready.laptop.peer_id(), NOW, b"a message")
            .map_err(|error| error.to_string())?;
        ready.main_messages.executions.run(b"done");
        ready.laptop_messages.executions.run(b"other");
        ready
            .laptop_messages
            .serve(&ready.laptop_managed.connections, &ready.main);
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        let there = within(&sim, LONG, request(&ready, id(1), b"a command")).await??;
        if !ran_with(&there, b"done") {
            return Err(format!(
                "the action the laptop sent was answered `{there:?}`"
            ));
        }
        let back = within(
            &sim,
            LONG,
            ready.main_messages.actions.request(
                &ready.main_managed.connections,
                &ready.main_managed.endpoint,
                &ready.laptop.peer_id(),
                id(2),
                ActionKind::COMMAND,
                b"a command",
            ),
        )
        .await?
        .map_err(|error| error.to_string())?;
        if !ran_with(&back, b"other") {
            return Err(format!("the action the main sent was answered `{back:?}`"));
        }
        let delivered = wait_for(&sim, &ready.main_messages.collected, 1, LONG).await?;
        if delivered[0].body != b"a message" || delivered[0].sender != ready.laptop.peer_id() {
            return Err(format!(
                "the main's message sink was handed `{}` from {}",
                String::from_utf8_lossy(&delivered[0].body),
                delivered[0].sender.fingerprint()
            ));
        }
        let returned = wait_for(&sim, &ready.laptop_messages.collected, 1, LONG).await?;
        if returned[0].body != b"a message" || returned[0].sender != ready.main.peer_id() {
            return Err(format!(
                "the laptop's message sink was handed `{}` from {}",
                String::from_utf8_lossy(&returned[0].body),
                returned[0].sender.fingerprint()
            ));
        }
        let handed = wait_for_executions(&sim, &ready.main_messages.executions, 1, LONG).await?;
        if handed.len() != 1 || handed[0].id != id(1) {
            return Err(format!(
                "the main's own code was handed {} actions, not the one the laptop sent",
                handed.len()
            ));
        }
        let handed_back =
            wait_for_executions(&sim, &ready.laptop_messages.executions, 1, LONG).await?;
        if handed_back.len() != 1 || handed_back[0].id != id(2) {
            return Err(format!(
                "the laptop's own code was handed {} actions, not the one the main sent",
                handed_back.len()
            ));
        }
        Ok(())
    })
}

/// A request the receiver cannot read is answered unreadable and runs nothing: an identifier
/// that is not sixteen bytes, a frame with no kind, a frame longer than the frame cap and a body
/// over its own cap inside a frame that is short enough are each refused by name, and the
/// receiver's own code is handed nothing.
pub(crate) fn a_malformed_action_is_answered_unreadable() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        ready.main_messages.executions.run(b"done");
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        let connection = wait_live(
            &sim,
            &ready.laptop_managed.connections,
            &ready.main.peer_id(),
        )
        .await?;
        // The identifier must be sixteen bytes, the kind is required, and the frame is read
        // whole or not at all.
        let mut oversized = ACTION_MAGIC.to_vec();
        oversized.push(ACTION_VERSION);
        oversized.extend_from_slice(&vec![b'x'; MAX_ACTION_BODY_BYTES * 2]);
        let shapes = [
            frame(&[field(0x01, b"abc")]),
            frame(&[field(0x01, id(9).as_bytes()), field(0x03, b"a body")]),
            oversized,
            // A body one byte over its own cap, inside a frame the receiver can still read
            // whole: the body field refuses it, not the frame's length.
            frame(&[
                field(0x01, id(8).as_bytes()),
                field(0x02, &[1]),
                field(0x03, &vec![b'x'; MAX_ACTION_BODY_BYTES + 1]),
            ]),
        ];
        for bytes in shapes {
            let answer = within(&sim, LONG, offer_bytes(&connection, &bytes)).await??;
            if answer != ActionAnswer::Unreadable {
                return Err(format!(
                    "{} bytes the receiver cannot read were answered `{answer:?}`, not unreadable",
                    bytes.len()
                ));
            }
        }
        if ready.main_messages.executions.count() != 0 {
            return Err(format!(
                "the receiver's own code was handed {} actions from frames it could not read",
                ready.main_messages.executions.count()
            ));
        }
        let entries = ready
            .main
            .audit()?
            .entries()
            .map_err(|error| error.to_string())?;
        if entries
            .iter()
            .any(|entry| matches!(entry.act, Act::ActionExecuted { .. }))
        {
            return Err("an action nobody could read was recorded as executed".to_owned());
        }
        Ok(())
    })
}

/// A peer's slow-down delay never reaches this machine uncapped: a frame naming the largest
/// delay a `u32` can hold is read as one window, as the message layer clamps the same value.
pub(crate) fn a_retry_after_is_clamped_to_one_window() -> Result<(), String> {
    let mut bytes = ANSWER_MAGIC.to_vec();
    bytes.push(ACTION_VERSION);
    bytes.extend_from_slice(&field(0x01, &[9]));
    bytes.extend_from_slice(&field(0x04, &u32::MAX.to_be_bytes()));
    let answer = ActionAnswer::decode(&bytes).map_err(|error| error.to_string())?;
    let ActionAnswer::SlowDown { retry_after } = answer else {
        return Err(format!(
            "a slow-down frame was decoded as `{answer:?}`, not a slow-down"
        ));
    };
    if retry_after > ACTION_WINDOW {
        return Err(format!(
            "a peer's delay of {} seconds was handed over as {retry_after:?}, past one {ACTION_WINDOW:?} window",
            u32::MAX
        ));
    }
    Ok(())
}

/// A flood of actions is throttled with a delay the sender is told, and the same peer's
/// messages are unaffected: the window is the action layer's own, so a throttle there is not
/// a message refused.
pub(crate) fn a_flood_of_actions_is_throttled_and_messages_are_unaffected() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        ready.main_messages.executions.run(b"ok");
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        let allowed = MAX_ACTIONS_PER_WINDOW as usize;
        for n in 1..=allowed {
            let outcome = within(&sim, LONG, request(&ready, id(n as u64), b"an action")).await??;
            if !ran_with(&outcome, b"ok") {
                return Err(format!(
                    "action {n} of the window was answered `{outcome:?}`, not a run"
                ));
            }
        }
        let throttled = within(
            &sim,
            LONG,
            request(&ready, id(allowed as u64 + 1), b"an action"),
        )
        .await??;
        let ActionAnswer::SlowDown { retry_after } = throttled else {
            return Err(format!(
                "the action past the window was answered `{throttled:?}`, not a slow-down"
            ));
        };
        if retry_after > ACTION_WINDOW {
            return Err(format!(
                "the sender was told to wait {retry_after:?}, past one {ACTION_WINDOW:?} window"
            ));
        }
        // Only an answer that means the receiver accepted the operation is the pair's traffic.
        // The slow-down took nothing, so the take count stays at the actions that ran.
        let traffic = ready
            .laptop_managed
            .connections
            .traffic(&ready.main.peer_id())
            .ok_or("the pair has no live connection after the flood")?;
        if traffic.taken() != allowed as u64 || traffic.rounds() != 0 {
            return Err(format!(
                "a slow-down after {allowed} accepted actions is measured as {} takes and {} rounds, not {allowed} takes and no round",
                traffic.taken(),
                traffic.rounds()
            ));
        }
        if ready.main_messages.executions.count() != allowed {
            return Err(format!(
                "the receiver's code was handed {} actions, not the {allowed} its window allows",
                ready.main_messages.executions.count()
            ));
        }
        // The message layer counts its own window, so the flood of actions leaves a message
        // beside it untouched.
        ready
            .laptop_messages
            .serve(&ready.laptop_managed.connections, &ready.main);
        ready
            .laptop_messages
            .messages
            .send(&ready.main.peer_id(), NOW, b"a message beside the flood")
            .map_err(|error| error.to_string())?;
        let delivered = wait_for(&sim, &ready.main_messages.collected, 1, LONG).await?;
        if delivered[0].body != b"a message beside the flood" {
            return Err(format!(
                "the message beside the flood arrived as `{}`",
                String::from_utf8_lossy(&delivered[0].body)
            ));
        }
        let entries = ready
            .laptop
            .audit()?
            .entries()
            .map_err(|error| error.to_string())?;
        if entries
            .iter()
            .any(|entry| matches!(entry.act, Act::MessageRefused { .. }))
        {
            return Err("a throttle of actions was recorded as a message refusal".to_owned());
        }
        Ok(())
    })
}

/// The beacon carries no action: with both machines registered and the beacon alive, an action
/// travels over the pair's own path and the beacon's memory holds neither its identifier nor
/// its body; with the beacon killed, the next action still runs.
pub(crate) fn the_beacon_never_carries_an_action() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        // Both machines keep themselves findable, so the beacon's memory is not empty and the
        // claim is about what it holds, not about a server nobody ever spoke to.
        let _main_session = session(&beacon, &ready.main).await?;
        let _laptop_session = session(&beacon, &ready.laptop).await?;
        ready.main_messages.executions.run(b"done");
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        let body = b"a body the beacon must never hold".to_vec();
        let first = within(&sim, LONG, request(&ready, id(1), &body)).await??;
        if !ran_with(&first, b"done") {
            return Err(format!("the action was answered `{first:?}`, not a run"));
        }
        // Read while the beacon is alive and the action has already travelled.
        let registry = beacon.registry();
        let rendered = registry
            .lock()
            .expect("the beacon's registry is not poisoned")
            .render(sim.clock().elapsed());
        if rendered.is_empty() {
            return Err(
                "the beacon remembers nothing, so the case would prove nothing about it".to_owned(),
            );
        }
        let hex = id(1).to_string();
        if rendered.contains(hex.as_str()) {
            return Err(format!("the beacon holds the action's identifier {hex}"));
        }
        let text = String::from_utf8_lossy(&body);
        if rendered.contains(text.as_ref()) {
            return Err("the beacon holds the action's body".to_owned());
        }
        // And it is not on the path: with the beacon killed, the next action still runs.
        beacon.kill();
        let second = within(&sim, LONG, request(&ready, id(2), b"a second command")).await??;
        if !ran_with(&second, b"done") {
            return Err(format!(
                "an action asked while the beacon was gone was answered `{second:?}`, not a run"
            ));
        }
        if ready.main_messages.executions.count() != 2 {
            return Err(format!(
                "the receiver's own code was handed {} actions, not the two the case asked for",
                ready.main_messages.executions.count()
            ));
        }
        if ready.keeper.is_finished() {
            return Err("a pair whose beacon is gone lost its keeper".to_owned());
        }
        Ok(())
    })
}

/// An action asked while the pair is away waits for the dial: the request is in flight, the
/// receiver's code has been handed nothing, and the action runs once the path is back.
pub(crate) fn an_action_asked_while_the_pair_is_away_waits_for_the_dial() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        // The request is the only dialer, so the case sees its dial and not the keeper's.
        ready.keeper.abort();
        ready.main_messages.executions.run(b"done");
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        // The pair's connection goes, and the close is delivered before the link starts dropping:
        // the receiver must not keep a closed connection the new dial would lose to.
        ready
            .laptop_managed
            .connections
            .disconnect(&ready.main.peer_id());
        sim.clock().advance(Duration::from_secs(1)).await;
        sim.clock().settle().await;
        // The next three datagrams are dropped, so the request's handshake is still pending when
        // the case looks: the action waits for the dial rather than being held anywhere. Three
        // is inside the connect budget, so the dial then completes.
        sim.link()
            .set_plan(FaultPlan::Scripted(vec![vec![Fault::Drop]; 3]));
        let actions = Arc::clone(&ready.laptop_messages.actions);
        let connections = Arc::clone(&ready.laptop_managed.connections);
        let endpoint = ready.laptop_managed.endpoint.clone();
        let peer = ready.main.peer_id();
        let asked = tokio::spawn(async move {
            actions
                .request(
                    &connections,
                    &endpoint,
                    &peer,
                    id(1),
                    ActionKind::COMMAND,
                    b"a command",
                )
                .await
                .map_err(|error| error.to_string())
        });
        sim.clock().advance(Duration::from_secs(2)).await;
        if asked.is_finished() {
            return Err("the request finished while the dial could not reach the peer".to_owned());
        }
        if ready.main_messages.executions.count() != 0 {
            return Err("an action ran before the pair was connected".to_owned());
        }
        let outcome = within(&sim, LONG, asked)
            .await?
            .map_err(|error| format!("the request's task did not finish: {error}"))??;
        if !ran_with(&outcome, b"done") {
            return Err(format!(
                "the action asked while the pair was away was answered `{outcome:?}`, not a run"
            ));
        }
        if ready.main_messages.executions.count() != 1 {
            return Err(format!(
                "the receiver's own code was handed {} actions, not the one the case asked for",
                ready.main_messages.executions.count()
            ));
        }
        Ok(())
    })
}

/// A failed dial holds nothing: the ask is answered with the dial's own failure, no mark is
/// written, and nothing is queued for a later dial.
pub(crate) fn a_failed_dial_holds_nothing() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        ready.main_messages.executions.run(b"done");
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        // Nothing dials for this pair and the address answers nothing: the ask meets the
        // dial's failure instead of being held.
        ready
            .laptop_managed
            .connections
            .disconnect(&ready.main.peer_id());
        ready.keeper.abort();
        sim.link().silence(ready.main.addr());
        let asked = within(&sim, LONG, request(&ready, id(1), b"a command")).await?;
        let text = match asked {
            Err(text) => text,
            Ok(outcome) => {
                return Err(format!(
                    "an action nothing could carry was answered `{outcome:?}`"
                ));
            }
        };
        if !text.contains("the action could not be sent") {
            return Err(format!("the failed dial is reported as `{text}`"));
        }
        let marks = ready
            .laptop_messages
            .actions
            .unknown(&ready.main.peer_id())
            .map_err(|error| error.to_string())?;
        if !marks.is_empty() {
            return Err(format!(
                "a failed dial left {} marks on the sender's memory",
                marks.len()
            ));
        }
        if ready.main_messages.executions.count() != 0 {
            return Err("an action nothing carried still ran on the receiver".to_owned());
        }
        sim.link().resume(ready.main.addr());
        Ok(())
    })
}

/// An action a person asks for against a peer that is not there is answered with the pair's
/// own failure, and the ask costs one dial rather than a dial a second.
///
/// The pair's connection is taken away and the peer's address is silenced, so the ask's dial
/// spends the connect budget and the beacon then says the peer is not registered: the answer
/// is [`ActionError::Connect`] naming that failure — not a bare "nothing was ready" — and the
/// pair made the one dial, which is what the layer's wait on the policy's own moment is for.
pub(crate) fn an_action_to_a_peer_that_is_not_there_names_the_failure() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        // The ask is the only dialer, so the dials the pair makes are the ones it spent.
        ready.keeper.abort();
        ready
            .laptop_managed
            .connections
            .disconnect(&ready.main.peer_id());
        sim.clock().advance(Duration::from_secs(1)).await;
        sim.clock().settle().await;
        // Nothing addressed to the peer arrives, and no registration names it either.
        sim.link().silence(ready.main.addr());
        let actions = Arc::clone(&ready.laptop_messages.actions);
        let connections = Arc::clone(&ready.laptop_managed.connections);
        let endpoint = ready.laptop_managed.endpoint.clone();
        let peer = ready.main.peer_id();
        let asked = tokio::spawn(async move {
            actions
                .request(
                    &connections,
                    &endpoint,
                    &peer,
                    id(1),
                    ActionKind::COMMAND,
                    b"a command",
                )
                .await
        });
        let answered = within(&sim, LONG, asked)
            .await?
            .map_err(|error| format!("the request's task did not finish: {error}"))?;
        match &answered {
            Err(ActionError::Connect(ConnectFailure::PeerUnknown { peer, cause }))
                if *peer == ready.main.fingerprint() =>
            {
                if cause.is_empty() {
                    return Err("the failure names no cause for the dial".to_owned());
                }
            }
            other => {
                return Err(format!(
                    "an action to a peer that is not there was answered `{other:?}`, not the \
                     pair's own failure"
                ));
            }
        }
        // One dial, not one a second: the ask waited on the policy's own moment instead of
        // polling with a dial each time.
        match ready
            .laptop_managed
            .connections
            .recovery(&ready.main.peer_id())
        {
            Recovery::Waiting { dial: 1, .. } => {}
            other => {
                return Err(format!(
                    "one ask left the pair reading `{other}`, not the one dial it made"
                ));
            }
        }
        let marks = ready
            .laptop_messages
            .actions
            .unknown(&ready.main.peer_id())
            .map_err(|error| error.to_string())?;
        if !marks.is_empty() {
            return Err(format!(
                "an ask that never left left {} marks on the sender's memory",
                marks.len()
            ));
        }
        if ready.main_messages.executions.count() != 0 {
            return Err("an action nothing carried still ran on the receiver".to_owned());
        }
        sim.link().resume(ready.main.addr());
        Ok(())
    })
}

/// A slow execution is unknown to its own sender and does not hold the pair: another pair's
/// action runs on the same machine while the first is still running, and the first is answered
/// unknown when its budget passes.
pub(crate) fn a_slow_execution_is_unknown_and_another_pair_is_unaffected() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        // A third machine paired with the main by records alone.
        let third = sim.machine().map_err(io_error)?;
        ready
            .main
            .records()
            .record_pairing(&third.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        ready
            .main
            .records()
            .record_address(&third.peer_id(), third.addr())
            .map_err(|error| error.to_string())?;
        third
            .records()
            .record_pairing(&ready.main.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        third
            .records()
            .record_address(&ready.main.peer_id(), ready.main.addr())
            .map_err(|error| error.to_string())?;
        let admin = label("admin")?;
        ready
            .main
            .rights()?
            .bind(&third.peer_id(), main_binding(&admin)?, NOW)
            .map_err(|error| error.to_string())?;
        ready
            .main
            .rights()?
            .grant(
                &pair(&third, &admin),
                Capability::WORK,
                Authority::Person(person("egor")?),
                None,
                NOW,
            )
            .map_err(|error| error.to_string())?;
        let third_managed = Managed::start(&sim, &beacon, &third, &third.records())?;
        let third_messages = Messaging::open(&sim, &third, Arc::new(NoFloor))?;
        let _third_keeper = spawn_keeper(&third_managed, &ready.main);
        wait_live(&sim, &third_managed.connections, &ready.main.peer_id()).await?;
        wait_live(&sim, &ready.main_managed.connections, &third.peer_id()).await?;
        // The main answers both peers, one service each.
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &third);
        ready.main_messages.executions.hold_for(
            &ready.laptop.peer_id(),
            EXECUTION_BUDGET * 2,
            b"slow",
        );
        ready
            .main_messages
            .executions
            .run_for(&third.peer_id(), b"fast");
        // The laptop's action is running when the third's arrives, and the third's is answered
        // while the laptop's is still running.
        let actions = Arc::clone(&ready.laptop_messages.actions);
        let connections = Arc::clone(&ready.laptop_managed.connections);
        let endpoint = ready.laptop_managed.endpoint.clone();
        let peer = ready.main.peer_id();
        let slow = tokio::spawn(async move {
            actions
                .request(
                    &connections,
                    &endpoint,
                    &peer,
                    id(1),
                    ActionKind::COMMAND,
                    b"a slow command",
                )
                .await
                .map_err(|error| error.to_string())
        });
        wait_for_executions(&sim, &ready.main_messages.executions, 1, LONG).await?;
        let fast = within(
            &sim,
            LONG,
            third_messages.actions.request(
                &third_managed.connections,
                &third_managed.endpoint,
                &ready.main.peer_id(),
                id(2),
                ActionKind::COMMAND,
                b"a fast command",
            ),
        )
        .await?
        .map_err(|error| error.to_string())?;
        if !ran_with(&fast, b"fast") {
            return Err(format!(
                "the other pair's action was answered `{fast:?}`, not the run it asked for"
            ));
        }
        // The execution outlived its bound: the receiver answers unknown, which is what the
        // sender is told.
        let slow = within(&sim, EXECUTION_BUDGET + Duration::from_secs(10), slow)
            .await?
            .map_err(|error| format!("the slow request's task did not finish: {error}"))??;
        if slow != ActionAnswer::Unknown {
            return Err(format!(
                "an execution past its budget was answered `{slow:?}`, not unknown"
            ));
        }
        // The receiver could not say whether it ran, so the sender keeps the durable mark: a
        // restart still shows it, and the crate never offers the identifier again by itself.
        let marks = ready
            .laptop_messages
            .actions
            .unknown(&ready.main.peer_id())
            .map_err(|error| error.to_string())?;
        if !marks.iter().any(|mark| mark.id == id(1)) {
            return Err(format!(
                "a receiver-composed unknown left no durable mark: {marks:?}"
            ));
        }
        let repeat = within(&sim, LONG, request(&ready, id(1), b"a slow command")).await?;
        if repeat != Ok(ActionAnswer::Unknown) {
            return Err(format!(
                "a repeat of an unknown identifier was answered `{repeat:?}`, not unknown"
            ));
        }
        if ready.main_messages.executions.count() != 2 {
            return Err(format!(
                "a repeat of an unknown identifier was handed to the receiver's own code ({} executions)",
                ready.main_messages.executions.count()
            ));
        }
        Ok(())
    })
}

/// An action memory that cannot be read ends the service: a memory replaced by bytes that are
/// not one is not an empty memory, so the service stops and hands back the refusal instead of
/// running the action as if nothing had been executed here.
pub(crate) fn an_action_memory_that_cannot_be_read_ends_the_service() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        ready.main_messages.executions.run(b"done");
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        let first = within(&sim, LONG, request(&ready, id(1), b"echo")).await??;
        if !ran_with(&first, b"done") {
            return Err(format!(
                "the first action was answered `{first:?}`, not a run, so the service was \
                 already failing"
            ));
        }
        // The memory is replaced by bytes that are not one, as a damaged file or a lost restore
        // leaves it.
        let name = ready
            .main
            .root
            .action_name(&ready.laptop.peer_id())
            .map_err(io_error)?;
        ready
            .main
            .root
            .write_action(&ready.laptop.peer_id(), b"not an action memory")
            .map_err(io_error)?;
        // The second request is answered nothing: the receiver's service ends on the file.
        let actions = Arc::clone(&ready.laptop_messages.actions);
        let connections = Arc::clone(&ready.laptop_managed.connections);
        let endpoint = ready.laptop_managed.endpoint.clone();
        let peer = ready.main.peer_id();
        let asked = tokio::spawn(async move {
            actions
                .request(
                    &connections,
                    &endpoint,
                    &peer,
                    id(2),
                    ActionKind::COMMAND,
                    b"echo",
                )
                .await
                .map_err(|error| error.to_string())
        });
        let ending = single_ending(&sim, &ready.main_messages, LONG).await?;
        let Err(text) = ending else {
            return Err("a memory that cannot be read ended the service cleanly".to_owned());
        };
        if !text.contains("is not an action memory") || !text.contains(&name) {
            return Err(format!(
                "the service's ending does not name {name}: `{text}`"
            ));
        }
        if ready.main_messages.executions.count() != 1 {
            return Err(format!(
                "the receiver's own code was handed {} actions, not the one it took before the \
                 memory was replaced",
                ready.main_messages.executions.count()
            ));
        }
        asked.abort();
        Ok(())
    })
}

/// An action in flight is not the pair's traffic: a connection closed with a request still
/// unanswered is a dial that carried nothing, so the episode is used up instead of
/// re-dialling for ever — and the keeper keeps running, because the peer may stop doing
/// it.
pub(crate) fn an_action_in_flight_is_not_the_pairs_traffic() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        // The pair's connection came from the laptop's keeper. The case judges its own dials,
        // so the main dials and the laptop only receives; two keepers would reset each other's
        // strikes.
        ready.keeper.abort();
        ready
            .laptop_managed
            .connections
            .disconnect(&ready.main.peer_id());
        let keeper = spawn_keeper(&ready.main_managed, &ready.laptop);
        // The main's inbox is not served: the stream is accepted and nothing answers it.
        let mut asked = Vec::new();
        let connection = wait_live(
            &sim,
            &ready.laptop_managed.connections,
            &ready.main.peer_id(),
        )
        .await?;
        // The sender's own side is ready before the request is made, so the request offers
        // over this connection rather than dialling one of its own.
        let _sent = wait_live(
            &sim,
            &ready.main_managed.connections,
            &ready.laptop.peer_id(),
        )
        .await?;
        let actions = Arc::clone(&ready.main_messages.actions);
        let connections = Arc::clone(&ready.main_managed.connections);
        let endpoint = ready.main_managed.endpoint.clone();
        let peer = ready.laptop.peer_id();
        asked.push(tokio::spawn(async move {
            actions
                .request(
                    &connections,
                    &endpoint,
                    &peer,
                    id(1),
                    ActionKind::COMMAND,
                    b"nobody answers this",
                )
                .await
                .map_err(|error| error.to_string())
        }));
        within(&sim, LONG, connection.accept_bi())
            .await?
            .map_err(|error| error.to_string())?;
        ready
            .laptop_managed
            .connections
            .disconnect(&ready.main.peer_id());
        // The close is one dial of the episode, with the connection that carried nothing
        // as its cause: a request in flight is this machine's own act and not the pair's
        // traffic, so a peer that keeps dropping after one is not mistaken for a live pair.
        let counted = counted_dial(
            &sim,
            &ready.main_managed.connections,
            &ready.laptop.peer_id(),
        )
        .await?;
        if counted == 0 {
            return Err("the close was not counted as a dial of the episode".to_owned());
        }
        if keeper.is_finished() {
            return Err(
                "the keeper stopped after a connection whose only traffic was an unanswered \
                 action"
                    .to_owned(),
            );
        }
        keeper.abort();
        for handle in asked {
            handle.abort();
        }
        Ok(())
    })
}

/// An answered action is the pair's traffic: a connection that carried one and then died is a
/// link failure, so the keeper dials again however often that happens.
pub(crate) fn an_answered_action_is_the_pairs_traffic() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        // The executor takes its time, so the case can read the connection's own measurement
        // while the request is in flight.
        ready
            .main_messages
            .executions
            .hold(EXECUTION_BUDGET / 2, b"done");
        let actions = Arc::clone(&ready.laptop_messages.actions);
        let connections = Arc::clone(&ready.laptop_managed.connections);
        let endpoint = ready.laptop_managed.endpoint.clone();
        let peer = ready.main.peer_id();
        let asked = tokio::spawn(async move {
            actions
                .request(
                    &connections,
                    &endpoint,
                    &peer,
                    id(1),
                    ActionKind::COMMAND,
                    b"echo",
                )
                .await
                .map_err(|error| error.to_string())
        });
        wait_for_executions(&sim, &ready.main_messages.executions, 1, LONG).await?;
        let traffic = ready
            .laptop_managed
            .connections
            .traffic(&ready.main.peer_id())
            .ok_or("the pair has no live connection while its action is in flight")?;
        if traffic.rounds() != 1 || traffic.taken() != 0 {
            return Err(format!(
                "an action in flight is measured as {} rounds and {} takes, not one round and no take",
                traffic.rounds(),
                traffic.taken()
            ));
        }
        let outcome = within(&sim, LONG, asked)
            .await?
            .map_err(|error| error.to_string())??;
        if !ran_with(&outcome, b"done") {
            return Err(format!("the answered action was `{outcome:?}`, not a run"));
        }
        let traffic = ready
            .laptop_managed
            .connections
            .traffic(&ready.main.peer_id())
            .ok_or("the pair lost its connection after the answer")?;
        if traffic.taken() != 1 || traffic.rounds() != 0 {
            return Err(format!(
                "an answered action is measured as {} takes and {} rounds, not one take and no round",
                traffic.taken(),
                traffic.rounds()
            ));
        }
        Ok(())
    })
}

/// A panicking executor ends the service with the bug named, as a panicking delivery sink
/// does: the action may have run, so the sender keeps the identifier's unknown mark and the
/// crate never offers it again.
fn panicking_executor(eager: bool) -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        if eager {
            ready.main_messages.executions.panic_eagerly();
        } else {
            ready.main_messages.executions.panic();
        }
        let outcome = within(&sim, LONG, request(&ready, id(1), b"a command")).await?;
        if outcome != Ok(ActionAnswer::Unknown) {
            return Err(format!(
                "a panicking execution was answered `{outcome:?}`, not unknown"
            ));
        }
        let ending = single_ending(&sim, &ready.main_messages, LONG).await?;
        let Err(text) = ending else {
            return Err("a panicking execution ended the service cleanly".to_owned());
        };
        if !text.contains("panicked") {
            return Err(format!(
                "the service's ending does not name the panic: `{text}`"
            ));
        }
        if ready.main_messages.executions.count() != 1 {
            return Err(format!(
                "the executor was handed {} actions, not one",
                ready.main_messages.executions.count()
            ));
        }
        let marks = ready
            .laptop_messages
            .actions
            .unknown(&ready.main.peer_id())
            .map_err(|error| error.to_string())?;
        if !marks.iter().any(|mark| mark.id == id(1)) {
            return Err(format!(
                "a panicking execution left no unknown mark: {marks:?}"
            ));
        }
        let repeat = within(&sim, LONG, request(&ready, id(1), b"a command")).await?;
        if repeat != Ok(ActionAnswer::Unknown) {
            return Err(format!(
                "a repeat of a panicking execution was answered `{repeat:?}`, not unknown"
            ));
        }
        if ready.main_messages.executions.count() != 1 {
            return Err("a repeat of an unknown identifier reached the executor".to_owned());
        }
        Ok(())
    })
}

/// A panicking executor ends the service with the bug named, and the action is never offered
/// again.
pub(crate) fn a_panicking_executor_ends_the_service() -> Result<(), String> {
    panicking_executor(false)
}

/// An executor that panics before it returns its future ends the service exactly as one that
/// panics while running does.
pub(crate) fn an_eagerly_panicking_executor_ends_the_service() -> Result<(), String> {
    panicking_executor(true)
}

/// A request that never got onto the wire is `not sent`, and this layer keeps no mark for it:
/// the peer's stream credit is exhausted, so the stream cannot be opened before the budget
/// passes; once the credit is back, the same operation runs.
pub(crate) fn a_request_that_never_left_is_not_spent() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        // The receiving machine serves throughout: the claim is about the peer's stream credit,
        // not about a peer that is not listening.
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        let connection = ready
            .laptop_managed
            .connections
            .traffic(&ready.main.peer_id())
            .ok_or("the pair has no live connection")?
            .connection()
            .clone();
        // Hold every bidirectional stream the peer grants; the request's own `open_bi` then
        // waits, and the layer gives up before a byte is written. The ceiling keeps a peer that
        // never stops granting streams from turning this into an unbounded loop.
        let mut held = Vec::new();
        loop {
            match within(&sim, Duration::from_millis(100), connection.open_bi()).await {
                Ok(Ok((send, _recv))) => held.push(send),
                Ok(Err(error)) => return Err(format!("opening a stream failed: {error}")),
                Err(_) => break,
            }
            if held.len() > 1000 {
                return Err("the peer never stopped granting streams".to_owned());
            }
        }
        let refused = within(&sim, LONG, request(&ready, id(1), b"a command")).await?;
        match refused {
            Err(error) if error.contains("may not have left") => {}
            other => {
                return Err(format!(
                    "a starved request was answered `{other:?}`, not `not sent`"
                ));
            }
        }
        let marks = ready
            .laptop_messages
            .actions
            .unknown(&ready.main.peer_id())
            .map_err(|error| error.to_string())?;
        if marks.iter().any(|mark| mark.id == id(1)) {
            return Err("a request that never left was marked unknown".to_owned());
        }
        // The receiver drains the held streams, and the same operation then runs.
        drop(held);
        ready.main_messages.executions.run(b"done");
        let ran = within(&sim, LONG, request(&ready, id(1), b"a command")).await?;
        if !matches!(ran, Ok(ActionAnswer::Ran { .. })) {
            return Err(format!(
                "the same operation after `not sent` was answered `{ran:?}`, not a run"
            ));
        }
        if ready.main_messages.executions.count() != 1 {
            return Err(format!(
                "the receiver's own code was handed {} actions, not one",
                ready.main_messages.executions.count()
            ));
        }
        Ok(())
    })
}

/// One request has one total bound: a dial that spends its connect bound on a dead address
/// leaves the offer only the rest of `ACTION_BUDGET`, so the answer is unknown at the budget's
/// end rather than after another full one.
pub(crate) fn one_request_has_one_total_budget() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        // The main is registered, so the dial after the dead address can find its live one.
        let _main_session = session(&beacon, &ready.main).await?;
        // The laptop's only remembered address for the main is dead: the dial spends its whole
        // connect bound on it before the beacon names the live one.
        ready
            .laptop
            .records()
            .record_address(&ready.main.peer_id(), socket(9999))
            .map_err(|error| error.to_string())?;
        ready
            .laptop_managed
            .connections
            .disconnect(&ready.main.peer_id());
        ready.keeper.abort();
        sim.clock().advance(Duration::from_secs(1)).await;
        sim.clock().settle().await;
        // The main's inbox is not served, so the answer never comes: the read gets only what the
        // one budget has left, and the request resolves at the budget's end. A per-phase budget
        // would resolve after the dial's own bound on top of it. The margin only has to absorb
        // the clock's 10 ms steps, and is far below the manager's dial bound (`connect.rs`'s
        // 10 s), which is what a per-phase budget spends before its second one.
        let margin = Duration::from_secs(1);
        match within(&sim, ACTION_BUDGET + margin, request(&ready, id(1), b"cmd")).await {
            Ok(Ok(ActionAnswer::Unknown)) => Ok(()),
            Ok(Ok(other)) => Err(format!(
                "a request whose dial spent most of the budget was answered `{other:?}`"
            )),
            Ok(Err(error)) => Err(format!("the request failed: {error}")),
            Err(_) => Err(
                "the request outlived one ACTION_BUDGET: the dial and the answer each got a \
                 full one"
                    .to_owned(),
            ),
        }
    })
}

/// A record read the operating system refused defers an action's dial; it does not fail it.
///
/// The records directory is replaced by a regular file, so every record read under the laptop's
/// root fails the way an operating-system fault does on a unix host, and the read the ask needs
/// before anything is dialled meets it. Three outcomes are observed, in order. A fault still
/// unread when the ask's last dial-length of [`ACTION_BUDGET`] begins is answered as
/// [`ActionError::Connect`] carrying [`ConnectFailure::Deferred`] that names the record, and the
/// pair is not stopped by it. A fault that clears inside the budget is not reported to the person
/// as a trust failure: the ask waits a round, the next read finds trust, and the request goes on
/// to the dial. And over a pair whose last dial met a network failure, the same fault is answered
/// with that failure rather than the deferral, in the answer and in the state the product reads.
#[cfg(unix)]
pub(crate) fn a_transient_record_fault_defers_an_action() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        let record = ready
            .laptop
            .storage()
            .record_name(&ready.main.peer_id())
            .map_err(io_error)?;
        // The ask is the only dialer, so what the pair does is what the ask made it do.
        ready.keeper.abort();
        ready
            .laptop_managed
            .connections
            .disconnect(&ready.main.peer_id());
        sim.clock().advance(Duration::from_secs(1)).await;
        sim.clock().settle().await;
        // Every record read under the laptop's root meets an operating-system fault, and it
        // stays on file for both asks below.
        let hidden = ready
            .laptop
            .storage()
            .hide_records_dir()
            .map_err(io_error)?;
        let asked = ask(&ready, id(1));
        // A fault still unread when the ask's last dial-length begins is answered as the deferral
        // it is, and the answer names the record. The clock is moved in keeper rounds rather than
        // polled, and the drive runs past the moment the read gives up.
        let spent = spend_budget(&sim, &asked).await?;
        // The read gives up one dial short of the budget, so the answer lands on that moment: a
        // reservation shorter than a dial lets the read spend the dial's time, and a longer one
        // spends the person's. `spend_budget` moves the clock in keeper rounds, so what it
        // measures is the first round at or after the read's own deadline.
        let reserved = ACTION_BUDGET - DIAL_BUDGET;
        let rounds = reserved.as_nanos().div_ceil(TRUST_POLL.as_nanos());
        let expected = TRUST_POLL * u32::try_from(rounds).expect("the reservation is a few rounds");
        if spent != expected {
            return Err(format!(
                "an ask answered a record fault after {spent:?}, not the {expected:?} its read \
                 reserves: the reservation is not one dial"
            ));
        }
        let answered = asked
            .await
            .map_err(|error| format!("the request's task failed: {error}"))?;
        match &answered {
            Err(error @ ActionError::Connect(ConnectFailure::Deferred { peer, detail })) => {
                if *peer != ready.main.fingerprint() {
                    return Err(format!(
                        "the deferral names {peer}, not the peer the action was asked of"
                    ));
                }
                if !detail.contains(&record) {
                    return Err(format!("the deferral does not name the record: {detail}"));
                }
                // The sentence a person reads names this machine's read, never a trust decision
                // and never a dial that may not have happened. `Deferred` is the outcome's name,
                // not a word its sentence uses.
                let words = error.to_string();
                if words.contains("not trusted") || words.contains("deferred") {
                    return Err(format!("a deferral's sentence reads `{words}`"));
                }
            }
            other => {
                return Err(format!(
                    "a record fault still unread when the ask's last dial-length began was \
                     answered `{other:?}`, not as a deferral naming the record"
                ));
            }
        }
        // A deferral is not a stop: the pair is not refused for a fault on this machine.
        let state = ready
            .laptop_managed
            .connections
            .recovery(&ready.main.peer_id());
        if matches!(state, Recovery::Stopped { .. }) {
            return Err(format!(
                "a deferred fault stopped the pair: it reads `{state}`"
            ));
        }
        // The second ask, under a fresh identifier so the first one's journal entry cannot
        // interfere: two rounds pass with the fault still on file, and a deferred read is tried
        // again rather than answered, so the ask is still running.
        let mut asked = ask(&ready, id(2));
        let early = sim.clock().drive(2 * TRUST_POLL, &mut asked).await;
        if let Some(answered) = early {
            let answered =
                answered.map_err(|error| format!("the request's task failed: {error}"))?;
            return Err(format!(
                "an action answered a deferred record fault while the fault was still on file: {answered:?}"
            ));
        }
        // The fault clears while the ask waits: the next read finds trust, so the request goes
        // on and the person is not told the pair is refused. The link is watched from here, so
        // the dial the ask makes after the fault is seen rather than assumed.
        let traced = sim.link().trace().len();
        hidden.restore().map_err(io_error)?;
        let answered = within(&sim, LONG, asked)
            .await?
            .map_err(|error| format!("the request's task did not finish: {error}"))?;
        if !sim
            .link()
            .trace()
            .iter()
            .skip(traced)
            .any(|event| event.from == ready.laptop.addr() && event.to == ready.main.addr())
        {
            return Err(
                "the ask never dialled after the record became readable: the fault cost the \
                 dial it was asked for"
                    .to_owned(),
            );
        }
        match &answered {
            Err(ActionError::Io { .. })
            | Err(ActionError::Insecure { .. })
            | Err(ActionError::Record(_))
            | Err(ActionError::Connect(ConnectFailure::Deferred { .. }))
            | Err(ActionError::Connect(ConnectFailure::NotTrusted { .. })) => {
                return Err(format!(
                    "a fault that cleared while the ask waited was still reported as a record or \
                     trust failure: {answered:?}"
                ));
            }
            _ => {}
        }
        // A deferral never stands in for the reason the pair is down. The pair's next dial is a
        // real one that meets a silent peer, so the policy has a network failure to keep; then
        // the record fault returns and is still unread when a fourth ask's last dial-length
        // begins, and the answer is the reason the pair is down rather than the fault this machine
        // met.
        ready
            .laptop_managed
            .connections
            .disconnect(&ready.main.peer_id());
        sim.clock().advance(Duration::from_secs(1)).await;
        sim.clock().settle().await;
        sim.link().silence(ready.main.addr());
        let asked = ask(&ready, id(3));
        let first = within(&sim, LONG, asked)
            .await?
            .map_err(|error| format!("the request's task did not finish: {error}"))?;
        if !matches!(&first, Err(ActionError::Connect(_))) {
            return Err(format!(
                "an ask that met a silent peer was answered `{first:?}`, not the failure its \
                 dial met"
            ));
        }
        let real = match ready
            .laptop_managed
            .connections
            .recovery(&ready.main.peer_id())
        {
            Recovery::Waiting {
                last: Some(last), ..
            }
            | Recovery::Exhausted { last, .. }
                if !matches!(last, ConnectFailure::Deferred { .. }) =>
            {
                last
            }
            other => {
                return Err(format!(
                    "the ask that met a silent peer left the pair reading `{other}`, not a \
                     network failure to keep"
                ));
            }
        };
        let hidden = ready
            .laptop
            .storage()
            .hide_records_dir()
            .map_err(io_error)?;
        let asked = ask(&ready, id(4));
        spend_budget(&sim, &asked).await?;
        let answered = asked
            .await
            .map_err(|error| format!("the request's task failed: {error}"))?;
        match &answered {
            Err(ActionError::Connect(named)) if *named == real => {}
            other => {
                return Err(format!(
                    "a record fault over a pair whose last dial met `{real}` was answered \
                     `{other:?}`: the answer is not the reason the pair is down"
                ));
            }
        }
        // One pair, one reason: the state the product reads still names it too.
        match ready
            .laptop_managed
            .connections
            .recovery(&ready.main.peer_id())
        {
            Recovery::Waiting {
                last: Some(last), ..
            }
            | Recovery::Exhausted { last, .. }
                if last == real => {}
            other => {
                return Err(format!(
                    "the answer named `{real}` while the state reads `{other}`"
                ));
            }
        }
        hidden.restore().map_err(io_error)?;
        Ok(())
    })
}

/// One ask of the laptop's action layer, spawned so the case can drive the clock while it waits.
#[cfg(unix)]
fn ask(ready: &Ready, id: ActionId) -> tokio::task::JoinHandle<Result<ActionAnswer, ActionError>> {
    let actions = Arc::clone(&ready.laptop_messages.actions);
    let connections = Arc::clone(&ready.laptop_managed.connections);
    let endpoint = ready.laptop_managed.endpoint.clone();
    let peer = ready.main.peer_id();
    tokio::spawn(async move {
        actions
            .request(
                &connections,
                &endpoint,
                &peer,
                id,
                ActionKind::COMMAND,
                b"a command",
            )
            .await
    })
}

/// Drive the clock in keeper rounds until `asked` finishes, and answer how much virtual time it
/// took.
///
/// One request has one budget, so an ask that outlives it by more than the rounds it waited in is
/// one the budget does not bound. The ask's first poll — where its deadline is taken — is pinned
/// to this instant before anything is measured, so what this answers is measured from the ask's
/// own start.
#[cfg(unix)]
async fn spend_budget(
    sim: &Sim,
    asked: &tokio::task::JoinHandle<Result<ActionAnswer, ActionError>>,
) -> Result<Duration, String> {
    tokio::task::yield_now().await;
    let mut spent = Duration::ZERO;
    while !asked.is_finished() {
        if spent > ACTION_BUDGET + 2 * TRUST_POLL {
            return Err(format!(
                "an action was still waiting {spent:?} after a record fault it never read: the \
                 budget is not the one the record read shares"
            ));
        }
        sim.clock().advance(TRUST_POLL).await;
        tokio::task::yield_now().await;
        spent += TRUST_POLL;
    }
    Ok(spent)
}
