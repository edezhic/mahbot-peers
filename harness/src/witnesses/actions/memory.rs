//! The action memory: one execution per identifier, the week it is kept, the journal that
//! refuses rather than forgets, and the file's own privacy and format.
//!
//! Every case runs over the simulated link and the injected clock. A memory's week is measured
//! in the layer's own moment — [`NOW`] plus the virtual time a case has moved — so a case that
//! wants a week later says so instead of walking a week of the simulation's timers.

use std::sync::Arc;
use std::time::Duration;

#[cfg(unix)]
use mahbot_peers::peer::ActionError;
use mahbot_peers::peer::actions::MAX_ACTIONS_BYTES;
use mahbot_peers::peer::{
    ACTION_MEMORY_RETENTION, ActionAnswer, ActionId, ActionKind, Authority, Capability,
    EXECUTION_BUDGET, MAX_ACTION_BODY_BYTES, MAX_RESULT_BYTES, NoFloor, Timestamp,
};

use crate::beacon::TestBeacon;
use crate::clock::block_on;
use crate::messages::Messaging;
use crate::sim::Sim;

#[cfg(unix)]
use super::super::rights::paired_machines;
use super::super::rights::{label, person};
use super::super::support::{field, holds_bytes, io_error, pair, within};
use super::{LONG, NOW, PROMPT, Ready, id, ran_with, ready, request, wait_for_executions};

/// The bytes every memory opens with, before its version.
const MAGIC: &[u8] = b"mahbot-peer-actions";

/// The version this build writes.
const VERSION: u8 = 1;

/// One entry's body: its identifier, its moment, and any field a newer build added inside it.
fn entry(id: ActionId, at: Timestamp, extra: &[u8]) -> Vec<u8> {
    let mut body = field(0x01, id.as_bytes());
    body.extend_from_slice(&field(0x02, &at.unix_seconds().to_be_bytes()));
    body.extend_from_slice(extra);
    body
}

/// A memory file: its magic, its version, then the executed entries, the unknown marks and
/// whatever else the case appends whole.
fn memory(executed: &[Vec<u8>], unknown: &[Vec<u8>], extra: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    bytes.push(VERSION);
    for body in executed {
        bytes.extend_from_slice(&field(0x01, body));
    }
    for body in unknown {
        bytes.extend_from_slice(&field(0x02, body));
    }
    for each in extra {
        bytes.extend_from_slice(each);
    }
    bytes
}

/// A journal of `count` executed identifiers, from `id(1000)` up, all remembered at `at`.
fn journal(at: Timestamp, count: u64) -> Vec<Vec<u8>> {
    (0..count).map(|n| entry(id(1000 + n), at, &[])).collect()
}

/// One operation offered three times runs once, and a new identifier runs again: the person
/// running the command a second time asked for a second operation.
pub(crate) fn an_action_runs_once_when_the_operation_is_offered_three_times() -> Result<(), String>
{
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        ready.main_messages.executions.run(b"done");
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        let first = request(&ready, id(1), b"echo").await?;
        if !ran_with(&first, b"done") {
            return Err(format!(
                "the first offer was answered `{first:?}`, not a run"
            ));
        }
        let second = request(&ready, id(1), b"echo").await?;
        if second != ActionAnswer::AlreadyExecuted {
            return Err(format!(
                "the second offer of one identifier was answered `{second:?}`, not already \
                 executed"
            ));
        }
        let third = request(&ready, id(1), b"echo").await?;
        if third != ActionAnswer::AlreadyExecuted {
            return Err(format!(
                "the third offer of one identifier was answered `{third:?}`, not already executed"
            ));
        }
        let ran = ready.main_messages.executions.count();
        if ran != 1 {
            return Err(format!(
                "one operation offered three times was run {ran} times, not once"
            ));
        }
        // A person running the command again is a new operation, with an identifier of its own.
        let again = request(&ready, id(2), b"echo").await?;
        if !ran_with(&again, b"done") {
            return Err(format!(
                "a new identifier was answered `{again:?}`, not a run"
            ));
        }
        let ran = ready.main_messages.executions.count();
        if ran != 2 {
            return Err(format!(
                "two operations were run {ran} times between them, not twice"
            ));
        }
        Ok(())
    })
}

/// An identifier belongs to one operation: the same identifier with a different body is
/// answered as a repeat, and the second body never reaches the machine's own code.
pub(crate) fn a_reused_identifier_is_a_repeat_whatever_the_body() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        ready.main_messages.executions.run(b"done");
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        let first = request(&ready, id(1), b"echo one").await?;
        if !ran_with(&first, b"done") {
            return Err(format!(
                "the first operation was answered `{first:?}`, not a run"
            ));
        }
        let second = request(&ready, id(1), b"echo two").await?;
        if second != ActionAnswer::AlreadyExecuted {
            return Err(format!(
                "one identifier used for a second operation was answered `{second:?}`, not \
                 already executed"
            ));
        }
        let handed = ready.main_messages.executions.handed();
        let bodies: Vec<_> = handed
            .iter()
            .map(|one| String::from_utf8_lossy(&one.body).into_owned())
            .collect();
        if handed.len() != 1 || handed[0].body.as_slice() != b"echo one" {
            return Err(format!(
                "the second body reached the machine's code: executions {bodies:?}"
            ));
        }
        Ok(())
    })
}

/// The memory is durable: after the receiver's own layer is dropped and reopened over the same
/// root, a repeat of an identifier is still a repeat.
pub(crate) fn an_action_remembers_across_the_receivers_restart() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        ready.main_messages.executions.run(b"done");
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        let first = request(&ready, id(1), b"echo").await?;
        if !ran_with(&first, b"done") {
            return Err(format!(
                "the first offer was answered `{first:?}`, not a run"
            ));
        }
        let ran = ready.main_messages.executions.count();
        if ran != 1 {
            return Err(format!("the first offer was run {ran} times, not once"));
        }
        let Ready {
            main,
            laptop,
            main_managed,
            laptop_managed,
            main_messages,
            laptop_messages,
            keeper,
        } = ready;
        // The receiving machine restarts: its layer goes, and a new one opens over the same
        // root, with an executor that has run nothing.
        drop(main_messages);
        let restarted = Messaging::open(&sim, &main, Arc::new(NoFloor))?;
        restarted.serve(&main_managed.connections, &laptop);
        let ready = Ready {
            main,
            laptop,
            main_managed,
            laptop_managed,
            main_messages: restarted,
            laptop_messages,
            keeper,
        };
        let again = within(&sim, PROMPT, request(&ready, id(1), b"echo")).await??;
        if again != ActionAnswer::AlreadyExecuted {
            return Err(format!(
                "a repeat after the receiver's restart was answered `{again:?}`, not already \
                 executed"
            ));
        }
        let ran = ready.main_messages.executions.count();
        if ran != 0 {
            return Err(format!(
                "the restarted machine's code was handed {ran} actions, not none"
            ));
        }
        Ok(())
    })
}

/// The memory keeps an identifier for a week of the layer's own time; after that a repeat runs
/// again, which is the cost of remembering by identifier and nothing else.
pub(crate) fn a_repeat_after_the_week_runs_again() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        ready.main_messages.executions.run(b"done");
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        let first = request(&ready, id(1), b"echo").await?;
        if !ran_with(&first, b"done") {
            return Err(format!(
                "the first offer was answered `{first:?}`, not a run"
            ));
        }
        ready
            .main_messages
            .moment
            .shift(ACTION_MEMORY_RETENTION + Duration::from_secs(1));
        let again = request(&ready, id(1), b"echo").await?;
        if !ran_with(&again, b"done") {
            return Err(format!(
                "a repeat after the week was answered `{again:?}`, not a run"
            ));
        }
        let ran = ready.main_messages.executions.count();
        if ran != 2 {
            return Err(format!(
                "a repeat after the week ran {ran} times between the two offers, not twice"
            ));
        }
        Ok(())
    })
}

/// An answer that never came back is marked unknown durably, survives the sender's restart and
/// is never offered again — not even to the machine that may have run it.
pub(crate) fn an_unanswered_action_is_unknown_and_never_offered_again() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        // The execution takes a moment, so the case can silence the link after the receiver
        // took the action and before its answer is written.
        ready
            .main_messages
            .executions
            .hold(Duration::from_secs(1), b"done");
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        // The request is its own task: the case has to silence the link once the receiver has
        // taken the action, and the answer is on its way back by then.
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
        // The laptop is gone before the answer reaches it: the action ran and nobody heard.
        sim.link().silence(ready.laptop.addr());
        let outcome = within(&sim, LONG, asked)
            .await?
            .map_err(|error| error.to_string())??;
        if outcome != ActionAnswer::Unknown {
            return Err(format!(
                "an action whose answer was dropped was answered `{outcome:?}`, not unknown"
            ));
        }
        sim.link().resume(ready.laptop.addr());
        let marks = ready
            .laptop_messages
            .actions
            .unknown(&ready.main.peer_id())
            .map_err(|error| error.to_string())?;
        if !marks.iter().any(|mark| mark.id == id(1)) {
            return Err(format!(
                "the unanswered action left {} marks, none of them its identifier",
                marks.len()
            ));
        }
        let Ready {
            main,
            laptop,
            main_managed,
            laptop_managed,
            main_messages,
            laptop_messages,
            keeper,
        } = ready;
        // The sender restarts: the mark is in the file, not in the layer that wrote it.
        drop(laptop_messages);
        let restarted = Messaging::open(&sim, &laptop, Arc::new(NoFloor))?;
        let ready = Ready {
            main,
            laptop,
            main_managed,
            laptop_managed,
            main_messages,
            laptop_messages: restarted,
            keeper,
        };
        let marks = ready
            .laptop_messages
            .actions
            .unknown(&ready.main.peer_id())
            .map_err(|error| error.to_string())?;
        if !marks.iter().any(|mark| mark.id == id(1)) {
            return Err(format!(
                "the mark was lost with the sender's restart: {} marks survive it",
                marks.len()
            ));
        }
        let again = request(&ready, id(1), b"echo").await?;
        if again != ActionAnswer::Unknown {
            return Err(format!(
                "an identifier already marked unknown was answered `{again:?}`, not unknown"
            ));
        }
        let ran = ready.main_messages.executions.count();
        if ran != 1 {
            return Err(format!(
                "the receiver's code was handed {ran} actions, not the one it took"
            ));
        }
        Ok(())
    })
}

/// A repeat that arrives while the first execution is still running is answered already
/// executed, and the first one still answers with what it ran.
pub(crate) fn a_repeat_while_the_first_runs_is_already_executed() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        ready
            .main_messages
            .executions
            .hold(EXECUTION_BUDGET / 2, b"late");
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        let actions = Arc::clone(&ready.laptop_messages.actions);
        let connections = Arc::clone(&ready.laptop_managed.connections);
        let endpoint = ready.laptop_managed.endpoint.clone();
        let peer = ready.main.peer_id();
        let first = tokio::spawn(async move {
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
        // The identifier is remembered before the run it describes, so the repeat below is
        // answered while the first execution is still holding.
        wait_for_executions(&sim, &ready.main_messages.executions, 1, LONG).await?;
        let repeat = within(&sim, PROMPT, request(&ready, id(1), b"echo")).await??;
        if repeat != ActionAnswer::AlreadyExecuted {
            return Err(format!(
                "a repeat during the first execution was answered `{repeat:?}`, not already \
                 executed"
            ));
        }
        // The repeat is the pair's traffic although it ran nothing: the receiver's journal
        // proves it accepted the operation before, so a machine holding only this answer is not
        // re-dialled for ever.
        let traffic = ready
            .laptop_managed
            .connections
            .traffic(&ready.main.peer_id())
            .ok_or("the pair lost its connection while the first action ran")?;
        if traffic.taken() != 1 {
            return Err(format!(
                "a repeat answered as already executed is measured as {} takes, not one",
                traffic.taken()
            ));
        }
        let first = within(&sim, LONG, first)
            .await?
            .map_err(|error| error.to_string())??;
        if !ran_with(&first, b"late") {
            return Err(format!(
                "the first execution was answered `{first:?}`, not its own result"
            ));
        }
        let traffic = ready
            .laptop_managed
            .connections
            .traffic(&ready.main.peer_id())
            .ok_or("the pair lost its connection after the answer")?;
        if traffic.taken() != 2 {
            return Err(format!(
                "the run and its repeat are measured as {} takes, not two",
                traffic.taken()
            ));
        }
        let ran = ready.main_messages.executions.count();
        if ran != 1 {
            return Err(format!(
                "one operation and its repeat were run {ran} times, not once"
            ));
        }
        Ok(())
    })
}

/// A full memory refuses a new identifier rather than forgetting one, and the entries that
/// expired are cleared before the journal is called full.
pub(crate) fn a_full_memory_refuses_rather_than_forgetting() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        ready.main_messages.executions.run(b"done");
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        // The memory is a file under the machine's root, and the root is what names it.
        let full = memory(&journal(NOW, 4096), &[], &[]);
        ready
            .main
            .root
            .write_action(&ready.laptop.peer_id(), &full)
            .map_err(io_error)?;
        let refused = request(&ready, id(1), b"echo").await?;
        if refused != ActionAnswer::MemoryFull {
            return Err(format!(
                "an action against a full memory was answered `{refused:?}`, not a full memory"
            ));
        }
        let ran = ready.main_messages.executions.count();
        if ran != 0 {
            return Err(format!(
                "a full memory ran the action anyway: the receiver's code was handed {ran} \
                 actions"
            ));
        }
        // Nothing was forgotten to make room: an identifier already in the journal is still
        // answered as spent.
        let spent = request(&ready, id(1000), b"echo").await?;
        if spent != ActionAnswer::AlreadyExecuted {
            return Err(format!(
                "an identifier in a full memory was answered `{spent:?}`, not already executed"
            ));
        }
        // Every entry is now past the week: they are cleared before the cap is consulted.
        let expired = NOW.unix_seconds() - ACTION_MEMORY_RETENTION.as_secs() - 1;
        let stale = memory(
            &journal(Timestamp::from_unix_seconds(expired), 4096),
            &[],
            &[],
        );
        ready
            .main
            .root
            .write_action(&ready.laptop.peer_id(), &stale)
            .map_err(io_error)?;
        let ran = request(&ready, id(2), b"echo").await?;
        if !ran_with(&ran, b"done") {
            return Err(format!(
                "an action against a memory whose entries all expired was answered `{ran:?}`, \
                 not a run"
            ));
        }
        let handed = ready.main_messages.executions.count();
        if handed != 1 {
            return Err(format!(
                "the receiver's code was handed {handed} actions, not the one that ran"
            ));
        }
        Ok(())
    })
}

/// A result too large to carry is answered as a run that was not carried, and the identifier
/// stays remembered: the command happened and can be run differently.
pub(crate) fn a_result_too_large_to_carry_is_answered_and_remembered() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        ready
            .main_messages
            .executions
            .run(vec![b'x'; MAX_RESULT_BYTES + 1]);
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        let ran = request(&ready, id(1), b"echo").await?;
        if ran != ActionAnswer::RanNotCarried {
            return Err(format!(
                "a result one byte over the cap was answered `{ran:?}`, not a run that was not \
                 carried"
            ));
        }
        // A run whose result was not carried is the pair's traffic: the receiver ran it, and the
        // answer says so.
        let traffic = ready
            .laptop_managed
            .connections
            .traffic(&ready.main.peer_id())
            .ok_or("the pair lost its connection after the answer")?;
        if traffic.taken() != 1 {
            return Err(format!(
                "a run whose result was not carried is measured as {} takes, not one",
                traffic.taken()
            ));
        }
        let repeat = request(&ready, id(1), b"echo").await?;
        if repeat != ActionAnswer::AlreadyExecuted {
            return Err(format!(
                "a repeat of an action whose result was not carried was answered `{repeat:?}`, \
                 not already executed"
            ));
        }
        let traffic = ready
            .laptop_managed
            .connections
            .traffic(&ready.main.peer_id())
            .ok_or("the pair lost its connection after the repeat")?;
        if traffic.taken() != 2 {
            return Err(format!(
                "the run and its repeat are measured as {} takes, not two",
                traffic.taken()
            ));
        }
        let handed = ready.main_messages.executions.count();
        if handed != 1 {
            return Err(format!(
                "the receiver's code was handed {handed} actions, not the one it ran"
            ));
        }
        // The boundary itself: a result of exactly the cap is carried whole.
        ready
            .main_messages
            .executions
            .run(vec![b'y'; MAX_RESULT_BYTES]);
        let at_cap = request(&ready, id(2), b"echo").await?;
        match &at_cap {
            ActionAnswer::Ran { result } if result.len() == MAX_RESULT_BYTES => {}
            other => {
                return Err(format!(
                    "a result of exactly the cap was answered `{other:?}`, not a run of {} bytes",
                    MAX_RESULT_BYTES
                ));
            }
        }
        Ok(())
    })
}

/// The body is handed to the machine's own code exactly as the caller wrote it, under the pair
/// the receiver knows.
pub(crate) fn a_body_is_handed_over_as_written() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        let body = "line\ncaf\u{e9}\tand a tab\n".as_bytes();
        ready.main_messages.executions.run(b"ok");
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        let ran = request(&ready, id(1), body).await?;
        if !ran_with(&ran, b"ok") {
            return Err(format!("the action was answered `{ran:?}`, not a run"));
        }
        let handed = ready.main_messages.executions.handed();
        let [one] = &handed[..] else {
            return Err(format!(
                "the receiver's code was handed {} actions, not one",
                handed.len()
            ));
        };
        if one.body != body {
            return Err(format!(
                "the body was handed over as {} bytes, not the {} the caller wrote",
                one.body.len(),
                body.len()
            ));
        }
        if one.kind != ActionKind::COMMAND {
            return Err(format!(
                "the action was handed over as `{}`, not a command",
                one.kind
            ));
        }
        if one.peer != ready.laptop.peer_id() {
            return Err(format!(
                "the action is attributed to {} instead of the transport's peer",
                one.peer.fingerprint()
            ));
        }
        let known = pair(&ready.laptop, &label("admin")?);
        if one.pair != known {
            return Err(format!(
                "the action ran under {:?}, not the pair the laptop holds",
                one.pair
            ));
        }
        // A body exactly at the cap is carried whole, not refused a byte early.
        let exact = vec![b'y'; MAX_ACTION_BODY_BYTES];
        let ran = request(&ready, id(3), &exact).await?;
        if !ran_with(&ran, b"ok") {
            return Err(format!(
                "a body at the cap was answered `{ran:?}`, not a run"
            ));
        }
        let handed = ready.main_messages.executions.handed();
        let Some(last) = handed.last() else {
            return Err("the receiver's code was handed no action".to_owned());
        };
        if last.body != exact {
            return Err(format!(
                "the body at the cap was handed over as {} bytes, not the {} the caller wrote",
                last.body.len(),
                exact.len()
            ));
        }
        if last.id != id(3) {
            return Err("the body at the cap was handed over under another identifier".to_owned());
        }
        // A body one byte over the cap is refused before anything is sent.
        let too_long = vec![b'x'; MAX_ACTION_BODY_BYTES + 1];
        match request(&ready, id(2), &too_long).await {
            Err(error) if error.contains("more than") => {}
            other => {
                return Err(format!(
                    "a body over the cap was answered `{other:?}`, not refused as too long"
                ));
            }
        }
        Ok(())
    })
}

/// A person's trust withdrawal is the way out of a full journal, and it must work even when the
/// peer's service is stopped for the whole withdrawal: the record keeps the withdrawal's
/// moment, so the next look forgets everything recorded before it.
pub(crate) fn a_withdrawn_trust_clears_the_action_memory() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        ready.main_messages.executions.run(b"done");
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        let ran = request(&ready, id(1), b"echo").await?;
        if !ran_with(&ran, b"done") {
            return Err(format!(
                "the first action was answered `{ran:?}`, not a run"
            ));
        }
        // The product stops the peer's service on the withdrawal and starts it again after the
        // return, so no sweep of the memory runs while the trust is gone.
        ready.main_messages.stop();
        // The withdrawal is one second after the first run, so the record's moment — not the
        // sweep's own period, which is longer — is what forgets the identifier.
        sim.clock().advance(Duration::from_secs(1)).await;
        let after = NOW.plus(Duration::from_secs(1));
        let egor = person("egor")?;
        ready
            .main
            .rights()?
            .withdraw_trust(&ready.laptop.peer_id(), egor.clone(), after)
            .map_err(|error| error.to_string())?;
        let pair = pair(&ready.laptop, &label("admin")?);
        ready
            .main
            .rights()?
            .restore_trust(&pair, egor.clone(), after)
            .map_err(|error| error.to_string())?;
        ready
            .main
            .rights()?
            .grant(
                &pair,
                Capability::WORK,
                Authority::Person(egor),
                None,
                after,
            )
            .map_err(|error| error.to_string())?;
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        let again = request(&ready, id(1), b"echo").await?;
        if !ran_with(&again, b"done") {
            return Err(format!(
                "the same identifier after a return from withdrawal was answered `{again:?}`, not a run"
            ));
        }
        let repeat = request(&ready, id(1), b"echo").await?;
        if repeat != ActionAnswer::AlreadyExecuted {
            return Err(format!(
                "the identifier after its second run was answered `{repeat:?}`, not already executed"
            ));
        }
        Ok(())
    })
}

/// An unknown outcome whose trace cannot be kept names both: the caller is told the action may
/// have run and that the memory could not record it, and the receiver's journal still answers
/// the repeat as already executed.
#[cfg(unix)]
pub(crate) fn an_untraceable_unknown_names_both_outcomes() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        // The receiver takes the action and outlives the execution budget, so its answer is
        // `unknown` and the sender must keep a trace.
        ready.main_messages.executions.hold_for(
            &ready.laptop.peer_id(),
            EXECUTION_BUDGET * 2,
            b"slow",
        );
        // The laptop's memory is readable but not writable: the trace cannot be kept.
        ready
            .laptop
            .root
            .set_action_dir_mode(0o500)
            .map_err(io_error)?;
        let asked = within(&sim, LONG, request(&ready, id(1), b"echo")).await?;
        let Err(error) = asked else {
            return Err(format!(
                "an unknown outcome whose trace cannot be kept was answered `{asked:?}`, not a \
                 fault"
            ));
        };
        if !error.contains("may have run") || !error.contains("could not keep the trace") {
            return Err(format!(
                "the fault does not name both the outcome and the trace: `{error}`"
            ));
        }
        // The memory is back; the receiver's journal still answers the repeat, and nothing runs
        // a second time.
        ready
            .laptop
            .root
            .set_action_dir_mode(0o700)
            .map_err(io_error)?;
        let repeat = within(&sim, LONG, request(&ready, id(1), b"echo")).await??;
        if repeat != ActionAnswer::AlreadyExecuted {
            return Err(format!(
                "the repeat of an untraceable unknown was answered `{repeat:?}`, not already \
                 executed"
            ));
        }
        let ran = ready.main_messages.executions.count();
        if ran != 1 {
            return Err(format!(
                "the receiver's code was handed {ran} actions, not one"
            ));
        }
        Ok(())
    })
}

/// An action memory is private to the account the product runs as: a directory another account
/// can write, a memory another account can read and a linked directory are each refused, and
/// putting the mode back opens the same memory.
#[cfg(unix)]
pub(crate) fn an_action_file_is_private_to_the_account() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let opened = Messaging::open(&sim, &laptop, Arc::new(NoFloor))?;
        let mode = laptop.root.action_dir_mode().map_err(io_error)?;
        if mode != 0o700 {
            return Err(format!(
                "the actions directory the layer creates is {mode:o}, not 0700"
            ));
        }
        let written = memory(&[entry(id(1), NOW, &[])], &[entry(id(2), NOW, &[])], &[]);
        laptop
            .root
            .write_action(&main.peer_id(), &written)
            .map_err(io_error)?;
        drop(opened);
        laptop.root.set_action_dir_mode(0o777).map_err(io_error)?;
        match Messaging::open(&sim, &laptop, Arc::new(NoFloor)) {
            Err(error) if error.contains("not private") => {}
            Err(error) => {
                return Err(format!(
                    "an actions directory another account can write reads `{error}`"
                ));
            }
            Ok(_) => {
                return Err(
                    "an actions directory another account can write was accepted".to_owned(),
                );
            }
        }
        laptop.root.set_action_dir_mode(0o700).map_err(io_error)?;
        let reopened = Messaging::open(&sim, &laptop, Arc::new(NoFloor))?;
        // A memory another account can read is refused, and naming the file is not reading it.
        laptop
            .root
            .set_action_file_mode(&main.peer_id(), 0o644)
            .map_err(io_error)?;
        match reopened.actions.unknown(&main.peer_id()) {
            Err(ActionError::Insecure { .. }) => {}
            Err(error) => {
                return Err(format!("an insecure memory reads `{error}`"));
            }
            Ok(marks) => {
                return Err(format!(
                    "a memory another account can read was read as {} marks",
                    marks.len()
                ));
            }
        }
        laptop
            .root
            .set_action_file_mode(&main.peer_id(), 0o600)
            .map_err(io_error)?;
        let marks = reopened
            .actions
            .unknown(&main.peer_id())
            .map_err(|error| error.to_string())?;
        let [mark] = &marks[..] else {
            return Err(format!(
                "the repaired memory holds {} marks, not one",
                marks.len()
            ));
        };
        if mark.id != id(2) {
            return Err(format!(
                "the repaired memory holds the mark {}, not the one it was written with",
                mark.id
            ));
        }
        // A directory that is a symbolic link to another one is refused too: a memory must not
        // be made to land outside the root.
        laptop
            .root
            .replace_action_dir_with_a_link()
            .map_err(io_error)?;
        match Messaging::open(&sim, &laptop, Arc::new(NoFloor)) {
            Err(error) if error.contains("not private") => Ok(()),
            Err(error) => Err(format!("a linked actions directory reads `{error}`")),
            Ok(_) => Err("a linked actions directory was accepted".to_owned()),
        }
    })
}

/// A memory's unknown fields are kept and written back at every level, and bytes that are not a
/// memory are refused rather than believed.
pub(crate) fn an_action_file_is_additive_and_refuses_garbage() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        ready.main_messages.executions.run(b"done");
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        // One field of a newer build, at the top of the file and inside an entry this build
        // reads: a build that grows the memory appends there.
        let top = field(0x7f, b"kept-by-a-newer-build");
        let inner = field(0x7f, b"kept-inside-an-entry");
        let crafted = memory(
            &[entry(id(900), NOW, &inner)],
            &[],
            std::slice::from_ref(&top),
        );
        ready
            .main
            .root
            .write_action(&ready.laptop.peer_id(), &crafted)
            .map_err(io_error)?;
        // A real execution makes the layer read the file and write the whole of it back.
        let ran = request(&ready, id(1), b"echo").await?;
        if !ran_with(&ran, b"done") {
            return Err(format!(
                "an action over a memory a newer build wrote was answered `{ran:?}`, not a run"
            ));
        }
        let rewritten = ready
            .main
            .root
            .read_action(&ready.laptop.peer_id())
            .map_err(io_error)?;
        if !holds_bytes(&rewritten, &top) {
            return Err(
                "the rewrite dropped a field this build does not know, so the format is not \
                 additive"
                    .to_owned(),
            );
        }
        if !holds_bytes(&rewritten, &inner) {
            return Err(
                "the rewrite dropped a field nested inside an executed identifier, so the \
                 format is not additive below the top"
                    .to_owned(),
            );
        }
        // Bytes that are not a memory are refused, not read as an empty one.
        ready
            .main
            .root
            .write_action(&ready.laptop.peer_id(), b"not an action memory")
            .map_err(io_error)?;
        match ready.main_messages.actions.unknown(&ready.laptop.peer_id()) {
            Err(error) if error.to_string().contains("is not an action memory") => {}
            Err(error) => {
                return Err(format!(
                    "bytes that are not a memory were refused as `{error}`"
                ));
            }
            Ok(marks) => {
                return Err(format!(
                    "bytes that are not a memory were read as {} marks",
                    marks.len()
                ));
            }
        }
        // A version of zero is not a memory either: a file that names no format cannot be read
        // as the first one.
        let mut unversioned = MAGIC.to_vec();
        unversioned.push(0);
        ready
            .main
            .root
            .write_action(&ready.laptop.peer_id(), &unversioned)
            .map_err(io_error)?;
        match ready.main_messages.actions.unknown(&ready.laptop.peer_id()) {
            Err(error) if error.to_string().contains("is not an action memory") => {}
            Err(error) => {
                return Err(format!("a memory of version zero was refused as `{error}`"));
            }
            Ok(marks) => {
                return Err(format!(
                    "a memory of version zero was read as {} marks",
                    marks.len()
                ));
            }
        }
        // A file over the cap is refused by its length before its fields are walked.
        let oversized =
            vec![
                0u8;
                usize::try_from(MAX_ACTIONS_BYTES).expect("the memory's cap is a length") + 1
            ];
        ready
            .main
            .root
            .write_action(&ready.laptop.peer_id(), &oversized)
            .map_err(io_error)?;
        match ready.main_messages.actions.unknown(&ready.laptop.peer_id()) {
            Err(error) if error.to_string().contains("more than") => Ok(()),
            Err(error) => Err(format!("a memory over the cap was refused as `{error}`")),
            Ok(marks) => Err(format!(
                "a memory over the cap was read as {} marks",
                marks.len()
            )),
        }
    })
}

/// An identifier has one spelling: the lowercase hex it displays as, and that text read back.
/// The other spellings — uppercase, the wrong length, not hex — are refused rather than
/// silently naming another operation.
pub(crate) fn an_identifier_round_trips_through_its_hex() -> Result<(), String> {
    // A value with a letter in its hex, so the uppercase check is not a no-op.
    let id = id(0xab);
    let text = id.to_string();
    if ActionId::from_hex(&text) != Some(id) {
        return Err(format!(
            "the identifier `{text}` did not read back as itself"
        ));
    }
    if ActionId::from_hex(&text.to_uppercase()).is_some() {
        return Err("an uppercase identifier was accepted".to_owned());
    }
    if ActionId::from_hex(&text[..text.len() - 1]).is_some() {
        return Err("an identifier of the wrong length was accepted".to_owned());
    }
    if ActionId::from_hex("not hex at all").is_some() {
        return Err("a non-hex identifier was accepted".to_owned());
    }
    Ok(())
}
