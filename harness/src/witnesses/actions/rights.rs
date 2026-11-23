//! Action cases about the right: the refusal that names its step and is not remembered, the
//! decline that is not a repeat and is answered even when the memory cannot release it, the pair
//! that is not ready, the pair that is closed, the body that chooses nothing, the kind this build
//! does not know, the log with no room, and the second process on the root.
//!
//! Every case runs over the simulated link and the injected clock, and every execution is read
//! from the [`Executions`] rig the machine's layer was built with. Nothing here opens a socket
//! or starts a process.
//!
//! # What a case may not assume
//!
//! The layer reads no clock, and every moment here is [`NOW`]: nothing in these cases waits on
//! a term or a window, so the simulation's own time is only what an await costs.

use mahbot_peers::peer::audit::{MAX_FILE_BYTES, RESERVED_FOR_PERSON_BYTES};
use mahbot_peers::peer::{
    Act, ActionAnswer, ActionError, ActionId, ActionKind, Authority, Capability, Limits, NoFloor,
    Step,
};
use std::sync::Arc;
use std::time::Duration;

use crate::beacon::TestBeacon;
use crate::clock::block_on;
use crate::sim::Sim;

use super::super::rights::{fill_log, label, person};
use super::super::support::{
    connected, field, holds_bytes, io_error, pair, single_ending, wait_live,
};
use super::{
    ACTION_MAGIC, ACTION_VERSION, NOW, PROMPT, bind_and_grant, id, offer_bytes, ran_with, ready,
    request,
};

/// The bytes an audit log opens with, as `src/peer/audit.rs` spells them.
const AUDIT_MAGIC: &[u8] = b"mahbot-peer-audit";

/// The log version this build writes.
const AUDIT_VERSION: u8 = 1;

/// A refusal names the step that refused it and is not remembered: the same operation, under the
/// same identifier, runs once the right is back.
pub(crate) fn a_refused_action_names_its_step_and_runs_once_the_right_is_given()
-> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        ready.main_messages.executions.run(b"ok");
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        let pair = pair(&ready.laptop, &label("admin")?);
        let egor = person("egor")?;
        ready
            .main
            .rights()?
            .withdraw(&pair, Capability::WORK, egor.clone(), NOW)
            .map_err(|error| error.to_string())?;
        let refused = request(&ready, id(1), b"echo").await?;
        let step = match &refused {
            ActionAnswer::Refused { step } => *step,
            other => {
                return Err(format!(
                    "an action under a withdrawn right was answered `{other:?}`, not a refusal"
                ));
            }
        };
        if step != Step::Right {
            return Err(format!(
                "the refusal came from `{step}`, not from the right"
            ));
        }
        let ran = ready.main_messages.executions.count();
        if ran != 0 {
            return Err(format!(
                "a refused action was handed to the machine's code {ran} times, not none"
            ));
        }
        let recorded = ready
            .main
            .audit()?
            .entries()
            .map_err(|error| error.to_string())?;
        if !recorded.iter().any(|entry| {
            matches!(&entry.act, Act::Refused { pair: named, capability, .. }
                if *named == pair && *capability == Capability::WORK)
        }) {
            return Err("the refusal is not in the main's log".to_owned());
        }
        // A refusal is not remembered: the person grants the right and repeats the operation.
        ready
            .main
            .rights()?
            .grant(&pair, Capability::WORK, Authority::Person(egor), None, NOW)
            .map_err(|error| error.to_string())?;
        let again = request(&ready, id(1), b"echo").await?;
        if !ran_with(&again, b"ok") {
            return Err(format!(
                "the same operation after the grant was answered `{again:?}`, not a run"
            ));
        }
        let ran = ready.main_messages.executions.count();
        if ran != 1 {
            return Err(format!("the operation was run {ran} times, not once"));
        }
        Ok(())
    })
}

/// A decline is answered as "not run" and is not remembered, so the same identifier offered
/// again after the machine's code changes its mind does run.
pub(crate) fn a_declined_action_is_not_remembered_and_answered_as_not_run() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        ready.main_messages.executions.decline();
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        let declined = request(&ready, id(1), b"echo").await?;
        if declined != ActionAnswer::NotRun {
            return Err(format!(
                "a declined action was answered `{declined:?}`, not not-run"
            ));
        }
        let ran = ready.main_messages.executions.count();
        if ran != 1 {
            return Err(format!(
                "the machine's code was handed the action {ran} times, not once"
            ));
        }
        // A decline executed nothing, so the identifier is free: the same operation runs.
        ready.main_messages.executions.run(b"ok");
        let again = request(&ready, id(1), b"echo").await?;
        if !ran_with(&again, b"ok") {
            return Err(format!(
                "a repeat of a declined action was answered `{again:?}`, not a run"
            ));
        }
        let ran = ready.main_messages.executions.count();
        if ran != 2 {
            return Err(format!(
                "the action was handed over {ran} times, not once declined and once run"
            ));
        }
        Ok(())
    })
}

/// A decline is answered before a memory fault ends the service: the sender is told `not run`,
/// never left to its own budget and an unknown mark for an action that did not run.
pub(crate) fn a_decline_is_answered_before_a_memory_fault_ends_the_service() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        ready.main_messages.executions.decline();
        // The fault lands in the window between the remember and the release: the machine's own
        // code turns the memory into a directory, so the release cannot read it.
        let root = ready.main.root.clone();
        let peer = ready.laptop.peer_id();
        ready.main_messages.executions.before_answer(move || {
            let _ = root.replace_action_with_a_directory(&peer);
        });
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        let declined = request(&ready, id(1), b"echo").await?;
        if declined != ActionAnswer::NotRun {
            return Err(format!(
                "a decline whose memory cannot be released was answered `{declined:?}`, not \
                 not-run"
            ));
        }
        let ran = ready.main_messages.executions.count();
        if ran != 1 {
            return Err(format!(
                "the machine's code was handed the action {ran} times, not once"
            ));
        }
        let name = ready
            .main
            .root
            .action_name(&ready.laptop.peer_id())
            .map_err(io_error)?;
        let ending = single_ending(&sim, &ready.main_messages, PROMPT).await?;
        if !ending.as_ref().is_err_and(|error| error.contains(&name)) {
            return Err(format!(
                "the service ended with `{ending:?}`, not the memory's fault at {name}"
            ));
        }
        Ok(())
    })
}

/// A pair with no binding and no claim is answered "not ready" and nothing runs; once the
/// receiver decides the binding, the same identifier runs — the sender needs only its trust.
pub(crate) fn an_unbound_pair_is_not_ready_and_runs_once_bound() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = connected(&sim, &beacon, Arc::new(NoFloor)).await?;
        ready.main_messages.executions.run(b"ok");
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        ready
            .laptop_messages
            .serve(&ready.laptop_managed.connections, &ready.main);
        let unbound = request(&ready, id(1), b"echo").await?;
        if unbound != ActionAnswer::NotReady {
            return Err(format!(
                "an action to an unbound pair was answered `{unbound:?}`, not not-ready"
            ));
        }
        let ran = ready.main_messages.executions.count();
        if ran != 0 {
            return Err(format!(
                "an action to an unbound pair was handed to the machine's code {ran} times, not none"
            ));
        }
        bind_and_grant(&ready)?;
        let again = request(&ready, id(1), b"echo").await?;
        if !ran_with(&again, b"ok") {
            return Err(format!(
                "the same action once bound was answered `{again:?}`, not a run"
            ));
        }
        let ran = ready.main_messages.executions.count();
        if ran != 1 {
            return Err(format!("the action was run {ran} times, not once"));
        }
        Ok(())
    })
}

/// A pair closed on the sender's own record is refused before anything is dialled: the caller is
/// told the pair is closed, nothing runs, and no connection appears for the pair.
pub(crate) fn a_closed_pair_is_refused_before_the_dial() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        ready.main_messages.executions.run(b"ok");
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        // Three failed comparisons close the laptop's pair, and nothing is left to dial with.
        let store = ready.laptop.records();
        for _ in 0..Limits::default().max_failures {
            store
                .record_failure(&ready.main.peer_id())
                .map_err(|error| error.to_string())?;
        }
        ready.keeper.abort();
        ready
            .laptop_managed
            .connections
            .disconnect(&ready.main.peer_id());
        let refused = ready
            .laptop_messages
            .actions
            .request(
                &ready.laptop_managed.connections,
                &ready.laptop_managed.endpoint,
                &ready.main.peer_id(),
                id(1),
                ActionKind::COMMAND,
                b"echo",
            )
            .await;
        let text = match refused {
            Ok(outcome) => {
                return Err(format!(
                    "an action to a closed pair was answered `{outcome:?}`, not refused"
                ));
            }
            Err(error) => error.to_string(),
        };
        if !text.contains("closed") {
            return Err(format!(
                "the refusal does not say the pair is closed: {text}"
            ));
        }
        let ran = ready.main_messages.executions.count();
        if ran != 0 {
            return Err(format!(
                "an action to a closed pair was handed to the machine's code {ran} times, not none"
            ));
        }
        if ready
            .laptop_managed
            .connections
            .traffic(&ready.main.peer_id())
            .is_some()
        {
            return Err("the refusal dialled: the pair holds a connection after it".to_owned());
        }
        Ok(())
    })
}

/// A body is bytes the machine's own code is handed and never a decision: one composed to look
/// like a grant runs, reaches the code verbatim, and leaves the rights and the recorded
/// capability as they were.
pub(crate) fn an_action_body_cannot_choose_a_right() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        ready.main_messages.executions.run(b"ok");
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        let pair = pair(&ready.laptop, &label("admin")?);
        let before = ready
            .main
            .rights()?
            .rights(&pair)
            .map_err(|error| error.to_string())?;
        let logged = ready
            .main
            .audit()?
            .entries()
            .map_err(|error| error.to_string())?
            .len();
        // A body shaped like the layer's own fields, asking for a right the pair does not hold.
        let mut body = field(0x02, b"grant");
        body.extend_from_slice(&field(0x03, b"screen"));
        body.extend_from_slice(br#"{"act":"grant","capability":"see the screen"}"#);
        let outcome = request(&ready, id(1), &body).await?;
        if !ran_with(&outcome, b"ok") {
            return Err(format!(
                "an action whose body looked like a grant was answered `{outcome:?}`, not a run"
            ));
        }
        let handed = ready.main_messages.executions.handed();
        let Some(first) = handed.first() else {
            return Err("the machine's code was handed no action".to_owned());
        };
        if first.body != body {
            return Err(format!(
                "the machine's code was handed {} bytes, not the {} the case sent",
                first.body.len(),
                body.len()
            ));
        }
        let after = ready
            .main
            .rights()?
            .rights(&pair)
            .map_err(|error| error.to_string())?;
        if after != before {
            return Err(format!(
                "the body changed the pair's rights: {} rows became {}",
                before.len(),
                after.len()
            ));
        }
        let entries = ready
            .main
            .audit()?
            .entries()
            .map_err(|error| error.to_string())?;
        if entries.len() != logged + 1 {
            return Err(format!(
                "the action wrote {} entries, not one",
                entries.len() - logged
            ));
        }
        let executed: Vec<_> = entries
            .iter()
            .filter(|entry| matches!(entry.act, Act::ActionExecuted { .. }))
            .collect();
        let [execution] = &executed[..] else {
            return Err(format!(
                "the log holds {} executed actions, not one",
                executed.len()
            ));
        };
        let Act::ActionExecuted {
            pair: named,
            capability,
            id: named_id,
            ..
        } = &execution.act
        else {
            return Err("the entry is not an executed action".to_owned());
        };
        if *named != pair {
            return Err("the execution was recorded for another pair".to_owned());
        }
        if *capability != Capability::WORK {
            return Err(format!(
                "the execution was recorded under `{capability}`, not the right it ran under"
            ));
        }
        if *named_id != *id(1).as_bytes() {
            return Err("the execution was recorded under another identifier".to_owned());
        }
        Ok(())
    })
}

/// A kind this build does not know is answered as unsupported, not run as a command, and its
/// identifier is not spent: a command under the same identifier runs afterwards. The right is
/// settled first, so the same unknown kind from a peer without "work on me" is refused at that
/// step instead.
pub(crate) fn an_unknown_kind_is_refused() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        ready.main_messages.executions.run(b"ok");
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        let connection = wait_live(
            &sim,
            &ready.laptop_managed.connections,
            &ready.main.peer_id(),
        )
        .await?;
        // A request of a kind this build does not know, with the identifier the case names.
        let unknown_kind = |action: ActionId| {
            let mut frame = ACTION_MAGIC.to_vec();
            frame.push(ACTION_VERSION);
            frame.extend_from_slice(&field(0x01, action.as_bytes()));
            // Kind 2 is not a kind this build knows; a command is 1.
            frame.extend_from_slice(&field(0x02, &[2]));
            frame.extend_from_slice(&field(0x03, b"cmd"));
            frame
        };
        // The right is settled before the kind: without "work on me", even an unknown kind is
        // refused at the right.
        let pair = pair(&ready.laptop, &label("admin")?);
        let egor = person("egor")?;
        ready
            .main
            .rights()?
            .withdraw(&pair, Capability::WORK, egor.clone(), NOW)
            .map_err(|error| error.to_string())?;
        let refused = offer_bytes(&connection, &unknown_kind(id(9))).await?;
        match &refused {
            ActionAnswer::Refused { step: Step::Right } => {}
            other => {
                return Err(format!(
                    "an unknown kind without the right was answered `{other:?}`, not a refusal \
                     at the right"
                ));
            }
        }
        ready
            .main
            .rights()?
            .grant(&pair, Capability::WORK, Authority::Person(egor), None, NOW)
            .map_err(|error| error.to_string())?;
        let action = id(1);
        let answer = offer_bytes(&connection, &unknown_kind(action)).await?;
        if answer != ActionAnswer::Unsupported {
            return Err(format!(
                "an action of an unknown kind was answered `{answer:?}`, not unsupported"
            ));
        }
        let ran = ready.main_messages.executions.count();
        if ran != 0 {
            return Err(format!(
                "an action of an unknown kind was handed to the machine's code {ran} times, not none"
            ));
        }
        // Nothing was remembered for it: the identifier is free for a command.
        let again = request(&ready, action, b"cmd").await?;
        if !ran_with(&again, b"ok") {
            return Err(format!(
                "a command under the refused identifier was answered `{again:?}`, not a run"
            ));
        }
        let ran = ready.main_messages.executions.count();
        if ran != 1 {
            return Err(format!("the command was run {ran} times, not once"));
        }
        Ok(())
    })
}

/// An execution that cannot be recorded does not run and is not remembered, whether the room
/// kept for a person is full or the file's own cap is; with the log's room back the same
/// identifiers run, and an entry names the run without carrying the body.
pub(crate) fn an_action_that_cannot_be_recorded_does_not_run() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        ready.main_messages.executions.run(b"ok");
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        let body = b"body-that-is-never-logged";
        // The part of the log a peer may fill is full: there is no room for the entry.
        fill_log(&ready.main, MAX_FILE_BYTES - RESERVED_FOR_PERSON_BYTES)?;
        let unrecorded = request(&ready, id(1), body).await?;
        if unrecorded != ActionAnswer::NotRecorded {
            return Err(format!(
                "an action with no room to record it was answered `{unrecorded:?}`, not \
                 not-recorded"
            ));
        }
        let ran = ready.main_messages.executions.count();
        if ran != 0 {
            return Err(format!(
                "an unrecorded action was handed to the machine's code {ran} times, not none"
            ));
        }
        // The file itself full — a person's own acts can fill it — is the same refusal, and
        // still not a fault: the service stays up.
        fill_log(&ready.main, MAX_FILE_BYTES)?;
        let capped = request(&ready, id(2), body).await?;
        if capped != ActionAnswer::NotRecorded {
            return Err(format!(
                "an action that would pass the log's cap was answered `{capped:?}`, not \
                 not-recorded"
            ));
        }
        let ran = ready.main_messages.executions.count();
        if ran != 0 {
            return Err(format!(
                "an action that would pass the log's cap was handed to the machine's code, \
                 making {ran} runs, not none"
            ));
        }
        // A full log is not a fault: no ending arrives, and the service answers once the log is
        // back.
        if single_ending(&sim, &ready.main_messages, PROMPT)
            .await
            .is_ok()
        {
            return Err("a full log ended the service".to_owned());
        }
        // A fresh, empty log: both operations run, because nothing was remembered for either.
        let mut empty = AUDIT_MAGIC.to_vec();
        empty.push(AUDIT_VERSION);
        ready.main.storage().write_audit(&empty).map_err(io_error)?;
        let first = request(&ready, id(1), body).await?;
        if !ran_with(&first, b"ok") {
            return Err(format!(
                "the same action with room to record it was answered `{first:?}`, not a run"
            ));
        }
        let second = request(&ready, id(2), body).await?;
        if !ran_with(&second, b"ok") {
            return Err(format!(
                "the action that would have passed the cap was answered `{second:?}`, not a run"
            ));
        }
        let ran = ready.main_messages.executions.count();
        if ran != 2 {
            return Err(format!("the two actions were run {ran} times, not twice"));
        }
        let entries = ready
            .main
            .audit()?
            .entries()
            .map_err(|error| error.to_string())?;
        let executed: Vec<_> = entries
            .iter()
            .filter(|entry| matches!(entry.act, Act::ActionExecuted { .. }))
            .collect();
        if executed.len() != 2 {
            return Err(format!(
                "the log holds {} executed actions, not two",
                executed.len()
            ));
        }
        for execution in executed {
            let Act::ActionExecuted {
                capability,
                id: named_id,
                ..
            } = &execution.act
            else {
                return Err("the entry is not an executed action".to_owned());
            };
            if *capability != Capability::WORK {
                return Err(format!(
                    "an execution was recorded under `{capability}`, not the right it ran under"
                ));
            }
            if *named_id != *id(1).as_bytes() && *named_id != *id(2).as_bytes() {
                return Err("an execution was recorded under another identifier".to_owned());
            }
        }
        let raw = ready.main.storage().read_audit().map_err(io_error)?;
        if holds_bytes(&raw, body) {
            return Err("the log carries the action's body".to_owned());
        }
        Ok(())
    })
}

/// The layer's own sweep answers `busy` when another writer holds the memory: the public
/// maintenance call a product makes on its own schedule reports the contention rather than
/// waiting for it, and the same call once the writer lets go compacts the file.
pub(crate) fn a_sweep_of_a_held_memory_is_busy() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        ready.main_messages.executions.run(b"ok");
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        // One execution, then a withdrawal a second later: the memory holds an entry the sweep
        // would drop, so the sweep takes the writer rather than returning early.
        let ran = request(&ready, id(1), b"echo").await?;
        if !ran_with(&ran, b"ok") {
            return Err(format!(
                "the action before the withdrawal was answered `{ran:?}`, not a run"
            ));
        }
        sim.clock().advance(Duration::from_secs(1)).await;
        let egor = person("egor")?;
        ready
            .main
            .rights()?
            .withdraw_trust(
                &ready.laptop.peer_id(),
                egor,
                NOW.plus(Duration::from_secs(1)),
            )
            .map_err(|error| error.to_string())?;
        let held = ready
            .main
            .root
            .lock_action(&ready.laptop.peer_id())
            .map_err(io_error)?;
        let busy = ready.main_messages.actions.sweep(&ready.laptop.peer_id());
        if !matches!(busy, Err(ActionError::Busy { .. })) {
            return Err(format!(
                "a sweep of a held memory answered `{busy:?}`, not busy"
            ));
        }
        drop(held);
        let before = ready
            .main
            .root
            .read_action(&ready.laptop.peer_id())
            .map_err(io_error)?;
        if !holds_bytes(&before, id(1).as_bytes()) {
            return Err("the memory did not hold the identifier the sweep was to drop".to_owned());
        }
        ready
            .main_messages
            .actions
            .sweep(&ready.laptop.peer_id())
            .map_err(|error| error.to_string())?;
        let after = ready
            .main
            .root
            .read_action(&ready.laptop.peer_id())
            .map_err(io_error)?;
        if holds_bytes(&after, id(1).as_bytes()) {
            return Err("the sweep left the identifier it was to drop".to_owned());
        }
        Ok(())
    })
}

/// A log this machine cannot write at all is a fault, not a full log: the action does not run,
/// the sender is told `not recorded` rather than left to its own budget, and the service ends
/// with the log's fault named.
pub(crate) fn a_log_that_cannot_be_written_is_a_fault_the_sender_hears() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        ready.main_messages.executions.run(b"ok");
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        // The log's path is a directory, so the append is refused: a hard fault rather than the
        // cap's refusal.
        ready
            .main
            .storage()
            .replace_audit_with_a_directory()
            .map_err(io_error)?;
        let unrecorded = request(&ready, id(1), b"cmd").await?;
        if unrecorded != ActionAnswer::NotRecorded {
            return Err(format!(
                "an action whose log cannot be written was answered `{unrecorded:?}`, not \
                 not-recorded"
            ));
        }
        let ran = ready.main_messages.executions.count();
        if ran != 0 {
            return Err(format!(
                "an action whose log cannot be written was handed to the machine's code {ran} \
                 times, not none"
            ));
        }
        let ending = single_ending(&sim, &ready.main_messages, PROMPT).await?;
        if !ending
            .as_ref()
            .is_err_and(|error| error.contains("audit.log"))
        {
            return Err(format!(
                "the service ended with `{ending:?}`, not the log's fault"
            ));
        }
        Ok(())
    })
}

/// A second writer holding the pair's action memory answers "busy", nothing runs and nothing is
/// remembered; once the writer is gone the same identifier runs.
pub(crate) fn a_second_process_on_the_root_is_busy() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let ready = ready(&sim, &beacon, Arc::new(NoFloor)).await?;
        ready.main_messages.executions.run(b"ok");
        ready
            .main_messages
            .serve(&ready.main_managed.connections, &ready.laptop);
        // The memory's lock file, held as the self-update window's second process holds it.
        let held = ready
            .main
            .root
            .lock_action(&ready.laptop.peer_id())
            .map_err(io_error)?;
        let busy = request(&ready, id(1), b"echo").await?;
        if busy != ActionAnswer::Busy {
            return Err(format!(
                "an action to a machine whose memory is held was answered `{busy:?}`, not busy"
            ));
        }
        let ran = ready.main_messages.executions.count();
        if ran != 0 {
            return Err(format!(
                "an action to a busy memory was handed to the machine's code {ran} times, not none"
            ));
        }
        drop(held);
        let again = request(&ready, id(1), b"echo").await?;
        if !ran_with(&again, b"ok") {
            return Err(format!(
                "the same action once the writer let go was answered `{again:?}`, not a run"
            ));
        }
        let ran = ready.main_messages.executions.count();
        if ran != 1 {
            return Err(format!("the action was run {ran} times, not once"));
        }
        Ok(())
    })
}
