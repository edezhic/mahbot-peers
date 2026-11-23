//! Action-layer cases: the at-most-once memory, the right, the one connection it shares with
//! messages, and the format on disk.
//!
//! Every case runs over the simulated link and the injected clock, and every execution is read
//! from the [`Executions`] rig the machine's layer was built with. Nothing here opens a socket
//! or starts a process; an action travels over the pair's own direct connection, on the same
//! stream reader a message uses.
//!
//! # What a case may not assume
//!
//! The layer reads no clock: the moment an action is remembered at is [`NOW`] plus the virtual
//! time the case has moved, and the memory's week is measured in that same time. A case that
//! advances the clock advances it for both machines, because the simulation has one.
//!
//! # Guards
//!
//! A guard may be pinned by more than one case, and a case may pin more than one guard; the guard
//! lists below name the cases that pin each guard, not a census of everything a change would
//! break. Two behaviours have no case at all and are described after them.
//!
//! Removing the journal's `Already` arm fails
//! `an_action_runs_once_when_the_operation_is_offered_three_times`,
//! `a_reused_identifier_is_a_repeat_whatever_the_body` and
//! `a_repeat_while_the_first_runs_is_already_executed`, the last of which also pins remembering
//! before the run; removing the decline's release fails
//! `a_declined_action_is_not_remembered_and_answered_as_not_run`, and answering it after a hard
//! fault fails `a_decline_is_answered_before_a_memory_fault_ends_the_service`; and removing the
//! log's full-log answer fails `an_action_that_cannot_be_recorded_does_not_run`, while removing
//! its hard-fault answer fails `a_log_that_cannot_be_written_is_a_fault_the_sender_hears`.
//!
//! Removing the durable unknown mark fails
//! `an_unanswered_action_is_unknown_and_never_offered_again`,
//! `a_slow_execution_is_unknown_and_another_pair_is_unaffected`,
//! `an_untraceable_unknown_names_both_outcomes`,
//! `a_panicking_executor_ends_the_service` and `an_eagerly_panicking_executor_ends_the_service`;
//! the not-sent classification fails `a_request_that_never_left_is_not_spent`, and the single
//! total budget fails `one_request_has_one_total_budget`.
//!
//! Removing the inbox's dispatch fails `a_message_and_an_action_share_one_connection` and
//! `a_malformed_action_is_answered_unreadable`, the throttle fails
//! `a_flood_of_actions_is_throttled_and_messages_are_unaffected`, its clamp fails
//! `a_retry_after_is_clamped_to_one_window`, the busy answer fails
//! `a_second_process_on_the_root_is_busy`, the traffic rule fails
//! `an_answered_action_is_the_pairs_traffic`,
//! `a_repeat_while_the_first_runs_is_already_executed`,
//! `a_result_too_large_to_carry_is_answered_and_remembered` and
//! `a_flood_of_actions_is_throttled_and_messages_are_unaffected`, and the panic guard fails
//! `a_panicking_executor_ends_the_service` and `an_eagerly_panicking_executor_ends_the_service`.
//!
//! The cases about the body carried verbatim, the identifier's hex round-trip, the additive file,
//! the privacy mode and the beacon's silence are the only ones here whose guard is a copy, a mode
//! or a constant.
//!
//! The release-before-answer order has no case: the window between the release and the answer is
//! one the rig has no hook into, so the order is held structurally instead — the two answers that
//! come after the identifier is remembered and say nothing ran, `not run` and `not recorded`,
//! both go through `Actions::release_then_answer`, which releases, then answers, and only then
//! hands back a hard fault.
//!
//! A write that does not finish has no case either: no transport this crate builds advertises a
//! stream window smaller than one frame, and the rig cannot put a small-window peer on the
//! receiving side of an action. The courtesy read is therefore reviewed, not exercised — the
//! normal path already proves `read_answer` hands an answer back, and the arm only decides to
//! call it.

pub(crate) mod link;
pub(crate) mod memory;
pub(crate) mod rights;

use std::sync::Arc;
use std::time::Duration;

use mahbot_peers::peer::{
    ACTION_ID_BYTES, ActionAnswer, ActionId, ActionKind, Authority, Capability, Execution, Floor,
    MAX_RESULT_BYTES, Pair, Timestamp,
};
use quinn::Connection;

use crate::actions::Executions;
use crate::beacon::TestBeacon;
use crate::sim::Sim;

use super::rights::{label, person};
use super::support::{Ready, main_binding, offer_frame, pair, within};

/// How many bytes of an answer a case reads: the result cap plus a magic, a version and a few
/// fields.
pub(super) const ANSWER_BYTES: usize = MAX_RESULT_BYTES + 256;

/// How long a case waits for something the crate does promptly.
pub(super) const PROMPT: Duration = Duration::from_secs(10);

/// How long a case waits for something that takes a whole budget.
pub(super) const LONG: Duration = Duration::from_secs(300);

/// The bytes an action frame opens with, as `src/peer/actions/wire.rs` spells them.
pub(super) const ACTION_MAGIC: &[u8] = b"mahbot-peer-action";

/// The frame version this build writes.
pub(super) const ACTION_VERSION: u8 = 1;

/// Whether an answer is a run whose result is exactly `expected`.
pub(super) fn ran_with(outcome: &ActionAnswer, expected: &[u8]) -> bool {
    matches!(outcome, ActionAnswer::Ran { result } if result == expected)
}

/// Two paired machines, connected, with the main bound to the laptop and "work on me" granted
/// on both sides, so a case can ask in either direction.
///
/// The laptop dials, so the case has one keeper and one dialling direction to reason about. The
/// main is the receiver of the cases' actions unless a case says otherwise.
pub(super) async fn ready(
    sim: &Sim,
    beacon: &TestBeacon,
    floor: Arc<dyn Floor + Send + Sync>,
) -> Result<Ready, String> {
    let ready = super::support::ready(sim, beacon, false, floor).await?;
    let admin = label("admin")?;
    ready
        .main
        .rights()?
        .grant(
            &pair(&ready.laptop, &admin),
            Capability::WORK,
            Authority::Person(person("egor")?),
            None,
            NOW,
        )
        .map_err(|error| error.to_string())?;
    // The laptop holds the same right for the pair its claim names, so a case can ask in
    // either direction on the one connection.
    ready
        .laptop
        .rights()?
        .grant(
            &pair(&ready.main, &admin),
            Capability::WORK,
            Authority::Person(person("egor")?),
            None,
            NOW,
        )
        .map_err(|error| error.to_string())?;
    Ok(ready)
}

/// Bind the main to the laptop and grant "work on me", after a case started unbound.
pub(super) fn bind_and_grant(ready: &Ready) -> Result<Pair, String> {
    let admin = label("admin")?;
    let pair = pair(&ready.laptop, &admin);
    ready
        .main
        .rights()?
        .bind(&ready.laptop.peer_id(), main_binding(&admin)?, NOW)
        .map_err(|error| error.to_string())?;
    ready
        .main
        .rights()?
        .grant(
            &pair,
            Capability::WORK,
            Authority::Person(person("egor")?),
            None,
            NOW,
        )
        .map_err(|error| error.to_string())?;
    Ok(pair)
}

/// An operation's identifier, distinct for each `n` a case uses.
pub(super) fn id(n: u64) -> ActionId {
    let mut bytes = [0u8; ACTION_ID_BYTES];
    bytes[..8].copy_from_slice(&n.to_be_bytes());
    ActionId::from_bytes(bytes)
}

/// Ask the main to run one action over the laptop's live connection.
pub(super) async fn request(
    ready: &Ready,
    id: ActionId,
    body: &[u8],
) -> Result<ActionAnswer, String> {
    ready
        .laptop_messages
        .actions
        .request(
            &ready.laptop_managed.connections,
            &ready.laptop_managed.endpoint,
            &ready.main.peer_id(),
            id,
            ActionKind::COMMAND,
            body,
        )
        .await
        .map_err(|error| error.to_string())
}

/// Offer one frame's bytes over `connection` and read the answer, so a case can send a frame
/// the typed action would not produce.
pub(super) async fn offer_bytes(
    connection: &Connection,
    bytes: &[u8],
) -> Result<ActionAnswer, String> {
    ActionAnswer::decode(&offer_frame(connection, bytes, ANSWER_BYTES).await?)
        .map_err(|error| error.to_string())
}

/// Wait until the machine's own code has been handed `count` actions.
pub(super) async fn wait_for_executions(
    sim: &Sim,
    executions: &Executions,
    count: usize,
    budget: Duration,
) -> Result<Vec<Execution>, String> {
    within(sim, budget, async {
        loop {
            if executions.count() >= count {
                return Ok::<Vec<Execution>, String>(executions.handed());
            }
            tokio::task::yield_now().await;
        }
    })
    .await?
}

/// A moment a case composes at: the message layer's own base.
pub(super) const NOW: Timestamp = crate::messages::NOW;
