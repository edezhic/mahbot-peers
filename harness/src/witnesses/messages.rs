//! Message-layer cases: the queue, its format, the offer, the receiver's answers and
//! the rights around them.
//!
//! Every case runs over the simulated link and the injected clock, and every delivery
//! is read from the sink the layer was built with. Nothing here opens a socket or
//! starts a process; the messages travel over the pair's own direct connection.
//!
//! # What a case may not assume
//!
//! The layer reads no clock: the moment a case composes at is [`NOW`] plus the virtual
//! time it has moved, and a retention or a window is measured in that same time. A
//! case that advances the clock advances it for both machines, because the simulation
//! has one.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use mahbot_peers::identity::Fingerprint;
use mahbot_peers::peer::audit::{MAX_FILE_BYTES, RESERVED_FOR_PERSON_BYTES};
use mahbot_peers::peer::messages::MAX_MESSAGES_BYTES;
use mahbot_peers::peer::{
    Act, Answer, Authority, Capability, Decision, DropReason, Dropped, EXCHANGE_BUDGET, Envelope,
    Floor, Gap, KEEPER_UNSTABLE_LIMIT, Keeper, MAX_BODY_BYTES, MAX_OFFERS_PER_WINDOW, MAX_QUEUE,
    MESSAGE_BUDGET, MESSAGE_RETENTION, MESSAGE_WINDOW, Message, MessageError, NoFloor, Pair,
    Question, QueueState, Refusal, RefusedReason, Speaker, Step, TAKEN_RETENTION, Timestamp,
};
use quinn::Connection;

use crate::beacon::TestBeacon;
use crate::clock::block_on;
use crate::connect::TrustSet;
use crate::machine::Machine;
use crate::messages::{Messaging, NOW, wait_for, wait_for_state};
use crate::sim::Sim;

use super::connection::Managed;
use super::peer::session;
use super::rights::{fill_log, label, paired_machines, person};
use super::support::{
    binding, field, holds_bytes, io_error, main_binding, offer_frame, pair, ready, single_ending,
    spawn_keeper, wait_live, within,
};

/// Offer one message by hand, as the sender's own service would.
async fn offer_raw(connection: &Connection, message: &Message) -> Result<Answer, String> {
    let bytes = message.encode().map_err(|error| error.to_string())?;
    offer_bytes(connection, &bytes).await
}

/// Offer one frame's bytes and read the answer, so a case can send a frame the typed
/// messages would not produce.
async fn offer_bytes(connection: &Connection, bytes: &[u8]) -> Result<Answer, String> {
    Answer::decode(&offer_frame(connection, bytes, ANSWER_BYTES).await?)
        .map_err(|error| error.to_string())
}

/// How many bytes of an answer a case reads. Comfortably more than the longest answer this
/// build writes — a magic, a version, a status and one four-byte delay — so a longer answer
/// does not turn the rig's read into a failure of its own.
const ANSWER_BYTES: usize = 256;

/// How long a service may take to end when the case is showing *which* path met the refusal:
/// a round is `MESSAGE_POLL` and the service's own sweep is `SWEEP_EVERY`, so a few seconds
/// cannot be the sweep.
const PROMPT: Duration = Duration::from_secs(5);

/// How long a case waits for a service to end when it only cares that it did.
const LONG: Duration = Duration::from_secs(120);

/// The bytes a message frame opens with: the offset of its version byte is this length.
const MESSAGE_MAGIC: &[u8] = b"mahbot-peer-message";

/// The bytes a queue file opens with: the offset of its version byte is this length.
const QUEUE_MAGIC: &[u8] = b"mahbot-peer-messages";

/// The frame with the body of its first `tag` field replaced by `with`'s answer, keeping
/// its magic, its version and every other field as they are.
///
/// One walk for the two shapes a case has to produce: a queue file whose nested record a
/// newer build grew, and a message frame whose count a sender renumbered. `head` is the
/// magic and the version byte, which are copied and never walked. A frame with no such
/// field is a mistake in the case, not a frame the format allows, so it is an error.
fn rewrite(
    frame: &[u8],
    head: usize,
    tag: u8,
    with: impl Fn(&[u8]) -> Vec<u8>,
) -> Result<Vec<u8>, String> {
    let mut out = frame
        .get(..head)
        .ok_or("a frame is shorter than its magic and version")?
        .to_vec();
    let mut rest = &frame[head..];
    let mut replaced = false;
    while !rest.is_empty() {
        let (&each, after_tag) = rest.split_first().ok_or("a field has no tag")?;
        let (length, after_length) = after_tag
            .split_first_chunk::<2>()
            .ok_or("a field has no length")?;
        let length = usize::from(u16::from_be_bytes(*length));
        let (body, after_body) = after_length
            .split_at_checked(length)
            .ok_or("a field runs past the end")?;
        if each == tag && !replaced {
            replaced = true;
            out.extend_from_slice(&field(each, &with(body)));
        } else {
            out.push(each);
            out.extend_from_slice(
                &u16::try_from(length)
                    .expect("a field read from a frame is short")
                    .to_be_bytes(),
            );
            out.extend_from_slice(body);
        }
        rest = after_body;
    }
    if !replaced {
        return Err(format!("the frame has no {tag:#04x} field to rewrite"));
    }
    Ok(out)
}

/// Two machines a person paired, each remembering the other's address.
fn pair_up(left: &Machine, right: &Machine) -> Result<(), String> {
    for (machine, peer) in [(left, right), (right, left)] {
        let store = machine.records();
        store
            .record_pairing(&peer.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        store
            .record_address(&peer.peer_id(), peer.addr())
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The queue
// ---------------------------------------------------------------------------

/// A message is durable in the sender's queue before any connection, named once and
/// counted within the pair, and its body is stored exactly as it was composed.
pub(crate) fn a_message_is_queued_and_stored_as_written() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let messaging = Messaging::open(&sim, &laptop, Arc::new(NoFloor))?;
        // A body a rendering would change: a newline, a tab and a non-ASCII byte.
        let body = "first line\ncaf\u{e9}\tand a tab\n".as_bytes().to_vec();
        let first = messaging
            .messages
            .send(&main.peer_id(), NOW, &body)
            .map_err(|error| error.to_string())?;
        let second = messaging
            .messages
            .send(&main.peer_id(), NOW, &body)
            .map_err(|error| error.to_string())?;
        if first.count() != 1 || second.count() != 2 {
            return Err(format!(
                "the two messages were counted {} and {}, not one and two",
                first.count(),
                second.count()
            ));
        }
        if first.id() == second.id() {
            return Err(format!("both messages are named {}", first.id()));
        }
        if first.composed_at() != NOW || second.composed_at() != NOW {
            return Err("a message was not recorded at the moment it was composed".to_owned());
        }
        let pending = messaging
            .messages
            .pending(&main.peer_id())
            .map_err(|error| error.to_string())?;
        if pending != vec![first, second] {
            return Err(format!(
                "the queue holds {pending:?}, not the two envelopes in order"
            ));
        }
        let stored = laptop
            .storage()
            .read_message(&main.peer_id())
            .map_err(io_error)?;
        if !holds_bytes(&stored, &body) {
            return Err(
                "the queue file does not hold the body byte for byte: it was escaped or rendered"
                    .to_owned(),
            );
        }
        // The escaped spelling of the newline is two bytes, and neither is in the body.
        if holds_bytes(&stored, b"\\n") {
            return Err("the queue file stores the newline escaped".to_owned());
        }
        let state = messaging
            .messages
            .state(&main.peer_id())
            .map_err(|error| error.to_string())?;
        if state == QueueState::Empty {
            return Err("a machine with two queued messages reports an empty queue".to_owned());
        }
        Ok(())
    })
}

/// A body is bounded: one of exactly the cap is queued, one byte more is refused, and the
/// refusal writes nothing.
pub(crate) fn a_body_longer_than_the_cap_is_refused() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let messaging = Messaging::open(&sim, &laptop, Arc::new(NoFloor))?;
        let at_cap = vec![b'a'; MAX_BODY_BYTES];
        let envelope = messaging
            .messages
            .send(&main.peer_id(), NOW, &at_cap)
            .map_err(|error| {
                format!("a body of exactly {MAX_BODY_BYTES} bytes was refused: {error}")
            })?;
        let before = laptop
            .storage()
            .read_message(&main.peer_id())
            .map_err(io_error)?;
        let over = vec![b'b'; MAX_BODY_BYTES + 1];
        match messaging.messages.send(&main.peer_id(), NOW, &over) {
            Err(MessageError::Body { bytes, limit })
                if bytes == MAX_BODY_BYTES + 1 && limit == MAX_BODY_BYTES => {}
            Err(error) => {
                return Err(format!(
                    "a body of {} bytes was refused with `{error}`, not as over the \
                     {MAX_BODY_BYTES}-byte cap",
                    over.len()
                ));
            }
            Ok(queued) => {
                return Err(format!(
                    "a body of {} bytes was queued as count {}",
                    over.len(),
                    queued.count()
                ));
            }
        }
        let pending = messaging
            .messages
            .pending(&main.peer_id())
            .map_err(|error| error.to_string())?;
        if pending != vec![envelope] {
            return Err(format!(
                "the queue holds {pending:?} after a refusal, not the one message at the cap"
            ));
        }
        let after = laptop
            .storage()
            .read_message(&main.peer_id())
            .map_err(io_error)?;
        if after != before {
            return Err("a refused body changed the queue file".to_owned());
        }
        Ok(())
    })
}

/// The moment a message says it was composed is a remark: the queue orders by count and
/// measures retention from the moment it stored the message, not from the caller's.
pub(crate) fn the_composed_moment_is_only_a_remark() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let messaging = Messaging::open(&sim, &laptop, Arc::new(NoFloor))?;
        // A moment long before the queue's own, and one a year after it.
        let epoch = Timestamp::from_unix_seconds(0);
        let ahead = NOW.plus(Duration::from_hours(365 * 24));
        let first = messaging
            .messages
            .send(&main.peer_id(), epoch, b"composed long before the queue")
            .map_err(|error| error.to_string())?;
        let second = messaging
            .messages
            .send(&main.peer_id(), ahead, b"composed a year from now")
            .map_err(|error| error.to_string())?;
        if first.composed_at() != epoch || second.composed_at() != ahead {
            return Err("a message was not recorded at the moment it was composed".to_owned());
        }
        let pending = messaging
            .messages
            .pending(&main.peer_id())
            .map_err(|error| error.to_string())?;
        if pending != vec![first, second] {
            return Err(format!(
                "the queue holds {pending:?}, not the two messages in count order"
            ));
        }
        // Retention runs from the queue's own moment: 71 hours on, both are still here,
        // although one says it is a year old and the other a year from now.
        sim.clock().advance(Duration::from_hours(71)).await;
        let sweep = messaging
            .messages
            .sweep()
            .map_err(|error| error.to_string())?;
        if sweep.expired != 0 || sweep.withdrawn != 0 {
            return Err(format!(
                "a sweep 71 hours after the messages were queued dropped {} expired and {} \
                 withdrawn, not none",
                sweep.expired, sweep.withdrawn
            ));
        }
        let pending = messaging
            .messages
            .pending(&main.peer_id())
            .map_err(|error| error.to_string())?;
        if pending.len() != 2 {
            return Err(format!(
                "the queue holds {} messages 71 hours after they were queued, not two",
                pending.len()
            ));
        }
        // Past the 72 hours the queue measured, both go, and the drop names both.
        sim.clock().advance(Duration::from_hours(1)).await;
        let at = NOW.plus(sim.clock().elapsed());
        let sweep = messaging
            .messages
            .sweep()
            .map_err(|error| error.to_string())?;
        if sweep.expired != 2 || sweep.withdrawn != 0 {
            return Err(format!(
                "a sweep 72 hours after the messages were queued dropped {} expired and {} \
                 withdrawn, not two and none",
                sweep.expired, sweep.withdrawn
            ));
        }
        if !messaging
            .messages
            .pending(&main.peer_id())
            .map_err(|error| error.to_string())?
            .is_empty()
        {
            return Err("a message past its retention is still queued".to_owned());
        }
        let entries = laptop
            .audit()?
            .entries()
            .map_err(|error| error.to_string())?;
        let named = entries.iter().any(|entry| {
            let Act::MessagesDropped {
                peer,
                dropped,
                reason: DropReason::Expired,
            } = &entry.act
            else {
                return false;
            };
            let mut counts: Vec<u64> = dropped.iter().map(|one| one.count).collect();
            counts.sort_unstable();
            *peer == main.peer_id() && entry.at == at && counts == [first.count(), second.count()]
        });
        if !named {
            return Err(format!(
                "no expiry at {at} names the two messages the queue dropped"
            ));
        }
        Ok(())
    })
}

/// A pair's queue is bounded, and a full queue refuses the next message instead of
/// dropping an older one.
pub(crate) fn a_full_queue_is_refused() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let messaging = Messaging::open(&sim, &laptop, Arc::new(NoFloor))?;
        for index in 0..MAX_QUEUE {
            messaging
                .messages
                .send(&main.peer_id(), NOW, format!("message {index}").as_bytes())
                .map_err(|error| error.to_string())?;
        }
        match messaging
            .messages
            .send(&main.peer_id(), NOW, b"one too many")
        {
            Err(MessageError::Full { limit, .. }) if limit == MAX_QUEUE => {}
            Err(error) => {
                return Err(format!(
                    "a full queue refused with `{error}`, not `full` at {MAX_QUEUE}"
                ));
            }
            Ok(envelope) => {
                return Err(format!(
                    "a full queue accepted count {} as well",
                    envelope.count()
                ));
            }
        }
        let pending = messaging
            .messages
            .pending(&main.peer_id())
            .map_err(|error| error.to_string())?;
        if pending.len() != MAX_QUEUE {
            return Err(format!(
                "the queue holds {} messages after a refusal, not {MAX_QUEUE}",
                pending.len()
            ));
        }
        if pending.first().map(Envelope::count) != Some(1)
            || pending.last().map(Envelope::count) != Some(MAX_QUEUE as u64)
        {
            return Err("the refusal changed which messages the queue holds".to_owned());
        }
        Ok(())
    })
}

/// A sender's queue survives the sender's restart: the machine closes its endpoint, comes
/// back over the same root, and a layer opened afresh on it reads the same messages, in the
/// same order, with their bodies and counts.
pub(crate) fn the_queue_survives_the_senders_restart() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, mut laptop) = paired_machines(&sim)?;
        let bodies: [&[u8]; 2] = [b"the first thing said", b"the second thing said"];
        {
            let before = Messaging::open(&sim, &laptop, Arc::new(NoFloor))?;
            for body in bodies {
                before
                    .messages
                    .send(&main.peer_id(), NOW, body)
                    .map_err(|error| error.to_string())?;
            }
        }
        // The sending machine restarts, as the receiving one does in its own case: its
        // endpoint closes, its identity and records are read from the root again, and it
        // comes back at a fresh address. Nothing re-pairs it — the pairing is in the root,
        // and this case is about the queue — so the address is not needed.
        let _moved = laptop.restart().await?;
        laptop.reopen_records()?;
        // A new layer, a new sink: everything it knows is the root.
        let after = Messaging::open(&sim, &laptop, Arc::new(NoFloor))?;
        let pending = after
            .messages
            .pending(&main.peer_id())
            .map_err(|error| error.to_string())?;
        if pending.len() != 2 {
            return Err(format!(
                "the reopened queue holds {} messages, not two",
                pending.len()
            ));
        }
        if pending[0].count() != 1 || pending[1].count() != 2 {
            return Err("the reopened queue lost the order of the two messages".to_owned());
        }
        if pending[0].composed_at() != NOW || pending[1].composed_at() != NOW {
            return Err("the reopened queue lost the moment a message was composed".to_owned());
        }
        let stored = laptop
            .storage()
            .read_message(&main.peer_id())
            .map_err(io_error)?;
        for body in bodies {
            if !holds_bytes(&stored, body) {
                return Err("a reopened queue lost a body".to_owned());
            }
        }
        Ok(())
    })
}

/// A queue that cannot grow is refused: a file a newer build filled to just under the cap
/// takes no further message, and the refusal leaves the file exactly as it was.
///
/// The cap is the module's own `MAX_MESSAGES_BYTES`, and one queued message is tens of bytes,
/// so the planted file leaves less than one message's room.
pub(crate) fn a_queue_that_cannot_grow_is_refused() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let messaging = Messaging::open(&sim, &laptop, Arc::new(NoFloor))?;
        const CAP: usize = MAX_MESSAGES_BYTES as usize;
        const ROOM: usize = CAP - 32;
        let mut planted = QUEUE_MAGIC.to_vec();
        planted.push(1);
        planted.extend_from_slice(&field(0x01, &1u64.to_be_bytes()));
        planted.extend_from_slice(&field(0x02, &0u64.to_be_bytes()));
        // Fields this build does not know, as a newer build leaves them: a body is bounded
        // by the format's two-byte length, so several of them carry the file to the cap.
        let filler = [b'x'; 60_000];
        while planted.len() + filler.len() + 3 < ROOM {
            planted.extend_from_slice(&field(0x7f, &filler));
        }
        planted.extend_from_slice(&field(0x7f, &vec![b'x'; ROOM - planted.len() - 3]));
        if planted.len() != ROOM {
            return Err(format!(
                "the planted queue is {} bytes, not the {ROOM} the case needs",
                planted.len()
            ));
        }
        laptop
            .storage()
            .write_message(&main.peer_id(), &planted)
            .map_err(io_error)?;
        match messaging.messages.send(&main.peer_id(), NOW, b"one more") {
            Err(MessageError::TooLarge { .. }) => {}
            Err(error) => {
                return Err(format!(
                    "a queue that cannot grow refused with `{error}`, not `too large`"
                ));
            }
            Ok(envelope) => {
                return Err(format!(
                    "a queue that cannot grow accepted count {} as well",
                    envelope.count()
                ));
            }
        }
        let stored = laptop
            .storage()
            .read_message(&main.peer_id())
            .map_err(io_error)?;
        if stored != planted {
            return Err(format!(
                "the refused message rewrote the queue: {} bytes, not the {} planted",
                stored.len(),
                planted.len()
            ));
        }
        Ok(())
    })
}

/// A queue another writer holds answers `Busy` rather than blocking, and the same call works
/// once the writer lets go: the second process a self-update leaves on one root.
///
/// The case plays that process by holding the peer's lock file, which is what a
/// read-modify-publish does for its span. A queue that answered by blocking would let a
/// caller's own code decide how long this machine's tasks wait.
pub(crate) fn a_queue_another_writer_holds_is_busy() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let messaging = Messaging::open(&sim, &laptop, Arc::new(NoFloor))?;
        messaging
            .messages
            .send(&main.peer_id(), NOW, b"queued before the other writer")
            .map_err(|error| error.to_string())?;
        let held = laptop
            .storage()
            .lock_message(&main.peer_id())
            .map_err(io_error)?;
        // A write needs the lock and is refused rather than waiting for it.
        match messaging
            .messages
            .send(&main.peer_id(), NOW, b"while the other writer holds it")
        {
            Err(MessageError::Busy { peer }) if peer == main.peer_id() => {}
            other => {
                return Err(format!(
                    "a write with the queue held answered `{other:?}`, not `busy`"
                ));
            }
        }
        // A read does not: the queue is published by one rename, so what a reader sees is
        // whole whatever a writer is doing.
        let pending = messaging
            .messages
            .pending(&main.peer_id())
            .map_err(|error| error.to_string())?;
        if pending.len() != 1 {
            return Err(format!(
                "a read with a writer holding the queue found {} messages, not the one queued",
                pending.len()
            ));
        }
        held.unlock().map_err(io_error)?;
        let envelope = messaging
            .messages
            .send(&main.peer_id(), NOW, b"after the other writer let go")
            .map_err(|error| error.to_string())?;
        if envelope.count() != 2 {
            return Err(format!(
                "the message queued after the other writer let go is count {}, not two",
                envelope.count()
            ));
        }
        Ok(())
    })
}

/// A message untaken after the retention is dropped, and the drop is recorded once.
pub(crate) fn an_untaken_message_is_dropped_after_retention_and_recorded() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let messaging = Messaging::open(&sim, &laptop, Arc::new(NoFloor))?;
        let envelope = messaging
            .messages
            .send(&main.peer_id(), NOW, b"nobody was there to take this")
            .map_err(|error| error.to_string())?;
        let at = NOW.plus(MESSAGE_RETENTION);
        // The layer reads one clock, so the case moves that clock rather than passing a
        // second moment beside it: nothing is expired before its own retention.
        if messaging
            .messages
            .sweep()
            .map_err(|error| error.to_string())?
            .expired
            != 0
        {
            return Err("a message was expired before its retention".to_owned());
        }
        messaging.moment.shift(MESSAGE_RETENTION);
        let sweep = messaging
            .messages
            .sweep()
            .map_err(|error| error.to_string())?;
        if sweep.expired != 1 || sweep.withdrawn != 0 {
            return Err(format!(
                "the sweep dropped {} expired and {} withdrawn messages, not one and none",
                sweep.expired, sweep.withdrawn
            ));
        }
        if !messaging
            .messages
            .pending(&main.peer_id())
            .map_err(|error| error.to_string())?
            .is_empty()
        {
            return Err("a message past its retention is still queued".to_owned());
        }
        let dropped = |entries: &[mahbot_peers::peer::Entry]| {
            entries
                .iter()
                .filter(|entry| {
                    matches!(
                        entry.act,
                        Act::MessagesDropped {
                            reason: DropReason::Expired,
                            ..
                        }
                    )
                })
                .count()
        };
        let entries = laptop
            .audit()?
            .entries()
            .map_err(|error| error.to_string())?;
        if dropped(&entries) != 1 {
            return Err(format!(
                "the log holds {} recorded expiries, not one",
                dropped(&entries)
            ));
        }
        let named = entries.iter().any(|entry| {
            matches!(
                &entry.act,
                Act::MessagesDropped { peer, dropped, reason: DropReason::Expired }
                    if *peer == main.peer_id()
                        && dropped.as_slice()
                            == [Dropped {
                                count: envelope.count(),
                                id: *envelope.id().as_bytes(),
                            }]
            ) && entry.at == at
        });
        if !named {
            return Err(format!(
                "no expiry at {at} names count {} and its identifier",
                envelope.count()
            ));
        }
        let again = messaging
            .messages
            .sweep()
            .map_err(|error| error.to_string())?;
        if again.expired != 0 {
            return Err("a second sweep expired a message the first one dropped".to_owned());
        }
        let entries = laptop
            .audit()?
            .entries()
            .map_err(|error| error.to_string())?;
        if dropped(&entries) != 1 {
            return Err("a second sweep recorded the same expiry again".to_owned());
        }
        Ok(())
    })
}

/// Withdrawing trust drops that pair's queue, records why, and refuses the next message.
pub(crate) fn a_withdrawn_trust_drops_the_queue_and_records_it() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let messaging = Messaging::open(&sim, &laptop, Arc::new(NoFloor))?;
        let envelope = messaging
            .messages
            .send(&main.peer_id(), NOW, b"said to a machine no longer trusted")
            .map_err(|error| error.to_string())?;
        laptop
            .rights()?
            .withdraw_trust(&main.peer_id(), person("owner")?, NOW)
            .map_err(|error| error.to_string())?;
        let sweep = messaging
            .messages
            .sweep()
            .map_err(|error| error.to_string())?;
        if sweep.withdrawn != 1 || sweep.expired != 0 {
            return Err(format!(
                "the sweep dropped {} withdrawn and {} expired messages, not one and none",
                sweep.withdrawn, sweep.expired
            ));
        }
        if !messaging
            .messages
            .pending(&main.peer_id())
            .map_err(|error| error.to_string())?
            .is_empty()
        {
            return Err(
                "a queue for a machine this one no longer trusts is still there".to_owned(),
            );
        }
        let entries = laptop
            .audit()?
            .entries()
            .map_err(|error| error.to_string())?;
        let named = entries.iter().any(|entry| {
            matches!(
                &entry.act,
                Act::MessagesDropped { peer, dropped, reason: DropReason::TrustWithdrawn }
                    if *peer == main.peer_id()
                        && dropped.as_slice()
                            == [Dropped {
                                count: envelope.count(),
                                id: *envelope.id().as_bytes(),
                            }]
            )
        });
        if !named {
            return Err("the withdrawal of trust recorded no dropped queue".to_owned());
        }
        match messaging
            .messages
            .send(&main.peer_id(), NOW, b"still there?")
        {
            Err(MessageError::Withdrawn { .. }) => Ok(()),
            Err(error) => Err(format!(
                "a message to a withdrawn machine was refused with `{error}`, not as withdrawn"
            )),
            Ok(_) => Err("a message to a withdrawn machine was queued".to_owned()),
        }
    })
}

/// A running service sweeps its own queue: a trust withdrawn while the service runs drops
/// the queue and records it, without the caller ever sweeping by hand.
///
/// This is what a product that runs only the services relies on, and it is the difference
/// between `serve`'s own sweep and the explicit [`Messages::sweep`] a case calls.
pub(crate) fn the_service_sweeps_its_own_queue() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let connected = ready(&sim, &beacon, false, Arc::new(NoFloor)).await?;
        let envelope = connected
            .laptop_messages
            .messages
            .send(
                &connected.main.peer_id(),
                NOW,
                b"for a machine this one stops trusting",
            )
            .map_err(|error| error.to_string())?;
        connected
            .laptop_messages
            .serve(&connected.laptop_managed.connections, &connected.main);
        connected
            .laptop
            .rights()?
            .withdraw_trust(&connected.main.peer_id(), person("owner")?, NOW)
            .map_err(|error| error.to_string())?;
        // One `SWEEP_EVERY` and a second: the service's own round sweeps its peer, and the
        // case never calls `sweep`.
        sim.clock().advance(Duration::from_secs(31)).await;
        let pending = connected
            .laptop_messages
            .messages
            .pending(&connected.main.peer_id())
            .map_err(|error| error.to_string())?;
        if !pending.is_empty() {
            return Err(format!(
                "a running service kept {} messages for a machine this one no longer trusts",
                pending.len()
            ));
        }
        let recorded = connected
            .laptop
            .audit()?
            .entries()
            .map_err(|error| error.to_string())?;
        let named = recorded.iter().any(|entry| {
            matches!(
                &entry.act,
                Act::MessagesDropped { peer, dropped, reason: DropReason::TrustWithdrawn }
                    if *peer == connected.main.peer_id()
                        && dropped.as_slice()
                            == [Dropped {
                                count: envelope.count(),
                                id: *envelope.id().as_bytes(),
                            }]
            )
        });
        if !named {
            return Err("the service dropped the queue without recording it".to_owned());
        }
        if !connected.laptop_messages.collected.deliveries().is_empty() {
            return Err("a queue dropped by the service still delivered something".to_owned());
        }
        Ok(())
    })
}

/// A message for a pair closed by three failed comparisons is refused before it is
/// written, and a withdrawn trust is still answered as withdrawn.
pub(crate) fn a_message_for_a_closed_pair_is_refused() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let messaging = Messaging::open(&sim, &laptop, Arc::new(NoFloor))?;
        let store = laptop.records();
        for _ in 0..3 {
            store
                .record_failure(&main.peer_id())
                .map_err(|error| error.to_string())?;
        }
        if !store.is_closed(&main.peer_id()) {
            return Err("three failed comparisons did not close the pair".to_owned());
        }
        match messaging
            .messages
            .send(&main.peer_id(), NOW, b"to a pair nobody can reopen")
        {
            Err(MessageError::Closed { .. }) => {}
            Err(error) => {
                return Err(format!(
                    "a message to a closed pair was refused with `{error}`, not as closed"
                ));
            }
            Ok(queued) => {
                return Err(format!(
                    "a message to a closed pair was queued as count {}",
                    queued.count()
                ));
            }
        }
        if !messaging
            .messages
            .pending(&main.peer_id())
            .map_err(|error| error.to_string())?
            .is_empty()
        {
            return Err("a message refused for a closed pair was written to the queue".to_owned());
        }
        // A closed pair a person then untrusts is answered as withdrawn: the withdrawal is
        // checked first, so the answer names the act that removed the rights.
        laptop
            .rights()?
            .withdraw_trust(&main.peer_id(), person("owner")?, NOW)
            .map_err(|error| error.to_string())?;
        match messaging
            .messages
            .send(&main.peer_id(), NOW, b"to a machine no longer trusted")
        {
            Err(MessageError::Withdrawn { .. }) => Ok(()),
            Err(error) => Err(format!(
                "a message to a withdrawn trust was refused with `{error}`, not as withdrawn"
            )),
            Ok(_) => Err("a message to a withdrawn trust was queued".to_owned()),
        }
    })
}

// ---------------------------------------------------------------------------
// The offer and the answer
// ---------------------------------------------------------------------------

/// The same envelope offered three times reaches the receiver's caller once and the two later
/// offers are answered `already taken`; a fresh identifier under a count already delivered is
/// taken, with the rewind declared.
pub(crate) fn the_same_envelope_reaches_the_caller_once() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        main.rights()?
            .bind(&laptop.peer_id(), main_binding(&label("admin")?)?, NOW)
            .map_err(|error| error.to_string())?;
        let main_managed = Managed::start(&sim, &beacon, &main, &main.records())?;
        let laptop_managed = Managed::start(&sim, &beacon, &laptop, &laptop.records())?;
        let main_messages = Messaging::open(&sim, &main, Arc::new(NoFloor))?;
        let laptop_messages = Messaging::open(&sim, &laptop, Arc::new(NoFloor))?;
        let connection = laptop_managed
            .connections
            .connect(&laptop_managed.endpoint, &main.fingerprint())
            .await
            .map_err(|error| error.to_string())?;
        wait_live(&sim, &main_managed.connections, &laptop.peer_id()).await?;
        wait_live(&sim, &laptop_managed.connections, &main.peer_id()).await?;
        // Only the receiving machine's service runs: the sender's queue would offer the
        // same envelope itself, and the case could no longer count the answers.
        main_messages.serve(&main_managed.connections, &laptop);
        let envelope = laptop_messages
            .messages
            .send(&main.peer_id(), NOW, b"hello")
            .map_err(|error| error.to_string())?;
        let message =
            Message::new(envelope, b"hello".to_vec()).map_err(|error| error.to_string())?;
        let answers = within(&sim, Duration::from_secs(60), async {
            let mut answers = Vec::with_capacity(3);
            for _ in 0..3 {
                answers.push(offer_raw(&connection, &message).await?);
            }
            Ok::<Vec<Answer>, String>(answers)
        })
        .await??;
        if answers != vec![Answer::Taken, Answer::AlreadyTaken, Answer::AlreadyTaken] {
            return Err(format!(
                "three offers of one envelope were answered {answers:?}, not taken then twice \
                 already taken"
            ));
        }
        // The identifier is what catches a sender that renumbered a message it had already
        // sent: the count is above the one taken, and the answer is still "already taken".
        let bumped = rewrite(
            &message.encode().map_err(|error| error.to_string())?,
            MESSAGE_MAGIC.len() + 1,
            0x02,
            |_| 2u64.to_be_bytes().to_vec(),
        )?;
        let answer = within(
            &sim,
            Duration::from_secs(60),
            offer_bytes(&connection, &bumped),
        )
        .await??;
        if answer != Answer::AlreadyTaken {
            return Err(format!(
                "an already-taken identifier offered under a higher count was answered \
                 `{answer:?}`, not already taken"
            ));
        }
        // A fresh identifier under a count this machine remembers taking is delivered: only a
        // remembered identifier suppresses a message, and the count is declared, not obeyed.
        let rewound = rewrite(
            &message.encode().map_err(|error| error.to_string())?,
            MESSAGE_MAGIC.len() + 1,
            0x01,
            |_| vec![0xab; 16],
        )?;
        let answer = within(
            &sim,
            Duration::from_secs(60),
            offer_bytes(&connection, &rewound),
        )
        .await??;
        if answer != Answer::Taken {
            return Err(format!(
                "a fresh identifier under a count already taken was answered `{answer:?}`, not \
                 taken"
            ));
        }
        let delivered = main_messages.collected.deliveries();
        if delivered.len() != 2 {
            return Err(format!(
                "the receiver's caller was handed {} messages, not the two that were offered \
                 under fresh identifiers",
                delivered.len()
            ));
        }
        if delivered[1].envelope.count() != 1 || delivered[1].gap != Some(Gap::Rewound) {
            return Err(format!(
                "a fresh identifier under a taken count arrived as count {} with gap {:?}, not \
                 as a declared rewind",
                delivered[1].envelope.count(),
                delivered[1].gap
            ));
        }
        let delivery = &delivered[0];
        if delivery.envelope.id() != envelope.id()
            || delivery.envelope.count() != envelope.count()
            || delivery.body != b"hello"
            || delivery.sender != laptop.peer_id()
        {
            return Err(format!(
                "the delivery is not the message offered: {delivery:?}"
            ));
        }
        Ok(())
    })
}

/// The receiver's memory of taken identifiers is in its root: a layer reopened over the
/// same root still answers `already taken` for an identifier it holds, and a fresh one under
/// a count it has delivered is taken with the rewind declared.
pub(crate) fn the_receivers_memory_survives_its_restart() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (mut main, laptop) = paired_machines(&sim)?;
        main.rights()?
            .bind(&laptop.peer_id(), main_binding(&label("admin")?)?, NOW)
            .map_err(|error| error.to_string())?;
        let mut main_managed = Managed::start(&sim, &beacon, &main, &main.records())?;
        let laptop_managed = Managed::start(&sim, &beacon, &laptop, &laptop.records())?;
        let laptop_messages = Messaging::open(&sim, &laptop, Arc::new(NoFloor))?;
        let connection = laptop_managed
            .connections
            .connect(&laptop_managed.endpoint, &main.fingerprint())
            .await
            .map_err(|error| error.to_string())?;
        wait_live(&sim, &main_managed.connections, &laptop.peer_id()).await?;
        wait_live(&sim, &laptop_managed.connections, &main.peer_id()).await?;
        let envelope = laptop_messages
            .messages
            .send(&main.peer_id(), NOW, b"taken once")
            .map_err(|error| error.to_string())?;
        let message =
            Message::new(envelope, b"taken once".to_vec()).map_err(|error| error.to_string())?;
        {
            let before = Messaging::open(&sim, &main, Arc::new(NoFloor))?;
            before.serve(&main_managed.connections, &laptop);
            let answer = within(
                &sim,
                Duration::from_secs(60),
                offer_raw(&connection, &message),
            )
            .await??;
            if answer != Answer::Taken {
                return Err(format!(
                    "the first offer was answered `{answer:?}`, not taken"
                ));
            }
            if before.collected.len() != 1 {
                return Err("the first offer was not handed to the caller".to_owned());
            }
        }
        // The receiving machine restarts: its endpoint closes, its identity and records
        // are read from the root again, and it comes back at the address the sender
        // remembers. What it remembers about the message is the file, not a value that
        // answered the first offer.
        let remembered = main.addr();
        drop(main_managed);
        let moved = main.restart().await?;
        if moved != remembered {
            main.rebind(remembered).map_err(|error| {
                format!("the restarted machine could not take its address back: {error}")
            })?;
        }
        main_managed = Managed::start(&sim, &beacon, &main, &main.records())?;
        let after = Messaging::open(&sim, &main, Arc::new(NoFloor))?;
        after.serve(&main_managed.connections, &laptop);
        let connection = laptop_managed
            .connections
            .connect(&laptop_managed.endpoint, &main.fingerprint())
            .await
            .map_err(|error| error.to_string())?;
        wait_live(&sim, &main_managed.connections, &laptop.peer_id()).await?;
        let answer = within(
            &sim,
            Duration::from_secs(60),
            offer_raw(&connection, &message),
        )
        .await??;
        if answer != Answer::AlreadyTaken {
            return Err(format!(
                "a restarted machine answered the same envelope `{answer:?}`, not already taken"
            ));
        }
        // The offer above is answered on its identifier alone, which the restart had to read
        // back. The next one keeps that identifier under a higher count, so the identifier
        // answers it too; the last carries a fresh identifier under a count already
        // delivered, so it is taken and the rewind is declared.
        let bumped = rewrite(
            &message.encode().map_err(|error| error.to_string())?,
            MESSAGE_MAGIC.len() + 1,
            0x02,
            |_| 2u64.to_be_bytes().to_vec(),
        )?;
        let answer = within(
            &sim,
            Duration::from_secs(60),
            offer_bytes(&connection, &bumped),
        )
        .await??;
        if answer != Answer::AlreadyTaken {
            return Err(format!(
                "a restarted machine answered a renumbered identifier `{answer:?}`, not already \
                 taken"
            ));
        }
        // A fresh identifier under a count the restarted machine remembers delivering is
        // taken, and the count it read back is what declares the rewind.
        let rewound = rewrite(
            &message.encode().map_err(|error| error.to_string())?,
            MESSAGE_MAGIC.len() + 1,
            0x01,
            |_| vec![0xcd; 16],
        )?;
        let answer = within(
            &sim,
            Duration::from_secs(60),
            offer_bytes(&connection, &rewound),
        )
        .await??;
        if answer != Answer::Taken {
            return Err(format!(
                "a restarted machine answered a fresh identifier under a taken count \
                 `{answer:?}`, not taken"
            ));
        }
        let handed = after.collected.deliveries();
        if handed.len() != 1
            || handed[0].envelope.count() != 1
            || handed[0].gap != Some(Gap::Rewound)
        {
            return Err(format!(
                "a restarted machine handed its caller {handed:?}, not the one rewound message \
                 with its count declared"
            ));
        }
        Ok(())
    })
}

/// A taken identifier is remembered for a week and then forgotten: a retry inside the week is
/// answered `already taken`, one after it is taken again, and a fresh identifier under a count
/// already used is taken with the rewind declared.
pub(crate) fn a_taken_identifier_is_forgotten_after_a_week() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        main.rights()?
            .bind(&laptop.peer_id(), main_binding(&label("admin")?)?, NOW)
            .map_err(|error| error.to_string())?;
        let main_managed = Managed::start(&sim, &beacon, &main, &main.records())?;
        let laptop_managed = Managed::start(&sim, &beacon, &laptop, &laptop.records())?;
        let main_messages = Messaging::open(&sim, &main, Arc::new(NoFloor))?;
        let laptop_messages = Messaging::open(&sim, &laptop, Arc::new(NoFloor))?;
        let connection = laptop_managed
            .connections
            .connect(&laptop_managed.endpoint, &main.fingerprint())
            .await
            .map_err(|error| error.to_string())?;
        wait_live(&sim, &main_managed.connections, &laptop.peer_id()).await?;
        wait_live(&sim, &laptop_managed.connections, &main.peer_id()).await?;
        // Only the receiving machine's service runs: the offers are the case's own.
        main_messages.serve(&main_managed.connections, &laptop);
        let envelope = laptop_messages
            .messages
            .send(&main.peer_id(), NOW, b"taken once a week")
            .map_err(|error| error.to_string())?;
        let message = Message::new(envelope, b"taken once a week".to_vec())
            .map_err(|error| error.to_string())?;
        let frame = message.encode().map_err(|error| error.to_string())?;
        let answer = within(
            &sim,
            Duration::from_secs(60),
            offer_bytes(&connection, &frame),
        )
        .await??;
        if answer != Answer::Taken {
            return Err(format!(
                "the first offer was answered `{answer:?}`, not taken"
            ));
        }
        // The identifier is remembered: the same message under a higher count is already
        // taken although its count is above the one delivered.
        let bumped = rewrite(&frame, MESSAGE_MAGIC.len() + 1, 0x02, |_| {
            2u64.to_be_bytes().to_vec()
        })?;
        let answer = within(
            &sim,
            Duration::from_secs(60),
            offer_bytes(&connection, &bumped),
        )
        .await??;
        if answer != Answer::AlreadyTaken {
            return Err(format!(
                "an identifier taken a moment ago was answered `{answer:?}` under a higher \
                 count, not already taken"
            ));
        }
        // The layer reads one clock: the case pushes that clock forward rather than passing
        // a moment beside it.
        let week = TAKEN_RETENTION;
        main_messages.moment.shift(week - Duration::from_hours(1));
        main_messages
            .messages
            .sweep()
            .map_err(|error| error.to_string())?;
        let answer = within(
            &sim,
            Duration::from_secs(60),
            offer_bytes(&connection, &bumped),
        )
        .await??;
        if answer != Answer::AlreadyTaken {
            return Err(format!(
                "an identifier taken an hour short of a week was answered `{answer:?}`, not \
                 already taken"
            ));
        }
        main_messages.moment.shift(Duration::from_hours(1));
        main_messages
            .messages
            .sweep()
            .map_err(|error| error.to_string())?;
        // A sender whose queue file was lost starts again rather than being wedged for the
        // pair's life: a fresh identifier at the count it would mint first is taken now that
        // nothing is remembered, and its count — one already delivered — declares a rewind.
        let fresh = rewrite(&frame, MESSAGE_MAGIC.len() + 1, 0x01, |_| vec![0x5a; 16])?;
        let fresh = rewrite(&fresh, MESSAGE_MAGIC.len() + 1, 0x02, |_| {
            1u64.to_be_bytes().to_vec()
        })?;
        let answer = within(
            &sim,
            Duration::from_secs(60),
            offer_bytes(&connection, &fresh),
        )
        .await??;
        if answer != Answer::Taken {
            return Err(format!(
                "a sender starting again after the week was answered `{answer:?}`, not taken"
            ));
        }
        let answer = within(
            &sim,
            Duration::from_secs(60),
            offer_bytes(&connection, &bumped),
        )
        .await??;
        if answer != Answer::Taken {
            return Err(format!(
                "an identifier taken a week ago was answered `{answer:?}`, not taken"
            ));
        }
        let delivered = main_messages.collected.deliveries();
        if delivered.len() != 3 {
            return Err(format!(
                "the receiver's caller was handed {} messages, not three",
                delivered.len()
            ));
        }
        // Count 1 was forgotten with its identifier and taken again: the count did not move
        // forward, so the delivery declares the rewind rather than claiming a jump.
        if delivered[1].envelope.id().as_bytes() != &[0x5a; 16]
            || delivered[1].envelope.count() != 1
            || delivered[1].gap != Some(Gap::Rewound)
        {
            return Err(format!(
                "a sender starting again was handed count {} with gap {:?}, not count one with \
                 the rewind declared",
                delivered[1].envelope.count(),
                delivered[1].gap
            ));
        }
        // Count 2 is exactly one past the last delivered, so the retry is not a gap.
        if delivered[2].envelope.id() != envelope.id()
            || delivered[2].envelope.count() != 2
            || delivered[2].gap.is_some()
        {
            return Err(format!(
                "the retry was handed over as count {} with gap {:?}, not as count two with \
                 nothing missing",
                delivered[2].envelope.count(),
                delivered[2].gap
            ));
        }
        Ok(())
    })
}

/// A caller that cannot store is handed the message again: nothing is recorded as taken
/// until it says it kept the message, and then it arrives once.
pub(crate) fn a_declined_delivery_is_offered_again() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let connected = ready(&sim, &beacon, false, Arc::new(NoFloor)).await?;
        // The receiving machine's caller cannot store: it answers `false` to every
        // delivery, as a product with a full disk does.
        connected.main_messages.collected.stop_accepting();
        let envelope = connected
            .laptop_messages
            .messages
            .send(&connected.main.peer_id(), NOW, b"offered until taken")
            .map_err(|error| error.to_string())?;
        connected
            .laptop_messages
            .serve(&connected.laptop_managed.connections, &connected.main);
        connected
            .main_messages
            .serve(&connected.main_managed.connections, &connected.laptop);
        for _ in 0..3 {
            sim.clock().advance(Duration::from_secs(5)).await;
        }
        if !connected.main_messages.collected.is_empty() {
            return Err(format!(
                "a caller that cannot store was handed {} messages",
                connected.main_messages.collected.len()
            ));
        }
        let pending = connected
            .laptop_messages
            .messages
            .pending(&connected.main.peer_id())
            .map_err(|error| error.to_string())?;
        if pending != vec![envelope] {
            return Err(format!(
                "the sender's queue holds {pending:?} after a declined delivery, not the one \
                 message it offered"
            ));
        }
        // Nothing recorded the identifier: the queue file a take would write names no
        // message, or is not there at all.
        if let Ok(stored) = connected
            .main
            .storage()
            .read_message(&connected.laptop.peer_id())
            && holds_bytes(&stored, envelope.id().as_bytes())
        {
            return Err("a delivery the caller declined was recorded as taken".to_owned());
        }
        // The caller can store again, and the message it never took arrives once.
        connected.main_messages.collected.start_accepting();
        let delivered = wait_for(
            &sim,
            &connected.main_messages.collected,
            1,
            Duration::from_secs(120),
        )
        .await?;
        if delivered.len() != 1 || delivered[0].envelope.id() != envelope.id() {
            return Err(format!(
                "the message offered again was handed over as {delivered:?}, not once"
            ));
        }
        sim.clock().advance(Duration::from_secs(5)).await;
        if connected.main_messages.collected.len() != 1 {
            return Err(format!(
                "the message was handed over {} times, not once",
                connected.main_messages.collected.len()
            ));
        }
        if !connected
            .laptop_messages
            .messages
            .pending(&connected.main.peer_id())
            .map_err(|error| error.to_string())?
            .is_empty()
        {
            return Err("the sender kept its copy of a message that was taken".to_owned());
        }
        Ok(())
    })
}

/// A message the receiver took is never recorded as a drop.
///
/// A sender's queue can hold a message the receiver already took: a removal that met another
/// writer leaves it, and a root restored from a backup brings it back. Offered again, it is
/// answered `already taken` — the receiver's own record says it reached a caller — so the
/// sender drops its copy and records nothing. A drop entry here would be a record of something
/// that did not happen, in the one file a person reads to learn what did.
pub(crate) fn a_message_the_receiver_took_is_never_recorded_as_a_drop() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let connected = ready(&sim, &beacon, false, Arc::new(NoFloor)).await?;
        connected
            .laptop_messages
            .messages
            .send(&connected.main.peer_id(), NOW, b"taken once")
            .map_err(|error| error.to_string())?;
        // The queue as it stands before the offer: a copy of it is what a backup holds, and
        // what the case puts back once the message has been taken.
        let queue = connected
            .laptop
            .storage()
            .read_message(&connected.main.peer_id())
            .map_err(io_error)?;
        connected
            .laptop_messages
            .serve(&connected.laptop_managed.connections, &connected.main);
        connected
            .main_messages
            .serve(&connected.main_managed.connections, &connected.laptop);
        wait_for(
            &sim,
            &connected.main_messages.collected,
            1,
            Duration::from_secs(120),
        )
        .await?;
        wait_for_state(
            &sim,
            &connected.laptop_messages.messages,
            &connected.main.peer_id(),
            |state| *state == QueueState::Empty,
            Duration::from_secs(120),
        )
        .await?;
        // The taken message is back in the sender's queue, as a restore leaves it.
        connected
            .laptop
            .storage()
            .write_message(&connected.main.peer_id(), &queue)
            .map_err(io_error)?;
        wait_for_state(
            &sim,
            &connected.laptop_messages.messages,
            &connected.main.peer_id(),
            |state| *state == QueueState::Empty,
            Duration::from_secs(120),
        )
        .await?;
        if connected.main_messages.collected.len() != 1 {
            return Err(format!(
                "the receiver's caller was handed the message {} times, not once",
                connected.main_messages.collected.len()
            ));
        }
        let entries = connected
            .laptop
            .audit()?
            .entries()
            .map_err(|error| error.to_string())?;
        if let Some(entry) = entries
            .iter()
            .find(|entry| matches!(entry.act, Act::MessagesDropped { .. }))
        {
            return Err(format!(
                "a message the receiver took was recorded as a drop: {:?}",
                entry.act
            ));
        }
        Ok(())
    })
}

/// A sender whose queue was lost counts again from one, and the count neither destroys its
/// message nor goes unmentioned: the message is delivered with the rewind declared.
pub(crate) fn a_rewound_count_is_declared_and_the_message_is_delivered() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let connected = ready(&sim, &beacon, false, Arc::new(NoFloor)).await?;
        connected
            .laptop_messages
            .serve(&connected.laptop_managed.connections, &connected.main);
        connected
            .main_messages
            .serve(&connected.main_managed.connections, &connected.laptop);
        let first = connected
            .laptop_messages
            .messages
            .send(&connected.main.peer_id(), NOW, b"the first")
            .map_err(|error| error.to_string())?;
        wait_for(
            &sim,
            &connected.main_messages.collected,
            1,
            Duration::from_secs(120),
        )
        .await?;
        // The sender's queue is lost, as a root restored from an older backup is, and its
        // count starts again at one with a fresh identifier.
        connected
            .laptop
            .storage()
            .remove_message(&connected.main.peer_id())
            .map_err(io_error)?;
        let second = connected
            .laptop_messages
            .messages
            .send(&connected.main.peer_id(), NOW, b"the second")
            .map_err(|error| error.to_string())?;
        if second.count() != 1 || second.id() == first.id() {
            return Err(format!(
                "a queue that was lost did not count again from one: count {}, identifier {}",
                second.count(),
                second.id()
            ));
        }
        let delivered = wait_for(
            &sim,
            &connected.main_messages.collected,
            2,
            Duration::from_secs(120),
        )
        .await?;
        if delivered[0].envelope.id() != first.id() {
            return Err(format!(
                "the first delivery is {:?}, not the message that was sent first",
                delivered[0].envelope.id()
            ));
        }
        // Only a remembered identifier suppresses a message: a fresh one under a count this
        // machine has already delivered arrives, with the rewind declared and nothing missing.
        if delivered[1].envelope.id() != second.id()
            || delivered[1].envelope.count() != 1
            || delivered[1].gap != Some(Gap::Rewound)
        {
            return Err(format!(
                "a rewound count was handed over as {:?} with gap {:?}, not as count one with \
                 a declared rewind",
                delivered[1].envelope.id(),
                delivered[1].gap
            ));
        }
        // Nothing was lost, so the sender records nothing: a drop entry here would be a record
        // of a message that reached a caller.
        let entries = connected
            .laptop
            .audit()?
            .entries()
            .map_err(|error| error.to_string())?;
        if entries
            .iter()
            .any(|entry| matches!(entry.act, Act::MessagesDropped { .. }))
        {
            return Err("a rewound message was recorded as dropped".to_owned());
        }
        wait_for_state(
            &sim,
            &connected.laptop_messages.messages,
            &connected.main.peer_id(),
            |state| *state == QueueState::Empty,
            Duration::from_secs(120),
        )
        .await?;
        Ok(())
    })
}

/// A queue composed while the peer was away waits for the binding and arrives when the
/// peer returns, in order.
pub(crate) fn the_queue_waits_for_the_binding_and_a_message_composed_while_away_arrives()
-> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        // The main decides; the laptop has neither a binding nor a claim yet.
        main.rights()?
            .bind(&laptop.peer_id(), main_binding(&label("admin")?)?, NOW)
            .map_err(|error| error.to_string())?;
        let main_managed = Managed::start(&sim, &beacon, &main, &main.records())?;
        let laptop_managed = Managed::start(&sim, &beacon, &laptop, &laptop.records())?;
        let main_messages = Messaging::open(&sim, &main, Arc::new(NoFloor))?;
        let laptop_messages = Messaging::open(&sim, &laptop, Arc::new(NoFloor))?;
        let bodies: [&[u8]; 2] = [b"composed while away", b"and a second one"];
        for body in bodies {
            laptop_messages
                .messages
                .send(&main.peer_id(), NOW, body)
                .map_err(|error| error.to_string())?;
        }
        // Nothing has connected, so there is no pair to name: the queue says so.
        let state = laptop_messages
            .messages
            .state(&main.peer_id())
            .map_err(|error| error.to_string())?;
        if state != QueueState::WaitingForBinding {
            return Err(format!(
                "a queue with no binding and no claim reports `{state:?}`, not waiting for the \
                 binding"
            ));
        }
        if !main_messages.collected.is_empty() {
            return Err("a message arrived before any connection".to_owned());
        }
        main_messages.serve(&main_managed.connections, &laptop);
        laptop_messages.serve(&laptop_managed.connections, &main);
        let _keeper = spawn_keeper(&laptop_managed, &main);
        let delivered = wait_for(
            &sim,
            &main_messages.collected,
            bodies.len(),
            Duration::from_secs(120),
        )
        .await?;
        for (delivery, body) in delivered.iter().zip(bodies) {
            if delivery.body != body {
                return Err(format!(
                    "the deliveries are out of order: `{}` arrived where `{}` was composed",
                    String::from_utf8_lossy(&delivery.body),
                    String::from_utf8_lossy(body)
                ));
            }
        }
        if delivered[0].envelope.count() != 1 || delivered[1].envelope.count() != 2 {
            return Err(
                "the two messages did not arrive in the order they were counted".to_owned(),
            );
        }
        Ok(())
    })
}

/// Messages from one machine arrive in the order of the sender's count, and two peers'
/// counts are independent.
pub(crate) fn order_is_kept_within_a_pair_and_two_peers_do_not_share_it() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let receiver = sim.machine().map_err(io_error)?;
        let first = sim.machine().map_err(io_error)?;
        let second = sim.machine().map_err(io_error)?;
        pair_up(&receiver, &first)?;
        pair_up(&receiver, &second)?;
        // The receiver decides for both, so both senders are shown a claim.
        for sender in [&first, &second] {
            receiver
                .rights()?
                .bind(&sender.peer_id(), main_binding(&label("admin")?)?, NOW)
                .map_err(|error| error.to_string())?;
        }
        let receiver_managed = Managed::start(&sim, &beacon, &receiver, &receiver.records())?;
        let first_managed = Managed::start(&sim, &beacon, &first, &first.records())?;
        let second_managed = Managed::start(&sim, &beacon, &second, &second.records())?;
        let receiver_messages = Messaging::open(&sim, &receiver, Arc::new(NoFloor))?;
        let first_messages = Messaging::open(&sim, &first, Arc::new(NoFloor))?;
        let second_messages = Messaging::open(&sim, &second, Arc::new(NoFloor))?;
        // Interleaved, so a shared counter would show up as one run of six.
        for round in 0..3u64 {
            first_messages
                .messages
                .send(
                    &receiver.peer_id(),
                    NOW,
                    format!("first {round}").as_bytes(),
                )
                .map_err(|error| error.to_string())?;
            second_messages
                .messages
                .send(
                    &receiver.peer_id(),
                    NOW,
                    format!("second {round}").as_bytes(),
                )
                .map_err(|error| error.to_string())?;
        }
        receiver_messages.serve(&receiver_managed.connections, &first);
        receiver_messages.serve(&receiver_managed.connections, &second);
        first_messages.serve(&first_managed.connections, &receiver);
        second_messages.serve(&second_managed.connections, &receiver);
        let _first_keeper = spawn_keeper(&first_managed, &receiver);
        let _second_keeper = spawn_keeper(&second_managed, &receiver);
        let delivered = wait_for(
            &sim,
            &receiver_messages.collected,
            6,
            Duration::from_secs(180),
        )
        .await?;
        let counts_of = |sender: &Machine| -> Vec<u64> {
            delivered
                .iter()
                .filter(|delivery| delivery.sender == sender.peer_id())
                .map(|delivery| delivery.envelope.count())
                .collect()
        };
        let first_counts = counts_of(&first);
        let second_counts = counts_of(&second);
        if first_counts != vec![1, 2, 3] {
            return Err(format!(
                "the first sender's counts arrived as {first_counts:?}, not 1, 2, 3 in order"
            ));
        }
        if second_counts != vec![1, 2, 3] {
            return Err(format!(
                "the second sender's counts arrived as {second_counts:?}, not 1, 2, 3 in order"
            ));
        }
        Ok(())
    })
}

/// A count that jumps is declared as a gap instead of being renumbered or continued
/// silently.
pub(crate) fn a_dropped_message_is_declared_as_a_gap() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        main.rights()?
            .bind(&laptop.peer_id(), main_binding(&label("admin")?)?, NOW)
            .map_err(|error| error.to_string())?;
        let main_managed = Managed::start(&sim, &beacon, &main, &main.records())?;
        let laptop_managed = Managed::start(&sim, &beacon, &laptop, &laptop.records())?;
        let main_messages = Messaging::open(&sim, &main, Arc::new(NoFloor))?;
        let laptop_messages = Messaging::open(&sim, &laptop, Arc::new(NoFloor))?;
        // The sender's service never runs: the envelopes are minted, and the case offers
        // the first and the third by hand.
        let first = laptop_messages
            .messages
            .send(&main.peer_id(), NOW, b"first")
            .map_err(|error| error.to_string())?;
        let lost = laptop_messages
            .messages
            .send(&main.peer_id(), NOW, b"lost on the way")
            .map_err(|error| error.to_string())?;
        let third = laptop_messages
            .messages
            .send(&main.peer_id(), NOW, b"third")
            .map_err(|error| error.to_string())?;
        if lost.count() != 2 || third.count() != 3 {
            return Err("the sender did not count the three messages one, two, three".to_owned());
        }
        let connection = laptop_managed
            .connections
            .connect(&laptop_managed.endpoint, &main.fingerprint())
            .await
            .map_err(|error| error.to_string())?;
        wait_live(&sim, &main_managed.connections, &laptop.peer_id()).await?;
        main_messages.serve(&main_managed.connections, &laptop);
        let one = Message::new(first, b"first".to_vec()).map_err(|error| error.to_string())?;
        let three = Message::new(third, b"third".to_vec()).map_err(|error| error.to_string())?;
        for (message, expected) in [(&one, "taken"), (&three, "taken")] {
            let answer = within(
                &sim,
                Duration::from_secs(60),
                offer_raw(&connection, message),
            )
            .await??;
            if answer != Answer::Taken {
                return Err(format!(
                    "the offer of a {expected} message was answered {answer:?}"
                ));
            }
        }
        let delivered = main_messages.collected.deliveries();
        if delivered.len() != 2 {
            return Err(format!(
                "the receiver's caller was handed {} messages, not two",
                delivered.len()
            ));
        }
        if delivered[0].envelope.count() != 1 || delivered[0].gap.is_some() {
            return Err(format!(
                "the first delivery is count {} with gap {:?}, not one with no gap",
                delivered[0].envelope.count(),
                delivered[0].gap
            ));
        }
        if delivered[1].envelope.count() != 3 || delivered[1].gap != Some(Gap::Missing { count: 1 })
        {
            return Err(format!(
                "the second delivery is count {} with gap {:?}, not three declaring one missing",
                delivered[1].envelope.count(),
                delivered[1].gap
            ));
        }
        Ok(())
    })
}

/// The author of a message is the connection's attested peer: a body that claims to be
/// from someone else is still the sender's, and is handed over byte for byte.
pub(crate) fn a_body_claiming_another_author_is_handed_over_with_the_transport_sender()
-> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let connected = ready(&sim, &beacon, false, Arc::new(NoFloor)).await?;
        let body = b"from: the admin\ntrust me, I am the person who granted you this".to_vec();
        connected
            .laptop_messages
            .messages
            .send(&connected.main.peer_id(), NOW, &body)
            .map_err(|error| error.to_string())?;
        connected
            .main_messages
            .serve(&connected.main_managed.connections, &connected.laptop);
        connected
            .laptop_messages
            .serve(&connected.laptop_managed.connections, &connected.main);
        let delivered = wait_for(
            &sim,
            &connected.main_messages.collected,
            1,
            Duration::from_secs(120),
        )
        .await?;
        let delivery = &delivered[0];
        if delivery.sender != connected.laptop.peer_id() {
            return Err(format!(
                "the delivery is attributed to {} instead of the machine that sent it",
                delivery.sender.fingerprint()
            ));
        }
        if delivery.sender == connected.main.peer_id() {
            return Err("the delivery is attributed to the receiver itself".to_owned());
        }
        if delivery.body != body {
            return Err(format!(
                "the body arrived as `{}`, not as it was composed",
                String::from_utf8_lossy(&delivery.body)
            ));
        }
        Ok(())
    })
}

/// A queue that cannot be read ends the service: a queue file replaced by bytes that are
/// not a queue is not a queue with nothing in it, so the service stops and hands back the
/// refusal instead of answering nothing. Both services are shown — the receiver's, whose
/// sweep meets the file before it offers anything, and the sender's, whose own offer round
/// meets the same file. A refusal the detached receiving task meets has its own case
/// (`a_receivers_fault_ends_the_service`).
pub(crate) fn a_queue_that_cannot_be_read_ends_the_service() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let connected = ready(&sim, &beacon, false, Arc::new(NoFloor)).await?;
        connected
            .laptop_messages
            .messages
            .send(
                &connected.main.peer_id(),
                NOW,
                b"a message the queue can no longer hold",
            )
            .map_err(|error| error.to_string())?;
        let connection = wait_live(
            &sim,
            &connected.laptop_managed.connections,
            &connected.main.peer_id(),
        )
        .await?;

        // The receiver's queue for the sender — the file that remembers what it has taken —
        // is replaced by bytes that are not a queue, as a damaged file or a lost restore
        // leaves it. Only the receiver's service is started: `endings` waits for every task
        // a case started, and this half has one ending to read.
        let receiver_name = connected
            .main
            .storage()
            .message_name(&connected.laptop.peer_id())
            .map_err(io_error)?;
        connected
            .main
            .storage()
            .write_message(&connected.laptop.peer_id(), b"not a queue")
            .map_err(io_error)?;
        connected
            .main_messages
            .serve(&connected.main_managed.connections, &connected.laptop);
        // An offer by hand, as the sender's own service would make it: the receiver's
        // service is already ending on the file, so the offer is answered nothing. The case
        // reads the ending rather than the answer.
        let envelope = connected
            .laptop_messages
            .messages
            .pending(&connected.main.peer_id())
            .map_err(|error| error.to_string())?
            .into_iter()
            .next()
            .ok_or("the sender's queue lost the message the case composed")?;
        let message = Message::new(envelope, b"a message the queue can no longer hold".to_vec())
            .map_err(|error| error.to_string())?;
        // The receiver answers nothing it could not record, so the offer is expected to go
        // unanswered: the case waits a bounded time for it and reads the service's ending
        // instead.
        let offered = within(
            &sim,
            Duration::from_secs(30),
            offer_raw(&connection, &message),
        )
        .await;
        let ending = single_ending(&sim, &connected.main_messages, LONG).await?;
        let Err(text) = ending else {
            return Err(format!(
                "an offer the receiver could not record ended its service cleanly \
                 (the offer answered `{offered:?}`)"
            ));
        };
        if !text.contains("is not a message queue") || !text.contains(&receiver_name) {
            return Err(format!(
                "the receiver's ending does not name {receiver_name}: `{text}`"
            ));
        }
        if !connected.main_messages.collected.is_empty() {
            return Err(format!(
                "a queue that cannot be read still delivered {} messages",
                connected.main_messages.collected.len()
            ));
        }

        // The sender's own queue is replaced the same way: its next round meets the file
        // before it offers anything.
        let sender_name = connected
            .laptop
            .storage()
            .message_name(&connected.main.peer_id())
            .map_err(io_error)?;
        connected
            .laptop
            .storage()
            .write_message(&connected.main.peer_id(), b"not a queue")
            .map_err(io_error)?;
        connected
            .laptop_messages
            .serve(&connected.laptop_managed.connections, &connected.main);
        let ending = single_ending(&sim, &connected.laptop_messages, LONG).await?;
        let Err(text) = ending else {
            return Err(
                "a queue that cannot be read ended the sender's service cleanly".to_owned(),
            );
        };
        if !text.contains("is not a message queue") || !text.contains(&sender_name) {
            return Err(format!(
                "the sender's ending does not name {sender_name}: `{text}`"
            ));
        }
        Ok(())
    })
}

/// A refusal met by the *receiving task* ends the service that started it.
///
/// The service is running and has already taken one message when `messages/` is removed whole,
/// as a cleaner or a botched restore removes it. The loop's own round only reads — its queue
/// head is empty and its sweep finds nothing to drop — so the refusal is met by the receiving
/// task, which cannot record that it took the next message. It reaches the caller through the
/// fault the detached receiving task leaves behind; a service that swallowed it would answer
/// nothing for the rest of its life while its caller believed it was delivering.
///
/// The fault is a missing directory rather than a mode, so this case runs on every host: a
/// unix-only shape of the same path is `a_service_that_cannot_read_or_write_ends`.
pub(crate) fn a_receivers_fault_ends_the_service() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let connected = ready(&sim, &beacon, false, Arc::new(NoFloor)).await?;
        connected
            .main_messages
            .serve(&connected.main_managed.connections, &connected.laptop);
        let connection = wait_live(
            &sim,
            &connected.laptop_managed.connections,
            &connected.main.peer_id(),
        )
        .await?;
        let first = connected
            .laptop_messages
            .messages
            .send(&connected.main.peer_id(), NOW, b"the queue is still whole")
            .map_err(|error| error.to_string())?;
        let first = Message::new(first, b"the queue is still whole".to_vec())
            .map_err(|error| error.to_string())?;
        let answer = within(
            &sim,
            Duration::from_secs(60),
            offer_raw(&connection, &first),
        )
        .await??;
        if answer != Answer::Taken {
            return Err(format!(
                "the message before the damage was answered `{answer:?}`, not taken"
            ));
        }
        // The receiving task is running; now the directory it must write into is gone.
        let lock = connected
            .main
            .storage()
            .message_lock_name(&connected.laptop.peer_id())
            .map_err(io_error)?;
        connected
            .main
            .storage()
            .remove_message_dir()
            .map_err(io_error)?;
        let second = connected
            .laptop_messages
            .messages
            .send(
                &connected.main.peer_id(),
                NOW,
                b"the queue is no longer whole",
            )
            .map_err(|error| error.to_string())?;
        let second = Message::new(second, b"the queue is no longer whole".to_vec())
            .map_err(|error| error.to_string())?;
        let offered = within(
            &sim,
            Duration::from_secs(30),
            offer_raw(&connection, &second),
        )
        .await;
        let ending = single_ending(&sim, &connected.main_messages, PROMPT).await;
        let Err(text) = ending? else {
            return Err(format!(
                "a receiving task that could not record its queue ended its service cleanly \
                 (the offer answered `{offered:?}`)"
            ));
        };
        if !text.contains(&lock) {
            return Err(format!(
                "the receiving task's ending does not name {lock}: `{text}`"
            ));
        }
        // The queue's lock is taken before the message is handed over, so this refusal is met
        // before the caller sees it: at least once means the message is offered again.
        if connected.main_messages.collected.len() != 1 {
            return Err(format!(
                "the caller was handed {} messages, not the one the receiver could take",
                connected.main_messages.collected.len()
            ));
        }
        Ok(())
    })
}

/// A caller whose delivery panics ends the service instead of leaving the pair silent.
///
/// The receiving task is detached, so a panic inside `Deliveries::deliver` would kill it with
/// nobody told: the pair would go on looking connected, the sender would go on offering, and
/// nothing would say why. The crate catches that one panic, records nothing as taken, and ends
/// the service with the caller's bug named, so the message is still the sender's to offer
/// again.
pub(crate) fn a_panicking_delivery_ends_the_service() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let connected = ready(&sim, &beacon, false, Arc::new(NoFloor)).await?;
        connected
            .main_messages
            .serve(&connected.main_managed.connections, &connected.laptop);
        let connection = wait_live(
            &sim,
            &connected.laptop_managed.connections,
            &connected.main.peer_id(),
        )
        .await?;
        connected.main_messages.collected.start_panicking();
        let envelope = connected
            .laptop_messages
            .messages
            .send(
                &connected.main.peer_id(),
                NOW,
                b"a caller with a bug of its own",
            )
            .map_err(|error| error.to_string())?;
        let message = Message::new(envelope, b"a caller with a bug of its own".to_vec())
            .map_err(|error| error.to_string())?;
        let offered = within(
            &sim,
            Duration::from_secs(30),
            offer_raw(&connection, &message),
        )
        .await;
        let ending = single_ending(&sim, &connected.main_messages, PROMPT).await;
        let Err(text) = ending? else {
            return Err(format!(
                "a panicking delivery ended its service cleanly (the offer answered `{offered:?}`)"
            ));
        };
        if !text.contains("panicked") {
            return Err(format!(
                "the ending does not name the caller's panic: `{text}`"
            ));
        }
        // Nothing was recorded as taken, so the message is still the sender's to offer again.
        let pending = connected
            .laptop_messages
            .messages
            .pending(&connected.main.peer_id())
            .map_err(|error| error.to_string())?;
        if pending.len() != 1 {
            return Err(format!(
                "a panicking delivery left {} messages queued, not the one",
                pending.len()
            ));
        }
        Ok(())
    })
}

/// A frame the receiver cannot read is answered, not met with silence.
///
/// Two shapes: bytes that are not a message at all, and a frame longer than any message this
/// build writes — a body twice the body cap, so the read refuses at its own limit rather than
/// buffering. Both are answered `Unreadable`, so a sender drops the message instead of keeping
/// it for the whole retention, and the answer carries no reason of the receiver's.
pub(crate) fn an_unreadable_frame_is_answered() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let connected = ready(&sim, &beacon, false, Arc::new(NoFloor)).await?;
        connected
            .main_messages
            .serve(&connected.main_managed.connections, &connected.laptop);
        let connection = wait_live(
            &sim,
            &connected.laptop_managed.connections,
            &connected.main.peer_id(),
        )
        .await?;
        let shapes = [
            b"not a message at all".to_vec(),
            vec![b'x'; MAX_BODY_BYTES * 2],
        ];
        for bytes in shapes {
            let answer = within(
                &sim,
                Duration::from_secs(60),
                offer_bytes(&connection, &bytes),
            )
            .await??;
            if answer != Answer::Unreadable {
                return Err(format!(
                    "{} bytes the receiver cannot read were answered `{answer:?}`, not unreadable",
                    bytes.len()
                ));
            }
        }
        if !connected.main_messages.collected.is_empty() {
            return Err(format!(
                "the receiver handed its caller {} messages from frames it could not read",
                connected.main_messages.collected.len()
            ));
        }
        Ok(())
    })
}

/// A peer that will not take a whole answer does not park the pair.
///
/// The peer's endpoint advertises a one-byte stream window, so this machine's answer blocks
/// after the first byte — a peer that stops reading, in the sharpest form there is. The write
/// is bounded like every other wait this crate makes: after `MESSAGE_BUDGET` the stream is
/// ended with only a prefix of the answer on it, and the receiving task takes the next offer.
/// A receiver parked in that write would take nothing again for the connection's life, while
/// keep-alives kept the connection looking healthy.
pub(crate) fn a_peer_that_will_not_take_the_answer_does_not_park_the_pair() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        main.rights()?
            .bind(&laptop.peer_id(), main_binding(&label("admin")?)?, NOW)
            .map_err(|error| error.to_string())?;
        let main_managed = Managed::start(&sim, &beacon, &main, &main.records())?;
        let main_messages = Messaging::open(&sim, &main, Arc::new(NoFloor))?;
        let laptop_messages = Messaging::open(&sim, &laptop, Arc::new(NoFloor))?;
        main_messages.serve(&main_managed.connections, &laptop);
        let (_endpoint, connection) =
            tiny_window_peer(&sim, &laptop, main.fingerprint(), main.addr()).await?;
        // The binding exchange owns the first stream a kept connection carries. With a
        // one-byte window it cannot finish either, so the case lets its budget pass before
        // the pair's receiving task is attached.
        sim.clock()
            .advance(EXCHANGE_BUDGET + Duration::from_secs(1))
            .await;
        sim.clock().settle().await;

        let first = laptop_messages
            .messages
            .send(&main.peer_id(), NOW, b"an answer nobody takes")
            .map_err(|error| error.to_string())?;
        let first = Message::new(first, b"an answer nobody takes".to_vec())
            .map_err(|error| error.to_string())?;
        let mut recv = offer_without_reading(&connection, &first).await?;
        wait_for(&sim, &main_messages.collected, 1, Duration::from_secs(120)).await?;
        // The answer cannot fit the peer's window, and nothing reads it: reading would hand
        // the window back and the write would finish. The bound is what ends the write, so
        // the peer is left with a prefix of the answer — an unreadable one — and an unbounded
        // write would leave it waiting for the rest for the connection's life.
        sim.clock()
            .advance(MESSAGE_BUDGET + Duration::from_secs(1))
            .await;
        sim.clock().settle().await;
        let read = within(&sim, MESSAGE_BUDGET * 3, recv.read_to_end(ANSWER_BYTES)).await;
        // The bound ends the write, so the stream is dropped — reset — with at most a prefix
        // of the answer on it, and the peer reads that prefix or an error. A stream that never
        // ends means the write outlived its budget, which is the failure; a whole answer means
        // the write was not bounded at all.
        let Ok(read) = read else {
            return Err(
                "the answer write never ended, so the peer waited for it past its budget"
                    .to_owned(),
            );
        };
        if read
            .as_ref()
            .is_ok_and(|bytes| Answer::decode(bytes).is_ok())
        {
            return Err(format!(
                "the peer read a whole answer through a one-byte window: {read:?}"
            ));
        }
        // The receiving task is not parked in that write: it takes the next offer.
        let second = laptop_messages
            .messages
            .send(&main.peer_id(), NOW, b"the next one")
            .map_err(|error| error.to_string())?;
        let second =
            Message::new(second, b"the next one".to_vec()).map_err(|error| error.to_string())?;
        let _recv = offer_without_reading(&connection, &second).await?;
        let delivered =
            wait_for(&sim, &main_messages.collected, 2, Duration::from_secs(120)).await?;
        if delivered[1].envelope.id() != second.envelope().id() {
            return Err(format!(
                "the second offer was not the message the receiver took next: {:?}",
                delivered[1].envelope.id()
            ));
        }
        Ok(())
    })
}

/// Offer one message over `connection` and hand back the half the answer arrives on, without
/// reading it: the peer in the case has a window too small for the answer.
async fn offer_without_reading(
    connection: &Connection,
    message: &Message,
) -> Result<quinn::RecvStream, String> {
    let (mut send, recv) = connection
        .open_bi()
        .await
        .map_err(|error| error.to_string())?;
    send.write_all(&message.encode().map_err(|error| error.to_string())?)
        .await
        .map_err(|error| error.to_string())?;
    send.finish().map_err(|error| error.to_string())?;
    Ok(recv)
}

/// A peer whose endpoint will not take a whole answer: a one-byte stream window, which no
/// transport this crate builds advertises.
///
/// The endpoint is handed back beside the connection because dropping it closes the
/// connection. The identity is `peer`'s, so this machine sees the pair's own peer dialing;
/// the socket is a fresh address on the simulated link, so nothing is shared with the
/// machine's own endpoint.
async fn tiny_window_peer(
    sim: &Sim,
    peer: &Machine,
    trusts: Fingerprint,
    at: SocketAddr,
) -> Result<(quinn::Endpoint, Connection), String> {
    let policy = TrustSet::default();
    policy.insert(trusts);
    let tls =
        mahbot_peers::tls::client_config(&peer.identity, Arc::new(policy), mahbot_peers::tls::ALPN)
            .map_err(|error| error.to_string())?;
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls))
        .map_err(|error| format!("{error:?}"))?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.stream_receive_window(1u32.into());
    config.transport_config(Arc::new(transport));
    let socket = sim.link().attach_next();
    let endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        Arc::clone(&socket) as Arc<dyn quinn::AsyncUdpSocket>,
        sim.clock().runtime(),
    )
    .map_err(|error| error.to_string())?;
    let connection = endpoint
        .connect_with(config, at, mahbot_peers::net::SERVER_NAME)
        .map_err(|error| error.to_string())?
        .await
        .map_err(|error| error.to_string())?;
    Ok((endpoint, connection))
}

/// Another writer holding a queue is not a fault, and does not make the service spin.
///
/// The second process of a self-update holds the lock file for the span of its write. While it
/// does, a round that answered `taken` cannot remove the message and a round that was refused
/// cannot either, so both keep it, wait a round, and try again: the service stays up, the
/// taken message leaves when the writer lets go and the caller has it exactly once, and a
/// refusal repeated while the queue is held is written once a second rather than once an
/// offer.
pub(crate) fn a_held_queue_does_not_stop_the_service() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let connected = ready(&sim, &beacon, false, Arc::new(NoFloor)).await?;
        connected
            .laptop_messages
            .serve(&connected.laptop_managed.connections, &connected.main);
        connected
            .main_messages
            .serve(&connected.main_managed.connections, &connected.laptop);
        connected
            .laptop_messages
            .messages
            .send(&connected.main.peer_id(), NOW, b"held by another writer")
            .map_err(|error| error.to_string())?;
        let held = connected
            .laptop
            .storage()
            .lock_message(&connected.main.peer_id())
            .map_err(io_error)?;
        // Five seconds of the layer's own time: long enough for a round to offer the message,
        // be answered, and fail to remove it.
        sim.clock().advance(Duration::from_secs(5)).await;
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        let pending = connected
            .laptop_messages
            .messages
            .pending(&connected.main.peer_id())
            .map_err(|error| error.to_string())?;
        if pending.len() != 1 {
            return Err(format!(
                "a queue another writer held kept {} messages, not the one it could not remove",
                pending.len()
            ));
        }
        held.unlock().map_err(io_error)?;
        // The writer let go: the next round removes the message, and the caller still has it
        // once.
        sim.clock().advance(Duration::from_secs(3)).await;
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        let pending = connected
            .laptop_messages
            .messages
            .pending(&connected.main.peer_id())
            .map_err(|error| error.to_string())?;
        if !pending.is_empty() {
            return Err(format!(
                "the queue still holds {} messages after the other writer let go",
                pending.len()
            ));
        }
        if connected.main_messages.collected.len() != 1 {
            return Err(format!(
                "the caller was handed the message {} times, not once",
                connected.main_messages.collected.len()
            ));
        }
        // The second half: the receiver refuses, and the queue is held again. The refusal is
        // written before the removal, as every act is, so the round that cannot remove the
        // message writes it again next round — which is why the round must wait one a second
        // and not one an offer.
        let admin = label("admin")?;
        let bound = pair(&connected.laptop, &admin);
        let owner = person("owner")?;
        connected
            .main
            .rights()?
            .withdraw(&bound, Capability::WRITE, owner.clone(), NOW)
            .map_err(|error| error.to_string())?;
        // Queued before the lock is taken: the service cannot run between these two calls,
        // because neither awaits.
        connected
            .laptop_messages
            .messages
            .send(
                &connected.main.peer_id(),
                NOW,
                b"refused while the queue is held",
            )
            .map_err(|error| error.to_string())?;
        let held = connected
            .laptop
            .storage()
            .lock_message(&connected.main.peer_id())
            .map_err(io_error)?;
        sim.clock().advance(Duration::from_secs(10)).await;
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        let refusals = connected
            .laptop
            .audit()?
            .entries()
            .map_err(|error| error.to_string())?
            .iter()
            .filter(|entry| matches!(entry.act, Act::MessageRefused { .. }))
            .count();
        if refusals == 0 {
            return Err("a refusal met while the queue was held was not written down".to_owned());
        }
        if refusals > 15 {
            return Err(format!(
                "a queue another writer held was refused {refusals} times in ten seconds: the \
                 service is spinning through its queue files"
            ));
        }
        held.unlock().map_err(io_error)?;
        sim.clock().advance(Duration::from_secs(3)).await;
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        let pending = connected
            .laptop_messages
            .messages
            .pending(&connected.main.peer_id())
            .map_err(|error| error.to_string())?;
        if !pending.is_empty() {
            return Err(format!(
                "the queue still holds {} refused messages after the other writer let go",
                pending.len()
            ));
        }
        if connected.main_messages.collected.len() != 1 {
            return Err(format!(
                "a refused message reached the caller: {} deliveries, not the one taken before",
                connected.main_messages.collected.len()
            ));
        }
        Ok(())
    })
}

/// A service that cannot read or write what a round needs ends with that refusal.
///
/// Two halves, one per path the loop reaches: the queue it cannot remove after a message the
/// peer took (a directory with no write permission, as a read-only root or a full disk leaves
/// it), and the record it cannot read before deciding whether to offer at all. Both are
/// permanent faults of this machine, and a service that swallowed them would look like a pair
/// with nothing to say while its caller believed it was delivering.
#[cfg(unix)]
pub(crate) fn a_service_that_cannot_read_or_write_ends() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let connected = ready(&sim, &beacon, false, Arc::new(NoFloor)).await?;
        connected
            .laptop_messages
            .messages
            .send(
                &connected.main.peer_id(),
                NOW,
                b"taken into a queue that cannot shrink",
            )
            .map_err(|error| error.to_string())?;
        // The queue is published by a rename inside `messages/`, so a directory without
        // write permission is a queue that cannot lose a message it has taken.
        connected
            .laptop
            .storage()
            .set_message_dir_mode(0o500)
            .map_err(io_error)?;
        connected
            .laptop_messages
            .serve(&connected.laptop_managed.connections, &connected.main);
        connected
            .main_messages
            .serve(&connected.main_managed.connections, &connected.laptop);
        let taken = wait_for(
            &sim,
            &connected.main_messages.collected,
            1,
            Duration::from_secs(120),
        )
        .await;
        let ending = single_ending(&sim, &connected.laptop_messages, PROMPT).await;
        connected
            .laptop
            .storage()
            .set_message_dir_mode(0o700)
            .map_err(io_error)?;
        let Err(text) = ending? else {
            return Err(format!(
                "a queue that cannot be written ended its service cleanly (the offer was \
                 answered {taken:?})"
            ));
        };
        let queue = connected
            .laptop
            .storage()
            .message_name(&connected.main.peer_id())
            .map_err(io_error)?;
        if !text.contains(&queue) {
            return Err(format!(
                "the sender's ending does not name {queue}: `{text}`"
            ));
        }
        // Nothing was lost: the message the queue could not remove is still there. The
        // service ended rather than going on offering it, which is what says the queue is
        // not writable instead of merely held this instant.
        let pending = connected
            .laptop_messages
            .messages
            .pending(&connected.main.peer_id())
            .map_err(|error| error.to_string())?;
        if pending.len() != 1 {
            return Err(format!(
                "a queue that could not remove a taken message holds {} of them, not the one",
                pending.len()
            ));
        }

        // The record half: a record that is not a record, read by the round that decides
        // whether the pair may be spoken to. The service runs one round first, so its own
        // sweep has read the record and will not run again for `SWEEP_EVERY`: what meets the
        // refusal from here is the gate.
        let second = ready(&sim, &beacon, false, Arc::new(NoFloor)).await?;
        let record = second
            .laptop
            .storage()
            .record_name(&second.main.peer_id())
            .map_err(io_error)?;
        second
            .laptop_messages
            .serve(&second.laptop_managed.connections, &second.main);
        sim.clock().advance(Duration::from_secs(3)).await;
        second
            .laptop
            .storage()
            .write_record(&second.main.peer_id(), b"not a record")
            .map_err(io_error)?;
        let ending = single_ending(&sim, &second.laptop_messages, PROMPT).await?;
        let Err(text) = ending else {
            return Err("a record that cannot be read ended the service cleanly".to_owned());
        };
        if !text.contains(&record) {
            return Err(format!(
                "the service's ending does not name {record}: `{text}`"
            ));
        }
        Ok(())
    })
}

/// A replaced connection still carries messages: the pair's connection is dropped, the
/// keeper dials again, and a message composed after the new connection is up reaches the
/// receiver's caller.
///
/// The layer notices the replacement by the connection's shared watch, not by its reusable
/// id. This case cannot discriminate the two: a simulation does not hand a dropped
/// connection's address out again on demand, so the old id-based comparison would pass it
/// too. What it proves is the behaviour — a message composed after the replacement reaches
/// the receiver — while the identity rule rests on the watch being made once per connection
/// and dropped with it.
pub(crate) fn a_replaced_connection_still_carries_messages() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let connected = ready(&sim, &beacon, false, Arc::new(NoFloor)).await?;
        connected
            .laptop_messages
            .serve(&connected.laptop_managed.connections, &connected.main);
        connected
            .main_messages
            .serve(&connected.main_managed.connections, &connected.laptop);
        let first: &[u8] = b"over the first connection";
        connected
            .laptop_messages
            .messages
            .send(&connected.main.peer_id(), NOW, first)
            .map_err(|error| error.to_string())?;
        wait_for(
            &sim,
            &connected.main_messages.collected,
            1,
            Duration::from_secs(120),
        )
        .await?;
        // The pair's connection goes and the keeper dials again: the message above was
        // taken, so the loss is a link failure and not a dial that carried nothing.
        if !connected
            .laptop_managed
            .connections
            .disconnect(&connected.main.peer_id())
        {
            return Err("the pair held no live connection to replace".to_owned());
        }
        wait_live(
            &sim,
            &connected.laptop_managed.connections,
            &connected.main.peer_id(),
        )
        .await?;
        wait_live(
            &sim,
            &connected.main_managed.connections,
            &connected.laptop.peer_id(),
        )
        .await?;
        let second: &[u8] = b"over the connection that replaced it";
        connected
            .laptop_messages
            .messages
            .send(&connected.main.peer_id(), NOW, second)
            .map_err(|error| error.to_string())?;
        let delivered = wait_for(
            &sim,
            &connected.main_messages.collected,
            2,
            Duration::from_secs(120),
        )
        .await?;
        if delivered[1].body != second {
            return Err(format!(
                "the message after the reconnect arrived as `{}`",
                String::from_utf8_lossy(&delivered[1].body)
            ));
        }
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// The rights around an offer
// ---------------------------------------------------------------------------

/// The host's own floor can refuse a message a right gives: the sender is told the class,
/// the host's words stay on the receiver, and the right is untouched.
pub(crate) fn the_hosts_floor_refuses_a_message_and_its_words_stay_local() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        // The host's own say, in its own words: it takes no message from anyone.
        let words = "the host does not take messages";
        let floor: Arc<dyn Floor + Send + Sync> =
            Arc::new(|_pair: &Pair, capability: Capability| {
                (capability == Capability::WRITE).then(|| words.to_owned())
            });
        let connected = ready(&sim, &beacon, false, floor).await?;
        connected
            .laptop_messages
            .messages
            .send(&connected.main.peer_id(), NOW, b"will you take this?")
            .map_err(|error| error.to_string())?;
        connected
            .laptop_messages
            .serve(&connected.laptop_managed.connections, &connected.main);
        connected
            .main_messages
            .serve(&connected.main_managed.connections, &connected.laptop);
        wait_for_state(
            &sim,
            &connected.laptop_messages.messages,
            &connected.main.peer_id(),
            |state| *state == QueueState::Empty,
            Duration::from_secs(120),
        )
        .await?;
        if !connected.main_messages.collected.is_empty() {
            return Err(format!(
                "a host whose floor refuses messages was handed {} of them",
                connected.main_messages.collected.len()
            ));
        }
        // The sender's own words about the refusal are this crate's, never the host's: the
        // log holds a class, and the class is not the host's sentence.
        let refused_here = connected
            .laptop
            .audit()?
            .entries()
            .map_err(|error| error.to_string())?;
        let reason = refused_here
            .iter()
            .find_map(|entry| match &entry.act {
                Act::MessageRefused { peer, reason, .. } if *peer == connected.main.peer_id() => {
                    Some(*reason)
                }
                _ => None,
            })
            .ok_or("the sender recorded no refusal of the message")?;
        if reason != RefusedReason::Rights {
            return Err(format!(
                "the sender's log holds `{reason}` for a message the host's floor refused"
            ));
        }
        // The receiver's log is where the host's words are, at the floor's step.
        let refused_there = connected
            .main
            .audit()?
            .entries()
            .map_err(|error| error.to_string())?;
        let refusal = refused_there
            .iter()
            .find_map(|entry| match &entry.act {
                Act::Refused {
                    capability,
                    refusal,
                    ..
                } if *capability == Capability::WRITE => Some(refusal.clone()),
                _ => None,
            })
            .ok_or("the receiver recorded no refusal of the message")?;
        if refusal.step() != Step::Floor {
            return Err(format!(
                "the receiver recorded the refusal at the `{}` step, not the host's floor",
                refusal.step()
            ));
        }
        match &refusal {
            Refusal::Floor { reason } if reason == words => {}
            other => {
                return Err(format!(
                    "the receiver's floor refused in `{other}`, not in the host's own words"
                ));
            }
        }
        // A floor refusal is not a withdrawal: with no floor at all the right still allows.
        let admin = label("admin")?;
        let question = Question {
            speaker: Speaker::Authenticated(connected.laptop.peer_id()),
            pair: pair(&connected.laptop, &admin),
            capability: Capability::WRITE,
        };
        match connected
            .main
            .rights()?
            .decide(&question, &NoFloor, NOW)
            .map_err(|error| error.to_string())?
        {
            Decision::Allowed { .. } => Ok(()),
            Decision::Refused { refusal } => Err(format!(
                "a host's floor refusal left the pair's write right refused at the `{}` step",
                refusal.step()
            )),
        }
    })
}

/// A message is offered only under the pair's live write right: with the right withdrawn
/// the queue says so and nothing is sent, and service resumes when the right is given
/// back.
pub(crate) fn no_write_right_means_no_offer_and_service_resumes() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let connected = ready(&sim, &beacon, true, Arc::new(NoFloor)).await?;
        let admin = label("admin")?;
        let pair = pair(&connected.laptop, &admin);
        let owner = person("owner")?;
        connected
            .main
            .rights()?
            .withdraw(&pair, Capability::WRITE, owner.clone(), NOW)
            .map_err(|error| error.to_string())?;
        let bodies: [&[u8]; 2] = [b"the first", b"the second"];
        for body in bodies {
            connected
                .main_messages
                .messages
                .send(&connected.laptop.peer_id(), NOW, body)
                .map_err(|error| error.to_string())?;
        }
        connected
            .main_messages
            .serve(&connected.main_managed.connections, &connected.laptop);
        connected
            .laptop_messages
            .serve(&connected.laptop_managed.connections, &connected.main);
        let state = connected
            .main_messages
            .messages
            .state(&connected.laptop.peer_id())
            .map_err(|error| error.to_string())?;
        if !matches!(state, QueueState::NoRight { .. }) {
            return Err(format!(
                "a queue whose pair's write right was withdrawn reports `{state:?}`, not `no right`"
            ));
        }
        sim.clock().advance(Duration::from_secs(5)).await;
        if !connected.laptop_messages.collected.is_empty() {
            return Err(format!(
                "{} messages were offered under a withdrawn right",
                connected.laptop_messages.collected.len()
            ));
        }
        if connected
            .main_messages
            .messages
            .pending(&connected.laptop.peer_id())
            .map_err(|error| error.to_string())?
            .len()
            != bodies.len()
        {
            return Err("a withdrawn right dropped a message instead of holding it".to_owned());
        }
        // A person gives it back, and the service resumes on its own.
        connected
            .main
            .rights()?
            .grant(
                &pair,
                Capability::WRITE,
                Authority::Person(owner),
                None,
                NOW,
            )
            .map_err(|error| error.to_string())?;
        let delivered = wait_for(
            &sim,
            &connected.laptop_messages.collected,
            bodies.len(),
            Duration::from_secs(120),
        )
        .await?;
        if delivered[0].body != bodies[0] || delivered[1].body != bodies[1] {
            return Err("the messages arrived out of order after the right came back".to_owned());
        }
        Ok(())
    })
}

/// A refusal is final: the receiver records it, the sender records it and drops its copy,
/// the queue moves on, and a later message is delivered with the gap the refusals left.
pub(crate) fn a_refusal_is_final_and_the_queue_moves_on() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let connected = ready(&sim, &beacon, false, Arc::new(NoFloor)).await?;
        let admin = label("admin")?;
        let pair = pair(&connected.laptop, &admin);
        let owner = person("owner")?;
        // The receiver's decision refuses from here on; the sender's own right is its
        // claim and stays live, so the queue is offered and the answer is the receiver's.
        connected
            .main
            .rights()?
            .withdraw(&pair, Capability::WRITE, owner.clone(), NOW)
            .map_err(|error| error.to_string())?;
        let bodies: [&[u8]; 2] = [b"refused one", b"refused two"];
        let mut envelopes = Vec::new();
        for body in bodies {
            envelopes.push(
                connected
                    .laptop_messages
                    .messages
                    .send(&connected.main.peer_id(), NOW, body)
                    .map_err(|error| error.to_string())?,
            );
        }
        connected
            .laptop_messages
            .serve(&connected.laptop_managed.connections, &connected.main);
        connected
            .main_messages
            .serve(&connected.main_managed.connections, &connected.laptop);
        wait_for_state(
            &sim,
            &connected.laptop_messages.messages,
            &connected.main.peer_id(),
            |state| *state == QueueState::Empty,
            Duration::from_secs(120),
        )
        .await?;
        let refused_here = connected
            .laptop
            .audit()?
            .entries()
            .map_err(|error| error.to_string())?;
        for envelope in &envelopes {
            let named = refused_here.iter().any(|entry| {
                matches!(
                    &entry.act,
                    Act::MessageRefused { peer, id, count, .. }
                        if *peer == connected.main.peer_id()
                            && *id == *envelope.id().as_bytes()
                            && *count == envelope.count()
                )
            });
            if !named {
                return Err(format!(
                    "the sender recorded no refusal of count {}",
                    envelope.count()
                ));
            }
        }
        let refused_there = connected
            .main
            .audit()?
            .entries()
            .map_err(|error| error.to_string())?;
        let refusals = refused_there
            .iter()
            .filter(|entry| {
                matches!(
                    &entry.act,
                    Act::Refused { pair: refused, capability, .. }
                        if *refused == pair && *capability == Capability::WRITE
                )
            })
            .count();
        if refusals != envelopes.len() {
            return Err(format!(
                "the receiver recorded {refusals} refusals, not {}",
                envelopes.len()
            ));
        }
        // A refusal is not a retry: the queue stays empty and nothing arrives.
        sim.clock().advance(Duration::from_secs(5)).await;
        if !connected
            .laptop_messages
            .messages
            .pending(&connected.main.peer_id())
            .map_err(|error| error.to_string())?
            .is_empty()
        {
            return Err("a refused message was queued again".to_owned());
        }
        if !connected.main_messages.collected.is_empty() {
            return Err("a refused message reached the receiver's caller".to_owned());
        }
        // The next message is delivered, and the two refused counts are declared missing.
        connected
            .main
            .rights()?
            .grant(
                &pair,
                Capability::WRITE,
                Authority::Person(owner),
                None,
                NOW,
            )
            .map_err(|error| error.to_string())?;
        connected
            .laptop_messages
            .messages
            .send(&connected.main.peer_id(), NOW, b"and this one")
            .map_err(|error| error.to_string())?;
        let delivered = wait_for(
            &sim,
            &connected.main_messages.collected,
            1,
            Duration::from_secs(120),
        )
        .await?;
        let delivery = &delivered[0];
        if delivery.body != b"and this one" {
            return Err("the message after the refusals did not arrive".to_owned());
        }
        if delivery.envelope.count() != 3 || delivery.gap != Some(Gap::Missing { count: 2 }) {
            return Err(format!(
                "the message after two refusals is count {} with gap {:?}, not three declaring \
                 two missing",
                delivery.envelope.count(),
                delivery.gap
            ));
        }
        Ok(())
    })
}

/// A peer cannot fill the log with refusals: with the part of the receiver's log a peer may
/// fill already full, a message its rights refuse is still answered and still dropped at
/// the sender, and the receiver's log takes neither an entry nor a byte past the room kept
/// for a person's own acts.
pub(crate) fn a_peer_cannot_fill_the_log_with_refusals() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let connected = ready(&sim, &beacon, false, Arc::new(NoFloor)).await?;
        let admin = label("admin")?;
        let pair = pair(&connected.laptop, &admin);
        // The receiver's decision refuses from here on; the sender's own right is its claim
        // and stays live, so the queue is offered and the answer is the receiver's.
        connected
            .main
            .rights()?
            .withdraw(&pair, Capability::WRITE, person("owner")?, NOW)
            .map_err(|error| error.to_string())?;
        // The log is filled to the point where the part a peer may fill is gone: the
        // refusal the offer causes has no room, and the file stays under its cap.
        fill_log(&connected.main, MAX_FILE_BYTES - RESERVED_FOR_PERSON_BYTES)?;
        let entries_before = connected
            .main
            .audit()?
            .entries()
            .map_err(|error| error.to_string())?
            .len();
        connected
            .laptop_messages
            .messages
            .send(
                &connected.main.peer_id(),
                NOW,
                b"refused, and answered anyway",
            )
            .map_err(|error| error.to_string())?;
        connected
            .laptop_messages
            .serve(&connected.laptop_managed.connections, &connected.main);
        connected
            .main_messages
            .serve(&connected.main_managed.connections, &connected.laptop);
        // The answer is still given: the sender records the refusal and drops its copy.
        wait_for_state(
            &sim,
            &connected.laptop_messages.messages,
            &connected.main.peer_id(),
            |state| *state == QueueState::Empty,
            Duration::from_secs(120),
        )
        .await?;
        let refused_here = connected
            .laptop
            .audit()?
            .entries()
            .map_err(|error| error.to_string())?;
        if !refused_here.iter().any(|entry| {
            matches!(
                &entry.act,
                Act::MessageRefused { peer, .. } if *peer == connected.main.peer_id()
            )
        }) {
            return Err("the sender recorded no refusal of the message".to_owned());
        }
        if !connected.main_messages.collected.is_empty() {
            return Err("a refused message reached the receiver's caller".to_owned());
        }
        // The receiver's log took nothing: no entry for the refusal, and no byte past the
        // room its own acts keep.
        let entries_after = connected
            .main
            .audit()?
            .entries()
            .map_err(|error| error.to_string())?
            .len();
        if entries_after != entries_before {
            return Err(format!(
                "the receiver's log took the refusal: {entries_after} entries, not \
                 {entries_before}"
            ));
        }
        let size = connected
            .main
            .storage()
            .read_audit()
            .map_err(io_error)?
            .len() as u64;
        if size > MAX_FILE_BYTES - RESERVED_FOR_PERSON_BYTES {
            return Err(format!(
                "the receiver's log grew to {size} bytes, past the {} kept for a person",
                MAX_FILE_BYTES - RESERVED_FOR_PERSON_BYTES
            ));
        }
        Ok(())
    })
}

/// A flood is throttled, the sender is told how long to wait, and a throttle is not a
/// refusal: nothing is recorded against the pair and every message arrives once the
/// window turns.
pub(crate) fn a_flood_is_throttled_and_the_sender_is_told() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let connected = ready(&sim, &beacon, false, Arc::new(NoFloor)).await?;
        let admin = label("admin")?;
        let bound = pair(&connected.laptop, &admin);
        let rights = connected.main.rights()?;
        let before = rights.rights(&bound).map_err(|error| error.to_string())?;
        for index in 0..MAX_QUEUE {
            connected
                .laptop_messages
                .messages
                .send(
                    &connected.main.peer_id(),
                    NOW,
                    format!("flood {index}").as_bytes(),
                )
                .map_err(|error| error.to_string())?;
        }
        connected
            .laptop_messages
            .serve(&connected.laptop_managed.connections, &connected.main);
        connected
            .main_messages
            .serve(&connected.main_managed.connections, &connected.laptop);
        let state = wait_for_state(
            &sim,
            &connected.laptop_messages.messages,
            &connected.main.peer_id(),
            |state| matches!(state, QueueState::Throttled { .. }),
            Duration::from_secs(120),
        )
        .await?;
        let QueueState::Throttled { until } = state else {
            return Err(format!("the queue reports `{state:?}`, not a throttle"));
        };
        let pending = connected
            .laptop_messages
            .messages
            .pending(&connected.main.peer_id())
            .map_err(|error| error.to_string())?;
        let taken = MAX_QUEUE - pending.len();
        if taken < MAX_OFFERS_PER_WINDOW as usize {
            return Err(format!(
                "the receiver throttled after {taken} offers, fewer than the {MAX_OFFERS_PER_WINDOW} \
                 its window allows"
            ));
        }
        let now = NOW.plus(sim.clock().elapsed());
        if until > now.plus(MESSAGE_WINDOW) {
            return Err(format!(
                "the sender was told to wait until {until}, past one {MESSAGE_WINDOW:?} window"
            ));
        }
        if pending.is_empty() {
            return Err("the queue emptied while the sender was throttled".to_owned());
        }
        let entries = connected
            .laptop
            .audit()?
            .entries()
            .map_err(|error| error.to_string())?;
        if entries
            .iter()
            .any(|entry| matches!(entry.act, Act::MessageRefused { .. }))
        {
            return Err("a throttle was recorded as a refusal".to_owned());
        }
        // The decision itself is untouched: the same rights the pair held before the flood.
        let after = rights.rights(&bound).map_err(|error| error.to_string())?;
        if after != before {
            return Err(format!(
                "a throttle changed the pair's rights: {before:?} became {after:?}"
            ));
        }
        // The window turns on its own, and every message arrives, once, in order: the
        // receiver's decision did not change, it only asked the sender to wait.
        let delivered = wait_for(
            &sim,
            &connected.main_messages.collected,
            MAX_QUEUE,
            Duration::from_secs(300),
        )
        .await?;
        for (index, delivery) in delivered.iter().enumerate() {
            if delivery.envelope.count() != index as u64 + 1 {
                return Err(format!(
                    "the deliveries are out of order: count {} arrived at place {index}",
                    delivery.envelope.count()
                ));
            }
            if delivery.gap.is_some() {
                return Err(format!(
                    "a throttled message was declared missing before count {}",
                    delivery.envelope.count()
                ));
            }
        }
        Ok(())
    })
}

/// An offer nobody answers costs one round a second, not a spin.
///
/// The far side here answers every offer the fastest way there is: it accepts the stream and
/// resets it. A service without a pause after an unanswered round would read its queue file
/// and the record once per iteration for as long as the retention lasts, so the case counts
/// the offers over ten seconds of the layer's own time and expects one per second.
pub(crate) fn an_unanswered_offer_costs_one_round() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let connected = ready(&sim, &beacon, false, Arc::new(NoFloor)).await?;
        let connection = wait_live(
            &sim,
            &connected.main_managed.connections,
            &connected.laptop.peer_id(),
        )
        .await?;
        let offers = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&offers);
        let resetting = tokio::spawn(async move {
            while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                counted.fetch_add(1, Ordering::SeqCst);
                let _ = send.reset(0u32.into());
                let _ = recv.stop(0u32.into());
            }
        });
        connected
            .laptop_messages
            .messages
            .send(&connected.main.peer_id(), NOW, b"nobody answers this")
            .map_err(|error| error.to_string())?;
        connected
            .laptop_messages
            .serve(&connected.laptop_managed.connections, &connected.main);
        sim.clock().advance(Duration::from_secs(10)).await;
        let rounds = offers.load(Ordering::SeqCst);
        resetting.abort();
        if rounds == 0 {
            return Err("the sender offered the message not once in ten seconds".to_owned());
        }
        if rounds > 12 {
            return Err(format!(
                "an offer nobody answered was made {rounds} times in ten seconds: the service \
                 is spinning through its queue"
            ));
        }
        let pending = connected
            .laptop_messages
            .messages
            .pending(&connected.main.peer_id())
            .map_err(|error| error.to_string())?;
        if pending.len() != 1 {
            return Err(format!(
                "an unanswered offer left {} messages queued, not the one it kept",
                pending.len()
            ));
        }
        Ok(())
    })
}

/// The beacon carries no message: with both machines registered and the beacon alive, a
/// message travels over the pair's own path and the beacon's memory holds neither its
/// identifier nor its body; with the beacon killed, the next message still arrives.
pub(crate) fn the_beacon_never_carries_a_message() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let connected = ready(&sim, &beacon, false, Arc::new(NoFloor)).await?;
        // Both machines keep themselves findable, so the beacon's memory is not empty and
        // the claim is about what it holds, not about a server nobody ever spoke to.
        let _main_session = session(&beacon, &connected.main).await?;
        let _laptop_session = session(&beacon, &connected.laptop).await?;
        connected
            .laptop_messages
            .serve(&connected.laptop_managed.connections, &connected.main);
        connected
            .main_messages
            .serve(&connected.main_managed.connections, &connected.laptop);
        let body = b"a body the beacon must never hold".to_vec();
        let envelope = connected
            .laptop_messages
            .messages
            .send(&connected.main.peer_id(), NOW, &body)
            .map_err(|error| error.to_string())?;
        let delivered = wait_for(
            &sim,
            &connected.main_messages.collected,
            1,
            Duration::from_secs(120),
        )
        .await?;
        if delivered[0].body != body {
            return Err("the message that arrived is not the one composed".to_owned());
        }
        // Read while the beacon is alive and the message has already travelled.
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
        let id = envelope.id().to_string();
        if rendered.contains(id.as_str()) {
            return Err(format!("the beacon holds the message's identifier {id}"));
        }
        let text = String::from_utf8_lossy(&body);
        if rendered.contains(text.as_ref()) {
            return Err("the beacon holds the message's body".to_owned());
        }
        // And it is not on the path: with the beacon killed, the next message still arrives.
        beacon.kill();
        let second = b"composed while the beacon is gone".to_vec();
        connected
            .laptop_messages
            .messages
            .send(&connected.main.peer_id(), NOW, &second)
            .map_err(|error| error.to_string())?;
        let delivered = wait_for(
            &sim,
            &connected.main_messages.collected,
            2,
            Duration::from_secs(120),
        )
        .await?;
        if delivered[1].body != second {
            return Err("a message composed while the beacon was gone did not arrive".to_owned());
        }
        if connected.keeper.is_finished() {
            return Err("a pair whose beacon is gone lost its keeper".to_owned());
        }
        Ok(())
    })
}

/// Offering a message is not the pair's traffic: a connection closed with an offer still
/// unanswered is a dial that carried nothing, so the keeper stops instead of re-dialling
/// for ever.
pub(crate) fn offering_a_message_is_not_the_pairs_traffic() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        // Both bound, so the sender's own gate is open and the offer really is made.
        main.rights()?
            .bind(&laptop.peer_id(), main_binding(&label("admin")?)?, NOW)
            .map_err(|error| error.to_string())?;
        laptop
            .rights()?
            .bind(
                &main.peer_id(),
                binding(
                    "laptop-account",
                    "laptop-instance",
                    &label("laptop-assistant")?,
                )?,
                NOW,
            )
            .map_err(|error| error.to_string())?;
        let main_managed = Managed::start(&sim, &beacon, &main, &main.records())?;
        let laptop_managed = Managed::start(&sim, &beacon, &laptop, &laptop.records())?;
        let main_messages = Messaging::open(&sim, &main, Arc::new(NoFloor))?;
        main_messages
            .messages
            .send(&laptop.peer_id(), NOW, b"nobody is there to take this")
            .map_err(|error| error.to_string())?;
        main_messages.serve(&main_managed.connections, &laptop);
        let keeper = spawn_keeper(&main_managed, &laptop);
        let mut closed = 0usize;
        within(&sim, Duration::from_secs(300), async {
            while closed < usize::from(KEEPER_UNSTABLE_LIMIT) && !keeper.is_finished() {
                let connection =
                    wait_live(&sim, &laptop_managed.connections, &main.peer_id()).await?;
                // The offer has started: the sender opened a stream and wrote it. The
                // connection goes while it waits for an answer nobody will send.
                within(&sim, MESSAGE_BUDGET, connection.accept_bi())
                    .await?
                    .map_err(|error| error.to_string())?;
                laptop_managed.connections.disconnect(&main.peer_id());
                closed += 1;
            }
            Ok::<(), String>(())
        })
        .await??;
        let end = within(&sim, Duration::from_secs(120), keeper)
            .await?
            .map_err(|error| format!("the keeper's task did not finish: {error}"))?;
        match &end {
            Keeper::Unstable { peer, .. } if *peer == laptop.fingerprint() => Ok(()),
            other => Err(format!(
                "the keeper ended `{other}`, not unstable after {closed} dials whose only traffic \
                 was an unanswered offer"
            )),
        }
    })
}

/// A message the peer took is the pair's traffic: a connection that carried one and then
/// died is a link failure, so the keeper dials again however often that happens.
///
/// The round's own measurement ends after the answer arrived, so by the frames alone this
/// connection carried nothing but its binding and one answer; only the take the sender
/// records when it reads the answer tells the keeper otherwise. The death happens inside the
/// keeper's settle window, which is the only time a dial that carried nothing is judged.
pub(crate) fn a_taken_message_is_the_pairs_traffic() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let connected = ready(&sim, &beacon, false, Arc::new(NoFloor)).await?;
        let keeper = &connected.keeper;
        connected
            .laptop_messages
            .serve(&connected.laptop_managed.connections, &connected.main);
        connected
            .main_messages
            .serve(&connected.main_managed.connections, &connected.laptop);
        // One more drop than the keeper tolerates of dials that carried nothing: each of
        // these connections carried a message the peer took.
        let mut delivered = 0usize;
        for round in 0..=KEEPER_UNSTABLE_LIMIT {
            connected
                .laptop_messages
                .messages
                .send(
                    &connected.main.peer_id(),
                    NOW,
                    format!("round {round}").as_bytes(),
                )
                .map_err(|error| error.to_string())?;
            delivered += 1;

            wait_for(
                &sim,
                &connected.main_messages.collected,
                delivered,
                Duration::from_secs(120),
            )
            .await?;
            // The answer is what makes the connection the pair's use on this side: wait
            // until the sender's own service has taken it and dropped its copy, or the
            // connection would die carrying only an unanswered offer.
            wait_for_state(
                &sim,
                &connected.laptop_messages.messages,
                &connected.main.peer_id(),
                |state| *state == QueueState::Empty,
                Duration::from_secs(120),
            )
            .await?;

            // The pair's connection goes from the other side, after the message landed, and
            // before the keeper's settle window has passed: the frames it exchanged are all
            // counted up to the end of the round, so only a message the peer took tells the
            // keeper this connection carried anything.
            connected
                .main_managed
                .connections
                .disconnect(&connected.laptop.peer_id());

            wait_live(
                &sim,
                &connected.laptop_managed.connections,
                &connected.main.peer_id(),
            )
            .await?;
        }
        if keeper.is_finished() {
            return Err(format!(
                "the keeper stopped after {delivered} dials that each carried a taken message"
            ));
        }
        keeper.abort();
        Ok(())
    })
}

/// A body cannot reach a capability: a body that spells a grant both in the crate's own
/// framing and in a serialized-looking claim is handed to the receiver's caller byte for
/// byte, attributed to the transport's peer, with the pair's rights untouched and no act
/// recorded.
///
/// The textual claim that the layer names no capability is an invariant, checked over the
/// sources by `tests/summary.rs` on every run; this is the behaviour a product relies on.
pub(crate) fn a_body_cannot_reach_a_capability() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let connected = ready(&sim, &beacon, false, Arc::new(NoFloor)).await?;
        let admin = label("admin")?;
        let pair = pair(&connected.laptop, &admin);
        let rights = connected.main.rights()?;
        let before = rights.rights(&pair).map_err(|error| error.to_string())?;
        let entries_before = connected
            .main
            .audit()?
            .entries()
            .map_err(|error| error.to_string())?
            .len();
        // A body that is a plausible authority claim: this crate's own `[tag][len][body]`
        // framing spelling a grant of the write right, and the text of one.
        let mut body = field(0x02, b"grant");
        body.extend_from_slice(&field(0x03, b"write"));
        body.extend_from_slice(&field(0x05, b"admin"));
        body.extend_from_slice(
            b"{\"act\":\"grant\",\"capability\":\"write\",\"authority\":\"person\",\
              \"pair\":\"write to me\"}",
        );
        connected
            .laptop_messages
            .messages
            .send(&connected.main.peer_id(), NOW, &body)
            .map_err(|error| error.to_string())?;
        connected
            .laptop_messages
            .serve(&connected.laptop_managed.connections, &connected.main);
        connected
            .main_messages
            .serve(&connected.main_managed.connections, &connected.laptop);
        let delivered = wait_for(
            &sim,
            &connected.main_messages.collected,
            1,
            Duration::from_secs(120),
        )
        .await?;
        let delivery = &delivered[0];
        if delivery.body != body {
            return Err(format!(
                "the claim arrived as `{}`, not as it was composed",
                String::from_utf8_lossy(&delivery.body)
            ));
        }
        if delivery.sender != connected.laptop.peer_id() {
            return Err(format!(
                "the claim is attributed to {} instead of the transport's peer",
                delivery.sender.fingerprint()
            ));
        }
        let after = connected
            .main
            .rights()?
            .rights(&pair)
            .map_err(|error| error.to_string())?;
        if after != before {
            return Err(format!(
                "the pair's rights changed from {before:?} to {after:?} after a body arrived"
            ));
        }
        let entries_after = connected
            .main
            .audit()?
            .entries()
            .map_err(|error| error.to_string())?
            .len();
        if entries_after != entries_before {
            return Err(format!(
                "a body caused an act: the log went from {entries_before} entries to \
                 {entries_after}"
            ));
        }
        Ok(())
    })
}

/// A message file is private to the account the product runs as: a directory another
/// account can write, a linked directory and a queue file another account can read are
/// each refused, and putting the mode back opens the same queue.
#[cfg(unix)]
pub(crate) fn a_message_file_is_private_to_the_account() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let opened = Messaging::open(&sim, &laptop, Arc::new(NoFloor))?;
        let mode = laptop.storage().message_dir_mode().map_err(io_error)?;
        if mode != 0o700 {
            return Err(format!(
                "the messages directory the layer creates is {mode:o}, not 0700"
            ));
        }
        opened
            .messages
            .send(&main.peer_id(), NOW, b"private")
            .map_err(|error| error.to_string())?;
        drop(opened);
        laptop
            .storage()
            .set_message_dir_mode(0o777)
            .map_err(io_error)?;
        match Messaging::open(&sim, &laptop, Arc::new(NoFloor)) {
            Err(error) if error.contains("not private") => {}
            Err(error) => {
                return Err(format!(
                    "a messages directory another account can write reads `{error}`"
                ));
            }
            Ok(_) => {
                return Err(
                    "a messages directory another account can write was accepted".to_owned(),
                );
            }
        }
        laptop
            .storage()
            .set_message_dir_mode(0o700)
            .map_err(io_error)?;
        let reopened = Messaging::open(&sim, &laptop, Arc::new(NoFloor))?;
        // A queue another account can read is refused, and the repair reaches it: naming
        // the file is not opening the queue.
        laptop
            .storage()
            .set_message_mode(&main.peer_id(), 0o644)
            .map_err(io_error)?;
        match reopened.messages.pending(&main.peer_id()) {
            Err(MessageError::Insecure { .. }) => {}
            Err(error) => {
                return Err(format!("an insecure queue reads `{error}`"));
            }
            Ok(pending) => {
                return Err(format!(
                    "a queue another account can read was read as {} envelopes",
                    pending.len()
                ));
            }
        }
        match reopened.messages.state(&main.peer_id()) {
            Err(MessageError::Insecure { .. }) => {}
            Err(error) => return Err(format!("the insecure queue's state reads `{error}`")),
            Ok(state) => {
                return Err(format!(
                    "a queue another account can read reported `{state:?}`"
                ));
            }
        }
        laptop
            .storage()
            .set_message_mode(&main.peer_id(), 0o600)
            .map_err(io_error)?;
        let pending = reopened
            .messages
            .pending(&main.peer_id())
            .map_err(|error| error.to_string())?;
        if pending.len() != 1 {
            return Err(format!(
                "the repaired queue holds {} messages, not one",
                pending.len()
            ));
        }
        // A messages directory that is a symbolic link is refused as a link, as a
        // records directory is: a queue must not be made to land outside the root.
        laptop
            .storage()
            .replace_message_dir_with_a_link()
            .map_err(io_error)?;
        match Messaging::open(&sim, &laptop, Arc::new(NoFloor)) {
            Err(error) if error.contains("not private") => Ok(()),
            Err(error) => Err(format!("a linked messages directory reads `{error}`")),
            Ok(_) => Err("a linked messages directory was accepted".to_owned()),
        }
    })
}

/// A message file's unknown fields are kept and written back, and bytes that are not a
/// message file are refused rather than believed.
pub(crate) fn a_message_file_is_additive_and_refuses_garbage() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let messaging = Messaging::open(&sim, &laptop, Arc::new(NoFloor))?;
        messaging
            .messages
            .send(&main.peer_id(), NOW, b"the first")
            .map_err(|error| error.to_string())?;
        let mut bytes = laptop
            .storage()
            .read_message(&main.peer_id())
            .map_err(io_error)?;
        // One field of a newer build: tag, length, body, after everything this build
        // knows.
        let top = field(0x7f, b"kept-by-a-newer-build");
        bytes.extend_from_slice(&top);
        laptop
            .storage()
            .write_message(&main.peer_id(), &bytes)
            .map_err(io_error)?;
        // A second message forces the whole file to be rewritten.
        messaging
            .messages
            .send(&main.peer_id(), NOW, b"the second")
            .map_err(|error| error.to_string())?;
        let rewritten = laptop
            .storage()
            .read_message(&main.peer_id())
            .map_err(io_error)?;
        if !holds_bytes(&rewritten, &top) {
            return Err(
                "the rewrite dropped a field this build does not know, so the format is not \
                 additive"
                    .to_owned(),
            );
        }
        let pending = messaging
            .messages
            .pending(&main.peer_id())
            .map_err(|error| error.to_string())?;
        if pending.len() != 2 {
            return Err(format!(
                "the rewritten queue holds {} messages, not two",
                pending.len()
            ));
        }
        // A field of a newer build nested inside the queue's own `0x03`: a build that grew
        // one queued message's body appends there, and the rewrite must keep it too.
        let inner = field(0x7e, b"nested-by-a-newer-build");
        let grown = rewrite(&rewritten, QUEUE_MAGIC.len() + 1, 0x03, |body| {
            let mut grown = body.to_vec();
            grown.extend_from_slice(&inner);
            grown
        })?;
        laptop
            .storage()
            .write_message(&main.peer_id(), &grown)
            .map_err(io_error)?;
        messaging
            .messages
            .send(&main.peer_id(), NOW, b"the third")
            .map_err(|error| error.to_string())?;
        let rewritten = laptop
            .storage()
            .read_message(&main.peer_id())
            .map_err(io_error)?;
        if !holds_bytes(&rewritten, &inner) {
            return Err(
                "the rewrite dropped a field nested inside a queued message, so the format is \
                 not additive below the top"
                    .to_owned(),
            );
        }
        let pending = messaging
            .messages
            .pending(&main.peer_id())
            .map_err(|error| error.to_string())?;
        if pending.len() != 3 {
            return Err(format!(
                "the rewritten queue holds {} messages, not three",
                pending.len()
            ));
        }
        // A field of a newer build nested inside a taken identifier: the module's "at every
        // level" claim covers that level, and a queue file is a file — no delivery is needed to
        // put an entry there.
        let inside = field(0x7d, b"nested-in-a-taken-identifier");
        let mut taken = field(0x01, &[0x11; 16]);
        taken.extend_from_slice(&field(0x03, &NOW.unix_seconds().to_be_bytes()));
        taken.extend_from_slice(&inside);
        let mut with_taken = rewritten.clone();
        with_taken.extend_from_slice(&field(0x04, &taken));
        laptop
            .storage()
            .write_message(&main.peer_id(), &with_taken)
            .map_err(io_error)?;
        messaging
            .messages
            .send(&main.peer_id(), NOW, b"the fourth")
            .map_err(|error| error.to_string())?;
        let rewritten = laptop
            .storage()
            .read_message(&main.peer_id())
            .map_err(io_error)?;
        if !holds_bytes(&rewritten, &inside) {
            return Err(
                "the rewrite dropped a field nested inside a taken identifier, so the format is \
                 not additive below the top"
                    .to_owned(),
            );
        }
        let pending = messaging
            .messages
            .pending(&main.peer_id())
            .map_err(|error| error.to_string())?;
        if pending.len() != 4 {
            return Err(format!(
                "the rewritten queue holds {} messages, not four",
                pending.len()
            ));
        }
        // Bytes that are not a queue are refused, not read as an empty one.
        laptop
            .storage()
            .write_message(&main.peer_id(), b"not a queue")
            .map_err(io_error)?;
        match messaging.messages.pending(&main.peer_id()) {
            Err(MessageError::Malformed { .. }) => Ok(()),
            Err(error) => Err(format!(
                "bytes that are not a queue were refused as `{error}`"
            )),
            Ok(pending) => Err(format!(
                "bytes that are not a queue were read as {} envelopes",
                pending.len()
            )),
        }
    })
}
