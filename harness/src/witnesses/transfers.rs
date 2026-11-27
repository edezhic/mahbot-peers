//! Transfer cases: a whole file moved over the pair's connection.
//!
//! A transfer is its own thing on the pair's connection — one bidirectional stream per
//! attempt, an offer, the receiving machine's answer, the file's bytes, then the
//! receiver's verdict — so a case here wires the same layers a product does: the
//! manager, the one reader that tells a message from an action from a transfer, and the
//! transfer layer behind it. Nothing is held in memory that a case did not ask for: the
//! file is [`Generated`] from its offset, and the sink hashes what it is handed.
//!
//! Every wait is the simulation's: a transfer is driven by [`drive_transfer`] or by
//! [`advance_until`] in steps a case chooses, so a case that has to cross a minute-long
//! bound spends seconds of virtual time rather than sixty thousand polls, and a transfer
//! that never ends fails its case instead of hanging it.

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mahbot_peers::net::{MAX_BUFFERED_BYTES, MAX_STREAM_BYTES, MAX_STREAMS, SERVER_NAME};
use mahbot_peers::peer::audit::{MAX_FILE_BYTES, RESERVED_FOR_PERSON_BYTES};
use mahbot_peers::peer::{
    ACTION_ID_BYTES, Act, ActionAnswer, ActionId, ActionKind, Actions, Answer, Authority,
    Capability, Deliveries, Digest, Executor, Floor, Inbox, InboxError, Issuer,
    MAX_OFFERS_PER_WINDOW, MAX_TRANSFER_STARTS, Messages, Moment, NoFloor, Pair, RECOVERY_DIALS,
    Recovery, Sink, Step, TRANSFER_CHUNK, TRANSFER_STALL, TRANSFER_START_WINDOW,
    TRANSFER_THROTTLE_CAP, TRANSFER_WAIT, Transfer, TransferError, TransferFailure, TransferLimit,
    TransferName, TransferState, Transfers,
};

use crate::actions::Executions;
use crate::beacon::TestBeacon;
use crate::clock::{MockClock, block_on};
use crate::link::FaultPlan;
use crate::machine::Machine;
use crate::messages::{Collected, NOW, SimMoment, wait_for};
use crate::sim::Sim;
use crate::transfers::{Generated, Store, drive_transfer, drive_transfer_in};

use super::connection::{self, Managed};
use super::rights::{fill_log, label, paired_machines, person};
use super::support::{
    binding, counted_dial, field, io_error, keep_findable, offer_frame, pair, round_trip,
    spawn_keeper, wait_live, within,
};

/// How long the connection, the layers and the transfer may take, in virtual time.
const BUDGET: Duration = Duration::from_secs(120);

/// The name the sender gives the file.
const FILE_NAME: &str = "a-report.pdf";

/// The file's length: four transfer chunks, so the sender reads its source more than once
/// and the sink is handed more than one chunk.
const FILE_BYTES: u64 = 256 * 1024;

/// The file the resume cases move: eight chunks, so an interruption lands in the middle.
const LONG_BYTES: u64 = 512 * 1024;

/// How many scheduler turns [`advance_until`] gives the tasks before it moves the clock.
const YIELDS: usize = 16;

/// How many turns a transfer must move nothing before [`drive_in`] moves the clock.
const QUIET: usize = 8;

/// How far a case that waits on a timer moves the clock at a time: a millisecond, which is what
/// every case but the round-trip one uses.
const STEP: Duration = Duration::from_millis(1);

/// How many offers a raw peer answers with a growing offset before it takes the file: more than
/// the stall bound has seconds, at the second of virtual time the sender leaves between attempts.
const GROWING_OFFERS: usize = 90;

/// How long a raw peer takes to answer an offer it has nothing new to say about: just inside the
/// answer budget, so the attempt is long and still answered, and a transfer that charges only the
/// pause between attempts outlives its own bound sixty times over.
const LATE_ANSWER: Duration = Duration::from_secs(29);

/// How many bytes of an answer a case reads: comfortably more than the longest answer either
/// layer writes.
const ANSWER_BYTES: usize = 256;

/// One transfer chunk, in the same unit as the file lengths a case offers.
const CHUNK: u64 = TRANSFER_CHUNK as u64;

/// A file one chunk past one stream's window: enough that the sender's writes fill the window
/// and the write after them parks.
const PAST_A_WINDOW: u64 = MAX_STREAM_BYTES as u64 + CHUNK;

/// A hundred mebibytes: the file the round-trip bound is measured on.
const HUNDRED_MEBIBYTES: u64 = 100 * 1024 * 1024;

/// The file one transfer moves in one go: four times the connection's own window and sixteen
/// times a stream's, so carrying it needs the transport's credit replenished many times over and
/// a restart would be handed a byte out of place.
///
/// It is not a gibibyte: what this case proves is the shape — one transfer, no restart, far
/// beyond every window — and not the size. A rate on a real path is the operator's procedure,
/// which is the only place one is measured.
const ONE_GO_BYTES: u64 = 128 * 1024 * 1024;

/// How many times a raw peer repeats one progress word: enough to outlast the transfer's own
/// bound many times over, so a transfer that counted the repetition as progress would not end.
const REPEATS: usize = 100_000;

/// One round trip of a link whose every datagram is delayed by five milliseconds.
const RTT: Duration = Duration::from_millis(10);

/// The most round trips a hundred mebibytes may take on such a link.
const ROUND_TRIPS: u64 = 30;

/// How long a write that will never complete is given before it is called blocked.
///
/// A stream whose credit is used up parks its writer; the bound is what turns that into an
/// answer rather than a hung case.
const BLOCKED: Duration = Duration::from_millis(200);

/// How many bytes past its own stream window a stream may accept before the case says the
/// transport did not bound it.
const STREAM_SLACK: u64 = 256 * 1024;

/// The same for the connection window: the credit every stream on one connection draws on.
const CONNECTION_SLACK: u64 = 1024 * 1024;

/// How often a dribbled frame grows by one byte: five seconds, so the read is re-armed
/// several times inside the answer budget.
const DRIBBLE: Duration = Duration::from_secs(5);

/// The status byte and the two fields a case reads out of an answer frame.
///
/// The frame is read here as the wire carries it — magic, version, a four-byte body length,
/// then tagged fields — because the point of the offers these cases build by hand is that the
/// typed layer would never write them.
struct AnswerFields {
    /// `0x01`: the answer's status byte.
    status: u8,
    /// `0x02`: how many bytes the receiver holds, with `running` and with `resume`.
    offset: Option<u64>,
    /// `0x03`: how long a throttling limit asks the sender to wait, in whole seconds.
    retry_after: Option<u32>,
    /// `0x04`: which limit was reached.
    which: Option<u8>,
}

/// What a machine has behind its one reader.
enum Files {
    /// No transfer layer at all: every frame the reader does not recognise is a message, which
    /// is what an older peer does.
    Older,
    /// A transfer layer, with the product's file ingress; `None` is a product that sends files
    /// and takes none.
    Transfers(Option<Arc<dyn Sink + Send + Sync>>),
}

impl Files {
    /// A machine with no transfer layer.
    const fn older() -> Self {
        Self::Older
    }

    /// A machine that offers files and takes none.
    const fn sending() -> Self {
        Self::Transfers(None)
    }

    /// A machine that takes files into `sink`.
    fn taking(sink: Arc<dyn Sink + Send + Sync>) -> Self {
        Self::Transfers(Some(sink))
    }
}

/// One machine's layers, over its own root, with the transfer layer behind the one reader.
struct Wired {
    /// The manager, its endpoint and the accept loop.
    managed: Managed,
    /// The transfer layer itself, as the product holds it; `None` on a machine that has
    /// none, which is the older peer of [`an_older_peer_answers_in_the_message_vocabulary`].
    transfers: Option<Arc<Transfers>>,
    /// The message layer, so a case can read the queue and compose a message.
    messages: Arc<Messages>,
    /// The action layer, so a case can ask the machine to run one.
    actions: Arc<Actions>,
    /// What the message layer's caller was handed.
    collected: Arc<Collected>,
    /// The machine's own code, as the action layer calls it.
    executions: Arc<Executions>,
    /// The service answering this machine's peer; aborted when the case is done.
    service: tokio::task::JoinHandle<Result<(), InboxError>>,
}

impl Wired {
    /// The transfer layer, or the failure of a case that expected one.
    fn transfers(&self) -> Result<&Arc<Transfers>, String> {
        self.transfers
            .as_ref()
            .ok_or_else(|| "the machine has no transfer layer".to_owned())
    }
}

impl Drop for Wired {
    fn drop(&mut self) {
        self.service.abort();
    }
}

/// Wire `machine`'s layers for one peer, with `sink` as the product's file ingress.
///
/// The same floor and the same moment go into every layer, which is what a product owes
/// them: a different floor in one layer is a host policy that allows messages and refuses
/// files in one place and not the other. [`Files::Older`] is a product with no transfer layer
/// at all — the one reader then has nowhere to hand a transfer frame, which is what an older
/// peer is.
fn wired(
    sim: &Sim,
    beacon: &TestBeacon,
    machine: &Machine,
    peer: &Machine,
    files: Files,
    floor: Arc<dyn Floor + Send + Sync>,
) -> Result<Wired, String> {
    let runtime = sim.clock().runtime();
    let moment: Arc<dyn Moment + Send + Sync> = Arc::new(SimMoment::new(sim.clock().clone(), NOW));
    let collected = Collected::new();
    let deliveries: Arc<dyn Deliveries + Send + Sync> = collected.clone();
    let executions = Executions::new(Arc::clone(&runtime));
    let executor: Arc<dyn Executor + Send + Sync> = executions.clone();
    let messages =
        Arc::new(machine.messages(Arc::clone(&floor), Arc::clone(&moment), deliveries)?);
    let actions = Arc::new(machine.actions(Arc::clone(&floor), Arc::clone(&moment), executor)?);
    let mut inbox = Inbox::new(
        Arc::clone(&messages),
        Arc::clone(&actions),
        Arc::clone(&runtime),
    );
    let transfers = match files {
        Files::Transfers(sink) => {
            let transfers = Arc::new(machine.transfers(floor, moment, sink)?);
            inbox = inbox.with_transfers(Arc::clone(&transfers));
            Some(transfers)
        }
        Files::Older => None,
    };
    let inbox = Arc::new(inbox);
    let managed = Managed::start(sim, beacon, machine, &machine.records())?;
    let service = tokio::spawn(Arc::clone(&inbox).serve(
        Arc::clone(&managed.connections),
        managed.endpoint.clone(),
        peer.peer_id(),
    ));
    Ok(Wired {
        managed,
        transfers,
        messages,
        actions,
        collected,
        executions,
        service,
    })
}

/// Two paired machines, each bound to the other, wired and connected.
struct Duo {
    /// The machine offering the file.
    sender: Machine,
    /// The machine receiving it, whose person decides.
    receiver: Machine,
    /// The assistant the sending machine's pair names: the pair the receiving machine's
    /// person grants, withdraws and rebinds.
    assistant: mahbot_peers::peer::Label,
    /// The sending machine's layers.
    sending: Wired,
    /// The receiving machine's layers.
    arriving: Wired,
}

/// Two machines a person already paired, each bound to the other, wired with no host floor of
/// their own and with no connection made yet.
fn wired_pair(
    sim: &Sim,
    beacon: &TestBeacon,
    sending_files: Files,
    arriving_files: Files,
) -> Result<Duo, String> {
    let (sender, receiver) = paired_machines(sim)?;
    wire_pair(
        sim,
        beacon,
        sender,
        receiver,
        sending_files,
        arriving_files,
        Arc::new(NoFloor),
    )
}

/// Pair two machines, bind each to the other and wire both, with no connection made yet.
///
/// The bindings are what a connection is decided under: the sending machine binds the
/// receiving one under its assistant, and the receiving machine binds the sender under
/// [`Duo::assistant`], which is the pair its person's decisions name. `floor` is the receiving
/// machine's own host floor; the sending machine has none of its own here, because nothing it
/// is asked to do passes through one.
fn wire_pair(
    sim: &Sim,
    beacon: &TestBeacon,
    sender: Machine,
    receiver: Machine,
    sending_files: Files,
    arriving_files: Files,
    floor: Arc<dyn Floor + Send + Sync>,
) -> Result<Duo, String> {
    let assistant = label("first-assistant")?;
    let receiving_assistant = label("second-assistant")?;
    sender
        .rights()?
        .bind(
            &receiver.peer_id(),
            binding("first-account", "first-instance", &receiving_assistant)?,
            NOW,
        )
        .map_err(|error| error.to_string())?;
    receiver
        .rights()?
        .bind(
            &sender.peer_id(),
            binding("second-account", "second-instance", &assistant)?,
            NOW,
        )
        .map_err(|error| error.to_string())?;
    let sending = wired(
        sim,
        beacon,
        &sender,
        &receiver,
        sending_files,
        Arc::new(NoFloor),
    )?;
    let arriving = wired(sim, beacon, &receiver, &sender, arriving_files, floor)?;
    Ok(Duo {
        sender,
        receiver,
        assistant,
        sending,
        arriving,
    })
}

/// Two machines a person paired, with no address in either record.
///
/// The beacon is then the only way each finds the other, which is the state a case about the
/// dial a transfer makes has to start from.
fn paired_without_addresses(sim: &Sim) -> Result<(Machine, Machine), String> {
    let sender = sim.machine().map_err(io_error)?;
    let receiver = sim.machine().map_err(io_error)?;
    for (machine, peer) in [(&sender, &receiver), (&receiver, &sender)] {
        machine
            .records()
            .record_pairing(&peer.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
    }
    Ok((sender, receiver))
}

/// Dial from the sending machine and wait until both sides hold the connection.
async fn connect(sim: &Sim, duo: &Duo) -> Result<(), String> {
    within(
        sim,
        BUDGET,
        duo.sending
            .managed
            .connections
            .connect(&duo.sending.managed.endpoint, &duo.receiver.fingerprint()),
    )
    .await?
    .map_err(|error| error.to_string())?;
    wait_live(
        sim,
        &duo.sending.managed.connections,
        &duo.receiver.peer_id(),
    )
    .await?;
    wait_live(
        sim,
        &duo.arriving.managed.connections,
        &duo.sender.peer_id(),
    )
    .await?;
    Ok(())
}

/// Pair two machines, bind each to the other, wire both and connect them.
async fn duo(
    sim: &Sim,
    beacon: &TestBeacon,
    sending_files: Files,
    arriving_files: Files,
) -> Result<Duo, String> {
    let duo = wired_pair(sim, beacon, sending_files, arriving_files)?;
    connect(sim, &duo).await?;
    Ok(duo)
}

/// The receiving machine's person grants "put files on me" to the sending pair.
fn allow_files(duo: &Duo) -> Result<(), String> {
    duo.receiver
        .rights()?
        .grant(
            &pair(&duo.sender, &duo.assistant),
            Capability::PUT_FILES,
            Authority::Person(person("the operator")?),
            None,
            NOW,
        )
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// Offer `file` to the receiving machine, answering the handle that moves it.
fn offer(duo: &Duo, file: &Arc<Generated>) -> Result<Transfer, String> {
    duo.sending
        .transfers()?
        .send(
            &duo.sending.managed.connections,
            &duo.sending.managed.endpoint,
            &duo.receiver.peer_id(),
            file.offering(),
        )
        .map_err(|error| error.to_string())
}

/// Whether `state` is the one the case wanted, or a failure naming what it was instead.
fn ended(state: TransferState, want: TransferState) -> Result<(), String> {
    if state == want {
        Ok(())
    } else {
        Err(format!(
            "the transfer ended `{state:?}` instead of `{want:?}`"
        ))
    }
}

/// Whether `state` is the failure the case wanted, or a failure naming what it was instead.
fn failed(state: TransferState, failure: TransferFailure) -> Result<(), String> {
    ended(state, TransferState::Failed { failure })
}

/// Wait until `done` holds, moving the clock in `step`-sized jumps, and fail after `budget`.
async fn advance_until(
    sim: &Sim,
    budget: Duration,
    step: Duration,
    done: impl FnMut() -> bool,
) -> Result<(), String> {
    if sim.clock().advance_until(budget, step, done).await {
        Ok(())
    } else {
        Err(format!(
            "the case's condition was not met within {budget:?} of virtual time"
        ))
    }
}

/// How far `transfer` says it has got: the bytes the receiver holds, or zero when it is not
/// moving.
fn moved(transfer: &Transfer) -> u64 {
    match transfer.state() {
        TransferState::Running { moved, .. } => moved,
        _ => 0,
    }
}

/// Move the clock in `step`-sized jumps, and only after the transfer has moved nothing for
/// [`QUIET`] scheduler turns.
///
/// [`drive_transfer_in`] hands the clock a step every few turns whatever the transfer is doing,
/// which is right for a case waiting on a timer and wrong for one counting round trips on the
/// link: time the sender spent runnable would be counted as time on the wire. Here the clock
/// moves only when the transfer can make no progress without it — when it is waiting for a
/// datagram the link is holding — so what the trace measures is the link's own delay, and the
/// step is how coarsely the case ticks that delay.
async fn drive_in(
    sim: &Sim,
    budget: Duration,
    step: Duration,
    transfer: &Transfer,
) -> Result<TransferState, String> {
    let mut spent = Duration::ZERO;
    let mut quiet = 0usize;
    let mut last = moved(transfer);
    loop {
        if transfer.state().is_over() {
            return Ok(transfer.state());
        }
        if spent >= budget {
            return Err(format!(
                "the transfer did not end within {budget:?} of virtual time: it reads `{:?}`",
                transfer.state()
            ));
        }
        tokio::task::yield_now().await;
        let now = moved(transfer);
        if now > last {
            last = now;
            quiet = 0;
            continue;
        }
        quiet += 1;
        if quiet >= QUIET {
            quiet = 0;
            sim.clock().advance(step).await;
            spent += step;
        }
    }
}

/// The receiving machine's view of the transfer under `name` from `peer`.
fn incoming_state(duo: &Duo, name: &TransferName) -> Result<Option<TransferState>, String> {
    let incoming = duo.arriving.transfers()?.incoming(&duo.sender.peer_id());
    Ok(incoming
        .into_iter()
        .find(|each| &each.name == name)
        .map(|each| each.state))
}

/// A whole file offered over the pair's connection arrives at the receiving machine's
/// sink byte for byte.
///
/// The bytes are the source's own function of the offset, so the sink's SHA-256 matching
/// the one the sender offered is the file arriving whole and unchanged: the crate asks the
/// sink what it assembled only once every byte is in, and answers the sender `complete`
/// only when that digest is the offered one.
pub(crate) fn a_file_arrives_byte_exact() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        // "Put files on me", granted by the receiving machine's own person to the pair the
        // sending machine's connection belongs to.
        allow_files(&duo)?;
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let transfer = offer(&duo, &file)?;
        let state = drive_transfer(&sim, BUDGET, &transfer).await?;
        ended(state, TransferState::Finished { bytes: FILE_BYTES })?;
        let name = file.name();
        let from = duo.sender.peer_id();
        if !hashing.finished(&from, name) {
            return Err("the sink was never asked what it assembled".to_owned());
        }
        if hashing.held_bytes(&from, name) != FILE_BYTES {
            return Err(format!(
                "the sink holds {} bytes of a {FILE_BYTES}-byte file",
                hashing.held_bytes(&from, name)
            ));
        }
        let assembled = hashing
            .assembled(&from, name)
            .ok_or("the sink assembled nothing")?;
        if assembled != file.digest() {
            return Err(format!(
                "the sink assembled {assembled} but the source offered {}",
                file.digest()
            ));
        }
        Ok(())
    })
}

/// A file is not a message: the queue, the delivery sink and the message window are the
/// message layer's, and a transfer touches none of them.
///
/// The receiving machine's queue for the sender is empty after the file arrived and its
/// caller was handed nothing; the sending machine never queued the file either; and a
/// message composed afterwards still arrives, so the transfer took no window from it.
pub(crate) fn a_transfer_is_not_a_message() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let transfer = offer(&duo, &file)?;
        let state = drive_transfer(&sim, BUDGET, &transfer).await?;
        ended(state, TransferState::Finished { bytes: FILE_BYTES })?;
        let (from, to) = (duo.sender.peer_id(), duo.receiver.peer_id());
        let queued = duo
            .arriving
            .messages
            .pending(&from)
            .map_err(|error| error.to_string())?;
        if !queued.is_empty() {
            return Err(format!(
                "the receiving machine's queue holds {} messages after a transfer",
                queued.len()
            ));
        }
        if !duo.arriving.collected.is_empty() {
            return Err(format!(
                "the receiving machine was handed {} messages by a transfer",
                duo.arriving.collected.len()
            ));
        }
        let sent = duo
            .sending
            .messages
            .pending(&to)
            .map_err(|error| error.to_string())?;
        if !sent.is_empty() {
            return Err(format!(
                "the sending machine's queue holds {} entries after offering a file",
                sent.len()
            ));
        }
        // The message window is the message layer's own: a word composed now still arrives.
        duo.sending
            .messages
            .send(&to, NOW, b"a word after the file")
            .map_err(|error| error.to_string())?;
        let delivered = wait_for(&sim, &duo.arriving.collected, 1, BUDGET).await?;
        let first = delivered
            .first()
            .ok_or("no message arrived after the file")?;
        if first.body != b"a word after the file" {
            return Err("the message that arrived after the file was not the one sent".to_owned());
        }
        Ok(())
    })
}

/// An older peer answers a transfer offer in the only vocabulary it has.
///
/// A machine whose inbox has no transfer layer hands every frame it does not recognise to
/// the message layer, which answers `unreadable`; a machine whose message window is used up
/// answers `throttled`. Neither is a transfer answer, so the sender ends `not understood` —
/// never refused at a step, never the receiving machine's store failing — and neither
/// answer is taken for a message that arrived.
pub(crate) fn an_older_peer_answers_in_the_message_vocabulary() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        // The receiving machine has no transfer layer at all, which is what an older peer is.
        let duo = duo(&sim, &beacon, Files::sending(), Files::older()).await?;
        allow_files(&duo)?;
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let transfer = offer(&duo, &file)?;
        // The message layer reads the offer under its own budget and answers `unreadable`.
        let state = drive_transfer_in(&sim, BUDGET, Duration::from_secs(1), &transfer).await?;
        failed(state, TransferFailure::NotUnderstood)?;
        if !duo.arriving.collected.is_empty() {
            return Err(format!(
                "the receiving machine was handed {} messages by a frame it could not read",
                duo.arriving.collected.len()
            ));
        }
        // Second half: the same machine with its message window used up answers `throttled`,
        // the other word of the same vocabulary, and the sender's answer does not change.
        let connection = wait_live(
            &sim,
            &duo.sending.managed.connections,
            &duo.receiver.peer_id(),
        )
        .await?;
        for _ in 0..MAX_OFFERS_PER_WINDOW {
            offer_frame(&connection, b"not a message this build reads", ANSWER_BYTES).await?;
        }
        // The next frame meets the used-up window, and the answer says so.
        let answer = within(
            &sim,
            BUDGET,
            offer_frame(&connection, b"not a message this build reads", ANSWER_BYTES),
        )
        .await??;
        match Answer::decode(&answer) {
            Ok(Answer::Throttled { .. }) => {}
            other => {
                return Err(format!(
                    "the receiving machine answered a frame over its window `{other:?}`, not \
                     throttled"
                ));
            }
        }
        let again = offer(&duo, &file)?;
        let state = drive_transfer(&sim, BUDGET, &again).await?;
        failed(state, TransferFailure::NotUnderstood)
    })
}

/// A transfer interrupted by a lost connection resumes where the receiver stopped.
///
/// The pair's connection goes away in the middle of the file, and the transfer waits for it
/// rather than failing — and it keeps waiting past the stall bound, because that bound is about
/// a live connection that stopped moving bytes and not about a pair that is still gone: with
/// nothing delivered to the receiving machine the clock passes the bound and the transfer still
/// reads `waiting`. The receiving machine states the offset it holds on the next offer, the
/// sender continues from there, and the sink — whose own write refuses a gap or a repeat — holds
/// exactly the file's bytes, in order, one write a chunk: nothing was sent twice.
pub(crate) fn a_transfer_resumes_after_a_reconnect() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let holding = Store::holding();
        let sink: Arc<dyn Sink + Send + Sync> = holding.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        let file = Generated::new(FILE_NAME, LONG_BYTES);
        let name = file.name().clone();
        let from = duo.sender.peer_id();
        // One write and no more, so the connection goes away in the middle of the file
        // rather than racing the receiving task to its end.
        holding.accept_burst(1);
        let transfer = offer(&duo, &file)?;
        advance_until(&sim, BUDGET, Duration::from_millis(10), || {
            holding.held_bytes(&from, &name) > 0
        })
        .await
        .map_err(|why| {
            format!(
                "{why}: the sink holds {} bytes and the transfer reads `{:?}`",
                holding.held_bytes(&from, &name),
                transfer.state()
            )
        })?;
        // The pair is silenced first and closed second, so no dial can bring it back: with the
        // link still up the transfer would re-dial at once, find a connection that carries
        // nothing, and end `no progress` at the stall bound — which is what a live connection
        // that stops moving is, and not the wait this case is about.
        sim.link().silence(duo.receiver.addr());
        if !duo
            .sending
            .managed
            .connections
            .disconnect(&duo.receiver.peer_id())
        {
            return Err("the pair had no live connection to close".to_owned());
        }
        advance_until(&sim, BUDGET, Duration::from_millis(100), || {
            transfer.state() == TransferState::Waiting
        })
        .await
        .map_err(|why| format!("{why}: the transfer reads `{:?}`", transfer.state()))?;
        let held_at_break = holding.held_bytes(&from, &name);
        let writes_at_break = holding.writes();
        // Nothing is delivered to the receiving machine, so no connection can be made, and the
        // clock passes the stall bound with the pair still gone: the transfer keeps waiting,
        // because that bound is about a connection that stopped moving and not about a pair that
        // has not come back.
        sim.clock()
            .advance(TRANSFER_STALL + Duration::from_secs(10))
            .await;
        if transfer.state() != TransferState::Waiting {
            return Err(format!(
                "the transfer reads `{:?}` after {:?} with no pair, not waiting",
                transfer.state(),
                TRANSFER_STALL + Duration::from_secs(10)
            ));
        }
        sim.link().resume(duo.receiver.addr());
        // The receiving machine's sink takes bytes again, the pair comes back — the transfer
        // dials by itself and the receiving machine's own service adopts the connection — and
        // the receiver states the offset it holds.
        holding.accept_burst(usize::MAX);
        let state = drive_transfer_in(&sim, BUDGET, Duration::from_secs(1), &transfer).await?;
        ended(state, TransferState::Finished { bytes: LONG_BYTES })?;
        // The sink holds exactly the file's bytes, in order: its own write refuses a gap or a
        // repeat, so a byte sent twice is a byte out of place and fails the case.
        let held = holding.bytes(&from, &name);
        if held != file.bytes(0, usize::try_from(LONG_BYTES).expect("half a mebibyte")) {
            return Err(format!(
                "the sink holds {} bytes of a {LONG_BYTES}-byte file, and not the file's bytes",
                held.len()
            ));
        }
        if held_at_break == 0 || held_at_break >= LONG_BYTES {
            return Err(format!(
                "the connection went away with {held_at_break} of {LONG_BYTES} bytes held: the \
                 case did not interrupt a transfer in the middle"
            ));
        }
        if holding.writes() <= writes_at_break {
            return Err(format!(
                "the sink was written {} times, which is no more than the {} it took before the \
                 pair came back: the resume wrote nothing",
                holding.writes(),
                writes_at_break
            ));
        }
        Ok(())
    })
}

/// Neither machine keeps a transfer across a restart: the file offered again lands from the
/// offset the receiving product's own sink states.
///
/// The receiving sink takes one write and then stops taking bytes, so the transfer stops
/// moving and ends at the stall bound — a task that still held the pair's connection would
/// keep the old socket alive, and a machine that is going down waits for nothing else. Both
/// machines then go down and come back over their own roots: same keys, same records, no
/// transfer in memory. A layer opened afresh over the receiving root and the same sink has no
/// incoming transfer at all, while the sink itself still holds the bytes it took. The sending
/// machine offers the same file again — same name, same length, same digest — and the
/// transfer resumes from the offset that sink states: the sink, whose own write refuses a gap
/// or a repeat, ends up holding exactly the file's bytes, in order, and was written again.
pub(crate) fn a_restart_forgets_the_transfer_and_the_product_offers_again() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let holding = Store::holding();
        let sink: Arc<dyn Sink + Send + Sync> = holding.clone();
        let file = Generated::new(FILE_NAME, LONG_BYTES);
        let name = file.name().clone();
        // One write and no more: the receiving product stops taking bytes in the middle of
        // the file rather than racing the receiving task to its end.
        holding.accept_burst(1);
        let duo = duo(
            &sim,
            &beacon,
            Files::sending(),
            Files::taking(Arc::clone(&sink)),
        )
        .await?;
        allow_files(&duo)?;
        let (from, to) = (duo.sender.peer_id(), duo.receiver.peer_id());
        let transfer = offer(&duo, &file)?;
        advance_until(&sim, BUDGET, Duration::from_millis(10), || {
            holding.held_bytes(&from, &name) > 0
        })
        .await
        .map_err(|why| {
            format!(
                "{why}: the sink holds {} bytes and the transfer reads `{:?}`",
                holding.held_bytes(&from, &name),
                transfer.state()
            )
        })?;
        // The transfer stops moving. The sending task ends at the first bound it meets; the
        // receiving one, whose stream the sending machine's re-offer meets, only at the
        // store's stall bound, so the bound is crossed here. Each holds the pair's
        // connection, and the restart below needs the last holder of the old socket gone.
        drive_transfer_in(
            &sim,
            TRANSFER_STALL + Duration::from_secs(30),
            Duration::from_secs(5),
            &transfer,
        )
        .await?;
        sim.clock().advance(TRANSFER_STALL).await;
        let held_at_restart = holding.held_bytes(&from, &name);
        if held_at_restart == 0 || held_at_restart >= LONG_BYTES {
            return Err(format!(
                "the machines went down holding {held_at_restart} of {LONG_BYTES} bytes: the \
                 case did not interrupt a transfer in the middle"
            ));
        }
        // Every handle that keeps a socket alive goes: the manager, its accept loop, the
        // service task and the transfer layer. The two layers are bound and dropped by name
        // because the rest of a partially moved struct lives to the end of the block, which
        // is exactly what the restart below cannot have. The `Transfer` handle kept from the
        // first life holds no socket.
        let Duo {
            mut sender,
            mut receiver,
            sending,
            arriving,
            ..
        } = duo;
        drop(sending);
        drop(arriving);
        sender
            .restart()
            .await
            .map_err(|error| format!("the sending machine: {error}"))?;
        receiver
            .restart()
            .await
            .map_err(|error| format!("the receiving machine: {error}"))?;
        // A layer opened afresh over the receiving machine's own root and the same sink knows
        // nothing of the transfer: the crate kept no transfer state across the restart, and
        // what the sink holds is the product's alone.
        {
            let floor: Arc<dyn Floor + Send + Sync> = Arc::new(NoFloor);
            let moment: Arc<dyn Moment + Send + Sync> =
                Arc::new(SimMoment::new(sim.clock().clone(), NOW));
            let forgotten = receiver.transfers(floor, moment, Some(Arc::clone(&sink)))?;
            let incoming = forgotten.incoming(&from);
            if !incoming.is_empty() {
                return Err(format!(
                    "the receiving machine's fresh layer still holds {} incoming transfer(s) \
                     after the restart",
                    incoming.len()
                ));
            }
        }
        if holding.held_bytes(&from, &name) != held_at_restart {
            return Err(format!(
                "the restart changed what the sink holds: {held_at_restart} bytes before it, \
                 {} after",
                holding.held_bytes(&from, &name)
            ));
        }
        // The machines' layers are rebuilt over the same roots and the same sink, the
        // receiving one makes itself findable again, and the sending one's manager finds it
        // and adopts the connection.
        let _found = keep_findable(&sim, &beacon, &receiver).await?;
        let sending = wired(
            &sim,
            &beacon,
            &sender,
            &receiver,
            Files::sending(),
            Arc::new(NoFloor),
        )?;
        let arriving = wired(
            &sim,
            &beacon,
            &receiver,
            &sender,
            Files::taking(Arc::clone(&sink)),
            Arc::new(NoFloor),
        )?;
        within(
            &sim,
            BUDGET,
            sending
                .managed
                .connections
                .connect(&sending.managed.endpoint, &receiver.fingerprint()),
        )
        .await?
        .map_err(|error| error.to_string())?;
        wait_live(&sim, &sending.managed.connections, &to).await?;
        wait_live(&sim, &arriving.managed.connections, &from).await?;
        // The same file, offered again by a product that knows only what its own sink holds.
        let writes_before = holding.writes();
        holding.accept_burst(usize::MAX);
        let again = sending
            .transfers()?
            .send(
                &sending.managed.connections,
                &sending.managed.endpoint,
                &to,
                file.offering(),
            )
            .map_err(|error| error.to_string())?;
        let state = drive_transfer_in(&sim, BUDGET, Duration::from_secs(1), &again).await?;
        ended(state, TransferState::Finished { bytes: LONG_BYTES })?;
        // The sink holds exactly the file's bytes, in order: its own write refuses a gap or a
        // repeat, so a byte sent twice is a byte out of place and fails the case.
        let held = holding.bytes(&from, &name);
        if held != file.bytes(0, usize::try_from(LONG_BYTES).expect("half a mebibyte")) {
            return Err(format!(
                "the sink holds {} bytes of a {LONG_BYTES}-byte file, and not the file's bytes",
                held.len()
            ));
        }
        if holding.writes() <= writes_before {
            return Err(format!(
                "the sink was written {} times, which is no more than the {writes_before} it \
                 took before the second offer: the resume wrote nothing",
                holding.writes()
            ));
        }
        Ok(())
    })
}

/// A transfer that stops moving bytes on a live connection is abandoned.
///
/// The source answers "not now" for every read, so the connection is up and nothing moves:
/// the bound is on no progress, and the transfer ends naming it rather than waiting for a
/// file that will never come. Both machines say the same thing, because the bound is about the
/// connection and not about the sender: the sending machine's handle and the receiving machine's
/// own view of the transfer it is taking both read `no progress`, and the receiving machine's
/// view is not `waiting`, which is a pair that went away.
pub(crate) fn a_stalled_transfer_is_abandoned() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let name = file.name().clone();
        file.stall_reads(usize::MAX);
        let transfer = offer(&duo, &file)?;
        // The bound is on no progress, so the case crosses it.
        let state = drive_transfer_in(
            &sim,
            TRANSFER_STALL + Duration::from_secs(30),
            Duration::from_secs(5),
            &transfer,
        )
        .await?;
        failed(state, TransferFailure::NoProgress)?;
        let arriving = incoming_state(&duo, &name)?;
        if arriving
            != Some(TransferState::Failed {
                failure: TransferFailure::NoProgress,
            })
        {
            return Err(format!(
                "the receiving machine reads `{arriving:?}` of a transfer that stopped moving \
                 on a live connection, not `no progress`"
            ));
        }
        Ok(())
    })
}

/// A receiving-side transfer that is dead is shown as dead, and is no longer stoppable.
///
/// The offer is authorised and the sink stops taking bytes, so the transfer is running; the
/// connection then goes away, and the transfer waits for the pair like any other. When the wait
/// bound passes with the sender still gone, the receiving machine reports it as `no pair` — one
/// expiry decides that, and the product's view never goes from failed to absent — and a stop of
/// it is answered `false`, because there is nothing left to stop.
pub(crate) fn a_dead_receiving_transfer_stays_visible_as_failed() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        let file = Generated::new(FILE_NAME, LONG_BYTES);
        let name = file.name().clone();
        // A source that answers "not now" before every chunk keeps the transfer moving for as
        // long as the case needs, with the receiving machine's reader waiting on the next one.
        file.stall_every(1);
        let transfer = offer(&duo, &file)?;
        advance_until(&sim, BUDGET, Duration::from_millis(100), || {
            moved(&transfer) > 0
                && matches!(
                    incoming_state(&duo, &name),
                    Ok(Some(TransferState::Running { moved, .. })) if moved > 0
                )
        })
        .await
        .map_err(|why| {
            format!(
                "{why}: the receiving machine reads `{:?}`",
                incoming_state(&duo, &name)
            )
        })?;
        // The receiving machine's side of the connection goes away, and its address stops
        // answering, so the sending machine cannot offer the file again: the transfer is left
        // waiting for a pair that never comes back.
        if !duo
            .arriving
            .managed
            .connections
            .disconnect(&duo.sender.peer_id())
        {
            return Err("the pair had no live connection to close".to_owned());
        }
        sim.link().silence(duo.receiver.addr());
        advance_until(&sim, BUDGET, Duration::from_millis(100), || {
            incoming_state(&duo, &name) == Ok(Some(TransferState::Waiting))
        })
        .await
        .map_err(|why| {
            format!(
                "{why}: the receiving machine reads `{:?}` of a transfer whose connection went \
                 away, not `waiting`",
                incoming_state(&duo, &name)
            )
        })?;
        // The sending side's product gives up on its own transfer, which is nothing to do with
        // the receiving machine's view: its task would otherwise spend the whole wait bound
        // dialling a peer that cannot answer.
        transfer.stop();
        advance_until(
            &sim,
            TRANSFER_WAIT + Duration::from_secs(60),
            Duration::from_secs(30),
            || {
                matches!(
                    incoming_state(&duo, &name),
                    Ok(Some(TransferState::Failed { .. }))
                )
            },
        )
        .await
        .map_err(|why| {
            format!(
                "{why}: the receiving machine reads `{:?}`",
                incoming_state(&duo, &name)
            )
        })?;
        let arriving = incoming_state(&duo, &name)?;
        let dead = Some(TransferState::Failed {
            failure: TransferFailure::NoPair,
        });
        if arriving != dead {
            return Err(format!(
                "the receiving machine reads `{arriving:?}` of a transfer whose sender never \
                 came back, not `no pair`"
            ));
        }
        if duo
            .arriving
            .transfers()?
            .stop_incoming(&duo.sender.peer_id(), &name)
        {
            return Err("the receiving machine let a dead transfer be stopped".to_owned());
        }
        Ok(())
    })
}

/// A stopped receiving transfer stays stopped until the wait bound passes.
///
/// The pair's connection goes away while the transfer is in flight, so the receiving machine's
/// entry reads `waiting`; its person stops it there. The link is resumed and the sender offers
/// again — a fresh offer under a stopped name is answered `stopped`, not authorised afresh —
/// so the sender ends `stopped by the receiver` and the sink was never handed a byte.
///
/// Before the receiver remembered a stop across the wait, the next offer was authorised afresh
/// and the file landed.
pub(crate) fn a_stopped_waiting_transfer_stays_stopped() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        let from = duo.sender.peer_id();
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let name = file.name().clone();
        // The source sends nothing yet, so the receiver is authorised with no byte stored and
        // its one read is parked on the connection — where the close reaches it.
        file.stall_reads(usize::MAX);
        let transfer = offer(&duo, &file)?;
        advance_until(&sim, BUDGET, Duration::from_millis(100), || {
            matches!(
                incoming_state(&duo, &name),
                Ok(Some(TransferState::Running { .. }))
            )
        })
        .await
        .map_err(|why| {
            format!(
                "{why}: the receiving machine reads `{:?}`",
                incoming_state(&duo, &name)
            )
        })?;
        // The receiving machine's address stops answering before its connection is closed, so
        // the keeper cannot make a fresh one the case then starves; the close still reaches the
        // sender, because it travels the other way.
        sim.link().silence(duo.receiver.addr());
        if !duo.arriving.managed.connections.disconnect(&from) {
            return Err("the pair had no live connection to close".to_owned());
        }
        advance_until(&sim, BUDGET, Duration::from_secs(5), || {
            incoming_state(&duo, &name) == Ok(Some(TransferState::Waiting))
        })
        .await
        .map_err(|why| {
            format!(
                "{why}: the receiving machine reads `{:?}` of a transfer whose connection went \
                 away, not `waiting`",
                incoming_state(&duo, &name)
            )
        })?;
        if !duo.arriving.transfers()?.stop_incoming(&from, &name) {
            return Err("the receiving machine let a waiting transfer be stopped".to_owned());
        }
        sim.link().resume(duo.receiver.addr());
        // The sender's source produces a byte again, so its next write meets the closed stream
        // and its next attempt is the offer that finds the name stopped.
        file.stall_reads(0);
        let state = drive_transfer_in(&sim, BUDGET * 3, Duration::from_secs(1), &transfer).await?;
        failed(state, TransferFailure::StoppedByReceiver)?;
        if hashing.held_bytes(&from, &name) != 0 {
            return Err(format!(
                "the sink holds {} bytes of a name the receiving machine stopped",
                hashing.held_bytes(&from, &name)
            ));
        }
        Ok(())
    })
}

/// A stopped transfer is visible to the product for the wait bound measured from the stop.
///
/// The transfer waits for its pair for a while before the receiving machine's person stops it, so
/// the last moment it was seen moving is already old. The stop is a moment of its own: the entry
/// stays visible for a whole `TRANSFER_WAIT` from it, rather than disappearing early because the
/// clock was left where the last chunk was.
pub(crate) fn a_stop_is_visible_from_the_stop() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        let from = duo.sender.peer_id();
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let name = file.name().clone();
        file.stall_reads(usize::MAX);
        let transfer = offer(&duo, &file)?;
        advance_until(&sim, BUDGET, Duration::from_millis(100), || {
            matches!(
                incoming_state(&duo, &name),
                Ok(Some(TransferState::Running { .. }))
            )
        })
        .await?;
        sim.link().silence(duo.receiver.addr());
        if !duo.arriving.managed.connections.disconnect(&from) {
            return Err("the pair had no live connection to close".to_owned());
        }
        // Long enough that the last moment this machine saw the transfer move is a third of a
        // wait bound old by the time the stop lands.
        sim.clock().advance(TRANSFER_WAIT / 3).await;
        if !duo.arriving.transfers()?.stop_incoming(&from, &name) {
            return Err("the receiving machine let a waiting transfer be stopped".to_owned());
        }
        // Past the wait bound from the last activity, and inside it from the stop.
        sim.clock().advance(TRANSFER_WAIT * 4 / 5).await;
        if incoming_state(&duo, &name) != Ok(Some(TransferState::Stopped)) {
            return Err(format!(
                "the receiving machine reads `{:?}` of a transfer it stopped, not `stopped`",
                incoming_state(&duo, &name)
            ));
        }
        transfer.stop();
        Ok(())
    })
}

/// A transfer whose pair never comes back ends, and names the pair rather than a refusal.
///
/// The receiving machine is paired and trusted, so the offer is one the record allows; but
/// there is no connection and no dial can reach the receiving machine, so the transfer waits
/// its own bound and then ends `no pair`.
pub(crate) fn a_transfer_without_a_pair_ends() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        // No connection is made, and the receiving machine's address is one nobody answers
        // on: the link drops every datagram aimed at it, as a machine that is gone does.
        let duo = wired_pair(&sim, &beacon, Files::sending(), Files::taking(sink))?;
        allow_files(&duo)?;
        sim.link().silence(duo.receiver.addr());
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let transfer = offer(&duo, &file)?;
        // The bound is on waiting for the pair, so the case crosses it.
        let state = drive_transfer_in(
            &sim,
            TRANSFER_WAIT + Duration::from_secs(60),
            Duration::from_secs(30),
            &transfer,
        )
        .await?;
        failed(state, TransferFailure::NoPair)
    })
}

/// A file the receiving machine already holds is not sent again.
///
/// The second offer names the same file — the same name, length and digest — and the
/// receiving machine answers that it is already complete there: the sender ends `finished`
/// and the sink is not written once more. Nothing was transferred, so nothing is recorded
/// either: an offer answered `already complete` leaves the receiving machine's log with the
/// same number of authorised-transfer entries it had before it.
pub(crate) fn an_already_complete_transfer_is_not_sent_again() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let first = offer(&duo, &file)?;
        ended(
            drive_transfer(&sim, BUDGET, &first).await?,
            TransferState::Finished { bytes: FILE_BYTES },
        )?;
        let writes = hashing.writes();
        let allowed = allowed_transfers(&duo.receiver)?;
        let again = offer(&duo, &file)?;
        ended(
            drive_transfer(&sim, BUDGET, &again).await?,
            TransferState::Finished { bytes: FILE_BYTES },
        )?;
        if hashing.writes() != writes {
            return Err(format!(
                "the sink was written {} times more for a file it already held",
                hashing.writes() - writes
            ));
        }
        let after = allowed_transfers(&duo.receiver)?;
        if after != allowed {
            return Err(format!(
                "the log holds {after} entries for an authorised transfer, and held {allowed} \
                 before one the receiving machine answered `already complete`"
            ));
        }
        Ok(())
    })
}

/// A name held with different content is a conflict, not a resume and not a failure to store.
///
/// The receiving machine holds every byte of one file under a name; an offer of another file
/// under that name is answered `conflict`, and what the sink holds is left exactly as it was.
pub(crate) fn a_name_held_with_different_content_is_a_conflict() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let holding = Store::holding();
        let sink: Arc<dyn Sink + Send + Sync> = holding.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        let from = duo.sender.peer_id();
        let held = Generated::new(FILE_NAME, FILE_BYTES);
        let name = held.name().clone();
        let first = offer(&duo, &held)?;
        ended(
            drive_transfer(&sim, BUDGET, &first).await?,
            TransferState::Finished { bytes: FILE_BYTES },
        )?;
        let before = holding.bytes(&from, &name);
        if before.len() != usize::try_from(FILE_BYTES).expect("four chunks") {
            return Err(format!(
                "the sink holds {} bytes after the first file arrived",
                before.len()
            ));
        }
        // The same name, different content: a longer file, so its digest differs too.
        let other = Generated::new(FILE_NAME, FILE_BYTES + CHUNK);
        let second = offer(&duo, &other)?;
        let state = drive_transfer(&sim, BUDGET, &second).await?;
        failed(state, TransferFailure::Conflict)?;
        if holding.bytes(&from, &name) != before {
            return Err("the sink's bytes changed under a name it already held".to_owned());
        }
        Ok(())
    })
}

/// A sink that holds part of a name but cannot name its digest is a conflict.
///
/// A name the sink holds bytes of is a name it was assembling toward one digest; without that
/// digest the crate cannot tell whether the next bytes belong after the ones already there, so
/// it appends none of them and answers `conflict`. The first transfer stores one chunk and
/// then refuses the next, which leaves the sink holding part of the name and the receiving
/// layer with no live transfer under it; the same file offered again is answered `conflict`
/// and the sink is handed no byte.
pub(crate) fn a_partial_name_with_no_digest_is_a_conflict() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let holding = Store::holding();
        let sink: Arc<dyn Sink + Send + Sync> = holding.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        let from = duo.sender.peer_id();
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let name = file.name().clone();
        // One chunk lands, and then the sink refuses: the transfer ends on the receiving side's
        // own failure, so the name is free for a fresh decision and the sink still holds part
        // of it.
        holding.accept_burst(1);
        let first = offer(&duo, &file)?;
        advance_until(&sim, BUDGET, Duration::from_millis(100), || {
            holding.held_bytes(&from, &name) > 0
        })
        .await
        .map_err(|why| format!("{why}: the sink holds no byte of the file"))?;
        holding.refuse();
        let state = drive_transfer(&sim, BUDGET, &first).await?;
        failed(state, TransferFailure::StoreFailed)?;
        let held = holding.held_bytes(&from, &name);
        if held == 0 || held >= FILE_BYTES {
            return Err(format!(
                "the sink holds {held} bytes of a {FILE_BYTES}-byte file, not part of it"
            ));
        }
        // The sink kept the bytes and lost the digest they were being assembled toward.
        holding.forget_toward();
        let writes = holding.writes();
        let again = Generated::new(FILE_NAME, FILE_BYTES);
        let second = offer(&duo, &again)?;
        let state = drive_transfer(&sim, BUDGET, &second).await?;
        failed(state, TransferFailure::Conflict)?;
        if holding.writes() != writes {
            return Err(format!(
                "the sink was written {} times for a name it holds part of with no digest",
                holding.writes() - writes
            ));
        }
        if holding.held_bytes(&from, &name) != held {
            return Err(format!(
                "the sink held {held} bytes and now holds {}",
                holding.held_bytes(&from, &name)
            ));
        }
        Ok(())
    })
}

/// A second offer of a name whose first stream is still being answered is answered `running`.
///
/// One stream per name: the receiving machine claims the name before it authorises anything, so
/// an offer that arrives while the first is still being answered is told the transfer is already
/// running there — the answer a product reads as "ask again later", and not a second
/// authorisation to write the same offsets of its sink. The answer states how many bytes the
/// receiver has stored, so a sender can tell a receiver that is still working from one that
/// stopped. The sink takes no write for the second offer and the receiving machine still holds
/// one incoming transfer under that name; the first transfer then finishes once the sink takes
/// bytes again, so the second offer disturbed nothing.
pub(crate) fn a_second_offer_of_a_running_name_is_answered_running() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let name = file.name().clone();
        // The sink takes one chunk and then answers "not now", so the first stream stays open
        // and its name stays claimed while the second offer is answered — and the offset that
        // answer states is the chunk the sink took.
        hashing.accept_burst(1);
        let transfer = offer(&duo, &file)?;
        let mut have = 0u64;
        advance_until(
            &sim,
            BUDGET,
            Duration::from_millis(100),
            || match incoming_state(&duo, &name) {
                Ok(Some(TransferState::Running { moved, .. })) if moved > 0 => {
                    have = moved;
                    true
                }
                _ => false,
            },
        )
        .await
        .map_err(|why| {
            format!(
                "{why}: the receiving machine reads `{:?}`",
                incoming_state(&duo, &name)
            )
        })?;
        // The same name, the same length and the same digest, offered by hand over the pair's own
        // connection while the first stream is still being answered.
        let connection = wait_live(
            &sim,
            &duo.sending.managed.connections,
            &duo.receiver.peer_id(),
        )
        .await?;
        let writes = hashing.writes();
        let bytes = offer_bytes(&name, FILE_BYTES, &file.digest());
        let answer = within(&sim, BUDGET, offer_frame(&connection, &bytes, ANSWER_BYTES)).await??;
        let fields = answer_fields(&answer)?;
        // Status 2 is `running`.
        if fields.status != 2 {
            return Err(format!(
                "a second offer of a name already being answered was answered with status {} \
                 rather than 2",
                fields.status
            ));
        }
        if fields.offset != Some(have) {
            return Err(format!(
                "a running answer stated {:?} bytes stored, and the receiving machine holds \
                 {have}",
                fields.offset
            ));
        }
        if hashing.writes() != writes {
            return Err(format!(
                "the sink was written {} times for an offer of a name already being answered",
                hashing.writes() - writes
            ));
        }
        let incoming = duo.arriving.transfers()?.incoming(&duo.sender.peer_id());
        let held = incoming.iter().filter(|each| each.name == name).count();
        if held != 1 {
            return Err(format!(
                "the receiving machine holds {held} transfers under `{name}` after a second \
                 offer of it"
            ));
        }
        // The sink takes bytes again and the first transfer finishes: the second offer took
        // nothing from it.
        hashing.accept_burst(usize::MAX);
        let state = drive_transfer(&sim, BUDGET, &transfer).await?;
        ended(state, TransferState::Finished { bytes: FILE_BYTES })
    })
}

/// A file whose content does not match the digest it was offered with is never complete.
///
/// The sink holds every byte and one of them is damaged, so the digest it assembled is not
/// the one the sender offered — including the part that was already there. The receiving
/// machine answers a digest mismatch, and the sender is never told the file arrived.
pub(crate) fn a_digest_mismatch_is_never_complete() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let holding = Store::holding();
        let sink: Arc<dyn Sink + Send + Sync> = holding.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        let from = duo.sender.peer_id();
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let name = file.name().clone();
        let first = offer(&duo, &file)?;
        ended(
            drive_transfer(&sim, BUDGET, &first).await?,
            TransferState::Finished { bytes: FILE_BYTES },
        )?;
        // One byte of a file the sink holds whole is damaged, and the same file is offered
        // again: every byte is there and the content is not the one the digest names.
        holding.corrupt(&from, &name, 3);
        let again = offer(&duo, &file)?;
        let state = drive_transfer(&sim, BUDGET, &again).await?;
        if state == (TransferState::Finished { bytes: FILE_BYTES }) {
            return Err("a damaged file was answered complete".to_owned());
        }
        failed(state, TransferFailure::DigestMismatch)?;
        // The sink holds every byte of the name, toward the digest the sender names, and cannot
        // say what it assembled. The crate has no evidence either way, so the offer is answered
        // "the receiver could not store it" and never "the digest does not match".
        holding.cannot_answer();
        let third = offer(&duo, &file)?;
        let state = drive_transfer(&sim, BUDGET, &third).await?;
        if state == (TransferState::Finished { bytes: FILE_BYTES }) {
            return Err("a file a sink could not answer for was answered complete".to_owned());
        }
        failed(state, TransferFailure::StoreFailed)
    })
}

/// The receiving machine states what it holds only after the transfer is authorised.
///
/// A peer with no "put files on me" right is refused at the right step, and the sink behind
/// that right is never asked what it holds: a peer that may not send learns nothing about
/// what this machine already has.
pub(crate) fn the_receiver_states_its_offset_only_after_the_right() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        // Bound both ways, so the pair exists and only the capability is missing.
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let transfer = offer(&duo, &file)?;
        let state = drive_transfer(&sim, BUDGET, &transfer).await?;
        failed(state, TransferFailure::Refused { step: Step::Right })?;
        if hashing.held_asks() != 0 {
            return Err(format!(
                "the sink was asked what it holds {} times for a transfer that was refused",
                hashing.held_asks()
            ));
        }
        if hashing.writes() != 0 {
            return Err(format!(
                "the sink was written {} times for a transfer that was refused",
                hashing.writes()
            ));
        }
        Ok(())
    })
}

/// A right withdrawn while a transfer runs ends future transfers, not this one.
///
/// The decision is made once, when the transfer is authorised, and holds for its whole life;
/// a second offer after the withdrawal is refused at the right step.
pub(crate) fn a_withdrawn_right_does_not_stop_a_running_transfer() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        // The sink takes nothing yet, so the transfer is still running when the right goes.
        hashing.stop_accepting();
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let transfer = offer(&duo, &file)?;
        advance_until(&sim, BUDGET, Duration::from_millis(100), || {
            matches!(transfer.state(), TransferState::Running { .. })
        })
        .await
        .map_err(|why| format!("{why}: the transfer reads `{:?}`", transfer.state()))?;
        duo.receiver
            .rights()?
            .withdraw(
                &pair(&duo.sender, &duo.assistant),
                Capability::PUT_FILES,
                person("the operator")?,
                NOW,
            )
            .map_err(|error| error.to_string())?;
        hashing.start_accepting();
        let state = drive_transfer(&sim, BUDGET, &transfer).await?;
        ended(state, TransferState::Finished { bytes: FILE_BYTES })?;
        // A new transfer is a new decision, and the right is gone.
        let other = Generated::new("another-report.pdf", FILE_BYTES);
        let next = offer(&duo, &other)?;
        let state = drive_transfer(&sim, BUDGET, &next).await?;
        failed(state, TransferFailure::Refused { step: Step::Right })
    })
}

/// A transfer authorised under one pair is not resumed under another.
///
/// The receiving machine is moved to a different assistant while the transfer waits for the
/// pair, and its person grants the same capability to the new pair, so the only thing that
/// changed is the pair the transfer was authorised under: the resume is refused at the right
/// step rather than continuing under a pair that inherits nothing. The receiving machine's own
/// view of the name ends with the refusal instead of staying running, and the name is free
/// again: offered under the pair the machine is bound to now, the same file is decided afresh
/// and lands.
pub(crate) fn a_moved_machine_refuses_the_resume() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        let file = Generated::new(FILE_NAME, LONG_BYTES);
        let name = file.name().clone();
        let from = duo.sender.peer_id();
        hashing.accept_burst(1);
        let transfer = offer(&duo, &file)?;
        advance_until(&sim, BUDGET, Duration::from_millis(10), || {
            hashing.held_bytes(&from, &name) > 0
        })
        .await
        .map_err(|why| {
            format!(
                "{why}: the sink holds {} bytes and the transfer reads `{:?}`",
                hashing.held_bytes(&from, &name),
                transfer.state()
            )
        })?;
        if !duo
            .sending
            .managed
            .connections
            .disconnect(&duo.receiver.peer_id())
        {
            return Err("the pair had no live connection to close".to_owned());
        }
        // The receiving machine now belongs to another assistant, and its person grants the
        // same capability to the pair that makes: only the pair the transfer was authorised
        // under is gone.
        let moved = label("another-assistant")?;
        duo.receiver
            .rights()?
            .bind(
                &duo.sender.peer_id(),
                binding("second-account", "second-instance", &moved)?,
                NOW,
            )
            .map_err(|error| error.to_string())?;
        duo.receiver
            .rights()?
            .grant(
                &pair(&duo.sender, &moved),
                Capability::PUT_FILES,
                Authority::Person(person("the operator")?),
                None,
                NOW,
            )
            .map_err(|error| error.to_string())?;
        hashing.accept_burst(usize::MAX);
        let state = drive_transfer_in(&sim, BUDGET, Duration::from_secs(1), &transfer).await?;
        failed(state, TransferFailure::Refused { step: Step::Right })?;
        // The refusal ends the receiving machine's own view of the name: it is terminal, and
        // specifically not left running — or quietly waiting — for the ten minutes the pair's
        // bound allows.
        let refused = Some(TransferState::Failed {
            failure: TransferFailure::Refused { step: Step::Right },
        });
        let arriving = incoming_state(&duo, &name)?;
        if arriving != refused {
            return Err(format!(
                "the receiving machine reads `{arriving:?}` of a resume it refused, not a \
                 refused transfer"
            ));
        }
        // The name is free again for a fresh decision: the machine is bound to the sender under
        // the assistant it moved to, and its person granted "put files on me" to that pair
        // above, so the same file offered again is decided anew and lands.
        let again = offer(&duo, &file)?;
        let state = drive_transfer_in(&sim, BUDGET, Duration::from_secs(1), &again).await?;
        ended(state, TransferState::Finished { bytes: LONG_BYTES })?;
        if hashing.held_bytes(&from, &name) != LONG_BYTES {
            return Err(format!(
                "the sink holds {} bytes of a {LONG_BYTES}-byte file after the refused name was \
                 offered again",
                hashing.held_bytes(&from, &name)
            ));
        }
        Ok(())
    })
}

/// Trust withdrawn in a peer ends the transfer, and the answer names the trust.
///
/// The withdrawal closes the pair's live connection and is on disk, so the transfer's next
/// look at the record ends it — rather than waiting out the pair's whole bound for a
/// connection this machine will never make.
pub(crate) fn a_withdrawn_trust_ends_the_transfer() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        hashing.stop_accepting();
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let transfer = offer(&duo, &file)?;
        advance_until(&sim, BUDGET, Duration::from_millis(100), || {
            matches!(transfer.state(), TransferState::Running { .. })
        })
        .await
        .map_err(|why| format!("{why}: the transfer reads `{:?}`", transfer.state()))?;
        duo.sender
            .rights()?
            .withdraw_trust(&duo.receiver.peer_id(), person("the operator")?, NOW)
            .map_err(|error| error.to_string())?;
        duo.sending
            .managed
            .connections
            .disconnect(&duo.receiver.peer_id());
        let state = drive_transfer(&sim, BUDGET, &transfer).await?;
        failed(state, TransferFailure::TrustWithdrawn)
    })
}

/// A product stops its own transfer, and each side learns an answer rather than an error.
///
/// The sending machine's person stops a running transfer: the receiver reads the sending
/// side's reset as its own word and ends `stopped`. The receiving machine's person stops one
/// it is taking: the sender is answered `stopped by the receiver`. The same holds when the
/// receiving machine's sink is answering "not now": the stop is honoured inside that retry
/// loop, so the sender learns `stopped by the receiver` and not the store's own failure, which
/// is the answer for a product that cannot write rather than for one that was told to stop.
pub(crate) fn a_product_stops_its_own_transfer() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        // First half: the sending side stops a transfer that is still reading its source, so
        // the receiver has the transfer and no bytes.
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let name = file.name().clone();
        file.stall_reads(usize::MAX);
        let transfer = offer(&duo, &file)?;
        advance_until(&sim, BUDGET, Duration::from_millis(100), || {
            matches!(
                incoming_state(&duo, &name),
                Ok(Some(TransferState::Running { .. }))
            )
        })
        .await
        .map_err(|why| {
            format!(
                "{why}: the receiving machine reads `{:?}`",
                incoming_state(&duo, &name)
            )
        })?;
        transfer.stop();
        advance_until(&sim, BUDGET, Duration::from_millis(100), || {
            incoming_state(&duo, &name) == Ok(Some(TransferState::Stopped))
        })
        .await
        .map_err(|why| {
            format!(
                "{why}: the receiving machine reads `{:?}`",
                incoming_state(&duo, &name)
            )
        })?;
        if transfer.state() != TransferState::Stopped {
            return Err(format!(
                "the sending side's own handle reads `{:?}`, not stopped",
                transfer.state()
            ));
        }
        // Second half: the receiving machine's person stops a transfer it is taking, while
        // the sink holds the first chunk back so the stop lands between two chunks.
        let second = Generated::new("a-second-report.pdf", FILE_BYTES);
        let second_name = second.name().clone();
        hashing.stop_accepting();
        let transfer = offer(&duo, &second)?;
        advance_until(&sim, BUDGET, Duration::from_millis(100), || {
            matches!(transfer.state(), TransferState::Running { .. })
        })
        .await
        .map_err(|why| format!("{why}: the transfer reads `{:?}`", transfer.state()))?;
        if !duo
            .arriving
            .transfers()?
            .stop_incoming(&duo.sender.peer_id(), &second_name)
        {
            return Err("the receiving machine had no running transfer to stop".to_owned());
        }
        hashing.start_accepting();
        let state = drive_transfer(&sim, BUDGET, &transfer).await?;
        failed(state, TransferFailure::StoppedByReceiver)?;
        // Third part: the sink is the thing answering "not now" when the receiving machine's
        // person stops the transfer, and the stop is honoured inside that retry loop.
        let third = Generated::new("a-third-report.pdf", FILE_BYTES);
        let third_name = third.name().clone();
        hashing.stop_accepting();
        let transfer = offer(&duo, &third)?;
        advance_until(&sim, BUDGET, Duration::from_millis(100), || {
            matches!(transfer.state(), TransferState::Running { .. })
        })
        .await
        .map_err(|why| format!("{why}: the transfer reads `{:?}`", transfer.state()))?;
        if !duo
            .arriving
            .transfers()?
            .stop_incoming(&duo.sender.peer_id(), &third_name)
        {
            return Err("the receiving machine had no running transfer to stop".to_owned());
        }
        // The sink is left answering "not now": the stop is what ends the transfer, not the
        // store giving up on it.
        let state = drive_transfer(&sim, BUDGET, &transfer).await?;
        failed(state, TransferFailure::StoppedByReceiver)?;
        // Fourth part: the name the *sending* side stopped is not the receiving person's to keep
        // stopped. The same file offered again is a fresh transfer that lands — never
        // `StoppedByReceiver`, which is a decision the receiving person never made.
        hashing.start_accepting();
        let again = Generated::new(FILE_NAME, FILE_BYTES);
        let transfer = offer(&duo, &again)?;
        let state = drive_transfer(&sim, BUDGET, &transfer).await?;
        ended(state, TransferState::Finished { bytes: FILE_BYTES })
    })
}

/// A stop that lands while the transport is not taking bytes is a stop, and it is final.
///
/// The sink answers "not now" for ever, so the sender's writes fill the stream's window and the
/// write after them parks for the whole stall bound. The sending machine's own person stops the
/// transfer there: the handle stays `Stopped` — a stall this machine already ended is not this
/// machine's own `no progress`, and the task's own ending must not put it back on its feet —
/// and the stream is reset with the stop code rather than dropped, which is what the receiving
/// machine reads as "the sending side stopped it" wherever it is not itself at its own bound.
///
/// The receiving machine's own view here is its own answer: its stall bound is anchored at or
/// before the sending side's, so it gives up on its sink first, and the reset arrives with
/// nothing left for it to say. The sibling case is where a receiving side reads that reset.
pub(crate) fn a_stop_during_a_stalled_write_is_stopped() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        // One chunk past one stream's window: the sender's writes fill the window and the write
        // after them is the one that parks.
        let file = Generated::new(FILE_NAME, PAST_A_WINDOW);
        hashing.stop_accepting();
        let transfer = offer(&duo, &file)?;
        advance_until(&sim, BUDGET, Duration::from_millis(100), || {
            matches!(transfer.state(), TransferState::Running { .. })
        })
        .await
        .map_err(|why| format!("{why}: the transfer reads `{:?}`", transfer.state()))?;
        transfer.stop();
        ended(transfer.state(), TransferState::Stopped)?;
        // The stop is the product's word on the handle at once, and the task's own ending must
        // not put it back on its feet: the write times out `TRANSFER_STALL` later and the task
        // ends there, with the handle still `stopped` and not `no progress`.
        let state = drive_transfer_in(
            &sim,
            TRANSFER_STALL + Duration::from_secs(30),
            Duration::from_secs(5),
            &transfer,
        )
        .await?;
        ended(state, TransferState::Stopped)?;
        ended(transfer.state(), TransferState::Stopped)?;
        // The bytes never reached the sink: the transfer moved them into the transport and the
        // product ended it there.
        if hashing.writes() != 0 {
            return Err(format!(
                "the sink was written {} times for a transfer whose product stopped it before a \
                 byte was stored",
                hashing.writes()
            ));
        }
        Ok(())
    })
}

/// The receiving side learns the sending side's stop while its sink is answering "not now".
///
/// The sink takes one chunk and then nothing, so the receiving machine is left in its "not now"
/// loop holding a chunk it cannot store; the sending machine's product stops the transfer while
/// the sender is between two chunks, which is where it is noticed at once rather than at the
/// stall bound. The stop reaches the receiver as a reset, and a reset is only visible by
/// reading: the one look at the stream the receiver takes before it calls its own store the
/// cause is what turns the transfer into `stopped` instead of `store failed`.
pub(crate) fn a_receiver_learns_the_senders_stop_while_its_sink_says_not_now() -> Result<(), String>
{
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        let file = Generated::new(FILE_NAME, LONG_BYTES);
        let name = file.name().clone();
        let from = duo.sender.peer_id();
        // One chunk in, then nothing: the sink never takes a second write.
        hashing.accept_burst(1);
        // A "not now" before every chunk, so the sender writes one chunk a second and the case
        // can stop it between two of them.
        file.stall_every(1);
        let transfer = offer(&duo, &file)?;
        // Two chunks on the wire: the first is stored, and the second is the one the receiver
        // holds while its sink refuses it.
        advance_until(&sim, BUDGET, Duration::from_millis(100), || {
            moved(&transfer) >= 2 * CHUNK
        })
        .await
        .map_err(|why| format!("{why}: the transfer reads `{:?}`", transfer.state()))?;
        // The source has nothing more to give, so the sender is between chunks: the stop is
        // noticed at its next look, not at the stall bound.
        file.stall_reads(usize::MAX);
        transfer.stop();
        ended(transfer.state(), TransferState::Stopped)?;
        advance_until(
            &sim,
            TRANSFER_STALL + Duration::from_secs(30),
            Duration::from_secs(5),
            || incoming_state(&duo, &name).is_ok_and(|state| state.is_some_and(|s| s.is_over())),
        )
        .await
        .map_err(|why| {
            format!(
                "{why}: the receiving machine reads `{:?}`",
                incoming_state(&duo, &name)
            )
        })?;
        let stored = hashing.held_bytes(&from, &name);
        if stored == 0 || stored >= LONG_BYTES {
            return Err(format!(
                "the sink holds {stored} bytes of a {LONG_BYTES}-byte transfer whose sink stopped \
                 taking bytes after its first write"
            ));
        }
        let arriving = incoming_state(&duo, &name)?;
        if arriving != Some(TransferState::Stopped) {
            return Err(format!(
                "the receiving machine reads `{arriving:?}` of a transfer the sending side \
                 stopped while its sink was answering \"not now\", not `stopped`"
            ));
        }
        Ok(())
    })
}

/// A zero-length file and a name no transfer may carry are refused here, not on the wire.
///
/// The sending machine refuses before anything is dialled or offered, so the receiving
/// machine's sink is never asked what it holds and never written.
pub(crate) fn a_zero_length_file_and_an_empty_name_are_refused_locally() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        let empty = Generated::new(FILE_NAME, 0);
        let refused = duo.sending.transfers()?.send(
            &duo.sending.managed.connections,
            &duo.sending.managed.endpoint,
            &duo.receiver.peer_id(),
            empty.offering(),
        );
        match refused {
            Err(TransferError::Empty) => {}
            Err(other) => {
                return Err(format!(
                    "a zero-length file was refused as `{other}`, not as empty"
                ));
            }
            Ok(_) => return Err("a zero-length file was offered".to_owned()),
        }
        let too_long = "a".repeat(mahbot_peers::peer::MAX_TRANSFER_NAME_BYTES + 1);
        for name in ["", too_long.as_str()] {
            if TransferName::new(name).is_ok() {
                return Err(format!(
                    "a name of {} bytes was taken for a transfer's name",
                    name.len()
                ));
            }
        }
        // Nothing reached the wire.
        if hashing.held_asks() != 0 || hashing.writes() != 0 {
            return Err(format!(
                "the receiving machine's sink was asked {} times and written {} times for a \
                 transfer refused before it was offered",
                hashing.held_asks(),
                hashing.writes()
            ));
        }
        if !duo
            .arriving
            .transfers()?
            .incoming(&duo.sender.peer_id())
            .is_empty()
        {
            return Err(
                "the receiving machine remembers a transfer that was never offered".to_owned(),
            );
        }
        Ok(())
    })
}

/// An offer this build cannot read is answered as one, and nothing lands in the sink.
///
/// The offers are written by hand, because the typed layer would never produce them: a name
/// with no bytes, a file of no length, a length shorter than what the sink already holds under
/// that name, a digest that contradicts the one it was assembling toward, and a frame whose
/// stream ends before the body it states. Each is answered for what it is — `malformed`, or
/// `conflict` for the one that names different content — and the sink is not written. The last
/// offer is the sending machine's own layer offering a shorter file under a name the sink
/// already holds whole, which no product's source would do: the sender learns `malformed` — the
/// receiving machine could not understand the offer — and not `not understood`, which is the
/// answer for a peer whose answer this build cannot read at all.
pub(crate) fn a_malformed_offer_is_answered_malformed() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let holding = Store::holding();
        let sink: Arc<dyn Sink + Send + Sync> = holding.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        // A whole file first, so the sink holds something under a name of its own: that is what
        // makes a shorter length and a different digest offers it can judge.
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let transfer = offer(&duo, &file)?;
        let state = drive_transfer(&sim, BUDGET, &transfer).await?;
        ended(state, TransferState::Finished { bytes: FILE_BYTES })?;
        let from = duo.sender.peer_id();
        let name = file.name().clone();
        let writes = holding.writes();
        let held = holding.held_bytes(&from, &name);
        if held != FILE_BYTES {
            return Err(format!(
                "the sink holds {held} bytes of a {FILE_BYTES}-byte file"
            ));
        }
        let connection = wait_live(
            &sim,
            &duo.sending.managed.connections,
            &duo.receiver.peer_id(),
        )
        .await?;
        // The same name with other content: a longer file, so it is the digest and not the
        // length that makes it a conflict.
        let other = Generated::new(FILE_NAME, FILE_BYTES + 4096);
        // A frame that says how long its body is and then stops short of it.
        let mut truncated = offer_fields(b"a-truncated-frame", FILE_BYTES, &file.digest());
        truncated.truncate(truncated.len() - 10);
        // Status 13 is `malformed` and status 6 is `conflict`.
        let offers: [(&str, Vec<u8>, u8); 5] = [
            (
                "an offer with an empty name",
                offer_fields(b"", FILE_BYTES, &file.digest()),
                13,
            ),
            (
                "an offer of no length",
                offer_fields(name.as_str().as_bytes(), 0, &file.digest()),
                13,
            ),
            (
                "an offer shorter than what the sink holds",
                offer_fields(name.as_str().as_bytes(), FILE_BYTES - 1, &file.digest()),
                13,
            ),
            (
                "an offer of other content under a held name",
                offer_fields(name.as_str().as_bytes(), FILE_BYTES + 4096, &other.digest()),
                6,
            ),
            ("an offer whose stream ends early", truncated, 13),
        ];
        for (what, bytes, want) in offers {
            let answer =
                within(&sim, BUDGET, offer_frame(&connection, &bytes, ANSWER_BYTES)).await??;
            let fields = answer_fields(&answer)?;
            if fields.status != want {
                return Err(format!(
                    "{what} was answered with status {} rather than {want}",
                    fields.status
                ));
            }
        }
        // Nothing was appended: the sink still holds the one file it was handed, and no offer
        // added a byte or a write to it.
        if holding.writes() != writes {
            return Err(format!(
                "the sink was written {} times for five offers it could not take, after {writes}",
                holding.writes()
            ));
        }
        if holding.held_bytes(&from, &name) != held {
            return Err(format!(
                "the sink holds {} bytes of `{name}` after five offers it could not take, not \
                 the {held} it held",
                holding.held_bytes(&from, &name)
            ));
        }
        // The same name from the sending machine's own layer, and a length shorter than what
        // the sink holds: a source that shrank since it was offered, which the receiving
        // machine answers as an offer it cannot understand rather than as an answer the sender
        // could not read.
        let shorter = Generated::new(FILE_NAME, FILE_BYTES - 4096);
        let transfer = offer(&duo, &shorter)?;
        let state = drive_transfer(&sim, BUDGET, &transfer).await?;
        failed(state, TransferFailure::Malformed)
    })
}

/// A dribbled frame does not hold a stream past the answer budget.
///
/// A peer writes an offer's header and one body byte, then one more byte every five virtual
/// seconds. The frame read is bounded as a whole, so the receiving machine answers `malformed`
/// long before the frame is complete, instead of re-arming its bound on every byte: a stream
/// slot the pair's messages and actions share is not held for as long as a peer cares to
/// dribble. The answer arriving while the frame is still unfinished is the whole of the proof,
/// and it is why the case states no budget of its own.
pub(crate) fn a_dribbled_frame_does_not_hold_a_stream() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let bytes = offer_bytes(file.name(), FILE_BYTES, &file.digest());
        let connection = wait_live(
            &sim,
            &duo.sending.managed.connections,
            &duo.receiver.peer_id(),
        )
        .await?;
        let opened = within(&sim, BUDGET, connection.open_bi())
            .await?
            .map_err(|error| error.to_string())?;
        let (mut send, mut recv) = opened;
        // The answer is read on its own task, so the case can dribble and move the clock while
        // it waits rather than parking on one read.
        let answer = Arc::new(Mutex::new(None));
        let slot = Arc::clone(&answer);
        let reader = tokio::spawn(async move {
            let bytes = recv.read_to_end(ANSWER_BYTES).await.unwrap_or_default();
            *slot.lock().expect("the answer slot is not poisoned") = Some(bytes);
        });
        // The offer's magic, version and body length, and one body byte.
        const HEADER: usize = 20 + 1 + 4;
        let mut written = HEADER + 1;
        send.write_all(&bytes[..written])
            .await
            .map_err(|error| format!("the stream took no offer: {error}"))?;
        // What the case proves is the *order*, not the crate's budget: the answer must arrive
        // while the frame is still being dribbled. A read bounded per read would wait for the
        // whole frame, which is a byte every five seconds — so the case's own patience is the
        // time that would take, and it stops the moment the answer lands.
        let patience = DRIBBLE * u32::try_from(bytes.len()).expect("a frame is short");
        let mut spent = Duration::ZERO;
        let got = loop {
            if let Some(bytes) = answer
                .lock()
                .expect("the answer slot is not poisoned")
                .clone()
            {
                break bytes;
            }
            if spent >= patience || written == bytes.len() {
                return Err(format!(
                    "a dribbled frame was not answered until the whole frame had arrived \
                     ({written} bytes written, {spent:?} spent)"
                ));
            }
            let _ = send.write_all(&bytes[written..=written]).await;
            written += 1;
            let _ = sim
                .clock()
                .advance_until(DRIBBLE, DRIBBLE, || {
                    answer
                        .lock()
                        .expect("the answer slot is not poisoned")
                        .is_some()
                })
                .await;
            spent += DRIBBLE;
        };
        reader.abort();
        let fields = answer_fields(&got)?;
        // Status 13 is `malformed`.
        if fields.status != 13 {
            return Err(format!(
                "a dribbled offer was answered with status {}, not 13",
                fields.status
            ));
        }
        Ok(())
    })
}

/// A limit on running transfers is terminal and carries no delay, whatever the frame says.
///
/// The frame names a wait beside it — a peer's own number, and one nothing acts on, because this
/// limit ends the transfer rather than pacing it. One answer means one thing: the sender ends
/// `limit { which: transfers }` with no delay to report, instead of waiting a number of seconds a
/// peer invented or telling its person to ask again in that many.
pub(crate) fn a_terminal_limit_carries_no_delay() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        // Status 5 is `limit`, 1 is the limit on running transfers, and 0x03 is a year of wait
        // beside it, which nothing may act on.
        let body = [
            field(0x01, &[5]),
            field(0x04, &[1]),
            field(0x03, &u32::MAX.to_be_bytes()),
        ]
        .concat();
        let raw = raw_pair(&sim, &beacon, vec![answer_frame(&body)]).await?;
        let (receiver, managed, transfers) = (&raw.receiver, &raw.managed, &raw.transfers);
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let transfer = transfers
            .send(
                &managed.connections,
                &managed.endpoint,
                &receiver.peer_id(),
                file.offering(),
            )
            .map_err(|error| error.to_string())?;
        let state = drive_transfer_in(&sim, BUDGET, Duration::from_millis(100), &transfer).await?;
        failed(
            state,
            TransferFailure::Limit {
                which: TransferLimit::Transfers,
                retry_after: None,
            },
        )
    })
}

/// An answer this build cannot read leaves the sender not understanding it, and nothing else.
///
/// The receiving side is a raw peer: it accepts the connection, answers the binding exchange,
/// and then answers each offer with a frame this build's receiver would never write — a status
/// of 200, which is no status this build has, and a body carrying no status field at all. The
/// sender ends `not understood` both times: never refused at a step, never the receiving
/// machine's store failing.
pub(crate) fn an_unknown_answer_status_is_not_understood() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let raw = raw_pair(
            &sim,
            &beacon,
            vec![
                answer_frame(&field(0x01, &[200])),
                // Status 10 is not one either: no build ever wrote it, and this one does not
                // read it, so it is a byte from a vocabulary this build cannot speak.
                answer_frame(&field(0x01, &[10])),
                answer_frame(&field(0x09, b"a body with no status field")),
            ],
        )
        .await?;
        let (receiver, managed, transfers) = (&raw.receiver, &raw.managed, &raw.transfers);
        for name in [
            "a-status-200.bin",
            "a-status-10.bin",
            "a-body-with-no-status.bin",
        ] {
            let file = Generated::new(name, FILE_BYTES);
            let transfer = transfers
                .send(
                    &managed.connections,
                    &managed.endpoint,
                    &receiver.peer_id(),
                    file.offering(),
                )
                .map_err(|error| error.to_string())?;
            let state = drive_transfer(&sim, BUDGET, &transfer).await?;
            failed(state, TransferFailure::NotUnderstood)?;
        }
        Ok(())
    })
}

/// A peer that answers `resume` and then throws every stream away is abandoned, not retried for
/// ever.
///
/// The raw receiving side says it holds nothing and will take the file from the start, then drops
/// each stream the moment the bytes begin: no byte ever lands there, and no answer ever says the
/// file got further. The sender's bound is on progress, so it ends `no progress` after the stall
/// bound — the attempt's own timing is not progress, and a peer cannot hold one of this machine's
/// places for the peer by answering `resume` and reading nothing.
///
/// With the sender crediting an attempt that produced no verdict, this never ends: the offset
/// never grows and every attempt looks like a fresh start.
pub(crate) fn a_peer_that_answers_resume_and_resets_is_abandoned() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        // Status 11 is `resume`, and 0x02 is the offset it says it already holds.
        let mut body = Vec::new();
        body.extend_from_slice(&field(0x01, &[11]));
        body.extend_from_slice(&field(0x02, &0u64.to_be_bytes()));
        let raw = raw_pair(&sim, &beacon, vec![answer_frame(&body)]).await?;
        let (receiver, managed, transfers) = (&raw.receiver, &raw.managed, &raw.transfers);
        let file = Generated::new("a-thrown-away.bin", FILE_BYTES);
        let transfer = transfers
            .send(
                &managed.connections,
                &managed.endpoint,
                &receiver.peer_id(),
                file.offering(),
            )
            .map_err(|error| error.to_string())?;
        let state = drive_transfer_in(
            &sim,
            TRANSFER_STALL + BUDGET,
            Duration::from_secs(1),
            &transfer,
        )
        .await?;
        failed(state, TransferFailure::NoProgress)?;
        let spent = sim.clock().elapsed();
        if spent < TRANSFER_STALL {
            return Err(format!(
                "the transfer was over after {spent:?}, before the {TRANSFER_STALL:?} bound that \
                 is the only thing it could have been ended by"
            ));
        }
        Ok(())
    })
}

/// A resume past the end of the file is a state this crate never produces, and the sender says so.
///
/// The raw receiving side answers `resume` with an offset one byte past the file's own length, so
/// the offer contradicts itself. The sender does not trust it and does not re-send: the transfer
/// ends `not understood`, which is the class for a receiving side this build cannot believe.
pub(crate) fn a_resume_past_the_end_is_not_understood() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let mut body = Vec::new();
        body.extend_from_slice(&field(0x01, &[11]));
        body.extend_from_slice(&field(0x02, &(FILE_BYTES + 1).to_be_bytes()));
        let raw = raw_pair(&sim, &beacon, vec![answer_frame(&body)]).await?;
        let (receiver, managed, transfers) = (&raw.receiver, &raw.managed, &raw.transfers);
        let file = Generated::new("a-past-the-end.bin", FILE_BYTES);
        let transfer = transfers
            .send(
                &managed.connections,
                &managed.endpoint,
                &receiver.peer_id(),
                file.offering(),
            )
            .map_err(|error| error.to_string())?;
        let state = drive_transfer(&sim, BUDGET, &transfer).await?;
        failed(state, TransferFailure::NotUnderstood)
    })
}

/// A throttle that comes from the wire is bounded, both ends of it.
///
/// A raw receiving side answers an offer with a start limit naming `u32::MAX` seconds, and the
/// product sees a wait no longer than `TRANSFER_THROTTLE_CAP`; one that names a wait of zero is
/// one second, so the retry is a look and not a spin; and one that names no wait at all is also
/// one second, because the class is what the answer means and a start limit is never an end. The
/// number is the peer's, and the bound is this machine's: a peer cannot park a transfer for
/// years, make it retry without pausing, or end it by leaving the delay out.
pub(crate) fn a_throttle_from_the_wire_is_bounded() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        for (name, asked, want) in [
            ("a-year.bin", Some(u32::MAX), TRANSFER_THROTTLE_CAP),
            ("no-wait.bin", Some(0), Duration::from_secs(1)),
            ("unnamed-wait.bin", None, Duration::from_secs(1)),
        ] {
            // Status 5 is `limit`, which 2 is the start limit, and 0x03 is the wait it names.
            let mut body = Vec::new();
            body.extend_from_slice(&field(0x01, &[5]));
            body.extend_from_slice(&field(0x04, &[2]));
            if let Some(asked) = asked {
                body.extend_from_slice(&field(0x03, &asked.to_be_bytes()));
            }
            let raw = raw_pair(&sim, &beacon, vec![answer_frame(&body)]).await?;
            let (receiver, managed, transfers) = (&raw.receiver, &raw.managed, &raw.transfers);
            let file = Generated::new(name, FILE_BYTES);
            let transfer = transfers
                .send(
                    &managed.connections,
                    &managed.endpoint,
                    &receiver.peer_id(),
                    file.offering(),
                )
                .map_err(|error| error.to_string())?;
            advance_until(&sim, BUDGET, Duration::from_millis(100), || {
                matches!(transfer.state(), TransferState::Throttled { .. })
            })
            .await
            .map_err(|why| format!("{why}: the transfer reads `{:?}`", transfer.state()))?;
            let TransferState::Throttled { retry_after } = transfer.state() else {
                return Err("the transfer stopped being throttled as it was read".to_owned());
            };
            if retry_after != want {
                return Err(format!(
                    "a peer that named {asked:?} seconds of throttle was waited on for \
                     {retry_after:?}, not {want:?}"
                ));
            }
            transfer.stop();
        }
        Ok(())
    })
}

/// A peer that keeps throttling ends the transfer with the limit, not with a pair that never
/// came back.
///
/// A raw receiving side takes the transfer once — `resume` at zero — and then answers every later
/// offer with a start limit naming a full window's wait, so the transfer is throttled for as long
/// as it keeps asking. A throttle is not a wait for the pair — the pair is answering — so it does
/// not anchor the wait bound again; once a whole `TRANSFER_WAIT` has gone by in throttles the
/// transfer ends, naming the limit it kept meeting and the wait it was last given. A peer cannot
/// park a transfer, and one of this machine's places for the peer with it, for ever.
///
/// The limit is the cause here because the pair did take the transfer; a limit met by a transfer
/// the pair never took ends as `no pair` instead, which is the case beside this one.
///
/// The peer first loses a whole start window of offers, which is what a pair with no binding
/// looks like, and only then takes the transfer and throttles it: a count of unanswered offers
/// that was never cleared by an answer would still be whole when the throttle arrived, and would
/// report the pair that has been there all along as one that went away.
pub(crate) fn a_peer_that_keeps_throttling_ends_the_transfer() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let asked = u32::try_from(TRANSFER_THROTTLE_CAP.as_secs())
            .expect("a throttle cap is far below four billion seconds");
        // The peer accepts the transfer first — status 11 is `resume` at offset zero — and
        // throttles every later offer: status 5 is `limit`, 2 is the start limit, and 0x03 is a
        // whole window of wait. A limit on a transfer the pair has taken is the pair pacing
        // starts, which is what the limit names, while a limit on a transfer the pair never took
        // is the pair not being ready. This case is the first of the two.
        let throttle = answer_frame(
            &[
                field(0x01, &[5]),
                field(0x04, &[2]),
                field(0x03, &asked.to_be_bytes()),
            ]
            .concat(),
        );
        let lost = usize::try_from(MAX_TRANSFER_STARTS).expect("a start limit is a small count");
        let raw = raw_pair_with(&sim, &beacon, |receiver| {
            raw_throttling_receiver(receiver, throttle, lost)
        })
        .await?;
        let (receiver, managed, transfers) = (&raw.receiver, &raw.managed, &raw.transfers);
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let transfer = transfers
            .send(
                &managed.connections,
                &managed.endpoint,
                &receiver.peer_id(),
                file.offering(),
            )
            .map_err(|error| error.to_string())?;
        let start = sim.clock().elapsed();
        let state = drive_transfer_in(
            &sim,
            TRANSFER_WAIT + BUDGET,
            Duration::from_secs(1),
            &transfer,
        )
        .await?;
        let spent = sim.clock().elapsed() - start;
        failed(
            state,
            TransferFailure::Limit {
                which: TransferLimit::Starts,
                retry_after: Some(TRANSFER_THROTTLE_CAP),
            },
        )?;
        if spent < TRANSFER_WAIT {
            return Err(format!(
                "a peer that throttled for {spent:?} ended the transfer, which is not the \
                 {TRANSFER_WAIT:?} the wait bound allows"
            ));
        }
        Ok(())
    })
}

/// A throttle that arrives with the receiving machine's stated offset grown ends the streak, so a
/// peer that keeps throttling while it takes bytes is never abandoned at the wait bound.
///
/// The raw peer throttles eleven times, naming the whole throttle cap each time and stating an
/// offset one kibibyte further every round: six hundred and sixty seconds of throttling, past the
/// `TRANSFER_WAIT` a streak that ignored the growth would end the transfer at. It then takes the
/// file and answers `complete`. Each round's grown offset ends the streak, so a peer that is
/// taking bytes while it paces the sender is not reported as one that kept meeting a limit.
pub(crate) fn a_growing_offset_ends_a_throttle_streak() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let asked = u32::try_from(TRANSFER_THROTTLE_CAP.as_secs())
            .expect("a throttle cap is far below four billion seconds");
        let throttle = answer_frame(
            &[
                field(0x01, &[5]),
                field(0x04, &[2]),
                field(0x03, &asked.to_be_bytes()),
            ]
            .concat(),
        );
        // Eleven rounds of the whole cap: six hundred and sixty seconds, past the wait bound.
        let raw = raw_pair_with(&sim, &beacon, move |receiver| {
            raw_growing_throttle_receiver(receiver, 11, 1024, throttle)
        })
        .await?;
        let (receiver, managed, transfers) = (&raw.receiver, &raw.managed, &raw.transfers);
        let file = Generated::new("a-growing-throttle.bin", FILE_BYTES);
        let transfer = transfers
            .send(
                &managed.connections,
                &managed.endpoint,
                &receiver.peer_id(),
                file.offering(),
            )
            .map_err(|error| error.to_string())?;
        let start = sim.clock().elapsed();
        // Two whole wait bounds: the eleven rounds spend one, and the rest is slack for the
        // scheduler turns of twelve offers.
        let state =
            drive_transfer_in(&sim, 2 * TRANSFER_WAIT, Duration::from_secs(1), &transfer).await?;
        let spent = sim.clock().elapsed() - start;
        ended(state, TransferState::Finished { bytes: FILE_BYTES })?;
        if spent <= TRANSFER_WAIT {
            return Err(format!(
                "the transfer was over after {spent:?}, which is not past the {TRANSFER_WAIT:?} a \
                 streak that ignored the grown offset would have ended it at"
            ));
        }
        Ok(())
    })
}

/// A pair that is there and answering, and whose start window is full, is reported as the limit
/// it met — never as a pair that was not there.
///
/// The peer answers the very first offer with a start limit, so nothing this machine did filled
/// its window: the pair is deciding, and it says "not so often". The transfer ends with that
/// limit and with the delay the peer last named. The other reading of a throttle — a window this
/// machine's own unanswered offers filled, which is a pair that was never ready — is
/// [`a_pair_that_never_binds_ends_as_the_pair`].
pub(crate) fn a_bound_pair_with_no_room_is_the_limit_it_met() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let asked = u32::try_from(TRANSFER_THROTTLE_CAP.as_secs())
            .expect("a throttle cap is far below four billion seconds");
        // Status 5 is `limit`, 0x04 names which (2 is the start limit) and 0x03 is the wait.
        let throttle = answer_frame(
            &[
                field(0x01, &[5]),
                field(0x04, &[2]),
                field(0x03, &asked.to_be_bytes()),
            ]
            .concat(),
        );
        let raw = raw_pair(&sim, &beacon, vec![throttle]).await?;
        let (receiver, managed, transfers) = (&raw.receiver, &raw.managed, &raw.transfers);
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let transfer = transfers
            .send(
                &managed.connections,
                &managed.endpoint,
                &receiver.peer_id(),
                file.offering(),
            )
            .map_err(|error| error.to_string())?;
        let state = drive_transfer_in(
            &sim,
            TRANSFER_WAIT + BUDGET,
            Duration::from_secs(1),
            &transfer,
        )
        .await?;
        failed(
            state,
            TransferFailure::Limit {
                which: TransferLimit::Starts,
                retry_after: Some(TRANSFER_THROTTLE_CAP),
            },
        )
    })
}

/// A connection that comes back and moves nothing gives the transfer no fresh budget.
///
/// The pair goes away and the transfer waits half the wait bound; the pair comes back and answers
/// every offer with nothing — offers that reach it, which is what the resumed link and the
/// connection the transfer re-dials prove. The half already spent is still spent, so what ends
/// the transfer is the rest of one wait bound and not a second one: waiting is a budget a
/// transfer spends, not an episode that restarts. The answer names the pair, which is what it met.
pub(crate) fn a_pair_that_comes_back_and_moves_nothing_spends_the_wait() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        // A live connection that says nothing at all: every offer is answered with an empty
        // stream, which is not a word this build understands as anything but silence.
        let raw = raw_pair(&sim, &beacon, Vec::new()).await?;
        let (receiver, managed, transfers) = (&raw.receiver, &raw.managed, &raw.transfers);
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let transfer = transfers
            .send(
                &managed.connections,
                &managed.endpoint,
                &receiver.peer_id(),
                file.offering(),
            )
            .map_err(|error| error.to_string())?;
        let start = sim.clock().elapsed();
        // The pair goes away: nothing reaches the receiving machine, so no connection can be
        // made and the transfer waits.
        sim.link().silence(receiver.addr());
        if !managed.connections.disconnect(&receiver.peer_id()) {
            return Err("the pair had no live connection to close".to_owned());
        }
        advance_until(&sim, BUDGET, Duration::from_millis(100), || {
            transfer.state() == TransferState::Waiting
        })
        .await
        .map_err(|why| format!("{why}: the transfer reads `{:?}`", transfer.state()))?;
        sim.clock().advance(TRANSFER_WAIT / 2).await;
        // It comes back, and moves nothing: a live connection, and silence on it. What is left
        // of the bound is all the transfer gets, so the case is driven for exactly that.
        sim.link().resume(receiver.addr());
        let carried = sim.link().delivered();
        // What is left of the bound, plus this case's own slack for noticing the pair: a
        // transfer given a fresh bound on reconnection would need a second whole one.
        let spent = sim.clock().elapsed() - start;
        let left = TRANSFER_WAIT.saturating_sub(spent) + BUDGET;
        let state = drive_transfer_in(&sim, left, Duration::from_secs(1), &transfer)
            .await
            .map_err(|why| {
                format!(
                    "{why}: the pair came back after {spent:?}, most of the wait bound, and gave \
                     the transfer a fresh budget instead of the rest of the one it had spent"
                )
            })?;
        failed(state, TransferFailure::NoPair)?;
        // The offers really did reach the pair once it was back: the wait was spent on a live
        // connection answering nothing, not by the link staying quiet — which is what makes
        // this case about a budget rather than about a pair that never came back.
        if sim.link().delivered() == carried {
            return Err(
                "no datagram reached the pair after it came back, so the wait was spent by a \
                 link that stayed quiet rather than by a live connection answering nothing"
                    .to_owned(),
            );
        }
        Ok(())
    })
}

/// A sending side that finished writing while the sink was still saying "not now" is the store's
/// failure, not the peer's source.
///
/// The whole file fits one stream window, so the sending side writes it and ends its stream at
/// once; the sink then answers "not now" for the whole stall bound. The receiver's one last look
/// at the stream finds it ended cleanly — nothing more is coming, and the sending side did
/// nothing wrong — so the transfer ends as this machine's own store failure and the sender is
/// told so. Reading that end as a failed source would blame a peer that was never at fault, and
/// leave the sender re-offering a file the receiver keeps failing to store.
pub(crate) fn a_clean_stream_end_at_a_slow_sink_is_a_store_failure() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let name = file.name().clone();
        let from = duo.sender.peer_id();
        // The sink refuses the write that would finish the file, so the receiver reads the whole
        // stream and holds its last bytes unstored for the whole stall bound: the sending side
        // has finished its stream, and there is no byte left for the receiver's last look to
        // find — only the end of the stream.
        hashing.fill_short_of(FILE_BYTES, 1);
        let transfer = offer(&duo, &file)?;
        let state = drive_transfer_in(
            &sim,
            TRANSFER_STALL + Duration::from_secs(120),
            Duration::from_secs(1),
            &transfer,
        )
        .await?;
        failed(state, TransferFailure::StoreFailed)?;
        let held = hashing.held_bytes(&from, &name);
        if held == 0 || held >= FILE_BYTES {
            return Err(format!(
                "the sink holds {held} bytes of a {FILE_BYTES}-byte file it could not finish"
            ));
        }
        let arriving = incoming_state(&duo, &name)?;
        if arriving
            != Some(TransferState::Failed {
                failure: TransferFailure::StoreFailed,
            })
        {
            return Err(format!(
                "the receiving machine reads `{arriving:?}` of a transfer its own sink could not \
                 take"
            ));
        }
        Ok(())
    })
}

/// A receiving machine with no sink refuses at the floor, and one with no right at the right.
///
/// The two answers are different steps, which is what "no sink is never the same as no right"
/// means: a product that has nowhere to put a file says so behind the permission, and a peer
/// without the permission never reaches the product's floor at all.
pub(crate) fn a_peer_with_no_sink_is_refused_at_the_floor() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        // The receiving machine's transfer layer was built with no sink at all: a product that
        // has not granted file ingress.
        let duo = duo(&sim, &beacon, Files::sending(), Files::sending()).await?;
        allow_files(&duo)?;
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let transfer = offer(&duo, &file)?;
        let state = drive_transfer(&sim, BUDGET, &transfer).await?;
        failed(state, TransferFailure::Refused { step: Step::Floor })?;
        // The layer's own floor is a floor like any other: the refusal is recorded, naming the
        // permission and the step, exactly once for the one offer that met it.
        let recorded = refusals(&duo.receiver)?;
        if recorded != 1 {
            return Err(format!(
                "the log holds {recorded} refusals for one offer a product with no sink refused"
            ));
        }
        let entries = duo
            .receiver
            .audit()?
            .entries()
            .map_err(|error| error.to_string())?;
        let at_the_floor = entries
            .iter()
            .filter(|entry| {
                matches!(
                    &entry.act,
                    Act::Refused {
                        capability,
                        refusal,
                        ..
                    } if *capability == Capability::PUT_FILES && refusal.step() == Step::Floor
                )
            })
            .count();
        if at_the_floor != 1 {
            return Err(format!(
                "the log holds {at_the_floor} refusals of `put files on me` at the floor for one \
                 offer a product with no sink refused"
            ));
        }
        // The same machine, with the permission withdrawn: the right is what refuses it now,
        // one step before the floor.
        duo.receiver
            .rights()?
            .withdraw(
                &pair(&duo.sender, &duo.assistant),
                Capability::PUT_FILES,
                person("the operator")?,
                NOW,
            )
            .map_err(|error| error.to_string())?;
        let second = Generated::new("a-file-with-no-right.bin", FILE_BYTES);
        let transfer = offer(&duo, &second)?;
        let state = drive_transfer(&sim, BUDGET, &transfer).await?;
        failed(state, TransferFailure::Refused { step: Step::Right })?;
        let after = refusals(&duo.receiver)?;
        if after != recorded + 1 {
            return Err(format!(
                "the log holds {after} refusals after one floor refusal and one at the right"
            ));
        }
        Ok(())
    })
}

/// How long a message may take to arrive: the bound the message cases wait under.
const MESSAGE_BOUND: Duration = Duration::from_secs(120);

/// One step of the message rig's wait: the resolution a round trip is measured to.
const MESSAGE_STEP: Duration = Duration::from_millis(100);

/// A product that only wants messages still works, and an offer costs it nothing.
///
/// The receiving machine has no transfer layer at all — its inbox was built without one and
/// its `Transfers` was never opened — so a message arrives and an action runs, and an offer
/// from the peer is answered in the only vocabulary it has: the message layer's `unreadable`,
/// which leaves the sender not understanding the answer. The word that follows the offer
/// arrives within the bound the message cases use, and no later than the one before it did.
pub(crate) fn a_product_that_only_wants_messages_still_works() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let duo = duo(&sim, &beacon, Files::sending(), Files::older()).await?;
        allow_files(&duo)?;
        // "Work on me" for the action, granted by the receiving machine's own person, and code
        // that runs what it is handed.
        duo.receiver
            .rights()?
            .grant(
                &pair(&duo.sender, &duo.assistant),
                Capability::WORK,
                Authority::Person(person("the operator")?),
                None,
                NOW,
            )
            .map_err(|error| error.to_string())?;
        duo.arriving.executions.run(b"done");
        let to = duo.receiver.peer_id();
        // The first word: a round trip with no file in sight.
        let started = sim.clock().elapsed();
        duo.sending
            .messages
            .send(&to, NOW, b"a word")
            .map_err(|error| error.to_string())?;
        let delivered = wait_for(&sim, &duo.arriving.collected, 1, MESSAGE_BOUND).await?;
        let before = sim.clock().elapsed() - started;
        if delivered.len() != 1 || delivered[0].body != b"a word" {
            return Err(format!(
                "a machine with no transfer layer was handed {delivered:?}, not the one word \
                 sent to it"
            ));
        }
        // An action runs on the same machine.
        let mut id = [0u8; ACTION_ID_BYTES];
        id[..8].copy_from_slice(&1u64.to_be_bytes());
        let answer = duo
            .sending
            .actions
            .request(
                &duo.sending.managed.connections,
                &duo.sending.managed.endpoint,
                &to,
                ActionId::from_bytes(id),
                ActionKind::COMMAND,
                b"a command",
            )
            .await
            .map_err(|error| error.to_string())?;
        match answer {
            ActionAnswer::Ran { result } if result == b"done" => {}
            other => {
                return Err(format!(
                    "an action sent to a machine with no transfer layer answered `{other:?}`"
                ));
            }
        }
        if duo.arriving.executions.count() != 1 {
            return Err(format!(
                "the machine's own code was handed {} actions, not one",
                duo.arriving.executions.count()
            ));
        }
        // An offer meets the message layer, which is the only reader this machine has.
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let transfer = offer(&duo, &file)?;
        let state = drive_transfer_in(&sim, BUDGET, Duration::from_secs(1), &transfer).await?;
        failed(state, TransferFailure::NotUnderstood)?;
        // The next word arrives within the same bound, and no later than the first did.
        let started = sim.clock().elapsed();
        duo.sending
            .messages
            .send(&to, NOW, b"a word after the offer")
            .map_err(|error| error.to_string())?;
        let delivered = wait_for(&sim, &duo.arriving.collected, 2, MESSAGE_BOUND).await?;
        let after = sim.clock().elapsed() - started;
        if delivered.len() != 2 || delivered[1].body != b"a word after the offer" {
            return Err(format!(
                "the word after the offer was not delivered: {delivered:?}"
            ));
        }
        if after > before + MESSAGE_STEP {
            return Err(format!(
                "a word after an offer took {after:?} of virtual time, longer than the \
                 {before:?} the word before it took"
            ));
        }
        Ok(())
    })
}

/// A source shorter than the length it offered is the sending side's own answer.
///
/// The file ends at half the length the offer stated, so the transfer ends naming its own
/// source rather than waiting for bytes that do not exist or blaming the peer. A source that
/// fails rather than ends — the disk it is read from went away at half the file — is the same
/// answer: what the sending machine could not read is its own, and neither the receiving
/// machine's store nor the pair is named for it.
pub(crate) fn a_source_that_ends_early_is_its_own_answer() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        file.end_after(FILE_BYTES / 2);
        let transfer = offer(&duo, &file)?;
        let state = drive_transfer(&sim, BUDGET, &transfer).await?;
        failed(state, TransferFailure::SourceUnreadable)?;
        // The same answer from a source that fails instead of ending: a read past the fault is
        // `failed`, not `ended`, and the sender learns the same word.
        let failing = Generated::new("a-failing-report.pdf", FILE_BYTES);
        failing.fail_at(FILE_BYTES / 2);
        let transfer = offer(&duo, &failing)?;
        let state = drive_transfer(&sim, BUDGET, &transfer).await?;
        failed(state, TransferFailure::SourceUnreadable)
    })
}

/// A sink that will not take bytes stops the sender through flow control, and not the pair.
///
/// The receiving machine's sink answers "not now", so the sender stops moving and neither
/// finishes nor grows without bound; a message from the same sender to the same receiver
/// still arrives while the file is blocked; and the transfer finishes once the sink takes
/// bytes again.
pub(crate) fn a_slow_sink_slows_the_sender() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        hashing.stop_accepting();
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let transfer = offer(&duo, &file)?;
        advance_until(&sim, BUDGET, Duration::from_millis(100), || {
            matches!(transfer.state(), TransferState::Running { .. })
        })
        .await
        .map_err(|why| format!("{why}: the transfer reads `{:?}`", transfer.state()))?;
        let stopped = transfer.state();
        // Two seconds later the sender has not finished and has not moved: the sink is what
        // is holding it, and the connection is not growing without bound.
        sim.clock().advance(Duration::from_secs(2)).await;
        if transfer.state() != stopped {
            return Err(format!(
                "the sender moved from `{stopped:?}` to `{:?}` while the sink took nothing",
                transfer.state()
            ));
        }
        if !matches!(stopped, TransferState::Running { .. }) {
            return Err(format!(
                "the transfer reads `{stopped:?}` with its sink blocked, not running"
            ));
        }
        // The pair's other services are not held behind the file.
        duo.sending
            .messages
            .send(&duo.receiver.peer_id(), NOW, b"a word beside the file")
            .map_err(|error| error.to_string())?;
        let delivered = wait_for(&sim, &duo.arriving.collected, 1, BUDGET).await?;
        let first = delivered
            .first()
            .ok_or("no message arrived beside the file")?;
        if first.body != b"a word beside the file" {
            return Err("the message beside the file was not the one sent".to_owned());
        }
        hashing.start_accepting();
        let state = drive_transfer(&sim, BUDGET, &transfer).await?;
        ended(state, TransferState::Finished { bytes: FILE_BYTES })
    })
}

/// A transfer that keeps making progress is never abandoned, however long it takes.
///
/// The source answers "not now" for a while before every chunk, so the whole file takes
/// longer than the stall bound while every chunk is a byte moved inside it: the bound is on
/// no progress, not on a transfer's length, and the file still arrives byte-exact. The
/// receiving machine's own view agrees throughout: a transfer it is still storing is never
/// reported as failed, because its offset keeps growing.
pub(crate) fn a_transfer_that_makes_progress_is_never_abandoned() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        let from = duo.sender.peer_id();
        // Two seconds of "not now" before every chunk of a two-mebibyte file: the transfer
        // lasts about a minute, which is the stall bound, and moves throughout.
        let length = 2 * 1024 * 1024;
        let file = Generated::new(FILE_NAME, length);
        let name = file.name().clone();
        file.stall_every(2);
        let transfer = offer(&duo, &file)?;
        // Past the stall bound with the file still arriving: the receiver's own view is the one
        // that would say the transfer died, and it never does while its sink is taking bytes.
        let mut watched = Duration::ZERO;
        while watched < TRANSFER_STALL + Duration::from_secs(5) {
            sim.clock().advance(Duration::from_secs(1)).await;
            watched += Duration::from_secs(1);
            if let Some(TransferState::Failed { failure }) = incoming_state(&duo, &name)? {
                return Err(format!(
                    "the receiving machine reported `{failure}` while its sink was still \
                     storing the file"
                ));
            }
        }
        let state = drive_transfer_in(&sim, BUDGET * 3, Duration::from_secs(1), &transfer).await?;
        let spent = sim.clock().elapsed();
        ended(state, TransferState::Finished { bytes: length })?;
        if spent <= TRANSFER_STALL {
            return Err(format!(
                "the transfer was over after {spent:?} of virtual time, which is not past the \
                 {TRANSFER_STALL:?} the case has to cross"
            ));
        }
        if hashing.held_bytes(&from, &name) != length {
            return Err(format!(
                "the sink holds {} bytes of a two-mebibyte file",
                hashing.held_bytes(&from, &name)
            ));
        }
        Ok(())
    })
}

/// A slow sink makes the sender wait for it, not give up on the file.
///
/// The receiving side stores one chunk every ten polls, so a file just past one stream window
/// takes twenty minutes of virtual time while every chunk is still a byte stored inside it. The
/// sender's writes fill the window at once and the write after them parks — the transport returns
/// flow-control credit a fraction of a window at a time, so the wait is far longer than the stall
/// bound — and the receiving machine reports its offset chunk by chunk while its sink stores. That
/// offset is the only progress there is, and the file arrives whole.
///
/// With the sender crediting its own parked write, or crediting nothing but a verdict, this ends
/// `no progress` a minute in, with the receiving machine still storing.
pub(crate) fn a_slow_sink_never_makes_the_sender_abandon_the_file() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        let from = duo.sender.peer_id();
        let file = Generated::new(FILE_NAME, PAST_A_WINDOW);
        let name = file.name().clone();
        hashing.slow(10);
        let transfer = offer(&duo, &file)?;
        let state = drive_transfer_in(
            &sim,
            Duration::from_secs(1800),
            Duration::from_secs(1),
            &transfer,
        )
        .await?;
        let spent = sim.clock().elapsed();
        ended(
            state,
            TransferState::Finished {
                bytes: PAST_A_WINDOW,
            },
        )?;
        if spent <= TRANSFER_STALL + Duration::from_secs(1) {
            return Err(format!(
                "the transfer was over after {spent:?} of virtual time, which is not past the \
                 stall bound and the poll past it the sender's verdict wait has to cross"
            ));
        }
        let arriving = incoming_state(&duo, &name)?;
        let finished = Some(TransferState::Finished {
            bytes: PAST_A_WINDOW,
        });
        if arriving != finished {
            return Err(format!(
                "the receiving machine reads `{arriving:?}` of a file it stored whole"
            ));
        }
        if hashing.held_bytes(&from, &name) != PAST_A_WINDOW {
            return Err(format!(
                "the sink holds {} bytes of a {PAST_A_WINDOW}-byte file",
                hashing.held_bytes(&from, &name)
            ));
        }
        let assembled = hashing
            .assembled(&from, &name)
            .ok_or("the sink assembled nothing")?;
        if assembled != file.digest() {
            return Err(format!(
                "the sink assembled {assembled} but the source offered {}",
                file.digest()
            ));
        }
        Ok(())
    })
}

/// A transfer's handle shows where it stands, and the receiving machine sees the same
/// transfer while it runs.
pub(crate) fn the_transfer_state_is_visible() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        let file = Generated::new(FILE_NAME, LONG_BYTES);
        let name = file.name().clone();
        let transfer = offer(&duo, &file)?;
        // A transfer that has not been offered yet is waiting for the pair, not running.
        if transfer.state() != TransferState::Waiting {
            return Err(format!(
                "a transfer that was just offered reads `{:?}`, not waiting",
                transfer.state()
            ));
        }
        let mut seen_running = false;
        let mut seen_incoming = false;
        advance_until(&sim, BUDGET, Duration::from_millis(10), || {
            let state = transfer.state();
            if matches!(state, TransferState::Running { .. }) {
                seen_running = true;
                if matches!(
                    incoming_state(&duo, &name),
                    Ok(Some(TransferState::Running { .. }))
                ) {
                    seen_incoming = true;
                }
            }
            state.is_over()
        })
        .await
        .map_err(|why| format!("{why}: the transfer reads `{:?}`", transfer.state()))?;
        ended(
            transfer.state(),
            TransferState::Finished { bytes: LONG_BYTES },
        )?;
        if !seen_running {
            return Err("the handle never showed the transfer running".to_owned());
        }
        if !seen_incoming {
            return Err(
                "the receiving machine never showed the transfer running while the sender did"
                    .to_owned(),
            );
        }
        Ok(())
    })
}

/// A transfer frame is not an action, and is never handed to the machine's own code.
///
/// The frame is written by hand — an offer this build's transfer layer would write — and
/// offered over the pair's connection: the one reader hands it to the transfer layer, and the
/// executor behind the action layer is never called.
pub(crate) fn a_transfer_frame_is_not_an_action() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        let connection = wait_live(
            &sim,
            &duo.sending.managed.connections,
            &duo.receiver.peer_id(),
        )
        .await?;
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let bytes = offer_bytes(file.name(), FILE_BYTES, &file.digest());
        let answer = within(&sim, BUDGET, offer_frame(&connection, &bytes, ANSWER_BYTES)).await??;
        if !answer.starts_with(b"mahbot-peer-transfer-answer") {
            return Err(format!(
                "an offer of {} bytes was answered with {} bytes that are not a transfer's",
                bytes.len(),
                answer.len()
            ));
        }
        if duo.arriving.executions.count() != 0 {
            return Err(format!(
                "the receiving machine's own code was handed {} actions for a transfer frame",
                duo.arriving.executions.count()
            ));
        }
        Ok(())
    })
}

/// A hundred mebibytes arrive within thirty round trips of a link with a constant delay.
///
/// The plan is set before the first datagram, so the handshake is in the trace with the file. A
/// round trip is the link's own 5 ms there and back, so thirty of them are 300 ms of virtual
/// time, and the count comes from the trace rather than from the time the rig happened to spend
/// driving the clock.
///
/// The count starts at the first datagram of the run, so the handshake and the offer's
/// authorisation are inside the thirty. A second of the crate's own inbox poll sits between
/// the handshake and the first byte the file moves — the receiving machine's reader looks for
/// a new connection once a second — and a hundred round trips of this link is what that second
/// would be worth if it were counted as a span. It is the inbox's interval and not the wire's,
/// and the link counts only the windows that carried a datagram, so the idle second is no
/// round trip.
///
/// Nothing but the file crosses the connection here: the precondition the case used to buy with
/// a word sent over the message layer — the accepting side's reader watching the connection —
/// is proved directly instead, by the binding exchange having finished on it. A message would
/// put a whole layer's round trip inside a count that is about the file.
pub(crate) fn a_hundred_mebibytes_arrive_within_thirty_round_trips() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        sim.link()
            .set_plan(FaultPlan::Latency(Duration::from_millis(5)));
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        // The accepting side has finished the binding exchange on the pair's connection, which
        // it can only do with its one reader polling: that, and not a message, is what says the
        // connection is being read before the file is offered on it.
        wait_live(
            &sim,
            &duo.arriving.managed.connections,
            &duo.sender.peer_id(),
        )
        .await?;
        let file = Generated::new(FILE_NAME, HUNDRED_MEBIBYTES);
        let name = file.name().clone();
        let from = duo.sender.peer_id();
        let transfer = offer(&duo, &file)?;
        // A step of one round trip, and only once the transfer has moved nothing for a while: a
        // rig that moves the clock while the sender is still runnable would count its own turns
        // as time on the wire. With a step this size the count is how many round trips the link
        // carried, not how finely the rig ticked — a millisecond step would make quinn's pacer
        // one packet a step and the case would never finish.
        let state = drive_in(&sim, BUDGET, RTT, &transfer).await?;
        ended(
            state,
            TransferState::Finished {
                bytes: HUNDRED_MEBIBYTES,
            },
        )?;
        let assembled = hashing
            .assembled(&from, &name)
            .ok_or("the sink assembled nothing")?;
        if assembled != file.digest() {
            return Err(format!(
                "the sink assembled {assembled} but the source offered {}",
                file.digest()
            ));
        }
        if hashing.held_bytes(&from, &name) != HUNDRED_MEBIBYTES {
            return Err(format!(
                "the sink holds {} bytes of a {HUNDRED_MEBIBYTES}-byte file",
                hashing.held_bytes(&from, &name)
            ));
        }
        // The trace is on, so the count is the link's own reading of which round trips
        // carried a datagram — the handshake and the offer included, and the virtual time
        // the rig spent excluded.
        let trips = sim.link().round_trips(0, RTT);
        if trips > ROUND_TRIPS {
            return Err(format!(
                "a hundred mebibytes took {trips} round trips of a {RTT:?} link, more than the \
                 {ROUND_TRIPS} the case allows"
            ));
        }
        Ok(())
    })
}

/// A file far beyond every window arrives in one transfer, byte-exact and without a single
/// restart.
///
/// The trace cannot hold a file this size's datagrams, so the link is asked not to record them
/// and the case proves the traffic with the sink and with the link's own count of what it
/// delivered. The sink refuses a gap or a repeat at the offset it is handed, so the digest
/// matching after the fact is the file arriving once, in order: a transfer restarted in the
/// middle would have been handed a byte out of place.
pub(crate) fn a_file_beyond_every_window_arrives_in_one_transfer() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        sim.link().record_trace(false);
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        let file = Generated::new(FILE_NAME, ONE_GO_BYTES);
        let name = file.name().clone();
        let from = duo.sender.peer_id();
        let transfer = offer(&duo, &file)?;
        let state = drive_in(&sim, BUDGET, STEP, &transfer).await?;
        ended(
            state,
            TransferState::Finished {
                bytes: ONE_GO_BYTES,
            },
        )?;
        let assembled = hashing
            .assembled(&from, &name)
            .ok_or("the sink assembled nothing")?;
        if assembled != file.digest() {
            return Err(format!(
                "the sink assembled {assembled} but the source offered {}",
                file.digest()
            ));
        }
        if hashing.held_bytes(&from, &name) != ONE_GO_BYTES {
            return Err(format!(
                "the sink holds {} bytes of a {ONE_GO_BYTES}-byte file",
                hashing.held_bytes(&from, &name)
            ));
        }
        // One write a chunk, and every one of them this file's.
        let writes = u64::try_from(hashing.writes()).expect("a write count is far below a u64");
        if writes < ONE_GO_BYTES / CHUNK {
            return Err(format!(
                "the sink took {writes} writes, fewer than the {} a {ONE_GO_BYTES}-byte file in \
                 {CHUNK}-byte chunks is",
                ONE_GO_BYTES / CHUNK
            ));
        }
        // The trace was asked not to record, and the link still carried the file.
        if !sim.link().trace().is_empty() {
            return Err(format!(
                "the trace recorded {} datagrams of a transfer the case asked it to keep out of \
                 the trace",
                sim.link().trace().len()
            ));
        }
        if sim.link().delivered() == 0 {
            return Err(format!(
                "the link delivered nothing for a {ONE_GO_BYTES}-byte file that arrived"
            ));
        }
        Ok(())
    })
}

/// The transport bounds what a peer can make this machine buffer, and what this machine queues.
///
/// A raw peer opens every stream the connection grants and writes into them while the far side
/// reads nothing: what it can push is the transport's own credit, and the credit cannot be read
/// back from the outside. So the case measures it the only way a caller can — by writing until
/// the write stops completing — and compares the counts with the crate's own numbers. The other
/// direction is the same equation and no more readable from outside: the endpoint sets quinn's
/// `send_window` to `MAX_BUFFERED_BYTES`, so this machine queues no more of its own writes than
/// a peer can push into it, whatever window the peer advertises.
pub(crate) fn the_transport_bounds_what_a_peer_can_buffer() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (client, server) = sim.trusting_pair().map_err(io_error)?;
        let (accepting, _first) = accept_raw(&server)?;
        let connection = raw_connection(&sim, &client, &server).await?;
        // Every stream the connection grants is open at once; the next one waits for credit
        // that a far side which never closes a stream will not grant.
        let mut streams = Vec::new();
        for _ in 0..MAX_STREAMS {
            let opened = within(&sim, BUDGET, connection.open_bi())
                .await?
                .map_err(|error| error.to_string())?;
            streams.push(opened);
        }
        if within(&sim, BLOCKED, connection.open_bi()).await.is_ok() {
            return Err(format!(
                "the connection opened a stream past the {MAX_STREAMS} it advertises"
            ));
        }
        // One stream takes the credit the far side advertises for one stream, and all of them
        // together take the credit it advertises for the connection.
        let chunk = vec![0x5a; TRANSFER_CHUNK];
        let mut most = 0u64;
        let mut total = 0u64;
        for (mut send, _recv) in streams {
            let accepted = fill(&sim, &mut send, &chunk).await;
            most = most.max(accepted);
            total = total.saturating_add(accepted);
        }
        let stream_bound =
            u64::try_from(MAX_STREAM_BYTES).expect("eight mebibytes fit a u64") + STREAM_SLACK;
        if most > stream_bound {
            return Err(format!(
                "one stream took {most} bytes, more than the {MAX_STREAM_BYTES} its window \
                 advertises and the {STREAM_SLACK} of slack the case allows"
            ));
        }
        let connection_bound = u64::try_from(MAX_BUFFERED_BYTES)
            .expect("thirty-two mebibytes fit a u64")
            + CONNECTION_SLACK;
        if total > connection_bound {
            return Err(format!(
                "the streams took {total} bytes together, more than the {MAX_BUFFERED_BYTES} the \
                 connection's window advertises and the {CONNECTION_SLACK} of slack the case \
                 allows"
            ));
        }
        if most == 0 {
            return Err("no stream took a byte: the case measured nothing".to_owned());
        }
        accepting.abort();
        Ok(())
    })
}

/// The pair's connection advertises only what it serves.
///
/// A peer's connection is built by the crate's own transport, which asks for no QUIC datagram
/// and grants no unidirectional stream: both would be receive window a peer could pin on a
/// channel nothing reads. A bidirectional stream still carries data, so what the connection
/// refuses is the two channels the crate never serves and not the one it does.
pub(crate) fn the_peer_connection_advertises_only_what_it_serves() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (client, server) = sim.trusting_pair().map_err(io_error)?;
        let (accepting, handoff) = accept_raw(&server)?;
        let connection = raw_connection(&sim, &client, &server).await?;
        if let Some(size) = connection.max_datagram_size() {
            return Err(format!(
                "the pair's connection advertises a {size}-byte datagram it never reads"
            ));
        }
        // A unidirectional stream is granted by credit and nothing else: a peer that asks and
        // waits was granted none.
        if within(&sim, BLOCKED, connection.open_uni()).await.is_ok() {
            return Err(
                "the pair's connection opened a unidirectional stream it never reads".to_owned(),
            );
        }
        // The two halves a case holds are one connection: a word written on the dialling half
        // is read on the accepting one, which two connections that share an address could not
        // do.
        let live = accepted(&sim, &handoff).await?;
        within(&sim, BUDGET, round_trip(&connection, &live)).await??;
        accepting.abort();
        Ok(())
    })
}

/// A third transfer to one peer is refused, on the sending machine and on the receiving one.
///
/// Both sides count the same limit: this machine refuses to queue a third transfer to one peer,
/// and the receiving machine refuses a third offer while two are authorised and waiting for
/// bytes. The third offer is built by hand, because the typed layer will not offer one.
pub(crate) fn a_third_transfer_to_one_peer_is_refused() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        // This machine's own count: two transfers wait for the pair, and the third is refused
        // before it is queued. No connection is made, so both stay waiting.
        let waiting = wired_pair(
            &sim,
            &beacon,
            Files::sending(),
            Files::taking(Store::hashing()),
        )?;
        let peer = waiting.receiver.peer_id();
        let transfers = waiting.sending.transfers()?;
        let mut held = Vec::new();
        for name in ["first.bin", "second.bin"] {
            held.push(
                transfers
                    .send(
                        &waiting.sending.managed.connections,
                        &waiting.sending.managed.endpoint,
                        &peer,
                        Generated::new(name, FILE_BYTES).offering(),
                    )
                    .map_err(|error| format!("a transfer to one peer was refused: {error}"))?,
            );
        }
        match transfers.send(
            &waiting.sending.managed.connections,
            &waiting.sending.managed.endpoint,
            &peer,
            Generated::new("third.bin", FILE_BYTES).offering(),
        ) {
            Err(TransferError::Limit { peer: named }) if named == peer => {}
            other => {
                return Err(format!(
                    "a third transfer to one peer was answered `{other:?}`, not a limit"
                ));
            }
        }
        // The receiving machine's count, on a pair of its own: two transfers are authorised
        // and held, and the third offer meets the limit rather than the decision.
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        // The sink takes nothing, so both transfers stay authorised and running.
        hashing.stop_accepting();
        let one = Generated::new("held-one.bin", FILE_BYTES);
        let two = Generated::new("held-two.bin", FILE_BYTES);
        let first = offer(&duo, &one)?;
        let second = offer(&duo, &two)?;
        advance_until(&sim, BUDGET, Duration::from_millis(10), || {
            duo.arriving
                .transfers()
                .is_ok_and(|transfers| transfers.incoming(&duo.sender.peer_id()).len() >= 2)
        })
        .await
        .map_err(|why| format!("{why}: the receiving machine authorised no second transfer"))?;
        let connection = wait_live(
            &sim,
            &duo.sending.managed.connections,
            &duo.receiver.peer_id(),
        )
        .await?;
        let third = Generated::new("third-held.bin", FILE_BYTES);
        let bytes = offer_bytes(third.name(), FILE_BYTES, &third.digest());
        let answer = within(&sim, BUDGET, offer_frame(&connection, &bytes, ANSWER_BYTES)).await??;
        let fields = answer_fields(&answer)?;
        // Status 5 is `limit`, and which 1 is the limit on running transfers.
        if fields.status != 5 {
            return Err(format!(
                "a third offer was answered with status {} rather than a limit",
                fields.status
            ));
        }
        if fields.which != Some(1) {
            return Err(format!(
                "the limit a third offer met names `{:?}`, not the running transfers",
                fields.which
            ));
        }
        // Neither of the two held transfers was disturbed, and the third never started.
        let incoming = duo.arriving.transfers()?.incoming(&duo.sender.peer_id());
        if incoming.len() != 2 {
            return Err(format!(
                "the receiving machine holds {} transfers after refusing a third",
                incoming.len()
            ));
        }
        if first.state().is_over() || second.state().is_over() {
            return Err("a held transfer ended while the third offer was refused".to_owned());
        }
        Ok(())
    })
}

/// The start limit is checked before the decision, so a peer cannot fill the log with refusals.
///
/// A peer with no "put files on me" grant offers a file `MAX_TRANSFER_STARTS` times and is
/// refused at the right step each time — six refusals, six entries. The seventh is answered
/// before the decision, so it is a limit with a wait no longer than the window, and it wrote
/// nothing: the log still holds exactly the six.
pub(crate) fn the_start_limit_is_checked_before_the_decision() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        let connection = wait_live(
            &sim,
            &duo.sending.managed.connections,
            &duo.receiver.peer_id(),
        )
        .await?;
        for start in 1..=MAX_TRANSFER_STARTS {
            let file = Generated::new(&format!("a-refused-{start}.bin"), FILE_BYTES);
            let bytes = offer_bytes(file.name(), FILE_BYTES, &file.digest());
            let answer =
                within(&sim, BUDGET, offer_frame(&connection, &bytes, ANSWER_BYTES)).await??;
            let fields = answer_fields(&answer)?;
            // Status 3 is `refused`, and which 2 is the right step.
            if fields.status != 3 || fields.which != Some(2) {
                return Err(format!(
                    "offer {start} of {MAX_TRANSFER_STARTS} was answered with status {} at step \
                     {:?}, not a refusal at the right",
                    fields.status, fields.which
                ));
            }
        }
        let refused = refusals(&duo.receiver)?;
        if refused != u64::from(MAX_TRANSFER_STARTS) {
            return Err(format!(
                "the log holds {refused} refusals after {MAX_TRANSFER_STARTS} refused offers"
            ));
        }
        // The seventh offer meets the start limit before the decision is asked.
        let beyond = Generated::new("a-refused-seventh.bin", FILE_BYTES);
        let bytes = offer_bytes(beyond.name(), FILE_BYTES, &beyond.digest());
        let answer = within(&sim, BUDGET, offer_frame(&connection, &bytes, ANSWER_BYTES)).await??;
        let fields = answer_fields(&answer)?;
        if fields.status != 5 || fields.which != Some(2) {
            return Err(format!(
                "an offer past the start limit was answered with status {} and limit {:?}, not \
                 the start limit",
                fields.status, fields.which
            ));
        }
        let retry = fields
            .retry_after
            .ok_or("the start limit named no wait at all")?;
        if Duration::from_secs(u64::from(retry)) > TRANSFER_START_WINDOW {
            return Err(format!(
                "the start limit asked for {retry} seconds, longer than the \
                 {TRANSFER_START_WINDOW:?} window"
            ));
        }
        let after = refusals(&duo.receiver)?;
        if after != refused {
            return Err(format!(
                "an offer refused by the start limit wrote an entry: the log holds {after} \
                 refusals, not {refused}"
            ));
        }
        Ok(())
    })
}

/// A transfer that resumes after a reconnect does not count against the start limit.
///
/// The window is spent: one refused offer and four that arrived are the five starts of six,
/// and the sixth is a transfer that is interrupted in the middle and then resumes. It finishes
/// — so the resume was not a seventh start — and a new transfer offered afterwards meets the
/// limit, which is what says the count is exactly six. The throttle reaches the product as its
/// own answer, with the wait the receiving machine asked for and no longer than its window.
pub(crate) fn a_resume_does_not_count_against_the_start_limit() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let holding = Store::holding();
        let sink: Arc<dyn Sink + Send + Sync> = holding.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        let from = duo.sender.peer_id();
        // One start is spent on a refusal: the first offer is made before the grant.
        let refused_file = Generated::new("a-refused-first.bin", FILE_BYTES);
        let refused = offer(&duo, &refused_file)?;
        let state = drive_transfer(&sim, BUDGET, &refused).await?;
        failed(state, TransferFailure::Refused { step: Step::Right })?;
        let refusals_before = refusals(&duo.receiver)?;
        allow_files(&duo)?;
        // Four starts arrive whole.
        for start in 1..=4 {
            let file = Generated::new(&format!("an-arrived-{start}.bin"), FILE_BYTES);
            let transfer = offer(&duo, &file)?;
            let state = drive_transfer(&sim, BUDGET, &transfer).await?;
            ended(state, TransferState::Finished { bytes: FILE_BYTES })?;
        }
        // The sixth start is interrupted in the middle and resumes from where the sink stopped.
        let file = Generated::new("a-resumed-sixth.bin", LONG_BYTES);
        let name = file.name().clone();
        holding.accept_burst(1);
        let transfer = offer(&duo, &file)?;
        advance_until(&sim, BUDGET, Duration::from_millis(10), || {
            holding.held_bytes(&from, &name) > 0
        })
        .await
        .map_err(|why| {
            format!(
                "{why}: the sink holds {} bytes and the transfer reads `{:?}`",
                holding.held_bytes(&from, &name),
                transfer.state()
            )
        })?;
        if !duo
            .sending
            .managed
            .connections
            .disconnect(&duo.receiver.peer_id())
        {
            return Err("the pair had no live connection to close".to_owned());
        }
        advance_until(&sim, BUDGET, Duration::from_millis(100), || {
            transfer.state() == TransferState::Waiting
        })
        .await
        .map_err(|why| format!("{why}: the transfer reads `{:?}`", transfer.state()))?;
        holding.accept_burst(usize::MAX);
        let state = drive_transfer_in(&sim, BUDGET, Duration::from_secs(1), &transfer).await?;
        ended(state, TransferState::Finished { bytes: LONG_BYTES })?;
        // The resume was not a start: the log gained no refusal, and the sixth start is spent.
        let refusals_after = refusals(&duo.receiver)?;
        if refusals_after != refusals_before {
            return Err(format!(
                "the log's refusals grew from {refusals_before} to {refusals_after} across a \
                 resume that was refused"
            ));
        }
        // A seventh start is one the window has none of, which is what says the resume took no
        // number of its own. The throttle is a wait, not an end: the handle shows the delay the
        // receiving machine named, inside its own window, and the same transfer finishes once
        // the window turns.
        let beyond = Generated::new("a-seventh.bin", FILE_BYTES);
        let seventh = offer(&duo, &beyond)?;
        advance_until(&sim, BUDGET, Duration::from_millis(100), || {
            matches!(seventh.state(), TransferState::Throttled { .. })
        })
        .await
        .map_err(|why| format!("{why}: the transfer reads `{:?}`", seventh.state()))?;
        let TransferState::Throttled { retry_after } = seventh.state() else {
            return Err("the transfer stopped being throttled as it was read".to_owned());
        };
        if retry_after == Duration::ZERO || retry_after > TRANSFER_START_WINDOW {
            return Err(format!(
                "the start limit told the product to wait `{retry_after:?}`, not inside the \
                 {TRANSFER_START_WINDOW:?} window"
            ));
        }
        let state = drive_transfer_in(&sim, BUDGET, Duration::from_secs(1), &seventh).await?;
        ended(state, TransferState::Finished { bytes: FILE_BYTES })
    })
}

/// An allowed transfer is recorded before it starts, and the record is the peer's own part.
///
/// One entry, naming the pair, the permission, the name's bytes, the length, the digest, the
/// issuer and the term. It is peer-driven, which the case shows by behaviour rather than by
/// asking the crate: the log's part for peer-driven acts is filled to the room kept for a
/// person, and a person's grant still lands.
pub(crate) fn an_allowed_transfer_is_recorded_before_it_starts() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let transfer = offer(&duo, &file)?;
        let state = drive_transfer(&sim, BUDGET, &transfer).await?;
        ended(state, TransferState::Finished { bytes: FILE_BYTES })?;
        let entries = duo
            .receiver
            .audit()?
            .entries()
            .map_err(|error| error.to_string())?;
        let mut allowed = Vec::new();
        for entry in &entries {
            if matches!(entry.act, Act::TransferAllowed { .. }) {
                allowed.push(entry);
            }
        }
        let [entry] = &allowed[..] else {
            return Err(format!(
                "the log holds {} entries for one authorised transfer",
                allowed.len()
            ));
        };
        let Act::TransferAllowed {
            pair: named,
            capability,
            name,
            length,
            digest,
            issuer,
            expires_at,
        } = &entry.act
        else {
            return Err("the entry is not a transfer's".to_owned());
        };
        if *named != pair(&duo.sender, &duo.assistant) {
            return Err(format!(
                "the entry names the pair `{named:?}`, not the one the transfer was authorised \
                 under"
            ));
        }
        if *capability != Capability::PUT_FILES {
            return Err(format!(
                "the entry names `{capability}` rather than the permission a file needs"
            ));
        }
        if name.as_slice() != file.name().as_str().as_bytes() {
            return Err(format!(
                "the entry names {} bytes that are not the transfer's name",
                name.len()
            ));
        }
        if *length != FILE_BYTES {
            return Err(format!(
                "the entry names a length of {length}, not {FILE_BYTES}"
            ));
        }
        if digest.as_slice() != file.digest().as_bytes() {
            return Err(
                "the entry's digest is not the one the transfer was offered with".to_owned(),
            );
        }
        if *issuer != Issuer::Person(person("the operator")?) {
            return Err(format!("the entry names the issuer `{issuer}`"));
        }
        if expires_at.is_some() {
            return Err(format!(
                "the entry names a term of {expires_at:?} for a right granted with none"
            ));
        }
        // The entry is peer-driven: the log's part for a peer's acts is full, and a person's
        // grant still lands on its own.
        fill_log(&duo.receiver, MAX_FILE_BYTES - RESERVED_FOR_PERSON_BYTES)?;
        let granted_at = NOW.plus(Duration::from_secs(1));
        duo.receiver
            .rights()?
            .grant(
                &pair(&duo.sender, &duo.assistant),
                Capability::WORK,
                Authority::Person(person("the operator")?),
                None,
                granted_at,
            )
            .map_err(|error| {
                format!(
                    "a person's grant did not land with the log's part for a peer full: {error}"
                )
            })?;
        let entries = duo
            .receiver
            .audit()?
            .entries()
            .map_err(|error| error.to_string())?;
        let landed = entries.iter().any(|entry| {
            entry.at == granted_at
                && matches!(
                    &entry.act,
                    Act::Granted { capability, .. } if *capability == Capability::WORK
                )
        });
        if !landed {
            return Err("a person's grant left no entry in the room kept for it".to_owned());
        }
        Ok(())
    })
}

/// A transfer the receiving machine cannot record is not run.
///
/// The log's part for peer-driven acts is full to the room kept for a person, and the next
/// offer cannot be written. The receiving machine answers `not recorded` and runs nothing: the
/// sender ends naming its own side's record, and the sink is never written.
pub(crate) fn a_transfer_that_cannot_be_recorded_is_not_run() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let transfer = offer(&duo, &file)?;
        let state = drive_transfer(&sim, BUDGET, &transfer).await?;
        ended(state, TransferState::Finished { bytes: FILE_BYTES })?;
        // The last entry is the transfer's own, which is the peer-driven part: filling the log
        // with copies of it fills exactly the room a peer may use.
        fill_log(&duo.receiver, MAX_FILE_BYTES - RESERVED_FOR_PERSON_BYTES)?;
        let writes = hashing.writes();
        let next = Generated::new("a-second.bin", FILE_BYTES);
        let blocked = offer(&duo, &next)?;
        let state = drive_transfer(&sim, BUDGET, &blocked).await?;
        failed(state, TransferFailure::NotRecorded)?;
        if hashing.writes() != writes {
            return Err(format!(
                "the sink was written {} times for a transfer the receiving machine could not \
                 record",
                hashing.writes() - writes
            ));
        }
        Ok(())
    })
}

/// A transfer counts as carried only once it moved a byte.
///
/// A dialled connection that carried nothing but a refused offer is a dial that carried
/// nothing: the keeper counts it, and the episode is used up after the stated number of them.
/// A connection that moved bytes is the pair being used, so its loss is ordinary churn and the
/// keeper dials again at once — whether the transfer went on to finish, ended on its own side
/// afterwards, or was still in flight when the connection went, because a transfer that moved
/// bytes carried them however the attempt it was in the middle of ends.
pub(crate) fn a_transfer_counts_as_carried_only_once_it_moved() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        // Half one: every dial carries an offer the receiving machine refuses, because it was
        // granted nothing.
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let refusing = wired_pair(&sim, &beacon, Files::sending(), Files::taking(sink))?;
        let peer = refusing.receiver.peer_id();
        let keeper = spawn_keeper(&refusing.sending.managed, &refusing.receiver);
        let mut previous = None;
        for round in 1..=RECOVERY_DIALS {
            let connection = connection::wait_connected(
                &sim,
                &refusing.sending.managed.connections,
                &peer,
                previous,
            )
            .await?;
            previous = Some(connection.stable_id());
            let file = Generated::new(&format!("a-strike-{round}.bin"), FILE_BYTES);
            let transfer = offer(&refusing, &file)?;
            let state = drive_transfer(&sim, BUDGET, &transfer).await?;
            failed(state, TransferFailure::Refused { step: Step::Right })?;
            // The connection goes the way a peer that accepts and drops does.
            if !refusing.sending.managed.connections.disconnect(&peer) {
                return Err(format!(
                    "round {round}: the pair had no live connection to close"
                ));
            }
            let counted = counted_dial(&sim, &refusing.sending.managed.connections, &peer).await?;
            if counted != round {
                return Err(format!(
                    "round {round}: the connection that carried only a refused offer was counted \
                     as dial {counted} of the episode"
                ));
            }
        }
        if !matches!(
            refusing.sending.managed.connections.recovery(&peer),
            Recovery::Exhausted { .. }
        ) {
            return Err(format!(
                "the episode is not used up after {RECOVERY_DIALS} connections that carried only \
                 a refused offer: the pair reads `{}`",
                refusing.sending.managed.connections.recovery(&peer)
            ));
        }
        keeper.abort();
        // Half two: a dialled connection that moved a byte is not a strike, and its loss is
        // re-dialled at once.
        let carrying = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = carrying.clone();
        let second = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&second)?;
        let peer = second.receiver.peer_id();
        let keeper = spawn_keeper(&second.sending.managed, &second.receiver);
        let first =
            connection::wait_connected(&sim, &second.sending.managed.connections, &peer, None)
                .await?;
        let file = Generated::new("a-carried.bin", FILE_BYTES);
        let transfer = offer(&second, &file)?;
        let state = drive_transfer(&sim, BUDGET, &transfer).await?;
        ended(state, TransferState::Finished { bytes: FILE_BYTES })?;
        if !second.sending.managed.connections.disconnect(&peer) {
            return Err("the pair had no live connection to close".to_owned());
        }
        redialled_without_a_strike(&sim, &second, first.stable_id(), "a whole file").await?;
        keeper.abort();
        // Half three: a transfer that moved bytes and then failed is the same use of the pair.
        let failing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = failing.clone();
        let third = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&third)?;
        let peer = third.receiver.peer_id();
        let keeper = spawn_keeper(&third.sending.managed, &third.receiver);
        let first =
            connection::wait_connected(&sim, &third.sending.managed.connections, &peer, None)
                .await?;
        let file = Generated::new("a-failed-halfway.bin", FILE_BYTES);
        // The source dies at the second chunk, so the first one is on the wire before the
        // transfer ends: the sending side's own answer, and its own bytes moved.
        file.fail_at(CHUNK);
        let transfer = offer(&third, &file)?;
        let state = drive_transfer(&sim, BUDGET, &transfer).await?;
        failed(state, TransferFailure::SourceUnreadable)?;
        if failing.held_bytes(&third.sender.peer_id(), file.name()) != CHUNK {
            return Err(format!(
                "the sink holds {} bytes of a transfer whose source failed at {CHUNK}",
                failing.held_bytes(&third.sender.peer_id(), file.name())
            ));
        }
        if !third.sending.managed.connections.disconnect(&peer) {
            return Err("the pair had no live connection to close".to_owned());
        }
        redialled_without_a_strike(&sim, &third, first.stable_id(), "a byte and then a failure")
            .await?;
        keeper.abort();
        // Half four: the same use while the attempt is still in flight. The sink takes one chunk
        // and then answers "not now", so the attempt holds its round through the verdict wait —
        // the connection dies with a round open and bytes already on the wire, which is a strike
        // only if the keeper judges the round rather than what the pair did with it.
        let moving = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = moving.clone();
        let fourth = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&fourth)?;
        let peer = fourth.receiver.peer_id();
        let keeper = spawn_keeper(&fourth.sending.managed, &fourth.receiver);
        let first =
            connection::wait_connected(&sim, &fourth.sending.managed.connections, &peer, None)
                .await?;
        // A file past one stream window, into a sink that takes nothing: the sending side fills
        // the window and parks in the write after it, so the attempt is still in flight with
        // megabytes on the wire.
        let file = Generated::new("a-still-arriving.bin", PAST_A_WINDOW);
        moving.stop_accepting();
        let transfer = offer(&fourth, &file)?;
        // Half the window is enough to say the attempt is in flight with real bytes on the wire;
        // how much of the window the transport actually grants is its own business.
        let half = u64::try_from(MAX_STREAM_BYTES).expect("eight mebibytes fit a u64") / 2;
        advance_until(
            &sim,
            BUDGET,
            Duration::from_millis(100),
            || matches!(transfer.state(), TransferState::Running { moved, .. } if moved >= half),
        )
        .await
        .map_err(|why| {
            format!(
                "{why}: the sender reads `{:?}` of a file that fills its window",
                transfer.state()
            )
        })?;
        // The pair has been used while the attempt is still in flight: the bytes on the wire are
        // on the connection's own count before the attempt ends.
        let traffic = fourth
            .sending
            .managed
            .connections
            .traffic(&peer)
            .ok_or("the pair holds no live connection to read")?;
        if traffic.taken() == 0 {
            return Err(format!(
                "a connection with {half} bytes of a file on the wire counted no use of the pair"
            ));
        }
        if !fourth.sending.managed.connections.disconnect(&peer) {
            return Err("the pair had no live connection to close".to_owned());
        }
        redialled_without_a_strike(&sim, &fourth, first.stable_id(), "a byte mid-attempt").await?;
        keeper.abort();
        transfer.stop();
        Ok(())
    })
}

/// Wait until the pair holds a connection other than `first`, and refuse if a strike was counted
/// on the way.
///
/// A strike would leave a wait of at least a gap behind it, so a sampling pass over the whole
/// recovery would have seen it; what the pair must show instead is a new connection with no
/// counted dial in between. `carried` names what the connection that went away had moved, for
/// the failure a case that saw a strike is worth.
async fn redialled_without_a_strike(
    sim: &Sim,
    duo: &Duo,
    first: usize,
    carried: &str,
) -> Result<(), String> {
    let connections = &duo.sending.managed.connections;
    let peer = duo.receiver.peer_id();
    let mut struck = None;
    advance_until(sim, BUDGET, Duration::from_millis(100), || {
        if struck.is_none() {
            match connections.recovery(&peer) {
                Recovery::Waiting {
                    dial,
                    last: Some(_),
                    ..
                } if dial >= 1 => struck = Some(connections.recovery(&peer)),
                Recovery::Exhausted { .. } => struck = Some(connections.recovery(&peer)),
                _ => {}
            }
        }
        connections
            .live(&peer)
            .is_some_and(|live| live.stable_id() != first)
    })
    .await
    .map_err(|why| format!("{why}: the pair did not dial again after a transfer carried bytes"))?;
    if let Some(state) = struck {
        return Err(format!(
            "a connection that carried {carried} was counted as a dial that carried nothing: \
             the pair read `{state}`"
        ));
    }
    Ok(())
}

/// A transfer to a pair that is down makes the manager dial.
///
/// The two records hold the pairing and no address, so the beacon is the only way to find the
/// peer. Offering a file is a reason to dial, through the same recovery machinery the message
/// queue uses: the pair stops reading `unwatched` and a dial is due at once. A second offer
/// while the episode is under way joins that episode rather than starting a fresh one, and both
/// transfers finish once the peer is findable.
pub(crate) fn a_transfer_causes_a_dial() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (sender, receiver) = paired_without_addresses(&sim)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = wire_pair(
            &sim,
            &beacon,
            sender,
            receiver,
            Files::sending(),
            Files::taking(sink),
            Arc::new(NoFloor),
        )?;
        allow_files(&duo)?;
        let peer = duo.receiver.peer_id();
        // Nothing has dialled for the pair, and the state says exactly that.
        if duo.sending.managed.connections.recovery(&peer) != Recovery::Unwatched {
            return Err(format!(
                "a pair no transfer has been offered to reads `{}`, not unwatched",
                duo.sending.managed.connections.recovery(&peer)
            ));
        }
        // The peer is not registered, so the first dial meets a beacon that does not know it.
        let first = Generated::new("a-dialled-one.bin", FILE_BYTES);
        let one = offer(&duo, &first)?;
        let mut dialled = None;
        for _ in 0..YIELDS * 4 {
            let state = duo.sending.managed.connections.recovery(&peer);
            let now = sim.clock().now();
            match &state {
                // A dial in flight is the state the offer caused.
                Recovery::Dialling { .. } | Recovery::Connected => {
                    dialled = Some(state.clone());
                    break;
                }
                // A dial that has already run and failed: the wait it earned is its own.
                Recovery::Waiting { dial, .. } if *dial >= 1 => {
                    dialled = Some(state.clone());
                    break;
                }
                // A wait nobody earned is a dial due at once, which is the same answer.
                Recovery::Waiting { until, .. } if *until <= now => {
                    dialled = Some(state.clone());
                    break;
                }
                _ => {}
            }
            tokio::task::yield_now().await;
        }
        if dialled.is_none() {
            return Err(format!(
                "offering a file to a pair that is down left the pair `{}`: nothing dialled",
                duo.sending.managed.connections.recovery(&peer)
            ));
        }
        // Wait for the first dial to have failed: the beacon does not know the peer, so the
        // episode counts it and names what it met.
        advance_until(&sim, BUDGET, Duration::from_millis(100), || {
            matches!(
                duo.sending.managed.connections.recovery(&peer),
                Recovery::Waiting {
                    dial,
                    last: Some(_),
                    ..
                } if dial >= 1
            )
        })
        .await
        .map_err(|why| {
            format!(
                "{why}: the first dial ended as `{}`",
                duo.sending.managed.connections.recovery(&peer)
            )
        })?;
        let Recovery::Waiting { dial: counted, .. } =
            duo.sending.managed.connections.recovery(&peer)
        else {
            return Err(format!(
                "the episode reads `{}` after its first dial",
                duo.sending.managed.connections.recovery(&peer)
            ));
        };
        // A second offer, with the episode under way, joins it: the count does not go back to
        // the first dial of a fresh run.
        let second = Generated::new("a-dialled-two.bin", FILE_BYTES);
        let two = offer(&duo, &second)?;
        for _ in 0..YIELDS {
            tokio::task::yield_now().await;
        }
        let Recovery::Waiting {
            dial: after_second, ..
        } = duo.sending.managed.connections.recovery(&peer)
        else {
            return Err(format!(
                "a second offer left the pair `{}`, not the episode it was in",
                duo.sending.managed.connections.recovery(&peer)
            ));
        };
        if after_second < counted {
            return Err(format!(
                "a second offer restarted the episode: the pair reads dial {after_second} of \
                 {counted} it had reached"
            ));
        }
        // The peer keeps itself findable, and the next dial of the same episode reaches it.
        let _findable = keep_findable(&sim, &beacon, &duo.receiver).await?;
        let state = drive_transfer_in(&sim, BUDGET, Duration::from_secs(1), &one).await?;
        ended(state, TransferState::Finished { bytes: FILE_BYTES })?;
        let state = drive_transfer_in(&sim, BUDGET, Duration::from_secs(1), &two).await?;
        ended(state, TransferState::Finished { bytes: FILE_BYTES })?;
        if let Recovery::Dialling { .. } = duo.sending.managed.connections.recovery(&peer) {
            return Err("the pair is still dialling with both transfers finished".to_owned());
        }
        Ok(())
    })
}

/// One offer frame's bytes, as this build writes them: the magic, the version, the body's
/// length and the name, the length and the digest.
fn offer_bytes(name: &TransferName, length: u64, digest: &Digest) -> Vec<u8> {
    offer_fields(name.as_str().as_bytes(), length, digest)
}

/// The same, for the offers a case writes by hand: the name is whatever bytes it names, which
/// is how an offer with an empty name is built.
fn offer_fields(name: &[u8], length: u64, digest: &Digest) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&field(0x01, name));
    body.extend_from_slice(&field(0x02, &length.to_be_bytes()));
    body.extend_from_slice(&field(0x03, digest.as_bytes()));
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"mahbot-peer-transfer");
    bytes.push(1);
    bytes.extend_from_slice(
        &u32::try_from(body.len())
            .expect("an offer is far below four gibibytes")
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&body);
    bytes
}

/// One answer frame's bytes, with `body` as its fields: the frame a raw receiving side writes.
fn answer_frame(body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"mahbot-peer-transfer-answer");
    bytes.push(1);
    bytes.extend_from_slice(
        &u32::try_from(body.len())
            .expect("an answer is far below four gibibytes")
            .to_be_bytes(),
    );
    bytes.extend_from_slice(body);
    bytes
}

/// A raw receiving side: a transport with no layer under it.
///
/// Every accepted connection answers the binding exchange — the first stream a kept connection
/// carries — and then runs `body` for that connection, which is where a case says what the peer
/// answers. Nothing here decides anything or reads anything into an offer, which is what lets a
/// case answer with a frame this build's receiver would never write.
fn raw_side<F, Fut>(machine: &Machine, body: F) -> Result<tokio::task::JoinHandle<()>, String>
where
    F: Fn(quinn::Connection) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let endpoint = machine.endpoint().map_err(|error| error.to_string())?;
    Ok(tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let Ok(connecting) = incoming.accept() else {
                continue;
            };
            let Ok(connection) = connecting.await else {
                continue;
            };
            tokio::spawn(body(connection));
        }
    }))
}

/// Answer the binding exchange, which owns the first stream a kept connection carries: the fact
/// is a few labels and a moment, far inside this bound.
async fn answer_exchange(connection: &quinn::Connection) {
    if let Ok((mut send, mut recv)) = connection.accept_bi().await {
        let _ = recv.read_to_end(1024).await;
        let _ = send.finish();
    }
}

/// Read an offer's opening bytes: what it says is the receiving layer's business, and this side
/// has none.
async fn read_offer(recv: &mut quinn::RecvStream) {
    let mut offer = [0u8; 512];
    let _ = recv.read(&mut offer).await;
}

/// A raw receiving side that answers each offer with the next of `answers`, the last repeating,
/// and nothing else.
fn raw_receiver(
    machine: &Machine,
    answers: Vec<Vec<u8>>,
) -> Result<tokio::task::JoinHandle<()>, String> {
    raw_side(machine, move |connection| {
        let answers = answers.clone();
        async move {
            answer_exchange(&connection).await;
            let mut answers = answers.into_iter();
            let mut last = Vec::new();
            while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                read_offer(&mut recv).await;
                let answer = answers.next().unwrap_or_else(|| last.clone());
                last = answer.clone();
                let _ = send.write_all(&answer).await;
                let _ = send.finish();
            }
        }
    })
}

/// A raw receiving side that resumes a transfer, reads its bytes, and then repeats one progress
/// word on the same stream, as a peer that keeps stating an offset it has already stated does.
///
/// The words go on until the sending side stops reading, one turn apart so the peer does not
/// starve the runtime: the sending side reads one per look, so a transfer that counted a repeated
/// offset as progress would spend a second of its own bound on each of them, for ever.
fn raw_repeating_receiver(
    machine: &Machine,
    resume: Vec<u8>,
    word: Vec<u8>,
    repeats: usize,
) -> Result<tokio::task::JoinHandle<()>, String> {
    raw_side(machine, move |connection| {
        let resume = resume.clone();
        let word = word.clone();
        async move {
            answer_exchange(&connection).await;
            while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                read_offer(&mut recv).await;
                if send.write_all(&resume).await.is_err() {
                    continue;
                }
                // The file's bytes, so the sending side is never parked on them.
                while let Ok(Some(_)) = recv.read_chunk(TRANSFER_CHUNK, true).await {}
                // The same word, for as long as the sending side keeps reading: the stream
                // stays open, so a transfer that counted a repeated offset as progress would
                // hold itself, and one of this machine's places for the peer, for ever.
                for _ in 0..repeats {
                    if send.write_all(&word).await.is_err() {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            }
        }
    })
}

/// A raw receiving side that loses the first offer, states a growing offset for the next
/// `offers`, and then takes the file.
fn raw_growing_receiver(
    machine: &Machine,
    offers: usize,
) -> Result<tokio::task::JoinHandle<()>, String> {
    raw_side(machine, move |connection| async move {
        answer_exchange(&connection).await;
        let mut seen = 0usize;
        while let Ok((mut send, mut recv)) = connection.accept_bi().await {
            read_offer(&mut recv).await;
            seen += 1;
            if seen == 1 {
                // Nothing at all: a lost attempt.
                let _ = send.finish();
                continue;
            }
            let have = u64::try_from(seen).expect("a count") * 1024;
            if seen <= offers {
                // Status 2 is `running`, 0x02 how far this side has got: one kibibyte
                // further than last time, every time.
                let answer =
                    answer_frame(&[field(0x01, &[2]), field(0x02, &have.to_be_bytes())].concat());
                if send.write_all(&answer).await.is_err() {
                    continue;
                }
                let _ = send.finish();
                continue;
            }
            // It takes the file: status 11 is `resume` from where it last said it had got
            // to, then every byte, then status 12, `complete`.
            let answer =
                answer_frame(&[field(0x01, &[11]), field(0x02, &have.to_be_bytes())].concat());
            if send.write_all(&answer).await.is_err() {
                continue;
            }
            while let Ok(Some(_)) = recv.read_chunk(TRANSFER_CHUNK, true).await {}
            let _ = send.write_all(&answer_frame(&field(0x01, &[12]))).await;
            let _ = send.finish();
        }
    })
}

/// How a raw receiving side that says nothing ends the stream it was offered.
#[derive(Clone, Copy)]
enum Silence {
    /// Held open: the offer hangs until the sending side's own answer budget runs out, so the
    /// attempt is one that produced no answer after half a minute.
    Hold,
    /// Finished at once: the sending side reads a lost attempt, so the round costs the retry pause
    /// and no budget — which is what makes the pause measurable.
    End,
}

/// The one offer a mostly-silent peer answers instead of finishing it.
#[derive(Clone)]
struct OneAnswer {
    /// Which offer, counting from one on the connection.
    offer: usize,
    /// The bytes written back before the stream is finished.
    bytes: Vec<u8>,
}

/// A raw receiving side that answers the exchange, reads every offer, and says nothing at all —
/// except on the offer named in `answer`, which it answers with those bytes before finishing.
///
/// `offers` records when each one arrived, on the case's own clock: a case that reads the gaps
/// between them is reading the wait the sender keeps between attempts. An answer on one of them is
/// a pair that is there, which is what a case about the retry wait needs beside a silent one.
fn raw_mostly_silent_receiver(
    machine: &Machine,
    clock: &MockClock,
    silence: Silence,
    answer: Option<OneAnswer>,
    offers: Arc<Mutex<Vec<Duration>>>,
) -> Result<tokio::task::JoinHandle<()>, String> {
    let clock = clock.clone();
    raw_side(machine, move |connection| {
        let clock = clock.clone();
        let offers = Arc::clone(&offers);
        let answer = answer.clone();
        async move {
            answer_exchange(&connection).await;
            // Held, not dropped: a stream dropped here would be finished, and a finished stream
            // is an answer — silence is what this side is for.
            let mut held = Vec::new();
            let mut seen = 0usize;
            while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                read_offer(&mut recv).await;
                seen += 1;
                offers
                    .lock()
                    .expect("the offer times are not poisoned")
                    .push(clock.elapsed());
                match answer.as_ref().filter(|one| one.offer == seen) {
                    Some(one) => {
                        let _ = send.write_all(&one.bytes).await;
                        let _ = send.finish();
                    }
                    None => match silence {
                        Silence::Hold => held.push(send),
                        Silence::End => {
                            let _ = send.finish();
                        }
                    },
                }
            }
        }
    })
}

/// A raw receiving side that loses the first offer and then answers every later one with the same
/// `running` offset, `after` of the case's own clock later.
///
/// The delay is what makes one attempt long: a transfer that charges only the pause between
/// attempts spends one second a round and outlives its own bound sixty times over, while one
/// that charges the attempt itself reaches that bound in a handful of them. What comes back is
/// how many offers the peer answered, which is the count a case reads.
fn raw_slow_repeating_receiver(
    machine: &Machine,
    clock: &MockClock,
    after: Duration,
    offers: Arc<AtomicUsize>,
) -> Result<tokio::task::JoinHandle<()>, String> {
    let clock = clock.clone();
    let answered = offers;
    raw_side(machine, move |connection| {
        let clock = clock.clone();
        let answered = Arc::clone(&answered);
        async move {
            answer_exchange(&connection).await;
            let mut first = true;
            while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                read_offer(&mut recv).await;
                if first {
                    first = false;
                    // Nothing at all: a lost attempt, so the next offer is a retry and a
                    // `running` answer is this machine's own transfer under the name.
                    let _ = send.finish();
                    continue;
                }
                // Status 2 is `running`, 0x02 how far this side has got — the same zero every
                // time, which is what a peer that is not moving says.
                let word =
                    answer_frame(&[field(0x01, &[2]), field(0x02, &0u64.to_be_bytes())].concat());
                let answered = Arc::clone(&answered);
                clock.schedule(after, move || {
                    tokio::spawn(async move {
                        let mut send = send;
                        answered.fetch_add(1, Ordering::SeqCst);
                        let _ = send.write_all(&word).await;
                        let _ = send.finish();
                    });
                });
            }
        }
    })
}

/// A raw receiving side that loses the first `lost` offers, takes the transfer once — `resume` at
/// zero, every byte read — and then answers that transfer and every later offer with `throttle`.
fn raw_throttling_receiver(
    machine: &Machine,
    throttle: Vec<u8>,
    lost: usize,
) -> Result<tokio::task::JoinHandle<()>, String> {
    raw_side(machine, move |connection| {
        let throttle = throttle.clone();
        async move {
            answer_exchange(&connection).await;
            let mut first = true;
            let mut lost = lost;
            while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                read_offer(&mut recv).await;
                if lost > 0 {
                    lost -= 1;
                    // Nothing at all: an offer the pair did not answer.
                    let _ = send.finish();
                    continue;
                }
                if first {
                    first = false;
                    // Status 11 is `resume` at zero, and every byte is read: the throttle
                    // then lands on a transfer the pair has taken, not in place of taking it.
                    let resume = answer_frame(
                        &[field(0x01, &[11]), field(0x02, &0u64.to_be_bytes())].concat(),
                    );
                    if send.write_all(&resume).await.is_err() {
                        continue;
                    }
                    while let Ok(Some(_)) = recv.read_chunk(TRANSFER_CHUNK, true).await {}
                }
                let _ = send.write_all(&throttle).await;
                let _ = send.finish();
            }
        }
    })
}

/// A raw receiving side that throttles `rounds` times, stating an offset further than the last
/// every time, and then takes the file.
///
/// Each of the first `rounds` offers is answered `resume` at zero, its bytes are read, and the
/// stream is then given a `running` answer one `growth` further than the last and the throttle the
/// case names. The offer after them is taken: `resume` at zero, every byte, `complete`.
fn raw_growing_throttle_receiver(
    machine: &Machine,
    rounds: usize,
    growth: u64,
    throttle: Vec<u8>,
) -> Result<tokio::task::JoinHandle<()>, String> {
    raw_side(machine, move |connection| {
        let throttle = throttle.clone();
        async move {
            answer_exchange(&connection).await;
            let mut rounds = rounds;
            let mut have = 0u64;
            while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                read_offer(&mut recv).await;
                // Status 11 is `resume` at zero: this side has nothing yet, and the bytes follow.
                let resume =
                    answer_frame(&[field(0x01, &[11]), field(0x02, &0u64.to_be_bytes())].concat());
                if send.write_all(&resume).await.is_err() {
                    continue;
                }
                while let Ok(Some(_)) = recv.read_chunk(TRANSFER_CHUNK, true).await {}
                if rounds == 0 {
                    // Status 12 is `complete`: the file is there.
                    let _ = send.write_all(&answer_frame(&field(0x01, &[12]))).await;
                    let _ = send.finish();
                    continue;
                }
                rounds -= 1;
                have += growth;
                // Status 2 is `running`, 0x02 how far this side has got: further than last time.
                let running =
                    answer_frame(&[field(0x01, &[2]), field(0x02, &have.to_be_bytes())].concat());
                let _ = send.write_all(&running).await;
                let _ = send.write_all(&throttle).await;
                let _ = send.finish();
            }
        }
    })
}

/// A raw receiving side that writes its answer in two halves `gap` apart, then takes the file.
///
/// The gap is longer than the poll the sending side reads an answer in, so the look runs out with
/// the frame half written; the split is the frame's last byte, so a look that started over would
/// read a body byte where the answer's magic should be.
fn raw_split_answer_receiver(
    machine: &Machine,
    clock: &MockClock,
    gap: Duration,
) -> Result<tokio::task::JoinHandle<()>, String> {
    let clock = clock.clone();
    raw_side(machine, move |connection| {
        let clock = clock.clone();
        async move {
            answer_exchange(&connection).await;
            while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                read_offer(&mut recv).await;
                // Status 11 is `resume` at zero: this side has nothing yet.
                let resume =
                    answer_frame(&[field(0x01, &[11]), field(0x02, &0u64.to_be_bytes())].concat());
                let (head, tail) = resume.split_at(resume.len() - 1);
                let tail = tail.to_vec();
                if send.write_all(head).await.is_err() {
                    continue;
                }
                clock.schedule(gap, move || {
                    tokio::spawn(async move {
                        let mut send = send;
                        let _ = send.write_all(&tail).await;
                        while let Ok(Some(_)) = recv.read_chunk(TRANSFER_CHUNK, true).await {}
                        // Status 12 is `complete`: the file is there.
                        let _ = send.write_all(&answer_frame(&field(0x01, &[12]))).await;
                        let _ = send.finish();
                    });
                });
            }
        }
    })
}

/// A raw receiving side that resumes at zero, reads every byte, and answers `complete` only once
/// the case's own clock has moved `after` further.
///
/// The wait is the clock's, not the task's: the clock fires the write, so the peer costs no
/// scheduler turns while it waits.
fn raw_late_verdict(
    machine: &Machine,
    clock: &MockClock,
    after: Duration,
) -> Result<tokio::task::JoinHandle<()>, String> {
    let clock = clock.clone();
    raw_side(machine, move |connection| {
        let clock = clock.clone();
        async move {
            answer_exchange(&connection).await;
            while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                read_offer(&mut recv).await;
                // Status 11 is `resume` at zero: this side has nothing yet.
                let resume =
                    answer_frame(&[field(0x01, &[11]), field(0x02, &0u64.to_be_bytes())].concat());
                if send.write_all(&resume).await.is_err() {
                    continue;
                }
                while let Ok(Some(_)) = recv.read_chunk(TRANSFER_CHUNK, true).await {}
                // Every byte is in, and the verdict waits: where it lands is the case's. Status
                // 12 is `complete`.
                let verdict = answer_frame(&field(0x01, &[12]));
                clock.schedule(after, move || {
                    tokio::spawn(async move {
                        let mut send = send;
                        let _ = send.write_all(&verdict).await;
                        let _ = send.finish();
                    });
                });
            }
        }
    })
}

/// A raw receiving side that loses `lost` offers, answers the next one `running` at zero, and then
/// writes `throttle` on that stream and on every later one.
///
/// The `running` answer is what the case is about: it is an answer, though not one that takes the
/// file, and it is what tells a throttle met afterwards that the window it met is the pair's
/// pacing rather than this machine's own unanswered offers.
fn raw_running_then_throttling_receiver(
    machine: &Machine,
    lost: usize,
    throttle: Vec<u8>,
) -> Result<tokio::task::JoinHandle<()>, String> {
    raw_side(machine, move |connection| {
        let throttle = throttle.clone();
        async move {
            answer_exchange(&connection).await;
            let mut lost = lost;
            let mut answered = false;
            while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                read_offer(&mut recv).await;
                if lost > 0 {
                    lost -= 1;
                    // Nothing at all: an offer the pair did not answer.
                    let _ = send.finish();
                    continue;
                }
                if !answered {
                    answered = true;
                    // Status 2 is `running`, 0x02 how far this side has got: an answer that
                    // says nothing was taken.
                    let running = answer_frame(
                        &[field(0x01, &[2]), field(0x02, &0u64.to_be_bytes())].concat(),
                    );
                    if send.write_all(&running).await.is_err() {
                        continue;
                    }
                }
                let _ = send.write_all(&throttle).await;
                let _ = send.finish();
            }
        }
    })
}

/// A raw receiving side that answers the exchange and then answers every offer `running` at zero.
///
/// Each accepted stream is read and answered on a task of its own: a case that holds streams open
/// on the same connection makes this side accept them too, and a side that answered them one after
/// another would park on the first held stream and never read the offer behind it.
fn raw_running_receiver(machine: &Machine) -> Result<tokio::task::JoinHandle<()>, String> {
    raw_side(machine, |connection| async move {
        answer_exchange(&connection).await;
        while let Ok((mut send, mut recv)) = connection.accept_bi().await {
            tokio::spawn(async move {
                read_offer(&mut recv).await;
                // Status 2 is `running` at zero: a transfer under this name is running here.
                let running =
                    answer_frame(&[field(0x01, &[2]), field(0x02, &0u64.to_be_bytes())].concat());
                let _ = send.write_all(&running).await;
                let _ = send.finish();
            });
        }
    })
}

/// A raw receiving side that takes each transfer, reads one chunk of it, and only then — `after`
/// of the case's own clock later — answers `store failed` and finishes the stream.
///
/// It reads nothing further and holds the receiving half open, so the sender's writes fill the
/// stream window and park: the answer lands on a sending side that has been waiting on a write for
/// its whole bound, which is where a receiving machine's own worst honest silence ends.
fn raw_late_store_failure(
    machine: &Machine,
    clock: &MockClock,
    after: Duration,
) -> Result<tokio::task::JoinHandle<()>, String> {
    let clock = clock.clone();
    raw_side(machine, move |connection| {
        let clock = clock.clone();
        async move {
            answer_exchange(&connection).await;
            while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                read_offer(&mut recv).await;
                // Status 11 is `resume` at zero: this side has nothing yet.
                let resume =
                    answer_frame(&[field(0x01, &[11]), field(0x02, &0u64.to_be_bytes())].concat());
                if send.write_all(&resume).await.is_err() {
                    continue;
                }
                // One chunk and no more: the sender's writes then fill the window and park.
                let _ = recv.read_chunk(TRANSFER_CHUNK, true).await;
                // Status 8 is `store failed`: the sink spent its own bound and gave up.
                let verdict = answer_frame(&field(0x01, &[8]));
                clock.schedule(after, move || {
                    tokio::spawn(async move {
                        // The receive half is moved in and only dropped when this task ends:
                        // dropping it earlier sends STOP_SENDING, which unparks the writer and
                        // moves the case into the verdict after the bytes instead of the one
                        // parked on a write.
                        let _held = recv;
                        let mut send = send;
                        let _ = send.write_all(&verdict).await;
                        let _ = send.finish();
                    });
                });
            }
        }
    })
}

/// A raw receiving side that spends most of the stall bound before it states an offset, then states
/// one in an attempt it throttles, and states the same offset in every later answer.
///
/// Its first `plain` offers are rounds that get the file no further and are charged to the stall
/// bound: the first is answered `resume` at zero and the stream is finished at once, and each of
/// the rest is answered `running` at zero `late` of the case's clock after it arrives. The offer
/// after them is answered `resume` at zero, then `running` at `offset`, then `throttle`, on one
/// stream — the offset is stated in an attempt that ends in a throttle — and every later offer is
/// answered `running` at the same `offset`. A transfer that forgot the offset the throttled
/// attempt stated would read the first restatement as growth and clear the bound those rounds had
/// spent.
///
/// `parked` chooses where the throttle is read: with it nothing is read from the stream, so the
/// sender's writes fill the window and the words are read by the write loop; without it every byte
/// is read first, so they are read in the verdict after the bytes.
fn raw_offset_then_throttle_receiver(
    machine: &Machine,
    clock: &MockClock,
    plain: usize,
    late: Duration,
    offset: u64,
    throttle: Vec<u8>,
    parked: bool,
) -> Result<tokio::task::JoinHandle<()>, String> {
    let clock = clock.clone();
    raw_side(machine, move |connection| {
        let clock = clock.clone();
        let throttle = throttle.clone();
        async move {
            answer_exchange(&connection).await;
            let mut plain = plain;
            // Whether any offer of this transfer has been answered: the first round has to be a
            // resume, because a `running` answer before any offer of this transfer left would end
            // it as already running.
            let mut answered = false;
            // Whether the throttle round has happened: every offer after it is answered `running`
            // at `offset`.
            let mut throttled = false;
            // Receive halves held open, so a write parked on one stays parked while the words
            // arrive: dropping one sends STOP_SENDING, which unparks the writer.
            let mut held: Vec<quinn::RecvStream> = Vec::new();
            while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                read_offer(&mut recv).await;
                if plain > 0 {
                    plain -= 1;
                    if !answered {
                        // A resume with the stream finished at once: it costs the sender no bytes
                        // and is charged its pause alone. Status 11 is `resume` at zero.
                        answered = true;
                        let resume = answer_frame(
                            &[field(0x01, &[11]), field(0x02, &0u64.to_be_bytes())].concat(),
                        );
                        let _ = send.write_all(&resume).await;
                        let _ = send.finish();
                        continue;
                    }
                    // Status 2 is `running` at zero, `late` of the case's clock after the offer:
                    // the round is answered and gets the file no further, and the stall bound is
                    // spent on it at the rate a real receiving machine would spend it.
                    let running = answer_frame(
                        &[field(0x01, &[2]), field(0x02, &0u64.to_be_bytes())].concat(),
                    );
                    clock.schedule(late, move || {
                        tokio::spawn(async move {
                            let mut send = send;
                            let _ = send.write_all(&running).await;
                            let _ = send.finish();
                        });
                    });
                    continue;
                }
                let running =
                    answer_frame(&[field(0x01, &[2]), field(0x02, &offset.to_be_bytes())].concat());
                if throttled {
                    let _ = send.write_all(&running).await;
                    let _ = send.finish();
                    continue;
                }
                throttled = true;
                // Status 11 is `resume` at zero: the bytes then follow.
                let resume =
                    answer_frame(&[field(0x01, &[11]), field(0x02, &0u64.to_be_bytes())].concat());
                if send.write_all(&resume).await.is_err() {
                    continue;
                }
                if parked {
                    // Held open, so the sender's write stays parked while the words arrive.
                    held.push(recv);
                } else {
                    // Every byte in, so the sender is in its verdict when the words arrive.
                    while let Ok(Some(_)) = recv.read_chunk(TRANSFER_CHUNK, true).await {}
                }
                if send.write_all(&running).await.is_err() {
                    continue;
                }
                let _ = send.write_all(&throttle).await;
                let _ = send.finish();
            }
        }
    })
}

/// `batch` bytes of the file every `step` of the case's clock, and nothing said about them.
///
/// A batch rather than a chunk because the transport returns flow-control credit in large steps: a
/// peer that reads a chunk at a time out of a window eight mebibytes wide is given no credit back
/// until it has taken half of it, so a case that has to keep the sender's writes moving between two
/// long silences has to take a batch that size.
fn drain(clock: MockClock, mut recv: quinn::RecvStream, batch: u64, step: Duration) {
    clock.clone().schedule(step, move || {
        tokio::spawn(async move {
            let mut buffer = vec![0u8; TRANSFER_CHUNK];
            let mut read = 0u64;
            while read < batch {
                match recv.read(&mut buffer).await {
                    Ok(Some(count)) => {
                        read += u64::try_from(count).expect("a read is far below a u64");
                    }
                    _ => return,
                }
            }
            drain(clock, recv, batch, step);
        });
    });
}

/// A raw receiving side that resumes at zero and then takes `batch` bytes of the file every `step`
/// of the case's clock, saying nothing at all about them.
///
/// The send halves are held for the life of the connection: a dropped one resets the stream, which
/// would end the sending side's attempt for a reason this case is not measuring. What the sender
/// sees is a peer that takes the bytes it is handed and never states an offset, which is not the
/// file getting further.
fn raw_slow_drain(
    machine: &Machine,
    clock: &MockClock,
    batch: u64,
    step: Duration,
) -> Result<tokio::task::JoinHandle<()>, String> {
    let clock = clock.clone();
    raw_side(machine, move |connection| {
        let clock = clock.clone();
        async move {
            answer_exchange(&connection).await;
            let mut held = Vec::new();
            while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                read_offer(&mut recv).await;
                // Status 11 is `resume` at zero: this side has nothing yet.
                let resume =
                    answer_frame(&[field(0x01, &[11]), field(0x02, &0u64.to_be_bytes())].concat());
                if send.write_all(&resume).await.is_err() {
                    continue;
                }
                drain(clock.clone(), recv, batch, step);
                held.push(send);
            }
        }
    })
}

/// The status and the two limit fields of one answer frame, as the wire carries them.
fn answer_fields(bytes: &[u8]) -> Result<AnswerFields, String> {
    let rest = bytes
        .strip_prefix(b"mahbot-peer-transfer-answer")
        .ok_or("the answer does not open with a transfer answer's magic")?;
    let (&version, rest) = rest
        .split_first()
        .ok_or("the answer ends after its magic")?;
    if version != 1 {
        return Err(format!("the answer names version {version}, not one"));
    }
    let (length, rest) = rest
        .split_first_chunk::<4>()
        .ok_or("the answer states no body length")?;
    let length = usize::try_from(u32::from_be_bytes(*length)).expect("a body is far below 4 GiB");
    let mut body = rest
        .get(..length)
        .ok_or("the answer is shorter than the body length it states")?;
    let mut fields = AnswerFields {
        status: 0,
        offset: None,
        retry_after: None,
        which: None,
    };
    let mut seen_status = false;
    while !body.is_empty() {
        let (&tag, after_tag) = body.split_first().ok_or("a field has no tag")?;
        let (length, after_length) = after_tag
            .split_first_chunk::<2>()
            .ok_or("a field has no length")?;
        let length = usize::from(u16::from_be_bytes(*length));
        let (value, after) = after_length
            .split_at_checked(length)
            .ok_or("a field runs past the answer's body")?;
        match tag {
            0x01 => {
                fields.status = *value.first().ok_or("the status field is empty")?;
                seen_status = true;
            }
            0x02 => {
                let bytes: [u8; 8] = value
                    .try_into()
                    .map_err(|_| "the offset field is not eight bytes")?;
                fields.offset = Some(u64::from_be_bytes(bytes));
            }
            0x03 => {
                let seconds: [u8; 4] = value
                    .try_into()
                    .map_err(|_| "the retry field is not four bytes")?;
                fields.retry_after = Some(u32::from_be_bytes(seconds));
            }
            0x04 => fields.which = value.first().copied(),
            _ => {}
        }
        body = after;
    }
    if !seen_status {
        return Err("the answer carries no status field".to_owned());
    }
    Ok(fields)
}

/// The refusal entries the receiving machine's log holds for a file it would not take.
fn refusals(machine: &Machine) -> Result<u64, String> {
    let entries = machine
        .audit()?
        .entries()
        .map_err(|error| error.to_string())?;
    let refusals = entries
        .iter()
        .filter(|entry| {
            matches!(
                &entry.act,
                Act::Refused { capability, .. } if *capability == Capability::PUT_FILES
            )
        })
        .count();
    Ok(u64::try_from(refusals).expect("an entry count is far below a u64"))
}

/// How many entries the receiving machine's log holds for an authorised transfer.
fn allowed_transfers(machine: &Machine) -> Result<usize, String> {
    let entries = machine
        .audit()?
        .entries()
        .map_err(|error| error.to_string())?;
    Ok(entries
        .iter()
        .filter(|entry| matches!(entry.act, Act::TransferAllowed { .. }))
        .count())
}

/// A sending machine with a transfer layer and a peer that is a transport and nothing more.
///
/// The pair is recorded on both sides and the manager is started, so the sending machine can
/// offer; the raw peer accepts the connection, answers the binding exchange, and answers each
/// offer with the next of `answers` and finishes the stream. That is the state a case needs when
/// it has to control the receiving machine's own words — a status no build writes, a throttle, a
/// resume that goes nowhere.
async fn raw_pair(sim: &Sim, beacon: &TestBeacon, answers: Vec<Vec<u8>>) -> Result<Raw, String> {
    raw_pair_with(sim, beacon, move |receiver| raw_receiver(receiver, answers)).await
}

/// The same pair, with the raw peer a case supplies rather than one answering from a list.
async fn raw_pair_with(
    sim: &Sim,
    beacon: &TestBeacon,
    peer: impl FnOnce(&Machine) -> Result<tokio::task::JoinHandle<()>, String>,
) -> Result<Raw, String> {
    let (sender, receiver) = sim.trusting_pair().map_err(io_error)?;
    for (machine, peer) in [(&sender, &receiver), (&receiver, &sender)] {
        machine
            .records()
            .record_pairing(&peer.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        machine
            .records()
            .record_address(&peer.peer_id(), peer.addr())
            .map_err(|error| error.to_string())?;
    }
    let moment: Arc<dyn Moment + Send + Sync> = Arc::new(SimMoment::new(sim.clock().clone(), NOW));
    let floor: Arc<dyn Floor + Send + Sync> = Arc::new(NoFloor);
    let managed = Managed::start(sim, beacon, &sender, &sender.records())?;
    let transfers = Arc::new(sender.transfers(floor, moment, None)?);
    // Detached when the handle drops, which is what a case wants: the raw peer answers for as
    // long as the case keeps offering.
    let _raw = peer(&receiver)?;
    within(
        sim,
        BUDGET,
        managed
            .connections
            .connect(&managed.endpoint, &receiver.fingerprint()),
    )
    .await?
    .map_err(|error| error.to_string())?;
    wait_live(sim, &managed.connections, &receiver.peer_id()).await?;
    Ok(Raw {
        _sender: sender,
        receiver,
        managed,
        transfers,
    })
}

/// The pair [`raw_pair`] built, held together so no half is dropped while a case still needs it.
///
/// The sending machine is bound even though no case reads it: its root is a temporary directory
/// that goes away with it, and with it the record the transfer is decided by.
struct Raw {
    _sender: Machine,
    /// The peer, which is a transport and nothing more.
    receiver: Machine,
    /// The sending machine's manager, its endpoint and the accept loop.
    managed: Managed,
    /// The sending machine's transfer layer.
    transfers: Arc<Transfers>,
}

/// The accepting half of a raw connection, handed back to a case that holds both halves.
type Handoff = Arc<Mutex<Option<quinn::Connection>>>;

/// Accept every connection `machine`'s endpoint is offered, hold it for the case, and hand the
/// first one back where a case holds both halves.
///
/// A raw peer's far side is a transport and nothing more: no manager, no inbox, no layer that
/// reads a stream. The handshake is accepted — a connection the server never accepts makes no
/// progress at all — and the streams the peer opens are left unread, which is the state the
/// transport's own bounds are measured in. The accepted half is left in the returned slot so a
/// case can write a word on the dialling half and read it on this one.
fn accept_raw(machine: &Machine) -> Result<(tokio::task::JoinHandle<()>, Handoff), String> {
    let endpoint = machine.endpoint().map_err(|error| error.to_string())?;
    let first: Handoff = Arc::new(Mutex::new(None));
    let handoff = Arc::clone(&first);
    let task = tokio::spawn(async move {
        // Held for the case's lifetime: a connection dropped here would be closed, and the
        // peer's writes would fail instead of filling this machine's buffers.
        let mut held = Vec::new();
        while let Some(incoming) = endpoint.accept().await {
            if let Ok(connecting) = incoming.accept()
                && let Ok(connection) = connecting.await
            {
                let mut slot = handoff.lock().expect("the raw handoff is not poisoned");
                if slot.is_none() {
                    *slot = Some(connection.clone());
                }
                drop(slot);
                held.push(connection);
            }
        }
    });
    Ok((task, first))
}

/// Wait until `handoff` holds the accepting half of a raw connection.
async fn accepted(sim: &Sim, handoff: &Handoff) -> Result<quinn::Connection, String> {
    within(sim, BUDGET, async {
        loop {
            let held = handoff
                .lock()
                .expect("the raw handoff is not poisoned")
                .clone();
            if let Some(connection) = held {
                return Ok::<quinn::Connection, String>(connection);
            }
            tokio::task::yield_now().await;
        }
    })
    .await?
}

/// A raw connection from `client`'s own endpoint to `server`'s, over the peer ALPN.
async fn raw_connection(
    sim: &Sim,
    client: &Machine,
    server: &Machine,
) -> Result<quinn::Connection, String> {
    let endpoint = client.endpoint().map_err(|error| error.to_string())?;
    let connecting = endpoint
        .connect(server.addr(), SERVER_NAME)
        .map_err(|error| error.to_string())?;
    within(sim, BUDGET, connecting)
        .await?
        .map_err(|error| error.to_string())
}

/// Write [`TRANSFER_CHUNK`]-sized chunks into `send` until the write stops completing, and
/// answer how many bytes it took.
///
/// A stream whose credit is used up parks its writer; the wait is bounded, so a stream that
/// never stops is a failure of the bound rather than a hung case.
async fn fill(sim: &Sim, send: &mut quinn::SendStream, chunk: &[u8]) -> u64 {
    let mut accepted = 0u64;
    let _ = within(sim, BLOCKED, async {
        loop {
            if send.write_all(chunk).await.is_err() {
                return;
            }
            accepted += u64::try_from(chunk.len()).expect("a chunk is far below a u64");
        }
    })
    .await;
    accepted
}

/// The host's own floor can allow messages while refusing files.
///
/// The floor is asked which permission is at stake, so a machine may take a peer's messages
/// and refuse its files without touching the rights: the message arrives, the file is refused
/// at the floor and not at the right, and the refusal is recorded naming the permission and
/// the step. A floor refusal is not a withdrawal, so the grant stays.
pub(crate) fn the_hosts_floor_can_allow_messages_and_refuse_files() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        // This machine takes no files. Every other permission is left to the rights.
        let floor: Arc<dyn Floor + Send + Sync> = Arc::new(|_: &Pair, capability: Capability| {
            (capability == Capability::PUT_FILES).then(|| "this machine takes no files".to_owned())
        });
        let (sender, receiver) = paired_machines(&sim)?;
        let duo = wire_pair(
            &sim,
            &beacon,
            sender,
            receiver,
            Files::sending(),
            Files::taking(sink),
            floor,
        )?;
        allow_files(&duo)?;
        connect(&sim, &duo).await?;
        // "Write to me" passes the same floor: a message arrives.
        duo.sending
            .messages
            .send(&duo.receiver.peer_id(), NOW, b"a word the floor allows")
            .map_err(|error| error.to_string())?;
        let delivered = wait_for(&sim, &duo.arriving.collected, 1, BUDGET).await?;
        if delivered.len() != 1 {
            return Err(format!(
                "a message the floor allows did not arrive: {} deliveries",
                delivered.len()
            ));
        }
        // "Put files on me" does not, and the step is the floor's, not the right's.
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let transfer = offer(&duo, &file)?;
        let state = drive_transfer_in(&sim, BUDGET, Duration::from_millis(100), &transfer).await?;
        ended(
            state,
            TransferState::Failed {
                failure: TransferFailure::Refused { step: Step::Floor },
            },
        )?;
        let audit = duo.receiver.audit()?;
        let entries = audit.entries().map_err(|error| error.to_string())?;
        let recorded = entries.iter().any(|entry| {
            matches!(
                &entry.act,
                Act::Refused {
                    capability,
                    refusal,
                    ..
                } if *capability == Capability::PUT_FILES && refusal.step() == Step::Floor
            )
        });
        if !recorded {
            return Err(
                "the floor's refusal was not recorded naming the permission and the step"
                    .to_owned(),
            );
        }
        Ok(())
    })
}

/// A sink that will not take the bytes is its own answer, not a stall and not a bad digest.
///
/// The receiving machine's product refuses the first chunk in its own words; the words stay
/// there, the class travels, and the sender learns that the receiving side could not store it
/// rather than that the transfer stopped or that what arrived did not match.
pub(crate) fn a_sink_that_refuses_is_its_own_answer() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        hashing.refuse();
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let name = file.name().clone();
        let from = duo.sender.peer_id();
        let transfer = offer(&duo, &file)?;
        let state = drive_transfer_in(&sim, BUDGET, Duration::from_millis(100), &transfer).await?;
        ended(
            state,
            TransferState::Failed {
                failure: TransferFailure::StoreFailed,
            },
        )?;
        if hashing.held_bytes(&from, &name) != 0 {
            return Err(format!(
                "a refusing sink was handed {} bytes",
                hashing.held_bytes(&from, &name)
            ));
        }
        Ok(())
    })
}

/// A transfer that has been moving bytes for longer than the wait bound still waits in full
/// when its connection goes away, and resumes.
///
/// The sink stores one chunk of a two-mebibyte file every twenty-one seconds, so the transfer is
/// still running — and the receiving machine's offset still growing — well past
/// [`TRANSFER_WAIT`]. The connection is closed there, and the wait bound is anchored at that
/// moment rather than at the offer: the pair stays away for a further [`TRANSFER_STALL`] and the
/// transfer keeps waiting, then resumes and lands whole. A bound measured from the offer would
/// have ended this transfer `no pair` on its first round after the close.
pub(crate) fn a_transfer_that_ran_past_the_wait_bound_still_resumes() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        let length = 2 * 1024 * 1024;
        let file = Generated::new(FILE_NAME, length);
        let name = file.name().clone();
        let from = duo.sender.peer_id();
        // One chunk stored every twenty-one seconds: thirty-two chunks, so the transfer lasts
        // longer than the wait bound while the receiving machine's offset keeps growing inside
        // the stall bound.
        hashing.slow(22);
        let transfer = offer(&duo, &file)?;
        let start = sim.clock().elapsed();
        advance_until(&sim, TRANSFER_WAIT * 2, Duration::from_secs(5), || {
            sim.clock().elapsed() > start + TRANSFER_WAIT + Duration::from_secs(30)
        })
        .await?;
        // The transfer is not merely unfinished: it is moving, which is what the wait bound
        // must not count against it.
        if !matches!(transfer.state(), TransferState::Running { .. }) {
            return Err(format!(
                "the transfer reads `{:?}` after {:?} of moving, not running",
                transfer.state(),
                sim.clock().elapsed() - start
            ));
        }
        if hashing.held_bytes(&from, &name) < length / 2 {
            return Err(format!(
                "the sink holds {} bytes of a {length}-byte file after {:?} of moving: the case \
                 did not keep the transfer running past the wait bound",
                hashing.held_bytes(&from, &name),
                sim.clock().elapsed() - start
            ));
        }
        // The pair is silenced first and closed second: with the link up the transfer would
        // re-dial at once, and a connection that carries nothing for the stall bound is a live
        // connection that stopped moving — `no progress` — which is not the wait this case is
        // about.
        sim.link().silence(duo.receiver.addr());
        if !duo
            .sending
            .managed
            .connections
            .disconnect(&duo.receiver.peer_id())
        {
            return Err("the pair had no live connection to close".to_owned());
        }
        advance_until(&sim, BUDGET, Duration::from_millis(100), || {
            transfer.state() == TransferState::Waiting
        })
        .await
        .map_err(|why| format!("{why}: the transfer reads `{:?}`", transfer.state()))?;
        // Nothing is delivered to the receiving machine, so no connection can be made: the
        // clock passes the stall bound with the pair still gone and the transfer keeps waiting,
        // because the wait bound began when the connection went away and not when the file was
        // offered.
        sim.clock()
            .advance(TRANSFER_STALL + Duration::from_secs(10))
            .await;
        if transfer.state() != TransferState::Waiting {
            return Err(format!(
                "the transfer reads `{:?}` after {:?} with no pair, not waiting",
                transfer.state(),
                TRANSFER_STALL + Duration::from_secs(10)
            ));
        }
        sim.link().resume(duo.receiver.addr());
        let state = drive_transfer_in(&sim, BUDGET * 4, Duration::from_secs(1), &transfer).await?;
        ended(state, TransferState::Finished { bytes: length })?;
        if hashing.held_bytes(&from, &name) != length {
            return Err(format!(
                "the sink holds {} bytes of a {length}-byte file",
                hashing.held_bytes(&from, &name)
            ));
        }
        Ok(())
    })
}

/// A transfer that waits longer than the wait bound for a sender that never comes back is
/// reported as ended, on both sides.
///
/// The pair's connection is closed while the receiving machine is waiting for the file's next
/// chunk and the sending machine is between two of them, and the receiving machine is never
/// reached again. Once the bound has passed, the receiving machine's own view of the name is
/// terminal and names the pair — never `waiting`, which is what a quiet transfer reads — and the
/// sending machine's handle ends the same way.
pub(crate) fn a_waiting_transfer_that_never_resumes_ends() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        let file = Generated::new(FILE_NAME, LONG_BYTES);
        let name = file.name().clone();
        let from = duo.sender.peer_id();
        // Two seconds of "not now" before every chunk, so the sender is between two of them
        // when the connection goes away and the receiving machine is waiting for the next one —
        // both sides then wait for the pair rather than for their own sink or source.
        file.stall_every(2);
        let transfer = offer(&duo, &file)?;
        advance_until(&sim, BUDGET, Duration::from_millis(10), || {
            hashing.held_bytes(&from, &name) > 0
        })
        .await
        .map_err(|why| {
            format!(
                "{why}: the sink holds {} bytes and the transfer reads `{:?}`",
                hashing.held_bytes(&from, &name),
                transfer.state()
            )
        })?;
        // The pair is silenced first and closed second, so no dial can bring it back: a
        // connection made and then silenced would be a live connection carrying nothing, which
        // the stall bound ends — the opposite of the wait this case is about.
        sim.link().silence(duo.receiver.addr());
        if !duo
            .sending
            .managed
            .connections
            .disconnect(&duo.receiver.peer_id())
        {
            return Err("the pair had no live connection to close".to_owned());
        }
        advance_until(&sim, BUDGET, Duration::from_millis(100), || {
            transfer.state() == TransferState::Waiting
        })
        .await
        .map_err(|why| format!("{why}: the transfer reads `{:?}`", transfer.state()))?;
        // The receiving machine's own view is terminal, and it names the pair rather than
        // showing a transfer that is still quietly waiting for one. Its own wait began when its
        // connection stopped answering — an idle timeout after the silence, not the moment this
        // machine closed its half — so the clock is carried until that view ends, and then the
        // answer is checked rather than assumed.
        advance_until(
            &sim,
            TRANSFER_WAIT + 2 * TRANSFER_STALL,
            Duration::from_secs(30),
            || incoming_state(&duo, &name).is_ok_and(|state| state.is_some_and(|s| s.is_over())),
        )
        .await
        .map_err(|why| {
            format!(
                "{why}: the receiving machine reads `{:?}`",
                incoming_state(&duo, &name)
            )
        })?;
        let arriving = incoming_state(&duo, &name)?;
        let ended_without_a_pair = Some(TransferState::Failed {
            failure: TransferFailure::NoPair,
        });
        if arriving != ended_without_a_pair {
            return Err(format!(
                "the receiving machine reads `{arriving:?}` of a transfer that waited \
                 {TRANSFER_WAIT:?} for a pair that never came, not `no pair`"
            ));
        }
        let state = drive_transfer_in(&sim, BUDGET, Duration::from_secs(1), &transfer).await?;
        failed(state, TransferFailure::NoPair)
    })
}

/// A record this machine cannot read is waited for, but bounded.
///
/// The sending machine's own record for the peer becomes something it cannot parse, as a record
/// damaged on disk is, and nothing can reach the receiving machine either. The transfer waits
/// the record's own bound and then ends naming its own progress rather than the pair — and it
/// gives back its place for the peer, instead of retrying for ever.
pub(crate) fn a_record_that_cannot_be_read_ends_the_transfer() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        let file = Generated::new(FILE_NAME, LONG_BYTES);
        let name = file.name().clone();
        let from = duo.sender.peer_id();
        // One write and no more, so the transfer is held in the middle of the file.
        hashing.accept_burst(1);
        let transfer = offer(&duo, &file)?;
        advance_until(&sim, BUDGET, Duration::from_millis(10), || {
            hashing.held_bytes(&from, &name) > 0
        })
        .await
        .map_err(|why| {
            format!(
                "{why}: the sink holds {} bytes and the transfer reads `{:?}`",
                hashing.held_bytes(&from, &name),
                transfer.state()
            )
        })?;
        // The sending machine's record for the peer is no longer a record at all.
        duo.sender
            .root
            .write_record(&duo.receiver.peer_id(), b"not a record at all")
            .map_err(io_error)?;
        // Nothing else can reach the receiving machine either, so the record is the only thing
        // in the transfer's way.
        sim.link().silence(duo.receiver.addr());
        sim.clock()
            .advance(TRANSFER_WAIT + Duration::from_secs(10))
            .await;
        let state = drive_transfer_in(&sim, BUDGET, Duration::from_secs(1), &transfer).await?;
        if matches!(
            state,
            TransferState::Failed {
                failure: TransferFailure::NoPair,
            }
        ) {
            return Err(format!(
                "the transfer ended `{state:?}`, naming the pair rather than this machine's own \
                 record"
            ));
        }
        failed(state, TransferFailure::NoProgress)
    })
}

/// A retry is never told its own transfer is already running.
///
/// The receiving machine's sink takes one chunk and then answers "not now" for ever, so its
/// stream stays open and holds the name while the sender is blocked on the stream's window. The
/// connection is closed there, the sender dials again and offers the same file while that first
/// stream is still holding the name: the `running` answer is this machine's own earlier attempt,
/// and the sender waits for it to let go rather than reporting its own transfer back to itself.
/// It ends on the receiving side's own failure, never `already running`.
pub(crate) fn a_retry_never_reports_its_own_transfer_as_running() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        // One chunk stored and no more: the sink answers "not now" for ever after it, so the
        // receiving machine's stream holds the name.
        hashing.accept_burst(1);
        // Larger than the peer's stream window, so the sender's write blocks and the transfer is
        // held by the receiving side rather than by its own source.
        let length = 9 * 1024 * 1024;
        let file = Generated::new(FILE_NAME, length);
        let name = file.name().clone();
        let from = duo.sender.peer_id();
        let transfer = offer(&duo, &file)?;
        advance_until(&sim, BUDGET, Duration::from_millis(10), || {
            moved(&transfer) > 0 && hashing.writes() >= 1
        })
        .await
        .map_err(|why| {
            format!(
                "{why}: the transfer reads `{:?}` and the sink was written {} times",
                transfer.state(),
                hashing.writes()
            )
        })?;
        // Ten seconds of the sender blocked and the sink not taking bytes: well inside the stall
        // bound, and long enough that the first stream is still holding the name when the pair
        // comes back.
        sim.clock().advance(Duration::from_secs(10)).await;
        if !duo
            .sending
            .managed
            .connections
            .disconnect(&duo.receiver.peer_id())
        {
            return Err("the pair had no live connection to close".to_owned());
        }
        advance_until(&sim, BUDGET, Duration::from_millis(100), || {
            transfer.state() == TransferState::Waiting
        })
        .await
        .map_err(|why| format!("{why}: the transfer reads `{:?}`", transfer.state()))?;
        // The pair comes back by itself and the sender asks again while the receiving machine's
        // first stream still holds the name. Every one of those offers is answered `running`, so
        // the sink's own question — asked only for an offer that was authorised — is never put
        // again: the retries are the sender's own earlier attempt, not new ones.
        wait_live(
            &sim,
            &duo.sending.managed.connections,
            &duo.receiver.peer_id(),
        )
        .await?;
        let asked = hashing.held_asks();
        sim.clock().advance(Duration::from_secs(5)).await;
        if hashing.held_asks() != asked {
            return Err(format!(
                "the sink was asked what it holds {} more times while the receiving machine's \
                 first stream still held the name: the retry was not answered `running`",
                hashing.held_asks() - asked
            ));
        }
        let state =
            drive_transfer_in(&sim, TRANSFER_WAIT, Duration::from_secs(1), &transfer).await?;
        if matches!(
            state,
            TransferState::Failed {
                failure: TransferFailure::AlreadyRunning,
            }
        ) {
            return Err(
                "the sender was told its own transfer was already running on the receiving \
                 machine"
                    .to_owned(),
            );
        }
        if !matches!(
            state,
            TransferState::Failed {
                failure: TransferFailure::StoreFailed | TransferFailure::NoProgress,
            }
        ) {
            return Err(format!(
                "the transfer ended `{state:?}`, which is neither the receiving side's own \
                 failure nor the stall bound"
            ));
        }
        if hashing.held_bytes(&from, &name) == 0 {
            return Err(
                "the sink holds nothing: the case never got past the first chunk".to_owned(),
            );
        }
        Ok(())
    })
}

/// A sink that cannot say what it assembled is a store failure, not a digest mismatch.
///
/// Every byte of the file arrives and the sink is asked what it assembled — and cannot say. The
/// crate has no evidence either way, so it answers the class that keeps "could not store it"
/// apart from "what arrived does not match", and both sides read it that way.
pub(crate) fn a_sink_that_cannot_answer_the_digest_is_a_store_failure() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let name = file.name().clone();
        let from = duo.sender.peer_id();
        hashing.cannot_answer();
        let transfer = offer(&duo, &file)?;
        let state = drive_transfer(&sim, BUDGET, &transfer).await?;
        ended(
            state,
            TransferState::Failed {
                failure: TransferFailure::StoreFailed,
            },
        )?;
        if !hashing.finished(&from, &name) {
            return Err("the sink was never asked what it assembled".to_owned());
        }
        let arriving = incoming_state(&duo, &name)?;
        let store_failed = Some(TransferState::Failed {
            failure: TransferFailure::StoreFailed,
        });
        if arriving != store_failed {
            return Err(format!(
                "the receiving machine reads `{arriving:?}` of a sink that could not say what it \
                 assembled, not a store failure"
            ));
        }
        Ok(())
    })
}

/// An offer to a pair with no binding and no claim is answered nothing, and goes through once
/// the receiving machine decides the binding.
///
/// The receiving machine's record holds a pairing and the right its person granted, and neither
/// a binding nor a claim, so there is no pair to name and nothing to refuse: the offer is not
/// answered at all — not refused at a step — and the sender keeps asking. Nothing is stored and
/// nothing is authorised. The binding is then decided, and the same transfer proceeds and lands.
pub(crate) fn an_offer_to_an_unbound_pair_is_answered_nothing() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = wired_pair(&sim, &beacon, Files::sending(), Files::taking(sink))?;
        connect(&sim, &duo).await?;
        // Back to "no binding and no claim": a pairing and the right its person grants, and
        // nothing else in the record.
        duo.receiver
            .root
            .remove_record(&duo.sender.peer_id())
            .map_err(io_error)?;
        duo.receiver
            .records()
            .record_pairing(&duo.sender.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        allow_files(&duo)?;
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let name = file.name().clone();
        let from = duo.sender.peer_id();
        let transfer = offer(&duo, &file)?;
        let start = sim.clock().elapsed();
        advance_until(&sim, BUDGET, Duration::from_millis(100), || {
            sim.clock().elapsed() > start + Duration::from_secs(15)
        })
        .await?;
        // Nothing was authorised, so nothing was stored and the receiving machine holds no
        // transfer under the name.
        if hashing.held_bytes(&from, &name) != 0 {
            return Err(format!(
                "the sink holds {} bytes for an offer that named no pair",
                hashing.held_bytes(&from, &name)
            ));
        }
        if incoming_state(&duo, &name)?.is_some() {
            return Err(format!(
                "the receiving machine holds a transfer under `{name}` an offer with no pair \
                 never authorised"
            ));
        }
        // The sender was answered nothing rather than refused: it is still asking.
        let state = transfer.state();
        if state.is_over() {
            return Err(format!(
                "the transfer reads `{state:?}` after an offer the receiving machine answered \
                 nothing"
            ));
        }
        if matches!(
            state,
            TransferState::Failed {
                failure: TransferFailure::Refused { .. },
            }
        ) {
            return Err(format!(
                "an offer with no pair was refused at a step: `{state:?}`"
            ));
        }
        // The sender does not ask once a second: the wait between unanswered offers doubles after
        // each one. Every offer that is not a resume still spends a start, so the receiving
        // machine's limit is reached later rather than after six seconds — and reached it is. It
        // arrives as a throttle rather than an end: the handle names the delay the receiving
        // machine asked for, inside its own window, and the transfer asks again when it passes.
        advance_until(&sim, BUDGET, Duration::from_millis(100), || {
            matches!(transfer.state(), TransferState::Throttled { .. })
        })
        .await
        .map_err(|why| {
            format!(
                "{why}: the transfer reads `{:?}` of an offer to a pair that never bound",
                transfer.state()
            )
        })?;
        let TransferState::Throttled { retry_after } = transfer.state() else {
            return Err("the transfer stopped being throttled as it was read".to_owned());
        };
        if retry_after == Duration::ZERO || retry_after > TRANSFER_START_WINDOW {
            return Err(format!(
                "the start limit asked for a wait of {retry_after:?}, not inside the \
                 {TRANSFER_START_WINDOW:?} window"
            ));
        }
        // The receiving machine decides the binding, and the same transfer goes through.
        duo.receiver
            .rights()?
            .bind(
                &duo.sender.peer_id(),
                binding("second-account", "second-instance", &duo.assistant)?,
                NOW,
            )
            .map_err(|error| error.to_string())?;
        let state = drive_transfer_in(&sim, BUDGET, Duration::from_secs(1), &transfer).await?;
        ended(state, TransferState::Finished { bytes: FILE_BYTES })?;
        if hashing.held_bytes(&from, &name) != FILE_BYTES {
            return Err(format!(
                "the sink holds {} bytes of a {FILE_BYTES}-byte file offered through the unbound \
                 window",
                hashing.held_bytes(&from, &name)
            ));
        }
        Ok(())
    })
}

/// A pair that never binds ends the transfer as the pair, not as a limit.
///
/// The receiving machine has no binding and no claim, so every offer is answered nothing and the
/// start limit is what those offers eventually meet — the limit was spent by offers a pair with
/// no binding could not decide. A transfer nothing has ever answered that ends because of it names
/// the pair, which is what the product shows its person: "throttled" would say the receiving
/// machine paced a transfer it never even looked at.
pub(crate) fn a_pair_that_never_binds_ends_as_the_pair() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = wired_pair(&sim, &beacon, Files::sending(), Files::taking(sink))?;
        connect(&sim, &duo).await?;
        // Back to "no binding and no claim": a pairing and the right its person grants, and
        // nothing else in the record.
        duo.receiver
            .root
            .remove_record(&duo.sender.peer_id())
            .map_err(io_error)?;
        duo.receiver
            .records()
            .record_pairing(&duo.sender.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        allow_files(&duo)?;
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let name = file.name().clone();
        let transfer = offer(&duo, &file)?;
        // The offers spend the receiving machine's start window, so the sender is throttled
        // before the pair ever decides anything: that is the state this case has to reach.
        advance_until(&sim, BUDGET, Duration::from_millis(100), || {
            matches!(transfer.state(), TransferState::Throttled { .. })
        })
        .await
        .map_err(|why| {
            format!(
                "{why}: the transfer reads `{:?}` of an offer to a pair that never bound",
                transfer.state()
            )
        })?;
        // Nothing answers the transfer itself, so the throttle streak runs out at the wait bound
        // and names the pair rather than the limit the unbound offers kept spending.
        let state = drive_transfer_in(
            &sim,
            TRANSFER_WAIT + BUDGET,
            Duration::from_secs(1),
            &transfer,
        )
        .await?;
        failed(state, TransferFailure::NoPair)?;
        if hashing.held_bytes(&duo.sender.peer_id(), &name) != 0 {
            return Err(format!(
                "the sink holds {} bytes for a pair that never bound",
                hashing.held_bytes(&duo.sender.peer_id(), &name)
            ));
        }
        Ok(())
    })
}

/// A stop reaches the tail: the phase after the bytes, where a slow sink spends most of the time.
///
/// The whole file fits one stream window, so the sending side writes every byte and then waits for
/// the receiving side's verdict while the sink stores a chunk every half minute. The product stops
/// the transfer there, and the transfer ends as stopped and gives one of this machine's places for
/// the peer back — two more transfers to the same peer are accepted at once, which is what a task
/// still reading the tail would not allow. The bytes the receiving machine already holds stay
/// where they are: what it does with a file nobody finished is its own decision.
pub(crate) fn a_stop_during_the_tail_is_stopped() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let hashing = Store::hashing();
        // One write every thirty calls, and the receiving side asks once a second: a chunk every
        // half minute, so the tail lasts minutes while the bytes are long written.
        hashing.slow(30);
        let sink: Arc<dyn Sink + Send + Sync> = hashing.clone();
        let duo = duo(&sim, &beacon, Files::sending(), Files::taking(sink)).await?;
        allow_files(&duo)?;
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let name = file.name().clone();
        let transfer = offer(&duo, &file)?;
        advance_until(&sim, BUDGET, Duration::from_millis(100), || {
            moved(&transfer) == FILE_BYTES
        })
        .await
        .map_err(|why| format!("{why}: the transfer reads `{:?}`", transfer.state()))?;
        // Every byte is written and the receiving side is still storing: this is the tail.
        if hashing.held_bytes(&duo.sender.peer_id(), &name) >= FILE_BYTES {
            return Err("the sink stored the whole file before the tail began".to_owned());
        }
        transfer.stop();
        // A second of virtual time is all the tail loop's look takes, and the task has to end for
        // one of this machine's places for the peer to come back.
        let stopped = sim.clock().elapsed();
        advance_until(&sim, BUDGET, Duration::from_millis(100), || {
            sim.clock().elapsed() > stopped + Duration::from_secs(5)
        })
        .await?;
        ended(transfer.state(), TransferState::Stopped)?;
        // This machine's two places for the peer: the second is free only because the stopped task
        // gave its place back, which a task still reading the tail would not have done.
        let transfers = duo.sending.transfers()?;
        let mut later = Vec::new();
        for name in ["after-the-stop.bin", "after-the-stop-too.bin"] {
            let file = Generated::new(name, FILE_BYTES);
            later.push(
                transfers
                    .send(
                        &duo.sending.managed.connections,
                        &duo.sending.managed.endpoint,
                        &duo.receiver.peer_id(),
                        file.offering(),
                    )
                    .map_err(|error| {
                        format!("a transfer after a stop in the tail was refused: {error}")
                    })?,
            );
        }
        for each in &later {
            each.stop();
        }
        Ok(())
    })
}

/// An offset the receiving side keeps growing, stated in answers to successive offers, keeps the
/// transfer alive past the stall bound.
///
/// The raw peer loses the first offer and then answers every later one with `running` at an
/// offset a kibibyte further than the last. The stall bound is measured from the last time the
/// receiver's offset *grew* — and from nothing else — so the transfer keeps going for longer than
/// the bound itself and then takes the file. Progress stated in an answer is the only thing that
/// says a file is still arriving when the receiver holds the name, and nothing takes it back.
pub(crate) fn a_growing_offset_in_answers_keeps_the_transfer_alive() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let raw = raw_pair_with(&sim, &beacon, |receiver| {
            raw_growing_receiver(receiver, GROWING_OFFERS)
        })
        .await?;
        let (receiver, managed, transfers) = (&raw.receiver, &raw.managed, &raw.transfers);
        let file = Generated::new(FILE_NAME, LONG_BYTES);
        let transfer = transfers
            .send(
                &managed.connections,
                &managed.endpoint,
                &receiver.peer_id(),
                file.offering(),
            )
            .map_err(|error| error.to_string())?;
        // A second of virtual time between offers, and more offers than the stall bound has
        // seconds: a transfer that did not credit the growth would end at the bound, one bound
        // after the last offset it saw.
        let state = drive_transfer_in(&sim, BUDGET * 2, Duration::from_secs(1), &transfer).await?;
        ended(state, TransferState::Finished { bytes: LONG_BYTES })
    })
}

/// A verdict that arrives past the receiver's own stall bound is still heard.
///
/// The raw peer resumes at zero, reads every byte, and only then answers `complete` — two and a
/// half seconds after [`TRANSFER_STALL`], which is inside the margin [`TRANSFER_GRACE`] states. The
/// sender reads the verdict for the receiver's bound plus that margin, so it hears the answer
/// instead of calling a transfer that arrived `no progress` and offering the file again.
pub(crate) fn a_verdict_past_the_receivers_stall_bound_is_heard() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let clock = sim.clock().clone();
        let raw = raw_pair_with(&sim, &beacon, move |receiver| {
            // Two and a half seconds past the bound: past it, so a sender reading only the bound
            // has already given up, and well inside the margin it allows past it.
            raw_late_verdict(
                receiver,
                &clock,
                TRANSFER_STALL + Duration::from_millis(2500),
            )
        })
        .await?;
        let (receiver, managed, transfers) = (&raw.receiver, &raw.managed, &raw.transfers);
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let transfer = transfers
            .send(
                &managed.connections,
                &managed.endpoint,
                &receiver.peer_id(),
                file.offering(),
            )
            .map_err(|error| error.to_string())?;
        let state = drive_transfer_in(&sim, BUDGET, Duration::from_millis(500), &transfer).await?;
        ended(state, TransferState::Finished { bytes: FILE_BYTES })
    })
}

/// A product that stops a transfer while the receiving machine is throttling it gets its place
/// back at once.
///
/// The throttle is the longest wait the layer has — a whole start window — and the peer names it.
/// A stop during that wait ends the transfer then, not when the peer's delay runs out, which is
/// what the two later transfers to the same peer prove: this machine has two places for the peer,
/// and the second is free only because the stopped task gave its own place back.
pub(crate) fn a_stop_during_a_throttle_is_stopped() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let asked = u32::try_from(TRANSFER_THROTTLE_CAP.as_secs())
            .expect("a throttle cap is far below four billion seconds");
        let throttle = answer_frame(
            &[
                field(0x01, &[5]),
                field(0x04, &[2]),
                field(0x03, &asked.to_be_bytes()),
            ]
            .concat(),
        );
        let raw = raw_pair(&sim, &beacon, vec![throttle]).await?;
        let (receiver, managed, transfers) = (&raw.receiver, &raw.managed, &raw.transfers);
        let file = Generated::new(FILE_NAME, FILE_BYTES);
        let transfer = transfers
            .send(
                &managed.connections,
                &managed.endpoint,
                &receiver.peer_id(),
                file.offering(),
            )
            .map_err(|error| error.to_string())?;
        advance_until(&sim, BUDGET, Duration::from_millis(100), || {
            matches!(transfer.state(), TransferState::Throttled { .. })
        })
        .await
        .map_err(|why| format!("{why}: the transfer reads `{:?}`", transfer.state()))?;
        transfer.stop();
        // Two seconds: more than the poll the wait is slept in, and far less than the window the
        // peer named.
        let stopped = sim.clock().elapsed();
        advance_until(&sim, BUDGET, Duration::from_millis(100), || {
            sim.clock().elapsed() > stopped + Duration::from_secs(2)
        })
        .await?;
        ended(transfer.state(), TransferState::Stopped)?;
        let mut later = Vec::new();
        for name in ["after-the-throttle.bin", "after-the-throttle-too.bin"] {
            let file = Generated::new(name, FILE_BYTES);
            later.push(
                transfers
                    .send(
                        &managed.connections,
                        &managed.endpoint,
                        &receiver.peer_id(),
                        file.offering(),
                    )
                    .map_err(|error| {
                        format!("a transfer after a stop in a throttle was refused: {error}")
                    })?,
            );
        }
        for each in &later {
            each.stop();
        }
        Ok(())
    })
}

/// A product that stops a transfer while it waits for the answer to its offer gets it back at
/// once.
///
/// The raw peer reads the offer and says nothing at all, holding the stream open: the sender's
/// answer budget is thirty seconds, and a stop noticed only when that budget ran out would hold
/// one of this machine's places for the peer for all of it. The stop is noticed inside a poll,
/// and the two transfers started straight after it are what proves the place came back — a task
/// still parked in the answer wait would refuse the second of them.
pub(crate) fn a_stop_while_waiting_for_the_answer_is_stopped() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let offers = Arc::new(Mutex::new(Vec::new()));
        let counted = Arc::clone(&offers);
        let clock = sim.clock().clone();
        let raw = raw_pair_with(&sim, &beacon, move |receiver| {
            raw_mostly_silent_receiver(receiver, &clock, Silence::Hold, None, counted)
        })
        .await?;
        let (receiver, managed, transfers) = (&raw.receiver, &raw.managed, &raw.transfers);
        let file = Generated::new("a-silent-answer.bin", FILE_BYTES);
        let transfer = transfers
            .send(
                &managed.connections,
                &managed.endpoint,
                &receiver.peer_id(),
                file.offering(),
            )
            .map_err(|error| error.to_string())?;
        // The offer has arrived and nothing has come back: the sender is in its answer wait.
        advance_until(&sim, BUDGET, Duration::from_millis(100), || {
            !offers
                .lock()
                .expect("the offer times are not poisoned")
                .is_empty()
        })
        .await?;
        transfer.stop();
        let stopped = sim.clock().elapsed();
        // Two seconds: more than the poll the answer wait is read in, and far less than the answer
        // budget the place would otherwise be held for.
        advance_until(&sim, BUDGET, Duration::from_millis(100), || {
            sim.clock().elapsed() > stopped + Duration::from_secs(2)
        })
        .await?;
        ended(transfer.state(), TransferState::Stopped)?;
        // The handle says stopped at once, so this line is the handle's; what the two later
        // transfers prove is the task itself having ended and given its place back.
        let mut later = Vec::new();
        for name in ["after-the-answer.bin", "after-the-answer-too.bin"] {
            let file = Generated::new(name, FILE_BYTES);
            later.push(
                transfers
                    .send(
                        &managed.connections,
                        &managed.endpoint,
                        &receiver.peer_id(),
                        file.offering(),
                    )
                    .map_err(|error| {
                        format!("a transfer after a stop in the answer wait was refused: {error}")
                    })?,
            );
        }
        for each in &later {
            each.stop();
        }
        Ok(())
    })
}

/// A stop made while this machine is dialling the pair takes effect when that dial returns.
///
/// The pair has each other's addresses and no live connection, so the first thing the transfer does
/// is dial. The receiving machine's address is silenced on the link, so the dial is still in flight
/// when the stop is made; the link is resumed before that dial returns, so the dial completes — the
/// pair reads `connected` when it does — rather than running out its own budget. The stop is made
/// while the task is parked inside the dial, which is not polled: the handle reads `stopped` at
/// once, and the place the task held for the peer is back by the time the later offers are made —
/// the two later offers, made after the pair is connected, show it, since a task still holding it
/// would have refused the second of them.
pub(crate) fn a_stop_during_a_dial_is_stopped() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (sender, receiver) = paired_machines(&sim)?;
        let sink: Arc<dyn Sink + Send + Sync> = Store::hashing();
        let duo = wire_pair(
            &sim,
            &beacon,
            sender,
            receiver,
            Files::sending(),
            Files::taking(sink),
            Arc::new(NoFloor),
        )?;
        allow_files(&duo)?;
        let peer = duo.receiver.peer_id();
        // The pair has no live connection, so the first thing the transfer does is dial. Nothing
        // reaches the receiving machine's address while it is silenced, so the dial is still in
        // flight when the stop is made.
        sim.link().silence(duo.receiver.addr());
        let file = Generated::new("a-stop-during-the-dial.bin", FILE_BYTES);
        let transfer = offer(&duo, &file)?;
        advance_until(&sim, BUDGET, Duration::from_millis(100), || {
            matches!(
                duo.sending.managed.connections.recovery(&peer),
                Recovery::Dialling { .. }
            )
        })
        .await
        .map_err(|why| {
            format!(
                "{why}: the pair reads `{}`",
                duo.sending.managed.connections.recovery(&peer)
            )
        })?;
        transfer.stop();
        // The handle says stopped at once, before the dial it is parked in has returned.
        ended(transfer.state(), TransferState::Stopped)?;
        sim.link().resume(duo.receiver.addr());
        advance_until(&sim, BUDGET, Duration::from_millis(100), || {
            matches!(
                duo.sending.managed.connections.recovery(&peer),
                Recovery::Connected
            )
        })
        .await
        .map_err(|why| {
            format!(
                "{why}: the dial reads `{}`",
                duo.sending.managed.connections.recovery(&peer)
            )
        })?;
        // The stop survived the dial's return, and the place is back by the time the later
        // offers are made.
        ended(transfer.state(), TransferState::Stopped)?;
        let mut later = Vec::new();
        for name in ["after-the-dial.bin", "after-the-dial-too.bin"] {
            let file = Generated::new(name, FILE_BYTES);
            later.push(offer(&duo, &file).map_err(|error| {
                format!("a transfer after a stop during the dial was refused: {error}")
            })?);
        }
        for each in &later {
            each.stop();
        }
        Ok(())
    })
}

/// An answer cut off inside its frame is a lost attempt, never a refusal.
///
/// The raw receiving side answers the first offer with an answer frame that stops inside its
/// header — the stream ends there, so nothing more is coming — and the second offer with a
/// refusal. A frame that is not whole is not a vocabulary this build cannot speak: the attempt is
/// lost, the sender asks again, and the answer it then gets is the one that counts. Reading it as
/// "not understood" would end a transfer over a word the receiving side never finished writing.
pub(crate) fn a_truncated_answer_is_a_lost_attempt() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        // Status 11 is `resume`; the frame is cut off two bytes into its header.
        let mut resume = Vec::new();
        resume.extend_from_slice(&field(0x01, &[11]));
        resume.extend_from_slice(&field(0x02, &0u64.to_be_bytes()));
        let full = answer_frame(&resume);
        let cut = full[..29].to_vec();
        // Status 3 is `refused`, and 0x04 is which step: 2 is the right.
        let mut refused = Vec::new();
        refused.extend_from_slice(&field(0x01, &[3]));
        refused.extend_from_slice(&field(0x04, &[2]));
        let raw = raw_pair(&sim, &beacon, vec![cut, answer_frame(&refused)]).await?;
        let (receiver, managed, transfers) = (&raw.receiver, &raw.managed, &raw.transfers);
        let file = Generated::new("a-cut-off.bin", FILE_BYTES);
        let transfer = transfers
            .send(
                &managed.connections,
                &managed.endpoint,
                &receiver.peer_id(),
                file.offering(),
            )
            .map_err(|error| error.to_string())?;
        let state = drive_transfer_in(&sim, BUDGET, Duration::from_secs(1), &transfer).await?;
        failed(state, TransferFailure::Refused { step: Step::Right })
    })
}

/// A peer that repeats one offset is not making progress, and the stall bound ends it.
///
/// The raw receiving side answers `resume` at zero, reads the file, and then says `running` at
/// zero two hundred times on the same stream: every word is the same byte the file has already
/// been at. A word only counts as progress when the offset it states has grown, so the transfer is
/// abandoned one stall bound after the last real progress — the same bound a silent peer meets —
/// instead of parking itself, and one of this machine's places for the peer, for ever.
pub(crate) fn a_peer_that_repeats_one_offset_is_abandoned() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        // Status 11 is `resume`, 2 is `running`, and 0x02 is the offset.
        let mut resume = Vec::new();
        resume.extend_from_slice(&field(0x01, &[11]));
        resume.extend_from_slice(&field(0x02, &0u64.to_be_bytes()));
        let mut word = Vec::new();
        word.extend_from_slice(&field(0x01, &[2]));
        word.extend_from_slice(&field(0x02, &0u64.to_be_bytes()));
        let raw = raw_pair_with(&sim, &beacon, move |receiver| {
            raw_repeating_receiver(
                receiver,
                answer_frame(&resume),
                answer_frame(&word),
                REPEATS,
            )
        })
        .await?;
        let (receiver, managed, transfers) = (&raw.receiver, &raw.managed, &raw.transfers);
        let file = Generated::new("one-offset.bin", FILE_BYTES);
        let transfer = transfers
            .send(
                &managed.connections,
                &managed.endpoint,
                &receiver.peer_id(),
                file.offering(),
            )
            .map_err(|error| error.to_string())?;
        let state = drive_transfer_in(
            &sim,
            TRANSFER_STALL + BUDGET,
            Duration::from_secs(1),
            &transfer,
        )
        .await?;
        failed(state, TransferFailure::NoProgress)?;
        let spent = sim.clock().elapsed();
        if spent < TRANSFER_STALL {
            return Err(format!(
                "the transfer was over after {spent:?}, before the {TRANSFER_STALL:?} bound that \
                 a repeated offset may not hold off"
            ));
        }
        Ok(())
    })
}

/// An offer the pair keeps answering `running` about the same offset is a live connection doing
/// nothing, and the stall bound measures the attempt as well as the pause after it.
///
/// The raw peer loses the first offer and then answers every later one with `running` at zero,
/// twenty-nine seconds after each arrives, so every attempt is long and none of them moves a
/// byte. The transfer ends one stall bound later, after a handful of offers: one that charged
/// only the pause between attempts would spend a second a round and outlive its own bound sixty
/// times over, which is what the count of answered offers and the case's own budget say.
pub(crate) fn an_offer_answered_with_nothing_new_is_abandoned() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let answered = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&answered);
        let raw = raw_pair_with(&sim, &beacon, |receiver| {
            raw_slow_repeating_receiver(receiver, sim.clock(), LATE_ANSWER, counted)
        })
        .await?;
        let (receiver, managed, transfers) = (&raw.receiver, &raw.managed, &raw.transfers);
        let file = Generated::new("one-hanging-offer.bin", FILE_BYTES);
        let transfer = transfers
            .send(
                &managed.connections,
                &managed.endpoint,
                &receiver.peer_id(),
                file.offering(),
            )
            .map_err(|error| error.to_string())?;
        let state = drive_transfer_in(
            &sim,
            TRANSFER_STALL + BUDGET,
            Duration::from_secs(1),
            &transfer,
        )
        .await?;
        failed(state, TransferFailure::NoProgress)?;
        let spent = sim.clock().elapsed();
        if spent < TRANSFER_STALL {
            return Err(format!(
                "the transfer was over after {spent:?}, before the {TRANSFER_STALL:?} bound that \
                 nothing moving may not hold off"
            ));
        }
        let offers = answered.load(Ordering::SeqCst);
        let allowed = usize::try_from(MAX_TRANSFER_STARTS).expect("a start limit is a small count");
        if offers > allowed {
            return Err(format!(
                "the transfer made {offers} offers to spend one stall bound: the time an attempt \
                 spends being answered with nothing is not counted against it"
            ));
        }
        Ok(())
    })
}

/// An offer the receiving machine never answers spends the wait bound on the attempt itself, not
/// only on the pause after it.
///
/// The raw peer reads every offer and says nothing, so each round costs this machine its whole
/// answer budget before it is one that produced no answer at all. Charged the attempt, the
/// transfer reaches the wait bound in a handful of rounds; charged only the pause between them it
/// would need sixty, each of those a further answer budget long.
pub(crate) fn a_hanging_offer_spends_the_wait_bound() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let offers = Arc::new(Mutex::new(Vec::new()));
        let counted = Arc::clone(&offers);
        let clock = sim.clock().clone();
        let raw = raw_pair_with(&sim, &beacon, move |receiver| {
            raw_mostly_silent_receiver(receiver, &clock, Silence::Hold, None, counted)
        })
        .await?;
        let (receiver, managed, transfers) = (&raw.receiver, &raw.managed, &raw.transfers);
        let file = Generated::new("a-hanging-offer.bin", FILE_BYTES);
        let transfer = transfers
            .send(
                &managed.connections,
                &managed.endpoint,
                &receiver.peer_id(),
                file.offering(),
            )
            .map_err(|error| error.to_string())?;
        let state = drive_transfer_in(
            &sim,
            TRANSFER_WAIT + BUDGET,
            Duration::from_secs(1),
            &transfer,
        )
        .await?;
        failed(state, TransferFailure::NoPair)?;
        let spent = sim.clock().elapsed();
        if spent < TRANSFER_WAIT {
            return Err(format!(
                "the transfer was over after {spent:?}, before the {TRANSFER_WAIT:?} bound that \
                 an unanswered offer must spend"
            ));
        }
        let rounds = offers
            .lock()
            .expect("the offer times are not poisoned")
            .len();
        let allowed = 4 * usize::try_from(MAX_TRANSFER_STARTS).expect("a start limit is a count");
        if rounds > allowed {
            return Err(format!(
                "the transfer made {rounds} offers to spend one wait bound: the time an attempt \
                 spends being answered with nothing is not counted against it"
            ));
        }
        Ok(())
    })
}

/// The wait between two offers the pair left unanswered doubles, so a pair that never binds is not
/// offered a file once a second for the whole wait bound.
///
/// The raw peer ends every offer's stream without a word, so no round spends the answer budget and
/// the gap between two offers is the pause itself. The case reads every gap against the schedule
/// the texts state — a second, then double, capped at eight — so a wait that does not double fails
/// where it should have grown, and a cap that is not eight fails where the doubling stops growing.
pub(crate) fn a_silent_pair_is_asked_again_at_a_doubling_gap() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let offers = Arc::new(Mutex::new(Vec::new()));
        let counted = Arc::clone(&offers);
        let clock = sim.clock().clone();
        let raw = raw_pair_with(&sim, &beacon, move |receiver| {
            raw_mostly_silent_receiver(receiver, &clock, Silence::End, None, counted)
        })
        .await?;
        let (receiver, managed, transfers) = (&raw.receiver, &raw.managed, &raw.transfers);
        let file = Generated::new("a-silent-pair.bin", FILE_BYTES);
        let transfer = transfers
            .send(
                &managed.connections,
                &managed.endpoint,
                &receiver.peer_id(),
                file.offering(),
            )
            .map_err(|error| error.to_string())?;
        let minute = Duration::from_secs(60);
        advance_until(&sim, BUDGET, Duration::from_secs(1), || {
            sim.clock().elapsed() > minute
        })
        .await?;
        let times = offers
            .lock()
            .expect("the offer times are not poisoned")
            .clone();
        if times.len() < 5 {
            return Err(format!(
                "the transfer made {} offers in {minute:?}: too few to read the schedule",
                times.len()
            ));
        }
        // Every gap against the schedule the texts state: a second, then double, capped at eight.
        // A wait that does not double fails at the gap where it should have grown, and a cap that
        // is not the stated one fails where the doubling stops growing, in either direction.
        let mut expected = Duration::from_secs(1);
        for (index, pair) in times.windows(2).enumerate() {
            let gap = pair[1] - pair[0];
            if gap != expected {
                return Err(format!(
                    "the gap after offer {index} is {gap:?}, not the {expected:?} the doubling \
                     states"
                ));
            }
            expected = (expected * 2).min(Duration::from_secs(8));
        }
        ended(transfer.state(), TransferState::Waiting)
    })
}

/// An attempt the pair answers without pacing the transfer puts the retry wait back to a second, so
/// a pair that answers once is not then left waiting out the doubling.
///
/// The raw peer loses the first offer, answers the second with `running` at zero — an answer that
/// neither throttles nor grows the offset — and loses every later one. The first gap is a second,
/// and so is the gap after the answered attempt: without the reset the wait would still be the
/// doubled one, and the third offer would follow the second by two seconds.
pub(crate) fn an_answer_without_pacing_restarts_the_retry_gap() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let offers = Arc::new(Mutex::new(Vec::new()));
        let counted = Arc::clone(&offers);
        let clock = sim.clock().clone();
        let raw = raw_pair_with(&sim, &beacon, move |receiver| {
            // Status 2 is `running`, 0x02 the offset it names: the second offer is answered, and
            // the offset it states has not grown.
            let running =
                answer_frame(&[field(0x01, &[2]), field(0x02, &0u64.to_be_bytes())].concat());
            raw_mostly_silent_receiver(
                receiver,
                &clock,
                Silence::End,
                Some(OneAnswer {
                    offer: 2,
                    bytes: running,
                }),
                counted,
            )
        })
        .await?;
        let (receiver, managed, transfers) = (&raw.receiver, &raw.managed, &raw.transfers);
        let file = Generated::new("answered-once.bin", FILE_BYTES);
        let transfer = transfers
            .send(
                &managed.connections,
                &managed.endpoint,
                &receiver.peer_id(),
                file.offering(),
            )
            .map_err(|error| error.to_string())?;
        advance_until(&sim, BUDGET, Duration::from_secs(1), || {
            offers
                .lock()
                .expect("the offer times are not poisoned")
                .len()
                >= 3
        })
        .await?;
        let times = offers
            .lock()
            .expect("the offer times are not poisoned")
            .clone();
        if times.len() < 3 {
            return Err(format!(
                "the transfer made {} offers: the answered attempt led to no other",
                times.len()
            ));
        }
        let first = times[1] - times[0];
        if first != Duration::from_secs(1) {
            return Err(format!(
                "the second offer came {first:?} after the first, not the one-second first gap"
            ));
        }
        let after_answer = times[2] - times[1];
        if after_answer != Duration::from_secs(1) {
            return Err(format!(
                "the offer after the answered attempt came {after_answer:?} later: the wait is \
                 not put back to one second"
            ));
        }
        ended(transfer.state(), TransferState::Waiting)
    })
}

/// An answer frame a look cuts in half is kept and continued, not read as a new frame.
///
/// The raw peer writes all but the last byte of its `resume`, waits two seconds — longer than the
/// poll the answer is read in — and writes the last one. A sender that dropped the bytes it had
/// would meet a body byte where the answer's magic should be and end the transfer `not understood`;
/// one that keeps them reads the frame whole and takes the file.
pub(crate) fn an_answer_cut_by_a_poll_is_continued() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let clock = sim.clock().clone();
        let raw = raw_pair_with(&sim, &beacon, move |receiver| {
            raw_split_answer_receiver(receiver, &clock, Duration::from_secs(2))
        })
        .await?;
        let (receiver, managed, transfers) = (&raw.receiver, &raw.managed, &raw.transfers);
        let file = Generated::new("a-cut-by-a-poll.bin", FILE_BYTES);
        let transfer = transfers
            .send(
                &managed.connections,
                &managed.endpoint,
                &receiver.peer_id(),
                file.offering(),
            )
            .map_err(|error| error.to_string())?;
        let state = drive_transfer_in(&sim, BUDGET, Duration::from_secs(1), &transfer).await?;
        ended(state, TransferState::Finished { bytes: FILE_BYTES })
    })
}

/// An offer the pair answered is not one it never answered, so a throttle met afterwards is the
/// start limit it names and not the pair's silence.
///
/// The raw peer loses a whole start window of offers, answers the next one `running` — an answer,
/// though not one that takes the file — and then throttles that transfer and every later offer for
/// a whole wait bound. What decides which cause a throttle streak ends as is the count of offers
/// this machine wrote and got nothing back for, and any answer that is not a bare limit clears it:
/// without that, a streak that began after a whole window of silence would end as `no pair`,
/// blaming the pair for the window this machine's own silence filled. A throttle spends neither
/// bound, so the streak's own wait bound is what ends the transfer, which is the time the case
/// measures.
pub(crate) fn a_pair_that_answered_is_not_a_pair_that_was_not_there() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let asked = u32::try_from(TRANSFER_THROTTLE_CAP.as_secs())
            .expect("a throttle cap is far below four billion seconds");
        // Status 5 is `limit`, 0x04 which limit — 2 is starts — and 0x03 the delay it names.
        let throttle = answer_frame(
            &[
                field(0x01, &[5]),
                field(0x04, &[2]),
                field(0x03, &asked.to_be_bytes()),
            ]
            .concat(),
        );
        let lost = usize::try_from(MAX_TRANSFER_STARTS).expect("a start limit is a small count");
        let raw = raw_pair_with(&sim, &beacon, move |receiver| {
            raw_running_then_throttling_receiver(receiver, lost, throttle)
        })
        .await?;
        let (receiver, managed, transfers) = (&raw.receiver, &raw.managed, &raw.transfers);
        let file = Generated::new("a-answered-offer.bin", FILE_BYTES);
        let transfer = transfers
            .send(
                &managed.connections,
                &managed.endpoint,
                &receiver.peer_id(),
                file.offering(),
            )
            .map_err(|error| error.to_string())?;
        let state = drive_transfer_in(
            &sim,
            TRANSFER_WAIT + BUDGET,
            Duration::from_secs(1),
            &transfer,
        )
        .await?;
        failed(
            state,
            TransferFailure::Limit {
                which: TransferLimit::Starts,
                retry_after: Some(TRANSFER_THROTTLE_CAP),
            },
        )?;
        let spent = sim.clock().elapsed();
        if spent < TRANSFER_WAIT {
            return Err(format!(
                "the transfer was over after {spent:?}, before the {TRANSFER_WAIT:?} bound a \
                 throttle streak must spend: it ended for some reason other than the streak"
            ));
        }
        Ok(())
    })
}

/// A pair that answers one offer and then stops answering ends as the pair at the wait bound.
///
/// The raw peer reads the first offer and finishes the stream with nothing, answers the second
/// `running` at zero — an answer that is not a bare limit and states an offset that has not grown —
/// and finishes every later stream with nothing, so every offer after the last the pair answered is
/// one it left unanswered. The case pins the cause and the bound: a pair that answers and then goes
/// silent ends `no pair` once [`TRANSFER_WAIT`] is spent — the cause the list in
/// [`TransferFailure::NoPair`] names — rather than at the first offer it left unanswered.
pub(crate) fn a_pair_that_answered_and_then_went_silent_ends_as_the_pair() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let offers = Arc::new(Mutex::new(Vec::new()));
        let counted = Arc::clone(&offers);
        let clock = sim.clock().clone();
        let raw = raw_pair_with(&sim, &beacon, move |receiver| {
            // Status 2 is `running`, 0x02 the offset it names: the second offer is answered, and
            // the offset it states has not grown. Every later stream is finished with nothing.
            let running =
                answer_frame(&[field(0x01, &[2]), field(0x02, &0u64.to_be_bytes())].concat());
            raw_mostly_silent_receiver(
                receiver,
                &clock,
                Silence::End,
                Some(OneAnswer {
                    offer: 2,
                    bytes: running,
                }),
                counted,
            )
        })
        .await?;
        let (receiver, managed, transfers) = (&raw.receiver, &raw.managed, &raw.transfers);
        let file = Generated::new("answered-then-silent.bin", FILE_BYTES);
        let transfer = transfers
            .send(
                &managed.connections,
                &managed.endpoint,
                &receiver.peer_id(),
                file.offering(),
            )
            .map_err(|error| error.to_string())?;
        let state = drive_transfer_in(
            &sim,
            TRANSFER_WAIT + BUDGET,
            Duration::from_secs(1),
            &transfer,
        )
        .await?;
        failed(state, TransferFailure::NoPair)?;
        let spent = sim.clock().elapsed();
        if spent < TRANSFER_WAIT {
            return Err(format!(
                "the transfer was over after {spent:?}, before the {TRANSFER_WAIT:?} bound a pair \
                 that answered once and then stopped answering must spend"
            ));
        }
        let times = offers
            .lock()
            .expect("the offer times are not poisoned")
            .clone();
        if times.len() < 3 {
            return Err(format!(
                "the transfer made {} offers: the answered attempt was not followed by another \
                 the pair left unanswered",
                times.len()
            ));
        }
        // The answered attempt reset the retry gap to one second: without that, this case would be
        // the silent-pair case with an answer the transfer never read.
        let after_answer = times[2] - times[1];
        if after_answer != Duration::from_secs(1) {
            return Err(format!(
                "the offer after the answered one came {after_answer:?} later, not the one-second \
                 gap an answer resets: the `running` answer never reached the transfer"
            ));
        }
        Ok(())
    })
}

/// An attempt that never left is not an offer, so the next attempt is still the transfer's first
/// one — and a `running` answer to it names a transfer that is not this machine's.
///
/// The raw peer answers `running` at zero to every offer. The pair's bidirectional-stream credit is
/// spent before the file is offered, so the first attempt cannot open a stream at all: it asked the
/// pair nothing, and the attempt that follows it is still this transfer's first offer. A `running`
/// answer to a first offer is a name another transfer holds there, which ends as `already running`.
/// Counted as an offer instead, the same answer would be read as this machine's own earlier attempt
/// and waited out until the stall bound, and the transfer would end `no progress` a minute later
/// without ever having asked anything.
pub(crate) fn an_attempt_that_never_left_is_still_the_first_offer() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let raw = raw_pair_with(&sim, &beacon, raw_running_receiver).await?;
        let (receiver, managed, transfers) = (&raw.receiver, &raw.managed, &raw.transfers);
        // The pair's connection, once its binding exchange has finished: the exchange owns the
        // first stream, and a stream this case opens before it would be taken for the exchange.
        let traffic = raw
            .managed
            .connections
            .traffic(&raw.receiver.peer_id())
            .ok_or("the pair has no live connection")?;
        advance_until(&sim, BUDGET, Duration::from_millis(100), || {
            raw.managed
                .connections
                .traffic(&raw.receiver.peer_id())
                .is_some_and(|each| each.exchange_done())
        })
        .await?;
        // Every stream the connection will give, held: the transfer's first attempt is then one
        // that waits for credit it will not get, and gives up without writing an offer. The count
        // is the connection's own — one of its streams is the binding exchange's, which the pair
        // has not let go of — rather than a number this case picked, so the probe is never the
        // thing that blocks.
        let connection = traffic.connection().clone();
        let mut held = Vec::new();
        while let Ok(opened) = within(&sim, Duration::from_secs(1), connection.open_bi()).await {
            held.push(opened.map_err(|error| error.to_string())?);
        }
        if held.is_empty() {
            return Err("the pair's connection took no stream at all".to_owned());
        }
        let file = Generated::new("a-first-offer.bin", FILE_BYTES);
        let transfer = transfers
            .send(
                &managed.connections,
                &managed.endpoint,
                &receiver.peer_id(),
                file.offering(),
            )
            .map_err(|error| error.to_string())?;
        // The first attempt spends the whole answer budget in `open_bi` and is one that could not
        // open a stream: a second of the wait bound and a retry, and nothing else.
        let started = sim.clock().elapsed();
        advance_until(&sim, BUDGET, Duration::from_secs(1), || {
            sim.clock().elapsed() >= started + Duration::from_secs(32)
        })
        .await?;
        // The credit comes back, and the attempt after it is still the transfer's first offer.
        drop(held);
        let state = drive_transfer_in(&sim, BUDGET, Duration::from_secs(1), &transfer).await?;
        failed(state, TransferFailure::AlreadyRunning)
    })
}

/// A receiving machine that spends its whole bound before it answers is heard, because the sending
/// side's bound outlasts its worst honest silence.
///
/// The raw peer resumes at zero, reads one chunk and then says nothing for [`TRANSFER_STALL`] plus
/// three and a half seconds — a sink that answers "not now" for its whole bound, then one look at
/// the stream, then the answer it writes. The sender is parked on a write the whole time, because
/// the file is twice one stream's window and the peer reads a chunk of it. The sender's bound is the
/// receiver's plus the margin [`TRANSFER_GRACE`] states, so the answer is read as `store failed`
/// instead of the transfer being timed out as `no progress` while the peer's own answer was "could
/// not store it" — two causes for one event. No other case reaches a parked write with an answer
/// this late.
pub(crate) fn a_store_that_spends_its_whole_bound_is_heard() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let clock = sim.clock().clone();
        let raw = raw_pair_with(&sim, &beacon, move |receiver| {
            // The bound, the one-second look at the stream, and the answer's travel: past the
            // receiver's own bound, past the first look a sender could take after it, and inside
            // the sender's own bound.
            raw_late_store_failure(
                receiver,
                &clock,
                TRANSFER_STALL + Duration::from_millis(3500),
            )
        })
        .await?;
        let (receiver, managed, transfers) = (&raw.receiver, &raw.managed, &raw.transfers);
        // Twice one stream's window: the sender cannot finish writing, so it is parked on a write
        // when the answer lands.
        let file = Generated::new("a-slow-store.bin", 2 * MAX_STREAM_BYTES as u64);
        let transfer = transfers
            .send(
                &managed.connections,
                &managed.endpoint,
                &receiver.peer_id(),
                file.offering(),
            )
            .map_err(|error| error.to_string())?;
        let state = drive_transfer_in(
            &sim,
            TRANSFER_STALL + BUDGET,
            Duration::from_secs(1),
            &transfer,
        )
        .await?;
        failed(state, TransferFailure::StoreFailed)?;
        let spent = sim.clock().elapsed();
        if spent < TRANSFER_STALL {
            return Err(format!(
                "the transfer was over after {spent:?}, before the {TRANSFER_STALL:?} the \
                 receiving machine's sink spends before it answers"
            ));
        }
        Ok(())
    })
}

/// An offset stated in an attempt that ended in a throttle is not thrown away, so restating it is
/// not growth and clears neither bound.
///
/// The raw peer first spends most of the stall bound on rounds that get the file no further — a
/// resume whose stream is finished at once, then three `running` answers at zero, each one eighteen
/// seconds after its offer — then resumes at zero, states four kibibytes and throttles the
/// transfer, and states that same offset in every later answer. Nothing takes the receiver's offset
/// back, a throttle included, so the restatement is the file not getting further and the bound
/// those rounds spent ends the transfer. Forgotten, the restatement would be read as growth: both
/// bounds would start again and the transfer would need another whole bound, which is what the
/// case's budget refuses.
///
/// The throttle is read in the verdict after the bytes: every byte of the small file is in before
/// the offset and the limit are written.
pub(crate) fn an_offset_stated_before_a_throttle_is_not_growth() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let clock = sim.clock().clone();
        // Status 5 is `limit`, 0x04 which limit — 2 is starts — and 0x03 the delay it names: one
        // second, so each restatement round is short and the bound is what ends the transfer.
        let throttle = answer_frame(
            &[
                field(0x01, &[5]),
                field(0x04, &[2]),
                field(0x03, &1u32.to_be_bytes()),
            ]
            .concat(),
        );
        let raw = raw_pair_with(&sim, &beacon, move |receiver| {
            // A resume round and three of eighteen seconds, inside the thirty a single answer may
            // take: enough to put the transfer near the bound, and each a round the bound is spent
            // on. The throttle is read in the verdict after the bytes.
            raw_offset_then_throttle_receiver(
                receiver,
                &clock,
                4,
                Duration::from_secs(18),
                4096,
                throttle,
                false,
            )
        })
        .await?;
        let (receiver, managed, transfers) = (&raw.receiver, &raw.managed, &raw.transfers);
        let file = Generated::new("a-throttled-offset.bin", FILE_BYTES);
        let transfer = transfers
            .send(
                &managed.connections,
                &managed.endpoint,
                &receiver.peer_id(),
                file.offering(),
            )
            .map_err(|error| error.to_string())?;
        // Ninety seconds: past the bound the rounds before the throttle spent, and far short of
        // the second bound a forgotten offset would buy.
        let state = drive_transfer_in(
            &sim,
            TRANSFER_STALL + Duration::from_secs(30),
            Duration::from_secs(1),
            &transfer,
        )
        .await?;
        failed(state, TransferFailure::NoProgress)?;
        let spent = sim.clock().elapsed();
        if spent < TRANSFER_STALL {
            return Err(format!(
                "the transfer was over after {spent:?}, before the {TRANSFER_STALL:?} bound that \
                 an offset restated may not hold off"
            ));
        }
        Ok(())
    })
}

/// The same rule where the throttle is read while the sending side is parked on a write: the offset
/// the attempt stated is carried out of it, so the first restatement is not growth.
///
/// A mebibyte past the sending side's own stream window, so the sender cannot finish writing
/// before the words arrive: the offset and the limit are read by the write loop rather than by the
/// verdict after the bytes. The rounds before the throttle are fewer and later than in the case
/// above — a resume round and two of twenty-five seconds, against a resume round and three of
/// eighteen — because the file is larger and the parked write is what this case is for. Every
/// answer after the throttle states the same offset, and a forgotten offset would buy the
/// transfer a second whole bound, which the case's budget refuses.
pub(crate) fn an_offset_stated_while_parked_is_not_growth() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let clock = sim.clock().clone();
        // Status 5 is `limit`, 0x04 which limit — 2 is starts — and 0x03 the delay it names: one
        // second, so each restatement round is short and the bound is what ends the transfer.
        let throttle = answer_frame(
            &[
                field(0x01, &[5]),
                field(0x04, &[2]),
                field(0x03, &1u32.to_be_bytes()),
            ]
            .concat(),
        );
        let raw = raw_pair_with(&sim, &beacon, move |receiver| {
            // A resume round and two of twenty-five seconds, inside the thirty a single answer may
            // take: most of the bound is spent before the throttle, and the throttle is read by
            // the write loop.
            raw_offset_then_throttle_receiver(
                receiver,
                &clock,
                3,
                Duration::from_secs(25),
                4096,
                throttle,
                true,
            )
        })
        .await?;
        let (receiver, managed, transfers) = (&raw.receiver, &raw.managed, &raw.transfers);
        // One mebibyte past the sending side's own stream window: it cannot finish writing, so it
        // is parked on a write when the words arrive.
        let file = Generated::new(
            "a-parked-throttle.bin",
            MAX_STREAM_BYTES as u64 + 1024 * 1024,
        );
        let transfer = transfers
            .send(
                &managed.connections,
                &managed.endpoint,
                &receiver.peer_id(),
                file.offering(),
            )
            .map_err(|error| error.to_string())?;
        // Ninety seconds: past the bound the rounds before the throttle spent, and far short of
        // the second bound a forgotten offset would buy.
        let state = drive_transfer_in(
            &sim,
            TRANSFER_STALL + Duration::from_secs(30),
            Duration::from_secs(1),
            &transfer,
        )
        .await?;
        failed(state, TransferFailure::NoProgress)?;
        let spent = sim.clock().elapsed();
        if spent < TRANSFER_STALL {
            return Err(format!(
                "the transfer was over after {spent:?}, before the {TRANSFER_STALL:?} bound that \
                 an offset restated may not hold off"
            ));
        }
        Ok(())
    })
}

/// A write the stream accepts is not the file getting further, so it may not refresh the attempt's
/// own stall clock.
///
/// The raw peer resumes at zero and then takes six mebibytes of the file every ten seconds of the
/// case's clock, saying nothing at all, with the stream held open throughout. Six mebibytes is a
/// batch the transport returns credit for, so the sender's writes really do get accepted between
/// the silences; the file is twice the sending side's own window, so the transfer cannot finish
/// inside the case's budget either way. Only the offset the receiver states moves the clock, and
/// this peer states none: the transfer is abandoned at the stall bound. If an accepted write
/// refreshed the clock, every batch would buy the transfer another ten seconds and it would still
/// be writing — or, at best, waiting for a verdict — when the budget ran out, which is the shape of
/// a peer that reads a byte a minute and parks one of this machine's places for the peer for the
/// length of the file.
pub(crate) fn a_write_the_stream_accepts_is_not_progress() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let clock = sim.clock().clone();
        let raw = raw_pair_with(&sim, &beacon, move |receiver| {
            raw_slow_drain(receiver, &clock, 6 * 1024 * 1024, Duration::from_secs(10))
        })
        .await?;
        let (receiver, managed, transfers) = (&raw.receiver, &raw.managed, &raw.transfers);
        // Twice what this machine may buffer of its own writes: the sender cannot finish the file
        // inside the case's budget, so nothing but the stall bound can end the transfer.
        let file = Generated::new("a-slow-drain.bin", 2 * MAX_BUFFERED_BYTES as u64);
        let transfer = transfers
            .send(
                &managed.connections,
                &managed.endpoint,
                &receiver.peer_id(),
                file.offering(),
            )
            .map_err(|error| error.to_string())?;
        // A minute and a half: past the bound, and short of the second one a clock refreshed by
        // accepted writes would buy.
        let state = drive_transfer_in(
            &sim,
            TRANSFER_STALL + Duration::from_secs(30),
            Duration::from_secs(1),
            &transfer,
        )
        .await?;
        failed(state, TransferFailure::NoProgress)?;
        let spent = sim.clock().elapsed();
        if spent < TRANSFER_STALL {
            return Err(format!(
                "the transfer was over after {spent:?}, before the {TRANSFER_STALL:?} bound that \
                 bytes the stream accepted may not hold off"
            ));
        }
        Ok(())
    })
}
