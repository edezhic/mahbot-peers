//! Presence cases: one registration per machine, one reader, and where a ceremony's flights go.
//!
//! The beacon keeps one registration per peer and the latest wins, so the two sessions a
//! machine used to hold — one for its presence, one for a ceremony — displaced each other. Each
//! case here pins one consequence of that, or one rule of the single registration and its one
//! reader that replaced it.

use std::task::Poll;
use std::time::Duration;

use mahbot_beacon::core::REGISTRATION_TTL;
use mahbot_peers::beacon::{BeaconError, Introduction, Request};
use mahbot_peers::identity::PeerId;
use mahbot_peers::peer::pair::{self, Ceremony, Opening};
use mahbot_peers::peer::{
    ConnectFailure, Connections, MAX_HELD, MAX_PENDING, PAIR_FLIGHT_TIMEOUT, Presence,
    RECOVERY_DIALS, Registration,
};

use crate::beacon::TestBeacon;
use crate::clock::block_on;
use crate::machine::Machine;
use crate::raw::RawClient;
use crate::sim::Sim;

use super::peer::{NOW, Pairing, Shown, now, pair_together, pair_with_delay, paired};
use super::support::{Woken, io_error, keep_findable, poll_once, within};

/// Push one opaque introduction from `sender` to `target` over `beacon`.
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

/// Push one opening — a real ceremony's first flight — from `sender` to `target`, so the
/// target's presence has something it can hold for a person who has not started, and answer what
/// was sent.
pub(super) async fn push_opening(
    sim: &Sim,
    beacon: &TestBeacon,
    sender: &Machine,
    target: &Machine,
) -> Result<Vec<u8>, String> {
    let (_, opening) = Ceremony::initiate(sender.peer_id(), target.fingerprint(), None, false)
        .map_err(|error| error.to_string())?;
    push(sim, beacon, sender, target, &opening).await?;
    Ok(opening)
}

/// The confirmation a ceremony's second side sends in one attempt, once it has seen the reveal.
/// It is a real ceremony payload, so a case that pushes it is pushing what a peer would.
fn confirmation(sender: &Machine, target: &Machine) -> Result<Vec<u8>, String> {
    let (mut initiator, opening) =
        Ceremony::initiate(sender.peer_id(), target.fingerprint(), None, false)
            .map_err(|error| error.to_string())?;
    let introduction = Introduction::signed(&sender.identity, target.peer_id(), opening)
        .map_err(|error| error.to_string())?;
    let (mut responder, answer) = Ceremony::respond(target.peer_id(), &introduction, None, false)
        .map_err(|error| error.to_string())?;
    let answer = answer.send.ok_or("the responder sent no answer")?;
    let reveal = initiator
        .receive(&answer)
        .map_err(|error| error.to_string())?
        .send
        .ok_or("the initiator revealed nothing")?;
    responder
        .receive(&reveal)
        .map_err(|error| error.to_string())?;
    let confirmation = responder
        .confirm(true)
        .map_err(|error| error.to_string())?
        .send
        .ok_or("the responder confirmed nothing")?;
    Ok(confirmation)
}

/// The three flights one attempt's initiator sends, in the order it sends them: its opening, its
/// reveal, and its confirmation. The responder's side is built and never delivered anything, so a
/// case that pushes these is pushing exactly what a peer in that position would.
fn initiator_flights(sender: &Machine, target: &Machine) -> Result<Vec<Vec<u8>>, String> {
    let (mut initiator, opening) =
        Ceremony::initiate(sender.peer_id(), target.fingerprint(), None, false)
            .map_err(|error| error.to_string())?;
    let introduction = Introduction::signed(&sender.identity, target.peer_id(), opening.clone())
        .map_err(|error| error.to_string())?;
    let (mut responder, answer) = Ceremony::respond(target.peer_id(), &introduction, None, false)
        .map_err(|error| error.to_string())?;
    let reveal = initiator
        .receive(&answer.send.ok_or("the responder sent no answer")?)
        .map_err(|error| error.to_string())?
        .send
        .ok_or("the initiator revealed nothing")?;
    responder
        .receive(&reveal)
        .map_err(|error| error.to_string())?;
    let confirmation = initiator
        .confirm(true)
        .map_err(|error| error.to_string())?
        .send
        .ok_or("the initiator confirmed nothing")?;
    Ok(vec![opening, reveal, confirmation])
}

/// A ceremony runs over the machine's own registration, and the machine is findable through it:
/// the beacon holds both machines before and after, and a peer looking either up gets its
/// address.
pub(crate) fn a_ceremony_leaves_the_registration_where_it_was() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (left, right, _left_presence, _right_presence) = pair_with_delay(
            &sim,
            &beacon,
            Duration::ZERO,
            Duration::ZERO,
            "the ceremony",
        )
        .await?;
        // A peer looking either machine up gets its address: the machine is findable after a
        // ceremony, as it was before.
        let watcher = sim.machine().map_err(io_error)?;
        let watcher_presence = keep_findable(&sim, &beacon, &watcher).await?;
        for (peer, address) in [
            (left.peer_id(), left.addr()),
            (right.peer_id(), right.addr()),
        ] {
            match watcher_presence.lookup(&peer).await {
                Ok(Some(found)) if found == address => {}
                other => {
                    return Err(format!(
                        "a peer looking {} up after a ceremony found {other:?}, not {address}",
                        peer.fingerprint()
                    ));
                }
            }
        }
        Ok(())
    })
}

/// Pair over a fresh beacon with both people taking `by` to compare, so a case can put the
/// comparison on either side of the registration's refresh or its lifetime. `what` names the case
/// in a failure.
async fn pair_after(by: Duration, what: &str) -> Result<(), String> {
    let sim = Sim::new().map_err(io_error)?;
    let beacon = TestBeacon::start(&sim).map_err(io_error)?;
    pair_with_delay(&sim, &beacon, by, by, what).await?;
    Ok(())
}

/// A registration refreshed while two people compare does not take the flight the ceremony is
/// waiting for: both sides confirm and the pair is written.
pub(crate) fn a_refresh_during_a_comparison_keeps_the_flight() -> Result<(), String> {
    // Longer than a third of the registration's lifetime, so the presence refreshes while both
    // people are looking at the comparison.
    block_on(pair_after(
        REGISTRATION_TTL / 2,
        "a refresh during the comparison",
    ))
}

/// A comparison that takes longer than the registration's own lifetime pairs, with no presence
/// loop and no refresh by the caller: the machine's presence refreshes the registration while the
/// people look.
pub(crate) fn a_comparison_outlives_the_registration_lifetime() -> Result<(), String> {
    block_on(pair_after(
        REGISTRATION_TTL + Duration::from_secs(30),
        "a comparison longer than the registration's lifetime",
    ))
}

/// A confirmation is not aged by the machine-flight timeout: its sender waits for as long as the
/// peer's person compares the same string, in either direction.
///
/// First the responder's person answers at once, so its confirmation is already waiting when the
/// initiator's person finishes a comparison that took longer than a machine waits for a flight;
/// then the other way round, so the initiator's confirmation waits through the responder's slow
/// comparison. Dropping either would leave one side waiting out its whole attempt and starting
/// over, after the other had already written the pair.
pub(crate) fn a_confirmation_is_not_aged_by_the_flight_timeout() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        // A budget of its own, so a confirmation that was dropped is reported as a comparison
        // that did not finish rather than as a rig that stopped making progress.
        let slow = PAIR_FLIGHT_TIMEOUT + Duration::from_secs(5);
        for (left_by, right_by) in [(slow, Duration::ZERO), (Duration::ZERO, slow)] {
            within(
                &sim,
                Duration::from_secs(150),
                pair_with_delay(
                    &sim,
                    &beacon,
                    left_by,
                    right_by,
                    "a comparison longer than the flight timeout",
                ),
            )
            .await??;
        }
        Ok(())
    })
}

/// An opening that arrives before the other machine's person starts the ceremony is held, not
/// lost.
///
/// The machine is registered and reads what the beacon pushes, so the flight arrives; its person
/// has not started on their side, so nothing waits for it yet. Dropping it would make the
/// initiator start over, and the person on the other side never saw anything.
pub(crate) fn a_flight_that_arrives_before_the_person_starts_is_held() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let left = sim.machine().map_err(io_error)?;
        let right = sim.machine().map_err(io_error)?;
        let left_store = left.records();
        let right_store = right.records();
        let left_presence = keep_findable(&sim, &beacon, &left).await?;
        let right_presence = keep_findable(&sim, &beacon, &right).await?;
        let left_shown = Shown::accepting();
        let right_shown = Shown::accepting();
        let (left_outcome, right_outcome) = within(&sim, Duration::from_secs(120), async {
            // The initiator is polled first, and its opening reaches the other machine while that
            // machine's person has not begun: the flight has nobody to go to yet.
            let responder = async {
                sim.clock().advance(Duration::from_secs(10)).await;
                pair::run(
                    &right_presence,
                    &right.identity,
                    Opening::Respond,
                    &right_store,
                    now,
                    right_shown.clone(),
                )
                .await
            };
            tokio::join!(
                pair::run(
                    &left_presence,
                    &left.identity,
                    Opening::Initiate(right.fingerprint()),
                    &left_store,
                    now,
                    left_shown.clone(),
                ),
                responder,
            )
        })
        .await?;
        let left_outcome = left_outcome.map_err(|error| error.to_string());
        let right_outcome = right_outcome.map_err(|error| error.to_string());
        if !paired(&left_outcome) || !paired(&right_outcome) {
            return Err(format!(
                "an opening delivered before the other person started was lost: \
                 {left_outcome:?} / {right_outcome:?}"
            ));
        }
        if left_shown.seen().len() != 1 || right_shown.seen().len() != 1 {
            return Err("the pair was asked to compare more than once".to_owned());
        }
        Ok(())
    })
}

/// A flight the beacon did not hand over is reported as not delivered; a lookup that missed as
/// not registered; and a registered peer whose path answers nothing as no direct path.
///
/// The beacon's one answer covers both a peer it holds no registration for and a connection that
/// could not take the frame, so a sentence naming either would be a cause this machine did not
/// observe. The crate knows which call it made, and each failure is reported as itself.
pub(crate) fn an_undelivered_flight_is_not_an_unregistered_peer() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let left = sim.machine().map_err(io_error)?;
        // A machine that is running, with no presence: nothing registered it.
        let absent = sim.machine().map_err(io_error)?;
        let left_store = left.records();
        let left_presence = keep_findable(&sim, &beacon, &left).await?;
        let failed = within(
            &sim,
            Duration::from_secs(120),
            pair::run(
                &left_presence,
                &left.identity,
                Opening::Initiate(absent.fingerprint()),
                &left_store,
                now,
                Shown::accepting(),
            ),
        )
        .await?
        .map_err(|error| error.to_string());
        let Err(undelivered) = failed else {
            return Err("a flight to a machine with no registration was handed over".to_owned());
        };
        let expected = format!(
            "the beacon did not hand the payload to {}",
            absent.fingerprint()
        );
        if undelivered != expected {
            return Err(format!(
                "a flight the beacon did not hand over reads `{undelivered}`, not `{expected}`"
            ));
        }
        // The beacon's own answer about one delivery, through the presence: it says what became
        // of the payload and nothing about the peer.
        match left_presence
            .introduce(absent.peer_id(), b"an opaque payload")
            .await
        {
            Err(error) => {
                let answer = error.to_string();
                if answer != expected {
                    return Err(format!(
                        "an undelivered payload reads `{answer}`, not `{expected}`"
                    ));
                }
            }
            Ok(()) => {
                return Err(
                    "a payload to a machine with no registration was handed over".to_owned(),
                );
            }
        }
        // The same peer, looked up: this machine made the lookup, and the beacon had no
        // registration for it. That is what the sentence says.
        let endpoint = left.endpoint().map_err(|error| error.to_string())?;
        left_store
            .record_pairing(&absent.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        let manager = Connections::new(
            &left.identity,
            left_store.clone(),
            Some(beacon.client(&left)?),
            sim.clock().runtime(),
            &left.transport,
        )
        .map_err(|error| error.to_string())?;
        let unknown = within(
            &sim,
            Duration::from_secs(120),
            manager.connect(&endpoint, &absent.fingerprint()),
        )
        .await?;
        let Err(unknown) = unknown else {
            return Err("a peer with no registration was reached".to_owned());
        };
        if !matches!(unknown, ConnectFailure::PeerUnknown { .. }) {
            return Err(format!("a lookup that missed was reported as `{unknown}`"));
        }
        let looked_up = unknown.to_string();
        if !looked_up.contains("the beacon does not know") {
            return Err(format!(
                "a lookup that missed reads `{looked_up}`, not that the beacon does not know the \
                 peer"
            ));
        }
        if looked_up.contains("did not hand") {
            return Err(format!(
                "a lookup that missed is reported as a delivery: {looked_up}"
            ));
        }
        // A peer that is registered and whose path answers nothing: the beacon knew it, so the
        // failure is the path, and it is neither of the two above.
        let pathless = sim.machine().map_err(io_error)?;
        let pathless_presence = keep_findable(&sim, &beacon, &pathless).await?;
        left_store
            .record_pairing(&pathless.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        sim.link().silence(pathless.addr());
        let no_path = within(
            &sim,
            Duration::from_secs(120),
            manager.connect(&endpoint, &pathless.fingerprint()),
        )
        .await?;
        let Err(no_path) = no_path else {
            return Err("a silenced peer was reached".to_owned());
        };
        if !matches!(no_path, ConnectFailure::NoDirectPath { .. }) {
            return Err(format!(
                "a registered peer with no path was reported as `{no_path}`"
            ));
        }
        let path = no_path.to_string();
        for wrong in ["does not know", "not registered"] {
            if path.contains(wrong) {
                return Err(format!(
                    "a registered peer whose path answered nothing claims `{wrong}`: {path}"
                ));
            }
        }
        // The registration is still there: it is the path that answered nothing, not the machine.
        if pathless_presence.state() != Registration::Registered {
            return Err(format!(
                "the silenced peer reads `{}` instead of a held registration",
                pathless_presence.state()
            ));
        }
        Ok(())
    })
}

/// One machine pairs with two peers at once, and each ceremony receives only its own peer's
/// flights.
///
/// A flight goes to the ceremony for the peer it comes from, never to whichever ceremony is
/// waiting. A machine pairing with two peers must never show a person a comparison for a peer
/// they did not start with, and must not lose either flight.
pub(crate) fn two_peers_pair_with_one_machine_at_once() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let left = sim.machine().map_err(io_error)?;
        let first = sim.machine().map_err(io_error)?;
        let second = sim.machine().map_err(io_error)?;
        let left_store = left.records();
        let first_store = first.records();
        let second_store = second.records();
        let left_presence = keep_findable(&sim, &beacon, &left).await?;
        let first_presence = keep_findable(&sim, &beacon, &first).await?;
        let second_presence = keep_findable(&sim, &beacon, &second).await?;
        let left_first = Shown::accepting();
        let left_second = Shown::accepting();
        let first_shown = Shown::accepting();
        let second_shown = Shown::accepting();
        let (first_outcome, second_outcome, one, two) =
            within(&sim, Duration::from_secs(120), async {
                tokio::join!(
                    pair::run(
                        &first_presence,
                        &first.identity,
                        Opening::Initiate(left.fingerprint()),
                        &first_store,
                        now,
                        first_shown.clone(),
                    ),
                    pair::run(
                        &second_presence,
                        &second.identity,
                        Opening::Initiate(left.fingerprint()),
                        &second_store,
                        now,
                        second_shown.clone(),
                    ),
                    pair::run(
                        &left_presence,
                        &left.identity,
                        Opening::Respond,
                        &left_store,
                        now,
                        left_first.clone(),
                    ),
                    pair::run(
                        &left_presence,
                        &left.identity,
                        Opening::Respond,
                        &left_store,
                        now,
                        left_second.clone(),
                    ),
                )
            })
            .await?;
        let outcomes = [
            (
                "the first peer",
                first_outcome.map_err(|error| error.to_string()),
            ),
            (
                "the second peer",
                second_outcome.map_err(|error| error.to_string()),
            ),
            (
                "one ceremony on the pairing machine",
                one.map_err(|error| error.to_string()),
            ),
            (
                "the other ceremony on the pairing machine",
                two.map_err(|error| error.to_string()),
            ),
        ];
        for (what, outcome) in &outcomes {
            if !paired(outcome) {
                return Err(format!("{what} did not pair: {outcome:?}"));
            }
        }
        if !left_store.is_paired(&first.peer_id()) || !left_store.is_paired(&second.peer_id()) {
            return Err("the pairing machine kept no record of both peers".to_owned());
        }
        let seen = [left_first.seen(), left_second.seen()];
        if seen.iter().any(|strings| strings.len() != 1) {
            return Err(format!(
                "a ceremony on the pairing machine showed {} comparisons",
                seen.iter().map(Vec::len).sum::<usize>()
            ));
        }
        if seen[0] == seen[1] {
            return Err("both ceremonies showed the same comparison".to_owned());
        }
        Ok(())
    })
}

/// A cancelled ceremony takes its waiting slot with it, so the next flight from that peer reaches
/// the ceremony that waits for it.
///
/// The most likely way the dropped-flight defect comes back with a green suite: a claim left
/// behind swallows the peer's next flight, and the ceremony that is waiting never sees it.
pub(crate) fn a_cancelled_ceremony_takes_its_waiting_slot() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let left = sim.machine().map_err(io_error)?;
        let right = sim.machine().map_err(io_error)?;
        let left_store = left.records();
        let right_store = right.records();
        let left_presence = keep_findable(&sim, &beacon, &left).await?;
        let right_presence = keep_findable(&sim, &beacon, &right).await?;
        // A ceremony that started on this machine and was dropped: it took a claim on the peer
        // and nothing arrived for it.
        {
            let flights = left_presence.flights(right.peer_id());
            if within(&sim, Duration::from_millis(200), flights.next())
                .await
                .is_ok()
            {
                return Err("a ceremony was handed a flight nobody sent".to_owned());
            }
        }
        let (left_outcome, right_outcome) = pair_together(
            &sim,
            Pairing {
                left: &left,
                right: &right,
                left_presence: &left_presence,
                right_presence: &right_presence,
                left_opens: Opening::Respond,
                right_opens: Opening::Initiate(left.fingerprint()),
                left_person: Shown::accepting(),
                right_person: Shown::accepting(),
                left_store: &left_store,
                right_store: &right_store,
            },
        )
        .await?;
        if !paired(&left_outcome) || !paired(&right_outcome) {
            return Err(format!(
                "a cancelled ceremony's claim swallowed the next flight: {left_outcome:?} / \
                 {right_outcome:?}"
            ));
        }
        Ok(())
    })
}

/// An opening is held for [`MAX_HELD`] peers at most — the newest one per peer — and handed out
/// newest first; a payload that cannot start a ceremony is not held at all.
///
/// The reader takes everything the beacon pushes, so the hold is what bounds this machine's
/// memory against a stranger who keeps starting ceremonies: it keeps the newest openings, which
/// are the ones whose people are still looking at their screens.
pub(crate) fn a_hold_is_bounded_and_keeps_the_newest() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let target = sim.machine().map_err(io_error)?;
        let target_presence = keep_findable(&sim, &beacon, &target).await?;
        // The senders are kept for their peer ids: each session is a local that closes when its
        // send is answered.
        let mut senders = Vec::new();
        for _ in 0..=MAX_HELD {
            let sender = sim.machine().map_err(io_error)?;
            push_opening(&sim, &beacon, &sender, &target).await?;
            senders.push(sender);
        }
        let sent: Vec<PeerId> = senders.iter().map(Machine::peer_id).collect();
        let openings = target_presence.openings();
        let taken = within(&sim, Duration::from_secs(120), async {
            let mut taken = Vec::new();
            while taken.len() < MAX_HELD {
                taken.push(openings.next().await.from());
            }
            taken
        })
        .await?;
        let newest: Vec<PeerId> = sent.iter().skip(1).rev().copied().collect();
        if taken != newest {
            return Err(format!(
                "the hold handed out {} openings, not the {} newest, newest first",
                taken.len(),
                newest.len()
            ));
        }
        // The one beyond the cap is not held beside them.
        if within(&sim, Duration::from_millis(200), openings.next())
            .await
            .is_ok()
        {
            return Err(format!("the hold kept more than {MAX_HELD} openings"));
        }
        // A payload that cannot start a ceremony is not held at all: nothing would ever take it,
        // and it would take a place an opening needs.
        let stranger = sim.machine().map_err(io_error)?;
        push(&sim, &beacon, &stranger, &target, b"not a ceremony opening").await?;
        sim.clock().advance(Duration::from_secs(2)).await;
        if within(&sim, Duration::from_millis(200), openings.next())
            .await
            .is_ok()
        {
            return Err("the hold kept a payload that cannot start a ceremony".to_owned());
        }
        Ok(())
    })
}

/// An opening is held once per peer: a machine that starts a second time before anyone waits on it
/// replaces the opening held for it rather than adding another.
///
/// The hold is a place per peer, so a person who starts after the other side restarted is handed
/// the attempt still running and never the one its initiator already abandoned. A hold that kept
/// both would hand the abandoned opening to a second responder.
pub(crate) fn a_hold_keeps_one_opening_per_peer() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let target = sim.machine().map_err(io_error)?;
        let presence = keep_findable(&sim, &beacon, &target).await?;
        let sender = sim.machine().map_err(io_error)?;
        // The same machine starts twice before this machine's person starts at all.
        let abandoned = push_opening(&sim, &beacon, &sender, &target).await?;
        let running = push_opening(&sim, &beacon, &sender, &target).await?;
        if abandoned == running {
            return Err("two starts of one machine produced the same opening".to_owned());
        }
        sim.clock().advance(Duration::from_secs(2)).await;
        let openings = presence.openings();
        let taken = within(&sim, Duration::from_secs(120), openings.next()).await?;
        if taken.payload() != running.as_slice() {
            return Err("the hold handed out the opening the peer had already replaced".to_owned());
        }
        if within(&sim, Duration::from_millis(200), openings.next())
            .await
            .is_ok()
        {
            return Err(
                "the hold kept the replaced opening beside the one that replaced it".to_owned(),
            );
        }
        Ok(())
    })
}

/// A claim takes in the opening held for its peer.
///
/// The other machine may start before this machine's person does, and this machine's person may
/// then start with that peer by fingerprint. The held opening is that attempt's first flight, so a
/// claim that left it in the hold would wait out the whole machine-flight timeout and end the
/// attempt, while a second responder could still be handed the flight.
pub(crate) fn a_claim_takes_in_the_opening_held_for_its_peer() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let target = sim.machine().map_err(io_error)?;
        let presence = keep_findable(&sim, &beacon, &target).await?;
        let sender = sim.machine().map_err(io_error)?;
        // Nobody waits on the sender, so its opening is held.
        let opening = push_opening(&sim, &beacon, &sender, &target).await?;
        sim.clock().advance(Duration::from_secs(2)).await;
        // The person starts with that peer by fingerprint after the other machine did.
        let flights = presence.flights(sender.peer_id());
        let Ok(first) = within(&sim, Duration::from_secs(120), flights.next()).await else {
            return Err(
                "the claim on the peer was never handed the opening held for it".to_owned(),
            );
        };
        if first.payload() != opening.as_slice() {
            return Err("the claim on the peer was not handed the opening held for it".to_owned());
        }
        // The hold and the slot are disjoint: the opening is not in both.
        let openings = presence.openings();
        if within(&sim, Duration::from_millis(200), openings.next())
            .await
            .is_ok()
        {
            return Err(
                "the opening was left in the hold as well as taken by the claim".to_owned(),
            );
        }
        Ok(())
    })
}

/// A peer's flights reach its ceremony in the order they were sent.
///
/// The ceremony claims the peer before any flight arrives, so all of them wait in that peer's
/// slot. The three flights one attempt's initiator sends — its opening, its reveal and its
/// confirmation — are pushed in that order, and the slot hands them over in it. A newer flight
/// must not displace an undelivered older one: the second flight of an exchange is the next step
/// of it, and a ceremony handed that step first ends as out of order and asks its person to
/// compare again for nothing.
///
/// The case drives the claim itself — `presence.flights(peer)`, which is what a ceremony takes
/// — so the flights can be pushed while nothing is taking them; a whole ceremony awaits each
/// flight before the next, so it would never leave more than one waiting.
pub(crate) fn a_peers_flights_reach_its_ceremony_in_the_order_they_were_sent() -> Result<(), String>
{
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let target = sim.machine().map_err(io_error)?;
        let presence = keep_findable(&sim, &beacon, &target).await?;
        let sender = sim.machine().map_err(io_error)?;
        let sent = initiator_flights(&sender, &target)?;
        let flights = presence.flights(sender.peer_id());
        for payload in &sent {
            push(&sim, &beacon, &sender, &target, payload).await?;
        }
        sim.clock().advance(Duration::from_secs(2)).await;
        for (step, expected) in sent.iter().enumerate() {
            let taken = within(&sim, Duration::from_secs(120), flights.next()).await?;
            if taken.payload() != expected.as_slice() {
                return Err(format!(
                    "the slot handed over flight {step} of the attempt, not the one sent at that \
                     step: the peer's flights did not reach its ceremony in the order they were \
                     sent"
                ));
            }
        }
        Ok(())
    })
}

/// One peer's flights wait in a stated number at most, and at the bound the oldest goes.
///
/// A peer that keeps sending has moved on from its oldest flight, so the newest are the ones its
/// person can still act on. The bound is what keeps a peer that never stops sending from growing
/// this machine's memory.
pub(crate) fn a_peers_pending_flights_are_bounded() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let target = sim.machine().map_err(io_error)?;
        let presence = keep_findable(&sim, &beacon, &target).await?;
        let sender = sim.machine().map_err(io_error)?;
        let flights = presence.flights(sender.peer_id());
        // One more than the bound, each a real opening: a peer that gave up and started again.
        let sent = (0..=MAX_PENDING)
            .map(|_| {
                Ceremony::initiate(sender.peer_id(), target.fingerprint(), None, false)
                    .map(|(_, opening)| opening)
                    .map_err(|error| error.to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        for payload in &sent {
            push(&sim, &beacon, &sender, &target, payload).await?;
        }
        sim.clock().advance(Duration::from_secs(2)).await;
        let mut taken = Vec::new();
        for _ in 0..MAX_PENDING {
            taken.push(
                within(&sim, Duration::from_secs(120), flights.next())
                    .await?
                    .payload()
                    .to_vec(),
            );
        }
        if taken != sent[1..] {
            return Err(format!(
                "the slot did not keep the newest {MAX_PENDING} of {} flights: at the bound the \
                 oldest goes",
                sent.len()
            ));
        }
        if within(&sim, Duration::from_millis(200), flights.next())
            .await
            .is_ok()
        {
            return Err(format!("the slot kept more than {MAX_PENDING} flights"));
        }
        Ok(())
    })
}

/// A handle that is dropped takes its waiting with it.
///
/// A handle waiting for any opening files its waker, and a cancelled ceremony's waker must go with
/// it: the push that follows wakes the handle still waiting and not the one that is gone, so
/// nothing accumulates on a machine that receives no further pushes. A claim on one peer is the
/// other half: the slot goes with its last handle, so a flight for that peer afterwards wakes
/// nobody and is not kept.
pub(crate) fn a_dropped_handle_takes_its_waiting_with_it() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let target = sim.machine().map_err(io_error)?;
        let presence = keep_findable(&sim, &beacon, &target).await?;
        let sender = sim.machine().map_err(io_error)?;
        // A handle waiting for any opening, polled once so its waker is filed, then dropped. The
        // one beside it stays, so the opening that follows is a control that the waker counts a
        // real wake.
        let gone = Woken::default();
        {
            let openings = presence.openings();
            if poll_once(openings.next(), &gone).is_ready() {
                return Err("an opening was handed over before anything was pushed".to_owned());
            }
        }
        let stays = Woken::default();
        let openings = presence.openings();
        if poll_once(openings.next(), &stays).is_ready() {
            return Err("an opening was handed over before anything was pushed".to_owned());
        }
        push_opening(&sim, &beacon, &sender, &target).await?;
        sim.clock().advance(Duration::from_secs(2)).await;
        if gone.wakes() != 0 {
            return Err(format!(
                "a dropped handle was woken {} times by an opening it cannot take",
                gone.wakes()
            ));
        }
        if stays.wakes() == 0 {
            return Err(
                "an opening woke neither the dropped handle nor the waiting one".to_owned(),
            );
        }
        // The same for a handle on one peer: the slot goes with its last waiter, so a flight for
        // that peer afterwards wakes nobody and is not filed under a waker nobody holds.
        let other = sim.machine().map_err(io_error)?;
        let peer = other.peer_id();
        let slot_gone = Woken::default();
        {
            let claimed = presence.flights(peer);
            if poll_once(claimed.next(), &slot_gone).is_ready() {
                return Err("a claim was handed a flight before anything was pushed".to_owned());
            }
        }
        push_opening(&sim, &beacon, &other, &target).await?;
        sim.clock().advance(Duration::from_secs(2)).await;
        if slot_gone.wakes() != 0 {
            return Err(format!(
                "a dropped claim was woken {} times by a flight it cannot take",
                slot_gone.wakes()
            ));
        }
        // The control for that one: a claim that is still there is woken by the same flight.
        // A third peer, because the opening the dropped claim did not take is still held for
        // the second one and would be handed over before anything was pushed.
        let third = sim.machine().map_err(io_error)?;
        let slot_stays = Woken::default();
        let claimed = presence.flights(third.peer_id());
        if poll_once(claimed.next(), &slot_stays).is_ready() {
            return Err("a claim was handed a flight before anything was pushed".to_owned());
        }
        push_opening(&sim, &beacon, &third, &target).await?;
        sim.clock().advance(Duration::from_secs(2)).await;
        if slot_stays.wakes() == 0 {
            return Err("a flight woke neither the dropped claim nor the live one".to_owned());
        }
        Ok(())
    })
}

/// A flight from a peer wakes every handle waiting on that peer, not only the last one to file a
/// waker: a second ceremony on the same peer is not left sleeping until its own deadline.
pub(crate) fn a_flight_wakes_every_handle_waiting_on_the_peer() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let target = sim.machine().map_err(io_error)?;
        let presence = keep_findable(&sim, &beacon, &target).await?;
        let sender = sim.machine().map_err(io_error)?;
        // Two handles on one peer, each polled once with a waker of its own, so the slot holds two
        // and a single-waker slot is visible.
        let first = Woken::default();
        let second = Woken::default();
        let one = presence.flights(sender.peer_id());
        let two = presence.flights(sender.peer_id());
        if poll_once(one.next(), &first).is_ready() || poll_once(two.next(), &second).is_ready() {
            return Err("a claim was handed a flight before anything was pushed".to_owned());
        }
        push_opening(&sim, &beacon, &sender, &target).await?;
        sim.clock().advance(Duration::from_secs(2)).await;
        for (which, woken) in [("first", &first), ("second", &second)] {
            if woken.wakes() == 0 {
                return Err(format!(
                    "the {which} handle waiting on the peer was not woken by its flight"
                ));
            }
        }
        Ok(())
    })
}

/// One installed session releases every request that was waiting for one.
///
/// Both requests are polled once before the presence has a session, so both wait on the same
/// gate, and the one registration that installs the session must release both. A latch that the
/// first waiter clears would leave the second waiting for the next refresh — longer than its own
/// request bound — and it would answer that no session could be had while one was open.
pub(crate) fn one_session_releases_every_waiting_request() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;
        let peer = sim.machine().map_err(io_error)?.peer_id();
        let presence = Presence::new(beacon.client(&machine)?);
        let first = Woken::default();
        let second = Woken::default();
        let mut one = std::pin::pin!(presence.lookup(&peer));
        let mut two = std::pin::pin!(presence.lookup(&peer));
        if poll_once(one.as_mut(), &first).is_ready() || poll_once(two.as_mut(), &second).is_ready()
        {
            return Err("a request answered before the presence had a session".to_owned());
        }
        let answers = within(&sim, Duration::from_secs(120), async {
            let mut answers = Vec::new();
            while answers.len() < 2 {
                if answers.is_empty()
                    && let Poll::Ready(answer) = poll_once(one.as_mut(), &first)
                {
                    answers.push(answer);
                }
                if answers.len() < 2
                    && let Poll::Ready(answer) = poll_once(two.as_mut(), &second)
                {
                    answers.push(answer);
                }
                tokio::task::yield_now().await;
            }
            answers
        })
        .await?;
        if let [Ok(one), Ok(two)] = answers.as_slice() {
            if one != two {
                return Err(format!(
                    "two requests for the same peer answered differently: {one:?} and {two:?}"
                ));
            }
        } else {
            return Err(format!(
                "a request waiting for a session answered {answers:?}, not the beacon's answer"
            ));
        }
        Ok(())
    })
}

/// Two handles on one peer share that peer's slot: a flight that arrived for the peer is still
/// taken by the handle that remains when the other is dropped, and only the last to go takes the
/// slot with it.
pub(crate) fn a_second_handle_keeps_the_flight_when_the_first_is_dropped() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let target = sim.machine().map_err(io_error)?;
        let target_presence = keep_findable(&sim, &beacon, &target).await?;
        let sender = sim.machine().map_err(io_error)?;
        // The claim is reference-counted, so the first handle can go while the second keeps
        // waiting for the same peer.
        let first = target_presence.flights(sender.peer_id());
        let second = target_presence.flights(sender.peer_id());
        let opening = push_opening(&sim, &beacon, &sender, &target).await?;
        sim.clock().advance(Duration::from_secs(2)).await;
        // The first ceremony is cancelled after the flight arrived; the other still takes it.
        drop(first);
        let flight = within(&sim, Duration::from_secs(120), second.next()).await?;
        if flight.payload() != opening.as_slice() {
            return Err(format!(
                "the remaining handle took `{}`, not the peer's flight",
                String::from_utf8_lossy(flight.payload())
            ));
        }
        Ok(())
    })
}

/// A flight whose sender has given up is not delivered, on either path: an opening held for a peer
/// nobody waits on, and a flight in the slot of a peer a ceremony has already claimed.
pub(crate) fn a_held_opening_older_than_the_flight_timeout_is_not_delivered() -> Result<(), String>
{
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let target = sim.machine().map_err(io_error)?;
        let presence = keep_findable(&sim, &beacon, &target).await?;
        let sender = sim.machine().map_err(io_error)?;
        let other = sim.machine().map_err(io_error)?;
        // The hold: nobody waits on the sender, so its opening waits for a responder's person.
        push_opening(&sim, &beacon, &sender, &target).await?;
        sim.clock().advance(Duration::from_secs(2)).await;
        // Longer than a machine waits for the other side's flight, with nothing else pushed: the
        // initiator has given up by now.
        sim.clock()
            .advance(PAIR_FLIGHT_TIMEOUT + Duration::from_secs(1))
            .await;
        let openings = presence.openings();
        if within(&sim, Duration::from_millis(200), openings.next())
            .await
            .is_ok()
        {
            return Err(format!(
                "an opening held longer than {PAIR_FLIGHT_TIMEOUT:?} was handed to a person"
            ));
        }
        // The slot: a ceremony claims another peer before the flight arrives, and the flight sits
        // there while the machine's person is busy.
        let claimed = presence.flights(other.peer_id());
        push_opening(&sim, &beacon, &other, &target).await?;
        sim.clock().advance(Duration::from_secs(2)).await;
        sim.clock()
            .advance(PAIR_FLIGHT_TIMEOUT + Duration::from_secs(1))
            .await;
        if within(&sim, Duration::from_millis(200), claimed.next())
            .await
            .is_ok()
        {
            return Err(format!(
                "a slot flight older than {PAIR_FLIGHT_TIMEOUT:?} was delivered"
            ));
        }
        Ok(())
    })
}

/// A confirmation is never held for a person who has not started: it belongs to an attempt that is
/// already under way, and the ceremony that was running it is the only one that can use it.
///
/// The confirmation is not aged, so holding it would hand it to the next ceremony for the same
/// peer — a comparison nobody is looking at, from an attempt that ended.
pub(crate) fn a_confirmation_is_not_held_for_a_later_ceremony() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let target = sim.machine().map_err(io_error)?;
        let presence = keep_findable(&sim, &beacon, &target).await?;
        let sender = sim.machine().map_err(io_error)?;
        // A real confirmation, as the sender's ceremony would send it: its opening answered, its
        // value revealed, its answer to the comparison.
        let confirmation = confirmation(&sender, &target)?;
        // Nobody waits on the sender, so there is no slot for it: the flight is dropped rather
        // than held, and a ceremony that later claims this peer is not handed it.
        push(&sim, &beacon, &sender, &target, &confirmation).await?;
        sim.clock().advance(Duration::from_secs(2)).await;
        let claimed = presence.flights(sender.peer_id());
        if within(&sim, Duration::from_millis(200), claimed.next())
            .await
            .is_ok()
        {
            return Err(
                "a claim on the peer was handed a confirmation from an attempt that ended"
                    .to_owned(),
            );
        }
        Ok(())
    })
}

/// A request never dials the beacon: it rides the machine's registration, or waits for one until
/// its own bound runs out.
///
/// The keeper's episode is used up first, so its next dial is the slow re-check — a minute away,
/// longer than any request's own bound. A request that dialled would then be the only thing
/// putting datagrams on the wire to the beacon while it waits, and the trace is where that shows:
/// nothing goes there, and the answer is the request's own bound running out.
pub(crate) fn a_request_never_dials_the_beacon() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;
        let presence = keep_findable(&sim, &beacon, &machine).await?;
        let peer = sim.machine().map_err(io_error)?.peer_id();
        beacon.stop();
        // Let the keeper fail its dials until the episode is used up, so nothing of its own is due
        // while the request waits.
        within(&sim, Duration::from_secs(300), async {
            while !matches!(
                presence.state(),
                Registration::Unreachable { dials, .. } if dials >= RECOVERY_DIALS
            ) {
                tokio::task::yield_now().await;
            }
            Ok::<(), String>(())
        })
        .await??;
        let mark = sim.link().trace().len();
        match within(&sim, Duration::from_secs(60), presence.lookup(&peer)).await? {
            Err(BeaconError::Unavailable) => {}
            other => {
                return Err(format!(
                    "a request with no session reads {other:?}, not that no session could be had"
                ));
            }
        }
        let dialled = sim.link().trace()[mark..]
            .iter()
            .filter(|event| event.to == beacon.address())
            .count();
        if dialled != 0 {
            return Err(format!(
                "a request with no session put {dialled} datagrams on the wire to the beacon: it \
                 dialled one itself"
            ));
        }
        Ok(())
    })
}

/// A confirmation from an attempt that ended is not obeyed in a claimed peer's slot: it is bound
/// to the transcript it was written for, and the ceremony that claimed the peer refuses it as a
/// binding mismatch and writes no pair on its own side.
///
/// The sender's side is not asserted: which of two confirmations reaches it first is a race, and
/// a sender that pairs on the one it took is the documented outcome, not a second defect.
pub(crate) fn a_stale_confirmation_is_not_obeyed_in_a_claimed_slot() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let target = sim.machine().map_err(io_error)?;
        let sender = sim.machine().map_err(io_error)?;
        let target_store = target.records();
        let sender_store = sender.records();
        let target_presence = keep_findable(&sim, &beacon, &target).await?;
        let sender_presence = keep_findable(&sim, &beacon, &sender).await?;
        // The sender's confirmation from an attempt that ended before this case's ceremony.
        let (mut initiator, opening) =
            Ceremony::initiate(sender.peer_id(), target.fingerprint(), None, false)
                .map_err(|error| error.to_string())?;
        let introduction = Introduction::signed(&sender.identity, target.peer_id(), opening)
            .map_err(|error| error.to_string())?;
        let (mut responder, answer) =
            Ceremony::respond(target.peer_id(), &introduction, None, false)
                .map_err(|error| error.to_string())?;
        let reveal = initiator
            .receive(&answer.send.ok_or("the responder sent no answer")?)
            .map_err(|error| error.to_string())?
            .send
            .ok_or("the initiator revealed nothing")?;
        responder
            .receive(&reveal)
            .map_err(|error| error.to_string())?;
        let stale = initiator
            .confirm(true)
            .map_err(|error| error.to_string())?
            .send
            .ok_or("the initiator confirmed nothing")?;
        // The target's person answers at once; the sender's takes long enough that the stale
        // confirmation is the first one the target's ceremony sees.
        let target_shown = Shown::accepting();
        let (target_outcome, _, _) = within(&sim, Duration::from_secs(120), async {
            let intrude = async {
                // The slot exists once the target's ceremony has claimed the peer, and the
                // comparison is shown once the real answer arrived: the stale confirmation is
                // pushed at that point.
                while target_shown.seen().is_empty() {
                    tokio::task::yield_now().await;
                }
                push(&sim, &beacon, &sender, &target, &stale).await
            };
            tokio::join!(
                pair::run(
                    &target_presence,
                    &target.identity,
                    Opening::Initiate(sender.fingerprint()),
                    &target_store,
                    now,
                    target_shown.clone(),
                ),
                pair::run(
                    &sender_presence,
                    &sender.identity,
                    Opening::Respond,
                    &sender_store,
                    now,
                    Shown::taking(sim.clock(), PAIR_FLIGHT_TIMEOUT + Duration::from_secs(5)),
                ),
                intrude,
            )
        })
        .await?;
        if !matches!(target_outcome, Err(pair::PairError::BindingMismatch)) {
            return Err(format!(
                "a confirmation from another attempt was not refused as a binding mismatch: \
                 {target_outcome:?}"
            ));
        }
        if target_store.is_paired(&sender.peer_id()) {
            return Err(
                "the target wrote the pair on a confirmation from another attempt".to_owned(),
            );
        }
        if target_shown.seen().len() != 1 {
            return Err(format!(
                "a confirmation from another attempt showed {} comparisons",
                target_shown.seen().len()
            ));
        }
        Ok(())
    })
}

/// A presence dropped while the keeper waits out its slow re-check does not wait the re-check out:
/// the endpoint handle the presence held is released, so the restart a product rebinds with
/// succeeds inside its own budget.
///
/// That wait is the longest one a presence takes, and a product that drops its presence during an
/// outage must be able to rebind its socket then, not a minute later. The restart proves the
/// keeper's wait ended; the reader's own wait is shorter than the restart budget, so this case
/// cannot tell whether it ended early or ran its period out. A dial already in flight is the one
/// wait a drop does not cancel; the bound it is under is stated on `Presence`, where a product
/// reads it, and a product that needs the socket sooner closes its own endpoint handle.
pub(crate) fn a_dropped_presence_ends_the_slow_recheck() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let mut machine = sim.machine().map_err(io_error)?;
        let presence = keep_findable(&sim, &beacon, &machine).await?;
        beacon.stop();
        // The keeper notices the closed session and fails its dials until the episode is used up,
        // where the wait that follows is the slow re-check.
        within(&sim, Duration::from_secs(300), async {
            while !matches!(
                presence.state(),
                Registration::Unreachable { dials, .. } if dials >= RECOVERY_DIALS
            ) {
                tokio::task::yield_now().await;
            }
            Ok::<(), String>(())
        })
        .await??;
        drop(presence);
        // A restart is the product's way of rebinding: it waits for the transport to let go of the
        // socket, so it succeeds only if both of the dropped presence's tasks ended.
        machine.restart().await.map(|_| ()).map_err(|error| {
            format!("a dropped presence kept the socket through the outage: {error}")
        })
    })
}

/// A frame the reader refuses does not stall it.
///
/// The beacon relays what a stranger hands it without looking at the signature, so any machine
/// with a beacon session can push frames this one refuses. A reader that waited out its idle
/// period on each of them would answer a legitimate sender `UnknownPeer` once the beacon's stream
/// credit ran out, and the pairing would end in a flight timeout.
pub(crate) fn a_refused_frame_does_not_stall_the_reader() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let left = sim.machine().map_err(io_error)?;
        let right = sim.machine().map_err(io_error)?;
        let left_store = left.records();
        let right_store = right.records();
        let left_presence = keep_findable(&sim, &beacon, &left).await?;
        let right_presence = keep_findable(&sim, &beacon, &right).await?;
        // A stranger with a beacon session hands the responder five frames that do not verify.
        let attacker = sim.machine().map_err(io_error)?;
        let raw = RawClient::connect(&attacker, &beacon).await?;
        for _ in 0..5 {
            let forged = Request::Introduce {
                to: right.peer_id(),
                signature: [0; 64],
                payload: b"not signed by anybody".to_vec(),
            };
            raw.send(&forged.encode()).await?;
        }
        // The opening has to be delivered inside the machine-flight wait: five refusals must not
        // cost the ceremony that wait.
        let (left_outcome, right_outcome) = pair_together(
            &sim,
            Pairing {
                left: &left,
                right: &right,
                left_presence: &left_presence,
                right_presence: &right_presence,
                left_opens: Opening::Initiate(right.fingerprint()),
                right_opens: Opening::Respond,
                left_person: Shown::accepting(),
                right_person: Shown::accepting(),
                left_store: &left_store,
                right_store: &right_store,
            },
        )
        .await?;
        if !paired(&left_outcome) || !paired(&right_outcome) {
            return Err(format!(
                "frames the reader refused cost the pair its flight: {left_outcome:?} / \
                 {right_outcome:?}"
            ));
        }
        Ok(())
    })
}
