//! The connection level and the rights: the binding, the claim, the four
//! capabilities, the default, the host's floor, withdrawal, return, the audit, and
//! the keeper's rule for a connection that only exchanged its binding.
//!
//! Every case runs over the simulated link and the injected clock. Nothing here opens
//! a socket or starts a process; a claim that needs a real network or a real Windows
//! host is in the capability inventory as unproducible, with what would produce it.

use std::time::Duration;

use mahbot_peers::identity::PeerId;
use mahbot_peers::peer::audit::{MAX_FILE_BYTES, RESERVED_FOR_PERSON_BYTES};
use mahbot_peers::peer::{
    Act, AuditError, Authority, Capability, Claim, Decision, Entry, GrantKind, Issuer, Label,
    NoFloor, Pair, PersonName, Question, Refusal, Rights, RightsError, Speaker, Standing, Step,
    Timestamp, WriteRefusal,
};

use crate::clock::block_on;
use crate::machine::Machine;
use crate::sim::Sim;

use super::peer::NOW;
use super::support::{field, io_error, main_binding, pair, within};

/// The assistant a case declares. The product's guest declaration changes no decision
/// the crate makes, so the crate keeps the name alone; see `peer::access::Binding`.
pub(super) fn label(text: &str) -> Result<Label, String> {
    Label::new(text).map_err(|error| error.to_string())
}

pub(super) fn person(name: &str) -> Result<PersonName, String> {
    PersonName::new(name).map_err(|error| error.to_string())
}

/// A question asked by a connection the handshake proved.
fn question(peer: &Machine, assistant: &Label, capability: Capability) -> Question {
    Question {
        speaker: Speaker::Authenticated(peer.peer_id()),
        pair: pair(peer, assistant),
        capability,
    }
}

/// A decision that must have refused, answering the refusal.
pub(super) fn refused(decision: Decision) -> Result<Refusal, String> {
    match decision {
        Decision::Refused { refusal } => Ok(refusal),
        Decision::Allowed { right } => Err(format!(
            "the decision allowed `{}` instead of refusing",
            right.capability()
        )),
    }
}

/// The rights on file for the pair, read fresh.
fn rights_on_file(rights: &Rights, pair: &Pair) -> Result<Vec<mahbot_peers::peer::Right>, String> {
    rights.rights(pair).map_err(|error| error.to_string())
}

/// The one right for a capability, or a failure naming what is there.
fn only_right(
    rights: &Rights,
    pair: &Pair,
    capability: Capability,
) -> Result<mahbot_peers::peer::Right, String> {
    rights_on_file(rights, pair)?
        .into_iter()
        .find(|right| right.capability() == capability)
        .ok_or_else(|| format!("no `{capability}` right is on file"))
}

/// Two machines a person already paired, each remembering the other's address.
pub(super) fn paired_machines(sim: &Sim) -> Result<(Machine, Machine), String> {
    let left = sim.machine().map_err(io_error)?;
    let right = sim.machine().map_err(io_error)?;
    for (machine, peer) in [(&left, &right), (&right, &left)] {
        let store = machine.records();
        store
            .record_pairing(&peer.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        store
            .record_address(&peer.peer_id(), peer.addr())
            .map_err(|error| error.to_string())?;
    }
    Ok((left, right))
}

/// Wait until the exchange left `peer`'s claim in `store`, optionally one naming
/// `assistant`.
///
/// The exchange runs on its own task after adoption, so a case that asserts on a
/// claim waits for it the way a person waits for a screen to fill: the clock is
/// driven and the task polled. The exchange measures its own frames before it keeps
/// the claim, so a claim on file is also the measurement landed. The read is `reread`,
/// so a store opened before the claim landed sees it: the claim is written by the
/// manager's own handle, not this one. A second connection replaces the claim only
/// when the deciding machine's newer fact arrives, so a case that asserts on a new
/// binding names the assistant it expects: the previous claim is still on file.
pub(super) async fn wait_claim(
    sim: &Sim,
    store: &mahbot_peers::peer::RecordStore,
    peer: &PeerId,
    named: Option<&Label>,
) -> Result<Claim, String> {
    within(sim, Duration::from_secs(60), async {
        loop {
            if let Ok(Some(record)) = store.reread(peer)
                && let Some(claim) = record.claim()
                && named.is_none_or(|named| claim.fact().assistant() == named)
            {
                return Ok::<Claim, String>(claim);
            }
            tokio::task::yield_now().await;
        }
    })
    .await?
}

// ---------------------------------------------------------------------------
// The binding and the claim
// ---------------------------------------------------------------------------

pub(crate) fn connection_binding_is_decided_by_one_machine() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = crate::beacon::TestBeacon::start(&sim).map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let admin = label("admin")?;
        let rights = main.rights()?;
        // The deciding machine decides, and the default acts for the pair it makes.
        let issued = rights
            .bind(&laptop.peer_id(), main_binding(&admin)?, NOW)
            .map_err(|error| error.to_string())?;
        let Some(issued) = issued else {
            return Err("the default did not issue for the new pair".to_owned());
        };
        if issued.capability() != Capability::WRITE || issued.issuer() != &Issuer::Default {
            return Err(format!(
                "the default issued `{}` by `{}`, not `write to me` by the default",
                issued.capability(),
                issued.issuer()
            ));
        }
        // The binding is durable on the deciding machine: a fresh open reads it.
        let reopened = main.reopen_records()?;
        let record = reopened
            .get(&laptop.peer_id())
            .ok_or("the record did not survive the store")?;
        let stored = record
            .binding()
            .ok_or("the binding did not survive the store")?;
        if stored.fact().assistant() != &admin {
            return Err("the stored binding names another assistant".to_owned());
        }
        // The other side is shown the claim over the direct connection, and allows
        // nothing on its strength.
        let _managed_main =
            crate::witnesses::connection::Managed::start(&sim, &beacon, &main, &main.records())?;
        let managed_laptop = crate::witnesses::connection::Managed::start(
            &sim,
            &beacon,
            &laptop,
            &laptop.records(),
        )?;
        let connection = managed_laptop
            .connections
            .connect(&managed_laptop.endpoint, &main.fingerprint())
            .await
            .map_err(|error| error.to_string())?;
        let claim = wait_claim(&sim, &laptop.records(), &main.peer_id(), None).await?;
        if claim.fact().assistant() != &admin {
            return Err(format!(
                "the claim names `{}`, not `{}`",
                claim.fact().assistant(),
                admin
            ));
        }
        if claim.fact().account().label().as_str() != "main-account"
            || claim.fact().instance().label().as_str() != "main-instance"
        {
            return Err(
                "the claim does not carry the labels the deciding machine supplied".to_owned(),
            );
        }
        // Nothing is allowed because another machine said so: the crate's own pair
        // helper reads the binding this machine decided, and the laptop decided none,
        // so the claim is only the label the laptop's person names the pair by.
        let laptop_rights = laptop.rights()?;
        let claim_pair = Pair::of_claim(&claim);
        if laptop_rights
            .bound_pair(&main.peer_id())
            .map_err(|error| error.to_string())?
            .is_some()
        {
            return Err("the laptop reports a binding it never decided".to_owned());
        }
        if rights
            .bound_pair(&laptop.peer_id())
            .map_err(|error| error.to_string())?
            .as_ref()
            != Some(&Pair::new(laptop.peer_id(), &admin))
        {
            return Err("the deciding machine's own pair is not its binding's".to_owned());
        }
        let refusal = refused(
            laptop_rights
                .decide(
                    &Question {
                        speaker: Speaker::Authenticated(main.peer_id()),
                        pair: claim_pair,
                        capability: Capability::WORK,
                    },
                    &NoFloor,
                    NOW,
                )
                .map_err(|error| error.to_string())?,
        )?;
        if refusal != Refusal::NoRight {
            return Err(format!("the claim allowed or refused as {refusal}"));
        }
        drop(connection);
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// The default and the four capabilities
// ---------------------------------------------------------------------------

/// The log's entries, read fresh through the same handle the decision writes.
fn acts(rights: &Rights) -> Result<Vec<Entry>, String> {
    rights.audit().entries().map_err(|error| error.to_string())
}

/// Assert the log holds an act of `shape` at `at`.
fn holds(
    entries: &[Entry],
    at: Timestamp,
    what: &str,
    shape: impl Fn(&Act) -> bool,
) -> Result<(), String> {
    if entries
        .iter()
        .any(|entry| entry.at == at && shape(&entry.act))
    {
        Ok(())
    } else {
        Err(format!("the log holds no {what} at {at}"))
    }
}

/// The default is one capability, `write to me`, issued once when a pair comes into
/// being, and the log records it as a created grant by the default.
pub(crate) fn default_issues_write_to_me_and_nothing_else() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let guest = label("guest")?;
        let rights = main.rights()?;
        let pair = pair(&laptop, &guest);
        let issued = rights
            .on_acquaintance(&pair, NOW)
            .map_err(|error| error.to_string())?
            .ok_or("the default issued nothing for a new pair")?;
        if issued.capability() != Capability::WRITE {
            return Err(format!(
                "the default issued `{}`, not `write to me`",
                issued.capability()
            ));
        }
        if issued.issuer() != &Issuer::Default {
            return Err(format!("the default issued by `{}`", issued.issuer()));
        }
        let file = rights_on_file(&rights, &pair)?;
        if file.len() != 1 {
            return Err(format!(
                "the default left {} rights on file, not one",
                file.len()
            ));
        }
        for capability in [
            Capability::WORK,
            Capability::SEE_SCREEN,
            Capability::TAKE_FILES,
        ] {
            if file.iter().any(|right| right.capability() == capability) {
                return Err(format!("the default issued `{capability}` as well"));
            }
        }
        let entries = acts(&rights)?;
        let last = entries
            .last()
            .ok_or("the log is empty after the default acted")?;
        if last.at != NOW {
            return Err(format!(
                "the default's grant is dated {}, not {NOW}",
                last.at
            ));
        }
        match &last.act {
            Act::Granted {
                capability,
                issuer,
                kind,
                ..
            } if *capability == Capability::WRITE
                && *issuer == Issuer::Default
                && *kind == GrantKind::Created => {}
            other => {
                return Err(format!(
                    "the log's last entry is {other:?}, not the default's grant"
                ));
            }
        }
        Ok(())
    })
}

/// The default never acts twice: a second acquaintance issues nothing, and a right a
/// person withdrew stays withdrawn instead of being re-created.
pub(crate) fn the_default_never_acts_again() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let guest = label("guest")?;
        let rights = main.rights()?;
        let pair = pair(&laptop, &guest);
        rights
            .on_acquaintance(&pair, NOW)
            .map_err(|error| error.to_string())?
            .ok_or("the default did not act for a new pair")?;
        if rights
            .on_acquaintance(&pair, NOW.plus(Duration::from_secs(1)))
            .map_err(|error| error.to_string())?
            .is_some()
        {
            return Err("the default acted a second time for the same pair".to_owned());
        }
        if rights_on_file(&rights, &pair)?.len() != 1 {
            return Err("the second acquaintance changed the rights on file".to_owned());
        }
        let at = NOW.plus(Duration::from_secs(2));
        let egor = person("egor")?;
        let withdrawn = rights
            .withdraw(&pair, Capability::WRITE, egor.clone(), at)
            .map_err(|error| error.to_string())?;
        if withdrawn.withdrawn_at() != Some(at) {
            return Err(format!(
                "the withdrawal is dated {:?}, not {at}",
                withdrawn.withdrawn_at()
            ));
        }
        if rights
            .on_acquaintance(&pair, NOW.plus(Duration::from_secs(3)))
            .map_err(|error| error.to_string())?
            .is_some()
        {
            return Err("the default re-created a right a person withdrew".to_owned());
        }
        let file = rights_on_file(&rights, &pair)?;
        if file.len() != 1 || file[0].withdrawn_at() != Some(at) {
            return Err("the withdrawn right did not stay on file as withdrawn".to_owned());
        }
        // The other way a right stops: a person gives the default's right a term, and
        // the default does not re-create it when the term passes.
        let other = label("other")?;
        let other_pair = Pair::new(laptop.peer_id(), &other);
        rights
            .on_acquaintance(&other_pair, NOW)
            .map_err(|error| error.to_string())?
            .ok_or("the default did not act for a second new pair")?;
        rights
            .grant(
                &other_pair,
                Capability::WRITE,
                Authority::Person(egor.clone()),
                Some(Duration::from_secs(10)),
                NOW,
            )
            .map_err(|error| error.to_string())?;
        let after = NOW.plus(Duration::from_secs(11));
        if rights
            .on_acquaintance(&other_pair, after)
            .map_err(|error| error.to_string())?
            .is_some()
        {
            return Err("the default re-created a right whose term passed".to_owned());
        }
        let file = rights_on_file(&rights, &other_pair)?;
        if file.len() != 1 || !matches!(file[0].standing(after), Standing::Ended(_)) {
            return Err(format!(
                "the ended default right is {file:?}, not one ended row"
            ));
        }
        Ok(())
    })
}

/// A guest's default is the same single `write to me`; a person may widen it, and the
/// log records the widening as that person's created grant.
pub(crate) fn a_guest_assistant_gets_the_default_and_a_person_may_widen_it() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let guest = label("guest")?;
        let rights = main.rights()?;
        let pair = pair(&laptop, &guest);
        rights
            .bind(&laptop.peer_id(), main_binding(&guest)?, NOW)
            .map_err(|error| error.to_string())?;
        // The binding names the assistant the product called a guest, and the
        // default it issued is the same single right every assistant gets.
        let record = main
            .records()
            .get(&laptop.peer_id())
            .ok_or("the binding left no record")?;
        if !record
            .binding()
            .is_some_and(|binding| binding.fact().assistant() == &guest)
        {
            return Err("the record does not keep the assistant's name".to_owned());
        }
        let file = rights_on_file(&rights, &pair)?;
        if file.len() != 1 || file[0].capability() != Capability::WRITE {
            return Err(format!(
                "a guest's default left {} rights, not only `write to me`",
                file.len()
            ));
        }
        let egor = person("egor")?;
        let widened = rights
            .grant(
                &pair,
                Capability::WORK,
                Authority::Person(egor.clone()),
                None,
                NOW,
            )
            .map_err(|error| error.to_string())?;
        if widened.capability() != Capability::WORK {
            return Err(format!(
                "the widened right is `{}`, not `work on me`",
                widened.capability()
            ));
        }
        if widened.issuer() != &Issuer::Person(egor.clone()) {
            return Err(format!(
                "the widened right is issued by `{}`",
                widened.issuer()
            ));
        }
        let entries = acts(&rights)?;
        let last = entries
            .last()
            .ok_or("the widening left no entry in the log")?;
        match &last.act {
            Act::Granted {
                capability,
                issuer,
                kind,
                ..
            } if *capability == Capability::WORK
                && *issuer == Issuer::Person(egor.clone())
                && *kind == GrantKind::Created => {}
            other => {
                return Err(format!(
                    "the log's last entry is {other:?}, not the person's widening"
                ));
            }
        }
        Ok(())
    })
}

/// A right a person withdrew refuses the next question at the right step, stays on
/// file as withdrawn at that moment, and is written down with the person's name.
pub(crate) fn a_right_withdrawn_refuses_the_next_question() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let guest = label("guest")?;
        let rights = main.rights()?;
        let pair = pair(&laptop, &guest);
        let egor = person("egor")?;
        rights
            .grant(
                &pair,
                Capability::WORK,
                Authority::Person(egor.clone()),
                None,
                NOW,
            )
            .map_err(|error| error.to_string())?;
        let first = rights
            .decide(&question(&laptop, &guest, Capability::WORK), &NoFloor, NOW)
            .map_err(|error| error.to_string())?;
        match first.allowed() {
            Some(right)
                if right.capability() == Capability::WORK
                    && right.issuer() == &Issuer::Person(egor.clone())
                    && right.withdrawn_at().is_none() => {}
            _ => {
                return Err(format!(
                    "the granted right did not allow the first question, or the answer did \
                     not name it: {first:?}"
                ));
            }
        }
        let at = NOW.plus(Duration::from_secs(5));
        rights
            .withdraw(&pair, Capability::WORK, egor.clone(), at)
            .map_err(|error| error.to_string())?;
        let refusal = refused(
            rights
                .decide(&question(&laptop, &guest, Capability::WORK), &NoFloor, at)
                .map_err(|error| error.to_string())?,
        )?;
        if refusal != (Refusal::Withdrawn { at }) {
            return Err(format!(
                "the withdrawn right refused as {refusal}, not at {at}"
            ));
        }
        if refusal.step() != Step::Right {
            return Err(format!(
                "the withdrawal refused at step `{}`",
                refusal.step()
            ));
        }
        let right = only_right(&rights, &pair, Capability::WORK)?;
        if right.withdrawn_at() != Some(at) {
            return Err(format!(
                "the right is withdrawn at {:?}, not {at}",
                right.withdrawn_at()
            ));
        }
        let entries = acts(&rights)?;
        holds(&entries, at, "a withdrawal by egor", |act| {
            matches!(act, Act::Withdrawn { by, capability, .. }
                if *by == egor && *capability == Capability::WORK)
        })?;
        Ok(())
    })
}

/// A right whose term passed refuses with the term's moment, is recorded once, and a
/// person's later grant restores it as a restore.
pub(crate) fn a_right_that_ends_refuses_and_is_recorded_once() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let guest = label("guest")?;
        let rights = main.rights()?;
        let pair = pair(&laptop, &guest);
        let egor = person("egor")?;
        rights
            .grant(
                &pair,
                Capability::WORK,
                Authority::Person(egor.clone()),
                Some(Duration::from_secs(60)),
                NOW,
            )
            .map_err(|error| error.to_string())?;
        let live = rights
            .decide(&question(&laptop, &guest, Capability::WORK), &NoFloor, NOW)
            .map_err(|error| error.to_string())?;
        if live.allowed().is_none() {
            return Err(format!(
                "the term had not passed but the answer was {live:?}"
            ));
        }
        let after = NOW.plus(Duration::from_secs(61));
        let refusal = refused(
            rights
                .decide(
                    &question(&laptop, &guest, Capability::WORK),
                    &NoFloor,
                    after,
                )
                .map_err(|error| error.to_string())?,
        )?;
        let ended_at = NOW.plus(Duration::from_secs(60));
        if refusal != (Refusal::Ended { at: ended_at }) {
            return Err(format!(
                "the ended right refused as {refusal}, not at {ended_at}"
            ));
        }
        if refusal.step() != Step::Right {
            return Err(format!("the ending refused at step `{}`", refusal.step()));
        }
        // The same ending, asked again once the row carries the moment it was noticed:
        // the answer must still name the term's end, not when this machine looked.
        let again = refused(
            rights
                .decide(
                    &question(&laptop, &guest, Capability::WORK),
                    &NoFloor,
                    after,
                )
                .map_err(|error| error.to_string())?,
        )?;
        if again != (Refusal::Ended { at: ended_at }) {
            return Err(format!(
                "the ending reported {again} on the second question, not its term at {ended_at}"
            ));
        }
        let swept = rights
            .end_expired(NOW.plus(Duration::from_secs(120)))
            .map_err(|error| error.to_string())?;
        if swept != 0 {
            return Err(format!(
                "the sweep recorded {swept} endings the question already recorded"
            ));
        }
        let entries = acts(&rights)?;
        let endings = entries
            .iter()
            .filter(|entry| {
                matches!(&entry.act, Act::Ended { pair: recorded, capability }
                    if recorded == &pair && *capability == Capability::WORK)
            })
            .count();
        if endings != 1 {
            return Err(format!(
                "the log holds {endings} endings for the right, not one"
            ));
        }
        let right = only_right(&rights, &pair, Capability::WORK)?;
        if !matches!(right.standing(after), Standing::Ended(_)) {
            return Err(format!(
                "the right stands {:?} after its term",
                right.standing(after)
            ));
        }
        let later = NOW.plus(Duration::from_secs(120));
        let restored = rights
            .grant(
                &pair,
                Capability::WORK,
                Authority::Person(egor.clone()),
                None,
                later,
            )
            .map_err(|error| error.to_string())?;
        if restored.standing(later) != Standing::Live {
            return Err(format!(
                "the restored right stands {:?}",
                restored.standing(later)
            ));
        }
        let entries = acts(&rights)?;
        let last = entries.last().ok_or("the restore left no entry")?;
        match &last.act {
            Act::Granted {
                capability, kind, ..
            } if *capability == Capability::WORK && *kind == GrantKind::Restored => {}
            other => {
                return Err(format!(
                    "the person's grant is recorded as {other:?}, not a restore"
                ));
            }
        }

        // A term that passes with no question asked is recorded by the sweep, once, and
        // a second sweep records nothing.
        rights
            .grant(
                &pair,
                Capability::TAKE_FILES,
                Authority::Person(egor),
                Some(Duration::from_secs(60)),
                later,
            )
            .map_err(|error| error.to_string())?;
        let swept = rights
            .end_expired(later.plus(Duration::from_secs(120)))
            .map_err(|error| error.to_string())?;
        if swept != 1 {
            return Err(format!(
                "the sweep recorded {swept} endings for the one term that passed"
            ));
        }
        let row = only_right(&rights, &pair, Capability::TAKE_FILES)?;
        if row.ended_at().is_none() {
            return Err("the sweep wrote the ending but did not mark the row".to_owned());
        }
        if rights
            .end_expired(later.plus(Duration::from_secs(120)))
            .map_err(|error| error.to_string())?
            != 0
        {
            return Err("a second sweep recorded the same ending again".to_owned());
        }
        Ok(())
    })
}

/// The host's floor refuses a right that exists without withdrawing it, is recorded as
/// a refusal, keeps rights it does not name, and cannot add one.
pub(crate) fn the_hosts_floor_refuses_a_granted_right_and_the_grant_stays() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let guest = label("guest")?;
        let rights = main.rights()?;
        let pair = pair(&laptop, &guest);
        let egor = person("egor")?;
        rights
            .on_acquaintance(&pair, NOW)
            .map_err(|error| error.to_string())?;
        rights
            .grant(&pair, Capability::WORK, Authority::Person(egor), None, NOW)
            .map_err(|error| error.to_string())?;
        let floor = |_: &Pair, capability: Capability| {
            (capability == Capability::WORK).then(|| "not on this host".to_owned())
        };
        let refusal = refused(
            rights
                .decide(&question(&laptop, &guest, Capability::WORK), &floor, NOW)
                .map_err(|error| error.to_string())?,
        )?;
        if refusal
            != (Refusal::Floor {
                reason: "not on this host".to_owned(),
            })
        {
            return Err(format!("the floor refused as {refusal}"));
        }
        if refusal.step() != Step::Floor {
            return Err(format!("the floor refused at step `{}`", refusal.step()));
        }
        let right = only_right(&rights, &pair, Capability::WORK)?;
        if right.standing(NOW) != Standing::Live {
            return Err(format!(
                "the floor left the right {:?} instead of live",
                right.standing(NOW)
            ));
        }
        let entries = acts(&rights)?;
        if !entries.iter().any(|entry| {
            matches!(&entry.act, Act::Refused { refusal: Refusal::Floor { reason }, .. }
                if reason == "not on this host")
        }) {
            return Err("the floor's refusal is not in the log".to_owned());
        }
        if entries.iter().any(|entry| {
            matches!(&entry.act, Act::Withdrawn { capability, .. }
                if *capability == Capability::WORK)
        }) {
            return Err("the floor's refusal was recorded as a withdrawal".to_owned());
        }
        // The floor keeps a right it does not name, and cannot add one.
        let write = rights
            .decide(&question(&laptop, &guest, Capability::WRITE), &floor, NOW)
            .map_err(|error| error.to_string())?;
        if write.allowed().is_none() {
            return Err(format!(
                "the floor refused a right it does not name: {write:?}"
            ));
        }
        let no_right = refused(
            rights
                .decide(
                    &question(&laptop, &guest, Capability::SEE_SCREEN),
                    &floor,
                    NOW,
                )
                .map_err(|error| error.to_string())?,
        )?;
        if no_right != Refusal::NoRight {
            return Err(format!(
                "a capability with no right refused as {no_right}, not for want of a right"
            ));
        }
        Ok(())
    })
}

/// A write attributed to a peer is refused before it changes anything and written
/// down: a peer asking for a right is a fact worth keeping.
pub(crate) fn a_peer_attributed_write_is_refused_and_recorded() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let other = sim.machine().map_err(io_error)?;
        let guest = label("guest")?;
        let rights = main.rights()?;
        let pair = pair(&laptop, &guest);
        match rights.grant(
            &pair,
            Capability::WORK,
            Authority::Peer(other.peer_id()),
            None,
            NOW,
        ) {
            Err(RightsError::Write(WriteRefusal::RemoteAuthority { peer }))
                if peer == other.peer_id() => {}
            Err(error) => return Err(format!("the peer's write was refused as `{error}`")),
            Ok(_) => return Err("a peer's word created a right".to_owned()),
        }
        if rights_on_file(&rights, &pair)?
            .iter()
            .any(|right| right.capability() == Capability::WORK)
        {
            return Err("a peer's word left a `work on me` right on file".to_owned());
        }
        let entries = acts(&rights)?;
        let last = entries.last().ok_or("the refused write left no entry")?;
        match &last.act {
            Act::WriteRefused {
                reason: WriteRefusal::RemoteAuthority { peer },
                capability,
                ..
            } if *peer == other.peer_id() && *capability == Capability::WORK => {}
            other_act => {
                return Err(format!(
                    "the log's last entry is {other_act:?}, not the refused write"
                ));
            }
        }
        Ok(())
    })
}

/// Trust is checked before any right: an unknown machine and a withdrawn one are both
/// refused at the authenticate step.
pub(crate) fn an_untrusted_machine_is_refused_before_any_right() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let stranger = sim.machine().map_err(io_error)?;
        let guest = label("guest")?;
        let rights = main.rights()?;
        let refusal = refused(
            rights
                .decide(
                    &question(&stranger, &guest, Capability::WORK),
                    &NoFloor,
                    NOW,
                )
                .map_err(|error| error.to_string())?,
        )?;
        if refusal != Refusal::Untrusted {
            return Err(format!("a machine with no record refused as {refusal}"));
        }
        if refusal.step() != Step::Authenticate {
            return Err(format!(
                "an unknown machine refused at step `{}`",
                refusal.step()
            ));
        }
        rights
            .withdraw_trust(&laptop.peer_id(), person("egor")?, NOW)
            .map_err(|error| error.to_string())?;
        let refusal = refused(
            rights
                .decide(&question(&laptop, &guest, Capability::WORK), &NoFloor, NOW)
                .map_err(|error| error.to_string())?,
        )?;
        if refusal != Refusal::Untrusted {
            return Err(format!(
                "a machine whose trust was withdrawn refused as {refusal}"
            ));
        }
        let record = main
            .records()
            .get(&laptop.peer_id())
            .ok_or("the paired machine's record vanished")?;
        if !record.is_withdrawn() {
            return Err("the untrusted pair's record is not withdrawn".to_owned());
        }
        Ok(())
    })
}

/// A question with no handshake behind it, or one whose key is not the pair's machine,
/// is refused at the authenticate step.
pub(crate) fn an_unauthenticated_question_is_refused() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let stranger = sim.machine().map_err(io_error)?;
        let guest = label("guest")?;
        let rights = main.rights()?;
        let pair = pair(&laptop, &guest);
        let nobody = Question {
            speaker: Speaker::Unauthenticated,
            pair: pair.clone(),
            capability: Capability::WORK,
        };
        let refusal = refused(
            rights
                .decide(&nobody, &NoFloor, NOW)
                .map_err(|error| error.to_string())?,
        )?;
        if refusal != Refusal::NotAuthenticated {
            return Err(format!("a question with no speaker refused as {refusal}"));
        }
        if refusal.step() != Step::Authenticate {
            return Err(format!(
                "a question with no speaker refused at step `{}`",
                refusal.step()
            ));
        }
        let impostor = Question {
            speaker: Speaker::Authenticated(stranger.peer_id()),
            pair,
            capability: Capability::WORK,
        };
        let refusal = refused(
            rights
                .decide(&impostor, &NoFloor, NOW)
                .map_err(|error| error.to_string())?,
        )?;
        if refusal != Refusal::NotAuthenticated {
            return Err(format!(
                "a key that is not the pair's machine refused as {refusal}"
            ));
        }
        if refusal.step() != Step::Authenticate {
            return Err(format!(
                "another machine's key refused at step `{}`",
                refusal.step()
            ));
        }
        Ok(())
    })
}

/// Rights are durable: after both machines reopen their stores and logs from the
/// roots, each still allows the right it granted.
pub(crate) fn rights_survive_a_restart_of_both_machines() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let guest = label("guest")?;
        let egor = person("egor")?;
        let pair_main = pair(&laptop, &guest);
        let pair_laptop = pair(&main, &guest);
        {
            let rights = main.rights()?;
            rights
                .on_acquaintance(&pair_main, NOW)
                .map_err(|error| error.to_string())?;
            rights
                .grant(
                    &pair_main,
                    Capability::WORK,
                    Authority::Person(egor.clone()),
                    None,
                    NOW,
                )
                .map_err(|error| error.to_string())?;
        }
        {
            let rights = laptop.rights()?;
            rights
                .on_acquaintance(&pair_laptop, NOW)
                .map_err(|error| error.to_string())?;
            rights
                .grant(
                    &pair_laptop,
                    Capability::WORK,
                    Authority::Person(egor),
                    None,
                    NOW,
                )
                .map_err(|error| error.to_string())?;
        }
        // Only the files are left: both stores are reopened from the roots.
        let reopened_main = Rights::new(main.reopen_records()?, main.audit()?);
        let reopened_laptop = Rights::new(laptop.reopen_records()?, laptop.audit()?);
        let after = NOW.plus(Duration::from_secs(1));
        let main_answer = reopened_main
            .decide(
                &question(&laptop, &guest, Capability::WORK),
                &NoFloor,
                after,
            )
            .map_err(|error| error.to_string())?;
        if main_answer.allowed().is_none() {
            return Err(format!(
                "the reopened machine refused its own right: {main_answer:?}"
            ));
        }
        let laptop_answer = reopened_laptop
            .decide(&question(&main, &guest, Capability::WORK), &NoFloor, after)
            .map_err(|error| error.to_string())?;
        if laptop_answer.allowed().is_none() {
            return Err(format!(
                "the other reopened machine refused its own right: {laptop_answer:?}"
            ));
        }
        Ok(())
    })
}

/// Withdrawing trust removes every right and the default's marker, refuses the next
/// question, and records how many rows went.
pub(crate) fn withdrawing_trust_removes_the_rights() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let guest = label("guest")?;
        let rights = main.rights()?;
        let pair = pair(&laptop, &guest);
        let egor = person("egor")?;
        rights
            .on_acquaintance(&pair, NOW)
            .map_err(|error| error.to_string())?;
        rights
            .grant(
                &pair,
                Capability::WORK,
                Authority::Person(egor.clone()),
                None,
                NOW,
            )
            .map_err(|error| error.to_string())?;
        let removed = rights
            .withdraw_trust(&laptop.peer_id(), egor.clone(), NOW)
            .map_err(|error| error.to_string())?;
        if removed != 2 {
            return Err(format!(
                "the withdrawal removed {removed} rights, not the two on file"
            ));
        }
        let refusal = refused(
            rights
                .decide(&question(&laptop, &guest, Capability::WORK), &NoFloor, NOW)
                .map_err(|error| error.to_string())?,
        )?;
        if refusal != Refusal::Untrusted {
            return Err(format!("the withdrawn machine refused as {refusal}"));
        }
        let record = main
            .records()
            .get(&laptop.peer_id())
            .ok_or("the withdrawn machine's record vanished")?;
        if !record.is_withdrawn() {
            return Err("the record does not say the trust was withdrawn".to_owned());
        }
        if !record.rights().is_empty() {
            return Err(format!(
                "the withdrawal left {} rights on file",
                record.rights().len()
            ));
        }
        if record.default_spent(&pair).is_some() {
            return Err("the withdrawal left the default's marker behind".to_owned());
        }
        let entries = acts(&rights)?;
        holds(
            &entries,
            NOW,
            "a trust withdrawal by egor",
            |act| matches!(act, Act::TrustWithdrawn { by, rights: 2, .. } if *by == egor),
        )?;
        Ok(())
    })
}

/// Returning a withdrawn machine reissues only the default; a person's earlier right
/// does not come back.
pub(crate) fn restoring_trust_reissues_only_the_default() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let guest = label("guest")?;
        let rights = main.rights()?;
        let pair = pair(&laptop, &guest);
        let egor = person("egor")?;
        rights
            .on_acquaintance(&pair, NOW)
            .map_err(|error| error.to_string())?;
        rights
            .grant(
                &pair,
                Capability::WORK,
                Authority::Person(egor.clone()),
                None,
                NOW,
            )
            .map_err(|error| error.to_string())?;
        rights
            .withdraw_trust(&laptop.peer_id(), egor.clone(), NOW)
            .map_err(|error| error.to_string())?;
        let at = NOW.plus(Duration::from_secs(1));
        let returned = rights
            .restore_trust(&pair, egor.clone(), at)
            .map_err(|error| error.to_string())?
            .issued
            .ok_or("the return did not reissue the default")?;
        if returned.capability() != Capability::WRITE || returned.issuer() != &Issuer::Default {
            return Err(format!(
                "the return reissued `{}` by `{}`, not `write to me` by the default",
                returned.capability(),
                returned.issuer()
            ));
        }
        let file = rights_on_file(&rights, &pair)?;
        if file.len() != 1 || file[0].capability() != Capability::WRITE {
            return Err(format!(
                "the return left {} rights, not only the default",
                file.len()
            ));
        }
        let refusal = refused(
            rights
                .decide(&question(&laptop, &guest, Capability::WORK), &NoFloor, at)
                .map_err(|error| error.to_string())?,
        )?;
        if refusal != Refusal::NoRight {
            return Err(format!(
                "the restored machine's old right refused as {refusal}, not for want of a right"
            ));
        }
        let entries = acts(&rights)?;
        holds(
            &entries,
            at,
            "a trust return by egor",
            |act| matches!(act, Act::TrustRestored { by, .. } if *by == egor),
        )?;
        holds(&entries, at, "the default's reissue", |act| {
            matches!(
                act,
                Act::Granted {
                    issuer: Issuer::Default,
                    ..
                }
            )
        })?;
        Ok(())
    })
}

/// A machine moved to another assistant starts from the new pair's default and
/// inherits nothing; the pair it left keeps the right a person granted.
pub(crate) fn a_moved_machine_starts_from_the_new_pairs_default() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let alpha = label("alpha")?;
        let beta = label("beta")?;
        let rights = main.rights()?;
        let egor = person("egor")?;
        let pair_alpha = pair(&laptop, &alpha);
        let pair_beta = pair(&laptop, &beta);
        rights
            .bind(&laptop.peer_id(), main_binding(&alpha)?, NOW)
            .map_err(|error| error.to_string())?
            .ok_or("the first binding did not issue the default")?;
        rights
            .grant(
                &pair_alpha,
                Capability::WORK,
                Authority::Person(egor),
                None,
                NOW,
            )
            .map_err(|error| error.to_string())?;
        let at = NOW.plus(Duration::from_secs(1));
        let issued = rights
            .bind(&laptop.peer_id(), main_binding(&beta)?, at)
            .map_err(|error| error.to_string())?
            .ok_or("the new binding did not issue the default")?;
        if issued.capability() != Capability::WRITE {
            return Err(format!(
                "the new pair started with `{}`, not `write to me`",
                issued.capability()
            ));
        }
        let file = rights_on_file(&rights, &pair_beta)?;
        if file.len() != 1 || file[0].capability() != Capability::WRITE {
            return Err(format!(
                "the new pair holds {} rights, not only the default",
                file.len()
            ));
        }
        let refusal = refused(
            rights
                .decide(&question(&laptop, &beta, Capability::WORK), &NoFloor, at)
                .map_err(|error| error.to_string())?,
        )?;
        if refusal != Refusal::NoRight {
            return Err(format!("the new pair inherited `work on me`: {refusal}"));
        }
        let work = only_right(&rights, &pair_alpha, Capability::WORK)?;
        if work.standing(at) != Standing::Live {
            return Err(format!(
                "the old pair's `work on me` is {:?}",
                work.standing(at)
            ));
        }
        Ok(())
    })
}

/// A person's clearing of a closed pair's attempt lock reopens it and is recorded with
/// the person and the moment.
pub(crate) fn clearing_the_attempt_lock_is_recorded() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let store = main.records();
        for _ in 0..3 {
            store
                .record_failure(&laptop.peer_id())
                .map_err(|error| error.to_string())?;
        }
        if !store.is_closed(&laptop.peer_id()) {
            return Err("three failures did not close the pair".to_owned());
        }
        let rights = main.rights()?;
        let egor = person("egor")?;
        rights
            .clear_attempt_lock(&laptop.peer_id(), egor.clone(), NOW)
            .map_err(|error| error.to_string())?;
        if store.is_closed(&laptop.peer_id()) {
            return Err("the clearing left the pair closed".to_owned());
        }
        let entries = acts(&rights)?;
        holds(
            &entries,
            NOW,
            "an attempt-lock clearing by egor",
            |act| matches!(act, Act::AttemptLockCleared { by, .. } if *by == egor),
        )?;
        Ok(())
    })
}

/// A half-written last entry is a torn tail, not corruption: opening the log keeps the
/// complete entries and cuts the file back to the last one.
pub(crate) fn the_audit_discards_a_torn_tail() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;
        let peer = sim.machine().map_err(io_error)?;
        let guest = label("guest")?;
        machine
            .records()
            .record_pairing(&peer.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        machine
            .rights()?
            .on_acquaintance(&pair(&peer, &guest), NOW)
            .map_err(|error| error.to_string())?;
        let storage = machine.storage();
        let log = machine.audit()?;
        if log.entries().map_err(|error| error.to_string())?.len() != 1 {
            return Err("the one act did not leave one entry".to_owned());
        }
        let whole = storage.read_audit().map_err(io_error)?;
        // A write that stopped after the length and three bytes of the body.
        let mut torn = whole.clone();
        torn.extend_from_slice(&40u32.to_be_bytes());
        torn.extend_from_slice(&[0x01, 0x02, 0x03]);
        storage.write_audit(&torn).map_err(io_error)?;
        let reopened = machine.audit()?;
        let entries = reopened.entries().map_err(|error| error.to_string())?;
        if entries.len() != 1 {
            return Err(format!(
                "the reopened log holds {} entries, not the one real entry",
                entries.len()
            ));
        }
        let repaired = storage.read_audit().map_err(io_error)?;
        if repaired.len() >= torn.len() {
            return Err(format!(
                "the torn tail was kept: {} bytes, not fewer than {}",
                repaired.len(),
                torn.len()
            ));
        }
        if repaired != whole {
            return Err("the repair did not cut back to the last complete entry".to_owned());
        }
        Ok(())
    })
}

/// A log another account can read is refused as insecure, and the refusal names it.
#[cfg(unix)]
pub(crate) fn the_audit_is_private_to_the_account() -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;
        let log = machine.audit()?;
        // The mode is the rule on unix, so the case changes it; everything else goes
        // through the machine's own storage handle.
        std::fs::set_permissions(log.path(), std::fs::Permissions::from_mode(0o644))
            .map_err(io_error)?;
        let error = match machine.storage().audit() {
            Ok(_) => return Err("a log another account can read was opened".to_owned()),
            Err(error) => error,
        };
        match &error {
            AuditError::Insecure { path, .. } if path.as_path() == log.path() => {}
            other => {
                return Err(format!("the open refused as `{other}`, not as insecure"));
            }
        }
        if !error
            .to_string()
            .contains(&log.path().display().to_string())
        {
            return Err(format!("the refusal does not name the file: {error}"));
        }
        Ok(())
    })
}

/// Each refusal belongs to exactly one step, and no two reasons are the same answer.
pub(crate) fn every_refusal_names_its_own_step() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let stranger = sim.machine().map_err(io_error)?;
        let guest = label("guest")?;
        let rights = main.rights()?;
        let pair = pair(&laptop, &guest);
        let egor = person("egor")?;
        let mut refusals = Vec::new();
        // Not authenticated: no completed handshake stands behind the question.
        refusals.push(refused(
            rights
                .decide(
                    &Question {
                        speaker: Speaker::Unauthenticated,
                        pair: pair.clone(),
                        capability: Capability::WORK,
                    },
                    &NoFloor,
                    NOW,
                )
                .map_err(|error| error.to_string())?,
        )?);
        // Untrusted: the store holds no record for the machine.
        refusals.push(refused(
            rights
                .decide(
                    &question(&stranger, &guest, Capability::WORK),
                    &NoFloor,
                    NOW,
                )
                .map_err(|error| error.to_string())?,
        )?);
        // No right: a capability the pair never held.
        refusals.push(refused(
            rights
                .decide(
                    &question(&laptop, &guest, Capability::SEE_SCREEN),
                    &NoFloor,
                    NOW,
                )
                .map_err(|error| error.to_string())?,
        )?);
        // Withdrawn.
        rights
            .grant(
                &pair,
                Capability::TAKE_FILES,
                Authority::Person(egor.clone()),
                None,
                NOW,
            )
            .map_err(|error| error.to_string())?;
        rights
            .withdraw(
                &pair,
                Capability::TAKE_FILES,
                egor.clone(),
                NOW.plus(Duration::from_secs(1)),
            )
            .map_err(|error| error.to_string())?;
        refusals.push(refused(
            rights
                .decide(
                    &question(&laptop, &guest, Capability::TAKE_FILES),
                    &NoFloor,
                    NOW.plus(Duration::from_secs(2)),
                )
                .map_err(|error| error.to_string())?,
        )?);
        // Ended.
        rights
            .grant(
                &pair,
                Capability::WORK,
                Authority::Person(egor.clone()),
                Some(Duration::from_secs(10)),
                NOW.plus(Duration::from_secs(3)),
            )
            .map_err(|error| error.to_string())?;
        refusals.push(refused(
            rights
                .decide(
                    &question(&laptop, &guest, Capability::WORK),
                    &NoFloor,
                    NOW.plus(Duration::from_secs(14)),
                )
                .map_err(|error| error.to_string())?,
        )?);
        // The host's floor, over a right that exists.
        rights
            .grant(
                &pair,
                Capability::WRITE,
                Authority::Person(egor),
                None,
                NOW.plus(Duration::from_secs(15)),
            )
            .map_err(|error| error.to_string())?;
        let floor = |_: &Pair, capability: Capability| {
            (capability == Capability::WRITE).then(|| "no writing today".to_owned())
        };
        refusals.push(refused(
            rights
                .decide(
                    &question(&laptop, &guest, Capability::WRITE),
                    &floor,
                    NOW.plus(Duration::from_secs(16)),
                )
                .map_err(|error| error.to_string())?,
        )?);
        let expected = [
            Step::Authenticate,
            Step::Authenticate,
            Step::Right,
            Step::Right,
            Step::Right,
            Step::Floor,
        ];
        if refusals.len() != expected.len() {
            return Err(format!(
                "the case produced {} refusals, not {}",
                refusals.len(),
                expected.len()
            ));
        }
        for (refusal, step) in refusals.iter().zip(expected) {
            if refusal.step() != step {
                return Err(format!(
                    "`{refusal}` reports step `{}`, not `{step}`",
                    refusal.step()
                ));
            }
        }
        for (index, refusal) in refusals.iter().enumerate() {
            for other in &refusals[index + 1..] {
                if refusal == other {
                    return Err(format!("two refusals are equal: `{refusal}`"));
                }
            }
        }
        Ok(())
    })
}

/// One run's seven kinds of act are all in the log, each at the caller's moment and
/// with the acting person's name where a person acted.
pub(crate) fn the_audit_records_every_act() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let guest = label("guest")?;
        let rights = main.rights()?;
        let pair = pair(&laptop, &guest);
        let egor = person("egor")?;
        let granted = NOW;
        let refused_at = NOW.plus(Duration::from_secs(1));
        let term = NOW.plus(Duration::from_secs(2));
        let ended_at = NOW.plus(Duration::from_secs(13));
        let seen_at = NOW.plus(Duration::from_secs(14));
        let withdrawn_at = NOW.plus(Duration::from_secs(15));
        let trust_gone = NOW.plus(Duration::from_secs(16));
        let returned_at = NOW.plus(Duration::from_secs(17));
        let cleared_at = NOW.plus(Duration::from_secs(18));
        rights
            .grant(
                &pair,
                Capability::WORK,
                Authority::Person(egor.clone()),
                None,
                granted,
            )
            .map_err(|error| error.to_string())?;
        rights
            .decide(
                &question(&laptop, &guest, Capability::SEE_SCREEN),
                &NoFloor,
                refused_at,
            )
            .map_err(|error| error.to_string())?;
        rights
            .grant(
                &pair,
                Capability::TAKE_FILES,
                Authority::Person(egor.clone()),
                Some(Duration::from_secs(10)),
                term,
            )
            .map_err(|error| error.to_string())?;
        rights
            .decide(
                &question(&laptop, &guest, Capability::TAKE_FILES),
                &NoFloor,
                ended_at,
            )
            .map_err(|error| error.to_string())?;
        rights
            .grant(
                &pair,
                Capability::SEE_SCREEN,
                Authority::Person(egor.clone()),
                None,
                seen_at,
            )
            .map_err(|error| error.to_string())?;
        rights
            .withdraw(&pair, Capability::SEE_SCREEN, egor.clone(), withdrawn_at)
            .map_err(|error| error.to_string())?;
        rights
            .withdraw_trust(&laptop.peer_id(), egor.clone(), trust_gone)
            .map_err(|error| error.to_string())?;
        rights
            .restore_trust(&pair, egor.clone(), returned_at)
            .map_err(|error| error.to_string())?;
        let store = main.records();
        for _ in 0..3 {
            store
                .record_failure(&laptop.peer_id())
                .map_err(|error| error.to_string())?;
        }
        rights
            .clear_attempt_lock(&laptop.peer_id(), egor.clone(), cleared_at)
            .map_err(|error| error.to_string())?;
        let entries = acts(&rights)?;
        holds(&entries, granted, "a grant by egor", |act| {
            matches!(act, Act::Granted { issuer: Issuer::Person(name), kind: GrantKind::Created, capability, .. }
                if *name == egor && *capability == Capability::WORK)
        })?;
        holds(&entries, refused_at, "a refusal", |act| {
            matches!(
                act,
                Act::Refused {
                    refusal: Refusal::NoRight,
                    ..
                }
            )
        })?;
        holds(
            &entries,
            ended_at,
            "an ending",
            |act| matches!(act, Act::Ended { capability, .. } if *capability == Capability::TAKE_FILES),
        )?;
        holds(&entries, withdrawn_at, "a withdrawal by egor", |act| {
            matches!(act, Act::Withdrawn { by, capability, .. }
                if *by == egor && *capability == Capability::SEE_SCREEN)
        })?;
        holds(
            &entries,
            trust_gone,
            "a trust withdrawal by egor",
            |act| matches!(act, Act::TrustWithdrawn { by, .. } if *by == egor),
        )?;
        holds(
            &entries,
            returned_at,
            "a trust return by egor",
            |act| matches!(act, Act::TrustRestored { by, .. } if *by == egor),
        )?;
        holds(
            &entries,
            cleared_at,
            "an attempt-lock clearing by egor",
            |act| matches!(act, Act::AttemptLockCleared { by, .. } if *by == egor),
        )?;
        Ok(())
    })
}

/// A right for a capability this build does not know satisfies no question and is kept
/// byte for byte when the record is rewritten.
pub(crate) fn a_right_for_an_unknown_capability_is_never_satisfied() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let main = sim.machine().map_err(io_error)?;
        let peer = sim.machine().map_err(io_error)?;
        let guest = label("guest")?;
        let store = main.records();
        store
            .record_pairing(&peer.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        let pair = pair(&peer, &guest);
        let rights = main.rights()?;
        rights
            .on_acquaintance(&pair, NOW)
            .map_err(|error| error.to_string())?;
        // A newer build's right: capability 9, the assistant, no term, the default
        // issuer, and an ending with no term — a shape this build refuses for a
        // capability it knows, kept untouched for one it does not.
        let name = guest.as_str().as_bytes();
        let mut body = vec![9u8];
        body.extend_from_slice(
            &u16::try_from(name.len())
                .map_err(|_| "the assistant's label is too long".to_owned())?
                .to_be_bytes(),
        );
        body.extend_from_slice(name);
        body.extend_from_slice(&[0, 1, 0, 1]); // no term, the default issuer, no withdrawal
        body.extend_from_slice(&NOW.unix_seconds().to_be_bytes()); // the ending

        let crafted = field(0x0a, &body);
        let storage = main.storage();
        let mut bytes = storage.read_record(&peer.peer_id()).map_err(io_error)?;
        bytes.extend_from_slice(&crafted);
        storage
            .write_record(&peer.peer_id(), &bytes)
            .map_err(io_error)?;
        drop(rights);
        drop(store);

        let reopened = Rights::new(main.reopen_records()?, main.audit()?);
        let file = rights_on_file(&reopened, &pair)?;
        if file.len() != 1 || file[0].capability() != Capability::WRITE {
            return Err(format!(
                "the unknown capability surfaced among {} rights",
                file.len()
            ));
        }
        let refusal = refused(
            reopened
                .decide(&question(&peer, &guest, Capability::WORK), &NoFloor, NOW)
                .map_err(|error| error.to_string())?,
        )?;
        if refusal != Refusal::NoRight {
            return Err(format!(
                "a question beside the unknown right refused as {refusal}"
            ));
        }
        reopened
            .grant(
                &pair,
                Capability::WORK,
                Authority::Person(person("egor")?),
                None,
                NOW.plus(Duration::from_secs(1)),
            )
            .map_err(|error| error.to_string())?;
        let rewritten = storage.read_record(&peer.peer_id()).map_err(io_error)?;
        if !rewritten
            .windows(crafted.len())
            .any(|window| window == crafted.as_slice())
        {
            return Err("the rewrite dropped the field for the unknown capability".to_owned());
        }
        Ok(())
    })
}

/// A grant is written to the log before the record changes: a record write that fails
/// leaves the grant recorded and the right unwritten, which is the order a crash can
/// only break in the direction the design allows.
#[cfg(unix)]
pub(crate) fn the_audit_is_written_before_the_record_changes() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let guest = label("guest")?;
        let rights = main.rights()?;
        let pair = pair(&laptop, &guest);
        let egor = person("egor")?;
        rights
            .grant(
                &pair,
                Capability::WORK,
                Authority::Person(egor.clone()),
                None,
                NOW,
            )
            .map_err(|error| error.to_string())?;
        // The record's directory is closed to writes, so the next grant's audit entry
        // lands and its record write cannot.
        main.storage()
            .set_records_dir_mode(0o555)
            .map_err(io_error)?;
        let refused = rights.grant(
            &pair,
            Capability::SEE_SCREEN,
            Authority::Person(egor),
            None,
            NOW,
        );
        main.storage()
            .set_records_dir_mode(0o700)
            .map_err(io_error)?;
        match refused {
            Err(RightsError::Record(_)) => {}
            other => {
                return Err(format!(
                    "the grant against a closed record directory answered {other:?}"
                ));
            }
        }
        // The act is on file; the right it describes is not.
        let entries = acts(&rights)?;
        let last = entries.last().ok_or("the failed grant left no entry")?;
        match &last.act {
            Act::Granted {
                capability, kind, ..
            } if *capability == Capability::SEE_SCREEN && *kind == GrantKind::Created => {}
            other => {
                return Err(format!(
                    "the log's last entry is {other:?}, not the grant whose write failed"
                ));
            }
        }
        let file = rights_on_file(&rights, &pair)?;
        if file
            .iter()
            .any(|right| right.capability() == Capability::SEE_SCREEN)
        {
            return Err("the failed write left the right on file".to_owned());
        }
        if !file
            .iter()
            .any(|right| right.capability() == Capability::WORK)
        {
            return Err("the failed write disturbed the right that was already there".to_owned());
        }
        Ok(())
    })
}

/// A machine moved to another assistant is that pair: a question naming the pair it
/// left is refused for want of a right, the refusal is recorded against that pair, and
/// the old row stays on file as a record of what it held.
pub(crate) fn a_question_for_a_pair_the_machine_left_is_refused() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let alpha = label("alpha")?;
        let beta = label("beta")?;
        let rights = main.rights()?;
        let egor = person("egor")?;
        let pair_alpha = pair(&laptop, &alpha);
        rights
            .bind(&laptop.peer_id(), main_binding(&alpha)?, NOW)
            .map_err(|error| error.to_string())?
            .ok_or("the first binding did not issue the default")?;
        rights
            .grant(
                &pair_alpha,
                Capability::WORK,
                Authority::Person(egor),
                None,
                NOW,
            )
            .map_err(|error| error.to_string())?;
        let at = NOW.plus(Duration::from_secs(1));
        rights
            .bind(&laptop.peer_id(), main_binding(&beta)?, at)
            .map_err(|error| error.to_string())?
            .ok_or("the new binding did not issue the default")?;
        let refusal = refused(
            rights
                .decide(&question(&laptop, &alpha, Capability::WORK), &NoFloor, at)
                .map_err(|error| error.to_string())?,
        )?;
        if refusal != Refusal::NoRight {
            return Err(format!(
                "the pair the machine left refused as {refusal}, not for want of a right"
            ));
        }
        let entries = acts(&rights)?;
        let last = entries.last().ok_or("the refusal left no entry")?;
        match &last.act {
            Act::Refused {
                pair,
                capability,
                refusal: Refusal::NoRight,
            } if pair == &pair_alpha && *capability == Capability::WORK => {}
            other => {
                return Err(format!(
                    "the log's last entry is {other:?}, not the refused alpha `work on me`"
                ));
            }
        }
        let allowed = rights
            .decide(&question(&laptop, &beta, Capability::WRITE), &NoFloor, at)
            .map_err(|error| error.to_string())?;
        if allowed.allowed().is_none() {
            return Err(format!(
                "the new pair's default did not allow `write to me`: {allowed:?}"
            ));
        }
        let work = only_right(&rights, &pair_alpha, Capability::WORK)?;
        if work.standing(at) != Standing::Live {
            return Err(format!(
                "the old pair's `work on me` is {:?}, not live",
                work.standing(at)
            ));
        }
        Ok(())
    })
}

/// Returning a withdrawn machine, and a new acquaintance, issue the default for the
/// pair its binding names, whatever pair the caller passed; the pair the caller passed
/// gets nothing.
pub(crate) fn restoring_trust_issues_the_default_for_the_binding_pair() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let alpha = label("alpha")?;
        let beta = label("beta")?;
        let rights = main.rights()?;
        let egor = person("egor")?;
        let pair_alpha = pair(&laptop, &alpha);
        let pair_beta = pair(&laptop, &beta);
        rights
            .bind(&laptop.peer_id(), main_binding(&alpha)?, NOW)
            .map_err(|error| error.to_string())?
            .ok_or("the binding did not issue the default")?;
        rights
            .grant(
                &pair_alpha,
                Capability::WORK,
                Authority::Person(egor.clone()),
                None,
                NOW,
            )
            .map_err(|error| error.to_string())?;
        rights
            .withdraw_trust(&laptop.peer_id(), egor.clone(), NOW)
            .map_err(|error| error.to_string())?;
        let at = NOW.plus(Duration::from_secs(1));
        let returned = rights
            .restore_trust(&pair_beta, egor.clone(), at)
            .map_err(|error| error.to_string())?
            .issued
            .ok_or("the return did not reissue the default")?;
        if returned.assistant() != &alpha {
            return Err(format!(
                "the returned default is for `{}`, not the binding's `{alpha}`",
                returned.assistant()
            ));
        }
        if returned.capability() != Capability::WRITE {
            return Err(format!(
                "the return reissued `{}`, not `write to me`",
                returned.capability()
            ));
        }
        if !rights_on_file(&rights, &pair_beta)?.is_empty() {
            return Err("the return wrote a right for the pair the caller passed".to_owned());
        }
        let file = rights_on_file(&rights, &pair_alpha)?;
        if file.len() != 1 || file[0].capability() != Capability::WRITE {
            return Err(format!(
                "the binding's pair holds {} rights, not only the default",
                file.len()
            ));
        }
        let entries = acts(&rights)?;
        if entries.len() < 2 {
            return Err("the return left fewer than two entries".to_owned());
        }
        let restored = &entries[entries.len() - 2];
        let granted = &entries[entries.len() - 1];
        match &restored.act {
            Act::TrustRestored { peer, by } if *peer == laptop.peer_id() && *by == egor => {}
            other => {
                return Err(format!(
                    "the second-to-last entry is {other:?}, not the trust return"
                ));
            }
        }
        match &granted.act {
            Act::Granted {
                pair,
                capability,
                issuer,
                kind,
                ..
            } if pair == &pair_alpha
                && *capability == Capability::WRITE
                && *issuer == Issuer::Default
                && *kind == GrantKind::Created => {}
            other => {
                return Err(format!(
                    "the last entry is {other:?}, not the binding pair's default grant"
                ));
            }
        }
        // A new acquaintance names the binding's pair too: the caller's pair gets
        // nothing, and the bound pair's one default act is already spent.
        if rights
            .on_acquaintance(&pair_beta, at)
            .map_err(|error| error.to_string())?
            .is_some()
        {
            return Err(
                "a new acquaintance issued a right for the pair the caller passed".to_owned(),
            );
        }
        if !rights_on_file(&rights, &pair_beta)?.is_empty() {
            return Err(
                "a new acquaintance wrote a right for the pair the caller passed".to_owned(),
            );
        }
        Ok(())
    })
}

/// When the default finds the pair already holds the capability a person granted, its
/// entry names that person and that person's term; the log never attributes the
/// person's right to the default, and the row on file is untouched.
pub(crate) fn the_defaults_already_held_entry_names_the_person() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let bound = label("bound")?;
        let rights = main.rights()?;
        let pair = pair(&laptop, &bound);
        let egor = person("egor")?;
        let term = Duration::from_secs(3600);
        let granted = rights
            .grant(
                &pair,
                Capability::WRITE,
                Authority::Person(egor.clone()),
                Some(term),
                NOW,
            )
            .map_err(|error| error.to_string())?;
        let expires_at = granted.expires_at();
        if expires_at != Some(NOW.plus(term)) {
            return Err(format!(
                "the person's grant expires at {expires_at:?}, not at {}",
                NOW.plus(term)
            ));
        }
        let at = NOW.plus(Duration::from_secs(1));
        let returned = rights
            .on_acquaintance(&pair, at)
            .map_err(|error| error.to_string())?
            .ok_or("the default answered nothing for a pair that already held the right")?;
        if returned.issuer() != &Issuer::Person(egor.clone()) {
            return Err(format!(
                "the default's answer is issued by `{}`, not the person",
                returned.issuer()
            ));
        }
        if returned.expires_at() != expires_at {
            return Err(format!(
                "the default's answer expires at {:?}, not the person's {expires_at:?}",
                returned.expires_at()
            ));
        }
        let entries = acts(&rights)?;
        let last = entries.last().ok_or("the default left no entry")?;
        match &last.act {
            Act::Granted {
                capability,
                issuer,
                expires_at: entry_expiry,
                kind,
                ..
            } if *capability == Capability::WRITE
                && *issuer == Issuer::Person(egor.clone())
                && *entry_expiry == expires_at
                && *kind == GrantKind::AlreadyHeld => {}
            other => {
                return Err(format!(
                    "the log's last entry is {other:?}, not the person's right held already"
                ));
            }
        }
        let row = only_right(&rights, &pair, Capability::WRITE)?;
        if row.issuer() != &Issuer::Person(egor.clone()) || row.expires_at() != expires_at {
            return Err(format!(
                "the row on file is `{}` expiring {:?}, not the person's",
                row.issuer(),
                row.expires_at()
            ));
        }
        Ok(())
    })
}

/// The audit's privacy is checked on every append, on the descriptor it writes through:
/// a log another account can read refuses the next append, and the file's mode restored
/// lets the one after it land.
#[cfg(unix)]
pub(crate) fn the_audit_rechecks_privacy_on_every_append() -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;
        let peer = sim.machine().map_err(io_error)?;
        let egor = person("egor")?;
        machine
            .records()
            .record_pairing(&peer.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        let log = machine.audit()?;
        let rights = Rights::new(machine.records(), log.clone());
        let admin = label("admin")?;
        let pair = pair(&peer, &admin);
        let grant = |at: Timestamp, capability| {
            rights.grant(&pair, capability, Authority::Person(egor.clone()), None, at)
        };
        grant(NOW, Capability::WORK).map_err(|error| error.to_string())?;
        std::fs::set_permissions(log.path(), std::fs::Permissions::from_mode(0o644))
            .map_err(io_error)?;
        let error = match grant(NOW.plus(Duration::from_secs(1)), Capability::TAKE_FILES) {
            Ok(_) => {
                return Err("an append to a log another account can read succeeded".to_owned());
            }
            Err(RightsError::Audit(error)) => error,
            Err(other) => {
                return Err(format!("the append refused as `{other}`, not by the log"));
            }
        };
        match &error {
            AuditError::Insecure { path, .. } if path.as_path() == log.path() => {}
            other => {
                return Err(format!("the append refused as `{other}`, not as insecure"));
            }
        }
        if !error
            .to_string()
            .contains(&log.path().display().to_string())
        {
            return Err(format!("the refusal does not name the file: {error}"));
        }
        std::fs::set_permissions(log.path(), std::fs::Permissions::from_mode(0o600))
            .map_err(io_error)?;
        let at = NOW.plus(Duration::from_secs(2));
        grant(at, Capability::TAKE_FILES).map_err(|error| error.to_string())?;
        let entries = log.entries().map_err(|error| error.to_string())?;
        if !entries.iter().any(|entry| entry.at == at) {
            return Err("the append after the mode was restored is not in the log".to_owned());
        }
        Ok(())
    })
}

/// A create cut inside the header leaves the header's own prefix, so opening the log
/// completes the header rather than refusing it; bytes that are not that prefix are
/// corruption.
pub(crate) fn the_audit_repairs_a_torn_header() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;
        let peer = sim.machine().map_err(io_error)?;
        let egor = person("egor")?;
        let storage = machine.storage();
        // Create the log, then cut its header in half, as a create that died would.
        machine.audit()?;
        let header = storage.read_audit().map_err(io_error)?;
        if header.is_empty() {
            return Err("the new log holds no header".to_owned());
        }
        storage
            .write_audit(&header[..header.len() / 2])
            .map_err(io_error)?;
        let reopened = machine.audit()?;
        let repaired = storage.read_audit().map_err(io_error)?;
        if repaired != header {
            return Err(format!(
                "the reopened log holds {} bytes, not the whole header's {}",
                repaired.len(),
                header.len()
            ));
        }
        machine
            .records()
            .record_pairing(&peer.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        let at = NOW;
        Rights::new(machine.records(), reopened.clone())
            .grant(
                &pair(&peer, &label("admin")?),
                Capability::WORK,
                Authority::Person(egor),
                None,
                at,
            )
            .map_err(|error| error.to_string())?;
        let entries = reopened.entries().map_err(|error| error.to_string())?;
        if !entries.iter().any(|entry| entry.at == at) {
            return Err("the entry appended after the repair is not in the log".to_owned());
        }
        storage.write_audit(b"garbage").map_err(io_error)?;
        match storage.audit() {
            Err(AuditError::Malformed { .. }) => {}
            Ok(_) => return Err("a file that is not the log's header was opened".to_owned()),
            Err(other) => {
                return Err(format!(
                    "a file that is not the log's header refused as `{other}`, not as malformed"
                ));
            }
        }
        Ok(())
    })
}

/// An audit field carrying bytes after its label is not this build's shape of that
/// field: the act is kept as its code rather than read as a name this build never wrote.
pub(crate) fn an_audit_field_with_bytes_after_its_label_keeps_its_code() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;
        let peer = sim.machine().map_err(io_error)?;
        let storage = machine.storage();
        machine.audit()?;
        let header = storage.read_audit().map_err(io_error)?;
        // A complete grant whose assistant label carries a byte after its value: read as
        // the value's prefix, the act would decode as a grant naming a name this build
        // never wrote. The field is refused instead, and the act is kept as its code.
        let name = label("admin")?;
        let mut label_body = u16::try_from(name.as_str().len())
            .map_err(|_| "the label is too long to frame".to_owned())?
            .to_be_bytes()
            .to_vec();
        label_body.extend_from_slice(name.as_str().as_bytes());
        label_body.push(0); // one byte after the value
        let mut act = vec![1u8]; // a grant
        for (tag, body) in [
            (0x01u8, peer.peer_id().as_bytes().to_vec()),
            (0x02, label_body),
            (0x03, vec![1u8]), // the capability
            (0x04, vec![1u8]), // the default issuer
            (0x0b, vec![1u8]), // created
        ] {
            act.extend(field(tag, &body));
        }
        let mut entry = field(0x01, &NOW.unix_seconds().to_be_bytes());
        entry.extend(field(0x02, &act));
        let mut file = header;
        file.extend_from_slice(
            &u32::try_from(entry.len())
                .map_err(|_| "the entry is too long to frame".to_owned())?
                .to_be_bytes(),
        );
        file.extend_from_slice(&entry);
        storage.write_audit(&file).map_err(io_error)?;
        let entries = storage
            .audit()
            .and_then(|log| log.entries())
            .map_err(|error| error.to_string())?;
        match entries.last().map(|entry| &entry.act) {
            Some(Act::Unrecognised { code: 1 }) => Ok(()),
            other => Err(format!(
                "a grant with bytes after its label's value read as {other:?}, not as its code"
            )),
        }
    })
}

// ---------------------------------------------------------------------------
// The log's room, the return, and the attempt lock
// ---------------------------------------------------------------------------

/// The log's header: the magic and the version byte. A case that walks the frames
/// itself starts after it.
const AUDIT_HEADER: usize = b"mahbot-peer-audit".len() + 1;

/// The last entry frame in a log's bytes: its length word and its body.
fn last_frame(bytes: &[u8]) -> Result<&[u8], String> {
    let mut rest = bytes
        .get(AUDIT_HEADER..)
        .ok_or("the log is shorter than its header")?;
    let mut last = None;
    while let Some((&length, after)) = rest.split_first_chunk::<4>() {
        let length = u32::from_be_bytes(length) as usize;
        if after.get(..length).is_none() {
            break;
        }
        last = Some(&rest[..4 + length]);
        rest = &after[length..];
    }
    last.ok_or_else(|| "the log holds no entry frame".to_owned())
}

/// Fill the log with copies of its last entry until one more would pass `target`.
///
/// The copies are whole entries, so the log stays a log; the caller leaves a peer-driven
/// entry last when the fill is about the room kept for a person's acts. The file is
/// written through the machine's own storage handle, so the case stays inside the root
/// the rig confines it to.
pub(super) fn fill_log(machine: &Machine, target: u64) -> Result<(), String> {
    let storage = machine.storage();
    let whole = storage.read_audit().map_err(io_error)?;
    let frame = last_frame(&whole)?.to_vec();
    let mut filled = whole;
    while (filled.len() + frame.len()) as u64 <= target {
        filled.extend_from_slice(&frame);
    }
    storage.write_audit(&filled).map_err(io_error)
}

/// A peer's refusals stop at the room the log keeps for a person, and a person's acts
/// do not: with the part a peer may fill full, a refusal is still answered without an
/// entry, while a withdrawal is written, takes effect, and keeps the file under its cap.
pub(crate) fn a_full_log_keeps_room_for_a_person() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let guest = label("guest")?;
        let pair = pair(&laptop, &guest);
        let egor = person("egor")?;
        let at = NOW;
        let rights = main.rights()?;
        // The right a person will withdraw, and one refusal to fill the log with.
        rights
            .grant(
                &pair,
                Capability::WORK,
                Authority::Person(egor.clone()),
                None,
                at,
            )
            .map_err(|error| error.to_string())?;
        let refusal = refused(
            rights
                .decide(
                    &question(&laptop, &guest, Capability::SEE_SCREEN),
                    &NoFloor,
                    at,
                )
                .map_err(|error| error.to_string())?,
        )?;
        if refusal.step() != Step::Right {
            return Err(format!("the refusal came from `{}`", refusal.step()));
        }
        fill_log(&main, MAX_FILE_BYTES - RESERVED_FOR_PERSON_BYTES)?;

        // A fresh handle sees the filled log. A refusal is still answered — and is not
        // written, because the peer's room is full.
        let log = main.audit()?;
        let rights = Rights::new(main.records(), log.clone());
        let before = log.entries().map_err(|error| error.to_string())?.len();
        let refused_again = refused(
            rights
                .decide(
                    &question(&laptop, &guest, Capability::SEE_SCREEN),
                    &NoFloor,
                    at,
                )
                .map_err(|error| error.to_string())?,
        )?;
        if refused_again.step() != Step::Right {
            return Err("a refusal with no room in the log was not answered".to_owned());
        }
        let after = log.entries().map_err(|error| error.to_string())?;
        if after.len() != before {
            return Err(format!(
                "a refusal with no room in the log was written anyway: {} entries, not {before}",
                after.len()
            ));
        }

        // A person's withdrawal lands in the reserved room, and the decision refuses
        // with it at once.
        let withdrawn_at = at.plus(Duration::from_secs(1));
        rights
            .withdraw(&pair, Capability::WORK, egor, withdrawn_at)
            .map_err(|error| error.to_string())?;
        let entries = log.entries().map_err(|error| error.to_string())?;
        holds(
            &entries,
            withdrawn_at,
            "a withdrawal by egor",
            |act| matches!(act, Act::Withdrawn { capability, .. } if *capability == Capability::WORK),
        )?;
        if (main.storage().read_audit().map_err(io_error)?.len() as u64) > MAX_FILE_BYTES {
            return Err("the person's act took the log past its cap".to_owned());
        }
        let refusal = refused(
            rights
                .decide(
                    &question(&laptop, &guest, Capability::WORK),
                    &NoFloor,
                    withdrawn_at,
                )
                .map_err(|error| error.to_string())?,
        )?;
        if refusal != (Refusal::Withdrawn { at: withdrawn_at }) {
            return Err(format!(
                "the withdrawn right answered {refusal}, not the withdrawal"
            ));
        }
        Ok(())
    })
}

/// A question that notices an ending when the log has no room left for the entry a peer
/// causes answers the ending and leaves the row unmarked: the term passed, so the right
/// refuses either way, and recording the ending must not spend room a person's acts need
/// — neither the part kept for them nor, once that is gone too, the file's last byte.
pub(crate) fn an_ending_with_no_room_is_answered_without_marking_the_row() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let guest = label("guest")?;
        let pair = pair(&laptop, &guest);
        let rights = main.rights()?;
        // A right whose term passes, and one refusal to fill the log with.
        let expires_at = NOW.plus(Duration::from_secs(10));
        rights
            .grant(
                &pair,
                Capability::WORK,
                Authority::Person(person("egor")?),
                Some(Duration::from_secs(10)),
                NOW,
            )
            .map_err(|error| error.to_string())?;
        refused(
            rights
                .decide(
                    &question(&laptop, &guest, Capability::SEE_SCREEN),
                    &NoFloor,
                    NOW,
                )
                .map_err(|error| error.to_string())?,
        )?;
        fill_log(&main, MAX_FILE_BYTES)?;
        let log = main.audit()?;
        let rights = Rights::new(main.records(), log.clone());
        let after = NOW.plus(Duration::from_secs(20));
        let refusal = refused(
            rights
                .decide(
                    &question(&laptop, &guest, Capability::WORK),
                    &NoFloor,
                    after,
                )
                .map_err(|error| error.to_string())?,
        )?;
        if refusal != (Refusal::Ended { at: expires_at }) {
            return Err(format!(
                "the ended right answered {refusal}, not its term at {expires_at}"
            ));
        }
        // The row is not marked: the ending has no entry, so the record must not claim
        // one, and the right refuses either way because its term passed.
        let row = only_right(&rights, &pair, Capability::WORK)?;
        if row.ended_at().is_some() {
            return Err("the ending was marked on the row without an entry".to_owned());
        }
        if acts(&rights)?
            .iter()
            .any(|entry| matches!(entry.act, Act::Ended { .. }))
        {
            return Err("an ending was written with no room for it".to_owned());
        }
        Ok(())
    })
}

/// A torn write near the cap is cut before the cap is judged: a log pushed just past
/// `MAX_FILE_BYTES` by a half-written entry opens, and comes back under its cap, instead
/// of becoming unopenable for ever.
pub(crate) fn a_torn_tail_past_the_cap_is_cut_before_the_cap_is_judged() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;
        let peer = sim.machine().map_err(io_error)?;
        machine
            .records()
            .record_pairing(&peer.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        let rights = machine.rights()?;
        rights
            .grant(
                &pair(&peer, &label("admin")?),
                Capability::WORK,
                Authority::Person(person("egor")?),
                None,
                NOW,
            )
            .map_err(|error| error.to_string())?;
        fill_log(&machine, MAX_FILE_BYTES)?;
        let storage = machine.storage();
        let before = storage.read_audit().map_err(io_error)?.len() as u64;
        if before > MAX_FILE_BYTES {
            return Err("the fill took the log past its cap".to_owned());
        }
        // A write that stopped inside its body: a length word naming one byte more than
        // the room that was left, and only that room behind it — which takes the file
        // past the cap and leaves the last entry short of its own length.
        let room = MAX_FILE_BYTES - before;
        let claim = u32::try_from(room + 1).unwrap_or(u32::MAX);
        let mut torn = storage.read_audit().map_err(io_error)?;
        torn.extend_from_slice(&claim.to_be_bytes());
        torn.extend(std::iter::repeat_n(0u8, usize::try_from(room).unwrap_or(0)));
        storage.write_audit(&torn).map_err(io_error)?;
        if (storage.read_audit().map_err(io_error)?.len() as u64) <= MAX_FILE_BYTES {
            return Err("the torn write did not take the log past its cap".to_owned());
        }
        // Opening cuts the tear before judging the cap.
        let log = machine.audit()?;
        let entries = log.entries().map_err(|error| error.to_string())?;
        if entries.is_empty() {
            return Err("the repaired log holds no entry".to_owned());
        }
        let after = storage.read_audit().map_err(io_error)?.len() as u64;
        if after > MAX_FILE_BYTES {
            return Err(format!("the repaired log still holds {after} bytes"));
        }
        Ok(())
    })
}

/// An append cuts a torn tail another process left before writing past it: the log is
/// whole afterwards, and the entry before the tear is untouched.
pub(crate) fn an_append_cuts_a_torn_tail_left_by_another_process() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;
        let peer = sim.machine().map_err(io_error)?;
        let egor = person("egor")?;
        machine
            .records()
            .record_pairing(&peer.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        let pair = pair(&peer, &label("admin")?);
        // The second handle is opened before the first writes: its own view of the
        // file is the header alone, which is what a process that opened the log and
        // then slept holds.
        let log = machine.audit()?;
        let second = machine.audit()?;
        Rights::new(machine.records(), log.clone())
            .grant(
                &pair,
                Capability::WORK,
                Authority::Person(egor.clone()),
                None,
                NOW,
            )
            .map_err(|error| error.to_string())?;
        let storage = machine.storage();
        let whole = storage.read_audit().map_err(io_error)?;
        // A write that stopped after its length word and three bytes of the body.
        let mut torn = whole.clone();
        torn.extend_from_slice(&40u32.to_be_bytes());
        torn.extend_from_slice(&[0x01, 0x02, 0x03]);
        storage.write_audit(&torn).map_err(io_error)?;
        // The second handle appends: it finds the tail before writing past it.
        let at = NOW.plus(Duration::from_secs(1));
        Rights::new(machine.records(), second.clone())
            .grant(
                &pair,
                Capability::TAKE_FILES,
                Authority::Person(egor),
                None,
                at,
            )
            .map_err(|error| error.to_string())?;
        let entries = second.entries().map_err(|error| error.to_string())?;
        if entries.len() != 2 {
            return Err(format!(
                "the log holds {} entries after the tear was cut, not the two real ones",
                entries.len()
            ));
        }
        if !entries.iter().any(|entry| entry.at == at) {
            return Err("the append after the tear is not in the log".to_owned());
        }
        // The entries before the tear are untouched, and the tear is gone: what follows
        // them is exactly the one frame this append wrote.
        let after = storage.read_audit().map_err(io_error)?;
        if !after.starts_with(&whole) {
            return Err("the entry before the tear was not left as it was".to_owned());
        }
        let appended = &after[whole.len()..];
        let framed = appended
            .split_first_chunk::<4>()
            .map(|(length, _)| u32::from_be_bytes(*length) as usize + 4);
        if framed != Some(appended.len()) {
            return Err(format!(
                "{} bytes follow the tear, not the one frame the append wrote",
                appended.len()
            ));
        }
        Ok(())
    })
}

/// A return that has a default still owed issues it, and only a return whose default has
/// acted answers that it is over — the state a return that failed after clearing the
/// trust is in, which a case cannot build without injecting a write failure.
pub(crate) fn a_return_finishes_what_it_started() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let guest = label("guest")?;
        let pair = pair(&laptop, &guest);
        let egor = person("egor")?;
        let rights = main.rights()?;
        // The state a return leaves when its default's write did not land: the trust is
        // back and the default has not acted for the pair. A pairing that never met an
        // acquaintance is the same state, so it is the one the case can build.
        let record = main
            .records()
            .get(&laptop.peer_id())
            .ok_or("the paired machine has no record")?;
        if record.is_withdrawn() || record.default_spent(&pair).is_some() {
            return Err("the case did not start from a trust with its default owed".to_owned());
        }
        let returned = rights
            .restore_trust(&pair, egor.clone(), NOW)
            .map_err(|error| error.to_string())?;
        let issued = returned
            .issued
            .ok_or("the return reported nothing to finish and issued no default")?;
        if issued.capability() != Capability::WRITE || issued.issuer() != &Issuer::Default {
            return Err(format!(
                "the return issued `{}` by `{}`, not `write to me` by the default",
                issued.capability(),
                issued.issuer()
            ));
        }
        if returned.closed.is_some() {
            return Err("the return reported a lock this pair does not hold".to_owned());
        }
        // Now the act is over, and saying so is not the same as finishing it.
        match rights.restore_trust(&pair, egor, NOW.plus(Duration::from_secs(1))) {
            Err(RightsError::NotWithdrawn { .. }) => {}
            other => {
                return Err(format!(
                    "a return that was over answered {other:?}, not that it is over"
                ));
            }
        }
        Ok(())
    })
}

/// A return from a withdrawal on a machine whose attempt lock is also closed says so,
/// rather than answering a right that cannot be used.
pub(crate) fn a_return_reports_a_still_closed_pair() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let guest = label("guest")?;
        let pair = pair(&laptop, &guest);
        let egor = person("egor")?;
        let store = main.records();
        for _ in 0..3 {
            store
                .record_failure(&laptop.peer_id())
                .map_err(|error| error.to_string())?;
        }
        let rights = main.rights()?;
        rights
            .on_acquaintance(&pair, NOW)
            .map_err(|error| error.to_string())?;
        rights
            .withdraw_trust(&laptop.peer_id(), egor.clone(), NOW)
            .map_err(|error| error.to_string())?;
        let at = NOW.plus(Duration::from_secs(1));
        let returned = rights
            .restore_trust(&pair, egor.clone(), at)
            .map_err(|error| error.to_string())?;
        if returned.issued.is_none() {
            return Err("the return issued no default".to_owned());
        }
        let closed = returned
            .closed
            .ok_or("the return did not report the closed attempt lock")?;
        if closed.failures != 3 || closed.max_failures != 3 {
            return Err(format!(
                "the return reports {}/{} failures, not the closed pair's 3/3",
                closed.failures, closed.max_failures
            ));
        }
        // What the return said is what the decision does: the machine cannot write
        // until the second, separate act.
        let refusal = refused(
            rights
                .decide(&question(&laptop, &guest, Capability::WRITE), &NoFloor, at)
                .map_err(|error| error.to_string())?,
        )?;
        if refusal != Refusal::Untrusted {
            return Err(format!("the still-closed pair answered {refusal}"));
        }
        rights
            .clear_attempt_lock(&laptop.peer_id(), egor, at)
            .map_err(|error| error.to_string())?;
        if rights
            .decide(&question(&laptop, &guest, Capability::WRITE), &NoFloor, at)
            .map_err(|error| error.to_string())?
            .allowed()
            .is_none()
        {
            return Err("the cleared pair still refuses the right it holds".to_owned());
        }
        Ok(())
    })
}

/// Clearing an attempt lock that holds nothing changes nothing and records nothing; an
/// unknown machine is still refused.
pub(crate) fn clearing_an_open_lock_records_nothing() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let stranger = sim.machine().map_err(io_error)?;
        let egor = person("egor")?;
        let rights = main.rights()?;
        rights
            .grant(
                &pair(&laptop, &label("admin")?),
                Capability::WORK,
                Authority::Person(egor.clone()),
                None,
                NOW,
            )
            .map_err(|error| error.to_string())?;
        let before = acts(&rights)?.len();
        rights
            .clear_attempt_lock(&laptop.peer_id(), egor.clone(), NOW)
            .map_err(|error| error.to_string())?;
        let after = acts(&rights)?;
        if after.len() != before {
            return Err(format!(
                "a clearing with nothing to clear recorded an act: {} entries, not {before}",
                after.len()
            ));
        }
        match rights.clear_attempt_lock(&stranger.peer_id(), egor, NOW) {
            Err(RightsError::NotPaired { peer }) if peer == stranger.peer_id() => {}
            other => {
                return Err(format!(
                    "a clearing for an unknown machine answered {other:?}, not that it is not paired"
                ));
            }
        }
        Ok(())
    })
}
