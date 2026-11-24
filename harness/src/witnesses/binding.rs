//! The binding as a wire fact and the manager's handling of it: the claim keeps the
//! deciding machine's newer decision, a fact of a newer version is read as this
//! version's prefix, a malformed fact changes nothing, a connection that only
//! exchanged its binding carried nothing, a withdrawn machine is not reached, and a
//! rebind takes effect at the next connection.
//!
//! Every case runs over the simulated link and the injected clock. Nothing here opens
//! a socket or starts a process.
//!
//! # Why the withdrawn handshake is a full one
//!
//! `a_withdrawn_machine_is_not_reached` withdraws a machine's trust on the dialer and
//! then dials it. The pin is the certificate verifier, and a resumed TLS session never
//! asks it, so resumption is disabled on both sides (`tls::client_config_with_resolver`
//! and `tls::server_config` say why): the handshake after a withdrawal is a full one,
//! the pin runs, and the key the far side presents is refused as untrusted.

use std::time::Duration;

use mahbot_peers::identity::PeerId;
use mahbot_peers::peer::access::MAX_LABEL_BYTES;
use mahbot_peers::peer::{
    Account, Binding, Capability, ConnectFailure, Connections, Fact, FactError, Instance, Label,
    LabelError, NoFloor, NotTrustedCause, Pair, Question, RECOVERY_DIALS, RecordError, Recovery,
    Refusal, Speaker, StopCause, Timestamp,
};
use mahbot_peers::tls::PeerPolicy;

use crate::beacon::TestBeacon;
use crate::clock::block_on;
use crate::sim::Sim;

use super::connection::Managed;
use super::peer::NOW;
use super::rights::{label, paired_machines, person, refused, wait_claim};
use super::support::{io_error, spawn_keeper, within};

/// The bytes a fact opens with: the offset of its version byte is this length.
const FACT_MAGIC: &[u8] = b"mahbot-peer-binding";

/// How many task turns a case gives the exchange to finish on a clean link before it
/// closes the connection. The exchange measures its own frames before it keeps the
/// claim, so waiting for the claim is waiting for the measurement; a connection
/// closed before it landed is judged as one that carried nothing.
const EXCHANGE_TURNS: usize = 32;

/// The connection level a deciding machine records, decided at `at`.
fn binding_at(assistant: &Label, at: Timestamp) -> Result<Binding, String> {
    Ok(Binding::new(
        Account::new("main-account").map_err(|error| error.to_string())?,
        Instance::new("main-instance").map_err(|error| error.to_string())?,
        assistant.clone(),
        at,
    ))
}

/// The bytes of the fact a binding at `at` travels as.
fn fact_at(assistant: &Label, at: Timestamp) -> Result<Vec<u8>, String> {
    binding_at(assistant, at)?
        .fact()
        .encode()
        .map_err(|error| error.to_string())
}

/// Wait until the pair holds no live connection, so the next dial is not judged by the
/// tie-break against the connection just closed.
async fn wait_no_live(sim: &Sim, connections: &Connections, peer: &PeerId) -> Result<(), String> {
    within(sim, Duration::from_secs(60), async {
        loop {
            if connections.live(peer).is_none() {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
}

/// The fact's bytes with one field's tag, length and body dropped, as a peer of a
/// build that does not know that field would send them.
fn without_field(bytes: &[u8], drop_tag: u8) -> Result<Vec<u8>, String> {
    let mut out = bytes
        .get(..=FACT_MAGIC.len())
        .ok_or("the fact is shorter than its magic and version")?
        .to_vec();
    let mut rest = &bytes[FACT_MAGIC.len() + 1..];
    while !rest.is_empty() {
        let (&tag, after_tag) = rest.split_first().ok_or("a fact field has no tag")?;
        let (length, after_length) = after_tag
            .split_first_chunk::<2>()
            .ok_or("a fact field has no length")?;
        let length = usize::from(u16::from_be_bytes(*length));
        let (body, after_body) = after_length
            .split_at_checked(length)
            .ok_or("a fact field runs past the end")?;
        if tag != drop_tag {
            out.push(tag);
            let length = u16::try_from(body.len()).map_err(|error| error.to_string())?;
            out.extend_from_slice(&length.to_be_bytes());
            out.extend_from_slice(body);
        }
        rest = after_body;
    }
    Ok(out)
}

/// The fact's bytes with `extra` appended inside the body of the field `tag` names, as a
/// longer body of the same tag would arrive.
fn with_trailing(bytes: &[u8], tag: u8, extra: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = bytes
        .get(..=FACT_MAGIC.len())
        .ok_or("the fact is shorter than its magic and version")?
        .to_vec();
    let mut rest = &bytes[FACT_MAGIC.len() + 1..];
    while !rest.is_empty() {
        let (&field, after_tag) = rest.split_first().ok_or("a fact field has no tag")?;
        let (length, after_length) = after_tag
            .split_first_chunk::<2>()
            .ok_or("a fact field has no length")?;
        let length = usize::from(u16::from_be_bytes(*length));
        let (body, after_body) = after_length
            .split_at_checked(length)
            .ok_or("a fact field runs past the end")?;
        let mut body = body.to_vec();
        if field == tag {
            body.extend_from_slice(extra);
        }
        out.push(field);
        let length = u16::try_from(body.len()).map_err(|error| error.to_string())?;
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&body);
        rest = after_body;
    }
    Ok(out)
}

/// Assert that a decoded fact carries the fields that were encoded.
fn same_fields(found: &Fact, expected: &Fact) -> Result<(), String> {
    if found == expected {
        return Ok(());
    }
    Err(format!(
        "the fact decoded as `{}`/`{}`/`{}` at {}, not the one that was encoded",
        found.account().label(),
        found.instance().label(),
        found.assistant(),
        found.decided_at()
    ))
}

/// The claim is the deciding machine's latest decision: an older fact does not undo it,
/// a newer one replaces it.
pub(crate) fn a_claim_keeps_the_newer_decision() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let store = laptop.records();
        let peer = main.peer_id();
        let first = label("first")?;
        let second = label("second")?;
        let older = Timestamp::from_unix_seconds(NOW.unix_seconds() - 1);
        let newer = NOW.plus(Duration::from_secs(1));

        store
            .record_claim(&peer, &fact_at(&first, NOW)?)
            .map_err(|error| error.to_string())?;
        let record = store.get(&peer).ok_or("the first fact left no record")?;
        let claim = record.claim().ok_or("the first fact left no claim")?;
        if claim.fact().assistant() != &first || claim.fact().decided_at() != NOW {
            return Err(format!(
                "the first fact left `{}` at {}, not `{}` at {NOW}",
                claim.fact().assistant(),
                claim.fact().decided_at(),
                first
            ));
        }

        // A re-delivered stale fact is not the latest decision.
        store
            .record_claim(&peer, &fact_at(&second, older)?)
            .map_err(|error| error.to_string())?;
        let record = store
            .get(&peer)
            .ok_or("the stale fact removed the record")?;
        let claim = record.claim().ok_or("the stale fact removed the claim")?;
        if claim.fact().assistant() != &first || claim.fact().decided_at() != NOW {
            return Err(format!(
                "an older fact decided at {older} replaced the claim with `{}` at {}",
                claim.fact().assistant(),
                claim.fact().decided_at()
            ));
        }

        // A newer fact is the deciding machine's latest decision, and it is durable.
        store
            .record_claim(&peer, &fact_at(&second, newer)?)
            .map_err(|error| error.to_string())?;
        let record = store.get(&peer).ok_or("the claim's record vanished")?;
        let claim = record.claim().ok_or("the newer fact left no claim")?;
        if claim.fact().assistant() != &second || claim.fact().decided_at() != newer {
            return Err(format!(
                "the newer fact left `{}` at {}, not `{}` at {newer}",
                claim.fact().assistant(),
                claim.fact().decided_at(),
                second
            ));
        }
        Ok(())
    })
}

/// A fact of a version this build does not write is read as this version's prefix, and
/// a fact this build cannot read at all is refused field by field.
pub(crate) fn a_fact_of_a_newer_version_is_read_as_this_versions_prefix() -> Result<(), String> {
    block_on(async {
        let admin = label("admin")?;
        let fact = binding_at(&admin, NOW)?.fact().clone();
        let bytes = fact.encode().map_err(|error| error.to_string())?;

        let decoded = Fact::decode(&bytes).map_err(|error| error.to_string())?;
        same_fields(&decoded, &fact)?;

        // A version above this build's, with a field this build does not know: the
        // known fields are read and the unknown one is ignored.
        let mut newer = bytes.clone();
        newer[FACT_MAGIC.len()] = 2;
        newer.extend_from_slice(&[0x7f, 0x00, 0x00]);
        let read = Fact::decode(&newer)
            .map_err(|error| format!("a fact of a newer version was refused: {error}"))?;
        same_fields(&read, &fact)?;

        // A version byte of zero is not a fact.
        let mut zero = bytes.clone();
        zero[FACT_MAGIC.len()] = 0;
        match Fact::decode(&zero) {
            Err(FactError::Version { found: 0 }) => {}
            other => {
                return Err(format!(
                    "a fact of version zero read as {other:?}, not a refusal of version zero"
                ));
            }
        }

        // Bytes that are not a fact at all.
        match Fact::decode(b"not a fact") {
            Err(FactError::Magic) => {}
            other => {
                return Err(format!(
                    "bytes that are not a fact read as {other:?}, not a magic refusal"
                ));
            }
        }

        // A fact that names no assistant cannot be read.
        let missing = without_field(&bytes, 0x03)?;
        match Fact::decode(&missing) {
            Err(FactError::Missing { field: "assistant" }) => {}
            other => {
                return Err(format!(
                    "a fact with no assistant field read as {other:?}, not a missing assistant"
                ));
            }
        }
        Ok(())
    })
}

/// A label is a name a person can be shown: one that says nothing, runs off a line or
/// runs too long is refused, and a fact field carrying bytes after its label is refused
/// as that field rather than read as the value's prefix.
pub(crate) fn a_label_is_a_name_a_person_can_be_shown() -> Result<(), String> {
    let admin = label("admin")?;
    let fact = binding_at(&admin, NOW)?.fact().clone();
    let bytes = fact.encode().map_err(|error| error.to_string())?;

    // A name that is only whitespace names nothing a person can see.
    match Label::new("   ") {
        Err(LabelError::Empty) => {}
        other => return Err(format!("a blank label was read as {other:?}")),
    }
    // A name longer than the format's cap cannot be carried by a record or a fact.
    let long = "a".repeat(MAX_LABEL_BYTES + 1);
    match Label::new(&long) {
        Err(LabelError::TooLong { bytes }) if bytes == MAX_LABEL_BYTES + 1 => {}
        other => return Err(format!("an oversized label was read as {other:?}")),
    }
    // A control character or a direction mark would let a name reorder or break the
    // line it is shown on, so each is refused.
    for unshowable in [
        "admin\u{7}",
        "admin\u{2028}next",
        "admin\u{202e}next",
        "admin\u{61c}next",
    ] {
        match Label::new(unshowable) {
            Err(LabelError::Control) => {}
            other => {
                return Err(format!("the label {unshowable:?} was read as {other:?}"));
            }
        }
    }
    // A field whose body carries bytes after its value is not this build's shape of that
    // field: it is refused rather than read as its prefix, so a body's shape is fixed
    // once and grows only as a new tag.
    let lengthened = with_trailing(&bytes, 0x03, &[0x00])?;
    match Fact::decode(&lengthened) {
        Err(FactError::Field { tag: 0x03, .. }) => Ok(()),
        other => Err(format!(
            "a fact field with bytes after its label read as {other:?}, not as a field refusal"
        )),
    }
}

/// A fact this build cannot read is refused as the peer's bytes, naming the machine
/// that sent them, and the claim already on file is untouched.
pub(crate) fn a_malformed_fact_changes_nothing() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let store = laptop.records();
        let peer = main.peer_id();
        let admin = label("admin")?;
        store
            .record_claim(&peer, &fact_at(&admin, NOW)?)
            .map_err(|error| error.to_string())?;
        let before = store
            .get(&peer)
            .and_then(|record| record.claim())
            .ok_or("the good fact left no claim")?;

        match store.record_claim(&peer, b"not a fact") {
            Err(RecordError::Claim { peer: named, .. }) => {
                if named != peer {
                    return Err(format!(
                        "the refusal names {named:?}, not the machine that sent the bytes"
                    ));
                }
            }
            Err(other) => {
                return Err(format!(
                    "bytes that are not a fact were refused as `{other}`, not as the peer's"
                ));
            }
            Ok(_) => {
                return Err("bytes that are not a fact were kept as a claim".to_owned());
            }
        }

        let after = store
            .get(&peer)
            .and_then(|record| record.claim())
            .ok_or("the refused fact removed the claim on file")?;
        if after != before {
            return Err(format!(
                "the refused fact changed the claim from `{}` at {} to `{}` at {}",
                before.fact().assistant(),
                before.fact().decided_at(),
                after.fact().assistant(),
                after.fact().decided_at()
            ));
        }
        Ok(())
    })
}

/// A connection that only exchanged its binding carried nothing, so the keeper counts it
/// as a dial that carried nothing: the episode is used up instead of re-dialling for ever,
/// and the pair is still being watched rather than given up on.
pub(crate) fn a_binding_only_connection_carried_nothing() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let admin = label("admin")?;
        // The deciding machine binds the laptop, so every connection the laptop makes
        // is answered with a fact and the exchange runs to its end.
        main.rights()?
            .bind(&laptop.peer_id(), binding_at(&admin, NOW)?, NOW)
            .map_err(|error| error.to_string())?;
        let _managed_main = Managed::start(&sim, &beacon, &main, &main.records())?;
        let managed_laptop = Managed::start(&sim, &beacon, &laptop, &laptop.records())?;
        let claims = laptop.reopen_records()?;
        let keeper = spawn_keeper(&managed_laptop, &main);
        let mut measured = false;
        within(&sim, Duration::from_secs(600), async {
            loop {
                // The episode is used up when the dials that carried nothing reach the cap:
                // that is what bounds a peer that accepts and drops, and it is what this case
                // waits for now that the keeper no longer ends.
                if keeper.is_finished()
                    || matches!(
                        managed_laptop.connections.recovery(&main.peer_id()),
                        Recovery::Exhausted { .. }
                    )
                {
                    return Ok::<(), String>(());
                }
                if let Some(live) = managed_laptop.connections.live(&main.peer_id()) {
                    // Let the exchange finish on the clean link before the connection
                    // goes. It is the manager's handshake and not the pair's traffic, so
                    // its frames must have been written — and measured — on this very
                    // connection, or the case would say nothing about them.
                    for _ in 0..EXCHANGE_TURNS {
                        tokio::task::yield_now().await;
                    }
                    within(&sim, Duration::from_secs(10), async {
                        loop {
                            let frames =
                                live.stats().frame_tx.stream + live.stats().frame_rx.stream;
                            if frames > 0 {
                                return;
                            }
                            tokio::task::yield_now().await;
                        }
                    })
                    .await?;
                    if !measured {
                        // The claim is written after the measurement, so waiting for it
                        // is waiting for the exchange's frames to have been subtracted
                        // from this connection before it dies.
                        wait_claim(&sim, &claims, &main.peer_id(), None).await?;
                        measured = true;
                    }
                    managed_laptop.connections.disconnect(&main.peer_id());
                }
                tokio::task::yield_now().await;
            }
        })
        .await??;
        // The dials carried nothing, so the pair's episode is used up — and the keeper is
        // still running, because a peer that might stop dropping it is not given up on.
        if keeper.is_finished() {
            return Err("the keeper stopped after connections that carried nothing".to_owned());
        }
        let state = managed_laptop.connections.recovery(&main.peer_id());
        let Recovery::Exhausted { dials, last, .. } = &state else {
            return Err(format!(
                "the pair reads `{state}`, not an episode used up after connections that carried \
                 nothing"
            ));
        };
        if *dials != RECOVERY_DIALS {
            return Err(format!(
                "the episode was used up after {dials} dials, not {RECOVERY_DIALS}"
            ));
        }
        if !matches!(last, ConnectFailure::NoDirectPath { .. }) {
            return Err(format!(
                "the used-up episode names `{last}`, not the connection that carried nothing"
            ));
        }
        keeper.abort();
        // The exchange really ran: the laptop holds the fact the deciding machine sent.
        let claim = wait_claim(&sim, &claims, &main.peer_id(), None).await?;
        if claim.fact().assistant() != &admin {
            return Err(format!(
                "the laptop's claim names `{}`, not `{}`",
                claim.fact().assistant(),
                admin
            ));
        }
        Ok(())
    })
}

/// A machine whose trust was withdrawn is closed by the manager itself and refused by
/// the keeper with the withdrawal as its cause, and a handshake that reaches the pin is
/// refused as untrusted.
pub(crate) fn a_withdrawn_machine_is_not_reached() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let admin = label("admin")?;
        main.rights()?
            .bind(&laptop.peer_id(), binding_at(&admin, NOW)?, NOW)
            .map_err(|error| error.to_string())?;
        let _managed_main = Managed::start(&sim, &beacon, &main, &main.records())?;
        let managed_laptop = Managed::start(&sim, &beacon, &laptop, &laptop.records())?;
        within(
            &sim,
            Duration::from_secs(60),
            managed_laptop
                .connections
                .connect(&managed_laptop.endpoint, &main.fingerprint()),
        )
        .await?
        .map_err(|error| error.to_string())?;
        let claim = wait_claim(&sim, &laptop.records(), &main.peer_id(), None).await?;
        if claim.fact().assistant() != &admin {
            return Err(format!(
                "the laptop's claim names `{}`, not `{}`",
                claim.fact().assistant(),
                admin
            ));
        }

        // A keeper is already running, parked on the live connection: the withdrawal
        // must stop it, not only a keeper started afterwards.
        let keeper = spawn_keeper(&managed_laptop, &main);
        within(&sim, Duration::from_secs(60), async {
            while managed_laptop.connections.live(&main.peer_id()).is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        // The person on the laptop withdraws the machine the laptop is connected to.
        laptop
            .rights()?
            .withdraw_trust(&main.peer_id(), person("egor")?, NOW)
            .map_err(|error| error.to_string())?;
        if !laptop
            .records()
            .get(&main.peer_id())
            .is_some_and(|record| record.is_withdrawn())
        {
            return Err("the laptop's record does not say the trust was withdrawn".to_owned());
        }

        // The manager stops reaching for the pair, and says why. It closes what is live
        // itself, on its next round: the caller does not have to, and a caller holding
        // another store over the root could not reach this manager at all.
        let end = within(&sim, Duration::from_secs(120), keeper)
            .await?
            .map_err(|error| format!("the keeper's task did not finish: {error}"))?;
        if managed_laptop.connections.live(&main.peer_id()).is_some() {
            return Err("the withdrawn pair still has a live connection".to_owned());
        }
        match &end {
            StopCause::NotTrusted(NotTrustedCause::Withdrawn) => {}
            other => {
                return Err(format!(
                    "the keeper ended `{other}`, not a refusal naming the withdrawal"
                ));
            }
        }

        // And the next handshake is refused for the key it presents: resumption is
        // off, so the handshake is a full one and the pin runs.
        match crate::connect::connect(&laptop, &main).await {
            Err(crate::connect::ConnectError::Connection(error)) => {
                let refusal = mahbot_peers::net::refusal(&error);
                if refusal != Some(mahbot_peers::tls::Refusal::Untrusted) {
                    return Err(format!(
                        "the withdrawn machine was refused as {refusal:?}, not as untrusted"
                    ));
                }
            }
            Ok(_) => {
                return Err("the withdrawn machine completed a handshake".to_owned());
            }
            Err(other) => {
                return Err(format!("the refusal came from the wrong layer: {other}"));
            }
        }
        Ok(())
    })
}

/// A withdrawal written through one store stops a manager built over another store of
/// the same root: the live connection is closed and the keeper stops naming the
/// withdrawal, with nothing asked of the caller.
pub(crate) fn a_withdrawal_is_seen_by_another_store() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let admin = label("admin")?;
        main.rights()?
            .bind(&laptop.peer_id(), binding_at(&admin, NOW)?, NOW)
            .map_err(|error| error.to_string())?;
        let _managed_main = Managed::start(&sim, &beacon, &main, &main.records())?;
        // The manager holds a store of its own, opened separately from the one the
        // rights layer withdraws through: two handles over one root, which is what a
        // product ends up with. A third, opened here and untouched until it is asked the
        // handshake's question below, is what keeps that question's answer from being
        // the manager's refreshed map.
        let manager_store = laptop.reopen_records()?;
        let handshake_store = laptop.reopen_records()?;
        let managed_laptop = Managed::start(&sim, &beacon, &laptop, &manager_store)?;
        within(
            &sim,
            Duration::from_secs(60),
            managed_laptop
                .connections
                .connect(&managed_laptop.endpoint, &main.fingerprint()),
        )
        .await?
        .map_err(|error| error.to_string())?;
        wait_claim(&sim, &manager_store, &main.peer_id(), None).await?;
        let keeper = spawn_keeper(&managed_laptop, &main);
        within(&sim, Duration::from_secs(60), async {
            while managed_laptop.connections.live(&main.peer_id()).is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        // The person withdraws through the machine's own store, not the manager's.
        laptop
            .rights()?
            .withdraw_trust(&main.peer_id(), person("egor")?, NOW)
            .map_err(|error| error.to_string())?;
        if manager_store
            .get(&main.peer_id())
            .is_some_and(|record| record.is_withdrawn())
        {
            return Err("the manager's own store saw the withdrawal without reading".to_owned());
        }
        // The handshake's own question, asked of the handle opened before the withdrawal
        // and never read since: it reads the record, so the key that was trusted a moment
        // ago is not any more.
        if handshake_store.trusts(&main.fingerprint()) {
            return Err(
                "a store loaded before the withdrawal still trusts the peer's key".to_owned(),
            );
        }
        // No disconnect, no reload: the manager asks the record and closes what is live.
        let end = within(&sim, Duration::from_secs(120), keeper)
            .await?
            .map_err(|error| format!("the keeper's task did not finish: {error}"))?;
        match &end {
            StopCause::NotTrusted(NotTrustedCause::Withdrawn) => {}
            other => {
                return Err(format!(
                    "the keeper ended `{other}`, not a refusal naming the withdrawal"
                ));
            }
        }
        if managed_laptop.connections.live(&main.peer_id()).is_some() {
            return Err("the withdrawn pair still has a live connection".to_owned());
        }
        // And the manager will not dial it again.
        match within(
            &sim,
            Duration::from_secs(60),
            managed_laptop
                .connections
                .connect(&managed_laptop.endpoint, &main.fingerprint()),
        )
        .await?
        {
            Err(ConnectFailure::NotTrusted {
                cause: NotTrustedCause::Withdrawn,
                ..
            }) => Ok(()),
            other => Err(format!(
                "a dial after the withdrawal answered {other:?}, not a refusal naming it"
            )),
        }
    })
}

/// A binding changed while the connection is up takes effect at the next connection,
/// and the claim it leaves still grants nothing.
pub(crate) fn a_rebind_takes_effect_at_the_next_connection() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let first = label("first")?;
        let second = label("second")?;
        let at = NOW.plus(Duration::from_secs(1));
        main.rights()?
            .bind(&laptop.peer_id(), binding_at(&first, NOW)?, NOW)
            .map_err(|error| error.to_string())?;
        let managed_main = Managed::start(&sim, &beacon, &main, &main.records())?;
        let managed_laptop = Managed::start(&sim, &beacon, &laptop, &laptop.records())?;
        within(
            &sim,
            Duration::from_secs(60),
            managed_laptop
                .connections
                .connect(&managed_laptop.endpoint, &main.fingerprint()),
        )
        .await?
        .map_err(|error| error.to_string())?;
        let claim = wait_claim(&sim, &laptop.records(), &main.peer_id(), None).await?;
        if claim.fact().assistant() != &first {
            return Err(format!(
                "the first connection's claim names `{}`, not `{}`",
                claim.fact().assistant(),
                first
            ));
        }

        // The deciding machine changes its mind while the connection is up. The
        // connection carries the old binding until it is closed and made again.
        main.rights()?
            .bind(&laptop.peer_id(), binding_at(&second, at)?, at)
            .map_err(|error| error.to_string())?;
        if !managed_main.connections.disconnect(&laptop.peer_id()) {
            return Err("the rebind held no live connection to close".to_owned());
        }
        wait_no_live(&sim, &managed_laptop.connections, &main.peer_id()).await?;
        within(
            &sim,
            Duration::from_secs(60),
            managed_laptop
                .connections
                .connect(&managed_laptop.endpoint, &main.fingerprint()),
        )
        .await?
        .map_err(|error| error.to_string())?;
        let claim = wait_claim(&sim, &laptop.records(), &main.peer_id(), Some(&second)).await?;

        // The claim names the pair for the laptop's person and is still not authority.
        let refusal = refused(
            laptop
                .rights()?
                .decide(
                    &Question {
                        speaker: Speaker::Authenticated(main.peer_id()),
                        pair: Pair::of_claim(&claim),
                        capability: Capability::WORK,
                    },
                    &NoFloor,
                    at,
                )
                .map_err(|error| error.to_string())?,
        )?;
        if refusal != Refusal::NoRight {
            return Err(format!(
                "the claim allowed work on the laptop: the decision refused as {refusal}"
            ));
        }

        let binding = main
            .records()
            .get(&laptop.peer_id())
            .and_then(|record| record.binding().cloned())
            .ok_or("the main's record holds no binding")?;
        let fact = binding.fact();
        if fact.assistant() != &second || fact.decided_at() != at {
            return Err(format!(
                "the main's record names `{}` at {}, not `{}` at {at}",
                fact.assistant(),
                fact.decided_at(),
                second
            ));
        }
        Ok(())
    })
}

/// A right withdrawn, and a right whose term passed, while the connection is up: the
/// next question refuses both, naming its own step and moment, and the connection
/// stays live — the decision reads the record afresh, not a view the connection took.
pub(crate) fn a_right_withdrawn_or_ended_while_connected_refuses() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let admin = label("admin")?;
        let rights = main.rights()?;
        let pair = Pair::new(laptop.peer_id(), &admin);
        let egor = person("egor")?;
        let term = NOW.plus(Duration::from_secs(60));
        rights
            .grant(
                &pair,
                Capability::WORK,
                mahbot_peers::peer::Authority::Person(egor.clone()),
                None,
                NOW,
            )
            .map_err(|error| error.to_string())?;
        rights
            .grant(
                &pair,
                Capability::SEE_SCREEN,
                mahbot_peers::peer::Authority::Person(egor.clone()),
                Some(Duration::from_secs(60)),
                NOW,
            )
            .map_err(|error| error.to_string())?;
        let _managed_main = Managed::start(&sim, &beacon, &main, &main.records())?;
        let managed_laptop = Managed::start(&sim, &beacon, &laptop, &laptop.records())?;
        within(
            &sim,
            Duration::from_secs(60),
            managed_laptop
                .connections
                .connect(&managed_laptop.endpoint, &main.fingerprint()),
        )
        .await?
        .map_err(|error| error.to_string())?;
        if managed_laptop.connections.live(&main.peer_id()).is_none() {
            return Err("the pair holds no live connection to decide against".to_owned());
        }
        let ask = |capability: Capability| Question {
            speaker: Speaker::Authenticated(laptop.peer_id()),
            pair: pair.clone(),
            capability,
        };
        for capability in [Capability::WORK, Capability::SEE_SCREEN] {
            let decision = rights
                .decide(&ask(capability), &NoFloor, NOW)
                .map_err(|error| error.to_string())?;
            if decision.allowed().is_none() {
                return Err(format!(
                    "`{capability}` was not allowed before it stopped: {decision:?}"
                ));
            }
        }
        let withdrawn_at = NOW.plus(Duration::from_secs(1));
        rights
            .withdraw(&pair, Capability::WORK, egor, withdrawn_at)
            .map_err(|error| error.to_string())?;
        let refusal = refused(
            rights
                .decide(&ask(Capability::WORK), &NoFloor, withdrawn_at)
                .map_err(|error| error.to_string())?,
        )?;
        if refusal != (Refusal::Withdrawn { at: withdrawn_at }) {
            return Err(format!(
                "the withdrawn right refused as {refusal}, not at {withdrawn_at}"
            ));
        }
        let after = NOW.plus(Duration::from_secs(61));
        let refusal = refused(
            rights
                .decide(&ask(Capability::SEE_SCREEN), &NoFloor, after)
                .map_err(|error| error.to_string())?,
        )?;
        if refusal != (Refusal::Ended { at: term }) {
            return Err(format!(
                "the ended right refused as {refusal}, not at {term}"
            ));
        }
        if managed_laptop.connections.live(&main.peer_id()).is_none() {
            return Err("the connection did not stay live across the decisions".to_owned());
        }
        Ok(())
    })
}

/// A right withdrawn through one store over a root refuses the next question on
/// another store over the same root: the decision re-reads the record, so no answer
/// comes from a stale view — the shape another process on this machine has.
pub(crate) fn a_withdrawal_by_another_store_refuses_the_next_question() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        let admin = label("admin")?;
        let pair = Pair::new(laptop.peer_id(), &admin);
        let ask = Question {
            speaker: Speaker::Authenticated(laptop.peer_id()),
            pair: pair.clone(),
            capability: Capability::WORK,
        };
        // The second store is loaded now, before the grant, so its map is the stale
        // view the decision must not answer from.
        let first = main.rights()?;
        let second = mahbot_peers::peer::Rights::new(main.reopen_records()?, main.audit()?);
        let egor = person("egor")?;
        first
            .grant(
                &pair,
                Capability::WORK,
                mahbot_peers::peer::Authority::Person(egor.clone()),
                None,
                NOW,
            )
            .map_err(|error| error.to_string())?;
        let allowed = second
            .decide(&ask, &NoFloor, NOW)
            .map_err(|error| error.to_string())?;
        if allowed.allowed().is_none() {
            return Err(format!(
                "the second store did not see the grant written after it loaded: {allowed:?}"
            ));
        }
        let at = NOW.plus(Duration::from_secs(1));
        first
            .withdraw(&pair, Capability::WORK, egor, at)
            .map_err(|error| error.to_string())?;
        let refusal = refused(
            second
                .decide(&ask, &NoFloor, at)
                .map_err(|error| error.to_string())?,
        )?;
        if refusal != (Refusal::Withdrawn { at }) {
            return Err(format!(
                "the second store answered {refusal}, not the withdrawal at {at}"
            ));
        }
        Ok(())
    })
}

/// A peer with no binding writes nothing: the exchange answers an empty stream with
/// nothing, so no claim is written, the pairing's record stays as it was, and the
/// connection stands.
pub(crate) fn a_peer_without_a_binding_leaves_no_claim() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let (main, laptop) = paired_machines(&sim)?;
        // Neither side is bound, so neither sends a fact and neither has a claim to
        // write. The connection is a real one over the simulated link.
        let _managed_main = Managed::start(&sim, &beacon, &main, &main.records())?;
        let managed_laptop = Managed::start(&sim, &beacon, &laptop, &laptop.records())?;
        within(
            &sim,
            Duration::from_secs(60),
            managed_laptop
                .connections
                .connect(&managed_laptop.endpoint, &main.fingerprint()),
        )
        .await?
        .map_err(|error| error.to_string())?;
        let live = managed_laptop
            .connections
            .live(&main.peer_id())
            .ok_or("the connection did not stay live")?;
        // Let the exchange finish on the clean link: it is the manager's handshake and
        // not the pair's traffic, so its frames must have been written on this very
        // connection before the case reads the record.
        for _ in 0..EXCHANGE_TURNS {
            tokio::task::yield_now().await;
        }
        within(&sim, Duration::from_secs(10), async {
            loop {
                let frames = live.stats().frame_tx.stream + live.stats().frame_rx.stream;
                if frames > 0 {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;
        let record = laptop
            .records()
            .get(&main.peer_id())
            .ok_or("the pairing's record vanished")?;
        if !record.is_paired() {
            return Err("the record no longer says the machines are paired".to_owned());
        }
        if record.claim().is_some() {
            return Err("a peer with no binding left a claim".to_owned());
        }
        // The record the exchange might have written is the one still on file: the
        // store reopens and reads the pairing back.
        if laptop.reopen_records()?.get(&main.peer_id()).is_none() {
            return Err("the record write failed: the reopened store lost the pairing".to_owned());
        }
        if managed_laptop.connections.live(&main.peer_id()).is_none() {
            return Err("the connection did not stay live".to_owned());
        }
        // An empty body is no fact at all, and the store is where that is decided: a
        // caller that received no bytes gets `Ok` with nothing written, so an empty
        // stream never becomes a refusal or a doomed write.
        laptop
            .records()
            .record_claim(&main.peer_id(), b"")
            .map_err(|error| format!("an empty fact was refused: {error}"))?;
        if laptop
            .reopen_records()?
            .get(&main.peer_id())
            .and_then(|record| record.claim())
            .is_some()
        {
            return Err("an empty fact was kept as a claim".to_owned());
        }
        Ok(())
    })
}
