//! Peer-layer cases: the durable record and the acquaintance ceremony.
//!
//! Every case runs over the simulated link and the injected clock. Nothing here
//! opens a socket or starts a process; a claim that needs a real network is in the
//! capability inventory as unproducible, with what would produce it.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use mahbot_peers::beacon::{Introduction, Session};
use mahbot_peers::peer::pair::{self, Ceremony, Opening, Outcome};
use mahbot_peers::peer::{
    COMPARISON_SYMBOLS, ConnectFailure, Connections, Limits, Malformed, NotTrustedCause,
    RecordError, RecordStore, Rights, Timestamp,
};

use crate::beacon::TestBeacon;
use crate::clock::block_on;
use crate::machine::Machine;
use crate::pair::Mediator;
use crate::sim::Sim;

use super::rights::person;
use super::support::{BUDGET, io_error, within};

/// A moment a case uses; the library never reads one.
pub(super) const NOW: Timestamp = Timestamp::from_unix_seconds(1_000_000);

pub(super) fn now() -> Timestamp {
    NOW
}

/// A live beacon session for `machine`, registered so introductions reach it.
pub(super) async fn session(beacon: &TestBeacon, machine: &Machine) -> Result<Session, String> {
    let session = beacon
        .client(machine)?
        .connect()
        .await
        .map_err(|error| error.to_string())?;
    session
        .register()
        .await
        .map_err(|error| error.to_string())?;
    Ok(session)
}

/// Sign `payload` as `from` for `to`: the one way a case hands a ceremony flight to
/// the beacon.
fn introduce(from: &Machine, to: &Machine, payload: Vec<u8>) -> Result<Introduction, String> {
    Introduction::signed(&from.identity, to.peer_id(), payload).map_err(|error| error.to_string())
}

/// The strings one side showed its person, and how the person answered.
#[derive(Clone, Default)]
pub(super) struct Shown {
    seen: Arc<Mutex<Vec<String>>>,
    accept: bool,
}

impl Shown {
    pub(super) fn accepting() -> Self {
        Self {
            seen: Arc::new(Mutex::new(Vec::new())),
            accept: true,
        }
    }

    pub(super) fn rejecting() -> Self {
        Self {
            accept: false,
            ..Self::accepting()
        }
    }

    pub(super) fn person(&self) -> impl FnMut(mahbot_peers::peer::Comparison) -> bool + '_ {
        move |comparison| {
            self.seen
                .lock()
                .expect("the shown list is not poisoned")
                .push(comparison.to_string());
            self.accept
        }
    }

    pub(super) fn seen(&self) -> Vec<String> {
        self.seen
            .lock()
            .expect("the shown list is not poisoned")
            .clone()
    }
}

/// The two sides of one comparison: the machines, how each enters, the people and
/// the stores they write.
pub(super) struct Pairing<'a> {
    pub left: &'a Machine,
    pub right: &'a Machine,
    pub left_opens: Opening,
    pub right_opens: Opening,
    pub left_person: &'a Shown,
    pub right_person: &'a Shown,
    pub left_store: &'a RecordStore,
    pub right_store: &'a RecordStore,
}

/// Run one ceremony on each side over one beacon, and hand back both outcomes.
pub(super) async fn pair_together(
    sim: &Sim,
    beacon: &TestBeacon,
    pairing: Pairing<'_>,
) -> Result<(Result<Outcome, String>, Result<Outcome, String>), String> {
    let left_session = session(beacon, pairing.left).await?;
    let right_session = session(beacon, pairing.right).await?;
    let (left_outcome, right_outcome) = within(sim, Duration::from_secs(90), async {
        tokio::join!(
            pair::run(
                &left_session,
                &pairing.left.identity,
                pairing.left_opens,
                pairing.left_store,
                now,
                pairing.left_person.person(),
            ),
            pair::run(
                &right_session,
                &pairing.right.identity,
                pairing.right_opens,
                pairing.right_store,
                now,
                pairing.right_person.person(),
            ),
        )
    })
    .await?;
    Ok((
        left_outcome.map_err(|error| error.to_string()),
        right_outcome.map_err(|error| error.to_string()),
    ))
}

pub(super) fn paired(outcome: &Result<Outcome, String>) -> bool {
    matches!(outcome, Ok(Outcome::Paired { .. }))
}

// ---------------------------------------------------------------------------
// The durable record
// ---------------------------------------------------------------------------

pub(crate) fn peer_record_round_trips() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;
        let peer = sim.machine().map_err(io_error)?;
        let address = std::net::SocketAddr::from(([10, 0, 0, 7], 4444));
        let store = machine.records();
        store
            .record_pairing(&peer.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        store
            .record_address(&peer.peer_id(), address)
            .map_err(|error| error.to_string())?;
        // A second store over the same root is what a later start reads.
        let store = machine.reopen_records()?;
        let record = store
            .get(&peer.peer_id())
            .ok_or("the record did not survive the store")?;
        if record.fingerprint() != peer.fingerprint() {
            return Err("the fingerprint is not derived from the stored key".to_owned());
        }
        if record.paired_at() != Some(NOW) {
            return Err(format!("the pairing moment reads {:?}", record.paired_at()));
        }
        if record.last_address() != Some(address) {
            return Err(format!("the address reads {:?}", record.last_address()));
        }
        if record.failures() != 0 || record.attempt().is_some() {
            return Err("a fresh pairing carries failures or an attempt".to_owned());
        }
        // The fingerprint is not a second fact in the file: its 44 bytes are not
        // there, and the 32-byte key is.
        let bytes = machine
            .storage()
            .read_record(&peer.peer_id())
            .map_err(io_error)?;
        if bytes
            .windows(record.fingerprint().as_bytes().len())
            .any(|window| window == record.fingerprint().as_bytes())
        {
            return Err("the record stores the fingerprint beside the key".to_owned());
        }
        // The address codec the record and the ceremony share reads both families.
        let v6 = std::net::SocketAddr::from((
            std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            5555,
        ));
        store
            .record_address(&peer.peer_id(), v6)
            .map_err(|error| error.to_string())?;
        let store = machine.reopen_records()?;
        if store
            .get(&peer.peer_id())
            .and_then(|record| record.last_address())
            != Some(v6)
        {
            return Err("an IPv6 address did not survive the record".to_owned());
        }
        // A link-local address without its scope cannot be dialed, so the scope and
        // the flow info are part of the address, not decoration.
        let link_local = std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
            std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            5555,
            7,
            9,
        ));
        store
            .record_address(&peer.peer_id(), link_local)
            .map_err(|error| error.to_string())?;
        let store = machine.reopen_records()?;
        if store
            .get(&peer.peer_id())
            .and_then(|record| record.last_address())
            != Some(link_local)
        {
            return Err("a link-local address lost its scope or flow info".to_owned());
        }
        Ok(())
    })
}

#[cfg(unix)]
pub(crate) fn peer_record_refuses_other_readers() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;
        let peer = sim.machine().map_err(io_error)?;
        let store = machine.records();
        store
            .record_pairing(&peer.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        machine
            .storage()
            .set_record_mode(&peer.peer_id(), 0o644)
            .map_err(io_error)?;
        match machine.reopen_records() {
            Err(error) if error.contains("not private") => {}
            Err(error) => return Err(format!("the insecure record reads `{error}`")),
            Ok(_) => return Err("a record readable by others was accepted".to_owned()),
        }
        // The repair a person runs reaches a record the store refuses: naming the file
        // does not open the store, so the mode can be put back.
        machine
            .storage()
            .set_record_mode(&peer.peer_id(), 0o600)
            .map_err(io_error)?;
        match machine.reopen_records() {
            Ok(store) if store.is_paired(&peer.peer_id()) => Ok(()),
            Ok(_) => Err("a repaired record lost its pairing".to_owned()),
            Err(error) => Err(format!("a repaired record reads `{error}`")),
        }
    })
}

#[cfg(unix)]
pub(crate) fn peer_record_refuses_other_writers() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;
        let peer = sim.machine().map_err(io_error)?;
        let store = machine.records();
        store
            .record_pairing(&peer.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        // A directory another account can write lets it delete a record, which is a
        // silent un-pairing: the store refuses it as it refuses an insecure file.
        machine
            .storage()
            .set_records_dir_mode(0o777)
            .map_err(io_error)?;
        match machine.reopen_records() {
            Err(error) if error.contains("not private") => {}
            Err(error) => return Err(format!("the insecure directory reads `{error}`")),
            Ok(_) => return Err("a record directory writable by others was accepted".to_owned()),
        }
        // The repair reaches the directory the store refuses, as it reaches a record.
        machine
            .storage()
            .set_records_dir_mode(0o700)
            .map_err(io_error)?;
        match machine.reopen_records() {
            Ok(store) if store.is_paired(&peer.peer_id()) => Ok(()),
            Ok(_) => Err("a repaired directory lost its pairing".to_owned()),
            Err(error) => Err(format!("a repaired directory reads `{error}`")),
        }
    })
}

pub(crate) fn peer_record_reload_sees_another_process() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;
        let peer = sim.machine().map_err(io_error)?;
        // Two stores over one root, as the self-update window has for a few seconds.
        let first = machine.records();
        let second = machine.reopen_records()?;
        first
            .record_pairing(&peer.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        if second.is_paired(&peer.peer_id()) {
            return Err("a store saw a pairing written after it loaded".to_owned());
        }
        // The read side is the caller's: reload, then trust.
        second.reload().map_err(|error| error.to_string())?;
        if !second.is_paired(&peer.peer_id()) {
            return Err("a reload did not see the other process's pairing".to_owned());
        }
        // A write from the second process re-reads the file first: the pairing the
        // first wrote is still there, and the address the second wrote is seen by
        // the first after its own reload.
        let address = std::net::SocketAddr::from(([10, 0, 0, 9], 9));
        second
            .record_address(&peer.peer_id(), address)
            .map_err(|error| error.to_string())?;
        first.reload().map_err(|error| error.to_string())?;
        let record = first
            .get(&peer.peer_id())
            .ok_or("the pairing was dropped by the other writer")?;
        if !record.is_paired() || record.paired_at() != Some(NOW) {
            return Err(format!(
                "the pairing reads {record:?} after the other write"
            ));
        }
        if record.last_address() != Some(address) {
            return Err("the first process did not see the address the second wrote".to_owned());
        }
        Ok(())
    })
}

pub(crate) fn peer_record_refuses_garbage() -> Result<(), String> {
    block_on(async {
        let root = super::support::temp_root()?;
        let store =
            RecordStore::open(root.path(), Limits::default()).map_err(|error| error.to_string())?;
        let peer = Sim::new()
            .map_err(io_error)?
            .machine()
            .map_err(io_error)?
            .peer_id();
        let path = RecordStore::path_for(root.path(), &peer);
        drop(store);

        type Case = (&'static str, Vec<u8>, fn(&Malformed) -> bool);
        let cases: Vec<Case> = vec![
            ("an empty file", Vec::new(), |reason| {
                matches!(reason, Malformed::Empty)
            }),
            ("a foreign magic", b"not a record".to_vec(), |reason| {
                matches!(reason, Malformed::Magic)
            }),
            (
                "version zero",
                {
                    let mut bytes = b"mahbot-peer-record".to_vec();
                    bytes.push(0);
                    bytes
                },
                |reason| matches!(reason, Malformed::Version { .. }),
            ),
            (
                "a body with no key",
                {
                    let mut bytes = b"mahbot-peer-record".to_vec();
                    bytes.push(1);
                    bytes.extend_from_slice(&[0x04, 0x00, 0x01, 0x00]);
                    bytes
                },
                |reason| matches!(reason, Malformed::NoKey),
            ),
        ];
        for (what, bytes, expected) in cases {
            crate::root::write_private(&path, &bytes).map_err(io_error)?;
            let Err(error) = RecordStore::open(root.path(), Limits::default()) else {
                return Err(format!("{what} was read as a record"));
            };
            match &error {
                RecordError::Malformed { reason, .. } if expected(reason) => {}
                _ => return Err(format!("{what} was refused as `{error}`")),
            }
            // A person acting on the refusal needs the file, not only the reason.
            if !error.to_string().contains(&path.display().to_string()) {
                return Err(format!(
                    "{what} was refused without naming the file: {error}"
                ));
            }
        }
        // The name's spelling is part of the format: one peer, one file. The
        // lowercase file from the last case goes, so only the name is judged.
        std::fs::remove_file(&path).map_err(io_error)?;
        let upper = path.with_file_name(format!("{}.record", "AB".repeat(32)));
        crate::root::write_private(&upper, b"not a record").map_err(io_error)?;
        match RecordStore::open(root.path(), Limits::default()) {
            Err(RecordError::Malformed {
                reason: Malformed::Name { .. },
                ..
            }) => {}
            Err(error) => return Err(format!("an uppercase name was refused as `{error}`")),
            Ok(_) => return Err("an uppercase name was read as a record".to_owned()),
        }
        Ok(())
    })
}

pub(crate) fn peer_record_reads_unknown_fields() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;
        let peer = sim.machine().map_err(io_error)?;
        let store = machine.records();
        store
            .record_pairing(&peer.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        // A newer build: a higher version and a field this one does not know.
        let storage = machine.storage();
        let mut bytes = storage.read_record(&peer.peer_id()).map_err(io_error)?;
        bytes[b"mahbot-peer-record".len()] = 2;
        bytes.extend_from_slice(&[0x7f, 0x00, 0x03, 0xde, 0xad, 0xbe]);
        storage
            .write_record(&peer.peer_id(), &bytes)
            .map_err(io_error)?;

        let store = machine.reopen_records()?;
        let record = store
            .get(&peer.peer_id())
            .ok_or("a record of a newer version was not read")?;
        if !record.is_paired() {
            return Err("a record of a newer version lost its pairing".to_owned());
        }
        // A write this build makes must put the unknown field back.
        store
            .record_address(
                &peer.peer_id(),
                std::net::SocketAddr::from(([10, 0, 0, 1], 1)),
            )
            .map_err(|error| error.to_string())?;
        let rewritten = storage.read_record(&peer.peer_id()).map_err(io_error)?;
        if !rewritten
            .windows(3)
            .any(|window| window == [0xde, 0xad, 0xbe])
        {
            return Err("a rewrite dropped a field this build does not know".to_owned());
        }
        if rewritten[b"mahbot-peer-record".len()] != 2 {
            return Err("a rewrite downgraded the version byte".to_owned());
        }
        let store = machine.reopen_records()?;
        if !store.is_paired(&peer.peer_id()) {
            return Err("the rewritten record lost its pairing".to_owned());
        }
        Ok(())
    })
}

pub(crate) fn peer_record_never_unpairs() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;
        let peer = sim.machine().map_err(io_error)?;
        let store = machine.records();
        store
            .record_pairing(&peer.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        store
            .record_address(
                &peer.peer_id(),
                std::net::SocketAddr::from(([10, 0, 0, 2], 2)),
            )
            .map_err(|error| error.to_string())?;
        store
            .record_failure(&peer.peer_id())
            .map_err(|error| error.to_string())?;
        let record = store
            .get(&peer.peer_id())
            .ok_or("the record a failure was counted in is gone")?;
        if !record.is_paired() || record.paired_at() != Some(NOW) {
            return Err("a later write dropped the pairing or re-dated it".to_owned());
        }
        if record.failures() != 1 {
            return Err(format!("the failure count reads {}", record.failures()));
        }
        if !store.is_paired(&peer.peer_id()) {
            return Err("the store stopped trusting a paired peer".to_owned());
        }
        Ok(())
    })
}

pub(crate) fn peer_record_survives_restart() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let mut machine = sim.machine().map_err(io_error)?;
        let peer = sim.machine().map_err(io_error)?;
        let fingerprint = machine.fingerprint();
        let store = machine.records();
        store
            .record_pairing(&peer.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        store
            .record_address(&peer.peer_id(), peer.addr())
            .map_err(|error| error.to_string())?;
        // An unfinished attempt is recorded with its expiry, so the restart has one
        // more fact to keep.
        let attempt = store
            .begin_attempt(&peer.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        drop(store);
        machine.restart().await?;
        if machine.fingerprint() != fingerprint {
            return Err("a restart changed the machine's identity".to_owned());
        }
        let store = machine.records();
        let record = store
            .get(&peer.peer_id())
            .ok_or("the record did not survive the restart")?;
        if !record.is_paired() || record.last_address() != Some(peer.addr()) {
            return Err(format!("after the restart the record reads {record:?}"));
        }
        let kept = record
            .attempt()
            .ok_or("the restart dropped the unfinished attempt")?;
        if kept.expires_at != attempt.expires_at || kept.lifetime != attempt.lifetime {
            return Err(format!(
                "the attempt reads {kept:?} after the restart, not {attempt:?}"
            ));
        }
        // The kept attempt still guards the peer, and its expiry still ends it.
        match store.begin_attempt(&peer.peer_id(), NOW.plus(Duration::from_secs(1))) {
            Err(RecordError::AttemptInProgress { .. }) => {}
            other => return Err(format!("the restart lost the attempt's guard: {other:?}")),
        }
        let later = attempt.expires_at.plus(Duration::from_secs(1));
        store
            .prune_expired(later)
            .map_err(|error| error.to_string())?;
        if store
            .get(&peer.peer_id())
            .and_then(|record| record.attempt())
            .is_some()
        {
            return Err("the attempt outlived the expiry the restart kept".to_owned());
        }
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// The ceremony
// ---------------------------------------------------------------------------

pub(crate) fn pairing_computes_one_string() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let left = sim.machine().map_err(io_error)?;
        let right = sim.machine().map_err(io_error)?;
        let left_store = left.records();
        let right_store = right.records();
        let left_shown = Shown::accepting();
        let right_shown = Shown::accepting();
        let (left_outcome, right_outcome) = pair_together(
            &sim,
            &beacon,
            Pairing {
                left: &left,
                right: &right,
                left_opens: Opening::Initiate(right.fingerprint()),
                right_opens: Opening::Respond,
                left_person: &left_shown,
                right_person: &right_shown,
                left_store: &left_store,
                right_store: &right_store,
            },
        )
        .await?;
        if !paired(&left_outcome) || !paired(&right_outcome) {
            return Err(format!(
                "the pair did not complete: {left_outcome:?} / {right_outcome:?}"
            ));
        }
        let left_seen = left_shown.seen();
        let right_seen = right_shown.seen();
        if left_seen.len() != 1 || right_seen.len() != 1 {
            return Err(format!(
                "the people were shown {left_seen:?} and {right_seen:?}, not one comparison each"
            ));
        }
        if left_seen != right_seen {
            return Err(format!(
                "the two machines computed different strings: {left_seen:?} and {right_seen:?}"
            ));
        }
        let string = &left_seen[0];
        if string.len() != COMPARISON_SYMBOLS
            || !string
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte))
        {
            return Err(format!("`{string}` is not six RFC 4648 base32 symbols"));
        }
        if !left_store.is_paired(&right.peer_id()) || !right_store.is_paired(&left.peer_id()) {
            return Err("both people confirmed but a side did not record the pair".to_owned());
        }
        // The outcome carries the peer's beacon-observed address, but the record
        // does not store it: only an authenticated connection does.
        if left_store
            .get(&right.peer_id())
            .and_then(|record| record.last_address())
            .is_some()
        {
            return Err("the pairing wrote an address no connection authenticated".to_owned());
        }
        match &left_outcome {
            Ok(Outcome::Paired { address, .. }) if *address == Some(right.addr()) => {}
            other => {
                return Err(format!(
                    "the initiator's outcome carries {other:?}, not the peer's address"
                ));
            }
        }
        Ok(())
    })
}

pub(crate) fn pairing_records_only_after_both_confirm() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let left = sim.machine().map_err(io_error)?;
        let right = sim.machine().map_err(io_error)?;
        let left_store = left.records();
        let right_store = right.records();
        let (left_outcome, right_outcome) = pair_together(
            &sim,
            &beacon,
            Pairing {
                left: &left,
                right: &right,
                left_opens: Opening::Initiate(right.fingerprint()),
                right_opens: Opening::Respond,
                left_person: &Shown::rejecting(),
                right_person: &Shown::accepting(),
                left_store: &left_store,
                right_store: &right_store,
            },
        )
        .await?;
        if !matches!(left_outcome, Ok(Outcome::Rejected { .. })) {
            return Err(format!("the rejecting side ended {left_outcome:?}"));
        }
        if !matches!(right_outcome, Ok(Outcome::PeerRejected { .. })) {
            return Err(format!("the confirming side ended {right_outcome:?}"));
        }
        if left_store.is_paired(&right.peer_id()) || right_store.is_paired(&left.peer_id()) {
            return Err("a one-sided rejection still recorded the pair".to_owned());
        }
        let left_record = left_store
            .get(&right.peer_id())
            .ok_or("the rejecting side kept no record")?;
        if left_record.failures() != 1 {
            return Err(format!(
                "the rejecting side counted {} failures, not one",
                left_record.failures()
            ));
        }
        let right_record = right_store.get(&left.peer_id());
        if right_record.as_ref().map_or(0, |record| record.failures()) != 0 {
            return Err(format!(
                "the confirming side counted failures: {right_record:?}"
            ));
        }
        Ok(())
    })
}

pub(crate) fn pairing_is_repeatable_until_both_hold() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let left = sim.machine().map_err(io_error)?;
        let right = sim.machine().map_err(io_error)?;
        let left_store = left.records();
        let right_store = right.records();
        let (first_left, first_right) = pair_together(
            &sim,
            &beacon,
            Pairing {
                left: &left,
                right: &right,
                left_opens: Opening::Initiate(right.fingerprint()),
                right_opens: Opening::Respond,
                left_person: &Shown::accepting(),
                right_person: &Shown::accepting(),
                left_store: &left_store,
                right_store: &right_store,
            },
        )
        .await?;
        if !paired(&first_left) || !paired(&first_right) {
            return Err("the first ceremony did not pair both sides".to_owned());
        }
        // One side loses its record, as a restored backup or a deleted file does.
        right
            .storage()
            .remove_record(&left.peer_id())
            .map_err(io_error)?;
        right_store.reload().map_err(|error| error.to_string())?;
        if right_store.is_paired(&left.peer_id()) {
            return Err("the removed record was still trusted".to_owned());
        }
        // The side that holds it keeps it and compares again; the other runs it.
        let left_shown = Shown::accepting();
        let right_shown = Shown::accepting();
        let (second_left, second_right) = pair_together(
            &sim,
            &beacon,
            Pairing {
                left: &left,
                right: &right,
                left_opens: Opening::Initiate(right.fingerprint()),
                right_opens: Opening::Respond,
                left_person: &left_shown,
                right_person: &right_shown,
                left_store: &left_store,
                right_store: &right_store,
            },
        )
        .await?;
        if !paired(&second_left) || !paired(&second_right) {
            return Err(format!(
                "the one-sided pair did not repair: {second_left:?} / {second_right:?}"
            ));
        }
        if left_shown.seen().len() != 1 || right_shown.seen().len() != 1 {
            return Err("the repair did not compare again on both sides".to_owned());
        }
        // Both hold it now: the ceremony answers "paired" and shows nothing.
        let left_shown = Shown::accepting();
        let right_shown = Shown::accepting();
        let (third_left, third_right) = pair_together(
            &sim,
            &beacon,
            Pairing {
                left: &left,
                right: &right,
                left_opens: Opening::Initiate(right.fingerprint()),
                right_opens: Opening::Respond,
                left_person: &left_shown,
                right_person: &right_shown,
                left_store: &left_store,
                right_store: &right_store,
            },
        )
        .await?;
        if !matches!(third_left, Ok(Outcome::AlreadyPaired { .. }))
            || !matches!(third_right, Ok(Outcome::AlreadyPaired { .. }))
        {
            return Err(format!(
                "a paired pair ran the ceremony again: {third_left:?} / {third_right:?}"
            ));
        }
        if !left_shown.seen().is_empty() || !right_shown.seen().is_empty() {
            return Err("a paired pair showed a comparison".to_owned());
        }
        Ok(())
    })
}

pub(crate) fn pairing_refuses_own_identity() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;
        let store = machine.records();
        let session = session(&beacon, &machine).await?;
        let outcome = within(
            &sim,
            BUDGET,
            pair::run(
                &session,
                &machine.identity,
                Opening::Initiate(machine.fingerprint()),
                &store,
                now,
                Shown::accepting().person(),
            ),
        )
        .await?
        .map_err(|error| error.to_string());
        if !matches!(outcome, Err(ref error) if error.contains("own identity")) {
            return Err(format!(
                "a peer with this machine's own key ended {outcome:?}"
            ));
        }
        if store.get(&machine.peer_id()).is_some() {
            return Err("the refused ceremony wrote a record".to_owned());
        }
        Ok(())
    })
}

pub(crate) fn pairing_closes_after_three_rejections() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let left = sim.machine().map_err(io_error)?;
        let right = sim.machine().map_err(io_error)?;
        let left_store = left.records();
        let right_store = right.records();
        for attempt in 1..=3 {
            let (left_outcome, _) = pair_together(
                &sim,
                &beacon,
                Pairing {
                    left: &left,
                    right: &right,
                    left_opens: Opening::Initiate(right.fingerprint()),
                    right_opens: Opening::Respond,
                    left_person: &Shown::rejecting(),
                    right_person: &Shown::accepting(),
                    left_store: &left_store,
                    right_store: &right_store,
                },
            )
            .await?;
            if !matches!(left_outcome, Ok(Outcome::Rejected { .. })) {
                return Err(format!("attempt {attempt} ended {left_outcome:?}"));
            }
        }
        if !left_store.is_closed(&right.peer_id()) {
            return Err("three rejections did not close the pair".to_owned());
        }
        // A restart does not clear it: a fresh open of the same root reads the
        // files, not the map this case wrote through.
        drop(left_store);
        let left_store = left.reopen_records()?;
        if !left_store.is_closed(&right.peer_id()) {
            return Err("a fresh open of the root cleared the closed pair".to_owned());
        }
        let left_session = session(&beacon, &left).await?;
        let refused = within(
            &sim,
            BUDGET,
            pair::run(
                &left_session,
                &left.identity,
                Opening::Initiate(right.fingerprint()),
                &left_store,
                now,
                Shown::accepting().person(),
            ),
        )
        .await?
        .map_err(|error| error.to_string());
        if !matches!(refused, Err(ref error) if error.contains("closed")) {
            return Err(format!("a closed pair started a ceremony: {refused:?}"));
        }
        // A connection attempt names the closure rather than the absence of a
        // record: "not trusted" is decided locally, and the cause is the closure.
        let endpoint = left.endpoint().map_err(|error| error.to_string())?;
        let manager = Connections::new(
            &left.identity,
            left_store.clone(),
            None,
            sim.clock().runtime(),
            &left.transport,
        )
        .map_err(|error| error.to_string())?;
        let refused = within(
            &sim,
            BUDGET,
            manager.connect(&endpoint, &right.fingerprint()),
        )
        .await?;
        match refused {
            Err(ConnectFailure::NotTrusted {
                cause: NotTrustedCause::Closed,
                ..
            }) => {}
            other => return Err(format!("a closed pair connected as {other:?}")),
        }
        // A person clears it on this machine, through the audited act.
        Rights::new(left_store.clone(), left.audit()?)
            .clear_attempt_lock(&right.peer_id(), person("egor")?, NOW)
            .map_err(|error| error.to_string())?;
        if left_store.is_closed(&right.peer_id()) {
            return Err("a person's clear did not reopen the pair".to_owned());
        }
        Ok(())
    })
}

pub(crate) fn pairing_attempt_expires() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;
        let peer = sim.machine().map_err(io_error)?;
        let store = machine.records();
        let limits = store.limits();
        let first = store
            .begin_attempt(&peer.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        if first.expires_at <= NOW || first.lifetime != limits.attempt_lifetime {
            return Err(format!("the attempt reads {first:?}"));
        }
        match store.begin_attempt(&peer.peer_id(), NOW.plus(Duration::from_secs(1))) {
            Err(RecordError::AttemptInProgress { .. }) => {}
            other => return Err(format!("a live attempt was not refused: {other:?}")),
        }
        // Past its lifetime it stops being one, without a person doing anything.
        let later = NOW
            .plus(limits.attempt_lifetime)
            .plus(Duration::from_secs(1));
        if store.begin_attempt(&peer.peer_id(), later).is_err() {
            return Err("an expired attempt still blocked a new one".to_owned());
        }
        Ok(())
    })
}

pub(crate) fn pairing_payload_never_carries_the_string() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let left = sim.machine().map_err(io_error)?;
        let right = sim.machine().map_err(io_error)?;
        let mut sent = Vec::new();
        let (mut left_ceremony, first) = Ceremony::initiate(
            left.peer_id(),
            right.fingerprint(),
            Some(left.addr()),
            false,
        )
        .map_err(|error| error.to_string())?;
        sent.push(first.clone());
        let opening = introduce(&left, &right, first)?;
        let (mut right_ceremony, step) =
            Ceremony::respond(right.peer_id(), &opening, Some(right.addr()), false)
                .map_err(|error| error.to_string())?;
        // Flight 2: the responder's commitment and fresh value.
        let second = step.send.ok_or("the responder sent nothing")?;
        sent.push(second.clone());
        let to_left = introduce(&right, &left, second)?;
        let left_step = left_ceremony
            .receive(to_left.payload())
            .map_err(|error| error.to_string())?;
        // Flight 3: the initiator's fresh value.
        let third = left_step.send.ok_or("the initiator sent no fresh value")?;
        sent.push(third.clone());
        let to_right = introduce(&left, &right, third)?;
        let right_step = right_ceremony
            .receive(to_right.payload())
            .map_err(|error| error.to_string())?;
        let left_comparison = left_step.show.ok_or("the initiator showed no comparison")?;
        let right_comparison = right_step
            .show
            .ok_or("the responder showed no comparison")?;
        if left_comparison != right_comparison {
            return Err("the two sides showed different comparisons".to_owned());
        }
        // Flight 4 and 5: both confirmations.
        let fourth = left_ceremony
            .confirm(true)
            .map_err(|error| error.to_string())?
            .send
            .ok_or("the initiator sent no confirmation")?;
        sent.push(fourth.clone());
        right_ceremony
            .receive(introduce(&left, &right, fourth)?.payload())
            .map_err(|error| error.to_string())?;
        let fifth = right_ceremony
            .confirm(true)
            .map_err(|error| error.to_string())?
            .send
            .ok_or("the responder sent no confirmation")?;
        sent.push(fifth.clone());
        left_ceremony
            .receive(introduce(&right, &left, fifth)?.payload())
            .map_err(|error| error.to_string())?;
        if !left_ceremony.finished() || !right_ceremony.finished() {
            return Err("a side did not finish after both confirmations".to_owned());
        }
        for bytes in &sent {
            // Each flight was parsed by the side that received it — the ceremony
            // calls above fail if one does not parse — so what is left is the bytes.
            if bytes
                .windows(left_comparison.as_bytes().len())
                .any(|window| window == left_comparison.as_bytes())
            {
                return Err("a ceremony payload carries the comparison".to_owned());
            }
        }
        Ok(())
    })
}

/// Drive two ceremonies to the comparison, with fresh values, without recording
/// anything.
fn drive_to_confirmation(
    left: &Machine,
    right: &Machine,
    left_already: bool,
    right_already: bool,
) -> Result<(Ceremony, Ceremony), String> {
    let (mut left_ceremony, first) = Ceremony::initiate(
        left.peer_id(),
        right.fingerprint(),
        Some(left.addr()),
        left_already,
    )
    .map_err(|error| error.to_string())?;
    let opening = introduce(left, right, first)?;
    let (mut right_ceremony, step) =
        Ceremony::respond(right.peer_id(), &opening, Some(right.addr()), right_already)
            .map_err(|error| error.to_string())?;
    let answer = step.send.ok_or("the responder sent nothing")?;
    let to_left = introduce(right, left, answer)?;
    let left_step = left_ceremony
        .receive(to_left.payload())
        .map_err(|error| error.to_string())?;
    let reveal = left_step.send.ok_or("the initiator sent no fresh value")?;
    let to_right = introduce(left, right, reveal)?;
    let right_step = right_ceremony
        .receive(to_right.payload())
        .map_err(|error| error.to_string())?;
    if left_step.show.is_none() || right_step.show.is_none() {
        return Err("a side showed no comparison".to_owned());
    }
    Ok((left_ceremony, right_ceremony))
}

/// The "already paired" flight both sides holding the pair produces.
fn paired_flight(left: &Machine, right: &Machine) -> Result<Vec<u8>, String> {
    let (_, first) =
        Ceremony::initiate(left.peer_id(), right.fingerprint(), Some(left.addr()), true)
            .map_err(|error| error.to_string())?;
    let opening = introduce(left, right, first)?;
    let (_, step) = Ceremony::respond(right.peer_id(), &opening, Some(right.addr()), true)
        .map_err(|error| error.to_string())?;
    step.send
        .ok_or("the responder sent no paired flight".to_owned())
}

pub(crate) fn pairing_rejects_a_replayed_flight() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let left = sim.machine().map_err(io_error)?;
        let right = sim.machine().map_err(io_error)?;
        // Attempt one: both confirm, and its two confirmation payloads are kept.
        let (mut first_left, mut first_right) = drive_to_confirmation(&left, &right, false, false)?;
        let first_left_confirm = first_left
            .confirm(true)
            .map_err(|error| error.to_string())?
            .send
            .ok_or("the initiator sent no confirmation")?;
        let first_right_confirm = first_right
            .confirm(true)
            .map_err(|error| error.to_string())?
            .send
            .ok_or("the responder sent no confirmation")?;
        first_right
            .receive(&first_left_confirm)
            .map_err(|error| error.to_string())?;
        first_left
            .receive(&first_right_confirm)
            .map_err(|error| error.to_string())?;
        // Attempt two has fresh values: the old flights cannot match its transcript.
        let (mut second_left, mut second_right) =
            drive_to_confirmation(&left, &right, false, false)?;
        match second_left.receive(&first_right_confirm) {
            Err(mahbot_peers::peer::PairError::BindingMismatch) => {}
            other => {
                return Err(format!(
                    "a replayed confirmation was accepted by the initiator: {other:?}"
                ));
            }
        }
        match second_right.receive(&first_left_confirm) {
            Err(mahbot_peers::peer::PairError::BindingMismatch) => {}
            other => {
                return Err(format!(
                    "a replayed confirmation was accepted by the responder: {other:?}"
                ));
            }
        }
        // A replayed "already paired" flight is bound to the old commitment too.
        let old_paired = paired_flight(&left, &right)?;
        let (mut third_left, _) =
            Ceremony::initiate(left.peer_id(), right.fingerprint(), Some(left.addr()), true)
                .map_err(|error| error.to_string())?;
        match third_left.receive(&old_paired) {
            Err(mahbot_peers::peer::PairError::BindingMismatch) => {}
            other => {
                return Err(format!(
                    "a replayed already-paired flight was accepted: {other:?}"
                ));
            }
        }
        // A machine that holds no record does not accept "already paired" at all: the
        // claim contradicts its own state, and it is refused before any binding is
        // considered.
        let (mut fresh_left, _) = Ceremony::initiate(
            left.peer_id(),
            right.fingerprint(),
            Some(left.addr()),
            false,
        )
        .map_err(|error| error.to_string())?;
        match fresh_left.receive(&old_paired) {
            Err(mahbot_peers::peer::PairError::NotPaired) => {}
            other => {
                return Err(format!(
                    "a machine holding no record accepted an already-paired claim: {other:?}"
                ));
            }
        }
        Ok(())
    })
}

pub(crate) fn pairing_mediator_yields_different_strings() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let left = sim.machine().map_err(io_error)?;
        let right = sim.machine().map_err(io_error)?;
        let left_store = left.records();
        let right_store = right.records();
        let mediator = Mediator::new(&sim, &beacon).await?;
        // A mediator that shared a machine's key would not make the two transcripts
        // differ: it is a party with its own identity and its own registration.
        if mediator.fingerprint() == left.fingerprint()
            || mediator.fingerprint() == right.fingerprint()
        {
            return Err("the mediator shares a machine's identity".to_owned());
        }
        let watcher_session = session(&beacon, &left).await?;
        if watcher_session
            .lookup(&mediator.peer_id())
            .await
            .map_err(|error| error.to_string())?
            .is_none()
        {
            return Err("the mediator is not registered at the beacon".to_owned());
        }
        let left_session = session(&beacon, &left).await?;
        let right_session = session(&beacon, &right).await?;
        let left_shown = Shown::rejecting();
        let right_shown = Shown::rejecting();
        let (left_outcome, right_outcome, interposed) =
            within(&sim, Duration::from_secs(90), async {
                tokio::join!(
                    pair::run(
                        &left_session,
                        &left.identity,
                        Opening::Initiate(mediator.fingerprint()),
                        &left_store,
                        now,
                        left_shown.person(),
                    ),
                    pair::run(
                        &right_session,
                        &right.identity,
                        Opening::Respond,
                        &right_store,
                        now,
                        right_shown.person(),
                    ),
                    mediator.interpose(left.peer_id(), right.peer_id()),
                )
            })
            .await?;
        let interposed = interposed?;
        let left_string = interposed
            .left
            .ok_or("the mediator showed the left machine no comparison")?;
        let right_string = interposed
            .right
            .ok_or("the mediator showed the right machine no comparison")?;
        if left_string == right_string {
            return Err(format!(
                "a mediator produced the same string on both sides: {left_string}"
            ));
        }
        if !matches!(left_outcome, Ok(Outcome::Rejected { .. }))
            || !matches!(right_outcome, Ok(Outcome::Rejected { .. }))
        {
            return Err(format!(
                "a person who saw different strings still confirmed: \
                 {left_outcome:?} / {right_outcome:?}"
            ));
        }
        // The two people saw exactly the strings the mediator's two transcripts
        // produced, and those differ.
        let left_human = left_shown.seen();
        let right_human = right_shown.seen();
        if left_human != [left_string.to_string()] || right_human != [right_string.to_string()] {
            return Err(format!(
                "the people saw {left_human:?} and {right_human:?}, \
                 not the mediator's {left_string} and {right_string}"
            ));
        }
        if !matches!(interposed.left_outcome, Outcome::PeerRejected { .. })
            || !matches!(interposed.right_outcome, Outcome::PeerRejected { .. })
        {
            return Err(format!(
                "the mediator did not see both rejections: {:?} / {:?}",
                interposed.left_outcome, interposed.right_outcome
            ));
        }
        if left_store.is_paired(&right.peer_id()) || right_store.is_paired(&left.peer_id()) {
            return Err("a mediated pair was recorded".to_owned());
        }
        if left_store.is_paired(&mediator.peer_id()) || right_store.is_paired(&mediator.peer_id()) {
            return Err("a machine recorded a pair with the mediator".to_owned());
        }
        Ok(())
    })
}

pub(crate) fn pairing_simultaneous_start_keeps_one() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let left = sim.machine().map_err(io_error)?;
        let right = sim.machine().map_err(io_error)?;
        let left_store = left.records();
        let right_store = right.records();
        let left_shown = Shown::accepting();
        let right_shown = Shown::accepting();
        let (left_outcome, right_outcome) = pair_together(
            &sim,
            &beacon,
            Pairing {
                left: &left,
                right: &right,
                left_opens: Opening::Initiate(right.fingerprint()),
                right_opens: Opening::Initiate(left.fingerprint()),
                left_person: &left_shown,
                right_person: &right_shown,
                left_store: &left_store,
                right_store: &right_store,
            },
        )
        .await?;
        if !paired(&left_outcome) || !paired(&right_outcome) {
            return Err(format!(
                "both starting at once left the pair unpaired: {left_outcome:?} / {right_outcome:?}"
            ));
        }
        let left_seen = left_shown.seen();
        let right_seen = right_shown.seen();
        if left_seen.len() != 1 || right_seen.len() != 1 {
            return Err(format!(
                "the people saw {left_seen:?} and {right_seen:?}, not one comparison each"
            ));
        }
        if left_seen != right_seen {
            return Err("the surviving attempt computed different strings".to_owned());
        }
        if !left_store.is_paired(&right.peer_id()) || !right_store.is_paired(&left.peer_id()) {
            return Err("both people confirmed but a side did not record the pair".to_owned());
        }
        // The smaller fingerprint's attempt is the one that survived: it played
        // the initiator, the larger one yielded and answered.
        let (left_role, right_role) = match (&left_outcome, &right_outcome) {
            (Ok(Outcome::Paired { role: left, .. }), Ok(Outcome::Paired { role: right, .. })) => {
                (*left, *right)
            }
            _ => return Err("a side did not report the role it played".to_owned()),
        };
        let (smaller, larger) = if left.peer_id() < right.peer_id() {
            (left_role, right_role)
        } else {
            (right_role, left_role)
        };
        if smaller != mahbot_peers::peer::Role::Initiator
            || larger != mahbot_peers::peer::Role::Responder
        {
            return Err(format!(
                "the smaller fingerprint did not win: smaller {smaller:?}, larger {larger:?}"
            ));
        }
        if left_store
            .get(&right.peer_id())
            .map(|record| record.failures())
            != Some(0)
            || right_store
                .get(&left.peer_id())
                .map(|record| record.failures())
                != Some(0)
        {
            return Err("the dropped attempt counted against somebody".to_owned());
        }
        Ok(())
    })
}

pub(crate) fn pairing_ignores_a_foreign_opening() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let first = sim.machine().map_err(io_error)?;
        let second = sim.machine().map_err(io_error)?;
        // The larger machine is the one a simultaneous start makes yield, so a
        // foreign opening flight aimed at it is what could hijack the ceremony.
        let (left, right) = if first.peer_id() > second.peer_id() {
            (first, second)
        } else {
            (second, first)
        };
        let third = sim.machine().map_err(io_error)?;
        let left_store = left.records();
        let right_store = right.records();
        let left_shown = Shown::accepting();
        let right_shown = Shown::accepting();
        let left_session = session(&beacon, &left).await?;
        let right_session = session(&beacon, &right).await?;
        let third_session = session(&beacon, &third).await?;
        // A third machine's own opening flight, addressed to the larger machine —
        // the one a simultaneous start makes yield — and delivered before either
        // real ceremony starts reading: it is the first thing the larger machine
        // sees while it waits for its reply.
        let (_, commit) = Ceremony::initiate(third.peer_id(), left.fingerprint(), None, false)
            .map_err(|error| error.to_string())?;
        within(
            &sim,
            BUDGET,
            third_session.introduce(left.peer_id(), &commit),
        )
        .await?
        .map_err(|error| error.to_string())?;
        let (left_outcome, right_outcome) = within(&sim, Duration::from_secs(90), async {
            tokio::join!(
                pair::run(
                    &left_session,
                    &left.identity,
                    Opening::Initiate(right.fingerprint()),
                    &left_store,
                    now,
                    left_shown.person(),
                ),
                pair::run(
                    &right_session,
                    &right.identity,
                    Opening::Initiate(left.fingerprint()),
                    &right_store,
                    now,
                    right_shown.person(),
                ),
            )
        })
        .await?;
        let left_outcome = left_outcome.map_err(|error| error.to_string());
        let right_outcome = right_outcome.map_err(|error| error.to_string());
        if !paired(&left_outcome) || !paired(&right_outcome) {
            return Err(format!(
                "a third machine's opening flight ended the pair: \
                 {left_outcome:?} / {right_outcome:?}"
            ));
        }
        if left_shown.seen().len() != 1 || right_shown.seen().len() != 1 {
            return Err("a foreign opening flight cost the pair a comparison".to_owned());
        }
        if left_store.get(&third.peer_id()).is_some() {
            return Err("a foreign opening flight was booked against its sender".to_owned());
        }
        if !left_store.is_paired(&right.peer_id()) || !right_store.is_paired(&left.peer_id()) {
            return Err("the pair was not recorded after the intrusion".to_owned());
        }
        Ok(())
    })
}

pub(crate) fn pairing_respond_ignores_a_foreign_payload() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let left = sim.machine().map_err(io_error)?;
        let right = sim.machine().map_err(io_error)?;
        let third = sim.machine().map_err(io_error)?;
        let left_store = left.records();
        let right_store = right.records();
        let left_shown = Shown::accepting();
        let right_shown = Shown::accepting();
        let left_session = session(&beacon, &left).await?;
        let right_session = session(&beacon, &right).await?;
        let third_session = session(&beacon, &third).await?;
        // A malformed payload, then a well-formed flight that does not open a
        // ceremony: neither may end a machine's wait for a real initiator.
        third_session
            .introduce(left.peer_id(), b"not a ceremony message")
            .await
            .map_err(|error| error.to_string())?;
        let already_paired = paired_flight(&third, &left)?;
        third_session
            .introduce(left.peer_id(), &already_paired)
            .await
            .map_err(|error| error.to_string())?;
        let (left_outcome, right_outcome) = within(&sim, Duration::from_secs(90), async {
            tokio::join!(
                pair::run(
                    &left_session,
                    &left.identity,
                    Opening::Respond,
                    &left_store,
                    now,
                    left_shown.person(),
                ),
                pair::run(
                    &right_session,
                    &right.identity,
                    Opening::Initiate(left.fingerprint()),
                    &right_store,
                    now,
                    right_shown.person(),
                ),
            )
        })
        .await?;
        let left_outcome = left_outcome.map_err(|error| error.to_string());
        let right_outcome = right_outcome.map_err(|error| error.to_string());
        if !paired(&left_outcome) || !paired(&right_outcome) {
            return Err(format!(
                "a stranger's payload ended the responder's wait: {left_outcome:?} / {right_outcome:?}"
            ));
        }
        if left_shown.seen().len() != 1 || right_shown.seen().len() != 1 {
            return Err("the stranger's payload cost the pair a comparison".to_owned());
        }
        if left_store.get(&third.peer_id()).is_some() {
            return Err("the stranger's payload was booked against it".to_owned());
        }
        drop(third_session);
        Ok(())
    })
}

pub(crate) fn pairing_respond_waits_for_its_peer() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let left = sim.machine().map_err(io_error)?;
        let right = sim.machine().map_err(io_error)?;
        let left_store = left.records();
        let right_store = right.records();
        let left_shown = Shown::accepting();
        let right_shown = Shown::accepting();
        let left_session = session(&beacon, &left).await?;
        let right_session = session(&beacon, &right).await?;
        let (left_outcome, right_outcome) = within(&sim, Duration::from_secs(120), async {
            let responder = pair::run(
                &left_session,
                &left.identity,
                Opening::Respond,
                &left_store,
                now,
                left_shown.person(),
            );
            let initiator = async {
                // Longer than the beacon's request bound (15 s) and inside the
                // session's idle timeout: a machine waiting to be paired is the
                // caller's wait, not a failed request.
                sim.clock().advance(Duration::from_secs(30)).await;
                tokio::task::yield_now().await;
                pair::run(
                    &right_session,
                    &right.identity,
                    Opening::Initiate(left.fingerprint()),
                    &right_store,
                    now,
                    right_shown.person(),
                )
                .await
            };
            tokio::join!(responder, initiator)
        })
        .await?;
        let left_outcome = left_outcome.map_err(|error| error.to_string());
        let right_outcome = right_outcome.map_err(|error| error.to_string());
        if !paired(&left_outcome) || !paired(&right_outcome) {
            return Err(format!(
                "a responder that waited half a minute gave up: {left_outcome:?} / {right_outcome:?}"
            ));
        }
        if left_shown.seen() != right_shown.seen() {
            return Err("the delayed ceremony computed different strings".to_owned());
        }
        Ok(())
    })
}

pub(crate) fn pairing_failure_leaves_no_attempt() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let dead = TestBeacon::start(&sim).map_err(io_error)?;
        let live = TestBeacon::start(&sim).map_err(io_error)?;
        let left = sim.machine().map_err(io_error)?;
        let right = sim.machine().map_err(io_error)?;
        let left_store = left.records();
        let right_store = right.records();
        // A session to a beacon that then stops answering.
        let dead_session = session(&dead, &left).await?;
        dead.stop();
        let failed = within(
            &sim,
            Duration::from_secs(60),
            pair::run(
                &dead_session,
                &left.identity,
                Opening::Initiate(right.fingerprint()),
                &left_store,
                now,
                Shown::accepting().person(),
            ),
        )
        .await?
        .map_err(|error| error.to_string());
        if !matches!(failed, Err(ref error) if error.contains("beacon")) {
            return Err(format!("a dead beacon ended {failed:?}"));
        }
        // No unfinished attempt survives, so nothing blocks the retry the person
        // makes as soon as the beacon is back. A record with no attempt and no
        // pairing is not an attempt.
        if left_store
            .get(&right.peer_id())
            .is_some_and(|record| record.attempt().is_some())
        {
            return Err("a failure before the first flight left an attempt behind".to_owned());
        }
        let (left_outcome, right_outcome) = pair_together(
            &sim,
            &live,
            Pairing {
                left: &left,
                right: &right,
                left_opens: Opening::Initiate(right.fingerprint()),
                right_opens: Opening::Respond,
                left_person: &Shown::accepting(),
                right_person: &Shown::accepting(),
                left_store: &left_store,
                right_store: &right_store,
            },
        )
        .await?;
        if !paired(&left_outcome) || !paired(&right_outcome) {
            return Err(format!(
                "the retry after a beacon failure was blocked: {left_outcome:?} / {right_outcome:?}"
            ));
        }
        Ok(())
    })
}

/// A peer that is reachable and silent is a flight timeout, not a beacon outage.
pub(crate) fn pairing_flight_timeout_is_not_a_beacon_outage() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let left = sim.machine().map_err(io_error)?;
        let right = sim.machine().map_err(io_error)?;
        let left_store = left.records();
        let left_session = session(&beacon, &left).await?;
        // The peer is registered and reachable, and never runs a ceremony.
        let _right_session = session(&beacon, &right).await?;
        let failed = within(
            &sim,
            Duration::from_secs(120),
            pair::run(
                &left_session,
                &left.identity,
                Opening::Initiate(right.fingerprint()),
                &left_store,
                now,
                Shown::accepting().person(),
            ),
        )
        .await?
        .map_err(|error| error.to_string());
        match &failed {
            Err(error) if error.contains("did not answer") && !error.contains("beacon") => {}
            other => return Err(format!("a silent peer ended {other:?}")),
        }
        // The attempt ended without a comparison: it counts against nobody and does
        // not block a retry.
        if left_store
            .get(&right.peer_id())
            .is_some_and(|record| record.attempt().is_some())
        {
            return Err("a flight timeout left an unfinished attempt".to_owned());
        }
        Ok(())
    })
}

/// Answer a waiting ceremony by hand up to the comparison, and hand the ceremony
/// back.
///
/// The responder takes the opening flight, answers it, takes the initiator's fresh
/// value, and checks it was shown a comparison. A case that drives one side by hand
/// uses this; `drive_to_confirmation` is the same with both sides driven.
async fn answer_to_confirmation(session: &Session, machine: &Machine) -> Result<Ceremony, String> {
    let opening = session
        .next_introduction()
        .await
        .map_err(|error| error.to_string())?;
    let (mut ceremony, step) =
        Ceremony::respond(machine.peer_id(), &opening, Some(machine.addr()), false)
            .map_err(|error| error.to_string())?;
    let answer = step.send.ok_or("the responder sent no answer")?;
    session
        .introduce(opening.from(), &answer)
        .await
        .map_err(|error| error.to_string())?;
    let reveal = session
        .next_introduction()
        .await
        .map_err(|error| error.to_string())?;
    let step = ceremony
        .receive(reveal.payload())
        .map_err(|error| error.to_string())?;
    if step.show.is_none() {
        return Err("the responder was shown no comparison".to_owned());
    }
    Ok(ceremony)
}

/// A comparison nobody answered is the attempt expiring, not a beacon outage.
pub(crate) fn pairing_attempt_expiry_is_its_own_failure() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let left = sim.machine().map_err(io_error)?;
        let right = sim.machine().map_err(io_error)?;
        // A stated short lifetime, recorded with the attempt: the wait this case
        // proves does not have to be the default fifteen minutes of virtual time.
        let left_store = left.records_with(Limits {
            attempt_lifetime: Duration::from_secs(2),
            ..Limits::default()
        })?;
        let left_session = session(&beacon, &left).await?;
        let right_session = session(&beacon, &right).await?;
        // The responder is driven by hand to the comparison and never confirms: the
        // initiator's wait for that confirmation is the attempt's lifetime.
        let responder = async {
            answer_to_confirmation(&right_session, &right).await?;
            Ok::<(), String>(())
        };
        let shown = Shown::accepting();
        // The attempt's deadline is the caller's moment, so this case supplies the
        // virtual clock's reading: a constant `now` would keep "what is left" at the
        // full lifetime for ever, which is the caller's bug, not the ceremony's.
        let clock = sim.clock().clone();
        let now = move || NOW.plus(clock.elapsed());
        let (failed, responder) = within(&sim, Duration::from_secs(120), async {
            tokio::join!(
                pair::run(
                    &left_session,
                    &left.identity,
                    Opening::Initiate(right.fingerprint()),
                    &left_store,
                    &now,
                    shown.person(),
                ),
                responder,
            )
        })
        .await?;
        responder?;
        let failed = failed.map_err(|error| error.to_string());
        match &failed {
            Err(error) if error.contains("expired") && !error.contains("beacon") => {}
            other => return Err(format!("an unanswered comparison ended {other:?}")),
        }
        if left_store
            .get(&right.peer_id())
            .is_some_and(|record| record.attempt().is_some())
        {
            return Err("an expired attempt stayed recorded".to_owned());
        }
        Ok(())
    })
}

/// A right that says it ended and names no term is not a row this build can read: the
/// decision's moment is the term's end, so the shape is refused where it is decoded
/// rather than left to be answered from a row that has no moment to name.
pub(crate) fn an_ending_without_a_term_is_not_a_record() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;
        let peer = sim.machine().map_err(io_error)?;
        // `[capability][label][term][issuer][withdrawn][ended]`, with the term absent and
        // the ending present: a shape this build never writes.
        let mut body = vec![1u8];
        body.extend_from_slice(&5u16.to_be_bytes());
        body.extend_from_slice(b"admin");
        body.push(0);
        body.push(1);
        body.push(0);
        body.push(1);
        body.extend_from_slice(&NOW.unix_seconds().to_be_bytes());
        let mut record = b"mahbot-peer-record".to_vec();
        record.push(1);
        record.extend_from_slice(&[0x01, 0x00, 0x20]);
        record.extend_from_slice(peer.peer_id().as_bytes());
        record.push(0x0a);
        record.extend_from_slice(
            &u16::try_from(body.len())
                .map_err(|_| "the right is too long to frame".to_owned())?
                .to_be_bytes(),
        );
        record.extend_from_slice(&body);
        let storage = machine.storage();
        storage
            .write_record(&peer.peer_id(), &record)
            .map_err(io_error)?;
        match storage.records_typed() {
            Err(RecordError::Malformed {
                reason: Malformed::Field { tag: 0x0a, detail },
                ..
            }) => {
                if !detail.contains("no term") {
                    return Err(format!("the refusal reads `{detail}`, not a missing term"));
                }
                Ok(())
            }
            Err(error) => Err(format!(
                "the ending without a term was refused as `{error}`"
            )),
            Ok(_) => Err("a right that ended without a term was read as a record".to_owned()),
        }
    })
}

/// A write that would cross the record's size cap is refused before it lands.
pub(crate) fn peer_record_refuses_an_oversized_write() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;
        let peer = sim.machine().map_err(io_error)?;
        let store = machine.records();
        store
            .record_pairing(&peer.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        // Pad the record with an unknown field to just under the cap, as a newer
        // build could: the address field this build adds would cross it.
        let mut bytes = machine
            .storage()
            .read_record(&peer.peer_id())
            .map_err(io_error)?;
        let cap = usize::try_from(mahbot_peers::peer::record::MAX_RECORD_BYTES)
            .expect("the cap fits usize");
        let pad = cap
            .saturating_sub(6)
            .checked_sub(bytes.len() + 3)
            .ok_or("the base record is already near the cap")?;
        bytes.push(0x7f);
        bytes.extend_from_slice(&u16::try_from(pad).expect("a small pad").to_be_bytes());
        bytes.resize(bytes.len() + pad, 0xaa);
        machine
            .storage()
            .write_record(&peer.peer_id(), &bytes)
            .map_err(io_error)?;
        let store = machine.reopen_records()?;
        let before = machine
            .storage()
            .read_record(&peer.peer_id())
            .map_err(io_error)?;
        match store.record_address(
            &peer.peer_id(),
            std::net::SocketAddr::from(([10, 0, 0, 1], 1)),
        ) {
            Err(RecordError::TooLarge { .. }) => {}
            other => return Err(format!("an oversized write reads {other:?}")),
        }
        if machine
            .storage()
            .read_record(&peer.peer_id())
            .map_err(io_error)?
            != before
        {
            return Err("a refused write changed the file".to_owned());
        }
        // The file is still a record this build opens.
        if machine.reopen_records()?.get(&peer.peer_id()).is_none() {
            return Err("the refused write left the record unreadable".to_owned());
        }
        Ok(())
    })
}

/// A `peers/` that is a symbolic link is refused, as a linked key file is.
#[cfg(unix)]
pub(crate) fn peer_record_refuses_a_symlinked_directory() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;
        let peer = sim.machine().map_err(io_error)?;
        let store = machine.records();
        store
            .record_pairing(&peer.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        machine
            .storage()
            .replace_records_dir_with_a_link()
            .map_err(io_error)?;
        match machine.reopen_records() {
            Err(error) if error.contains("symbolic link") => Ok(()),
            Err(error) => Err(format!("the symlinked directory reads `{error}`")),
            Ok(_) => Err("a symlinked record directory was accepted".to_owned()),
        }
    })
}

/// An attempt that ends on a record that says nothing removes the record.
pub(crate) fn peer_record_drops_an_empty_attempt() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;
        let stranger = sim.machine().map_err(io_error)?;
        let store = machine.records();
        let exists = || {
            machine
                .storage()
                .record_exists(&stranger.peer_id())
                .map_err(io_error)
        };
        store
            .begin_attempt(&stranger.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        if !exists()? {
            return Err("an attempt on an unknown peer wrote no record".to_owned());
        }
        store
            .end_attempt(&stranger.peer_id())
            .map_err(|error| error.to_string())?;
        if store.get(&stranger.peer_id()).is_some() || exists()? {
            return Err("an attempt that ended left an empty record behind".to_owned());
        }
        // A person's clear on a peer this machine remembers nothing about is refused
        // and creates nothing either.
        let rights = Rights::new(store.clone(), machine.audit()?);
        match rights.clear_attempt_lock(&stranger.peer_id(), person("egor")?, NOW) {
            Err(mahbot_peers::peer::RightsError::NotPaired { peer })
                if peer == stranger.peer_id() => {}
            other => return Err(format!("a clear on an unknown peer reads {other:?}")),
        }
        if store.get(&stranger.peer_id()).is_some() || exists()? {
            return Err("a clear fabricated a record".to_owned());
        }
        // A rejected peer whose only facts were the failures and the attempt is
        // removed by the clear, not published as an empty record.
        store
            .record_failure(&stranger.peer_id())
            .map_err(|error| error.to_string())?;
        store
            .begin_attempt(&stranger.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        rights
            .clear_attempt_lock(&stranger.peer_id(), person("egor")?, NOW)
            .map_err(|error| error.to_string())?;
        if store.get(&stranger.peer_id()).is_some() || exists()? {
            return Err("a clear published an empty record".to_owned());
        }
        // A record with something worth keeping is not removed.
        store
            .record_pairing(&stranger.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        store
            .begin_attempt(&stranger.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        store
            .end_attempt(&stranger.peer_id())
            .map_err(|error| error.to_string())?;
        if !store.is_paired(&stranger.peer_id()) || !exists()? {
            return Err("ending an attempt removed a pairing".to_owned());
        }
        Ok(())
    })
}

/// A link that delivers the loser's opening flight after the winner revealed does
/// not cost the pair its one comparison.
pub(crate) fn pairing_tolerates_a_reordered_opening() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let first = sim.machine().map_err(io_error)?;
        let second = sim.machine().map_err(io_error)?;
        let (left, right) = if first.peer_id() < second.peer_id() {
            (first, second)
        } else {
            (second, first)
        };
        let (mut left_ceremony, left_commit) = Ceremony::initiate(
            left.peer_id(),
            right.fingerprint(),
            Some(left.addr()),
            false,
        )
        .map_err(|error| error.to_string())?;
        let (_, right_commit) = Ceremony::initiate(
            right.peer_id(),
            left.fingerprint(),
            Some(right.addr()),
            false,
        )
        .map_err(|error| error.to_string())?;
        // The larger machine yields to the smaller one's opening flight.
        let opening = introduce(&left, &right, left_commit)?;
        let (mut right_ceremony, step) =
            Ceremony::respond(right.peer_id(), &opening, Some(right.addr()), false)
                .map_err(|error| error.to_string())?;
        let answer = step.send.ok_or("the responder sent nothing")?;
        let to_left = introduce(&right, &left, answer)?;
        let left_step = left_ceremony
            .receive(to_left.payload())
            .map_err(|error| error.to_string())?;
        let comparison = left_step.show.ok_or("the winner showed no comparison")?;
        // The loser's own opening flight arrives late, after the winner revealed.
        let stale = introduce(&right, &left, right_commit)?;
        let step = left_ceremony
            .receive(stale.payload())
            .map_err(|error| error.to_string())?;
        if step.send.is_some() || step.show.is_some() || step.outcome.is_some() {
            return Err("a reordered opening flight changed the ceremony".to_owned());
        }
        // The ceremony still completes, with that one comparison.
        let reveal = left_step.send.ok_or("the winner sent no fresh value")?;
        let to_right = introduce(&left, &right, reveal)?;
        let right_step = right_ceremony
            .receive(to_right.payload())
            .map_err(|error| error.to_string())?;
        if right_step.show != Some(comparison) {
            return Err("the two sides showed different comparisons".to_owned());
        }
        let left_confirm = left_ceremony
            .confirm(true)
            .map_err(|error| error.to_string())?
            .send
            .ok_or("the winner sent no confirmation")?;
        right_ceremony
            .receive(introduce(&left, &right, left_confirm)?.payload())
            .map_err(|error| error.to_string())?;
        let right_confirm = right_ceremony
            .confirm(true)
            .map_err(|error| error.to_string())?
            .send
            .ok_or("the responder sent no confirmation")?;
        let step = left_ceremony
            .receive(introduce(&right, &left, right_confirm)?.payload())
            .map_err(|error| error.to_string())?;
        if !matches!(step.outcome, Some(Outcome::Paired { .. })) {
            return Err(format!("the reordered ceremony ended {:?}", step.outcome));
        }
        Ok(())
    })
}

/// A person who never answers the comparison expires the attempt instead of
/// parking the ceremony for ever.
pub(crate) fn pairing_abandoned_comparison_expires() -> Result<(), String> {
    struct NeverAnswers;

    impl mahbot_peers::peer::Person for NeverAnswers {
        fn ask(
            &mut self,
            _: mahbot_peers::peer::Comparison,
        ) -> impl std::future::Future<Output = bool> + Send {
            std::future::pending()
        }
    }

    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let left = sim.machine().map_err(io_error)?;
        let right = sim.machine().map_err(io_error)?;
        let left_store = left.records_with(Limits {
            attempt_lifetime: Duration::from_secs(2),
            ..Limits::default()
        })?;
        let left_session = session(&beacon, &left).await?;
        let right_session = session(&beacon, &right).await?;
        // The responder is driven by hand to the comparison; the initiator's person
        // is never answered.
        let responder = async {
            answer_to_confirmation(&right_session, &right).await?;
            Ok::<(), String>(())
        };
        let clock = sim.clock().clone();
        let now = move || NOW.plus(clock.elapsed());
        let (failed, responder) = within(&sim, Duration::from_secs(120), async {
            tokio::join!(
                pair::run(
                    &left_session,
                    &left.identity,
                    Opening::Initiate(right.fingerprint()),
                    &left_store,
                    &now,
                    NeverAnswers,
                ),
                responder,
            )
        })
        .await?;
        responder?;
        let failed = failed.map_err(|error| error.to_string());
        match &failed {
            Err(error) if error.contains("expired") && !error.contains("beacon") => {}
            other => return Err(format!("an abandoned comparison ended {other:?}")),
        }
        if left_store
            .get(&right.peer_id())
            .is_some_and(|record| record.attempt().is_some())
        {
            return Err("an abandoned attempt stayed recorded".to_owned());
        }
        Ok(())
    })
}

/// The storage root is a caller's fact and is never created here: a mistyped or
/// deleted root fails loudly instead of answering an empty set, and neither the root
/// nor a parent of it is created.
pub(crate) fn peer_record_requires_its_root() -> Result<(), String> {
    let root = super::support::temp_root()?;
    let missing = root.path().join("no-such-dir").join("not-a-root");
    match RecordStore::open(&missing, Limits::default()) {
        Err(RecordError::RootMissing { path }) if path == missing => {}
        Err(error) => return Err(format!("a missing root was refused as `{error}`")),
        Ok(_) => return Err("a missing root answered an empty store".to_owned()),
    }
    if missing.exists() {
        return Err("opening the store created the root".to_owned());
    }
    if missing.parent().is_some_and(std::path::Path::exists) {
        return Err("opening the store created the root's parent".to_owned());
    }
    Ok(())
}

/// A `peers/` directory this crate creates is private before it is read.
#[cfg(unix)]
pub(crate) fn peer_record_creates_a_private_directory() -> Result<(), String> {
    let sim = Sim::new().map_err(io_error)?;
    let machine = sim.machine().map_err(io_error)?;
    drop(machine.records());
    let mode = machine.storage().records_dir_mode().map_err(io_error)?;
    if mode != 0o700 {
        return Err(format!("the created directory has mode {mode:o}"));
    }
    Ok(())
}

/// Opening the store writes nothing: a records directory its owner can read and
/// search but not write still opens and reads what it holds.
#[cfg(unix)]
pub(crate) fn peer_record_opens_a_read_only_directory() -> Result<(), String> {
    let sim = Sim::new().map_err(io_error)?;
    let machine = sim.machine().map_err(io_error)?;
    let peer = sim.machine().map_err(io_error)?;
    let store = machine.records();
    store
        .record_pairing(&peer.peer_id(), NOW)
        .map_err(|error| error.to_string())?;
    drop(store);
    let storage = machine.storage();
    storage.set_records_dir_mode(0o500).map_err(io_error)?;
    let reopened = machine.reopen_records();
    storage.set_records_dir_mode(0o700).map_err(io_error)?;
    let reopened = reopened?;
    if !reopened.is_paired(&peer.peer_id()) {
        return Err("a read-only records directory lost its pairing".to_owned());
    }
    Ok(())
}

/// Dropping expired attempts — and only expired ones: an attempt another process is
/// running keeps its guard, and a record that held nothing else is removed.
pub(crate) fn peer_record_drops_expired_attempts() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;
        let expired = sim.machine().map_err(io_error)?;
        let live = sim.machine().map_err(io_error)?;
        let paired = sim.machine().map_err(io_error)?;
        // A ceremony a crash left behind: an attempt with a one-second lifetime and
        // nothing else.
        let short = machine.records_with(Limits {
            attempt_lifetime: Duration::from_secs(1),
            ..Limits::default()
        })?;
        short
            .begin_attempt(&expired.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        let store = machine.records_with(Limits {
            attempt_lifetime: Duration::from_mins(15),
            ..Limits::default()
        })?;
        // An attempt another process is running: it must survive the prune.
        store
            .begin_attempt(&live.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        // A paired peer with a failure and no attempt: both facts stay.
        store
            .record_pairing(&paired.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        store
            .record_failure(&paired.peer_id())
            .map_err(|error| error.to_string())?;
        let expired_exists = || {
            machine
                .storage()
                .record_exists(&expired.peer_id())
                .map_err(io_error)
        };
        if !expired_exists()? {
            return Err("the attempt wrote no record".to_owned());
        }

        store
            .prune_expired(NOW.plus(Duration::from_secs(2)))
            .map_err(|error| error.to_string())?;
        if store.get(&expired.peer_id()).is_some() || expired_exists()? {
            return Err("an expired attempt-only record survived the prune".to_owned());
        }
        if store
            .get(&live.peer_id())
            .is_none_or(|record| record.attempt().is_none())
        {
            return Err("the prune dropped an attempt that had not expired".to_owned());
        }
        let kept = store
            .get(&paired.peer_id())
            .ok_or("the prune dropped a paired record")?;
        if kept.failures() != 1 || !store.is_paired(&paired.peer_id()) {
            return Err("the prune lost the pairing or the failure count".to_owned());
        }

        // Opening the store does not prune: the live attempt is still there.
        let reopened = machine.reopen_records()?;
        if reopened
            .get(&live.peer_id())
            .is_none_or(|record| record.attempt().is_none())
        {
            return Err("opening the store dropped a live attempt".to_owned());
        }

        // An attempt another process restarted after this store loaded the expired
        // one is kept: the prune re-reads the file and checks the expiry again.
        let restarted = sim.machine().map_err(io_error)?;
        short
            .begin_attempt(&restarted.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        let other = machine.reopen_records()?;
        let later = NOW.plus(Duration::from_secs(5));
        other
            .restart_attempt(&restarted.peer_id(), later)
            .map_err(|error| error.to_string())?;
        // `short`'s map still holds the expired attempt, so its snapshot names the
        // peer; the re-read finds the fresh one.
        short
            .prune_expired(later)
            .map_err(|error| error.to_string())?;
        let fresh = machine
            .reopen_records()?
            .get(&restarted.peer_id())
            .and_then(|record| record.attempt())
            .ok_or("the prune dropped an attempt another process had restarted")?;
        if fresh.expires_at <= later {
            return Err("the prune kept the wrong attempt".to_owned());
        }

        // One record that cannot be read does not stop the sweep: the rest are still
        // pruned, and the refusal names the file a person has to act on. The sweep
        // walks the records in peer-id order, so the unreadable one must sort first
        // or a sweep that stopped at it would look like a pass.
        let first = sim.machine().map_err(io_error)?;
        let second = sim.machine().map_err(io_error)?;
        let (unreadable, doomed) = if first.peer_id() < second.peer_id() {
            (first, second)
        } else {
            (second, first)
        };
        short
            .begin_attempt(&unreadable.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        short
            .begin_attempt(&doomed.peer_id(), NOW)
            .map_err(|error| error.to_string())?;
        let storage = machine.storage();
        storage
            .write_record(&unreadable.peer_id(), b"not a record")
            .map_err(io_error)?;
        let bad_name = storage
            .record_name(&unreadable.peer_id())
            .map_err(io_error)?;
        let Err(error) = short.prune_expired(NOW.plus(Duration::from_secs(2))) else {
            return Err("the prune read a garbage record as a record".to_owned());
        };
        if !error.to_string().contains(&bad_name) {
            return Err(format!("the refusal does not name the file: {error}"));
        }
        if storage.record_exists(&doomed.peer_id()).map_err(io_error)? {
            return Err("the sweep stopped at the unreadable record".to_owned());
        }
        Ok(())
    })
}
