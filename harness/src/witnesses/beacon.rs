//! Beacon cases: the real server and the real client over the simulated link.
//!
//! Every case here is one acceptance criterion of the beacon: two clients find
//! each other, the address answer follows the peer path, a restart forgets
//! everything, registration is bound to the caller's key, an introduction is
//! signed and delivered live only, the message set is closed, the version is
//! explicit, and an impostor without the pinned key gets no answer.

use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;

use mahbot_beacon::core::REGISTRATION_TTL;
use mahbot_beacon::server::EXCHANGE_TIMEOUT;
use mahbot_peers::beacon::{
    BEACON_IDLE_TIMEOUT, BEACON_KEEP_ALIVE, BEACON_REQUEST_TIMEOUT, Beacon, BeaconError, Frame,
    Introduction, MAX_CONCURRENT_STREAMS, MAX_FRAME_BYTES, MAX_PAYLOAD_BYTES, PROTOCOL_VERSION,
    Push, Refusal, Request, Response, Session,
};
use mahbot_peers::identity::{Identity, PeerId};
use mahbot_peers::net::Transport;
use quinn::AsyncUdpSocket;
use rustls::SignatureScheme;
use rustls::client::ResolvesClientCert;
use rustls::sign::CertifiedKey;

use crate::beacon::TestBeacon;
use crate::clock::block_on;
use crate::connect::{TrustSet, connect};
use crate::machine::Machine;
use crate::raw::{RawClient, Rogue, RogueBeacon};
use crate::sim::Sim;

use super::support::{BUDGET, io_error, within};

pub(crate) fn two_clients_find_each_other() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let first = sim.machine().map_err(io_error)?;
        let second = sim.machine().map_err(io_error)?;
        let first_session = session(&sim, &beacon, &first).await?;
        let second_session = session(&sim, &beacon, &second).await?;

        let registration = register(&sim, &first_session).await?;
        if registration != REGISTRATION_TTL {
            return Err(format!(
                "the beacon granted {registration:?}, not {REGISTRATION_TTL:?}"
            ));
        }
        register(&sim, &second_session).await?;

        if lookup(&sim, &first_session, &second.peer_id()).await? != Some(second.addr()) {
            return Err("the first client did not find the second".to_owned());
        }
        if lookup(&sim, &second_session, &first.peer_id()).await? != Some(first.addr()) {
            return Err("the second client did not find the first".to_owned());
        }
        Ok(())
    })
}

pub(crate) fn observed_address_is_the_peer_path() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let first = sim.machine().map_err(io_error)?;
        let second = sim.machine().map_err(io_error)?;
        let first_session = session(&sim, &beacon, &first).await?;

        let own = observed(&sim, &first_session).await?;
        if own != first.addr() {
            return Err(format!(
                "the beacon reports {own}, but the peer-facing socket is at {}",
                first.addr()
            ));
        }

        // The answer is the peer path: dialing exactly the reported address
        // reaches this machine.
        first.trust(&second);
        second.trust(&first);
        let pair = connect(&second, &first).await.map_err(|e| e.to_string())?;
        if pair.server.remote_address() != second.addr() {
            return Err("the peer connection did not land on the machine's endpoint".to_owned());
        }

        // A session on another socket reports that socket: the answer tracks the
        // path it was asked over, not some ambient notion of "my address".
        let side_socket = sim.link().attach_next();
        let side_endpoint = Transport::default()
            .endpoint(
                Arc::clone(&side_socket) as Arc<dyn AsyncUdpSocket>,
                sim.clock().runtime(),
                &first.identity,
                Arc::new(TrustSet::default()),
            )
            .map_err(|error| error.to_string())?;
        let side = Beacon::new(
            side_endpoint,
            sim.clock().runtime(),
            beacon.address(),
            beacon.key(),
            first.identity.clone(),
        );
        let side_session = within(&sim, BUDGET, side.connect())
            .await?
            .map_err(|error| error.to_string())?;
        let side_own = observed(&sim, &side_session).await?;
        if side_own != side_socket.addr() {
            return Err(format!(
                "the side socket is at {}, but the beacon reported {side_own}",
                side_socket.addr()
            ));
        }
        if side_own == first.addr() {
            return Err("the answer did not depend on the socket it was asked over".to_owned());
        }
        Ok(())
    })
}

pub(crate) fn beacon_restart_forgets_and_recovers() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let mut beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let first = sim.machine().map_err(io_error)?;
        let second = sim.machine().map_err(io_error)?;
        let first_session = session(&sim, &beacon, &first).await?;
        let second_session = session(&sim, &beacon, &second).await?;
        register(&sim, &first_session).await?;
        register(&sim, &second_session).await?;
        if lookup(&sim, &first_session, &second.peer_id()).await? != Some(second.addr()) {
            return Err("the pair did not find each other before the restart".to_owned());
        }

        beacon.restart().await?;

        // The old sessions are dead: nothing answers on them, and the failure is
        // the connection's, not a malformed frame.
        match within(&sim, BUDGET, first_session.lookup(&second.peer_id())).await? {
            Err(BeaconError::Unavailable) => {}
            other => {
                return Err(format!(
                    "a session survived the beacon's restart: {other:?}"
                ));
            }
        }

        // A fresh session knows nothing: there is no disk and no recovery.
        let fresh = session(&sim, &beacon, &first).await?;
        if lookup(&sim, &fresh, &second.peer_id()).await?.is_some() {
            return Err("the restarted beacon remembered a registration".to_owned());
        }

        // Both recover on their next need by registering again.
        register(&sim, &fresh).await?;
        let second_fresh = session(&sim, &beacon, &second).await?;
        register(&sim, &second_fresh).await?;
        if lookup(&sim, &fresh, &second.peer_id()).await? != Some(second.addr()) {
            return Err("the clients did not recover after the restart".to_owned());
        }
        Ok(())
    })
}

pub(crate) fn beacon_starts_and_stops() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;
        let session = session(&sim, &beacon, &machine).await?;
        register(&sim, &session).await?;
        if lookup(&sim, &session, &machine.peer_id()).await? != Some(machine.addr()) {
            return Err("a running beacon did not answer its own registration".to_owned());
        }

        beacon.stop();
        if within(&sim, BUDGET, session.lookup(&machine.peer_id()))
            .await?
            .is_ok()
        {
            return Err("a stopped beacon answered a request".to_owned());
        }
        // A connect to a stopped beacon must *fail*, not hang: the answer is an
        // error inside the client's own bound.
        let client = beacon.client(&machine)?;
        match within(
            &sim,
            BEACON_REQUEST_TIMEOUT + Duration::from_secs(5),
            client.connect(),
        )
        .await?
        {
            Err(_) => Ok(()),
            Ok(_) => Err("a stopped beacon accepted a session".to_owned()),
        }
    })
}

pub(crate) fn registration_is_bound_to_the_caller_key() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let victim = sim.machine().map_err(io_error)?;
        let attacker = sim.machine().map_err(io_error)?;
        let victim_session = session(&sim, &beacon, &victim).await?;
        register(&sim, &victim_session).await?;

        // The attacker registers itself. There is no id in the frame, so it can
        // only ever register the key the handshake proved.
        let raw = RawClient::connect(&attacker, &beacon).await?;
        match Response::decode(&raw.send(&Request::Register.encode()).await?)
            .map_err(|error| error.to_string())?
        {
            Response::Registered { .. } => {}
            other => {
                return Err(format!(
                    "the attacker's registration was answered {other:?}"
                ));
            }
        }
        if lookup(&sim, &victim_session, &victim.peer_id()).await? != Some(victim.addr()) {
            return Err("the attacker moved the victim's id".to_owned());
        }
        if lookup(&sim, &victim_session, &attacker.peer_id()).await? != Some(attacker.addr()) {
            return Err("the attacker was not registered at its own path".to_owned());
        }

        // A frame that asserts an address is not believed: the set has no such
        // field, so the frame is refused and nothing is recorded.
        let mut claiming = Request::Register.encode();
        claiming.extend_from_slice(&[4, 127, 0, 0, 1, 0x1f, 0x90]);
        match Response::decode(&raw.send(&claiming).await?).map_err(|error| error.to_string())? {
            Response::Refused(Refusal::Malformed) => {}
            other => {
                return Err(format!(
                    "a registration asserting an address was answered {other:?}"
                ));
            }
        }
        if lookup(&sim, &victim_session, &victim.peer_id()).await? != Some(victim.addr()) {
            return Err("an address claim changed the victim's registration".to_owned());
        }

        // The beacon's whole memory is the two registrations.
        let snapshot = beacon
            .registry()
            .lock()
            .expect("beacon registry is not poisoned")
            .snapshot();
        let mut expected = vec![
            (victim.peer_id(), victim.addr()),
            (attacker.peer_id(), attacker.addr()),
        ];
        expected.sort_by_key(|(id, _)| *id);
        if snapshot != expected {
            return Err(format!(
                "the beacon remembers {snapshot:?}, not the two registrations"
            ));
        }
        Ok(())
    })
}

pub(crate) fn registration_ttl_is_the_beacons_housekeeping() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;
        // The session's liveness and the registration's lifetime are two
        // different clocks: a ping keeps the connection open, only a refresh keeps
        // the registration. A keep-alive that reached the idle timeout would leave
        // no room for a missed ping, so it must stay below it.
        if BEACON_KEEP_ALIVE >= BEACON_IDLE_TIMEOUT {
            return Err(format!(
                "the beacon pings every {BEACON_KEEP_ALIVE:?}, which is not below its {BEACON_IDLE_TIMEOUT:?} idle timeout"
            ));
        }
        let session = session(&sim, &beacon, &machine).await?;
        register(&sim, &session).await?;
        if lookup(&sim, &session, &machine.peer_id()).await? != Some(machine.addr()) {
            return Err("a fresh registration was not answered".to_owned());
        }

        // Ask periodically, as a client that refreshes would, so the session stays
        // open while the registration ages.
        const STEP: Duration = Duration::from_secs(20);
        for _ in 0..5 {
            sim.clock().advance(STEP).await;
            if lookup(&sim, &session, &machine.peer_id()).await? != Some(machine.addr()) {
                return Err("a registration expired before its lifetime".to_owned());
            }
        }
        // Up to one second short of the lifetime: still registered.
        sim.clock()
            .advance(REGISTRATION_TTL - 5 * STEP - Duration::from_secs(1))
            .await;
        if lookup(&sim, &session, &machine.peer_id()).await? != Some(machine.addr()) {
            return Err("a registration expired before its lifetime".to_owned());
        }
        sim.clock().advance(Duration::from_secs(2)).await;
        if lookup(&sim, &session, &machine.peer_id()).await?.is_some() {
            return Err("an expired registration was still answered".to_owned());
        }

        register(&sim, &session).await?;
        if lookup(&sim, &session, &machine.peer_id()).await? != Some(machine.addr()) {
            return Err("a refreshed registration was not answered".to_owned());
        }
        Ok(())
    })
}

pub(crate) fn introduction_is_signed_by_its_sender() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let sender = sim.machine().map_err(io_error)?;
        let recipient = sim.machine().map_err(io_error)?;
        let sender_session = session(&sim, &beacon, &sender).await?;
        let recipient_session = session(&sim, &beacon, &recipient).await?;
        register(&sim, &sender_session).await?;
        register(&sim, &recipient_session).await?;

        let payload = b"an opaque key exchange".to_vec();
        introduce(&sim, &sender_session, recipient.peer_id(), &payload)
            .await
            .map_err(|error| error.to_string())?;
        let introduction = next_introduction(&sim, &recipient_session).await?;
        if introduction.from() != sender.peer_id()
            || introduction.to() != recipient.peer_id()
            || introduction.payload() != payload
        {
            return Err("the introduction did not arrive as it was sent".to_owned());
        }
        if !introduction.is_authentic() {
            return Err("an honestly relayed introduction did not verify".to_owned());
        }

        // A compromised beacon holds the beacon's key, so it passes the pin, and
        // still cannot speak for a machine: the recipient checks the signature.
        let impostor = Identity::generate();
        let signed = Introduction::signed(&impostor, recipient.peer_id(), payload.clone())
            .map_err(|error| error.to_string())?;
        let forged = Push::Introduction {
            from: sender.peer_id(),
            to: recipient.peer_id(),
            signature: *signed.signature(),
            payload: payload.clone(),
        }
        .encode();
        let rogue = RogueBeacon::start(&sim, beacon.identity(), Rogue::Push(forged))
            .map_err(|error| error.to_string())?;
        match pushed(&sim, &rogue, &recipient, beacon.key()).await? {
            Err(BeaconError::UnauthenticatedIntroduction { from }) if from == sender.peer_id() => {}
            other => {
                return Err(format!(
                    "an introduction under a false sender id was not refused: {other:?}"
                ));
            }
        }

        // An altered payload is refused the same way: the code never passes
        // through the beacon, and an alteration cannot influence what the two
        // humans compare.
        let authentic =
            Introduction::signed(&sender.identity, recipient.peer_id(), payload.clone())
                .map_err(|error| error.to_string())?;
        let mut altered_payload = payload;
        altered_payload[0] ^= 0xff;
        let altered = Push::Introduction {
            from: sender.peer_id(),
            to: recipient.peer_id(),
            signature: *authentic.signature(),
            payload: altered_payload,
        }
        .encode();
        let rogue = RogueBeacon::start(&sim, beacon.identity(), Rogue::Push(altered))
            .map_err(|error| error.to_string())?;
        match pushed(&sim, &rogue, &recipient, beacon.key()).await? {
            Err(BeaconError::UnauthenticatedIntroduction { from }) if from == sender.peer_id() => {}
            other => {
                return Err(format!(
                    "an altered introduction was not refused: {other:?}"
                ));
            }
        }
        Ok(())
    })
}

pub(crate) fn beacon_relays_introductions_live_only() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let sender = sim.machine().map_err(io_error)?;
        let recipient = sim.machine().map_err(io_error)?;
        let sender_session = session(&sim, &beacon, &sender).await?;
        register(&sim, &sender_session).await?;

        // The addressee is not registered: the sender is told, and nothing waits.
        match introduce(&sim, &sender_session, recipient.peer_id(), b"early").await {
            Err(BeaconError::UnknownPeer(id)) if id == recipient.peer_id() => {}
            other => {
                return Err(format!(
                    "an introduction to an unregistered id was answered {other:?}"
                ));
            }
        }

        let recipient_session = session(&sim, &beacon, &recipient).await?;
        register(&sim, &recipient_session).await?;
        match within(
            &sim,
            Duration::from_secs(2),
            recipient_session.next_introduction(),
        )
        .await
        {
            // Nothing was waiting: the await never resolved inside the budget.
            Err(_) => {}
            Ok(Ok(_)) => {
                return Err("an introduction was stored while the addressee was away".to_owned());
            }
            Ok(Err(error)) => {
                return Err(format!("the recipient's first poll failed: {error}"));
            }
        }

        // While it is registered, delivery is live.
        introduce(&sim, &sender_session, recipient.peer_id(), b"live")
            .await
            .map_err(|error| error.to_string())?;
        let introduction = next_introduction(&sim, &recipient_session).await?;
        if introduction.payload() != b"live" {
            return Err("the live introduction did not arrive".to_owned());
        }

        // A session that closes is not registered any more: the beacon drops the
        // registration with the connection, before any lifetime runs out.
        recipient_session.close(b"gone");
        let recipient_id = recipient.peer_id();
        let registry = beacon.registry();
        within(&sim, BUDGET, async {
            while registry
                .lock()
                .expect("beacon registry is not poisoned")
                .snapshot()
                .iter()
                .any(|(id, _)| *id == recipient_id)
            {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        if lookup(&sim, &sender_session, &recipient_id)
            .await?
            .is_some()
        {
            return Err("a closed session stayed registered".to_owned());
        }

        // A registration that is not refreshed expires, and nothing is stored for
        // a later registration to collect.
        let recipient_session = session(&sim, &beacon, &recipient).await?;
        register(&sim, &recipient_session).await?;
        sim.clock()
            .advance(REGISTRATION_TTL + Duration::from_secs(1))
            .await;
        match introduce(&sim, &sender_session, recipient.peer_id(), b"late").await {
            Err(BeaconError::UnknownPeer(id)) if id == recipient.peer_id() => {}
            other => {
                return Err(format!(
                    "an introduction to an expired registration was answered {other:?}"
                ));
            }
        }
        Ok(())
    })
}

pub(crate) fn introduction_payload_is_opaque_to_the_beacon() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let sender = sim.machine().map_err(io_error)?;
        let recipient = sim.machine().map_err(io_error)?;
        let sender_session = session(&sim, &beacon, &sender).await?;
        let recipient_session = session(&sim, &beacon, &recipient).await?;
        register(&sim, &sender_session).await?;
        register(&sim, &recipient_session).await?;

        // Every byte value, so a relay that rewrites, normalises or truncates
        // anything is visible.
        let payload: Vec<u8> = (0..=255u8).cycle().take(1024).collect();
        introduce(&sim, &sender_session, recipient.peer_id(), &payload)
            .await
            .map_err(|error| error.to_string())?;
        let introduction = next_introduction(&sim, &recipient_session).await?;
        if introduction.payload() != payload.as_slice() {
            return Err("the payload did not arrive byte for byte".to_owned());
        }

        // The beacon's whole memory is the two registrations: no payload, no
        // queue, nothing about the message it just carried.
        let snapshot = beacon
            .registry()
            .lock()
            .expect("beacon registry is not poisoned")
            .snapshot();
        let mut expected = vec![
            (sender.peer_id(), sender.addr()),
            (recipient.peer_id(), recipient.addr()),
        ];
        expected.sort_by_key(|(id, _)| *id);
        if snapshot != expected {
            return Err(format!(
                "the beacon remembers {snapshot:?}, not just the registrations"
            ));
        }

        // The snapshot is a curated view; the registry's own rendering is not. A
        // field added to hold the payload would print here, so this check fails
        // when the claim it makes is broken. The payload is the byte run
        // 254, 255, 0, 1 repeated, which is how a stored copy would read in a
        // debug rendering.
        let remembered = format!(
            "{:?}",
            beacon
                .registry()
                .lock()
                .expect("beacon registry is not poisoned")
        );
        if remembered.contains("254, 255, 0, 1") {
            return Err(format!(
                "the beacon's state carries the payload it relayed: {remembered}"
            ));
        }
        Ok(())
    })
}

pub(crate) fn introduction_size_limit() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let sender = sim.machine().map_err(io_error)?;
        let recipient = sim.machine().map_err(io_error)?;
        let sender_session = session(&sim, &beacon, &sender).await?;
        let recipient_session = session(&sim, &beacon, &recipient).await?;
        register(&sim, &sender_session).await?;
        register(&sim, &recipient_session).await?;

        let largest = vec![0u8; MAX_PAYLOAD_BYTES];
        introduce(&sim, &sender_session, recipient.peer_id(), &largest)
            .await
            .map_err(|error| error.to_string())?;
        let introduction = next_introduction(&sim, &recipient_session).await?;
        if introduction.payload().len() != MAX_PAYLOAD_BYTES {
            return Err("the largest documented payload did not arrive intact".to_owned());
        }

        let over = vec![0u8; MAX_PAYLOAD_BYTES + 1];
        match introduce(&sim, &sender_session, recipient.peer_id(), &over).await {
            Err(BeaconError::PayloadTooLarge(len)) if len == MAX_PAYLOAD_BYTES + 1 => {}
            other => return Err(format!("an oversized payload was accepted: {other:?}")),
        }
        match Introduction::new(sender.peer_id(), recipient.peer_id(), [0; 64], over.clone()) {
            Err(BeaconError::PayloadTooLarge(len)) if len == MAX_PAYLOAD_BYTES + 1 => {}
            other => return Err(format!("an oversized introduction was built: {other:?}")),
        }

        // And the server refuses a raw frame that carries one.
        let raw = RawClient::connect(&sender, &beacon).await?;
        let frame = Request::Introduce {
            to: recipient.peer_id(),
            signature: [0; 64],
            payload: over,
        }
        .encode();
        match refused(&raw, &frame).await? {
            Refusal::PayloadTooLarge => Ok(()),
            other => Err(format!("an oversized frame was refused as {other:?}")),
        }
    })
}

pub(crate) fn closed_message_set_refuses_unknown_kinds() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;
        let raw = RawClient::connect(&machine, &beacon).await?;

        let unknown = Frame::new(PROTOCOL_VERSION, 0x77, Vec::new()).encode();
        expect_refusal(&raw, &unknown, Refusal::UnknownMessage).await?;

        // A response and a push sent as a request are unknown in that direction.
        let response_kind = Frame::new(PROTOCOL_VERSION, 0x81, Vec::new()).encode();
        expect_refusal(&raw, &response_kind, Refusal::UnknownMessage).await?;
        let push_kind = Frame::new(PROTOCOL_VERSION, 0xC1, Vec::new()).encode();
        expect_refusal(&raw, &push_kind, Refusal::UnknownMessage).await?;

        // A body that is not the length its kind implies.
        let wrong_length = Frame::new(PROTOCOL_VERSION, 0x02, vec![0; 33]).encode();
        expect_refusal(&raw, &wrong_length, Refusal::Malformed).await?;

        // A second frame on the same stream: the set is closed per stream.
        let mut trailing = Request::Register.encode();
        trailing.push(0);
        expect_refusal(&raw, &trailing, Refusal::Malformed).await?;

        // A frame that announces more than the protocol reads, refused before its
        // body is buffered: only the header is sent.
        let mut oversized = vec![PROTOCOL_VERSION, 0x01];
        oversized.extend_from_slice(
            &u32::try_from(MAX_FRAME_BYTES)
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        expect_refusal(&raw, &oversized, Refusal::Malformed).await?;
        Ok(())
    })
}

pub(crate) fn version_mismatch_is_explicit() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;
        let raw = RawClient::connect(&machine, &beacon).await?;

        // The server answers under its own version and names the mismatch.
        let frame = raw.send(&Frame::new(2, 0x01, Vec::new()).encode()).await?;
        if frame.version() != PROTOCOL_VERSION {
            return Err(format!(
                "the refusal came under version {}, not {PROTOCOL_VERSION}",
                frame.version()
            ));
        }
        match Response::decode(&frame).map_err(|error| error.to_string())? {
            Response::Refused(Refusal::VersionMismatch) => {}
            other => return Err(format!("a version-2 request was answered {other:?}")),
        }

        // The client names both versions instead of misreading a body.
        let reply = Frame::new(2, 0x81, Vec::new()).encode();
        let rogue = RogueBeacon::start(&sim, beacon.identity(), Rogue::Reply(reply))
            .map_err(|error| error.to_string())?;
        let client = Beacon::new(
            machine.endpoint().map_err(|error| error.to_string())?,
            sim.clock().runtime(),
            rogue.address(),
            beacon.key(),
            machine.identity.clone(),
        );
        let session = within(&sim, BUDGET, client.connect())
            .await?
            .map_err(|error| error.to_string())?;
        match within(&sim, BUDGET, session.register()).await? {
            Err(BeaconError::VersionMismatch {
                beacon: 2,
                client: 1,
            }) => Ok(()),
            other => Err(format!(
                "a version-2 answer was not reported as a mismatch: {other:?}"
            )),
        }
    })
}

pub(crate) fn impostor_beacon_gives_no_answers() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let impostor = TestBeacon::start(&sim).map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;

        // The address is the impostor's; the pinned key is the real beacon's.
        let client = Beacon::new(
            machine.endpoint().map_err(|error| error.to_string())?,
            sim.clock().runtime(),
            impostor.address(),
            beacon.key(),
            machine.identity.clone(),
        );
        let answered = match within(&sim, BUDGET, client.connect()).await? {
            Ok(session) => within(&sim, BUDGET, session.register()).await?.is_ok(),
            Err(_) => false,
        };
        if answered {
            return Err("an impostor without the pinned key gave a usable answer".to_owned());
        }
        // And the client never reached either service: nothing was registered.
        for (side, registry) in [
            ("the impostor", impostor.registry()),
            ("the real beacon", beacon.registry()),
        ] {
            if !registry
                .lock()
                .expect("beacon registry is not poisoned")
                .is_empty()
            {
                return Err(format!("the client registered with {side}"));
            }
        }
        Ok(())
    })
}

pub(crate) fn unauthenticated_caller_gets_nothing() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;

        // A client that pins the beacon's key but presents no key of its own.
        let trust = TrustSet::default();
        trust.insert(beacon.key());
        let tls = mahbot_peers::tls::client_config_with_resolver(
            Arc::new(NoCertificate),
            Arc::new(trust),
            mahbot_peers::beacon::ALPN,
        )
        .map_err(|error| error.to_string())?;
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls))
            .map_err(|error| format!("{error:?}"))?;
        let mut config = quinn::ClientConfig::new(Arc::new(crypto));
        config.transport_config(Arc::new(
            mahbot_peers::beacon::transport_config().map_err(|error| error.to_string())?,
        ));
        let answered = match within(
            &sim,
            BUDGET,
            RawClient::connect_with(&machine, beacon.address(), config),
        )
        .await?
        {
            Err(_) => false,
            Ok(raw) => within(&sim, BUDGET, raw.send(&Request::Register.encode()))
                .await?
                .is_ok(),
        };
        if answered {
            return Err("a caller that presented no key got an answer".to_owned());
        }
        if !beacon
            .registry()
            .lock()
            .expect("beacon registry is not poisoned")
            .is_empty()
        {
            return Err("a caller that presented no key was registered".to_owned());
        }
        Ok(())
    })
}

pub(crate) fn addresses_round_trip() -> Result<(), String> {
    let mut addresses: Vec<SocketAddr> = ["127.0.0.1:443", "[::1]:443", "[2001:db8::1]:65535"]
        .iter()
        .map(|text| {
            text.parse()
                .map_err(|_| format!("{text} is not a socket address"))
        })
        .collect::<Result<_, _>>()?;
    // A link-local address is meaningless without its scope, so the codec must
    // carry both extra fields rather than decode a different address than it was
    // given.
    addresses.push(SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        4433,
        0x1234,
        7,
    )));
    for address in addresses {
        let frame = Frame::parse(&Response::Observed(address).encode())
            .map_err(|error| error.to_string())?;
        match Response::decode(&frame).map_err(|error| error.to_string())? {
            Response::Observed(decoded) if decoded == address => {}
            other => return Err(format!("{address} round-tripped as {other:?}")),
        }
    }
    Ok(())
}

pub(crate) fn a_dead_beacon_is_noticed() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let mut beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;
        let before = session(&sim, &beacon, &machine).await?;
        register(&sim, &before).await?;

        // A process that dies sends nothing, so the client learns from its own
        // request bound — and it does learn, instead of waiting on a session that
        // looks open forever.
        beacon.kill();
        match within(
            &sim,
            BEACON_REQUEST_TIMEOUT + Duration::from_secs(5),
            before.lookup(&machine.peer_id()),
        )
        .await?
        {
            Err(BeaconError::Unavailable) => {}
            other => {
                return Err(format!(
                    "a request to a killed beacon was answered {other:?}"
                ));
            }
        }

        // Recovery is the next need: a fresh session against the revived beacon.
        beacon.restart().await?;
        let recovered = session(&sim, &beacon, &machine).await?;
        register(&sim, &recovered).await?;
        if lookup(&sim, &recovered, &machine.peer_id()).await? != Some(machine.addr()) {
            return Err("a client did not recover after the beacon was killed".to_owned());
        }
        Ok(())
    })
}

pub(crate) fn a_stalled_stream_is_refused() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;
        let raw = RawClient::connect(&machine, &beacon).await?;

        // A request that never ends: part of a header and no FIN. The beacon
        // answers within its own bound instead of holding the connection's loop
        // for as long as the peer keeps the stream open.
        let register = Request::Register.encode();
        let frame = within(
            &sim,
            EXCHANGE_TIMEOUT + Duration::from_secs(2),
            raw.stall(&register[..register.len() - 1]),
        )
        .await??;
        match Response::decode(&frame).map_err(|error| error.to_string())? {
            Response::Refused(Refusal::Slow) => {}
            other => return Err(format!("a stalled stream was answered {other:?}")),
        }

        // The same connection still serves a complete request.
        match Response::decode(&raw.send(&Request::ObservedAddress.encode()).await?)
            .map_err(|error| error.to_string())?
        {
            Response::Observed(address) if address == machine.addr() => Ok(()),
            other => Err(format!(
                "the connection stopped serving after a stalled stream: {other:?}"
            )),
        }
    })
}

pub(crate) fn a_stalled_handshake_gives_its_place_back() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        // One place, so a handshake that never finished would deny the next
        // client until the idle timeout.
        let beacon = TestBeacon::start_with_limit(&sim, 1).map_err(io_error)?;
        let stalled = sim.machine().map_err(io_error)?;
        let later = sim.machine().map_err(io_error)?;

        // Nothing is delivered back to the stalled client, so its handshake never
        // finishes: its Initial arrives and the server waits for a flight that
        // will not come. The `Connecting` is held, not dropped, so the client
        // neither gives up nor tells the server to.
        sim.link().silence(stalled.addr());
        let _connecting = RawClient::start(&stalled, &beacon)?;
        // A millisecond of virtual time for the Initial to arrive and the beacon
        // to take the place and arm its own deadline.
        sim.clock()
            .drive(Duration::from_millis(1), std::future::pending::<()>())
            .await;
        // The control: the place really was taken, so the recovery below is not a
        // case that never had a handshake to recover from.
        match within(&sim, BUDGET, beacon.client(&later)?.connect()).await? {
            Err(_) => {}
            Ok(_) => return Err("a stalled handshake did not hold the place".to_owned()),
        }
        // The deadline itself, with nothing delivered back to the stalled client
        // in between.
        sim.clock()
            .advance(EXCHANGE_TIMEOUT + Duration::from_millis(1))
            .await;

        let session = session(&sim, &beacon, &later).await?;
        register(&sim, &session).await?;
        if lookup(&sim, &session, &later.peer_id()).await? != Some(later.addr()) {
            return Err("the beacon did not serve a client after a stalled handshake".to_owned());
        }
        Ok(())
    })
}

pub(crate) fn a_recipient_that_never_reads_does_not_stall_the_sender() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let sender = sim.machine().map_err(io_error)?;
        let recipient = sim.machine().map_err(io_error)?;
        let sender_session = session(&sim, &beacon, &sender).await?;
        register(&sim, &sender_session).await?;

        // The recipient registers and then never accepts a stream: it advertises
        // a stream budget and leaves every push unread.
        let raw = RawClient::connect(&recipient, &beacon).await?;
        match Response::decode(&raw.send(&Request::Register.encode()).await?)
            .map_err(|error| error.to_string())?
        {
            Response::Registered { .. } => {}
            other => {
                return Err(format!(
                    "the recipient's registration was answered {other:?}"
                ));
            }
        }

        for _ in 0..MAX_CONCURRENT_STREAMS {
            introduce(&sim, &sender_session, recipient.peer_id(), b"unread")
                .await
                .map_err(|error| error.to_string())?;
        }
        // The budget is spent: the next push cannot be written, and the beacon
        // answers within its own bound instead of parking the sender's loop.
        match introduce(&sim, &sender_session, recipient.peer_id(), b"unread").await {
            Err(BeaconError::UnknownPeer(id)) if id == recipient.peer_id() => {}
            other => {
                return Err(format!(
                    "a push to a recipient that never reads was answered {other:?}"
                ));
            }
        }

        // The sender's own requests were never starved: it can refresh its
        // registration and be found.
        register(&sim, &sender_session).await?;
        if lookup(&sim, &sender_session, &sender.peer_id()).await? != Some(sender.addr()) {
            return Err("the sender's registration was starved by a third party".to_owned());
        }

        // And the recipient is still registered: a push that could not be written
        // says nothing about whether the machine is there, so a third party cannot
        // use the beacon to evict it from discovery.
        if lookup(&sim, &sender_session, &recipient.peer_id()).await? != Some(recipient.addr()) {
            return Err("a failed push de-registered a live third party".to_owned());
        }
        Ok(())
    })
}

pub(crate) fn beacon_alpn_is_its_own() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;

        // A client that pins the beacon's key but offers the peer layer's ALPN
        // must not complete: the two services are separate protocols.
        let trust = TrustSet::default();
        trust.insert(beacon.key());
        let policy: Arc<dyn mahbot_peers::tls::PeerPolicy> = Arc::new(trust);
        let tls =
            mahbot_peers::tls::client_config(&machine.identity, policy, mahbot_peers::tls::ALPN)
                .map_err(|error| error.to_string())?;
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls))
            .map_err(|error| format!("{error:?}"))?;
        let config = quinn::ClientConfig::new(Arc::new(crypto));
        match within(
            &sim,
            BUDGET,
            RawClient::connect_with(&machine, beacon.address(), config),
        )
        .await?
        {
            Err(_) => Ok(()),
            Ok(raw) => match within(&sim, BUDGET, raw.send(&Request::Register.encode())).await? {
                Ok(_) => Err("a peer-layer client got an answer from the beacon".to_owned()),
                Err(_) => Ok(()),
            },
        }
    })
}

/// Connect a session for `machine` to `beacon`.
async fn session(sim: &Sim, beacon: &TestBeacon, machine: &Machine) -> Result<Session, String> {
    within(sim, BUDGET, beacon.client(machine)?.connect())
        .await?
        .map_err(|error| error.to_string())
}

async fn register(sim: &Sim, session: &Session) -> Result<Duration, String> {
    within(sim, BUDGET, session.register())
        .await?
        .map_err(|error| error.to_string())
}

async fn lookup(
    sim: &Sim,
    session: &Session,
    id: &PeerId,
) -> Result<Option<std::net::SocketAddr>, String> {
    within(sim, BUDGET, session.lookup(id))
        .await?
        .map_err(|error| error.to_string())
}

async fn observed(sim: &Sim, session: &Session) -> Result<std::net::SocketAddr, String> {
    within(sim, BUDGET, session.observed_address())
        .await?
        .map_err(|error| error.to_string())
}

async fn introduce(
    sim: &Sim,
    session: &Session,
    to: PeerId,
    payload: &[u8],
) -> Result<(), BeaconError> {
    match within(sim, BUDGET, session.introduce(to, payload)).await {
        Ok(result) => result,
        Err(_) => Err(BeaconError::Transport(
            "no answer within the budget".to_owned(),
        )),
    }
}

async fn next_introduction(sim: &Sim, session: &Session) -> Result<Introduction, String> {
    within(sim, BUDGET, session.next_introduction())
        .await?
        .map_err(|error| error.to_string())
}

/// Connect to a rogue beacon at `rogue` and read the introduction it pushes.
async fn pushed(
    sim: &Sim,
    rogue: &RogueBeacon,
    machine: &Machine,
    key: mahbot_peers::identity::Fingerprint,
) -> Result<Result<Introduction, BeaconError>, String> {
    let client = Beacon::new(
        machine.endpoint().map_err(|error| error.to_string())?,
        sim.clock().runtime(),
        rogue.address(),
        key,
        machine.identity.clone(),
    );
    let session = within(sim, BUDGET, client.connect())
        .await?
        .map_err(|error| error.to_string())?;
    within(sim, BUDGET, session.next_introduction()).await
}

/// Send `bytes` and require the beacon to refuse them with `expected`.
async fn expect_refusal(raw: &RawClient, bytes: &[u8], expected: Refusal) -> Result<(), String> {
    match refused(raw, bytes).await? {
        refusal if refusal == expected => Ok(()),
        other => Err(format!(
            "the beacon refused the frame as {other:?}, not {expected:?}"
        )),
    }
}

async fn refused(raw: &RawClient, bytes: &[u8]) -> Result<Refusal, String> {
    let frame = raw.send(bytes).await?;
    if frame.version() != PROTOCOL_VERSION {
        return Err(format!(
            "the refusal came under version {}, not {PROTOCOL_VERSION}",
            frame.version()
        ));
    }
    match Response::decode(&frame).map_err(|error| error.to_string())? {
        Response::Refused(refusal) => Ok(refusal),
        other => Err(format!("the beacon answered {other:?} instead of refusing")),
    }
}

/// A client that advertises raw public keys and presents none: the server must
/// refuse it, so an unauthenticated caller gets nothing.
#[derive(Debug)]
struct NoCertificate;

impl ResolvesClientCert for NoCertificate {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        None
    }

    fn only_raw_public_keys(&self) -> bool {
        true
    }

    fn has_certs(&self) -> bool {
        false
    }
}
