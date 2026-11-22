//! Transport cases: the injected seams, the pinned handshake, the idle timer and
//! the rebind.

use std::sync::Arc;
use std::time::Duration;

use mahbot_peers::identity::Fingerprint;
use mahbot_peers::net::{DEFAULT_IDLE_TIMEOUT, Transport, TransportError};
use mahbot_peers::tls::{ALPN, PeerPolicy};
use quinn::AsyncUdpSocket;

use crate::clock::{DRIVE_YIELDS, block_on};
use crate::connect::{
    ConnectError, Pair, SERVER_NAME, TrustSet, connect, connect_by, connect_over,
};
use crate::link::{AddressTaken, Fault, FaultPlan, Rates};
use crate::machine::Machine;
use crate::sim::Sim;

use super::support::{endpoint_over, io_error, server_tls, within};

pub(crate) fn endpoint_from_injected_seams() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let socket = sim.link().attach_next();
        let addr = socket.addr();
        let endpoint = Transport::default()
            .endpoint(
                Arc::clone(&socket) as Arc<dyn AsyncUdpSocket>,
                sim.clock().runtime(),
                &crate::root::detached_identity().map_err(io_error)?,
                Arc::new(TrustSet::default()),
            )
            .map_err(|error| error.to_string())?;
        let local = endpoint.local_addr().map_err(|error| error.to_string())?;
        if local != addr {
            return Err(format!(
                "the endpoint reports {local} but the injected socket is at {addr}"
            ));
        }
        if sim.link().trace().iter().any(|event| event.delivered()) {
            return Err("building an endpoint delivered a datagram".to_owned());
        }
        Ok(())
    })
}

pub(crate) fn idle_timeout_bounds() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let socket = sim.link().attach_next();
        let transport = Transport {
            idle_timeout: Duration::MAX,
            keep_alive: None,
        };
        match transport.endpoint(
            Arc::clone(&socket) as Arc<dyn AsyncUdpSocket>,
            sim.clock().runtime(),
            &crate::root::detached_identity().map_err(io_error)?,
            Arc::new(TrustSet::default()),
        ) {
            Err(TransportError::IdleTimeout) => {}
            other => {
                return Err(format!(
                    "an unrepresentable idle timeout was accepted: {other:?}"
                ));
            }
        }
        let message = TransportError::IdleTimeout.to_string();
        if !message.contains("idle timeout") {
            return Err(format!("the refusal reads `{message}`"));
        }
        Ok(())
    })
}

pub(crate) fn concurrent_dialers_pair_correctly() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let first = sim.machine().map_err(io_error)?;
        let second = sim.machine().map_err(io_error)?;
        let server = sim.machine().map_err(io_error)?;
        for client in [&first, &second] {
            client.trust(&server);
            server.trust(client);
        }
        let (one, two) = tokio::join!(connect(&first, &server), connect(&second, &server));
        let one = one.map_err(|error| error.to_string())?;
        let two = two.map_err(|error| error.to_string())?;
        if one.server.remote_address() != first.addr()
            || two.server.remote_address() != second.addr()
        {
            return Err(format!(
                "a dialer received the other's connection: {} and {}",
                one.server.remote_address(),
                two.server.remote_address()
            ));
        }
        // The halves must belong to the same connection, not merely to the same
        // pair of addresses: a datagram sent on one half must arrive on the
        // other.
        for (pair, payload) in [(&one, b"one"), (&two, b"two")] {
            pair.client
                .send_datagram(payload.as_slice().into())
                .map_err(|error| error.to_string())?;
            let received = within(&sim, Duration::from_secs(1), pair.server.read_datagram())
                .await?
                .map_err(|error| error.to_string())?;
            if &received[..] != payload {
                return Err(format!(
                    "a datagram arrived on the wrong connection as {received:?}"
                ));
            }
        }
        Ok(())
    })
}

pub(crate) fn pinned_handshake() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (client, server) = sim.trusting_pair().map_err(io_error)?;
        let pair = connect(&client, &server).await.map_err(|e| e.to_string())?;
        if pair.server.remote_address() != client.addr() {
            return Err(format!(
                "the server sees {} but the client is at {}",
                pair.server.remote_address(),
                client.addr()
            ));
        }
        pair.client
            .send_datagram(b"hello".as_slice().into())
            .map_err(|e| e.to_string())?;
        let received = within(&sim, Duration::from_secs(1), pair.server.read_datagram())
            .await?
            .map_err(|e| e.to_string())?;
        if &received[..] != b"hello" {
            return Err(format!("the datagram arrived as {received:?}"));
        }
        Ok(())
    })
}

pub(crate) fn untrusted_peer_is_refused() -> Result<(), String> {
    block_on(async {
        // The server does not trust the client.
        let sim = Sim::new().map_err(io_error)?;
        let client = sim.machine().map_err(io_error)?;
        let server = sim.machine().map_err(io_error)?;
        client.trust(&server);
        match connect(&client, &server).await {
            Ok(_) => {
                return Err(
                    "a handshake completed with a client the server does not trust".to_owned(),
                );
            }
            Err(ConnectError::Connection(_)) => {}
            Err(other) => return Err(format!("the refusal came from the wrong layer: {other}")),
        }

        // The client does not trust the server.
        let sim = Sim::new().map_err(io_error)?;
        let client = sim.machine().map_err(io_error)?;
        let server = sim.machine().map_err(io_error)?;
        server.trust(&client);
        match connect(&client, &server).await {
            Ok(_) => {
                Err("a handshake completed with a server the client does not trust".to_owned())
            }
            Err(ConnectError::Connection(_)) => Ok(()),
            Err(other) => Err(format!("the refusal came from the wrong layer: {other}")),
        }
    })
}

pub(crate) fn machine_address_can_change() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (client, server) = sim.trusting_pair().map_err(io_error)?;
        connect(&client, &server).await.map_err(|e| e.to_string())?;
        let cutoff = sim.link().trace().len();
        let before = client.addr();
        let target = sim.link().alloc_addr();
        if target == before {
            return Err("the link handed out the address the client already holds".to_owned());
        }
        client.rebind(target).map_err(|error| error.to_string())?;
        if client.addr() != target {
            return Err(format!(
                "an explicit rebind to {target} left the client at {}",
                client.addr()
            ));
        }
        match client.rebind(server.addr()) {
            Err(AddressTaken(addr)) if addr == server.addr() => {}
            other => {
                return Err(format!(
                    "a rebind onto the server's live address was not refused: {other:?}"
                ));
            }
        }
        let after = client.rebind_next();
        if after == target || client.addr() != after {
            return Err(format!(
                "the second rebind did not move the address: {target} then {}",
                client.addr()
            ));
        }
        let pair = connect(&client, &server).await.map_err(|e| e.to_string())?;
        if pair.server.remote_address() != after {
            return Err(format!(
                "after the rebind the server sees {} not {after}",
                pair.server.remote_address()
            ));
        }
        let trace = sim.link().trace();
        if trace.len() <= cutoff {
            return Err("the second connection sent nothing".to_owned());
        }
        if trace[cutoff..].iter().any(|event| event.from == target) {
            return Err("a datagram still carried the address the client left".to_owned());
        }
        if !trace[cutoff..].iter().any(|event| event.from == after) {
            return Err("no datagram carried the new address".to_owned());
        }
        Ok(())
    })
}

/// Drive a connected pair to just before `timeout` and past it: it must still be
/// open at `timeout - 1 s` and `TimedOut` at `timeout + 1 s`, on both ends. This
/// is where the transport's timer meets the injected clock.
async fn assert_idle_timeout(sim: &Sim, pair: &Pair, timeout: Duration) -> Result<(), String> {
    if pair.client.close_reason().is_some() {
        return Err("the connection closed before time moved".to_owned());
    }
    sim.clock().advance(timeout - Duration::from_secs(1)).await;
    if pair.client.close_reason().is_some() {
        return Err(format!(
            "the connection closed before its {timeout:?} idle timeout"
        ));
    }
    sim.clock().advance(Duration::from_secs(2)).await;
    match pair.client.close_reason() {
        Some(quinn::ConnectionError::TimedOut) => {}
        other => {
            return Err(format!(
                "the idle timeout did not fire when the clock advanced: {other:?}"
            ));
        }
    }
    if pair.server.close_reason().is_none() {
        return Err("the other end did not observe the idle timeout".to_owned());
    }
    Ok(())
}

pub(crate) fn transport_timer_follows_clock() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let idle = Duration::from_secs(5);
        let (client, server) = sim.trusting_pair().map_err(io_error)?;
        let client = client.with_idle_timeout(idle);
        let server = server.with_idle_timeout(idle);
        let pair = connect(&client, &server).await.map_err(|e| e.to_string())?;
        assert_idle_timeout(&sim, &pair, idle).await
    })
}

pub(crate) fn default_idle_timeout_applies() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        // The bare timeout, without the default keep-alive: a quiet connection that
        // is not held must close at the documented instant.
        let (client, server) = sim.trusting_pair().map_err(io_error)?;
        let client = client.with_keep_alive(None);
        let server = server.with_keep_alive(None);
        let pair = connect(&client, &server).await.map_err(|e| e.to_string())?;
        assert_idle_timeout(&sim, &pair, DEFAULT_IDLE_TIMEOUT).await
    })
}

pub(crate) fn connect_times_out_on_a_dead_link() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (client, server) = sim.trusting_pair().map_err(io_error)?;
        // Every datagram is dropped, so the handshake can only end when its
        // virtual budget runs out.
        sim.link().set_plan(FaultPlan::Seeded {
            seed: 1,
            rates: Rates {
                drop: 100,
                ..Rates::default()
            },
        });
        let budget = Duration::from_secs(1);
        let started = sim.clock().elapsed();
        match connect_by(&client, &server, budget).await {
            Err(ConnectError::TimedOut { budget: spent_on }) if spent_on == budget => {}
            other => {
                return Err(format!(
                    "a link that drops everything did not time out: {other:?}"
                ));
            }
        }
        let spent = sim.clock().elapsed() - started;
        if spent != budget {
            return Err(format!(
                "the attempt gave up after {spent:?}, not at its {budget:?} budget"
            ));
        }
        if sim.link().trace().iter().any(|event| event.delivered()) {
            return Err("a datagram was delivered on a link that drops everything".to_owned());
        }
        Ok(())
    })
}

pub(crate) fn retry_after_a_timeout() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (client, server) = sim.trusting_pair().map_err(io_error)?;
        server.start_accepting().await.map_err(|e| e.to_string())?;
        // Two dials abandoned before an attempt takes their half: the server
        // files both under the client's address, and the newer one replaces the
        // older rather than accumulating.
        abandon_dial(&client, &server).await?;
        abandon_dial(&client, &server).await?;
        if server.inbox.len() > 1 {
            return Err(format!(
                "the server filed {} connections for one dialer",
                server.inbox.len()
            ));
        }
        // The client's first datagram gets through, so the server holds a
        // half-finished connection; the server's answer is late, so the client
        // gives up with that half still on the server's side.
        sim.link().set_plan(FaultPlan::Scripted(vec![
            Vec::new(),
            vec![Fault::Delay(Duration::from_millis(50))],
        ]));
        match connect_by(&client, &server, Duration::from_millis(10)).await {
            Err(ConnectError::TimedOut { .. }) => {}
            other => {
                return Err(format!(
                    "an attempt with no answer did not time out: {other:?}"
                ));
            }
        }
        sim.link().set_plan(FaultPlan::Clean);
        let pair = connect(&client, &server)
            .await
            .map_err(|error| format!("the retry after a timeout failed: {error}"))?;
        if pair.server.remote_address() != client.addr() {
            return Err(format!(
                "the retry paired {} with {}",
                pair.server.remote_address(),
                client.addr()
            ));
        }
        // And it is a working connection, not merely a handshake.
        pair.client
            .send_datagram(b"retry".as_slice().into())
            .map_err(|error| error.to_string())?;
        let received = within(&sim, Duration::from_secs(1), pair.server.read_datagram())
            .await?
            .map_err(|error| error.to_string())?;
        if &received[..] != b"retry" {
            return Err(format!("the retried pair carried {received:?}"));
        }
        if !server.inbox.is_empty() {
            return Err("the server kept an entry after the attempt took its own".to_owned());
        }
        Ok(())
    })
}

/// Start a handshake and drop it before the server's half is taken.
async fn abandon_dial(client: &Machine, server: &Machine) -> Result<(), String> {
    let client_endpoint = client.endpoint().map_err(|error| error.to_string())?;
    let dial = client_endpoint
        .connect(server.addr(), SERVER_NAME)
        .map_err(|error| error.to_string())?;
    tokio::pin!(dial);
    for _ in 0..DRIVE_YIELDS {
        tokio::select! {
            biased;
            _ = &mut dial => return Err("an abandoned handshake completed without an accept".to_owned()),
            () = tokio::task::yield_now() => {}
        }
    }
    Ok(())
}

pub(crate) fn alpn_mismatch_is_refused() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (client, server) = sim.trusting_pair().map_err(io_error)?;
        // Both of the library's configurations offer the crate's protocol and
        // nothing else.
        let policy: Arc<dyn PeerPolicy> = Arc::new(TrustSet::default());
        let client_alpn =
            mahbot_peers::tls::client_config(&client.identity, Arc::clone(&policy), ALPN)
                .map_err(|error| error.to_string())?
                .alpn_protocols;
        let server_alpn = mahbot_peers::tls::server_config(&server.identity, policy, ALPN)
            .map_err(|error| error.to_string())?
            .alpn_protocols;
        for (side, alpn) in [("client", client_alpn), ("server", server_alpn)] {
            if alpn != vec![ALPN.to_vec()] {
                return Err(format!(
                    "the {side} configuration offers {alpn:?}, not the crate's ALPN"
                ));
            }
        }
        // A server that speaks another protocol must not complete a handshake,
        // even though both sides pin each other's key.
        let mut tls = server_tls(&server)?;
        tls.alpn_protocols = vec![b"mahbot-peers/other".to_vec()];
        let endpoint = endpoint_over(&sim, &server, tls)?;
        match connect_over(&client, &server, &endpoint, Duration::from_secs(2)).await {
            Ok(_) => Err("a peer speaking another ALPN completed the handshake".to_owned()),
            Err(ConnectError::Connection(_)) => Ok(()),
            Err(other) => Err(format!("the refusal came from the wrong layer: {other}")),
        }
    })
}

pub(crate) fn closed_custom_endpoint_is_reported() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (client, server) = sim.trusting_pair().map_err(io_error)?;
        let endpoint = endpoint_over(&sim, &server, server_tls(&server)?)?;
        endpoint.close(0u32.into(), b"closed by the case");
        match connect_over(&client, &server, &endpoint, Duration::from_secs(1)).await {
            Err(ConnectError::Closed) => Ok(()),
            other => Err(format!(
                "a closed endpoint was not reported as closed: {other:?}"
            )),
        }
    })
}

/// A peer that presents this machine's own key is refused for being a copy, and
/// the reason is not the one an untrusted stranger gets.
pub(crate) fn own_identity_is_refused() -> Result<(), String> {
    use mahbot_peers::net::refusal;
    use mahbot_peers::tls::Refusal;

    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let original = sim.machine().map_err(io_error)?;
        let clone = sim.clone_of(&original).map_err(io_error)?;
        if clone.fingerprint() != original.fingerprint() {
            return Err("a copy of a root did not carry its identity".to_owned());
        }
        if clone.root_id() == original.root_id() {
            return Err("a clone shares the root it was copied from".to_owned());
        }
        // A clone would have been paired with itself: its peer list holds the very
        // key it presents, so the refusal cannot be the policy's.
        original.trust(&clone);
        clone.trust(&original);
        for (dialer, listener) in [(&original, &clone), (&clone, &original)] {
            let refused = match connect(dialer, listener).await {
                Ok(_) => {
                    return Err("a peer presenting this machine's own key was accepted".to_owned());
                }
                Err(ConnectError::Connection(error)) => refusal(&error),
                Err(other) => {
                    return Err(format!("the refusal came from the wrong layer: {other}"));
                }
            };
            if refused != Some(Refusal::OwnIdentity) {
                return Err(format!(
                    "a clone was refused as {refused:?}, not as this machine's own identity"
                ));
            }
        }

        // The same failure with a different cause reads differently: a peer whose
        // key this machine does not remember is untrusted, not a copy.
        let sim = Sim::new().map_err(io_error)?;
        let dialer = sim.machine().map_err(io_error)?;
        let stranger = sim.machine().map_err(io_error)?;
        stranger.trust(&dialer);
        match connect(&dialer, &stranger).await {
            Err(ConnectError::Connection(error)) => {
                if refusal(&error) != Some(Refusal::Untrusted) {
                    return Err(format!(
                        "an unpinned peer was refused as {:?}, not as untrusted",
                        refusal(&error)
                    ));
                }
            }
            other => return Err(format!("an unpinned peer was not refused: {other:?}")),
        }
        // Text that is not one of our refusals reads back as no refusal at all. The
        // reader cannot tell who wrote the text, which is why what it answers is a
        // log line and not evidence.
        let foreign = quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
            error_code: quinn::VarInt::from_u32(0),
            reason: b"the peer went away".to_vec().into(),
        });
        if refusal(&foreign).is_some() {
            return Err("an unrelated close reason was read as a refusal".to_owned());
        }
        Ok(())
    })
}

/// The 44 bytes the handshake pins, the 88 characters a human reads and the bytes
/// the other machine computes are one value.
pub(crate) fn handshake_value_is_the_pinned_bytes() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (client, server) = sim.trusting_pair().map_err(io_error)?;
        let pair = connect(&client, &server).await.map_err(|e| e.to_string())?;
        for (side, connection, expected) in [
            ("server", &pair.server, client.fingerprint()),
            ("client", &pair.client, server.fingerprint()),
        ] {
            let identity = connection
                .peer_identity()
                .ok_or_else(|| format!("the {side} recorded no peer identity"))?;
            let presented = identity
                .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
                .map_err(|_| format!("the {side} recorded an identity of another type"))?;
            if presented.len() != 1 {
                return Err(format!(
                    "the {side} received {} keys, not the one a raw public key sends",
                    presented.len()
                ));
            }
            let pinned = Fingerprint::from_spki(presented[0].as_ref())
                .ok_or_else(|| format!("what the {side} received is not an ed25519 SPKI"))?;
            if pinned != expected {
                return Err(format!(
                    "the {side} pinned {pinned}, but the peer calls itself {expected}"
                ));
            }
            if Fingerprint::from_hex(&pinned.to_string()) != Some(pinned) {
                return Err(format!(
                    "the {side}'s 44 bytes do not read back from the 88 characters shown"
                ));
            }
        }
        // And the pin is what the trusting side's policy was asked about.
        if !server.trust.contains(&client.fingerprint())
            || !client.trust.contains(&server.fingerprint())
        {
            return Err("a completed handshake left the peer out of the trust set".to_owned());
        }
        Ok(())
    })
}

pub(crate) fn retry_after_an_abandoned_attempt() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (client, server) = sim.trusting_pair().map_err(io_error)?;
        // A server endpoint with no accept task: its half of a handshake is
        // queued and never taken, so the client cannot finish.
        let endpoint = endpoint_over(&sim, &server, server_tls(&server)?)?;
        // Start a handshake and abandon it. The server keeps its half until an
        // accept task takes it, and the abort is what the next attempt must
        // refuse to take for its own.
        abandon_dial(&client, &server).await?;
        let pair = connect_over(&client, &server, &endpoint, Duration::from_secs(2))
            .await
            .map_err(|error| format!("the retry after an abandoned attempt failed: {error}"))?;
        if pair.server.remote_address() != client.addr() {
            return Err(format!(
                "the retry paired {} with {}",
                pair.server.remote_address(),
                client.addr()
            ));
        }
        Ok(())
    })
}

/// A keep-alive holds a quiet connection past the idle timeout that would close it.
pub(crate) fn keep_alive_holds_a_quiet_connection() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let idle = Duration::from_secs(5);
        let ping = Duration::from_secs(1);
        let (client, server) = sim.trusting_pair().map_err(io_error)?;
        let client = client.with_idle_timeout(idle).with_keep_alive(Some(ping));
        let server = server.with_idle_timeout(idle).with_keep_alive(Some(ping));
        let pair = connect(&client, &server).await.map_err(|e| e.to_string())?;
        sim.clock().advance(Duration::from_secs(20)).await;
        tokio::task::yield_now().await;
        if pair.client.close_reason().is_some() || pair.server.close_reason().is_some() {
            return Err("a keep-alive did not hold a quiet connection".to_owned());
        }
        // The same connection without the keep-alive is what the idle-timeout cases
        // close; this case only has to show the interval keeps it open.
        Ok(())
    })
}

/// Neither TLS configuration offers resumption, and the server sends no tickets: the
/// pin is the certificate verifier, a resumed session never reaches it, and a machine
/// whose trust was withdrawn must reach it on its next handshake.
///
/// This is the case that fails if either half is removed. rustls exposes no getter for
/// the resumption setting, so the client half is compared with the value
/// `Resumption::disabled()` itself renders as: any other resumption — the default
/// in-memory store, or one built by hand — renders differently, and a rename inside the
/// dependency changes both sides of the comparison equally. The withdrawal case beside
/// this one proves the outcome over a real handshake; this one proves the two settings
/// the outcome rests on, which a handshake cannot tell apart — a client with resumption
/// off and a server that sends tickets, or the reverse, would each still refuse a
/// resumption the other half never attempted.
pub(crate) fn the_tls_configurations_offer_no_resumption() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let (client, server) = sim.trusting_pair().map_err(io_error)?;
        let policy: Arc<dyn PeerPolicy> = Arc::new(TrustSet::default());
        let client = mahbot_peers::tls::client_config(&client.identity, Arc::clone(&policy), ALPN)
            .map_err(|error| error.to_string())?;
        let disabled = format!("{:?}", rustls::client::Resumption::disabled());
        // The comparison must be able to tell the two apart: if a future rustls rendered
        // the setting opaquely, both sides would read alike and the check would pass
        // without looking at anything.
        if disabled == format!("{:?}", rustls::client::Resumption::default()) {
            return Err(
                "the resumption setting renders the same whatever it holds, so this case cannot tell resumption from its absence"
                    .to_owned(),
            );
        }
        if format!("{:?}", client.resumption) != disabled {
            return Err(format!(
                "the client configuration resumes sessions ({:?}), so a withdrawn machine could resume past the pin",
                client.resumption
            ));
        }
        let server = mahbot_peers::tls::server_config(&server.identity, policy, ALPN)
            .map_err(|error| error.to_string())?;
        if server.send_tls13_tickets != 0 {
            return Err(format!(
                "the server configuration sends {} tickets, so a client could resume past the pin",
                server.send_tls13_tickets
            ));
        }
        Ok(())
    })
}
