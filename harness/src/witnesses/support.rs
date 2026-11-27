//! Helpers shared by the cases in this module tree.

use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use mahbot_peers::identity::PeerId;
use mahbot_peers::peer::{
    Account, Binding, ConnectFailure, Connections, Floor, Instance, Label, Pair, Presence,
    Recovery, Registration, StopCause,
};
use mahbot_peers::tls::PeerPolicy;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::udp::RecvMeta;
use quinn::{AsyncUdpSocket, Connection, Endpoint, EndpointConfig};

use crate::beacon::TestBeacon;
use crate::invariants::Source;
use crate::machine::Machine;
use crate::messages::Messaging;
use crate::sim::Sim;

use super::connection::Managed;
use super::peer::NOW;
use super::rights::{label, paired_machines, wait_claim};

pub(crate) fn io_error(error: io::Error) -> String {
    error.to_string()
}

/// One field as the format writes it: a tag, a two-byte length and the body.
pub(super) fn field(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(
        &u16::try_from(body.len())
            .expect("a field this case writes is short")
            .to_be_bytes(),
    );
    out.extend_from_slice(body);
    out
}

/// Whether `haystack` holds `needle` verbatim.
pub(super) fn holds_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// Run a machine's presence and wait until the beacon holds its registration.
///
/// A running machine keeps itself findable: the presence registers by itself and stays
/// registered until it is dropped. A case that needs it registered before the next step asks here
/// rather than guessing how many scheduler turns a handshake and a registration take.
///
/// One `Presence` per machine per case: a second one would displace the first's registration, and
/// that is the very thing the presence exists to prevent. A machine that restarts gets a new
/// endpoint, so its presence is rebuilt after the restart.
pub(super) async fn keep_findable(
    sim: &Sim,
    beacon: &TestBeacon,
    machine: &Machine,
) -> Result<Presence, String> {
    let presence = Presence::new(beacon.client(machine)?);
    let registry = beacon.registry();
    let peer = machine.peer_id();
    within(sim, Duration::from_secs(120), async {
        loop {
            let held = registry
                .lock()
                .expect("the beacon registry is not poisoned")
                .snapshot()
                .iter()
                .any(|(id, _)| *id == peer);
            if held && presence.state() == Registration::Registered {
                return Ok::<(), String>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    Ok(presence)
}

/// Await the moment the pair's recovery counts one dial that met the connection which
/// carried nothing, and answer how many dials the episode had made.
///
/// The state shows it for the length of the gap that follows, so a case that samples once a
/// poll finds it; an episode that is used up at once is the same answer.
pub(super) async fn counted_dial(
    sim: &Sim,
    connections: &Connections,
    peer: &PeerId,
) -> Result<u32, String> {
    let mut spent = Duration::ZERO;
    loop {
        match connections.recovery(peer) {
            // Only a failed dial writes a network failure, and it always counts the dial, so
            // this pattern cannot match an episode that has dialled nothing.
            Recovery::Waiting {
                dial,
                last: Some(ConnectFailure::NoDirectPath { .. }),
                ..
            } => return Ok(dial),
            Recovery::Exhausted { dials, .. } => return Ok(dials),
            _ => {}
        }
        if spent >= Duration::from_secs(120) {
            return Err(format!(
                "the pair never counted a dial that met a connection which carried nothing: \
                 it reads `{}` after {spent:?}",
                connections.recovery(peer)
            ));
        }
        // The state shows the counted dial for the length of the gap that follows, so a
        // step of a tenth of the first gap finds it without spending the case's poll budget.
        sim.clock().advance(Duration::from_millis(100)).await;
        tokio::task::yield_now().await;
        spent += Duration::from_millis(100);
    }
}

/// The one service a case started, and how it ended, within `budget` of virtual time.
///
/// The budget is the case's: a refusal the service's own round meets arrives within a round
/// or two, so a case that wants to show *which* path met it asks for seconds, and a case that
/// only cares that it ended asks for more.
pub(super) async fn single_ending(
    sim: &Sim,
    messaging: &Messaging,
    budget: Duration,
) -> Result<Result<(), String>, String> {
    let endings = within(sim, budget, messaging.endings()).await?;
    let [ending] = &endings[..] else {
        return Err(format!(
            "the case started {} services, not one",
            endings.len()
        ));
    };
    Ok(ending.clone())
}

/// The connection level a machine records for `peer`, with its own account, instance and
/// assistant: the two sides of a case never share one, so a claim that arrived is always
/// the peer's.
pub(super) fn binding(account: &str, instance: &str, assistant: &Label) -> Result<Binding, String> {
    Ok(Binding::new(
        Account::new(account).map_err(|error| error.to_string())?,
        Instance::new(instance).map_err(|error| error.to_string())?,
        assistant.clone(),
        NOW,
    ))
}

/// The same, for the machine a case calls the main one: its own account and instance, and
/// the assistant the case names.
pub(super) fn main_binding(assistant: &Label) -> Result<Binding, String> {
    binding("main-account", "main-instance", assistant)
}

/// The pair a machine's binding of `peer` names.
pub(super) fn pair(peer: &Machine, assistant: &Label) -> Pair {
    Pair::new(peer.peer_id(), assistant)
}

/// Run the manager's keeper for `peer` on its own task, as a product does.
pub(super) fn spawn_keeper(
    managed: &Managed,
    peer: &Machine,
) -> tokio::task::JoinHandle<StopCause> {
    let connections = Arc::clone(&managed.connections);
    let endpoint = managed.endpoint.clone();
    let peer = peer.fingerprint();
    tokio::spawn(async move { connections.keep_connected(&endpoint, &peer).await })
}

/// The pieces one connected case needs, all live.
///
/// The manager owns the endpoint and the accept loop, so it lives as long as the case
/// does; the message layers are the machines' own, and the keeper is the dialling
/// side's, spawned once. The layers' services are the case's to start: a case that has
/// to change a right or queue something first does it before the service runs.
pub(super) struct Ready {
    pub(super) main: Machine,
    pub(super) laptop: Machine,
    pub(super) main_managed: Managed,
    pub(super) laptop_managed: Managed,
    pub(super) main_messages: Messaging,
    pub(super) laptop_messages: Messaging,
    pub(super) keeper: tokio::task::JoinHandle<StopCause>,
}

/// Two paired machines, connected, with a message layer on each and nothing bound.
///
/// `floor` is the host's own say over what it allows at all, for both machines' layers:
/// `NoFloor` unless a case has a host that refuses. The laptop dials, so the case has one
/// keeper and one dialling direction to reason about.
pub(super) async fn connected(
    sim: &Sim,
    beacon: &TestBeacon,
    floor: Arc<dyn Floor + Send + Sync>,
) -> Result<Ready, String> {
    let (main, laptop) = paired_machines(sim)?;
    connect(sim, beacon, main, laptop, floor).await
}

/// Two paired machines, connected, with a message layer on each and the main bound to the
/// laptop.
///
/// `bind_laptop` binds the other way round as well. The laptop dials, so the case has one
/// keeper and one dialling direction to reason about.
pub(super) async fn ready(
    sim: &Sim,
    beacon: &TestBeacon,
    bind_laptop: bool,
    floor: Arc<dyn Floor + Send + Sync>,
) -> Result<Ready, String> {
    let (main, laptop) = paired_machines(sim)?;
    main.rights()?
        .bind(&laptop.peer_id(), main_binding(&label("admin")?)?, NOW)
        .map_err(|error| error.to_string())?;
    if bind_laptop {
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
    }
    let ready = connect(sim, beacon, main, laptop, floor).await?;
    if !bind_laptop {
        wait_claim(
            sim,
            &ready.laptop.reopen_records()?,
            &ready.main.peer_id(),
            None,
        )
        .await?;
    }
    Ok(ready)
}

/// The connection itself: managers, layers, keeper, and both sides' exchange.
async fn connect(
    sim: &Sim,
    beacon: &TestBeacon,
    main: Machine,
    laptop: Machine,
    floor: Arc<dyn Floor + Send + Sync>,
) -> Result<Ready, String> {
    let main_managed = Managed::start(sim, beacon, &main, &main.records())?;
    let laptop_managed = Managed::start(sim, beacon, &laptop, &laptop.records())?;
    let main_messages = Messaging::open(sim, &main, Arc::clone(&floor))?;
    let laptop_messages = Messaging::open(sim, &laptop, floor)?;
    let keeper = spawn_keeper(&laptop_managed, &main);
    // Both sides must hold the connection and have finished the exchange before the
    // case speaks of either: the exchange is what makes the pair's "write to me" reach
    // the side that did not decide it.
    wait_live(sim, &main_managed.connections, &laptop.peer_id()).await?;
    wait_live(sim, &laptop_managed.connections, &main.peer_id()).await?;
    Ok(Ready {
        main,
        laptop,
        main_managed,
        laptop_managed,
        main_messages,
        laptop_messages,
        keeper,
    })
}

/// Wait until `peer`'s pair holds a live connection whose binding exchange has finished,
/// and hand it back.
///
/// The exchange owns the first stream a kept connection carries, so a case that offers
/// by hand waits for it: its own stream would otherwise be taken for the exchange's.
pub(super) async fn wait_live(
    sim: &Sim,
    connections: &mahbot_peers::peer::Connections,
    peer: &PeerId,
) -> Result<Connection, String> {
    within(sim, Duration::from_secs(120), async {
        loop {
            if let Some(traffic) = connections.traffic(peer)
                && traffic.exchange_done()
            {
                return Ok::<Connection, String>(traffic.connection().clone());
            }
            tokio::task::yield_now().await;
        }
    })
    .await?
}

/// Prove the connection carries application data: open one bidirectional stream, write a
/// few bytes and finish it. The far side need not read it.
///
/// The write is answered locally the moment quinn buffers it, so the proof is the wait
/// after it: [`quinn::SendStream::stopped`] resolves when the peer's transport has
/// acknowledged every byte, which a connection that carries nothing never does. A case
/// bounds that wait with [`within`], like any other await that may never resolve.
pub(crate) async fn carries(connection: &quinn::Connection) -> Result<(), String> {
    let (mut send, _recv) = connection
        .open_bi()
        .await
        .map_err(|error| format!("the connection opened no stream: {error}"))?;
    send.write_all(TRAFFIC)
        .await
        .map_err(|error| format!("the stream took no bytes: {error}"))?;
    send.finish()
        .map_err(|error| format!("the stream could not be finished: {error}"))?;
    send.stopped()
        .await
        .map_err(|error| format!("the peer never acknowledged the stream: {error}"))?;
    Ok(())
}

/// The bytes [`carries`] writes: enough to be a stream frame, few enough to fit any
/// window.
const TRAFFIC: &[u8] = b"traffic";

/// Write a word on `client`'s half of a connection and read it on `server`'s.
///
/// [`carries`] proves a connection takes data; this proves the two halves a case holds are one
/// connection and not two that merely share an address, which is what a case about a dialer
/// receiving the wrong half has to show.
///
/// A connection a manager keeps carries the manager's own binding exchange first, on the half
/// that accepted it, so a case that round-trips such a connection waits for
/// [`Connections::traffic`] to report the exchange done before it accepts: the exchange's stream
/// is not the word.
pub(crate) async fn round_trip(client: &Connection, server: &Connection) -> Result<(), String> {
    let (mut send, _recv) = client
        .open_bi()
        .await
        .map_err(|error| format!("the connection opened no stream: {error}"))?;
    send.write_all(TRAFFIC)
        .await
        .map_err(|error| format!("the stream took no bytes: {error}"))?;
    send.finish()
        .map_err(|error| format!("the stream could not be finished: {error}"))?;
    let (_, mut recv) = server
        .accept_bi()
        .await
        .map_err(|error| format!("the other half accepted no stream: {error}"))?;
    let read = recv
        .read_to_end(TRAFFIC.len())
        .await
        .map_err(|error| format!("the other half read nothing: {error}"))?;
    if read != TRAFFIC {
        return Err(format!(
            "the other half read {} bytes that are not the word written on the first",
            read.len()
        ));
    }
    Ok(())
}

/// Offer one frame's bytes over `connection` and read up to `limit` bytes of the answer,
/// so a case can send a frame the typed layer would not produce.
pub(super) async fn offer_frame(
    connection: &Connection,
    bytes: &[u8],
    limit: usize,
) -> Result<Vec<u8>, String> {
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|error| error.to_string())?;
    send.write_all(bytes)
        .await
        .map_err(|error| error.to_string())?;
    send.finish().map_err(|error| error.to_string())?;
    recv.read_to_end(limit)
        .await
        .map_err(|error| error.to_string())
}

/// How much virtual time one request may take before a case fails instead of
/// hanging: every case's budget for an await that may never resolve.
pub(crate) const BUDGET: Duration = Duration::from_secs(10);

pub(crate) fn socket(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

pub(crate) fn source(path: &str, text: &str) -> Source {
    Source {
        path: path.to_owned(),
        text: text.to_owned(),
    }
}

/// Await `future` while the clock moves, so a transport that never answers fails
/// the case instead of hanging it: the poll budget only stops a case that spins
/// without parking.
pub(crate) async fn within<F: Future>(
    sim: &Sim,
    budget: Duration,
    future: F,
) -> Result<F::Output, String> {
    sim.clock()
        .drive(budget, future)
        .await
        .ok_or_else(|| format!("no answer within {budget:?} of virtual time"))
}

/// A private temporary directory for a case that needs a storage root of its own
/// without a simulated world around it: the key-file cases.
pub(crate) fn temp_root() -> Result<tempfile::TempDir, String> {
    crate::root::identity_dir().map_err(io_error)
}

/// A machine's server-side TLS configuration, pinning the peers it trusts.
pub(crate) fn server_tls(machine: &Machine) -> Result<rustls::ServerConfig, String> {
    let policy: Arc<dyn PeerPolicy> = Arc::clone(&machine.trust) as Arc<dyn PeerPolicy>;
    mahbot_peers::tls::server_config(&machine.identity, policy, mahbot_peers::tls::ALPN)
        .map_err(|error| error.to_string())
}

/// An endpoint over a machine's own socket, carrying a TLS configuration the case
/// built: the server side of a case that has to change something.
pub(crate) fn endpoint_over(
    sim: &Sim,
    machine: &Machine,
    tls: rustls::ServerConfig,
) -> Result<Endpoint, String> {
    let crypto = QuicServerConfig::try_from(tls)
        .map_err(|error| format!("the case's TLS configuration was refused: {error:?}"))?;
    Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        Some(quinn::ServerConfig::with_crypto(Arc::new(crypto))),
        Arc::clone(&machine.socket) as Arc<dyn AsyncUdpSocket>,
        sim.clock().runtime(),
    )
    .map_err(|error| error.to_string())
}

/// Everything queued on a link socket, oldest first.
///
/// Only for a socket no transport drives: polling with a no-op waker replaces
/// whatever waker was registered, which would strand a quinn driver task.
pub(crate) fn drain(socket: &crate::link::LinkedSocket) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let mut buffer = [0u8; 256];
        let mut meta = [RecvMeta::default(); 1];
        let len = {
            let mut buffers = [io::IoSliceMut::new(&mut buffer)];
            let mut context = Context::from_waker(Waker::noop());
            match socket.poll_recv(&mut context, &mut buffers, &mut meta) {
                Poll::Ready(Ok(1)) => meta[0].len,
                _ => return out,
            }
        };
        out.push(buffer[..len].to_vec());
    }
}
