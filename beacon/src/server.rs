//! The QUIC side: accept a connection, prove who is calling, answer one frame per
//! stream, and push introductions to live connections.
//!
//! The endpoint, the runtime and the clock are the caller's — this module creates
//! no socket, spawns on no ambient executor and reads no clock of its own — so the
//! same loop runs against a real UDP socket in the binary and against the
//! harness's simulated link in a test.
//!
//! Every wait for a peer's next message is bounded by the injected runtime's
//! timer: a half-open handshake, a peer that opens a stream and never finishes its
//! frame, a recipient that never reads what is pushed to it, and an answer that
//! cannot be written all end at [`EXCHANGE_TIMEOUT`] instead of holding a
//! connection slot or parking a task for the life of the process. A stalled
//! recipient therefore cannot stall the sender's own request loop, which is what
//! keeps a registration refreshable. The accept loop itself waits for the next
//! stream of a live connection for as long as that connection lives, which is what
//! a connection is for.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use mahbot_peers::beacon::timeout;
use mahbot_peers::beacon::wire;
use mahbot_peers::beacon::{BeaconError, Frame, Refusal, Request, Response};
use mahbot_peers::identity::{Fingerprint, PeerId};
use quinn::{Connection, Endpoint, RecvStream, Runtime, SendStream};
use rustls::pki_types::CertificateDer;

use crate::clock::Clock;
use crate::core::{Action, ConnectionId, Registry};

/// How long one exchange may take: reading a request, writing an answer, or
/// handing a frame to a recipient. The runtime's timer measures it, so a test
/// moves it and the server never reads a clock of its own. An introduction passes
/// through all three in sequence, so the client's request bound is more than three
/// times this one and a live but slow beacon is not reported as dead; the
/// harness's recorded case `deadlines_are_ordered` pins the ordering.
pub const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(3);

/// The most connections the beacon serves at once, handshakes in flight included.
/// The beacon is the only internet-facing piece of the design, so what it keeps is
/// capped rather than left to whatever arrives.
pub const DEFAULT_MAX_CONNECTIONS: usize = 1024;

/// The beacon, bound to one endpoint, one runtime and one clock.
pub struct BeaconServer {
    endpoint: Endpoint,
    shared: Arc<Shared>,
    max_connections: usize,
}

/// What the accept loop and every task it spawns share.
struct Shared {
    runtime: Arc<dyn Runtime>,
    clock: Arc<dyn Clock>,
    registry: Arc<Mutex<Registry>>,
    connections: Arc<Mutex<HashMap<ConnectionId, Connection>>>,
}

impl BeaconServer {
    /// Serve on an endpoint the caller built, over a registry the caller can
    /// inspect. The endpoint carries the beacon's TLS configuration, so its key
    /// is the key clients pin; the runtime is where every task is spawned.
    #[must_use]
    pub fn new(
        endpoint: Endpoint,
        runtime: Arc<dyn Runtime>,
        clock: Arc<dyn Clock>,
        registry: Arc<Mutex<Registry>>,
    ) -> Self {
        Self {
            endpoint,
            shared: Arc::new(Shared {
                runtime,
                clock,
                registry,
                connections: Arc::new(Mutex::new(HashMap::new())),
            }),
            max_connections: DEFAULT_MAX_CONNECTIONS,
        }
    }

    /// Serve at most `max` connections at once; a further one is refused.
    #[must_use]
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// Accept and serve until the endpoint closes.
    ///
    /// Each incoming connection is handed to its own task before its handshake is
    /// awaited, so a peer that stalls mid-handshake cannot delay the next one; the
    /// handshake itself is bounded, so it cannot hold its slot either.
    pub async fn run(self) {
        let shared = self.shared;
        let serving = Arc::new(AtomicUsize::new(0));
        let mut next = 0u64;
        while let Some(incoming) = self.endpoint.accept().await {
            if serving.load(Ordering::Relaxed) >= self.max_connections {
                incoming.refuse();
                continue;
            }
            serving.fetch_add(1, Ordering::Relaxed);
            let id = ConnectionId(next);
            next += 1;
            let slot = Slot(Arc::clone(&serving));
            let shared = Arc::clone(&shared);
            let runtime = Arc::clone(&shared.runtime);
            runtime.spawn(Box::pin(async move {
                let _slot = slot;
                // quinn has no handshake timeout of its own: without this bound a
                // peer that sends an Initial and walks away holds its slot until
                // the idle timeout, and enough of them deny service. quinn offers
                // no way to abort a half-open connection, so its transport state
                // stays until that timeout; the slot — what the cap protects — is
                // released here, and a handshake that completes after this point
                // is never served.
                let Some(Ok(connection)) =
                    timeout(&*shared.runtime, EXCHANGE_TIMEOUT, async move {
                        incoming.accept()?.await
                    })
                    .await
                else {
                    return;
                };
                let Some(caller) = caller_of(&connection) else {
                    connection.close(0u32.into(), b"no identity");
                    return;
                };
                lock(&shared.connections).insert(id, connection.clone());
                serve(&shared, connection, caller, id).await;
            }));
        }
    }
}

/// Hold one connection's place in the cap until its task ends, whatever ended it.
struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn serve(shared: &Arc<Shared>, connection: Connection, caller: PeerId, id: ConnectionId) {
    let alive = Arc::new(AtomicBool::new(true));
    loop {
        let Ok((send, recv)) = connection.accept_bi().await else {
            break;
        };
        // One stream, one task: a peer that opens a stream and stalls it holds
        // only that task, not the loop that serves its registration refresh.
        let shared = Arc::clone(shared);
        let connection = connection.clone();
        let runtime = Arc::clone(&shared.runtime);
        let alive = Arc::clone(&alive);
        runtime.spawn(Box::pin(async move {
            exchange(&shared, &connection, &alive, caller, id, send, recv).await;
        }));
    }
    // A stream accepted just before the close may still be read by its task after
    // this point. The flag is set before the disconnect, and `handle` reads it
    // under the registry lock, so an exchange either sees the connection gone or
    // has its registration removed by the disconnect that follows.
    alive.store(false, Ordering::Release);
    lock(&shared.registry).disconnect(id);
    lock(&shared.connections).remove(&id);
}

async fn exchange(
    shared: &Arc<Shared>,
    connection: &Connection,
    alive: &AtomicBool,
    caller: PeerId,
    id: ConnectionId,
    mut send: SendStream,
    mut recv: RecvStream,
) {
    let frame = match timeout(&*shared.runtime, EXCHANGE_TIMEOUT, Frame::read(&mut recv)).await {
        Some(Ok(frame)) => frame,
        // A reset or a lost connection is a dead exchange: there is nobody left
        // to answer, and a refusal would be written into a closed stream.
        Some(Err(BeaconError::Unavailable)) => return,
        Some(Err(_)) => {
            answer(shared, &mut send, Response::Refused(Refusal::Malformed)).await;
            return;
        }
        None => {
            answer(shared, &mut send, Response::Refused(Refusal::Slow)).await;
            return;
        }
    };
    match handle(shared, connection, alive, caller, id, &frame) {
        Some(Action::Reply(response)) => answer(shared, &mut send, response).await,
        Some(Action::Deliver {
            connection: target,
            peer,
            frame,
        }) => relay(shared, send, target, peer, frame),
        None => {}
    }
}

fn handle(
    shared: &Shared,
    connection: &Connection,
    alive: &AtomicBool,
    caller: PeerId,
    id: ConnectionId,
    frame: &Frame,
) -> Option<Action> {
    if frame.require_version().is_err() {
        return Some(Action::Reply(Response::Refused(Refusal::VersionMismatch)));
    }
    let request = match Request::decode(frame) {
        Ok(request) => request,
        Err(BeaconError::UnknownMessage(_)) => {
            return Some(Action::Reply(Response::Refused(Refusal::UnknownMessage)));
        }
        Err(BeaconError::PayloadTooLarge(_)) => {
            return Some(Action::Reply(Response::Refused(Refusal::PayloadTooLarge)));
        }
        Err(_) => return Some(Action::Reply(Response::Refused(Refusal::Malformed))),
    };
    // The liveness check and the insert happen under the same lock the
    // disconnect takes, so a request read on a connection that has just gone is
    // dropped instead of registering an id nothing can reach.
    let mut registry = lock(&shared.registry);
    if !alive.load(Ordering::Acquire) {
        return None;
    }
    Some(registry.handle(
        caller,
        id,
        connection.remote_address(),
        shared.clock.now(),
        request,
    ))
}

/// Hand one frame to a live connection, then answer the sender, in a task of its
/// own: the sender's loop goes straight back to serving its own requests.
///
/// The write is bounded by [`EXCHANGE_TIMEOUT`]. A recipient that never reads its
/// streams stops granting stream credit, so a push that cannot complete answers
/// `UnknownPeer` — never leaving the sender waiting on a third party. Nothing is
/// forgotten: the recipient's registration is its own, and a failed push says
/// nothing about whether it is still there. `Delivered` means the frame was written
/// to the recipient's connection, not that its application read it: delivery is
/// at-least-once, and idempotency belongs to whatever the payload sets up.
fn relay(
    shared: &Arc<Shared>,
    mut send: SendStream,
    target: ConnectionId,
    peer: PeerId,
    frame: Vec<u8>,
) {
    let shared = Arc::clone(shared);
    let runtime = Arc::clone(&shared.runtime);
    runtime.spawn(Box::pin(async move {
        let recipient = lock(&shared.connections).get(&target).cloned();
        let delivered = match recipient {
            Some(recipient) => {
                timeout(&*shared.runtime, EXCHANGE_TIMEOUT, push(&recipient, &frame)).await
                    == Some(Ok(()))
            }
            None => false,
        };
        let response = if delivered {
            Response::Delivered
        } else {
            Response::UnknownPeer(peer)
        };
        answer(&shared, &mut send, response).await;
    }));
}

/// Write one answer, bounded: a peer that never reads cannot park the task.
async fn answer(shared: &Shared, send: &mut SendStream, response: Response) {
    let bytes = response.encode();
    let _ = timeout(
        &*shared.runtime,
        EXCHANGE_TIMEOUT,
        wire::write(send, &bytes),
    )
    .await;
}

async fn push(connection: &Connection, frame: &[u8]) -> Result<(), ()> {
    let mut send = connection.open_uni().await.map_err(|_| ())?;
    send.write_all(frame).await.map_err(|_| ())?;
    send.finish().map_err(|_| ())
}

/// The caller's id, as the handshake proved it. Under raw public keys the single
/// certificate is the 44-byte SubjectPublicKeyInfo, so the id is the key inside
/// it — never a value the request carried.
fn caller_of(connection: &Connection) -> Option<PeerId> {
    let identity = connection.peer_identity()?;
    let certificates = identity.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    let spki = certificates.first()?;
    Fingerprint::from_spki(spki.as_ref()).map(|fingerprint| fingerprint.peer_id())
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().expect("beacon state is not poisoned")
}
