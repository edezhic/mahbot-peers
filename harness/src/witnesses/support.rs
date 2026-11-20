//! Helpers shared by the cases in this module tree.

use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use mahbot_peers::tls::PeerPolicy;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::udp::RecvMeta;
use quinn::{AsyncUdpSocket, Endpoint, EndpointConfig};

use crate::invariants::Source;
use crate::machine::Machine;
use crate::sim::Sim;

pub(crate) fn io_error(error: io::Error) -> String {
    error.to_string()
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
