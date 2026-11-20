//! Endpoint construction over two injected seams: a datagram socket and a clock.
//!
//! Neither seam is optional and neither has a default, so no code path can
//! quietly acquire a real socket or the wall clock. This crate enables no runtime
//! feature on `quinn`: a binary passes a real UDP socket and the runtime of its
//! choosing (quinn's `runtime-tokio`, enabled by the binary, or its own
//! `quinn::Runtime`), and the test harness passes an in-memory socket and a clock
//! the test drives.

use std::fmt;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{AsyncUdpSocket, Endpoint, EndpointConfig, IdleTimeout, Runtime};

use crate::identity::Identity;
use crate::tls::{self, PeerPolicy, Refusal};

/// How long a connection may sit idle before QUIC gives up on it.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// The refusal a failed connection reports, when it was refused for the key it
/// presented rather than for anything else.
///
/// The handshake can only answer with text, so this is where that text is turned
/// back into a reason: [`Refusal::OwnIdentity`] for a peer that presented this
/// machine's own key — a copy of the storage root — and [`Refusal::Untrusted`] for
/// a key this machine does not remember. `None` is a failure that is about
/// something else entirely: a timeout, a version mismatch, a closed endpoint.
///
/// It is diagnostic, in both directions. The decision was the verifier's and
/// cannot be revisited here; and the text may have been written by the far side —
/// a peer can close a connection with a reason that repeats one of our phrases.
/// So `OwnIdentity` read from a connection this machine did not itself refuse may
/// be another machine's claim: the value belongs in a log, and nothing
/// outward-facing (rights, trust, retries) may be decided on it.
#[must_use]
pub fn refusal(error: &quinn::ConnectionError) -> Option<Refusal> {
    let reason = match error {
        quinn::ConnectionError::TransportError(error) => Some(error.reason.as_str()),
        quinn::ConnectionError::ConnectionClosed(close) => std::str::from_utf8(&close.reason).ok(),
        quinn::ConnectionError::ApplicationClosed(close) => std::str::from_utf8(&close.reason).ok(),
        _ => None,
    };
    reason.and_then(Refusal::of)
}

/// Everything about an endpoint that is not a seam: today, the idle timeout.
#[derive(Clone, Debug)]
pub struct Transport {
    pub idle_timeout: Duration,
}

impl Default for Transport {
    fn default() -> Self {
        Self {
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
        }
    }
}

impl Transport {
    /// Build an endpoint that both accepts and initiates connections, pinned to
    /// `policy` in both directions.
    pub fn endpoint(
        &self,
        socket: Arc<dyn AsyncUdpSocket>,
        runtime: Arc<dyn Runtime>,
        me: &Identity,
        policy: Arc<dyn PeerPolicy>,
    ) -> Result<Endpoint, TransportError> {
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(
            IdleTimeout::try_from(self.idle_timeout).map_err(|_| TransportError::IdleTimeout)?,
        ));
        let transport = Arc::new(transport);
        // The crate builds the TLS configuration itself — TLS 1.3 only, with the
        // ring provider — so an initial cipher suite always exists and this
        // conversion cannot fail.
        let server_tls =
            QuicServerConfig::try_from(tls::server_config(me, Arc::clone(&policy), tls::ALPN)?)
                .expect("the crate's TLS 1.3 configuration has an initial cipher suite");
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(server_tls));
        server.transport_config(Arc::clone(&transport));
        let client_tls =
            QuicClientConfig::try_from(Arc::new(tls::client_config(me, policy, tls::ALPN)?))
                .expect("the crate's TLS 1.3 configuration has an initial cipher suite");
        let mut client = quinn::ClientConfig::new(Arc::new(client_tls));
        client.transport_config(transport);
        let mut endpoint = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            Some(server),
            socket,
            runtime,
        )?;
        endpoint.set_default_client_config(client);
        Ok(endpoint)
    }
}

/// Why an endpoint could not be built.
#[derive(Debug)]
pub enum TransportError {
    Io(io::Error),
    Tls(rustls::Error),
    IdleTimeout,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "socket: {error}"),
            Self::Tls(error) => write!(f, "tls: {error}"),
            Self::IdleTimeout => f.write_str("idle timeout does not fit a QUIC variable integer"),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<io::Error> for TransportError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rustls::Error> for TransportError {
    fn from(error: rustls::Error) -> Self {
        Self::Tls(error)
    }
}
