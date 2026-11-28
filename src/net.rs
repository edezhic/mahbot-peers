//! Endpoint construction over two injected seams: a datagram socket and a clock.
//!
//! Neither seam is optional and neither has a default: the caller supplies both.

use std::fmt;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{AsyncUdpSocket, Endpoint, EndpointConfig, IdleTimeout, Runtime};

use crate::identity::Identity;
use crate::tls::{self, PeerPolicy, Refusal};

/// The name rustls is given for a peer connection. With raw public keys the name
/// is not what identifies the peer — the pinned fingerprint is — so it only has to
/// be a valid DNS name.
pub const SERVER_NAME: &str = "mahbot-peers";

/// How long a connection may sit idle before QUIC gives up on it.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// How often a quiet connection pings, by default.
///
/// A pair is mostly silent — the queue lives at the sender and a peer may have
/// nothing to say for days — so the default keeps the connection: a third of
/// [`DEFAULT_IDLE_TIMEOUT`], which leaves one lost ping before the timeout would
/// close it, and a peer that is really gone stops answering and is closed by that
/// timeout.
pub const DEFAULT_KEEP_ALIVE: Duration = Duration::from_secs(10);

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

/// How many bytes a peer may make this machine buffer on one connection: the
/// connection-level flow-control credit every stream on it draws on.
///
/// This is a receive window, not a promise about heap: quinn's own bookkeeping sits on top
/// of it, and it says what a peer can make this machine hold, not what this machine sends.
/// It is shared by everything the connection carries — messages, actions and file
/// transfers — so a stalled sink cannot take the credit a message needs.
///
/// Two transfers at [`MAX_STREAM_BYTES`] each account for half of it; the other half is
/// left to messages and actions, whose frames are a few kilobytes.
pub const MAX_BUFFERED_BYTES: usize = 32 * 1024 * 1024;

/// How many bytes a peer may make this machine buffer on one stream: the per-stream
/// credit a file transfer draws on.
///
/// It is also what this machine sends ahead of the peer's reading: quinn cannot buffer more
/// than the peer's advertised stream window, so with this crate on both sides a transfer
/// queues at most this much here. Eight mebibytes is one round trip's worth at 50 MB/s and
/// a 100 ms round trip, and two of them fit in [`MAX_BUFFERED_BYTES`] beside the messages.
pub const MAX_STREAM_BYTES: usize = 8 * 1024 * 1024;

/// How many streams one connection may carry at once.
///
/// Two file transfers, one message offer or action request per round each way, and room for
/// the binding exchange's stream. A peer that opens more is not refused: it is blocked for want
/// of credit, because this machine advertises room for this many and no more.
pub const MAX_STREAMS: u32 = 16;

/// Everything about an endpoint that is not a seam: the idle timeout, and how
/// often a quiet connection pings so it does not reach it.
///
/// The flow-control credit is not a field here: [`Self::endpoint`] sets it to
/// [`MAX_BUFFERED_BYTES`], [`MAX_STREAM_BYTES`] and [`MAX_STREAMS`] for every endpoint it
/// builds, so a product that constructs this struct as it always has gets the correct
/// numbers without asking. A product that builds its own [`quinn::TransportConfig`] gets
/// whatever it sets, and these bounds do not apply to it.
#[derive(Clone, Debug)]
pub struct Transport {
    /// How long a connection may carry nothing before QUIC gives up on it.
    ///
    /// The timeout that applies is the smaller of the two machines' values, so the
    /// shorter one governs both ends.
    pub idle_timeout: Duration,
    /// How often this machine pings a quiet connection, or `None` to send none.
    ///
    /// A value that is not shorter than [`Self::idle_timeout`] would not be effective.
    pub keep_alive: Option<Duration>,
}

impl Default for Transport {
    fn default() -> Self {
        Self {
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            // A quiet pair stays connected while either side pings: silence is the
            // normal case for this product, and a connection that dies of it has to be
            // re-dialled. A caller that wants the bare timeout states `None`.
            keep_alive: Some(DEFAULT_KEEP_ALIVE),
        }
    }
}

impl Transport {
    /// Build an endpoint that both accepts and initiates connections, pinned to
    /// `policy` in both directions.
    ///
    /// This sets the flow control a pair's connection carries — the memory bound and the
    /// throughput in one equation — and it is the transport a product should use. A product
    /// that builds its own `quinn::TransportConfig` decides those numbers itself; the bound
    /// stated here is what this one gives.
    ///
    /// The socket's own buffers are the caller's: the numbers above are what a peer may make
    /// this machine buffer in this crate, and the operating system's send and receive buffers
    /// sit on top of them. On a fast path they are the bottleneck — macOS defaults are far too
    /// small for a gigabit at a hundred milliseconds — so a product that wants the throughput
    /// sizes them where it makes the socket (`SO_SNDBUF`/`SO_RCVBUF`), which this crate cannot
    /// do for it because it never makes one.
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
        transport.keep_alive_interval(self.keep_alive);
        // The one equation behind the throughput and the memory bound: a peer may make
        // this machine buffer at most `MAX_BUFFERED_BYTES` on a connection, at most
        // `MAX_STREAM_BYTES` on one stream, and at most `MAX_STREAMS` streams at once.
        // Two transfers therefore account for half the connection's credit, and the rest
        // stays available to messages and actions, so a stalled sink cannot starve them.
        // The same numbers bound what this machine sends: `send_window` is the most of its own
        // writes quinn retains for the peer, so a peer that advertises an enormous window
        // cannot make this machine queue a file. `MAX_BUFFERED_BYTES` is not smaller than
        // `MAX_STREAM_BYTES`, which is what quinn recommends of the two: a stream window larger
        // than the connection's would let one stream take credit the connection does not have.
        let stream_window = u32::try_from(MAX_STREAM_BYTES)
            .expect("the stream window fits a QUIC variable integer");
        let connection_window = u32::try_from(MAX_BUFFERED_BYTES)
            .expect("the connection window fits a QUIC variable integer");
        transport.stream_receive_window(quinn::VarInt::from_u32(stream_window));
        transport.receive_window(quinn::VarInt::from_u32(connection_window));
        transport.send_window(connection_window.into());
        transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(MAX_STREAMS));
        // This crate sends no datagrams and opens no unidirectional stream on a pair's
        // connection: advertising room for either would reserve buffers nothing uses.
        transport.max_concurrent_uni_streams(quinn::VarInt::from_u32(0));
        transport.datagram_receive_buffer_size(None);
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
