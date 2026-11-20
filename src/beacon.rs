//! The beacon: the one global service, as the protocol and the client see it.
//!
//! The beacon helps machines find each other and tells a machine how it appears
//! from outside. It remembers, in memory and for a short lifetime, where an id
//! currently is; it hands one opaque payload from one machine to another while
//! they are both present; and it answers with the address it observes on the
//! connection the question arrived over. It never sees conversation bytes,
//! accounts, rights or authorship, it keeps no state on disk, and it has no say in
//! whether a connection is allowed.
//!
//! Two properties are structural rather than promised. Registration is bound to
//! the caller's key as the TLS handshake proved it — no frame carries an id — and
//! the address recorded is the one the beacon observes on the caller's path, not
//! one the caller names. An introduction is signed by its sender over both ids
//! and the payload, so a relay that rewrites any of them is refused by the
//! recipient; the beacon cannot make a payload arrive under another id.
//!
//! The server is a separate crate the product never runs and never ships: the
//! product pins the beacon's address and key and speaks [`client`] to it. The
//! server's TLS configuration therefore lives with the server, not here.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use crate::identity::{Fingerprint, Identity, PEER_ID_LEN, PeerId, SIGNATURE_LEN};
use crate::tls::{self, PeerPolicy};

pub mod client;
mod time;
pub mod wire;

pub use client::{Beacon, Session};
pub use wire::{Frame, MAX_FRAME_BYTES, PROTOCOL_VERSION, Push, Refusal, Request, Response};

/// The beacon's own protocol, distinct from the peer layer's: a connection
/// offered to one must not complete on the other.
///
/// The version is not in this name. It travels in every frame, so a change to
/// the message set is a refusal the client can name — "the beacon speaks 2, this
/// client speaks 1" — rather than a handshake failure that reads as a generic
/// transport error.
pub const ALPN: &[u8] = b"mahbot-beacon";

/// The name rustls is given for a beacon connection. With raw public keys the
/// name is not what identifies the service — the pinned key is — so it only has
/// to be a valid DNS name.
pub const SERVER_NAME: &str = "mahbot-beacon";

/// The largest opaque payload one introduction carries. Bigger ones are refused,
/// not stored or relayed: an introduction is a key exchange, not a message
/// channel.
pub const MAX_PAYLOAD_BYTES: usize = 8 * 1024;

/// How long a beacon connection may sit idle. A session pings every
/// [`BEACON_KEEP_ALIVE`], so an inactive but otherwise healthy connection — and the
/// NAT binding under it — is not dropped; a peer that is gone stops answering and
/// is cleaned up when this expires. A registration's own lifetime is separate: it
/// is refreshed by a request, not by the transport.
pub const BEACON_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// How often a session pings, so an idle session keeps its connection and its NAT
/// binding.
pub const BEACON_KEEP_ALIVE: Duration = Duration::from_secs(10);

/// How long one request may wait for its answer. The transport's idle timeout is
/// not a substitute: a request already sent to a beacon that is gone would wait
/// out the whole idle timeout, and the caller needs that failure named sooner. The
/// server's own bound per exchange is smaller, so a live but slow beacon is never
/// reported as dead.
pub const BEACON_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// The most streams one side may have open to the other at once. It bounds the
/// beacon's per-connection state, and it is the number of introductions a
/// recipient can leave unread before the beacon's next push has to wait for
/// credit.
pub const MAX_CONCURRENT_STREAMS: u32 = 16;

/// The domain separator of an introduction's signature.
const INTRODUCTION_DOMAIN: &[u8] = b"mahbot-peers introduction v1";

/// Why the beacon, or a session with it, refused something.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum BeaconError {
    /// The service is not running, or the connection to it is gone.
    Unavailable,
    /// The addressee is not reachable at this moment, so nothing was stored.
    UnknownPeer(PeerId),
    /// The payload is larger than [`MAX_PAYLOAD_BYTES`].
    PayloadTooLarge(usize),
    /// The peer speaks another protocol version. It names both, so a caller can
    /// report a mismatch instead of retrying a frame the peer cannot read.
    VersionMismatch { beacon: u8, client: u8 },
    /// The kind is not in the message set, or was sent in the wrong direction.
    UnknownMessage(u8),
    /// A frame or body is not what its kind implies.
    Malformed,
    /// The beacon refused the request and named why.
    Refused(Refusal),
    /// An introduction arrived under an id whose key did not sign it. The
    /// recipient refuses it; the beacon cannot repair it.
    UnauthenticatedIntroduction { from: PeerId },
    /// The beacon answered with a message this request does not expect. The name
    /// is the answer's, so a caller can see what it got instead.
    Unexpected(&'static str),
    /// The connection, handshake or TLS configuration failed. The message is the
    /// transport's.
    Transport(String),
}

impl fmt::Display for BeaconError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => f.write_str("the beacon is unavailable"),
            Self::UnknownPeer(id) => write!(f, "peer {} is not reachable", id.fingerprint()),
            Self::PayloadTooLarge(len) => write!(
                f,
                "an introduction of {len} bytes exceeds {MAX_PAYLOAD_BYTES}"
            ),
            Self::VersionMismatch { beacon, client } => write!(
                f,
                "the beacon speaks version {beacon}, this client speaks {client}"
            ),
            Self::UnknownMessage(kind) => write!(f, "{kind:#04x} is not a beacon message"),
            Self::Malformed => f.write_str("the beacon frame is malformed"),
            Self::Refused(refusal) => write!(f, "the beacon refused the request: {refusal:?}"),
            Self::UnauthenticatedIntroduction { from } => {
                write!(
                    f,
                    "an introduction claiming to be from {} is not signed by it",
                    from.fingerprint()
                )
            }
            Self::Unexpected(answer) => {
                write!(
                    f,
                    "the beacon answered {answer}, which this request does not expect"
                )
            }
            Self::Transport(error) => write!(f, "transport: {error}"),
        }
    }
}

impl std::error::Error for BeaconError {}

/// One opaque blob handed to a peer, with the ids that frame it and the sender's
/// signature over all three.
///
/// The payload is never read here. [`Introduction::is_authentic`] is what makes
/// the `from` field believable: the signature covers both ids and the payload, so
/// neither the beacon nor anyone else on the path can re-attribute or alter it.
///
/// The signature proves who sent it and that it was not altered; it does not
/// prove freshness. A relay can replay an old introduction, and the ceremony must
/// tolerate that — its fresh values are what make a replayed transcript fail to
/// match, not this signature.
#[derive(Clone, PartialEq, Eq)]
pub struct Introduction {
    from: PeerId,
    to: PeerId,
    signature: [u8; SIGNATURE_LEN],
    payload: Vec<u8>,
}

impl Introduction {
    /// Build an introduction from its wire parts, refusing an oversized payload.
    ///
    /// # Errors
    ///
    /// [`BeaconError::PayloadTooLarge`] with the payload's length.
    pub fn new(
        from: PeerId,
        to: PeerId,
        signature: [u8; SIGNATURE_LEN],
        payload: Vec<u8>,
    ) -> Result<Self, BeaconError> {
        check_payload_len(payload.len())?;
        Ok(Self {
            from,
            to,
            signature,
            payload,
        })
    }

    /// Build and sign an introduction from `signer` to `to`.
    ///
    /// # Errors
    ///
    /// [`BeaconError::PayloadTooLarge`] with the payload's length.
    pub fn signed(signer: &Identity, to: PeerId, payload: Vec<u8>) -> Result<Self, BeaconError> {
        let from = signer.peer_id();
        let signature = signer.sign(&transcript(&from, &to, &payload));
        Self::new(from, to, signature, payload)
    }

    /// Who sent it.
    #[must_use]
    pub const fn from(&self) -> PeerId {
        self.from
    }

    /// Who it is for.
    #[must_use]
    pub const fn to(&self) -> PeerId {
        self.to
    }

    /// The sender's signature over `from`, `to` and the payload.
    #[must_use]
    pub const fn signature(&self) -> &[u8; SIGNATURE_LEN] {
        &self.signature
    }

    /// The opaque bytes. The beacon never reads them.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Whether `from`'s key signed this exact introduction.
    #[must_use]
    pub fn is_authentic(&self) -> bool {
        self.from.verify(
            &transcript(&self.from, &self.to, &self.payload),
            &self.signature,
        )
    }
}

impl fmt::Debug for Introduction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Introduction")
            .field("from", &self.from)
            .field("to", &self.to)
            .field("payload_len", &self.payload.len())
            .finish_non_exhaustive()
    }
}

/// What an introduction's signature covers. Both ids are in the transcript: with
/// only the payload, a relay could re-attribute an introduction or forward one
/// meant for another machine.
fn transcript(from: &PeerId, to: &PeerId, payload: &[u8]) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(INTRODUCTION_DOMAIN.len() + 2 * PEER_ID_LEN + 4 + payload.len());
    message.extend_from_slice(INTRODUCTION_DOMAIN);
    message.extend_from_slice(from.as_bytes());
    message.extend_from_slice(to.as_bytes());
    message.extend_from_slice(
        &u32::try_from(payload.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    message.extend_from_slice(payload);
    message
}

/// The one definition of the payload cap: the checked constructor and the frame
/// decoder both ask here, so the sender and the verifier cannot disagree about
/// what is too large.
fn check_payload_len(len: usize) -> Result<(), BeaconError> {
    if len > MAX_PAYLOAD_BYTES {
        Err(BeaconError::PayloadTooLarge(len))
    } else {
        Ok(())
    }
}

/// A client configuration that pins the beacon's key and presents `me`.
///
/// # Errors
///
/// [`BeaconError::Transport`] when rustls or quinn refuses the configuration.
pub fn client_config(
    me: &Identity,
    beacon: Fingerprint,
) -> Result<quinn::ClientConfig, BeaconError> {
    let tls = tls::client_config_with_resolver(
        me,
        Arc::new(rustls::client::AlwaysResolvesClientRawPublicKeys::new(
            me.certified_key(),
        )),
        Arc::new(PinnedBeacon(beacon)),
        ALPN,
    )
    .map_err(|error| BeaconError::Transport(error.to_string()))?;
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls))
        .map_err(|error| BeaconError::Transport(format!("{error:?}")))?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(Arc::new(transport_config()?));
    Ok(config)
}

/// The transport settings the protocol needs: the idle timeout, the keep-alive
/// interval that makes a quiet session survive it, and the per-connection stream
/// limit that bounds the beacon's state.
///
/// The receive window is one frame per stream and one frame per stream across the
/// connection, rather than quinn's megabyte: the largest thing the beacon sends is
/// a frame, and the protocol never uses QUIC datagrams, so nothing advertises or
/// buffers a channel it would not drain. The server differs in one respect — it
/// accepts no unidirectional stream — and says so where its own configuration is
/// built.
///
/// # Errors
///
/// [`BeaconError::Transport`] when the idle timeout is out of range for QUIC.
pub fn transport_config() -> Result<quinn::TransportConfig, BeaconError> {
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(BEACON_IDLE_TIMEOUT).map_err(|_| {
            BeaconError::Transport("the beacon idle timeout is out of range".into())
        })?,
    ));
    transport.keep_alive_interval(Some(BEACON_KEEP_ALIVE));
    transport.max_concurrent_bidi_streams(quinn::VarInt::from_u32(MAX_CONCURRENT_STREAMS));
    transport.max_concurrent_uni_streams(quinn::VarInt::from_u32(MAX_CONCURRENT_STREAMS));
    let frame = u32::try_from(MAX_FRAME_BYTES).expect("a frame fits a u32");
    transport.stream_receive_window(frame.into());
    transport.receive_window((frame * MAX_CONCURRENT_STREAMS).into());
    // Disabled, not merely unused: a buffer for a channel the protocol never
    // reads is memory a peer could pin, and `None` is what stops quinn from
    // advertising DATAGRAM support at all.
    transport.datagram_receive_buffer_size(None);
    Ok(transport)
}

/// The pin: exactly the beacon's fingerprint, byte for byte.
#[derive(Debug)]
struct PinnedBeacon(Fingerprint);

impl PeerPolicy for PinnedBeacon {
    fn trusts(&self, peer: &Fingerprint) -> bool {
        *peer == self.0
    }
}
