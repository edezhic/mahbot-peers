//! The rendezvous service as the client sees it.
//!
//! The beacon is for introduction and discovery only: it remembers where an id
//! currently is, answers where an id is, hands an opaque blob from one party to
//! another during pairing, and tells a machine how it appears from outside. That
//! last duty — the address observer — is not part of this seam yet. The beacon
//! never sees conversation bytes, accounts, rights or authorship, and it has no
//! say in whether a connection is allowed: it only helps two machines find each
//! other.
//!
//! The trait is the seam. The real service is a separate binary the product
//! never runs; the harness's in-memory stand-in implements this same trait, so
//! both are exercised through one thing. No wire format is defined here: how the
//! client reaches the service is the service's own concern.

use std::fmt;
use std::net::SocketAddr;

use async_trait::async_trait;

use crate::identity::PeerId;

/// The largest opaque payload the seam will carry in one introduction. Bigger
/// ones are refused rather than buffered: an introduction is a key exchange,
/// not a message channel.
pub const MAX_INTRODUCTION_BYTES: usize = 8 * 1024;

/// One opaque blob handed to a peer, with the id that sent it.
///
/// Build it with [`Introduction::new`]: the fields are private, so the size
/// limit cannot be stepped around and a service cannot store an introduction the
/// seam promised to refuse.
#[derive(Clone, PartialEq, Eq)]
pub struct Introduction {
    from: PeerId,
    payload: Vec<u8>,
}

impl Introduction {
    /// Build an introduction, refusing a payload over [`MAX_INTRODUCTION_BYTES`].
    ///
    /// # Errors
    ///
    /// [`BeaconError::PayloadTooLarge`] with the payload's length.
    pub fn new(from: PeerId, payload: Vec<u8>) -> Result<Self, BeaconError> {
        if payload.len() > MAX_INTRODUCTION_BYTES {
            return Err(BeaconError::PayloadTooLarge(payload.len()));
        }
        Ok(Self { from, payload })
    }

    /// Who sent it.
    #[must_use]
    pub const fn from(&self) -> PeerId {
        self.from
    }

    /// The opaque bytes. The service never reads them.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

impl fmt::Debug for Introduction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Introduction")
            .field("from", &self.from)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

/// Why the service refused a request.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum BeaconError {
    /// The service is not running, or has stopped.
    Unavailable,
    /// The addressee is not registered.
    UnknownPeer(PeerId),
    /// The payload is larger than [`MAX_INTRODUCTION_BYTES`].
    PayloadTooLarge(usize),
}

impl fmt::Display for BeaconError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => f.write_str("the rendezvous service is unavailable"),
            Self::UnknownPeer(id) => write!(f, "peer {id} is not registered"),
            Self::PayloadTooLarge(len) => write!(
                f,
                "an introduction of {len} bytes exceeds {MAX_INTRODUCTION_BYTES}"
            ),
        }
    }
}

impl std::error::Error for BeaconError {}

/// The rendezvous seam.
#[async_trait]
pub trait Rendezvous: fmt::Debug + Send + Sync {
    /// Remember that `id` is reachable at `addr`, replacing any earlier address.
    async fn register(&self, id: PeerId, addr: SocketAddr) -> Result<(), BeaconError>;

    /// Where `id` is, if it is registered at all.
    async fn lookup(&self, id: &PeerId) -> Result<Option<SocketAddr>, BeaconError>;

    /// Hand `payload` to `to`, tagged with `from`. The service does not read it.
    ///
    /// An implementation builds the [`Introduction`] with [`Introduction::new`],
    /// which is where the size limit is enforced.
    async fn introduce(
        &self,
        from: PeerId,
        to: PeerId,
        payload: Vec<u8>,
    ) -> Result<(), BeaconError>;

    /// Take one introduction addressed to `me`, oldest first.
    async fn take_introduction(&self, me: &PeerId) -> Result<Option<Introduction>, BeaconError>;
}
