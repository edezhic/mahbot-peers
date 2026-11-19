//! The instance identity: one ed25519 key per storage root.
//!
//! The fingerprint is the 44-byte RFC 8410 SubjectPublicKeyInfo of the key, and
//! the peer id is the 32-byte public key inside it. Nothing here touches a file
//! — how the key is stored and which permissions it carries is not part of this
//! crate — and the private half stays in this value: it has no textual form and
//! never reaches `Debug`. Only the public half crosses a boundary, because that
//! is what peers exchange.

use std::fmt;
use std::sync::Arc;

use ring::signature::{Ed25519KeyPair, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;

/// RFC 8410 §4: `SEQUENCE { AlgorithmIdentifier id-Ed25519, BIT STRING key }`.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Length of an Ed25519 SubjectPublicKeyInfo, which is also the fingerprint.
pub const FINGERPRINT_LEN: usize = 44;

/// Length of an Ed25519 public key, which is also the peer id.
pub const PEER_ID_LEN: usize = 32;

/// The public half of an instance identity: what a peer remembers and pins.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId([u8; PEER_ID_LEN]);

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

/// The 44-byte SubjectPublicKeyInfo of an identity. Pinned byte for byte, so a
/// peer cannot substitute a key that merely verifies.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Fingerprint([u8; FINGERPRINT_LEN]);

impl Fingerprint {
    /// Interpret DER-encoded bytes as an Ed25519 SubjectPublicKeyInfo.
    ///
    /// Returns `None` for anything that is not exactly one of those 44 bytes:
    /// the raw-public-key handshake hands over whatever the peer sent, and the
    /// shape check is part of the pin, not a convenience.
    #[must_use]
    pub fn from_spki(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != FINGERPRINT_LEN || !bytes.starts_with(&ED25519_SPKI_PREFIX) {
            return None;
        }
        let mut spki = [0u8; FINGERPRINT_LEN];
        spki.copy_from_slice(bytes);
        Some(Self(spki))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; FINGERPRINT_LEN] {
        &self.0
    }

    /// The peer id inside this fingerprint.
    #[must_use]
    pub fn peer_id(&self) -> PeerId {
        let mut id = [0u8; PEER_ID_LEN];
        id.copy_from_slice(&self.0[ED25519_SPKI_PREFIX.len()..]);
        PeerId(id)
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

/// An ed25519 identity held in memory.
///
/// `Debug` prints the fingerprint only: the private half has no textual form.
#[derive(Clone)]
pub struct Identity {
    fingerprint: Fingerprint,
    certified: Arc<CertifiedKey>,
}

impl Identity {
    /// Generate a fresh identity from the system's randomness.
    #[must_use]
    pub fn generate() -> Self {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
            .expect("system randomness is available");
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("a generated key parses");
        let mut spki = [0u8; FINGERPRINT_LEN];
        spki[..ED25519_SPKI_PREFIX.len()].copy_from_slice(&ED25519_SPKI_PREFIX);
        spki[ED25519_SPKI_PREFIX.len()..].copy_from_slice(pair.public_key().as_ref());
        let signer = rustls::crypto::ring::sign::any_supported_type(&PrivateKeyDer::Pkcs8(
            PrivatePkcs8KeyDer::from(pkcs8.as_ref().to_vec()),
        ))
        .expect("the ring provider signs ed25519");
        let certified = CertifiedKey::new(vec![CertificateDer::from(spki.to_vec())], signer);
        Self {
            fingerprint: Fingerprint(spki),
            certified: Arc::new(certified),
        }
    }

    #[must_use]
    pub const fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    #[must_use]
    pub fn peer_id(&self) -> PeerId {
        self.fingerprint.peer_id()
    }

    /// The key pair as rustls wants it: the raw public key as the "certificate"
    /// and the matching signer. Only this crate's TLS configuration uses it, so
    /// `rustls::sign::CertifiedKey` stays off the published surface.
    #[must_use]
    pub(crate) fn certified_key(&self) -> Arc<CertifiedKey> {
        Arc::clone(&self.certified)
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Identity").field(&self.fingerprint).finish()
    }
}

fn write_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(f, "{byte:02x}")?;
    }
    Ok(())
}
