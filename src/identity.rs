//! The instance identity: one ed25519 key per storage root.
//!
//! The fingerprint is the 44-byte RFC 8410 SubjectPublicKeyInfo of the key, and
//! the peer id is the 32-byte public key inside it. Nothing here touches a file
//! — how the key is stored and which permissions it carries is not part of this
//! crate — and the private half stays in this value: it has no textual form and
//! never reaches `Debug`. Only the public half crosses a boundary, because that
//! is what peers exchange, and only a signature over a transcript the caller
//! names crosses it besides.
//!
//! The key's PKCS#8 bytes are exposed so a caller can persist them itself; the
//! crate does not know where, or with which permissions.

use std::fmt;
use std::sync::Arc;

use ring::signature::{self, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
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

/// Length of an ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// The public half of an instance identity: what a peer remembers and pins.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId([u8; PEER_ID_LEN]);

impl PeerId {
    /// The key's bytes. The peer id is public, and every transcript a caller
    /// signs or verifies starts from it.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PEER_ID_LEN] {
        &self.0
    }

    /// Read a peer id from the key's bytes.
    ///
    /// Nothing is checked: a peer id is an ed25519 public key, and a key that
    /// does not verify is refused when a signature is checked, not here.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; PEER_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Whether `signature` is `message` signed by this id's key.
    ///
    /// Ed25519 only: the key's bytes are the whole public key, and a signature
    /// that does not verify is a lie about who sent the message.
    #[must_use]
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        UnparsedPublicKey::new(&signature::ED25519, self.0)
            .verify(message, signature)
            .is_ok()
    }
}

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
    pair: Arc<Ed25519KeyPair>,
    pkcs8: Arc<[u8]>,
    certified: Arc<CertifiedKey>,
}

impl Identity {
    /// Generate a fresh identity from the system's randomness.
    #[must_use]
    pub fn generate() -> Self {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
            .expect("system randomness is available");
        Self::from_der(pkcs8.as_ref()).expect("a generated key parses")
    }

    /// Rebuild an identity from the PKCS#8 bytes [`Identity::pkcs8`] produced.
    ///
    /// `None` for anything that is not a PKCS#8 ed25519 key: a corrupt or
    /// truncated key file must fail loudly rather than start a second identity.
    #[must_use]
    pub fn from_pkcs8(pkcs8: &[u8]) -> Option<Self> {
        Self::from_der(pkcs8)
    }

    fn from_der(pkcs8: &[u8]) -> Option<Self> {
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8).ok()?;
        let mut spki = [0u8; FINGERPRINT_LEN];
        spki[..ED25519_SPKI_PREFIX.len()].copy_from_slice(&ED25519_SPKI_PREFIX);
        spki[ED25519_SPKI_PREFIX.len()..].copy_from_slice(pair.public_key().as_ref());
        let signer = rustls::crypto::ring::sign::any_supported_type(&PrivateKeyDer::Pkcs8(
            PrivatePkcs8KeyDer::from(pkcs8.to_vec()),
        ))
        .ok()?;
        let certified = CertifiedKey::new(vec![CertificateDer::from(spki.to_vec())], signer);
        Some(Self {
            fingerprint: Fingerprint(spki),
            pair: Arc::new(pair),
            pkcs8: Arc::from(pkcs8),
            certified: Arc::new(certified),
        })
    }

    /// The private key as PKCS#8 bytes, for a caller that persists it.
    ///
    /// The crate has no opinion on where those bytes go or which permissions the
    /// file carries; that is the caller's storage rule, not the identity's.
    #[must_use]
    pub fn pkcs8(&self) -> &[u8] {
        &self.pkcs8
    }

    /// Sign `message` with this identity's key.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        let signature = self.pair.sign(message);
        let mut bytes = [0u8; SIGNATURE_LEN];
        bytes.copy_from_slice(signature.as_ref());
        bytes
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
