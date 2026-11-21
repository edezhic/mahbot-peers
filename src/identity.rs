//! The instance identity: one ed25519 key per storage root.
//!
//! The fingerprint is the 44-byte RFC 8410 SubjectPublicKeyInfo of the key, and
//! the peer id is the 32-byte public key inside it. Both are pinned byte for byte:
//! a peer that presents a key which merely verifies, or a key of the right shape
//! with one byte changed, is not the peer this machine remembers.
//!
//! There is exactly one human rendering of an identity — the 88 lowercase hex
//! characters of those 44 bytes, [`Fingerprint`]'s `Display`. There is no second,
//! hashed or shortened spelling: a hash of a fingerprint identifies nothing, and a
//! shortened one identifies less. A peer id has no rendering of its own, because
//! it is the same key: [`PeerId`]'s `Debug` prints the fingerprint's bytes too.
//!
//! The private half stays in [`Identity`]: it has no textual form and never
//! reaches `Debug`. Only the public half crosses a boundary, because that is what
//! peers exchange, and only a signature over a transcript the caller names crosses
//! it besides.
//!
//! The key is minted in exactly one place and only when there is no key file yet:
//! [`keyfile::load_or_create`]. The crate has no generator on its surface, so no
//! caller can mint a fresh identity on every start by accident.

use std::fmt;
use std::sync::Arc;

use ring::signature::{self, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;

use crate::hex;

/// Who may reach the key file, and the rules that decide it.
pub mod access;
/// The key file under a storage root: its name, its format, and its one create.
pub mod keyfile;

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

/// The pinned 44 bytes: the fixed header and the public key. The one place the
/// fingerprint of a key is assembled, so "the peer id is the key inside it" cannot
/// drift between a freshly parsed key and one read back from a peer id.
fn key_spki(key: &[u8; PEER_ID_LEN]) -> Fingerprint {
    let mut spki = [0u8; FINGERPRINT_LEN];
    spki[..ED25519_SPKI_PREFIX.len()].copy_from_slice(&ED25519_SPKI_PREFIX);
    spki[ED25519_SPKI_PREFIX.len()..].copy_from_slice(key);
    Fingerprint(spki)
}

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

    /// The fingerprint this id is the key inside: the one rendering of the
    /// machine, recoverable from the 32 bytes because an ed25519 SPKI is a fixed
    /// header followed by exactly this key.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        key_spki(&self.0)
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
    /// The fingerprint's rendering, not a second one: a machine has one spelling.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.fingerprint(), f)
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

    /// Read back what [`Fingerprint`]'s `Display` wrote: 88 lowercase hex
    /// characters, and nothing else.
    ///
    /// This is the inverse of the one rendering, which is what makes it a
    /// rendering of the identity rather than a label for it: a human carrying a
    /// fingerprint from one machine to another carries these bytes.
    #[must_use]
    pub fn from_hex(text: &str) -> Option<Self> {
        if text.len() != FINGERPRINT_LEN * 2 {
            return None;
        }
        let digits = text.as_bytes();
        let mut spki = [0u8; FINGERPRINT_LEN];
        for (index, byte) in spki.iter_mut().enumerate() {
            *byte = (hex::digit(digits[index * 2])? << 4) | hex::digit(digits[index * 2 + 1])?;
        }
        Self::from_spki(&spki)
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
        fmt::Display::fmt(self, f)
    }
}

/// The one rendering of an identity: the 44 pinned bytes as 88 lowercase hex
/// characters. Lossless — [`Fingerprint::from_hex`] gives the same bytes back.
impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::write(f, &self.0)
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
    /// Rebuild an identity from the PKCS#8 bytes a key file holds.
    ///
    /// `None` for anything that is not the v2 PKCS#8 form of an ed25519 key — the
    /// one the key file holds, with its public key checked against the seed. A
    /// corrupt or truncated key file must fail loudly rather than start a second
    /// identity.
    ///
    /// Minting a key is not this function's business — see
    /// [`keyfile::load_or_create`], which mints only when there is no key file.
    #[must_use]
    pub fn from_pkcs8(pkcs8: &[u8]) -> Option<Self> {
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8).ok()?;
        // `from_pkcs8` checks the public key the structure carries against the
        // seed, so this is the key the private half belongs to.
        let key: [u8; PEER_ID_LEN] = pair
            .public_key()
            .as_ref()
            .try_into()
            .expect("an ed25519 public key is 32 bytes");
        let fingerprint = key_spki(&key);
        let signer = rustls::crypto::ring::sign::any_supported_type(&PrivateKeyDer::Pkcs8(
            PrivatePkcs8KeyDer::from(pkcs8.to_vec()),
        ))
        .ok()?;
        let certified = CertifiedKey::new(
            vec![CertificateDer::from(fingerprint.as_bytes().to_vec())],
            signer,
        );
        Some(Self {
            fingerprint,
            pair: Arc::new(pair),
            pkcs8: Arc::from(pkcs8),
            certified: Arc::new(certified),
        })
    }

    /// The private key as PKCS#8 bytes: what the key file holds, byte for byte.
    ///
    /// Crate-internal: a key is persisted by [`keyfile::load_or_create`], which
    /// owns the name, the format and the permissions, so there is no second way to
    /// store one and no reason to hand the private half out.
    #[must_use]
    pub(crate) fn pkcs8(&self) -> &[u8] {
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
