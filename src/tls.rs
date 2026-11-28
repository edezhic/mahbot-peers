//! TLS 1.3 with raw public keys (RFC 7250) and a pin, not a certificate chain.
//!
//! Both sides present their Ed25519 SubjectPublicKeyInfo and both check the
//! peer's bytes against the policy they were given. There is no PKI here: the
//! only trust decision is "is this the fingerprint I remember", which is why the
//! policy is a trait the caller supplies rather than a certificate store.

use std::fmt;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};

use crate::identity::{Fingerprint, Identity};

/// The protocol the peer layer speaks. Fixed here so a mismatch fails the
/// handshake instead of reaching application code. The beacon has its own.
pub const ALPN: &[u8] = b"mahbot-peers/1";

/// Why a handshake refused the key a peer presented.
///
/// The two are told apart because they mean different things and lead to
/// different actions: an untrusted peer is a stranger or a revoked machine, while
/// our own identity arriving from the network is a copy of this machine's storage
/// root, which no amount of pairing can make into a second machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The peer presented this machine's own key: a copy of the storage root, not
    /// another machine. Two peers with one identity are one machine, so the
    /// connection is refused instead of talking to ourselves.
    OwnIdentity,
    /// The peer presented a key this machine does not remember.
    Untrusted,
}

impl Refusal {
    /// The words the refusal carries into the local handshake error.
    pub(crate) const fn phrase(self) -> &'static str {
        match self {
            Self::OwnIdentity => "is this machine's own identity",
            Self::Untrusted => "is not a trusted peer",
        }
    }

    /// The reason a refusal left behind, when the text is one of ours.
    ///
    /// rustls hands a refused key back as an opaque error, and quinn carries the
    /// text of whichever side ended the connection — so the value is a reading of
    /// text, not a decision. [`crate::net::refusal`] is the way in for a failed
    /// connection.
    pub(crate) fn of(reason: &str) -> Option<Self> {
        [Self::OwnIdentity, Self::Untrusted]
            .into_iter()
            .find(|refusal| reason.contains(refusal.phrase()))
    }
}

/// Whether a presented key is refused, and why.
///
/// The machine's own key is decided first: a restored backup is a copy of a
/// machine that is still running, and no policy entry can make it a peer.
pub(crate) fn refusal(
    me: &Fingerprint,
    presented: &Fingerprint,
    policy: &dyn PeerPolicy,
) -> Option<Refusal> {
    if presented == me {
        Some(Refusal::OwnIdentity)
    } else if policy.trusts(presented) {
        None
    } else {
        Some(Refusal::Untrusted)
    }
}

/// Who a connection may talk to.
pub trait PeerPolicy: fmt::Debug + Send + Sync {
    fn trusts(&self, peer: &Fingerprint) -> bool;
}

/// A client configuration that pins the server's fingerprint and presents the
/// identity's raw public key.
///
/// `alpn` is the service's own name: the peer layer and the beacon are two
/// protocols, and a connection offered to one must not complete on the other.
pub fn client_config(
    me: &Identity,
    policy: Arc<dyn PeerPolicy>,
    alpn: &[u8],
) -> Result<rustls::ClientConfig, rustls::Error> {
    client_config_with_resolver(
        me,
        Arc::new(rustls::client::AlwaysResolvesClientRawPublicKeys::new(
            me.certified_key(),
        )),
        policy,
        alpn,
    )
}

/// A client configuration with a caller-supplied certificate resolver.
///
/// The resolver is where the client's identity comes from, so a caller can present a key it
/// holds elsewhere. `me` is still needed: it names the machine whose own key must never be
/// accepted back from the network.
///
/// # Why resumption is off
///
/// The pin is [`ServerCertVerifier::verify_server_cert`], and rustls does not call it
/// on a resumed session: a resumed handshake carries a ticket, not a certificate. A
/// machine that completed a handshake before its trust was withdrawn could then
/// resume that session afterwards and never reach the pin, which is exactly what a
/// withdrawal must prevent. Resumption buys nothing here — a pair is long-lived and
/// connects rarely — so it is disabled rather than special-cased, and the server
/// sends no tickets either ([`server_config`]).
pub fn client_config_with_resolver(
    me: &Identity,
    resolver: Arc<dyn rustls::client::ResolvesClientCert>,
    policy: Arc<dyn PeerPolicy>,
    alpn: &[u8],
) -> Result<rustls::ClientConfig, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServer {
            me: me.fingerprint(),
            policy,
            provider,
        }))
        .with_client_cert_resolver(resolver);
    config.alpn_protocols = vec![alpn.to_vec()];
    config.resumption = rustls::client::Resumption::disabled();
    Ok(config)
}

/// A server configuration that pins the client's fingerprint and refuses our own.
///
/// It sends no session tickets, for the reason [`client_config_with_resolver`]
/// states: the pin is the client-certificate verifier, and a resumed session never
/// reaches it.
pub fn server_config(
    me: &Identity,
    policy: Arc<dyn PeerPolicy>,
    alpn: &[u8],
) -> Result<rustls::ServerConfig, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(PinnedClient {
            me: me.fingerprint(),
            policy,
            provider,
        }))
        .with_cert_resolver(Arc::new(
            rustls::server::AlwaysResolvesServerRawPublicKeys::new(me.certified_key()),
        ));
    config.alpn_protocols = vec![alpn.to_vec()];
    config.send_tls13_tickets = 0;
    Ok(config)
}

#[derive(Debug)]
struct PinnedServer {
    me: Fingerprint,
    policy: Arc<dyn PeerPolicy>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedServer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        pin(self.me, &self.policy, end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is not offered".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

#[derive(Debug)]
struct PinnedClient {
    me: Fingerprint,
    policy: Arc<dyn PeerPolicy>,
    provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for PinnedClient {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        pin(self.me, &self.policy, end_entity)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is not offered".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// The pin itself: exactly 44 bytes of Ed25519 SubjectPublicKeyInfo, trusted by
/// policy and never this machine's own key. Anything else is refused before its
/// signature is even looked at.
fn pin(
    me: Fingerprint,
    policy: &Arc<dyn PeerPolicy>,
    presented: &CertificateDer<'_>,
) -> Result<(), rustls::Error> {
    let fingerprint = Fingerprint::from_spki(presented.as_ref()).ok_or_else(|| {
        rustls::Error::General("peer presented a key that is not an ed25519 SPKI".into())
    })?;
    match refusal(&me, &fingerprint, policy.as_ref()) {
        None => Ok(()),
        Some(refusal) => Err(rustls::Error::General(format!(
            "peer {fingerprint} {}",
            refusal.phrase()
        ))),
    }
}
