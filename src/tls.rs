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

/// Who a connection may talk to. A machine's peer store implements this; the
/// test harness backs it with an in-memory set of fingerprints.
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
        Arc::new(rustls::client::AlwaysResolvesClientRawPublicKeys::new(
            me.certified_key(),
        )),
        policy,
        alpn,
    )
}

/// A client configuration with a caller-supplied certificate resolver.
///
/// The resolver is where the client's identity comes from, so a caller can
/// present a key it holds elsewhere — or, in a test, present none at all.
pub fn client_config_with_resolver(
    resolver: Arc<dyn rustls::client::ResolvesClientCert>,
    policy: Arc<dyn PeerPolicy>,
    alpn: &[u8],
) -> Result<rustls::ClientConfig, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServer { policy, provider }))
        .with_client_cert_resolver(resolver);
    config.alpn_protocols = vec![alpn.to_vec()];
    Ok(config)
}

/// A server configuration that pins the client's fingerprint.
pub fn server_config(
    me: &Identity,
    policy: Arc<dyn PeerPolicy>,
    alpn: &[u8],
) -> Result<rustls::ServerConfig, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(PinnedClient { policy, provider }))
        .with_cert_resolver(Arc::new(
            rustls::server::AlwaysResolvesServerRawPublicKeys::new(me.certified_key()),
        ));
    config.alpn_protocols = vec![alpn.to_vec()];
    Ok(config)
}

#[derive(Debug)]
struct PinnedServer {
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
        pin(&self.policy, end_entity)?;
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
        pin(&self.policy, end_entity)?;
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
/// policy. Anything else is refused before its signature is even looked at.
fn pin(policy: &Arc<dyn PeerPolicy>, presented: &CertificateDer<'_>) -> Result<(), rustls::Error> {
    let fingerprint = Fingerprint::from_spki(presented.as_ref()).ok_or_else(|| {
        rustls::Error::General("peer presented a key that is not an ed25519 SPKI".into())
    })?;
    if policy.trusts(&fingerprint) {
        Ok(())
    } else {
        Err(rustls::Error::General(format!(
            "peer {fingerprint} is not trusted"
        )))
    }
}
