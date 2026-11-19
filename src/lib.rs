//! Peer layer between mahbot instances.
//!
//! The seams the rest of the layer is built on — identity, the QUIC transport
//! over raw public keys, the rendezvous service. Pairing, delivery and rights are
//! not here yet.
//!
//! The library holds no filesystem access and reads no ambient state: a caller
//! hands it an identity, a socket and a clock, and it uses nothing else. That is
//! what lets the test harness run the real transport over an in-memory link and
//! an injected clock.
#![warn(clippy::pedantic)]
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::module_name_repetitions
)]

// The rendezvous service, as the client sees it.
pub mod beacon;
// The per-instance ed25519 identity and its byte-exact fingerprint.
pub mod identity;
// Endpoint construction over a datagram socket and a clock, both injected.
pub mod net;
// TLS 1.3 with raw public keys, pinned to the peer's fingerprint.
pub mod tls;
