//! Peer layer between mahbot instances.
//!
//! The seams the rest of the layer is built on — identity and its key file, the
//! QUIC transport over raw public keys, the beacon as its protocol and client —
//! and the peer layer above them: what a machine remembers about another, how two
//! machines become acquainted, and how they stay connected. Delivery and rights
//! are not here yet.
//!
//! The library reads no ambient state: a caller hands it a storage root, a socket,
//! an identity and a clock, and it uses nothing else. Two things under the root are
//! the crate's: the identity's key file (`identity::keyfile`) and the peer records
//! (`peer::record`), both private to the account the product runs as and both
//! permanent formats. That is what lets the test harness run the real transport over
//! an in-memory link and an injected clock.
#![warn(clippy::pedantic)]
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::module_name_repetitions
)]

// The beacon: its closed message set, the client half the product speaks, and
// the deadline combinator both halves share.
pub mod beacon;
// Lowercase hex, shared by the identity's rendering and the record's file name.
mod hex;
// The per-instance ed25519 identity, its byte-exact fingerprint and its key file.
pub mod identity;
// Endpoint construction over a datagram socket and a clock, both injected.
pub mod net;
// The one write and read path the crate's private files share.
mod private;
// The peer layer: the durable peer record, the acquaintance ceremony, the
// connection manager and the beacon registration that keeps a machine findable.
pub mod peer;
// TLS 1.3 with raw public keys, pinned to the peer's fingerprint.
pub mod tls;
