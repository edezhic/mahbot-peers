//! Peer layer between mahbot instances.
//!
//! What the crate does and what the product supplies is stated once, in the repository README.
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
// The peer layer: the durable peer record and its two levels, the acquaintance
// ceremony, the connection manager, the binding exchange, the rights, the record of
// what happened, the messages one machine composes for another, the actions it asks
// another to run, the whole file it moves to it, and the one reader that tells them
// apart.
pub mod peer;
// TLS 1.3 with raw public keys, pinned to the peer's fingerprint.
pub mod tls;
