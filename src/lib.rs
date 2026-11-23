//! Peer layer between mahbot instances.
//!
//! The seams the rest of the layer is built on — identity and its key file, the
//! QUIC transport over raw public keys, the beacon as its protocol and client —
//! and the peer layer above them: what a machine remembers about another, how two
//! machines become acquainted, how they stay connected, what a connected machine may
//! do, what one machine says to another, and what it asks another to do. Messages and
//! actions are here; the product layer above them — files, the screen, what a message
//! means and what an action runs — is not.
//!
//! The library reads no ambient state: a caller hands it a storage root, a socket,
//! an identity and a clock, and it uses nothing else. Five things under the root are
//! the crate's: the identity's key file (`identity::keyfile`), the peer records
//! (`peer::record`, which hold both the machine's level and the connection's), the
//! audit log (`peer::audit`), the message queues (`peer::messages`), and the action
//! memories (`peer::actions`, which hold both the executed identifiers and the
//! unknown marks). All five are private to the account the product runs as and all
//! five are permanent formats. That is what lets the test harness run the real
//! transport over an in-memory link and an injected clock.
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
// another to run, and the one reader that tells them apart.
pub mod peer;
// TLS 1.3 with raw public keys, pinned to the peer's fingerprint.
pub mod tls;
