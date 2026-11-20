//! The beacon server: the one global service, as the owner runs it.
//!
//! The server is not part of the product and is not published. It holds one map
//! in memory — which id is reachable on which live connection, and where that
//! connection appears from — with a short lifetime, and nothing else: no
//! mailbox, no attempt counter, no disk, no recovery. Restarting it loses every
//! registration by construction.
//!
//! The crate is split so the testable part is the whole of the behaviour. [`core`]
//! is a plain state machine over the protocol's own types, with time passed in;
//! [`config`] parses the command line and builds the server's TLS; [`server`] binds
//! that state machine to a `quinn` endpoint, a runtime and an injected
//! [`clock::Clock`]; the process entry point, which is the only thing that binds a
//! socket, reads the environment and reads the wall clock, lives in the sibling
//! `mahbot-beacon-server` package.
#![warn(clippy::pedantic)]
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::module_name_repetitions
)]

pub mod clock;
pub mod config;
pub mod core;
pub mod server;
