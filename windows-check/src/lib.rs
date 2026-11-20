//! Type-check of the Windows key-file reader and writer, on a host that is not
//! Windows.
//!
//! The library itself cannot be checked for a Windows target here: `ring` compiles C
//! for its target, and a host without the Windows headers stops in that compiler
//! before it reaches this crate's own code. This crate compiles the same
//! `src/identity/access/` sources with only the dependencies the access-list code
//! uses, so both Windows targets type-check without a Windows host:
//!
//! ```sh
//! cargo check -p mahbot-peers-windows-check --target x86_64-pc-windows-msvc
//! cargo check -p mahbot-peers-windows-check --target x86_64-pc-windows-gnu
//! ```
//!
//! It proves the code compiles; it runs nothing. The reader and writer are exercised
//! on a Windows host, and the capability inventory records that procedure.
#![allow(dead_code)]
// The library calls these; this crate only compiles them.
// The included module's documentation links into `mahbot_peers`, which this crate is
// not: the links are correct where the module lives, and resolving them here would
// mean a second copy of the crate.
#![allow(rustdoc::broken_intra_doc_links)]

#[path = "../../src/identity/access/mod.rs"]
pub mod access;
