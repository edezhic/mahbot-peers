//! Type-check of the Windows key-file reader and writer, on a host that is not
//! Windows.
//!
//! The library itself cannot be checked for a Windows target here: `ring` compiles C
//! for its target, and a host without the Windows headers stops in that compiler
//! before it reaches this crate's own code. This crate compiles the same
//! `src/identity/access/` sources with only the dependencies the access-list code
//! uses, so both Windows targets type-check without a Windows host.
//!
//! `rust-toolchain.toml` pins the channel and the components, not the targets. A target
//! that is not installed stops the check in
//!
//! ```text
//! error[E0463]: can't find crate for `core`
//! ```
//!
//! with a note naming the target, so a fresh `rustup` installation needs this once:
//!
//! ```sh
//! rustup target add x86_64-pc-windows-msvc x86_64-pc-windows-gnu
//! ```
//!
//! Then, for each target, the compile check and the lint check:
//!
//! ```sh
//! cargo check -p mahbot-peers-windows-check --target x86_64-pc-windows-msvc
//! cargo clippy -p mahbot-peers-windows-check --target x86_64-pc-windows-msvc -- -D warnings
//! cargo check -p mahbot-peers-windows-check --target x86_64-pc-windows-gnu
//! cargo clippy -p mahbot-peers-windows-check --target x86_64-pc-windows-gnu -- -D warnings
//! ```
//!
//! The lint runs per target too: on a host that is not Windows,
//! `cargo clippy --workspace --all-targets` never compiles the Windows module at all,
//! so a Windows-only lint failure would otherwise pass here. The crate root enables
//! `clippy::pedantic` under the same allowances the library gives these sources, so the
//! gate lints the Windows reader to the same standard as the code it belongs to.
//!
//! This proves the code compiles; it runs nothing. The reader and writer are exercised
//! on a Windows host, and the capability inventory records that procedure.
//!
//! # The peer layer's storage is covered through the same gate
//!
//! `src/peer/messages/` and `src/peer/actions/` hold no `#[cfg(windows)]` code and call no
//! access rule directly: their storage goes through `crate::private`, whose directory and file
//! rule *is* `identity::access` — the module this crate compiles for both Windows targets. A
//! queue's and an action memory's privacy on Windows is therefore decided by the code checked
//! here, reached through `private::create_private_dir`, `private::create_private` (one lock
//! file per peer's queue or memory) and `private::open_private`, and no second include is
//! added: the layers depend on `quinn`, `ring` and `rustls`, so their own sources cannot be
//! checked for a Windows target on a host without the Windows headers. What that leaves
//! unchecked is the layers' own logic — a queue's framing, an action memory's journal, the
//! offer, the decision and the inbox's dispatch — which is not platform-specific, and the one
//! branch `private` takes per platform: `create_private_dir` settles a half-made directory
//! only where the platform applies the access list after the creation, and the Windows arm of
//! that is reached by neither this crate nor a case on this host. What it does check is every
//! access decision either layer makes.
// The same lint set the library's root enables, with the same allowances: these are the
// library's own sources, and this crate is the only one that lints their Windows half.
#![warn(clippy::pedantic)]
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    clippy::module_name_repetitions
)]
// The library calls these; this crate only compiles them.
#![allow(dead_code)]
// The included module's documentation links into `mahbot_peers`, which this crate is
// not: the links are correct where the module lives, and resolving them here would
// mean a second copy of the crate.
#![allow(rustdoc::broken_intra_doc_links)]

#[path = "../../src/identity/access/mod.rs"]
pub mod access;
