# mahbot-peers

The peer layer between mahbot instances: machines connect directly, with no
relay in the path, and remember each other by key. This crate is the network
half — it knows keys, addresses and byte counts; the product knows people,
accounts, rights, authorship and queues.

The crate holds the seams the rest of the layer is built on, and the beacon: the
one global service, as its protocol and its client. Pairing, delivery and rights
are not here yet.

## What the crate provides

The library (`src/`) holds:

| Module | What it fixes |
| --- | --- |
| `identity` | one ed25519 identity per storage root, in a key file the caller's root holds; the fingerprint is the 44-byte RFC 8410 SubjectPublicKeyInfo and the peer id is the key inside it. `identity::access` is who may reach that file, `identity::keyfile` is its name, its format and its one create |
| `tls` | TLS 1.3 with raw public keys (RFC 7250), pinned to the peer's fingerprint instead of a certificate chain, with a per-service ALPN |
| `net` | endpoint construction over an injected datagram socket and an injected clock — no default for either |
| `beacon` | the beacon: the closed message set (`wire`), the client half (`Beacon`, `Session`) — register, look an id up, learn the address observed on this path, hand a signed introduction over, take the ones pushed to a live session — and the one deadline combinator the client and the server share (`timeout`) |

## The identity

A machine is one ed25519 key, and the unit of identity is the storage root: two
roots are two peers, even on one machine. The library never resolves the root
itself — a caller hands one in — and it reads no configuration.

The key file's name, its format, the guarantees, the typed refusals, the one
create and the one rendering are a permanent compatibility contract, because a key
is never rotated and there is no migration. They are stated once, where they are
enforced: `identity::keyfile` for the file, `identity` for the pinned bytes and
their rendering. What a reader of this crate needs here is the shape: one identity
per root; a copy of a root is the same machine, and is refused as a clone with an
answer distinct from an untrusted peer's. What losing the key means, and why
deleting it is the only deliberate way to become a new machine, are in
`identity::keyfile`; three source-scan invariants keep a replacement from happening
by accident.

Windows is the platform this repository has no host for: the rule is witnessed
everywhere as a decision, the reader and the writer type-check for both Windows
targets through `windows-check` (a crate that compiles just those sources and
nothing else), and the inventory entry `library.identity.key_file.windows_dacl`
carries the manual procedure, first creation included. That procedure names its
accounts by SID, so it runs on an installation whose display language is not
English.

A refusal is a typed error, never a log line a caller can continue past, and its
message is the same text on every run: it names the path, the fact, and — where the
platform has one command that repairs it — that command with the same path, quoted for
that platform's own tool, so it can be run as printed. The repairs are attributed per
platform in `identity::access`'s documentation, which quotes what each message says:
`chmod` for a unix mode, `chmod -N` for a macOS extended entry, `icacls` for a Windows
list or owner, and no command for ownership on unix, where the file has to be handed
back to the account the product runs as. A file state this suite cannot produce is
recorded in the capability inventory (`harness/src/inventory.rs`) as unproducible, with
what does produce it: a manual procedure for the foreign owner (a second account on
unix; an elevated prompt of the same account on Windows), for the Windows access-list
states, and — off macOS — for the extended access list; and for the two Windows shapes
no command can produce, the record says so and the case that decides them as data is
the evidence. Every procedure that changes the key file names a scratch root of its
own before it changes anything — the account-name procedure changes no file and names
none — and each states what it needs and checks that the key still loads after every
change.

The beacon is introduction and address service and nothing else. It remembers
where an id currently is, in memory and for a short lifetime; it relays an
opaque payload between two machines that are both present; it answers with the
address it observes on the connection the question arrived over. It carries no
conversation bytes, holds no accounts, rights, authorship or queues, executes
nothing, keeps no state on disk and knows no secret but its own identity — one key
file, with the same name, format and create as a machine's.

Two properties are structural rather than promised. A registration is bound to
the key the handshake proved: no frame carries an id, and the address recorded
is the one observed on the caller's path, not one the caller names. An
introduction is signed by its sender over both ids and the payload, so a
compromised beacon cannot pass one off under another id or alter it. Trust
between machines comes from pinned keys and the ceremony, never from the beacon.

The address answer is the beacon protocol's own request, asked over the same
connection the peers use. That is the point: an answer obtained over some other
socket would name an address the peers cannot reach, and hole punching depends on
the answer being the peer-facing path, so no second socket is opened for it.

A session is bounded in both directions. It pings every `BEACON_KEEP_ALIVE` so an
idle session keeps its connection and its NAT binding, and every request — the
handshake included, and the frame of a pushed introduction — gives up after
`BEACON_REQUEST_TIMEOUT` of the injected runtime's time: a beacon that is gone is
a bounded failure, not a session that looks open forever. An introduction makes
the server apply its own exchange bound three times in sequence, so the client's
bound is more than three times the server's and a live but slow beacon is never
reported as dead; the recorded case `deadlines_are_ordered` pins that ordering and
the idle timeout above it. `next_introduction`'s wait for the beacon to speak
first is the caller's.

## The server

`beacon/` is the server library (`mahbot-beacon`, `publish = false`) and
`beacon-server/` is its process entry point (`mahbot-beacon-server`). Neither is
published; the owner runs the binary:

```sh
cargo build -p mahbot-beacon-server
mkdir -p "$HOME/.mahbot-beacon"
target/debug/mahbot-beacon-server \
  --listen 0.0.0.0:4433 --root "$HOME/.mahbot-beacon"
```

The key is the beacon's identity and lives in that directory as `identity.key` — the
same name, format and privacy rule as a machine's, created once and never replaced.
It is printed at start as a fingerprint; that is the key the product pins. Keep the
directory out of the checkout: `.gitignore` covers `*.key` as a second line of
defence. The key is the only thing the beacon persists — it is configuration, not
state. Registrations live in memory and are gone on restart.

The server library is split so the testable part is the whole of the behaviour:
`core` is a plain state machine with time passed in, `config` parses the command
line and builds the server's TLS and transport, `server` binds the state machine
to a `quinn` endpoint, an injected runtime and an injected clock. The server
spawns on the runtime it is handed, never on an ambient executor, and every wait
is bounded by that runtime's timer — the handshake, reading a request, writing an
answer, pushing an introduction — so a half-open handshake, a peer that stalls a
stream and a recipient that never reads can neither park a task nor starve the
sender's own registration refresh. Connections are capped and each is limited in
the streams it may open; the numbers are the constants beside the protocol, and
the server advertises no unidirectional stream and no QUIC datagram at all — both
would be receive window a peer could pin on a channel the beacon never drains.

Only the entry point binds a real socket, reads the environment and the wall
clock. The scan exempts that one file from those three invariants and no others
(the invariant table itself is not scanned either, because it holds the patterns);
`harness/tests/summary.rs` proves each exemption is still needed, that nothing else
about the file is excused, and that no other file in the entry crate escapes the
no-state-on-disk claim. What the entry point decides — what the command line means
— is a pure function in the library and is witnessed in a default build, and its
key file goes through the peer library's loader, so the name and mint invariants
scan it and the exempted surface stays glue.

## The harness

The harness (`harness/`, never published) is the test rig:

- **Machines.** `Sim::machine()` creates a machine with its own temporary root, its
  own address on the link and the identity that root's key file gives it — the
  harness mints no key of its own. `Sim::clone_of` copies one machine's key into a
  second root, which is what restoring a backup onto another host gives and what the
  clone refusal is about. The handle exposes no filesystem path, and its storage
  capability refuses any root but its own.
- **Link.** Datagrams travel through an `AsyncUdpSocket` the test controls —
  the same seam a real socket uses. A script or a seed drops, delays, reorders,
  duplicates and re-addresses them, and every run leaves a trace that replays to
  itself. A machine's apparent address can change mid-run. A connection attempt
  drives the clock itself, so a link that drops everything ends at a
  deterministic virtual instant instead of hanging the test, and one machine can
  serve several dialers at once.
- **Clock.** Time moves only when the test moves it. `quinn` reads the clock and
  creates its timers through it, so an idle timeout fires on `advance` and never
  on wall time. The harness's tokio has no `time` feature and its runtime has no
  timer driver, so a timer sleep does not compile, and the single-source-of-time
  invariant forbids any other sleep. A case that spins instead of parking is
  stopped by a poll budget, and an await that may never resolve is driven against
  a virtual budget (`MockClock::drive`), so a datagram that never arrives fails
  the case instead of hanging the suite.
- **Beacon rig.** The real server over the simulated link and the library's real
  client. It can be started, stopped, killed and restarted at the same address
  and key, and its whole memory is inspectable. A raw client and a rogue server
  speak bytes the typed messages would not produce, so the closed message set, the
  version check and the introduction's signature are exercised against the real
  server. A killed beacon is a process that is gone: the link stops delivering to
  its address, so a client only learns from its own bound.
- **Witnesses and invariants.** The capability inventory and the cross-cutting
  invariant table live here, together with the checks that enforce them: every
  entry is either witnessed by a recorded case or marked unproducible with the
  reason it cannot be produced here and the procedure that produces it, the check
  fails in both directions, and every invariant is proven awake by a control
  snippet it must catch. An empty scan is a failure; the one exempt file names the
  invariants it does not answer to, each of those is re-proven necessary and every
  other invariant still scans it. A claim only one platform can decide is in the
  inventory on every host, so nothing is skipped silently.

## Building and testing

The toolchain is pinned in `rust-toolchain.toml` (1.99.1, the channel the other
mahbot workspaces use). The crate's own floor is `rust-version = "1.96"`.

```sh
cargo build
cargo test            # the default workspace: witnesses, summary checks, invariants
cargo clippy --workspace --all-targets -- -D warnings
cargo package --offline -p mahbot-peers   # needs a committed tree
cargo build -p mahbot-beacon-server       # the owner's binary
```

The Windows code is compiled by every Windows build and by nobody on this host, so
the gate that keeps it from rotting compiles the same sources without `ring`: the
`windows-check` workspace member includes `src/identity/access/mod.rs` itself and
depends on nothing but `windows-sys` on Windows and `libc` on unix.

```sh
rustup target add x86_64-pc-windows-msvc x86_64-pc-windows-gnu
for target in x86_64-pc-windows-msvc x86_64-pc-windows-gnu; do
  cargo check -p mahbot-peers-windows-check --target "$target"
  cargo clippy -p mahbot-peers-windows-check --target "$target" -- -D warnings
done
```

`rust-toolchain.toml` pins the channel and the components, not the targets, so the
first line is what a fresh `rustup` installation needs once; without it the check
stops in "can't find crate for `std`". The lint runs per target too: on a host that
is not Windows, `cargo clippy --workspace --all-targets` never compiles the Windows
module at all, so a Windows-only lint failure would otherwise pass here.

That proves the reader and the writer compile for both Windows targets; it runs
nothing. A check of the whole library — `cargo check -p mahbot-peers --target
x86_64-pc-windows-msvc` — stops in `ring`'s C build on a host without the Windows
headers, so it is a gate for a host that has them, not this one. The DACL reader and
writer are exercised for real only on a Windows host, and the inventory records that
procedure.

The default members are the library, the harness and the beacon library; the Windows
type-check crate is a member but not a default one, so the default suite is unchanged.
The beacon server's binary is deliberately not one: it is the only package that
enables quinn's `runtime-tokio`, and building it in the same invocation would
give the harness's tokio a `time` feature it does without. `cargo test` and
`cargo build` over the default members therefore keep the harness's compile-time
guarantee that a timer sleep does not compile; `cargo test --workspace`,
`cargo build --workspace` and `cargo clippy --workspace` unify the feature, and
there the single-source-of-time invariant is what forbids a sleep. The entry
point is therefore compiled by `cargo build -p mahbot-beacon-server` and by
`cargo clippy --workspace`, which are the gates that keep it from rotting; its
decisions live in the library, where the default suite compiles and runs them.

The harness is `publish = false` and depends on the library by path and version,
so packaging it needs `mahbot-peers` 0.1.0 to be on crates.io; the publishable
crate is the library, and that is the one the command above packages. The
workspace members `beacon/`, `beacon-server/`, `harness/` and `windows-check/` are
anchored out of the package by the `exclude` list, so a pattern cannot swallow
`src/beacon/`.

The default suite needs no external host, no service outside the process and no
wall-clock waiting: loopback addresses are used as names on the simulated link
and are never bound. Tests keep no process-global state, so they run in parallel.

## Dependencies

`quinn` 0.11 over `rustls` 0.23 with the `ring` provider, TLS 1.3 and raw public
keys. `quinn`'s `Endpoint`, `AsyncUdpSocket` and `Runtime` appear in the crate's
public API, so a consumer must depend on the same `quinn` 0.11 line rather than
its own copy. No runtime feature is enabled on `quinn` in the library, the
harness or the beacon library: the library is handed a runtime and a socket by
its caller, so it adds no executor, socket or timer driver to a consumer's graph.
Only the beacon server's binary enables `quinn/runtime-tokio`. (`quinn` still
depends on `tokio` itself for its synchronization primitives; what is absent is
the runtime around it.)

Three dependencies are the key file's. `tempfile` writes the key beside itself and
publishes it by an operation that fails if the name exists (`renameat2` with
`RENAME_NOREPLACE` where the kernel has it, `MoveFileEx` without replace on
Windows), which is the half-written-key hazard removed rather than handled. `libc`
is the effective account on unix, which decides whether the owner is us; the six
Darwin ACL calls `libc` does not declare are declared in
`src/identity/access/unix.rs`. `windows-sys` is the DACL on Windows, read and
written. The Windows code is compiled by every Windows build and by nobody on a
host that is not Windows; `windows-check` type-checks it for both Windows targets
here, and the manual procedure for exercising it is in the inventory.
