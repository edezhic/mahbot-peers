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
| `identity` | one ed25519 identity per instance; the fingerprint is the 44-byte RFC 8410 SubjectPublicKeyInfo and the peer id is the key inside it. The key signs and round-trips through PKCS#8; the key file under the storage root is not part of the crate yet |
| `tls` | TLS 1.3 with raw public keys (RFC 7250), pinned to the peer's fingerprint instead of a certificate chain, with a per-service ALPN |
| `net` | endpoint construction over an injected datagram socket and an injected clock — no default for either |
| `beacon` | the beacon: the closed message set (`wire`) and the client half (`Beacon`, `Session`) — register, look an id up, learn the address observed on this path, hand a signed introduction over, take the ones pushed to a live session |

The beacon is introduction and address service and nothing else. It remembers
where an id currently is, in memory and for a short lifetime; it relays an
opaque payload between two machines that are both present; it answers with the
address it observes on the connection the question arrived over. It carries no
conversation bytes, holds no accounts, rights, authorship or queues, executes
nothing, keeps no state on disk and knows no secret but its own identity.

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
a bounded failure, not a session that looks open forever. The server's own bound
per exchange is smaller, so a live but slow beacon is never reported as dead.
`next_introduction`'s wait for the beacon to speak first is the caller's.

## The server

`beacon/` is the server library (`mahbot-beacon`, `publish = false`) and
`beacon-server/` is its process entry point (`mahbot-beacon-server`). Neither is
published; the owner runs the binary:

```sh
cargo build -p mahbot-beacon-server
mkdir -p "$HOME/.mahbot-beacon"
target/debug/mahbot-beacon-server \
  --listen 0.0.0.0:4433 --key "$HOME/.mahbot-beacon/beacon.key"
```

Keep the key out of the checkout: it is the beacon's identity, and `.gitignore`
covers `*.key` as a second line of defence. It is printed at start as a
fingerprint; that is the key the product pins. On unix the file is created with
mode 0600 if absent and refused if other users can read it; on Windows it
inherits the profile's ACLs, and the beacon is the owner's server. The key is the
only thing the beacon persists — it is configuration, not state. Registrations
live in memory and are gone on restart.

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
clock, and owns the key file. The source scan excludes that one file with a stated
reason (the invariant table itself is not scanned either, because it holds the
patterns); `harness/tests/summary.rs` proves the exclusion list is exactly that
file, that the file still needs it, and that no other file in the entry crate
escapes the no-state-on-disk claim. What the entry point decides — what the
command line means, whether a key file is private — is a pure function in the
library and is witnessed in a default build, so the excluded surface stays glue.

## The harness

The harness (`harness/`, never published) is the test rig:

- **Machines.** `Sim::machine()` creates a machine with its own temporary root,
  its own identity and its own address on the link. The handle exposes no
  filesystem path, and its storage capability refuses any root but its own.
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
  entry is either witnessed by a recorded case or marked unproducible with a
  reason, the check fails in both directions, and every invariant is proven
  awake by a control snippet it must catch. An empty scan is a failure, and the
  one excluded file is named with its reason and re-proven necessary.

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

The default members are the library, the harness and the beacon library. The
beacon server's binary is deliberately not one: it is the only package that
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
workspace members `beacon/`, `beacon-server/` and `harness/` are anchored out of
the package by the `exclude` list, so a pattern cannot swallow `src/beacon/`.

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
