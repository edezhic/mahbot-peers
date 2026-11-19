# mahbot-peers

The peer layer between mahbot instances: machines connect directly, with no
relay in the path, and remember each other by key. This crate is the network
half — it knows keys, addresses and byte counts; the product knows people,
accounts, rights, authorship and queues.

The crate holds the seams the rest of the layer is built on. There is no
protocol behaviour here yet — no pairing, no delivery, no rights, no identity
file.

## What the crate provides

The library (`src/`) holds the seams:

| Module | What it fixes |
| --- | --- |
| `identity` | one ed25519 identity per instance; the fingerprint is the 44-byte RFC 8410 SubjectPublicKeyInfo and the peer id is the key inside it (the key file under the storage root is not part of the crate yet) |
| `tls` | TLS 1.3 with raw public keys (RFC 7250), pinned to the peer's fingerprint instead of a certificate chain |
| `net` | endpoint construction over an injected datagram socket and an injected clock — no default for either |
| `beacon` | the rendezvous seam: register an id at an address, look an id up, hand an opaque introduction between two parties |

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
- **Beacon stand-in.** An in-memory rendezvous service behind the same seam the
  real one will sit behind. It can be started, stopped and wiped.
- **Witnesses and invariants.** The capability inventory and the cross-cutting
  invariant table live here, together with the checks that enforce them: every
  entry is either witnessed by a recorded case or marked unproducible with a
  reason, the check fails in both directions, and every invariant is proven
  awake by a control snippet it must catch. An empty scan is a failure.

## Building and testing

The toolchain is pinned in `rust-toolchain.toml` (1.99.1, the channel the other
mahbot workspaces use). The crate's own floor is `rust-version = "1.96"`.

```sh
cargo build
cargo test            # the whole workspace: witnesses, summary checks, invariants
cargo clippy --workspace --all-targets -- -D warnings
cargo package --offline -p mahbot-peers   # needs a committed tree
```

The harness is `publish = false` and depends on the library by path and version,
so packaging it needs `mahbot-peers` 0.1.0 to be on crates.io; the publishable
crate is the library, and that is the one the command above packages.

The default suite needs no external host, no service outside the process and no
wall-clock waiting: loopback addresses are used as names on the simulated link
and are never bound. Tests keep no process-global state, so they run in parallel.

## Dependencies

`quinn` 0.11 over `rustls` 0.23 with the `ring` provider, TLS 1.3 and raw public
keys. `quinn`'s `Endpoint`, `AsyncUdpSocket` and `Runtime` appear in the crate's
public API, so a consumer must depend on the same `quinn` 0.11 line rather than
its own copy. No runtime feature is enabled on `quinn`: the library is handed a runtime
and a socket by its caller, so it adds no executor, socket or timer driver to a
consumer's graph — a binary enables `quinn/runtime-tokio` or supplies its own
`quinn::Runtime`. (`quinn` still depends on `tokio` itself for its
synchronization primitives; what is absent is the runtime around it.)
`quinn-proto` is held as a direct dependency so the lockfile
can be raised on that line alone: 0.11.19 is the lowest release with no open
RustSec advisory (every one of them a denial of service), and the floor must not
be lost behind the facade. `cargo audit` over the whole graph is a manual gate
before any tag or lockfile change; there is no automatic CI. There are no git
dependencies, so the crate packages and publishes as it stands.
