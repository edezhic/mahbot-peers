# mahbot-peers

The peer layer between mahbot instances: machines connect directly, with no
relay in the path, and remember each other by key. This crate is the network
half — it knows keys, addresses and byte counts; the product knows people,
accounts, rights, authorship and queues.

The crate holds the seams the rest of the layer is built on — identity and its key
file, the QUIC transport over raw public keys, the beacon — and the peer layer above
them. Delivery is not here yet; the connection level and the rights are.

## What the crate provides

The library (`src/`) holds:

| Module | What it fixes |
| --- | --- |
| `identity` | one ed25519 identity per storage root, in a key file the caller's root holds; the fingerprint is the 44-byte RFC 8410 SubjectPublicKeyInfo and the peer id is the key inside it. `identity::access` is who may reach that file, `identity::keyfile` is its name, its format and its one create |
| `tls` | TLS 1.3 with raw public keys (RFC 7250), pinned to the peer's fingerprint instead of a certificate chain, with a per-service ALPN and resumption off so the pin always runs |
| `net` | endpoint construction over an injected datagram socket and an injected clock — no default for either |
| `beacon` | the beacon: the closed message set (`wire`), the client half (`Beacon`, `Session`) — register, look an id up, learn the address observed on this path, hand a signed introduction over, take the ones pushed to a live session — and the one deadline combinator the client and the server share (`timeout`, whose documentation says why there is one copy and not two) |
| `peer` | the peer layer: `record` is the durable memory of another machine, at both levels; `access` is the connection level's vocabulary — the account on the instance, the assistant, the pair, the four capabilities, the rights and the small versioned fact; `pair` the acquaintance ceremony, `connect` the per-machine connection manager, `presence` the registration refresh, `binding` the exchange that carries the connection level over a live connection, `rights` the decision, `audit` the record of what happened. Each is documented where it is enforced |

The key-replacement invariant covers every shipped source: no `fs::rename`,
`remove_dir` or `fs::copy` anywhere, and no write form in the identity module. The
record and the audit log are both created through `tempfile`, not a rename of their own;
the log is then the one private file appended in place, because an append-only record
cannot be rewritten without losing a concurrent writer's entry.

## The identity

A machine is one ed25519 key, and the unit of identity is the storage root: two
roots are two peers, even on one machine. The library never resolves the root
itself — a caller hands one in — and it reads no configuration.

The key file's name, its format, the guarantees, the typed refusals, the one
create and the one rendering are a permanent compatibility contract, because a key
is never rotated and there is no migration. They are stated once, where they are
enforced: `identity::keyfile` for the file, `identity` for the pinned bytes and
their rendering. What a reader of this crate needs here is the shape: one identity
per root; a copy of a root is the same machine, so a peer that presents this machine's
own key is refused as a clone, with an answer distinct from an untrusted peer's. What
losing the key means, and why
deleting it is the only deliberate way to become a new machine, are in
`identity::keyfile`; three source-scan invariants keep a replacement from happening
by accident.

Windows is the platform this repository has no host for: the rule is witnessed
everywhere as a decision, the reader and the writer type-check for both Windows
targets through `windows-check` (a crate that compiles just those sources and
nothing else), and the inventory entry `library.identity.key_file.windows_dacl`
carries the manual procedure, first creation included. The accounts that procedure
grants, removes or sets as owner, other than the one the product runs as, are written
by SID in the quoted `"*S-1-…"` form `identity::access` documents, so it runs on an
installation whose display language is not English; that account is `%USERNAME%`.

A refusal is a typed error, never a log line a caller can continue past, and its
message is the same text on every run: it names the path, the fact, and, where the
rule appends one, a command with the same path, quoted for that platform's own tool,
so it can be run as printed. A key file's refusal appends a command for a unix mode
(`chmod`), a Windows owner that is not this account or a file with none
(`icacls /setowner`), a macOS extended entry (`chmod -N`) and an inherited Windows
list (the protected list). A storage root's refusal appends one for two of them — the
macOS entry and the inherited Windows list — and names what has to change for the rest.
For the key file's message, every other cause has a repair that exists and is not
appended, and `identity::access`'s documentation is the authority that says what each
message prints, which causes append nothing and what each of those repairs depends on:
the unix hand-back, a missing or unattributable list, a fourth account, and a replaced
link or non-regular file. This paragraph is the summary; the table there is the exact
text. A file state this suite cannot produce is recorded in the capability inventory
(`harness/src/inventory.rs`) as unproducible, with what does produce it: a manual
procedure for the foreign owner (a second account on unix; an elevated prompt of the
same account on Windows), for the Windows access-list states, and — off macOS — for
the extended access list; and for the two Windows shapes the record cannot show being
produced — a file with no owner and an entry this reader cannot attribute — the record
says so, and the case that decides them as data is the evidence. Every procedure that
changes the key file names a scratch root of its own before it changes anything — the
account-name procedure changes no file and names none — and each states what it needs
and checks the result of every change: the refusal it must raise, or the same identity
once the state is repaired.

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

## The connection level and the rights

A peer record has two levels. The machine's is the key, the pairing, the address, the
failures and the trust. The connection's is `peer::access`: which account on which
instance the machine is connected to, which assistant it is bound to, the claim the
other side's decision left here, and one right per pair and capability. The unit is the
plan's: a machine together with the assistant it is connected to.

The assistant a machine is connected to is decided by the machine it is connected to,
and only there. `Rights::bind` writes that decision durably on the deciding machine and
issues the default for the pair; a machine moved to another assistant is a new pair,
which starts from the default and inherits nothing from the pair it left. The decision
travels to the other side as a small versioned fact over the direct connection, on a
task the connection manager runs after it adopts a connection, and is kept there as a
claim. A claim names the pair for that machine's person and grants nothing: the
decision never reads it, and the crate never allows anything because another machine
said so. The account label in it is the deciding machine's word, shown and never used;
the crate never invents one and never turns a peer's key into one.

A right is `(peer, assistant, capability, term, issuer, withdrawn)`. The plan's scope
field is deliberately not here: no capability yet names a resource it would narrow, and
the format is additive, so it arrives as its own tag when one does. The four
capabilities are write to me, take files from me, work on me and see the screen — one
capability covering watching and acting. The list is closed: a right stored for a
capability this build does not know is kept and written back untouched, and no question
this build can ask matches it.

Only this machine's own person, or its own default, can write a right. A write
attributed to a peer is refused before it changes anything and the refusal is recorded.
The default has one act per pair: exactly "write to me", once, when the pair comes into
being, and again only when a person returns the machine from a withdrawn trust. It never
re-creates a right a person withdrew or one that ended, and it renews nothing: the row
stays on file, and its presence is what stops the default acting again. The default is
one capability for every assistant — the plan's guest floor — so a guest is never
defaulted `work on me` or `see the screen`, and a person may widen it explicitly, with
the record naming that person. The product's declaration of which assistant is a guest
is not stored: it changes no decision the crate makes, and the format is additive when a
decision depends on it.

`Rights::decide` answers the one question — may this connection, as this assistant,
exercise this capability on this machine now — in the plan's order: authenticate, right,
the host's own floor. The answer names either the right that allowed it or the step and
reason that refused: not authenticated, the machine is not trusted, no right for this
pair, the right was withdrawn, the right ended, or the host's floor refused it. Each
refusal belongs to exactly one step. A question naming a pair this machine did not bind
the machine to is refused for want of a right. The floor is the product's — the crate
never says what it allows — and it can only refuse what a right already gives, never
add; a refusal at the floor is not a withdrawal, and the right stays on file. Nothing
executes here.

A right a person withdraws refuses the next question with no new connection needed. A
right given a term ends by itself, the ending is recorded once, and nothing renews it.
Withdrawing trust in a whole machine is a separate act: it removes the rights that
machine held, makes it untrusted — its next handshake is refused, the manager closes
what is live and stops reaching for it — and keeps the binding, so a return needs no new
comparison and issues again only the default. `restore_trust` issues the default for the
pair the binding names, whatever pair the caller passed, and it is one act: a call that
finds the trust back and the default not yet issued finishes it rather than reporting
that it is over, and only a return whose default has acted answers that there is nothing
to restore. The pairing attempt lock is a separate person act, so a return on a machine
whose comparisons closed the pair answers the lock it left standing (`Restored::closed`)
instead of a right the machine cannot use.

Nothing on that path depends on who holds which handle. The manager asks the record on
disk before every dial, before every handshake and once per keeper round while a
connection is up — `TRUST_POLL` while a connection is watched, `KEEPER_SETTLE` while a
fresh dial is still being judged — so a withdrawal written through the rights layer's
store, another store over the same root, or the other process the self-update window
keeps on it stops the manager: the live connection is closed and the keeper stops naming
the withdrawal, with no reload asked of the caller. A record that is there and cannot be
read is its own cause, not an unpaired machine: the manager fails closed and names the
file. `Connections::disconnect` remains the immediate way to close it in the same act.

Every grant, refusal, ending, withdrawal, return and attempt-lock clearing is appended
to `peer::audit`, a private append-only log under the storage root, before the record
changes: a crash may leave a recorded act that did not happen and never an act nobody
recorded. The log is created as a private temporary file and published without
replacing, so it carries the rule before its first byte lands. Every append re-checks the
log's privacy on the descriptor it writes through, so a log another account can read
refuses the next append, and every append cuts a torn tail another process left before
writing past it. A half-written last entry is cut back, and a half-written header is
completed rather than refused. The log keeps the bytes below its cap minus
`RESERVED_FOR_PERSON_BYTES` for a person: the entries a peer causes by asking — a
refusal, a refused write, an ending a question notices — stop there and are answered
without an entry, while a grant, a withdrawal, a trust withdrawal, a return and an
attempt-lock clearing may use the whole file, so a peer cannot fill the log and take
away the acts that stop it. A person's act that would pass the cap is refused until the
product makes room, and an ending that finds no room is answered and left unmarked: the
log is never compacted, so what a peer's part loses stays lost. The record is re-read
before every question, so a withdrawal by another process on the same root refuses the
next question on this one. Every moment is the caller's; the crate reads no clock.

The connection manager's rule for a fresh connection now reads the binding exchange as
what it is: the manager's own handshake, not the pair's use. A connection that only
exchanged its binding and then died carried nothing, and the keeper's strike rule
applies to it.

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
  capability refuses any root but its own. `Machine::restart` closes the endpoint,
  waits — on the virtual clock — for the transport to let go of the socket, and
  brings the machine back over the same root at a new address, with the identity and
  the records read from disk again: everything a process restart keeps is the root.
  `Machine::audit` and `Machine::rights` open the machine's log and its decision over
  the same root, so a case reads exactly what a restart would; the binding exchange
  runs on its own task, so a case that asserts on a claim waits for it while the
  clock is driven.
- **Mediator.** `pair::Mediator` is a party with its own key, its own address and a
  live beacon session. It answers one machine's ceremony and starts another with a
  second machine, confirming both, so a case can show that the two strings differ and
  that a pair whose strings differ is recorded on neither side.
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
publishes it by an operation that fails if the name exists (`renameatx_np` with
`RENAME_EXCL` on macOS, `renameat2` with `RENAME_NOREPLACE` on Linux where the kernel
has it, `MoveFileEx` without replace on Windows, or a hard link when the platform call
is not usable), which is the half-written-key hazard removed rather than handled.
`libc` is unix's: the effective account (`geteuid`), the login name for a uid
(`getpwuid_r`/`passwd`), the open flags that make a link or a FIFO a refusal rather
than a wait (`O_NOFOLLOW`, `O_NONBLOCK`), and the error codes those checks answer with
(`ELOOP` for a link; `ENOENT`, `ENOTSUP` and `EOPNOTSUPP` when a macOS file has no
extended list or its volume has no ACLs). It declares none of the six Darwin
declarations the macOS reader needs — the five `sys/acl.h` calls and `mbr_uuid_to_id`
from `<membership.h>` — and `src/identity/access/unix.rs` declares them itself.
`windows-sys` is the DACL on Windows, read and written. The Windows code
is compiled by every Windows build and by nobody on a host that is not Windows;
`windows-check` type-checks it for both Windows targets here, and the manual procedure
for exercising it is in the inventory.
