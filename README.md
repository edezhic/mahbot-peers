# mahbot-peers

The peer layer between mahbot instances: machines connect directly, with no
relay in the path, and remember each other by key. This crate is the network
half — it knows keys, addresses, byte counts, the messages one machine queues for
another, the actions one asks another to run, and the bytes of a whole file in
flight; the product knows people, accounts, rights, what a message means, what an
action runs, where a file lands, how it is named on disk and what happens to a
partial one. The screen is not here.

The public modules are `identity`, `tls`, `net`, `beacon` and `peer`; `peer`'s module doc lists
its layers and what each is for.

## What you supply, and what the crate does not do

The library reads no ambient state. A caller hands in a storage root, an
`Identity`, a `quinn::AsyncUdpSocket`, a `quinn::Runtime`, and every durable
moment as a `Timestamp`; waits are measured by the injected runtime's timer. It
opens no socket, builds no runtime and resolves no path or configuration.

The crate never hashes a transferred file and never turns its name into a path. It
never invents an identity, an account name or a label: the labels it stores are the
product's, and a peer's key never becomes a name. It does not execute a message, an
action body or a file: an action body goes to the product's `Executor`, a file's
bytes to its `Sink`, and a message body is opaque.

The product runs the pieces the crate hands back: `Connections::serve` for
accepts, one `Connections::keep_connected` per paired peer, one `Presence` per
machine, and one `Inbox::serve` per paired peer when messages, actions or
transfers are wanted. The crate spawns only on the runtime it was handed.

Every refusal is a typed error, never a log line a caller can continue past. A key
file's or a storage root's refusal names the path, the fact and, where the rule
appends one, a runnable command; `identity::access` is the exact wording table.

## The storage root

One root is one machine. Everything the crate keeps durably is under it:

- `identity.key` — the machine's ed25519 identity (`identity::keyfile`).
- `peers/<64 hex>.record` — the durable peer records (`peer::record`).
- `audit.log` — the append-only record of what happened (`peer::audit`).
- `messages/` — the queues one machine keeps for a peer (`peer::messages`).
- `actions/` — the executed identifiers and unknown marks (`peer::actions`).

All five are private to the account the product runs as, and all five are
permanent formats. A transfer is not a sixth: it adds no format of its own, and
its authorisation is an audit entry.

## The identity

A machine is one ed25519 key, and the unit of identity is the storage root: two
roots are two peers, even on one machine. `identity` states the key, the
fingerprint derived from it and its one rendering.

The key file's name, format, guarantees, typed refusals, one create and one
rendering are a permanent compatibility contract, because a key is never rotated
and there is no migration; `identity::keyfile` states them. Two consequences a
product must plan for: a copy of a root is the same machine, so a peer that
presents this machine's own key is refused as a clone; and deleting the key is
the only deliberate way to become a new machine.

## The transport

`net` builds the endpoint over the socket and runtime you hand in; `tls` is the
pinning: TLS 1.3 with raw public keys, the peer's fingerprint in place of a
certificate chain.

## The peer record and the pair

A peer record has two levels, the machine's and the connection's (`peer::access`),
in one file per peer under `peers/`. Its format is additive and versioned, and
`peer::record` states it and the rules every write keeps.

`peer::access` defines the pair and the binding. The decision is the connected
machine's: `Rights::bind` writes it durably there and issues the pair's default,
and the other side keeps a `Claim` that grants nothing. A product that moves a
machine to another assistant must treat it as a new pair.

## The acquaintance ceremony

Two people make two machines acquainted by comparing six symbols. `peer::pair` is
the ceremony's contract, and `Limits` states what an unfinished attempt costs and
what a rejection counts.

## Rights

A right is `(peer, assistant, capability, term, issuer, withdrawn)`. The five
capabilities and the closed list are `peer::access`'s; three are served today —
write to me, work on me and put files on me.

`peer::rights` is the decision and the contract: the order of its questions, who
may write a right, the default a pair comes into being with, what withdrawal and
return do, and what the audit records. The floor is yours to implement: `Floor`
is asked after a right exists, and can only refuse.

## The audit

`peer::audit` is the private append-only log under the storage root. The module states
what is recorded, the ordering, the torn tail, the cap and the room a person keeps below
it.

## The connection manager

`Connections` is the per-machine manager: one connection per pair, the dial, the punch
and the keeper. `peer::connect` is the contract — the dial's order, the punch and its
18-row outcome table, and what a withdrawn trust stops without the caller reloading —
and `peer::recovery` states the answer set and which answers are retried.

A refusal's text is diagnostic: it may have been written by the far side, so a product
decides neither trust nor a retry from it.

## Recovery

Run `Connections::keep_connected` once per paired peer, and show what
`Connections::recovery` reports; `Connections::watched` says whether a keeper will act on
a pair. A product with news the crate cannot see hands it in through `Connections::wake`;
`Connections::ensure` makes one dial only when the policy is due, which is how a queue or
a transfer dials without hammering the peer. The policy is `peer::recovery`'s module
documentation, and that is the contract: a bounded, visible, paced retry is not the
silent retry loop the design rules out.

## Presence at the beacon

Build one `Presence` per machine and keep it for as long as the machine runs. Reach
the beacon through it rather than through a `Session` of your own, and hand it to the
ceremony and to `Connections::with_presence`. `peer::presence` is the exact contract.

## The beacon

The beacon is introduction and address service and nothing else; `beacon`
states what it never sees and what makes it safe to rely on. `peer::connect`
states what it does see: the candidate list a punch relays, private local
addresses included, because an introduction is signed and not encrypted. The
product pins the beacon's address and key.

A restart loses every registration by construction, and `beacon::wire` is the
closed message set.

## Messages

A body is opaque: escape it, and take the author from `Delivery::sender`, the
connection's attested peer — never from anything in the body. Store durably inside
`Deliveries::deliver` and deduplicate on the identifier. Do not re-send after a restart:
the queue is durable. `peer::messages` is the exact contract.

## Actions

At most once is the caller's: remember an operation's identifier before asking, and never
reuse one for a different operation. `peer::actions` is the exact contract.

## Files

A whole file moves over the pair's own connection, and the direction is one: a machine
offers a file and it lands on the peer. Nothing fetches. The product supplies a `Source` and
a `Sink`, and, at offer time, the file's length and the SHA-256 it must have; `peer::transfer`
states what each must answer, and `Transfers::open` what a machine with no sink refuses.

A transfer's name is the product's, scoped to one peer; `TransferName` states what it may be.
A product with no sink must not grant `Capability::PUT_FILES`.

## The beacon server

`beacon/` is the server library (`mahbot-beacon`, `publish = false`) and
`beacon-server/` is its process entry point (`mahbot-beacon-server`). Neither is
published; the owner runs the binary:

```sh
cargo build -p mahbot-beacon-server
mkdir -p "$HOME/.mahbot-beacon"
target/debug/mahbot-beacon-server \
  --listen 0.0.0.0:4433 --root "$HOME/.mahbot-beacon"
```

The key is the beacon's identity and lives in that directory as `identity.key` —
the same name, format and privacy rule as a machine's, created once and never
replaced. It is printed at start as a fingerprint; that is the key the product
pins. Keep the directory out of the checkout: `.gitignore` covers `*.key` as a
second line of defence.

## What 0.1.0 contains

This release changes the public surface, which nothing published before this one had to. The accept
path takes the manager's endpoint: `Inbox::serve` and the message service are given it so that a
queued message can cause a dial. `Presence` keeps its own registration: it registers when it is
built and refreshes itself, and `Presence::state` reports a `Registration` — no answer from the
beacon yet, registered, or the beacon unreachable with the moment the next try was due — so a product
can show a beacon outage instead of looking as though nothing were wrong. The policy has a module of
its own, `peer::recovery`, because the state a product shows and the failures it reports are one
contract: `Recovery`, `StopCause`, `ConnectFailure` and `NotTrustedCause` live there — the last
two moved from `peer::connect` and are still re-exported from `peer` — together with the stated
numbers a caller plans against, `RECOVERY_FIRST_GAP`, `RECOVERY_DIALS` and `RECOVERY_RECHECK`, which
is the bound the slow re-check never exceeds, and `DIAL_BUDGET`, the longest one dial may take,
which the action budget reserves so that a record read cannot cost the dial. `ConnectFailure` gained
`Nowhere` — no beacon and no remembered address, which is configuration rather than a network
state — and `Deferred` — this machine could not read the peer's record just now, which is not a
statement about the peer and not a claim that a dial was made. `Connections` gained `wake` (a person
asking again starts a fresh episode), `ensure` (one dial, paced by the policy, which is how a queued
message or a requested action dials), `recovery` and `watched` (the state, and whether a keeper will
act on it), and `vanish_bound`, whose `Vanish` is a reading rather than a bare duration.
`VANISH_BOUND` is the floor of the bound that reading states, public because a caller choosing a
keep-alive acts on it. `ACCEPT_IN_FLIGHT` is the cap on half-finished handshakes one machine carries
at once — public because the lane count it replaced was, and because a caller opening a public
address needs the number. `Keeper`, `ACCEPT_LANES` and `KEEPER_UNSTABLE_LIMIT` are gone, and
`Connections::keep_connected` answers the `StopCause` it stopped for. `Presence` is no longer
`Clone` — it holds the registration it reports — so a product keeps it once, behind whatever it
already shares, rather than copying it. One registration per machine, and one reader:
`Presence::new` starts the registration and the reader itself, and `Presence::run` is gone, because
a loop the caller can cancel is a registration the caller can lose while a ceremony is using it.
`pair::run` takes a `&Presence` instead of a `Session`, so a caller no longer registers a session of
its own to run a ceremony. `Presence` gained `lookup`, `observed_address`, `introduce`, `runtime`,
`flights` and `openings`, and `Flights` is new: `next` for the next introduction of the peer the
handle is bound to, and a borrow of the presence so a handle cannot outlive the registration it
reads. `MAX_HELD` is public because it is the hold's stated bound, and `openings` hands held
openings out newest first. `MAX_PENDING` is public for the same reason: it is how many of one peer's
flights wait for its ceremony, and they wait in the order the peer sent them — a newer flight does
not displace an undelivered older one below the bound, and at the bound the oldest goes. Only an
opening is held, because only an opening can start a ceremony, and a flight is aged by the wait its
sender is under — the machine-flight timeout for a machine flight, the attempt's own lifetime for
a confirmation. Dropping the presence ends both of its tasks; a dial already in flight is the one
wait a drop does not cancel, and its bound is `BEACON_REQUEST_TIMEOUT`. A ceremony that waits to be
called keeps waiting for as long as its person might still start on the other machine, and it names
no cause about the peer: a machine that is not registered cannot be reached by the other side at
all, and says so through `Presence::state`, which is where a product reads a beacon outage during a
ceremony.

The punch adds its own surface. `Connections::with_presence` hands the manager the machine's one
`Presence`, shared as an `Arc` with the ceremony that compares under the same registration — which
is what lets the manager step aside while a ceremony with that peer is running — so a candidate
list can travel both ways; a manager built without one still sends its candidates and dials the
beacon's address, but cannot receive the peer's, so its punch is one-sided. `Connections::declares`
states the addresses the product knows this machine has — the only way a private candidate is
dialled, because nothing here reads the interfaces. `PeerRecord::addresses` is the bounded
newest-first list the record keeps, `RecordStore::record_address` now maintains that list rather
than one address, and `RecordStore::forget_address` drops one the handshake disproved — an address
that answered with another machine's key — best effort: a failed write leaves it, and the next
dial meets the same key once more. `ConnectFailure::NoDirectPath` carries `candidates`, every
address the dial failed at, in the order it tried them and without repeats. A key that is not the
peer's is the one address fault that leaves the refusal and becomes an answer of its own:
`ConnectFailure::WrongPeer` carries the peer asked for, the key that answered and the address it
answered from. `connect_with` answers it even when the pair holds a connection, and `ensure` answers
it beside `Recovery::Connected` when its own dial met it, because `ensure` asks for the policy's
pace and a pair that is already up has nothing to pace.
`peer::{MAX_CANDIDATES, MAX_REMEMBERED_ADDRESSES, PUNCH_REARM}` are public because each is a bound a
caller plans against: the most candidates one punch may dial, the most addresses one record keeps
— a permanent format bound, so a later build that needs more adds a record tag rather than raising
it — and the least time between two re-arms of a punch.

`BeaconError::UnknownPeer`'s text says the beacon did not hand the payload over where it used to say
the peer was not reachable, which the beacon's one answer does not prove; a ceremony flight it did
not take is that same error on `PairError::Beacon`, so one sentence covers one fact.

`PairError::FlightTimeout` names the wait that ended and nothing about why nothing arrived.

## Building and testing

The toolchain is pinned in `rust-toolchain.toml`; the crate's own floor is `rust-version = "1.96"`.
The workspace is the published library, the harness, the beacon library, the beacon server's binary
and a Windows type-check crate. The gates are:

```sh
cargo test
cargo clippy --workspace --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
cargo package --offline -p mahbot-peers   # needs a committed tree
cargo build -p mahbot-beacon-server
```

`windows-check` type-checks and lints the Windows reader for both Windows targets on a host that
is not Windows.

The default suite needs no external host, no service and no wall-clock waiting, and keeps no
process-global state, so it runs in parallel.

## Dependencies

`quinn` 0.11 over `rustls` 0.23 with the `ring` provider. `quinn`'s `Endpoint`, `AsyncUdpSocket`
and `Runtime` appear in the crate's public API, so a consumer must depend on the same `quinn` 0.11
line rather than its own copy. No runtime feature is enabled on `quinn` in the library, the harness
or the beacon library: the library is handed a runtime and a socket by its caller, so it adds no
executor, socket or timer driver to a consumer's graph. Only the beacon server's binary enables
`quinn/runtime-tokio`. (`quinn` still depends on `tokio` itself for its synchronization primitives;
what is absent is the runtime around it.)

Three dependencies are the private files': `tempfile`, `libc` on unix and `windows-sys` on
Windows.

## How this repository proves itself

Every capability is witnessed by a recorded case or declared unproducible with the
reason and the procedure that produces it, and every row of the outcome table in
`peer::connect` is a recorded case or a declared gap with its reason. `harness/`
is that rig, and it is never published.
