# mahbot-peers

The peer layer between mahbot instances: machines connect directly, with no
relay in the path, and remember each other by key. This crate is the network
half — it knows keys, addresses, byte counts, the messages one machine queues for
another, the actions one asks another to run, and the bytes of a whole file in
flight; the product knows people, accounts, rights, what a message means, what an
action runs, where a file lands, how it is named on disk and what happens to a
partial one.

The crate holds the seams the rest of the layer is built on — identity and its key
file, the QUIC transport over raw public keys, the beacon — and the peer layer above
them. Messages, actions and files are here: a message is queued at its sender, offered
over the pair's direct connection, decided by the receiver's rights and delivered at
least once; an action carries the caller's identifier, is executed at most once, and a
repeat is answered "already executed"; a whole file moves over the same connection —
an offer, the receiver's one decision, then the bytes, with resume, a SHA-256 the
receiver verifies, and a backpressure that is the transport's. What stays with the
product is where a file lands, how it is named on disk and what happens to a partial
file. The screen is not here.

## What the crate provides

The library (`src/`) holds:

| Module | What it fixes |
| --- | --- |
| `identity` | one ed25519 identity per storage root, in a key file the caller's root holds; the fingerprint is the 44-byte RFC 8410 SubjectPublicKeyInfo and the peer id is the key inside it. `identity::access` is who may reach that file, `identity::keyfile` is its name, its format and its one create |
| `tls` | TLS 1.3 with raw public keys (RFC 7250), pinned to the peer's fingerprint instead of a certificate chain, with a per-service ALPN and resumption off so the pin always runs |
| `net` | endpoint construction over an injected datagram socket and an injected clock — no default for either |
| `beacon` | the beacon: the closed message set (`wire`), the client half (`Beacon`, `Session`) — register, look an id up, learn the address observed on this path, hand a signed introduction over, take the ones pushed to a live session — and the one deadline combinator the client and the server share (`timeout`, whose documentation says why there is one copy and not two) |
| `peer` | the peer layer: `record` is the durable memory of another machine, at both levels; `access` is the connection level's vocabulary — the account on the instance, the assistant, the pair, the five capabilities, the rights and the small versioned fact; `pair` the acquaintance ceremony, `connect` the per-machine connection manager and the punch, `traverse` the punch's candidate set, its signed payload and its filter (private, and no protocol of its own), `recovery` the one retry policy for a pair, `presence` the machine's one registration at the beacon — kept alive by itself, and the one reader of what the beacon pushes to it, dispatching each payload by kind: a ceremony flight, a candidate list, or a stranger's bytes it drops, `binding` the exchange that carries the connection level over a live connection, `rights` the decision, `audit` the record of what happened, `messages` the queue a machine keeps for a peer and the offer it makes over the pair's own connection, `actions` the at-most-once command with its durable journal and unknown marks, `transfer` the whole-file transfer over the pair's own connection — an offer, the receiver's one decision, then the bytes with resume, a SHA-256 the product reports at each end and the crate compares, and a backpressure that is the transport's — and `inbox` the one reader that tells a message from an action from a transfer on that connection. Each is documented where it is enforced |

The key-replacement invariant covers every shipped source: no `fs::rename`,
`remove_dir` or `fs::copy` anywhere, and no write form in the identity module. The
record, the message queues and the action memories are all created through `tempfile`,
not a rename of their own; the log is the one private file appended in place, because an
append-only record cannot be rewritten without losing a concurrent writer's entry.

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
connection the peers use. It keeps that shape, and it is one input to a punch, not
a check: the check is the authenticated handshake the two machines run themselves.
An answer obtained over some other socket would name an address the peers cannot
reach, so no second socket is opened for it. The beacon never sees a punch and
gains no duty from one: it relays the candidate list in the signed introduction
payload as it relays a ceremony flight, without acting on it — and because that
payload is signed and not encrypted, it can read the list, private LAN addresses
included.

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

A peer record has two levels. The machine's is the key, the pairing, the addresses
it remembers — a bounded newest-first list — the failures and the trust. The
connection's is `peer::access`: which account on which
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
the format is additive, so it arrives as its own tag when one does. "Put files on me" is
no exception to that, though it is the one that looks like one: it grants an undirected
push into a place the product chooses, so there is no resource the crate could name in the
right. The five capabilities are write to me, put files on me, work on me, take files
from me and see the screen — the last of which is one capability covering watching and
acting. Only three of them are served by anything: write to me, put files on me and work
on me. "Take files from me" and "see the screen" are inert — nothing lets a peer ask this
machine for a file of its own, and nothing streams the screen yet — so granting either
changes nothing. The list is closed: a right stored for a capability this build does not
know is kept and written back untouched, and no question this build can ask matches it.

Only this machine's own person, or its own default, can write a right. A write
attributed to a peer is refused before it changes anything and the refusal is recorded.
The default has one act per pair: exactly "write to me", once, when the pair comes into
being, and again only when a person returns the machine from a withdrawn trust. It never
re-creates a right a person withdrew or one that ended, and it renews nothing: the row
stays on file, and its presence is what stops the default acting again. It covers
messages and the addressed reply and never a file landing here: file ingress is an
explicit grant by the person on the machine that bears the effect. The default is
one capability for every assistant — the plan's guest floor — so a guest is never
defaulted `work on me`, `see the screen` or `put files on me`, and a person may widen it
explicitly, with the record naming that person. The product's declaration of which
assistant is a guest is not stored: it changes no decision the crate makes, and the
format is additive when a decision depends on it.

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
connection is up, and a round that watches a connection is at most `TRUST_POLL` — the
settle window only cuts it shorter, and a round that dials is the dial's own budget
instead, with nothing up to withdraw — so a withdrawal written through the rights layer's
store, another store over the same root, or the other process the self-update window
keeps on it stops the manager: the live connection is closed and the keeper stops naming
the withdrawal, with no reload asked of the caller. A record that is there and cannot be
read is its own cause, not an unpaired machine: the manager fails closed and names the
file. `Connections::disconnect` remains the immediate way to close it in the same act.

Every grant, refusal, ending, withdrawal, return, attempt-lock clearing, refused message, dropped
queue, executed action and authorised transfer is appended to `peer::audit`, a private append-only
log under the storage root, before the act it describes: a crash may leave a recorded act that did
not happen and never an act nobody recorded. The log is created as a private temporary file and
published without replacing, so it carries the rule before its first byte lands. Every append
re-checks the log's privacy on the descriptor it writes through, so a log another account can read
refuses the next append, and every append cuts a torn tail another process left before writing past
it. A half-written last entry is cut back, and a half-written header is completed rather than
refused. The log keeps the bytes below its cap minus `RESERVED_FOR_PERSON_BYTES` for a person: the
entries a peer causes by asking — a refusal, a refused write, an ending a question notices, a
message a receiver refuses, an executed action, a transfer it authorised — stop there and are
answered without an entry, while a grant, a withdrawal, a trust withdrawal, a return and an
attempt-lock clearing may use the whole file, so a peer cannot fill the log and take away the acts
that stop it. A person's act that would pass the cap is refused until the product makes room, and an
ending that finds no room is answered and left unmarked: the log is never compacted, so what a
peer's part loses stays lost. The record is re-read before every question, so a withdrawal by
another process on the same root refuses the next question on this one. Every moment is the
caller's; the crate reads no clock.

The connection manager's rule for a fresh connection reads the binding exchange, a message
offer, an action request and a transfer attempt as what they are: the manager's own handshake
and the sender's own act, not the pair's use. A connection that only exchanged its binding, or
offered a message or an action nobody answered, or opened a transfer that moved no byte, and
then died carried nothing, so it is one dial of the pair's recovery like any other that
carried nothing. A message the receiver took, or answered "already taken", an action whose
answer means the receiver accepted it — it ran, ran with a result too large to carry, or the
identifier was already spent — or a transfer that moved a byte is the pair's use and ends the
run of dials, which is what keeps a machine holding one queued message, one unanswered action
or one file in flight from being re-dialled for ever.

## Recovery

A pair that has been acquainted recovers by itself, and the crate owns that: the product only
shows what the crate reports. `Connections::keep_connected` is run once per paired peer and never
returns while the pair is trusted and there is somewhere to dial. `Connections::recovery` says
what the policy is doing at any moment — no keeper running for the pair, connected, dialling,
waiting after a stated failure, an episode used up with its last failure, or stopped with the
reason — and `Connections::watched` says whether a keeper will act on it. The moments are fields,
because an `Instant` has no rendering of its own; `Display` gives a sentence a product may show,
and it states a condition rather than a schedule — "the episode is used up", "stopped: this machine
does not trust the peer" — because a reason to dial can move the moment.

The policy itself — the episode, the gaps, the slow re-check, which reasons start a fresh episode
and which only make the next dial due, what is retried and what never is, and why an authenticated
inbound connection consumes a dial number instead of starting an episode — is stated once, in
`src/peer/recovery.rs`'s module documentation, and that is the contract. This section summarises
it and does not restate it: a restated contract is one that will be wrong somewhere within a week.
Between them those rules are what make a pair come back after one machine was switched off for
hours, after the beacon was down, after a NAT mapping expired and after the peer restarted on a
different port, with no person and no restart. A bounded, visible, paced retry is not the plan's
silent retry loop: that forbids a loop nobody can see and nothing bounds, and this one is bounded
by the episode, paced by the gap and readable while it runs.

A queued message, a running transfer and a coordination payload from the peer make a dial due,
and none of them dials once a second: `Connections::ensure` makes one dial only when the policy is
due, so the queue's poll, the transfer's wait and the keeper cannot hammer a peer between them and
a beacon session is not opened per poll. A product with news the crate cannot see — a person asking
again — hands it in through `Connections::wake`, which starts a fresh episode. A stop is not
permanent while its cause is: `ensure` re-opens a stopped pair once the cause has gone and dials it
once, and self-recovery resumes when the caller runs `keep_connected` again — `watched` is how a
product knows it is the one that has to. A stop whose cause is still there is answered as the stop,
with its cause, and that is the same cause the readable state shows.

### A punch

One dial tries, in this order: the caller's hint when there is one; then every
address the record remembers for the peer, newest first and all dialled at once,
because each of them completed a handshake once and waiting for four ten-second
dials in turn would spend the budget on an order that says nothing; then the
beacon, and only when nothing above worked, so the beacon is not consulted while
an earlier address works. The third step is the punch: two machines behind network
address translation dial each other's beacon-observed address at the same time,
plus the candidate list the peer sends inside the signed, opaque introduction
payload the beacon already relays. The connectivity check is the authenticated
handshake itself — there is no STUN exchange, no second socket, no second protocol
and no separate check phase — so a punch dials addresses with exactly the code a
remembered address is dialled with, and the handshake that proves the key is the
same handshake that proves the path. `DIAL_BUDGET` (60 s) is the product-facing
bound on how long one dial, and therefore the wait before an honest failure, may
take; the punch fits inside it rather than extending it.

One punch dials at most `MAX_CANDIDATES` (8) candidates, and `PUNCH_REARM` (5 s) is the
least time between two re-arms of the same pair from coordination payloads. A used-up
recovery episode is never re-armed, and a punch counts as one dial of the episode, not
one per candidate. Only addresses that arrive from the peer are filtered: the caller's
hint and the beacon's observed address are dialled as they come. A stored candidate list
is used for a minute and no longer — a list is worth what the moment it arrived is worth
— and a punch that finds none waits a short window for a fresh one rather than dialling
an old one. The filter refuses loopback, link-local, multicast, the limited broadcast,
unspecified, this machine's own address and port, and a private address unless the product
declared an address of this machine in the same block — the whole RFC 1918 block
(10/8, 172.16/12, 192.168/16) or the carrier-shared 100.64/10, not a subnet of it. Two
things follow, and both are accepted: a candidate from a neighbour on the same block is
dialled, and a subnet-directed broadcast inside the block cannot be told from a host
address without the block's prefix. A paired peer can also name a global address, or this
machine's own external one — which the crate never learns — and make this machine send a
padded handshake to it or dial itself: bounded by the ceiling and the re-arm interval.
Coordination is never sent to a peer while a ceremony with that peer is running,
because an older build ends its ceremony on an unknown payload; a pairing nobody
finished is not a ceremony, so an opening whose sender has given up stops holding the
punch off once it is older than a machine flight is waited for, and a person who walked
away from a comparison does not keep the pair from punching for ever. A payload from a
peer this machine no longer trusts causes no dial: the keeper reads the record before it
dials, and the re-arm asks the record first. A payload can still reach an older build in
the window before that build's opening arrives here, and end its ceremony: the local
check covers only what this machine can see, and that window is accepted rather than
hidden. The beacon can read each machine's candidate list, private LAN addresses
included, because the payload is signed and not encrypted, and it learns that two
specific machines are reconnecting at a moment; the relay already reveals the reconnect
timing, and the list is the accepted cost beside it.

The record keeps up to `MAX_REMEMBERED_ADDRESSES` (4) addresses per peer, newest first,
in a new tag beside the single-address field; the single field keeps the newest, so an
older build still finds one. The rule for what may be written is one rule: the source
address of an accepted connection the tie-break kept, or the address a completed dial
reached when the pair kept that dial's connection — a completed authenticated handshake
is authenticated data — and never an address that arrived only as a hint from the
network. A dial that loses the tie-break writes nothing, so it cannot overwrite the
address the pair's connection is at. An address leaves the list when a handshake at it
proves a key which is not the peer's: the record's claim is then disproved, so the
address is dropped and the next dial does not meet it again. A dial that tried its
addresses and reached none is refused as `ConnectFailure::NoDirectPath`, which carries
the candidate set it tried rather than one address; what each address did — a timeout, a
failed handshake, no key — stays on this machine, and the product shows one cause beside
the set. A refusal with no evidence names both that the beacon cannot be reached and that
this network may block UDP; a beacon that answered — a version mismatch, a refusal, a
malformed frame — is never called unreachable, and no cause the crate has just ruled out
is named. A network that blocks UDP entirely reports the beacon unreachable; one that
blocks UDP towards the peer only reports no direct path. The one per-address fault that
becomes an answer of its own is a key that is not the peer's: `ConnectFailure::WrongPeer`
names the peer asked for, the key that answered and the address, because that is a
security fact and not a network one, and it outranks the beacon and network answers the
same dial went on to collect. It is answered even when the pair is already up, and when the
peer's own dial brought it up while this one was still trying — `connect_with` answers it in
both cases, and `ensure` answers it beside `Recovery::Connected` when its own dial met it —
because the pair being up says nothing about an address that proved another machine's key. The
record then forgets that address, so the fact is reported once and the next dial does not
meet it again; the pair itself is untouched. The outcome table in `connect`'s module
documentation is the contract: 18 rows naming the mapping, filtering and pooling classes
and what this one dial does with them, every combination of the three the rig can
configure in a row, and every row a recorded case or a declared gap with its reason. The
classes are named and not counted, and
nothing in the crate branches on them; a class that does not connect is refused honestly
with the product's advice where the network is what failed, never with a NAT diagnosis the
crate cannot make — and a handshake that completed and lost the tie-break is not a network
failure at all, so it carries no advice to change networks.

The machine stays findable by itself too, and has exactly one registration: `Presence` is built once
per machine, registers at once and keeps itself registered — refreshing at a third of the answered
lifetime, dialling again as soon as its session closes, and opening a new session after a beacon
outage — for as long as it exists. Dropping it closes the session and ends both of its tasks: the
keeper is woken out of a failed-dial wait, and the reader out of the session's wait or its pause. A
dial already in flight is the one thing a drop does not cancel — it finishes first, so the
endpoint handle that task holds can outlive the drop by up to `BEACON_REQUEST_TIMEOUT`, and that is
the bound. A product that must have the socket back before it drops the presence and then closes and
drops its own endpoint handle: the connection and the dial end with it, both tasks finish, and the
socket goes. The beacon forgets the registration with the connection. `Presence::state` reports a
`Registration`, so a product can tell a registration being refreshed from a beacon that is
unreachable and when the next try is due. A request — `lookup`, `observed_address`,
`introduce` — rides that registration and never dials a session of its own: a request that finds
none waits for one until its own request bound runs out and then answers `Unavailable`, so the retry
cadence is the keeper's and a caller that asks again does not become it.

The beacon keeps one registration per peer and the latest wins, so a second session that registers
would displace the machine's. The ceremony therefore takes the machine's `Presence` instead of a
session of its own: it neither registers nor opens a connection, and the flight it is waiting for
cannot be pushed to a session nobody reads. `Presence` is also the one reader of what the beacon
pushes: an introduction from a peer a ceremony waits on goes to that ceremony and never to another,
and that peer's flights wait for it in the order they were sent, `MAX_PENDING` of them at most —
the second flight of an exchange is the next step of it, so handing the newer one over first would
lose the step before it and end the ceremony as out of order, and at the bound the oldest goes. An
opening from a peer nobody waits on yet is held instead — one per peer, and for `MAX_HELD` peers
at most, handed out newest first because an opening that has been sitting is one whose initiator is
likelier to have given up already — so an opening that arrives before the other person has started
is not lost and a stranger cannot fill this machine's memory. Only an opening is held: no other
flight can start a ceremony, so no other is kept for one. A frame the reader refuses costs it
nothing — the beacon relays what any machine hands it, without looking at the signature — so a
stranger's bad bytes cannot make the reader sleep through a legitimate flight. One rule decides
whether a flight is handed over, on either path, and it is the wait its sender is under: a machine
flight older than `PAIR_FLIGHT_TIMEOUT` is not shown to a person, in the hold or in a peer's slot,
while a confirmation is not aged by it, because its sender waits for as long as the peer's person
compares the same string. A cancelled ceremony takes its claim with it, and the flights waiting for
that peer go with the last handle on it; a `Flights` handle borrows the presence it reads, so a
waiter cannot outlive the registration that would feed it, and a handle that never took a peer takes
its waker with it. The invariant `peer.one_beacon_registration` scans the crate's own sources to
keep it so: the registration is made and read in one file. A raw `Session` a product opens for
itself is not prevented from registering — the crate cannot hold one registration per machine
without process-global state, which it does not have — so a product reaches the beacon through its
presence. The crate opens one session of its own besides: the manager's lookup, which registers
nothing and reads nothing, so it displaces no registration — and the harness's rig opens raw
sessions that do register, which is why the invariant's scope leaves the rig out.

Two things would defeat a retry, and both are fixed rather than papered over. A connection that is
merely not yet declared dead does not outrank a fresh one, and the manager reads that itself rather
than leaving it to whoever happens to look. How long a vanished peer goes unnoticed is this
machine's own stated bound rather than the two machines' negotiated timeout:
`Connections::vanish_bound` answers a `Vanish`, which says both the bound and whether this machine
measures the silence at all, and every branch of it is measured by a case. A machine that cannot
measure silence — no keep-alive, or its own reader not heard from — does not conclude it: nothing is
judged vanished and the connection lives until the transport's own timeout ends it, and the reading
says so rather than showing a bound nothing keeps. A connection that ended because it timed out is a
peer that went quiet — a NAT mapping expiring, a laptop closing — so its loss is a redial and never a
failure counted against the pair.

A record read the operating system refused is this machine's own and may pass: the ask is answered
`ConnectFailure::Deferred`, which names the record and is not a statement about the peer — a live
connection is not torn down, and nothing is trusted on a file nobody could read. A deferral is not
a reason the pair is down, either: over a pair whose last dial met something else, the state keeps
that reason and so does the answer, and the fault is only why this call could not ask again. A peer
that accepts a connection and closes it because its own record could not be read costs this machine
one dial of the episode; that is the fault's cost and it passes with the fault. An insecure,
malformed or too-large record never becomes trust and stops the pair's recovery.

`Connections::serve` hands each incoming connection to a task of its own, so a burst of stalled
handshakes costs a bounded number of tasks and delays the next accept by at most one keeper round.

This release changes the public surface, which nothing published before this one had to. The accept
path takes the manager's endpoint: `Inbox::serve` and the message service are given it so that a
queued message can cause a dial. `Presence` keeps its own registration: it registers when it is
built and refreshes itself, and `Presence::state` reports a `Registration` — no answer from the
beacon yet, held, or the beacon unreachable with the moment the next try was due — so a product
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
no cause about the peer: a machine whose own registration is not held cannot be reached by the other
side at all, and says so through `Presence::state`, which is where a product reads a beacon outage
during a ceremony.

The punch adds its own surface. `Connections::with_presence` hands the manager the
machine's one `Presence`, shared as an `Arc` with the ceremony that compares under the
same registration — which is what lets the manager step aside while a ceremony with
that peer is running — so a candidate list can travel both ways; a manager built
without one still sends its candidates and dials the beacon's address, but cannot
receive the peer's, so its punch is one-sided. `Connections::declares` states the
addresses the product knows this machine has — the only way a private candidate is
dialled, because nothing here reads the interfaces. `PeerRecord::addresses` is the
bounded newest-first list the record keeps, `RecordStore::record_address` now maintains
that list rather than one address, and `RecordStore::forget_address` drops one the
handshake disproved — an address that answered with another machine's key is no longer
dialled and refused on every later call. `ConnectFailure::NoDirectPath` carries
`candidates`, every address the dial failed at, in the order it tried them and without
repeats. A key that is not the peer's is the one address fault that leaves the refusal
and becomes an answer of its own: `ConnectFailure::WrongPeer` carries the peer asked for,
the key that answered and the address it answered from. `connect_with` answers it even
when the pair holds a connection, and `ensure` answers it beside `Recovery::Connected`
when its own dial met it, because `ensure` asks for the policy's pace and a pair that is
already up has nothing to pace. `peer::{MAX_CANDIDATES,
MAX_REMEMBERED_ADDRESSES, PUNCH_REARM}` are public
because each is a bound a caller plans against: the most candidates one punch may dial,
the most addresses one record keeps — a permanent format bound, so a later build that needs
more adds a record tag rather than raising it — and the least time between two re-arms of a
punch.

`BeaconError::UnknownPeer`'s text says the beacon did not hand the payload over where it used to say
the peer was not reachable, which the beacon's one answer does not prove; a ceremony flight it did
not take is that same error on `PairError::Beacon`, so one sentence covers one fact.

`PairError::FlightTimeout` names the wait that ended and nothing about why nothing arrived.

## The messages

A message is a body and an envelope. The body is opaque bytes: the crate stores it as
written, hands it over as written, and never reads it. No path leads from a body to a
capability, and the invariant `messages.no_capability_from_a_body` scans the module to
keep it that way: the one decision a message meets is `Rights::may_take_message`, whose
inputs are the transport's peer, the host's floor and the moment, so nothing a body says can
select a capability, ask a question or reach a grant. The envelope is a 16-byte identifier
minted once at the sender, a count that starts at one for the first message to a peer and
grows by one, and the moment the sender says it composed the message. The composed moment
is a remark: nothing decides, orders or expires by it.

The author is the connection's attested peer, never a field in the frame. A body that
claims to be from someone else is text like any other; the product marks it and escapes
it, as it already does for a guest's report, and a peer's name never becomes an account
name anywhere the crate stores, shows or answers it.

`Messages::send` publishes the message into this machine's queue for that peer before it
returns, so a restart keeps it, and a queue holds at most `MAX_QUEUE` messages rather
than dropping an older one. It refuses before writing anything when the record says the
pair is not one to speak to: no pairing, a withdrawn trust, or a pair closed by three
failed comparisons. `Inbox::serve` runs once per paired peer, and the message layer's offer
loop runs inside it: it offers the head of the queue over the pair's live direct connection,
one bidirectional stream per offer, bounded by `MESSAGE_BUDGET`, and repeats until the
receiver answers or the message expires. A connection that dies mid-offer costs a retry, not
the message, and so does an offer nobody answers: the next one waits a round, so a peer that
resets each offer stream costs a round a second rather than a spin through this machine's
queue files. A queue this machine cannot read or write is not a queue with nothing in it —
the service ends with that refusal and hands it to whoever started it, whether its own round
met it or the inbox's reader did. A product that runs only the services still has its queues
swept: the service sweeps its own peer every `SWEEP_EVERY`, so the retention and a withdrawn
trust take effect without the caller sweeping by hand. The queue waits while the pair is not
one this machine may speak to: with the binding not yet arrived it says so and sends nothing,
and with the pair's "write to me" not live it holds. Withdrawing trust in a machine drops that
pair's queue with a record of it.

A queue is rewritten whole, so a read-modify-publish holds that peer's lock file in
`messages/` for the whole of itself: the self-update window's second process on a root
cannot lose a message the first just queued, where the record merges and the log appends. The
lock file is per peer, so two processes writing two peers never wait for each other; this
process writes one queue at a time, so two peers written at the same instant wait for one
write and its flush. The delivery sink runs with no lock held, so a slow caller delays that
peer's later messages and no other peer's, and a drop's audit entry is appended between two
short holdings of the queue rather than inside one, so the log's own lock is never taken while
a peer's queue is held. A lock another writer holds is not waited on without a bound: the
write answers `MessageError::Busy` and is retried, while a read does not need it — the queue
is published by one rename, so a reader sees a whole file whatever a writer is doing. This
process's own writer is the one wait a caller's disk decides: a second task writing a queue
waits for it, and it is held across the whole read-modify-publish. Two waits in this layer are
not the crate's to bound: the caller's own `Deliveries::deliver`, which runs synchronously
inside the receiving task and holds that pair's receiving for as long as it takes, and the
log's cross-process lock, which every append on the root takes — a blocked log delays every
pair's entry, and no queue is held while it is waited for. Dropping a queue — after the
retention, after a refusal, after a withdrawal — does not depend on the log taking the
entry: the bodies go either way, and a drop that could not be recorded is better than bodies
kept for a machine nobody trusts.

The receiver asks the same question everything else asks, in the plan's order and with
the same record of what happened — the host's floor included, and a floor refusal is not a
withdrawal. On the machine that did not decide the binding, the claim names the pair and
the receiver's own decision is the one that counts: a sender cannot see the peer's rights,
so it offers and is answered. A refusal is of that message and not of the pair: it is
recorded, the sender drops its copy, and the queue moves on. It travels as a class and not
as a sentence — the receiver's words, the host's floor among them, stay on the receiver,
and what the sender writes is this crate's own phrase. A message may arrive more than once:
the receiver records the identifier as taken only after its caller's `Deliveries::deliver`
returns `true`, so a caller that stores durably inside that call never loses one; a caller
that cannot store — a full disk — answers `false` and is offered the message again, and a
crash between the call and the record — or another writer holding the queue at that
instant — delivers it twice, which is what at least once by construction means. A caller
whose `deliver` panics ends the service with that bug named and the message still queued,
rather than leaving the pair silent; a frame the receiver cannot read — bytes that are not a
message, or one longer than any message this build writes — is answered as unreadable, so
the sender drops it instead of keeping it for the retention.

Only a remembered identifier suppresses a message. One the receiver already took is answered
`already taken`: by the peer's own account it reached a caller, so the sender drops its copy
and records nothing — and the peer is the only one who can say so. Every other identifier is
delivered, whatever its count. The taken identifiers are durable for about a week and bounded
in number, so past that week the same message can be delivered twice: that is what remembering
by identifier costs, and it is stated rather than hidden. The sender's count is durable beside
its queue. Messages from one machine arrive in the order of the sender's count, and a count
that jumps is declared to the caller as a `Gap` — the number missing when it jumps forward,
and a rewind when it does not move forward: a sender whose queue was lost starts again from
one, or a retry lands after its identifier was forgotten. A count is never renumbered,
silently continued, or the reason a message is destroyed; across pairs no order is promised.

A receiver takes at most `MAX_OFFERS_PER_WINDOW` offers from one peer per `MESSAGE_WINDOW`
and answers the rest with a delay the sender waits out, clamped to one window so a peer
that names a century is not believed. A throttle is not a refusal: no right changes and
nothing is recorded against the pair. A refusal a peer does cause is written in the log's
peer part, which stops at its reserve, so a flood cannot take the room a person's own acts
need. A body is at most `MAX_BODY_BYTES`, and a message untaken after `MESSAGE_RETENTION`
is dropped and the drop recorded. The beacon carries no message: a message travels only on
the pair's own connection, and the beacon's memory holds registrations and nothing else.

## The actions

An action is something one machine asks another to do, and which must not happen twice. It
carries an identifier the caller names, a kind, a bounded body and a bounded result. The
crate never mints the identifier: a caller that repeats the same operation carries the same
identifier and is answered `already executed`, while a person deliberately running the
command again is a new operation with a new identifier and does run. At most once therefore
cannot be held by the crate alone, and the obligation is the caller's — remember an
operation's identifier before asking, because a caller that forgets it and asks again after
its own crash has asked for a new operation. An identifier belongs to one operation; using it
for a different one is answered as a repeat, and that too is the caller's obligation.

The receiving machine keeps a durable journal of executed identifiers under `actions/`, one
private, additive file per peer for both the journal and the sender's unknown marks, shared
safely by every handle and process on the root. The identifier is remembered before the run it
describes, so an action that ran is never missing from the memory. Nothing is remembered for a
refusal or for a decline, because neither executed — unless another writer holds the memory
when the decline tries to release it, in which case the identifier stays spent, the same cost
as a crash in the remembering window. The cost is stated rather than hidden: a crash in that
window can leave an identifier remembered for an action that did not run, and a repeat is then
answered "already executed" for something that never happened. A repeat that arrives while the
first run is still in progress gets the same answer as one arriving after it; a decline
releases the identifier, so a repeat after it runs again. The journal keeps a week, as the
message layer keeps its taken identifiers; past it a repeat may run again, which is the honest
cost of remembering. Expired identifiers are cleared before the memory is called full, and a
full journal refuses a new action rather than forgetting an old one: forgetting one would turn
into a command running twice on someone's machine. The way out for a machine that has filled
it is the one that already exists — a person withdraws trust in that machine, which clears
that peer's journal and unknown marks; the record keeps the withdrawal's moment, so the
clearing holds even while that peer's service is stopped for the whole withdrawal, and the
same identifier runs again once the trust is back.

There is no sender-side queue and no automatic retry. An action runs on the live connection
and nowhere else; if the pair is not connected when a person asks, the ask is an ordinary
reason to dial, and a failed dial is the failure the caller already knows, with the action
held nowhere. A request the machine could not get onto the wire — no stream could be
opened, or the write did not finish — is reported as `not sent`, unless the receiver had
already answered: that answer is read under a short courtesy bound and handed back, so a
request the receiver answered is never reported as unsent. This layer keeps no mark for a
request it did not get out, and a frame that may have been whole is stopped from running twice
by the receiver's journal. Once the request is on the wire and no answer comes back — or the
receiver answers that it could not tell — the action is marked unknown: the mark is durable,
per peer, bounded, survives a restart, and is read back by `Actions::unknown`. When the memory
cannot be read or written at all, the caller is answered `untraced` instead, which names both
the unknown outcome and the storage fault; the receiver's journal still stops a repeat from
running twice, but nothing here can be read back. While the mark is kept, the same identifier
is never offered again by this crate; the memory keeps the newest marks and drops the oldest,
and a repeat whose mark was dropped reaches the receiver's journal instead, which answers
`already executed` for as long as it remembers.

The receiving machine decides in the plan's order — authenticate, the right, the host's
floor, the kind, the journal, the record of the execution, the run. A command asks
"work on me", and nothing in the body chooses a right. The kind is checked after the
right and the floor, so a peer without that right is refused at that step whatever kind
it names; a kind this build does not know is then answered unsupported rather than run
as a command. The pair is the one the message layer uses, and a pair whose binding has
not arrived is answered `not ready`, which is neither a refusal nor an execution. A
refusal names the step that refused it and is recorded; it is a refusal of that action
and never of the pair, so a person who grants the right and repeats the operation gets
it executed. A decline releases the identifier before it is answered `not run`, so a
repeat after it runs again; a memory that cannot release the identifier still leaves the
decline answered, and a hard fault ends the service after the answer.

The execution is recorded before it runs: the entry names the peer, the pair, the right
it ran under and the identifier, and never the body — what the command actually was is
the product's own record, keyed by the identifier. Nothing is executed unrecorded: a log
with no room left stops the peer from acting, visibly, and releases the identifier it
remembered — another writer holding the memory at that instant leaves it spent, the same
cost as a crash in that window. A log that cannot be written at all is the same refusal
for the sender — `not recorded` — and then ends the service with the log's own fault, so
whoever started it sees the cause. The machine's own code is given `EXECUTION_BUDGET` to
say whether it ran and what came back; if it cannot answer, the sender is told the
outcome is unknown and the identifier stays remembered — or the caller is told
`untraced`, when the memory cannot be read or written. A result larger than
`MAX_RESULT_BYTES` is not carried and is not truncated: the answer says the action ran
and the result was too large to carry. A panicking executor ends the service with the
bug named.

A receiver takes at most `MAX_ACTIONS_PER_WINDOW` actions from one peer per `ACTION_WINDOW`,
in a window of its own: a flood of actions cannot throttle the same peer's messages, and the
crate never re-offers by itself — the wait is reported to the caller. The action layer
chooses no capability of its own and asks no question of its own: its one decision is
`Rights::may_run_action`, whose inputs are the transport's peer, the host's floor and the
moment, and the capability it records is the one that decision returned. The invariant
`actions.no_capability_from_a_body` scans the module to keep it that way — the layer names
no `Capability` value — so no path leads from a body to a right, a grant or a capability.

Messages, actions and transfers share the pair's connection. `Inbox::serve` is the one place
that takes a stream and decides what it is: the binding exchange owns the first stream a kept
connection carries, and the inbox owns every stream after it, handing a message, an action or a
transfer to the layer whose magic the frame carries. A message is therefore never taken for an
action nor an action for a message, in either direction, and neither for a transfer. Two checks keep
it so: `peer.one_stream_acceptor` finds a third acceptor in any other file, excusing only the two
the exemption table names, and `peer.one_acceptor_per_file` holds each of those to a single
`accept_bi` call site. An action in flight does not count as the pair having carried traffic for the
connection manager, while an answer that means the receiving side accepted the operation — it ran,
ran with a result too large to carry, or the identifier was already spent — does. Every other answer
means nothing was taken, so a slow-down followed by a drop is not a link failure. A message counts
only the take; an action also counts a repeat, because its journal proves the receiver accepted the
operation before. So a machine holding one unanswered action cannot be re-dialled for ever. The
beacon carries no action: an action travels only on the pair's own connection.

## The files

A whole file moves over the pair's own connection, and the direction is one: a machine offers a file
and it lands on the peer. Nothing fetches — a peer asking this machine for a file of its own is not
served, which is why "take files from me" is inert and granting it changes nothing. The beacon
carries no file either: a transfer travels only on the pair's own connection.

A file does not travel as a stream of messages. It is a transfer in its own right: one bidirectional
stream per attempt, an offer, the receiving machine's answer, then the bytes, then the receiver's
verdict. It does not inherit the message layer's body cap, does not consume its window, its queue,
its taken identifiers or its retention, and a transfer frame is never counted as a message. The
inbox tells the two apart by the frame's magic, and a frame it does not recognise is still a message
— which is exactly how a peer that does not know transfers answers an offer as unreadable.

Only the receiving machine's decision is asked, because it bears the effect: the permission is "put
files on me" (`Capability::PUT_FILES`), never the default, and the host's floor is asked after it
with the same capability. The sending machine's own person is the one acting, so no second grant is
required — exactly as sending a message requires only the receiver's "write to me". The decision is
made once, when the transfer is authorised, and holds for its whole life, including across a
reconnect: a right withdrawn afterwards ends future transfers, not this one, while withdrawn trust
closes the connection and therefore ends it. The binding to an assistant is re-checked when a
transfer resumes, and only then.

A product that only wants messages and actions is unchanged: the transfer layer is added to the
inbox with `Inbox::with_transfers`, nothing else on the surface gained a required argument, and an
inbox without one costs nothing and slows nothing — an offer that arrives at such a machine is
answered in the message layer's own vocabulary, exactly as an older peer answers it.

The crate moves bytes and decides whether it may; the product says where they go and what they are.
It supplies a `Source`, which answers bytes at an offset — the same offset again after a reconnect —
and may answer "not now" rather than block; a `Sink`, which accepts bytes at an offset, is told
which peer is sending, and answers what it holds for a name and what it assembled once it holds them
all; and, at offer time, the file's length and the SHA-256 it must have. The sink's three questions
are lookups that answer without waiting, because the crate asks them while the sending machine waits
on its bound: a product hashes as the bytes land, since it has to produce that digest anyway, and a
product that cannot answer one of them without waiting has put the wrong thing behind the trait. The
crate never writes the file, never hashes it and never turns its name into a path: a transfer's name
is the product's, scoped to one peer, carried as given and bounded in length, and the crate only
compares two names for equality. A product with no sink has not granted file ingress: a peer with no
right is refused at the right step, and one that holds the right and finds nothing behind it is
refused at the layer's own floor, which is recorded like any other floor refusal.

The bytes are the transport's, not this layer's. The receiving machine's connection credit is
`MAX_BUFFERED_BYTES` (32 MiB) and one stream's is `MAX_STREAM_BYTES` (8 MiB), so two transfers —
`MAX_RUNNING_TRANSFERS` — account for half the connection's credit and the rest stays available to
messages and actions. The same numbers bound what this machine queues: quinn's `send_window` is
`MAX_BUFFERED_BYTES`, so a peer that advertises an enormous window cannot make this machine buffer a
file of its own writes. A sink that answers "not now" stops this machine reading, which stops the
sender through QUIC's flow control instead of growing memory or dropping the file, and the sender
reads its source one `TRANSFER_CHUNK` (64 KiB) at a time. A product that builds its own
`quinn::TransportConfig` gets its own numbers, and these bounds do not apply to it.

Those numbers are what a peer may make this machine buffer in the crate, not what the operating
system buffers: the socket's send and receive buffers sit on top of them and are the caller's to
size, because the crate never makes a socket. On a fast path they are the bottleneck — macOS
defaults are far too small for a gigabit at a hundred milliseconds — so a product that wants the
throughput sizes `SO_SNDBUF`/`SO_RCVBUF` where it makes the socket.

A transfer whose connection goes away is `Waiting`, not failed: it resumes when the pair reconnects,
and the product is not asked to start it again. An outage longer than the stall bound is still a
wait, because that bound is about a live connection. On resume the receiver states how much it
already holds — and only after the transfer is authorised — and the sender continues from there. A
transfer with a live connection that stops moving bytes is abandoned after `TRANSFER_STALL` (60 s)
of no progress, on both sides, which is not a bound on the transfer's length: a large file on a slow
link and a slow sink take as long as they take, and so does a slow source — one that produces
something inside the bound, because one that produces nothing for the whole of it is no progress.
The sending side's own bound is that plus a stated margin (`TRANSFER_GRACE`, 5 s), which carries an
answer written within it: the constant's own doc states what that margin covers and what lies
outside it. A receiver that spends its whole bound before it answers is heard as the answer it gave
— "could not store it" — whether the sender is parked on a write the receiver has not read yet or
waiting for the verdict after every byte, instead of being timed out as `no progress` first, because
one event has one cause. What counts as progress is the bytes that landed at the receiving side —
the offset it states, in its answer to an offer and in the progress word it sends while its sink is
slow and once a second while the file keeps arriving — and only when that offset has grown: a word
repeating an offset this machine has already seen is not the file getting further, so a peer cannot
hold a transfer, and one of this machine's places for the peer with it, by saying `running` about
the same byte. Nothing else counts and nothing takes it back: a verdict that never arrived, a
timeout and a re-send leave the count where it was, a byte the transport accepted is not the count,
and a throttle keeps the offset it states — it can raise the count and never lower it. The progress
word is what makes a slow sink safe: the transport returns flow-control credit in large steps, so a
writer parked at a stream window's edge can wait minutes for a receiving side that is storing all
the while, and it is the receiver's own offset, chunk by chunk, that keeps it from calling a working
transfer stopped. A sender whose own source is slow reads the same word while it waits, so a slow
disk is not a stopped transfer either. The same offset is what the receiver's `Running` answer
states when a second stream offers a name already being answered. One that waits longer than
`TRANSFER_WAIT` (600 s) for the pair ends as `NoPair` — the pair never answered: its connection did
not come back, its binding exchange never finished, this machine could not open a stream or write
its offer and spent the whole wait bound doing so, or its offers went unanswered for the rest of the
wait bound — either every offer it made, the accepted residual for a pair that is present and
silent, or every offer after the last it answered — and the receiving side reports the same for a
transfer whose sender never came back, so a dead transfer is never shown as a quiet one — one that
is already complete on the receiver is answered complete instead of being sent again, and one
offered under a name whose stream is still being answered is answered `Running` with the receiver's
offset. A transfer the receiving machine has ended stays visible to its product for `TRANSFER_WAIT`
after it ended, and is forgotten once that has passed, so the product's view never goes from failed
to absent without the wait bound passing first. One the receiving machine's person stopped stays
stopped: every later offer under that name is answered `Stopped` until the wait bound passes, so a
stop is not undone by the sender asking again. One the *sending* machine's product stops is a
different act: it is `Stopped` at once and stays so, the stream is reset with the transfer's stop
code, and the receiving machine learns that the sending side stopped it rather than that a stream
merely went away — including while its sink is answering "not now", where the receiver reads the
stream once more before it calls its own store the cause. A stop is noticed inside a poll wherever
the transfer waits on its own clock — the answer to its offer, a throttle, the tail, and the polls
spent waiting for a pair to come back — and two waits are not polled, because neither is on that
clock: the dial itself, already under way when the stop is made, and a stream the peer has not made
room for — opening one at its stream limit, or writing the offer while the peer takes no bytes. The
handle says stopped at once; one of this machine's places for the peer comes back when that wait
returns. The tail matters too: once every byte is written the transfer waits for the receiver's
verdict, which for a slow sink is most of its life, and a stop there ends it as stopped and gives
the place back rather than finishing a file nobody wants. That is not the receiving person's
decision, so the name is free: a sending product that offers the file again gets a fresh transfer,
never `StoppedByReceiver` for something the receiving person never did. The wait bound is a budget a
transfer spends rather than an episode that restarts: it is added up over every wait, so a transfer
that has been moving bytes for an hour has spent none of it and is still waited for in full when its
connection drops there, while a pair that keeps coming back and moving nothing exhausts it instead
of parking the transfer — and the stall bound is spent the same way, on the time a live connection
spends not moving, so a connection that comes back buys no fresh budget either. Only the receiving
machine's stated offset growing clears either bound, and an answer that ends the attempt without
pacing it buys the transfer more time only by stating a further offset (`TRANSFER_STALL` states what
each kind of answered round spends). Bytes the transport accepted are not growth, so a peer that
reads a byte a minute, or that keeps this machine waiting before saying "the same offset", cannot
stretch the bound.
A record this machine cannot read is waited for under the same bound and then ends as `NoProgress`
rather than holding one of this machine's places for the peer for ever.
Nothing of a transfer's own state is kept across a process restart on either side: the product
offers the file again and the receiver states what it holds. Its authorisation is not transfer state
— it is an audit entry, kept like every other allowed act.

The answer set is closed and every cause
is its own: it arrived; it was already there; a transfer under that name is running there; it was
refused and at which step; it was not run because the machine could not write its own record of the
act; a limit was reached and which one; the name is already held with different content; what
arrived does not match the digest; the receiving side could not store it; the receiving side's
person stopped it; the offer could not be understood at all. What it learns about its own side is in
the same set: no progress, and the pair never answering — its connection did not come back, its
binding exchange never finished, this machine could not open a stream or write its offer and spent
the whole wait bound doing so, or its offers went unanswered for the rest of the wait bound: either
every offer it made, or every offer after the last it answered — its own product stopped it, its own
source could not be read, this machine no longer trusts the peer, and nothing arrived that it could
understand — a peer answering in another vocabulary, or a status byte this build cannot read.
`NoPair` says what this machine observed, not that the pair was absent: `TransferFailure::NoPair`'s
own doc states what it covers. A pair that answered anything other than a bare limit does not reach
it through the window of offers this machine filled itself — the count starts again, so the limit it
then meets is the limit it met, however slow it was to take the file — and a pair that answers and
then stops answering altogether still ends as `no pair` at the wait bound.
The one answer that is not an end is the start limit's throttle: the receiving machine names
how long to wait before starting another transfer, the product sees `Throttled { retry_after }`, and
the transfer asks again when that passes. The delay is the peer's, so it is clamped where it is
read: never longer than `TRANSFER_THROTTLE_CAP` (60 s) and never shorter than a second, a start
limit that names no delay at all is one second rather than an end. A peer that keeps throttling for
`TRANSFER_WAIT` (600 s) ends the transfer instead of parking it for ever — unless the offset it
states keeps growing, which ends the streak: a peer that throttles while it takes bytes is pacing a
transfer that is moving, and only one that throttles while moving nothing is ended by the bound. A
throttle is an answer, so what it ends with is the limit it kept meeting — unless the window it was
meeting was one this machine filled itself: a pair with no binding to decide under answers offers
with nothing, those offers spend its start window, and a throttle reached that way ends as `NoPair`,
which is what the transfer met. The count of those unanswered offers is cleared by any answer that
is not a bare limit, so a pair that answered once — with a name it already holds, say — is a pair
that is there, and the throttle it meets afterwards is the limit it names. A throttle is slept in
polls, so a product that stops its transfer during one gets its place back at once rather than when
the peer's delay runs out. A limit on running transfers is still terminal, because this machine's
own count would have refused a third one locally, and it carries no delay: the frame's wait beside
it is a peer's number nothing acts on. An answer that is still arriving is never a refusal: a frame
the budget cut in half is kept and continued by the next look, and a stream that ends inside a frame
is a lost attempt rather than "not understood", so a word split across two looks is read once and
the answer that then arrives is the one that counts. What the sender learns is the class, never the
receiver's sentence: the host's floor among them stays on the receiver, as a message's refusal does.
Integrity is the receiving machine's: the product's sink reports the SHA-256 it assembled —
including the part that was already there from an earlier attempt — and the crate compares it with
the one the sender offered, so a truncated or corrupted transfer is never answered complete. A sink
that holds every byte but cannot say what it assembled is answered "the receiver could not store
it", never "the digest does not match": the crate has no evidence either way and does not
accuse the bytes.

A transfer that is about to move bytes is recorded first, one entry per transfer and not per chunk,
in the log's part for peer-driven acts; a log that cannot take the entry stops the transfer and
answers the sender `not recorded`, and a name that turns out complete or in conflict moved nothing
and leaves no entry. How often a peer may start one is bounded per peer — `MAX_TRANSFER_STARTS` (6)
per `TRANSFER_START_WINDOW` (60 s) — and checked before the rights decision, so a peer cannot force
a record reread or fill the log at will; a resume after a reconnect is the same transfer and does
not count again. The wait between two offers the pair left unanswered doubles, from one second up to
eight, and goes back to one as soon as an offer is answered without pacing the transfer, so an offer
to a pair that never binds is not retried once a second for the whole wait bound. An offer waits
thirty seconds for the receiving machine's answer, and the verdict that follows the bytes waits for
the stall bound plus `TRANSFER_GRACE`, because a sink still writing the tail is not a sink that
stopped. Every offer that is not a resume still spends one start of that window — the doubling slows
the spending rather than avoiding it — while a resume is the same transfer and spends none. One peer
may have `MAX_RUNNING_TRANSFERS` (2) transfers running or waiting at once; the receiving side counts
them and records the new one as one decision under one lock, so the limit holds when a peer offers
several names at once — which is what keeps "two transfers take half the connection's credit" true.
The rig runs one task at a time and cannot race two offers, so that half is a structural guarantee
and no case produces it. A transfer's name is at most `MAX_TRANSFER_NAME_BYTES` (128), the bound a
label has, and a zero-length file and an empty name are refused locally, before anything is sent.

Nothing of a transfer's own state is stored: no queue, no retention, no journal of its own, no file
on disk. The crate holds a transfer's name, its length, its digest and how far it has got in memory
while it runs, and nothing of that after a restart; what it does keep is the authorisation, an audit
entry like every other allowed act, naming the same name, length and digest. Where a file lands, how
it is named on disk and what happens to a partial file are the product's decisions, and the crate
never makes them silently.

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

Only the entry point binds a real socket, reads the environment and the wall clock. The scan
exempts that one file from those three invariants and no others (the invariant table itself is
not scanned either, because it holds the patterns); the two files that accept a stream of the
pair's connection — the binding exchange and the inbox — are exempt from
`peer.one_stream_acceptor` and nothing else, and `peer.one_acceptor_per_file` allows each of
them a single `accept_bi` call site, so a second reader hidden in either is still caught.
`harness/tests/summary.rs` proves each exemption is still needed and how many invariants it
names, that nothing else about an exempt file is excused, that the files excused from the
third-acceptor claim are exactly the ones the per-file claim checks, and that no other file in
the entry crate escapes the no-state-on-disk claim. What the entry point decides — what the
command line means — is a pure function in the library and is witnessed in a default build,
and its key file goes through the peer library's loader, so the name and mint invariants scan
it and the exempted surface stays glue.

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
  itself. A plan that delays every datagram by exactly the same amount lets a case
  count round trips by the link's own reading rather than by how much virtual time the
  rig happened to spend. A machine's apparent address can change mid-run. A dial drives
  the clock itself, so a link that drops everything ends at a
  deterministic virtual instant instead of hanging the test, and one machine can
  serve several dialers at once.
- **Networks.** The link can also put a translating network between the machines: one
  network is a NAT described by its mapping (endpoint-independent, address-dependent or
  address-and-port-dependent), its filtering (the same three), its address pooling
  (shared or per destination), whether it carries a hairpin, and whether it stands in a
  row of two. It is off by default, IPv4 only, and deterministic: a case configures the
  network and the translation answers where each datagram goes from the traffic before
  it, so a run replays. `Link::traversal()` reports the mappings, the holes and the
  hairpins the translation left behind: a hole is opened by a datagram a machine sends
  out through its network, so a punch shows one on each side towards the other's
  address. A one-sided dial leaves one on the dialling side, and one on the dialled side
  only where that side's filter admits the handshake it did not ask for and it replies;
  a machine behind no network opens none. The rig surface is
  `Sim::machine_behind`, `Sim::machines_behind_one`, `Machine::network`,
  `Link::network`, `Link::attach_on`, `Link::network_of`, `Link::external`,
  `Link::blocks` and `Link::traversal`. One thing the rig cannot prove is stated rather
  than assumed: it binds each machine to a concrete address, while a real product that
  binds the wildcard gets an unspecified one, so the local-network row and the
  own-address gate prove the crate's logic given a product that declares its address.
  Convergence is a recorded case rather than an argument:
  `several_dials_end_with_one_connection` completes two handshakes per side, and
  `more_than_two_completed_dials_end_with_one_connection` gives one identity three
  addresses, so three handshakes complete on one side and the pair still ends with
  exactly one connection.
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
- **Peer rig.** `Messaging` opens a machine's message and action layers over its own root,
  with a moment read from the simulated clock, a sink that keeps what the receiver's caller
  was handed and an `Executions` executor that records what the machine's own code was given
  and can run, decline, panic or take its time. `serve` starts the one inbox task per peer and
  the rig stops it on drop. A case that has to count the answers offers by hand on the pair's
  live connection; a case that proves the queue or the action memory runs the real service and
  reads the sink or the executor.
- **Transfer rig.** A `Source` whose bytes are a function of the absolute offset, so a resumed
  attempt reads what the first one would have and a large file costs nothing to offer; a sink
  that folds what it is handed into a SHA-256 and keeps only the count, which is enough to
  prove a file arrived byte for byte; a sink that keeps the bytes themselves, for the small
  cases that have to show a resume, a truncation or a corrupted byte; and a wait that moves the
  virtual clock until a transfer is over instead of sleeping.
- **Witnesses and invariants.** The capability inventory and the cross-cutting
  invariant table live here, together with the checks that enforce them: every
  entry is either witnessed by a recorded case or marked unproducible with the
  reason it cannot be produced here and the procedure that produces it, the check
  fails in both directions, and every invariant is proven awake by a control
  snippet it must catch. An empty scan is a failure; the exempt files name the
  invariants they do not answer to, each of those is re-proven necessary and every
  other invariant still scans them. A claim only one platform can decide is in the
  inventory on every host, so nothing is skipped silently.

## Building and testing

The toolchain is pinned in `rust-toolchain.toml` (1.99.1, the channel the other
mahbot workspaces use). The crate's own floor is `rust-version = "1.96"`.

```sh
cargo build
cargo test            # the default workspace: witnesses, summary checks, invariants
cargo clippy --workspace --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace   # the doc gate, harness included
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
