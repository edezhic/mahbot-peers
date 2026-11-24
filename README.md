# mahbot-peers

The peer layer between mahbot instances: machines connect directly, with no
relay in the path, and remember each other by key. This crate is the network
half — it knows keys, addresses, byte counts, the messages one machine queues for
another, and the actions one asks another to run; the product knows people, accounts,
rights, what a message means, what an action runs and how both are shown.

The crate holds the seams the rest of the layer is built on — identity and its key
file, the QUIC transport over raw public keys, the beacon — and the peer layer above
them. Messages and actions are here: a message is queued at its sender, offered over
the pair's direct connection, decided by the receiver's rights and delivered at least
once; an action carries the caller's identifier, is executed at most once, and a
repeat is answered "already executed". Files and the screen are not.

## What the crate provides

The library (`src/`) holds:

| Module | What it fixes |
| --- | --- |
| `identity` | one ed25519 identity per storage root, in a key file the caller's root holds; the fingerprint is the 44-byte RFC 8410 SubjectPublicKeyInfo and the peer id is the key inside it. `identity::access` is who may reach that file, `identity::keyfile` is its name, its format and its one create |
| `tls` | TLS 1.3 with raw public keys (RFC 7250), pinned to the peer's fingerprint instead of a certificate chain, with a per-service ALPN and resumption off so the pin always runs |
| `net` | endpoint construction over an injected datagram socket and an injected clock — no default for either |
| `beacon` | the beacon: the closed message set (`wire`), the client half (`Beacon`, `Session`) — register, look an id up, learn the address observed on this path, hand a signed introduction over, take the ones pushed to a live session — and the one deadline combinator the client and the server share (`timeout`, whose documentation says why there is one copy and not two) |
| `peer` | the peer layer: `record` is the durable memory of another machine, at both levels; `access` is the connection level's vocabulary — the account on the instance, the assistant, the pair, the four capabilities, the rights and the small versioned fact; `pair` the acquaintance ceremony, `connect` the per-machine connection manager, `recovery` the one retry policy for a pair, `presence` the registration refresh that re-arms itself after a beacon outage, `binding` the exchange that carries the connection level over a live connection, `rights` the decision, `audit` the record of what happened, `messages` the queue a machine keeps for a peer and the offer it makes over the pair's own connection, `actions` the at-most-once command with its durable journal and unknown marks, and `inbox` the one reader that tells a message from an action on that connection. Each is documented where it is enforced |

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
connection is up, and a round that watches a connection is at most `TRUST_POLL` — the
settle window only cuts it shorter, and a round that dials is the dial's own budget
instead, with nothing up to withdraw — so a withdrawal written through the rights layer's
store, another store over the same root, or the other process the self-update window
keeps on it stops the manager: the live connection is closed and the keeper stops naming
the withdrawal, with no reload asked of the caller. A record that is there and cannot be
read is its own cause, not an unpaired machine: the manager fails closed and names the
file. `Connections::disconnect` remains the immediate way to close it in the same act.

Every grant, refusal, ending, withdrawal, return, attempt-lock clearing, refused message,
dropped queue and executed action is appended to `peer::audit`, a private append-only log
under the storage root, before the act it describes: a crash may leave a recorded act that did
not happen and never an act nobody recorded. The log is created as a private temporary file
and published without replacing, so it carries the rule before its first byte lands. Every
append re-checks the log's privacy on the descriptor it writes through, so a log another
account can read refuses the next append, and every append cuts a torn tail another process
left before writing past it. A half-written last entry is cut back, and a half-written header
is completed rather than refused. The log keeps the bytes below its cap minus
`RESERVED_FOR_PERSON_BYTES` for a person: the entries a peer causes by asking — a refusal, a
refused write, an ending a question notices, a message a receiver refuses, an executed action
— stop there and are answered without an entry, while a grant, a withdrawal, a trust
withdrawal, a return and an attempt-lock clearing may use the whole file, so a peer cannot
fill the log and take away the acts that stop it. A person's act that would pass the cap is
refused until the product makes room, and an ending that finds no room is answered and left
unmarked: the log is never compacted, so what a peer's part loses stays lost. The record is
re-read before every question, so a withdrawal by another process on the same root refuses the
next question on this one. Every moment is the caller's; the crate reads no clock.

The connection manager's rule for a fresh connection reads the binding exchange, a message
offer and an action request as what they are: the manager's own handshake and the sender's
own act, not the pair's use. A connection that only exchanged its binding, or offered a
message or an action nobody answered, and then died carried nothing, so it is one dial of the
pair's recovery like any other that carried nothing. A message the receiver took, or answered
"already taken", or an action whose answer means the receiver accepted it — it ran, ran with
a result too large to carry, or the identifier was already spent — is the pair's use and ends
the run of dials, which is what keeps a machine holding one queued message or one unanswered
action from being re-dialled for ever.

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

A queued message dials, and does not dial once a second: `Connections::ensure` makes one dial only
when the policy is due, so the queue's poll and the keeper cannot hammer a peer between them and a
beacon session is not opened per poll. A product with news the crate cannot see — a person asking
again — hands it in through `Connections::wake`, which starts a fresh episode. A stop is not
permanent while its cause is: `ensure` re-opens a stopped pair once the cause has gone and dials it
once, and self-recovery resumes when the caller runs `keep_connected` again — `watched` is how a
product knows it is the one that has to. A stop whose cause is still there is answered as the stop,
with its cause, and that is the same cause the readable state shows.

The machine stays findable by itself too: `Presence::run` opens and holds its own session, and
when the beacon is gone it opens another — so a beacon that comes back finds this machine
registered again with no person and no restart. `Presence::state` reports a `Registration`, so a
product can tell a registration being refreshed from a beacon that is unreachable and when the next
try is due.

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
queued message can cause a dial. `Presence::run` opens and re-opens its own session and returns
nothing, and `Presence::state` reports a `Registration` — no answer from the beacon yet, held, or
the beacon unreachable with the moment the next try was due — so a product can show a beacon
outage instead of looking as though nothing were wrong. The policy has a module of its own,
`peer::recovery`, because the state a product shows and the failures it reports are one contract:
`Recovery`, `StopCause`, `ConnectFailure` and `NotTrustedCause` live there — the last two moved
from `peer::connect` and are still re-exported from `peer` — together with the stated numbers a
caller plans against, `RECOVERY_FIRST_GAP`, `RECOVERY_DIALS` and `RECOVERY_RECHECK`, which is the
bound the slow re-check never exceeds, and `DIAL_BUDGET`, the longest one dial may take, which the
action budget reserves so that a record read cannot cost the dial. `ConnectFailure` gained
`Nowhere` — no beacon and no remembered address, which is configuration rather than a network
state — and `Deferred` — this machine could not read the peer's record just now, which is not a
statement about the peer and not a claim that a dial was made. `Connections` gained `wake` (a
person asking again starts a fresh episode), `ensure` (one dial, paced by the policy, which is how
a queued message or a requested action dials), `recovery` and `watched` (the state, and whether a
keeper will act on it), and `vanish_bound`, whose `Vanish` is a reading rather than a bare
duration. `VANISH_BOUND` is the floor of the bound that reading states, public because a caller
choosing a keep-alive acts on it. `ACCEPT_IN_FLIGHT` is the cap on half-finished handshakes one
machine carries at once — public because the lane count it replaced was, and because a caller
opening a public address needs the number. `Keeper`, `ACCEPT_LANES` and `KEEPER_UNSTABLE_LIMIT`
are gone, and `Connections::keep_connected` answers the `StopCause` it stopped for. `Presence` is
no longer `Clone` — it holds the registration it reports — so a product keeps it once, behind
whatever it already shares, rather than copying it.

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

Messages and actions share the pair's connection. `Inbox::serve` is the one place that takes a
stream and decides what it is: the binding exchange owns the first stream a kept connection
carries, and the inbox owns every stream after it, handing a message or an action to the layer
whose magic the frame carries. A message is therefore never taken for an action nor an action
for a message, in either direction. Two checks keep it so: `peer.one_stream_acceptor` finds a
third acceptor in any other file, excusing only the two the exemption table names, and
`peer.one_acceptor_per_file` holds each of those to a single `accept_bi` call site. An action
in flight does not count as the pair having carried traffic for the connection manager, while
an answer that means the receiving side accepted the operation — it ran, ran with a result
too large to carry, or the identifier was already spent — does. Every other answer means
nothing was taken, so a slow-down followed by a drop is not a link failure. A message counts
only the take; an action also counts a repeat, because its journal proves the receiver
accepted the operation before. So a machine holding one unanswered action cannot be re-dialled
for ever. The beacon carries no action: an action travels only on the pair's own connection.

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
  itself. A machine's apparent address can change mid-run. A dial drives the clock
  itself, so a link that drops everything ends at a
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
- **Peer rig.** `Messaging` opens a machine's message and action layers over its own root,
  with a moment read from the simulated clock, a sink that keeps what the receiver's caller
  was handed and an `Executions` executor that records what the machine's own code was given
  and can run, decline, panic or take its time. `serve` starts the one inbox task per peer and
  the rig stops it on drop. A case that has to count the answers offers by hand on the pair's
  live connection; a case that proves the queue or the action memory runs the real service and
  reads the sink or the executor.
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
