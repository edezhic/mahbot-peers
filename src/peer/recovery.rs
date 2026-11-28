//! The one retry policy for a pair: episodes, growing gaps, and the state a caller reads.
//!
//! # A dial is not an attempt
//!
//! One connection try is a *dial*. The word *attempt* already means a pairing attempt in
//! this crate ([`crate::peer::record::Attempt`]) and is not used for these, so the two
//! cannot be confused in a state, a constant or a report.
//!
//! # An episode
//!
//! Recovery runs in episodes. An episode is a run of dials for one pair: the first is due
//! at once, each gap after a failed one doubles from [`RECOVERY_FIRST_GAP`], and the episode
//! makes at most [`RECOVERY_DIALS`] of them. When it is used up the pair is not finished —
//! it waits [`RECOVERY_RECHECK`] and dials once more, and so on for as long as this machine
//! is running. That is the bound: a peer that keeps refusing is dialled at a decreasing
//! rate and then once a minute, never at handshake rate, and the state says which of the
//! two it is doing.
//!
//! # Reasons to dial, and what starts a new episode
//!
//! This section is the contract; the other three places that describe it — the connection
//! manager's module note, the README and the plan — summarise it and point here.
//!
//! Two different things arrive from outside the policy, and they are not the same:
//!
//! - *A fresh episode*, because the reason the last one went slow has gone: this machine's
//!   start or a caller running the keeper again, a hint carrying a fresh address for the peer,
//!   and a person's requested action. Those are news — somebody has just been told where the
//!   peer is, or a person asked again — and news starts the run of dials over. A person's
//!   action is handed in through [`Connections::wake`](crate::peer::Connections::wake), and a
//!   hint through the dial that carries it. A hint is a claim and not proof: waiting a minute
//!   to test an address a caller has just been given is a bound nobody needs, so the episode
//!   starts over on the claim, while the dial that reaches the peer is what disproves a stop.
//! - *A dial now*, keeping the episode: a message waiting to be delivered, a transfer
//!   waiting for the pair, or a coordination payload from the peer asking for a punch. Each
//!   is a standing condition rather than news, so it moves the next dial to now without
//!   resetting the count. The crate's own queue, its own transfer layer and its own punch
//!   re-arm are what hand it in, and no other path does. The re-arm is rate-limited to one
//!   per [`PUNCH_REARM`](crate::peer::PUNCH_REARM) and never moves a used-up episode, so a
//!   peer that sends a list a second cannot force a dial a second.
//!
//! An authenticated inbound connection from the peer is a reason for neither: the pair is
//! already connected. It is folded in as the next dial of the episode — an inbound connection
//! consumes a dial number — so a peer that dials in and drops cannot escape the cap by being
//! the one who dialled. It does re-open a pair that stopped because it had nowhere to dial:
//! the connection's source address is an address the record now holds.
//!
//! A stopped pair is woken by neither: trust is a person's business, and a stop re-opens only
//! when its cause has gone.
//!
//! # What is retried and what is not
//!
//! Beacon unreachable, peer unknown, no direct path and a key that is not the peer's are
//! retried: each of them is a state that can pass, and a machine that has been switched off, a
//! beacon that was down and a path that changed all look like one of them for a while. "No
//! direct path" is still reported as itself — being retried does not make it a different failure,
//! it makes it one that may stop being true — and it carries the honest advice that another
//! network may work only where the network is what failed: silence from every address it tried. A
//! handshake that completed and lost the tie-break is not a network failure, and it carries no
//! advice to change networks. A wrong key is retried for the same reason and never decides trust:
//! the address that answered that way may be a stale mapping the peer's network has since given to
//! another machine, the peer may be somewhere else entirely, and the peer's own key is still the
//! only one this machine accepts.
//!
//! A refusal of trust is never retried, and neither is a pair with no beacon and no remembered
//! address: the first is decided locally and only a person changes it, and the second is
//! configuration rather than network. Both stop the keeper and both are named in
//! [`StopCause`]. Neither is permanent: a stop is re-opened once its cause has gone — a
//! person restoring trust, or an address learned from the peer — and then the pair is dialled
//! by the next keeper or the next `ensure`. A record this machine could not read *this
//! instant* is neither a refusal nor a stop: [`ConnectFailure::Deferred`] says so, and the
//! dial is tried again rather than counted.
//!
//! # What this state is not
//!
//! It is not an audit entry. The audit answers who allowed what, and a connection retry is
//! nobody's decision: filling the log with them would drown it and would let a refusing
//! peer exhaust the room kept for a person. Retrying is *visible* — [`Recovery`] is
//! readable at any time through [`crate::peer::Connections::recovery`] — and it is not
//! durable: a restart begins a fresh episode, which is the same answer a durable state
//! would give and one fewer thing that can be wrong on disk.

use std::fmt;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::identity::{Fingerprint, PeerId};
use crate::peer::connect::TRUST_POLL;

/// Why the pair could not be connected.
///
/// The five failures of [`crate::peer::connect`]'s note, plus the two answers that are not a
/// network state at all: [`Self::Nowhere`], which is configuration, and [`Self::Deferred`],
/// which is this machine's own fault. The policy records the last of them beside a wait, so a
/// caller can read why the pair is down without a second source.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectFailure {
    /// The beacon leg failed: no beacon is configured, the beacon did not answer,
    /// or it refused the lookup. `cause` names which, and the addresses tried before it
    /// that did not answer, because the failures are classes and the cause is the detail a
    /// reader acts on.
    BeaconUnreachable { peer: Fingerprint, cause: String },
    /// The beacon has no address for the peer: it is not registered. `cause` names
    /// the addresses tried before the beacon, because the remembered dial's detail
    /// is what a reader acts on.
    PeerUnknown { peer: Fingerprint, cause: String },
    /// The peer's address is known and no connection could be made — or a dial's
    /// handshake completed but the tie-break dropped it while the pair held nothing.
    ///
    /// `candidates` is every address the dial failed at, in the order it tried them and without
    /// repeats: a punch dials several at once and each of them is a place the peer was not. It is
    /// empty when every dial of this one completed a handshake and the pair kept none — there is
    /// then no address to name. `cause` names only what this
    /// machine has not ruled out: the text may have been written by the far side. What each
    /// address did — a timeout, a failed handshake, no key — is a diagnostic and does not travel
    /// with this set, because a product shows one honest cause beside the addresses; the beacon
    /// failures carry no set, so theirs name the remembered addresses and their faults, which is
    /// the only place those appear. The one per-address fault reported as its own answer is a key
    /// that is not the peer's: that is [`Self::WrongPeer`], a security fact and not a network one.
    NoDirectPath {
        peer: Fingerprint,
        /// Every address this dial failed at, in the order it tried them.
        candidates: Vec<SocketAddr>,
        cause: String,
    },
    /// An address answered, and the key it proved is not the peer's.
    ///
    /// A security fact and not a network one: something is listening at an address this machine
    /// was told is the peer's, and the key it proved is not the one a person paired with. It is
    /// decided from the handshake alone, never from text, and it is not [`Self::NotTrusted`]:
    /// nothing is decided about the peer, which may be somewhere else entirely.
    ///
    /// [`crate::peer::Connections::connect_with`] answers it even when the pair holds a connection:
    /// the pair being up says nothing about an address that answered with another machine's key,
    /// and a caller that wants the connection reads it from [`crate::peer::Connections::live`].
    /// [`crate::peer::Connections::ensure`] answers it beside [`crate::peer::Recovery::Connected`]
    /// when its own dial met it, because that caller asks for the policy's pace and a pair that is
    /// already up has nothing to pace.
    ///
    /// The address is dropped from the peer's record when this answer is made, best effort: a
    /// failed write leaves it, and the next dial meets the same key and gives the same answer once
    /// more, at the keeper's pace rather than in a loop. The pair itself is untouched, because a
    /// stale mapping says nothing about the peer.
    WrongPeer {
        peer: Fingerprint,
        /// The key the address proved.
        presented: Fingerprint,
        /// The address that answered with it.
        address: SocketAddr,
    },
    /// This machine does not trust the peer. Decided locally and only locally;
    /// `cause` names the local state it is.
    NotTrusted {
        peer: Fingerprint,
        cause: NotTrustedCause,
    },
    /// This machine could not read the peer's record *this instant* — an I/O fault, or a lock
    /// another writer holds. It is a statement about this machine and not about the peer, so it
    /// is not [`Self::NotTrusted`]: nothing is decided about the peer, no dial is counted
    /// against it, a live connection is not torn down, and the next dial reads the file again.
    /// `detail` is the fault, in the record's own words. The pair may be connected while this is
    /// the answer, so the sentence names this machine's read and never claims the peer is out of
    /// reach or that a dial was made.
    Deferred { peer: Fingerprint, detail: String },
    /// There is no beacon configured and the record remembers no address, so this machine
    /// has nowhere to dial. Configuration, not a network state that can pass: a person
    /// configures a beacon or pairs again, and nothing here is retried.
    Nowhere { peer: Fingerprint },
}

/// The one sentence for a pair with nowhere to dial, so the two places that say it cannot
/// drift apart.
const NOWHERE: &str = "no beacon is configured and no address is remembered";

impl fmt::Display for ConnectFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BeaconUnreachable { peer, cause } => {
                // The prefix claims nothing the cause has not: no beacon may be configured, one
                // may have refused, and one may have answered with another version. Naming the
                // beacon here would assert one the first case rules out, and calling it
                // unreachable would name a cause the other two just ruled out.
                write!(f, "could not reach {peer}: {cause}")
            }
            Self::PeerUnknown { peer, cause } => {
                write!(f, "the beacon does not know {peer}: {cause}")
            }
            Self::NoDirectPath {
                peer,
                candidates,
                cause,
            } => {
                // The set is a list and not a count: a reader acts on which addresses were
                // tried, and one address renders exactly as it did before there was a list. An
                // empty set is a dial that completed and whose connection was gone before the
                // pair could keep it, so there is no address to name and no advice to give: the
                // cause already says the handshake completed. The advice, where there is any, is
                // the cause's own, because only the cause knows whether the network is what
                // failed.
                if candidates.is_empty() {
                    return write!(f, "no direct path to {peer}: {cause}");
                }
                let tried = candidates
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                write!(f, "no direct path to {peer} at {tried}: {cause}")
            }
            Self::WrongPeer {
                peer,
                presented,
                address,
            } => write!(
                f,
                "the address {address} proved {presented}, not {peer}: something other than the \
                 peer is at an address this machine was told is the peer's"
            ),
            Self::NotTrusted { peer, cause } => {
                write!(f, "{peer} is not trusted: {cause}")
            }
            Self::Deferred { peer, detail } => write!(
                f,
                "this machine could not read {peer}'s record this instant — {detail}; \
                 nothing is decided about the peer, and the pair is not refused"
            ),
            Self::Nowhere { peer } => write!(f, "there is nowhere to dial {peer}: {NOWHERE}"),
        }
    }
}

impl std::error::Error for ConnectFailure {}

/// Why this machine does not trust a peer: no record at all, a pair its person closed after
/// repeated failed comparisons, a trust its person withdrew, or a record that cannot be read.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NotTrustedCause {
    /// No record says a person paired this machine with the peer.
    NoRecord,
    /// The pair is closed on this machine until a person clears it.
    Closed,
    /// A person withdrew this machine's trust in the peer; a person must restore it.
    Withdrawn,
    /// The peer's record cannot be read: it is reachable by another account, or its bytes are
    /// not a record this build can read. Distinct from [`Self::NoRecord`], because the file a
    /// person must look at is not the same question as a pairing that was never made. `detail`
    /// is the record's own refusal, which names the file and, where one command repairs it, the
    /// command. This is a decision: nothing is trusted on a file nobody could read, and the pair
    /// is stopped.
    Unreadable { detail: String },
}

impl fmt::Display for NotTrustedCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRecord => f.write_str("no record says a person paired this machine with it"),
            Self::Closed => {
                f.write_str("the pair is closed on this machine until a person clears it")
            }
            Self::Withdrawn => f.write_str("a person withdrew this machine's trust in it"),
            Self::Unreadable { detail } => write!(f, "its record cannot be read — {detail}"),
        }
    }
}

impl std::error::Error for NotTrustedCause {}

/// How long the first gap after a failed dial is. Each later gap in the same episode
/// doubles: 1, 2, 4, 8 and 16 seconds for the [`RECOVERY_DIALS`] an episode makes.
pub const RECOVERY_FIRST_GAP: Duration = Duration::from_secs(1);

/// How many dials one episode makes before the pair waits instead of redialling quickly.
pub const RECOVERY_DIALS: u32 = 6;

/// How often a pair whose episode is used up is dialled again.
///
/// This is the slow re-check, and the one timer the crate runs for a pair that is not
/// connected. A minute is short enough that a machine that came back or a beacon that
/// returned is noticed without a person and long enough that a peer that is gone costs one
/// dial a minute rather than a stream of them. A machine waits the answer `recheck` gives
/// rather than this moment exactly, so this stays the bound a product may show.
pub const RECOVERY_RECHECK: Duration = Duration::from_secs(60);

/// The most a machine takes off the slow re-check.
///
/// Derived from the machine's own key and never added to a wait: a machine re-checks a little
/// earlier than the nominal moment, never later, so [`RECOVERY_RECHECK`] stays the bound a
/// product may show. Small enough that the bound is still the bound, and large enough that
/// machines that lost the same beacon do not return to it in lockstep.
const RECHECK_SPREAD: Duration = Duration::from_secs(5);

/// The slow re-check for this machine: [`RECOVERY_RECHECK`] less this machine's share of
/// [`RECHECK_SPREAD`].
///
/// The share is a pure function of the key — no ambient randomness, so a test that moves the
/// clock controls it — and the same machine always takes the same share off. It is counted in
/// microseconds only so that two machines' moments practically never coincide; the whole of
/// the spread is still a bound a product may show.
pub(crate) fn recheck(me: &PeerId) -> Duration {
    let key = me.as_bytes();
    let share = u64::from(u32::from_be_bytes([key[0], key[1], key[2], key[3]]));
    RECOVERY_RECHECK.saturating_sub(Duration::from_micros(share % RECHECK_SPREAD_MICROS))
}

/// [`RECHECK_SPREAD`] in the unit the share is counted in, so nothing here converts.
const RECHECK_SPREAD_MICROS: u64 =
    RECHECK_SPREAD.as_secs() * 1_000_000 + RECHECK_SPREAD.subsec_micros() as u64;

/// How soon a dial deferred by a local fault is tried again.
///
/// One keeper round ([`TRUST_POLL`]), so the wait a caller takes after a fault is exactly the
/// moment the policy named: short, because the fault is this machine's and may pass, and long
/// enough that a record that stays unreadable is not re-read in a spin. The dial is not counted
/// against the peer.
const DEFERRED_GAP: Duration = TRUST_POLL;

/// How the wait after the `dial`-th failure of an episode is measured.
///
/// One place, because the pair's recovery and this machine's registration use the same
/// policy: the gap grows, and once the episode is used up the wait is the slow re-check the
/// caller named — [`recheck`] for a pair, the same for a registration.
pub(crate) fn after(dial: u32, recheck: Duration) -> Duration {
    if dial >= RECOVERY_DIALS {
        recheck
    } else {
        gap(dial)
    }
}

/// The gap after the `dial`-th failed dial of one episode.
///
/// `dial` counts from one and is below the episode's cap here — [`after`] routes the cap and
/// everything past it to the re-check — so the shift is at most [`RECOVERY_DIALS`] - 2.
fn gap(dial: u32) -> Duration {
    RECOVERY_FIRST_GAP.saturating_mul(1u32 << dial.saturating_sub(1))
}

/// How this machine's recovery of one pair stands, readable at any time.
///
/// Non-exhaustive: a new state is a new answer, and a product compiled against an earlier
/// version must still build, so a consumer matches with a wildcard arm and this enum grows
/// without breaking it.
///
/// The moments are the injected runtime's: compare them with
/// [`quinn::Runtime::now`]'s answer, never with a wall clock. [`Display`](fmt::Display) says
/// what the policy is doing and not when, because an `Instant` has no rendering of its own;
/// the moment is a field of the state.
///
/// [`Self::Connected`] is the one state the policy never stores: the manager answers it from
/// the connection it holds. The others are what the policy itself is doing.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Recovery {
    /// Nothing has happened to the pair's recovery: no keeper has run for it, no dial of the
    /// policy's has failed, and the next dial a caller asks for is due at once.
    ///
    /// A caller may dial — [`crate::peer::Connections::ensure`] is how a waiting message and a
    /// requested action do, and the policy paces those dials like any other. A dial that fails
    /// leaves the pair reading [`Self::Waiting`] or [`Self::Exhausted`] instead, whether or not
    /// a keeper watches, because the count is what bounds a peer that keeps dropping the
    /// connection. A dial that reached the peer leaves this state as it was: a pair no keeper
    /// watches has no run of dials behind it and nothing will re-dial it, and
    /// [`crate::peer::Connections::watched`] is what says so. A pair a keeper ran for and then
    /// stopped reads [`Self::Stopped`], because a stop is a decision rather than an absence.
    Unwatched,
    /// The pair has a live connection.
    Connected,
    /// A dial is in flight, and after it the connection it made is being judged.
    ///
    /// This state is stored while a dial runs — the beacon leg and the handshake — and while the
    /// connection that dial made, or one the peer dialled in, is being judged in the
    /// [`crate::peer::KEEPER_SETTLE`] window. A connection the dial made that carried nothing
    /// there is that dial failed, which the fold counts. A caller that does not run a keeper
    /// never has to end it — [`crate::peer::Connections::recovery`] settles a dial whose
    /// connection died before anybody judged it — and it answers [`Self::Connected`] as soon as
    /// the connection is live.
    Dialling {
        /// Which dial of this episode it is, counting from one.
        dial: u32,
    },
    /// The next dial of this episode is due at `until`.
    ///
    /// A keeper makes that dial. A pair nobody watches is dialled only by a caller that asks —
    /// [`crate::peer::Connections::ensure`] — and [`crate::peer::Connections::watched`] says
    /// which of the two it is; the moment is the same either way, because it is the policy's,
    /// not the keeper's.
    Waiting {
        /// When the next dial is due.
        until: Instant,
        /// How many dials this episode has made.
        dial: u32,
        /// What the last one met. With `dial` at zero no dial has run, and this is the local
        /// fault that deferred the next one.
        last: Option<ConnectFailure>,
    },
    /// This episode is used up. The pair is dialled again at `until`, one dial a re-check,
    /// and a reason to dial makes the next one due at once without resetting the count —
    /// only a fresh episode does that. This is not a stop: the pair is still watched and
    /// still dialled, only at the slow rate.
    Exhausted {
        /// When the next single dial is due.
        until: Instant,
        /// How many dials the episode made.
        dials: u32,
        /// What the last one met.
        last: ConnectFailure,
    },
    /// Nothing dials it again by itself: a keeper returns here and stays returned, and a
    /// service path that met a refusal stops the pair here too.
    ///
    /// A stop is a decision and not a network state that passes — this machine does not
    /// trust the peer, or there is nowhere to dial it — so nothing waits it out. It is not
    /// permanent either: [`crate::peer::Connections::ensure`] re-opens it once its cause has
    /// gone, and so does a keeper the caller runs again.
    Stopped {
        /// What stopped it.
        cause: StopCause,
    },
}

/// Why no timer dials a pair again by itself.
///
/// A stop is a decision and not a network state that passes, so no timer waits it out. It is
/// not permanent either: [`crate::peer::Connections::ensure`] re-opens it once its cause has
/// gone and dials once, and self-recovery resumes when the caller runs
/// [`crate::peer::Connections::keep_connected`] again —
/// [`crate::peer::Connections::watched`] says which of the two it is. Nothing inside the
/// crate restarts a stopped keeper by itself.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StopCause {
    /// This machine does not trust the peer, or the record that would say it does cannot
    /// be read. A person decides trust, so no event and no timer re-opens it: only a
    /// person's restoration, which [`crate::peer::Connections::ensure`] notices.
    NotTrusted(NotTrustedCause),
    /// There is no beacon configured and the record remembers no address: configuration,
    /// not a network state that can pass. What re-opens it is proof that the peer is
    /// somewhere — a dial that reached it, or the peer's own connection, whose source
    /// address the record then holds.
    Nowhere,
}

impl Recovery {
    /// The state of a pair with nothing dialling: the next dial due at `until`, after `dial`
    /// of the episode's dials, with `last` what the last of them met.
    fn waiting(until: Instant, dial: u32, last: Option<ConnectFailure>) -> Self {
        Self::Waiting { until, dial, last }
    }

    /// Whether a dial is due at `now`.
    pub(crate) fn due(&self, now: Instant) -> bool {
        match self {
            Self::Unwatched => true,
            Self::Waiting { until, .. } | Self::Exhausted { until, .. } => now >= *until,
            Self::Connected | Self::Dialling { .. } | Self::Stopped { .. } => false,
        }
    }

    /// Take the dial that is due, marking it in flight, and answer which of the episode it
    /// is; `None` when none is due.
    ///
    /// The check and the mark are one step, so two callers reading this state cannot both
    /// take the same dial. A caller that keeps the state also has to keep the fact that a
    /// dial is running — [`crate::peer::Connections`] does, and refuses to begin a second
    /// one while its first is in flight — so this marks the state only.
    pub(crate) fn begin(&mut self, now: Instant) -> Option<u32> {
        if !self.due(now) {
            return None;
        }
        let dial = match self {
            Self::Waiting { dial, .. } => dial.saturating_add(1),
            // A re-check is one dial, not a fresh episode: the timer does not restart the
            // run of dials, only a reason to dial does.
            Self::Exhausted { .. } => RECOVERY_DIALS,
            _ => 1,
        };
        *self = Self::Dialling { dial };
        Some(dial)
    }

    /// The dial failed: wait the growing gap, or use the episode up.
    ///
    /// Total over every state: a stop stays a stop, an episode that is already used up
    /// stays used up at its cap, so a connection that dies after the pair went slow cannot
    /// speed it up again, and a pair no keeper has run for has no episode to count.
    pub(crate) fn failed(&mut self, now: Instant, failure: ConnectFailure, recheck: Duration) {
        // A dial that produced a connection which then died is that dial, not a new one; a
        // connection nobody dialled for is the next. `Unwatched` has no episode behind it and
        // `Connected` is never stored — see the enum's note — so neither counts, and a stop
        // stays a stop.
        let dial = match self {
            Self::Dialling { dial } => *dial,
            Self::Waiting { dial, .. } => dial.saturating_add(1),
            Self::Exhausted { dials, .. } => *dials,
            Self::Unwatched | Self::Connected | Self::Stopped { .. } => return,
        };
        *self = if dial >= RECOVERY_DIALS {
            Self::Exhausted {
                until: now + after(dial, recheck),
                dials: dial,
                last: failure,
            }
        } else {
            Self::waiting(now + after(dial, recheck), dial, Some(failure))
        };
    }

    /// A local fault that is not the peer's — a record that could not be read just now.
    ///
    /// The dial is deferred, not failed: it does not count against the peer, so a fault
    /// that lasts an hour does not use up an episode, and it does not stop the pair. A stop
    /// stays a stop, because a stop is a decision and not a state that passes; an episode
    /// that is used up stays as it is, because its next dial is already the slow re-check
    /// and a fault costs one round of it rather than a faster rate; and a dial already in
    /// flight is not deferred by a fault on this machine. Only the wait moves — and it never
    /// moves closer than the gap the last failure earned — and only a pair with no dial
    /// behind it records the fault: once an episode has dialled, what the last dial met is
    /// what a reader needs, and this fault was not a dial's answer.
    pub(crate) fn deferred(&mut self, now: Instant, failure: ConnectFailure) {
        let soonest = now + DEFERRED_GAP;
        *self = match self {
            Self::Stopped { .. } | Self::Dialling { .. } | Self::Exhausted { .. } => return,
            Self::Waiting { dial: 0, .. } | Self::Unwatched | Self::Connected => {
                Self::waiting(soonest, 0, Some(failure))
            }
            Self::Waiting { until, dial, last } => {
                Self::waiting((*until).max(soonest), *dial, last.clone())
            }
        };
    }

    /// The pair has a connection: the next dial is due at once, and the episode goes on.
    ///
    /// The count is kept, because a connection that dies at once is a dial that produced
    /// nothing and belongs to the same run of dials as the dial that made it. Only a
    /// connection the pair got to use ends the run — [`Self::settled`]. A connection nobody
    /// dialled for — the peer's own — takes the next dial number rather than starting the run
    /// over, so a peer that dials in and drops is bounded like one this machine dials.
    pub(crate) fn adopted(&mut self) {
        let dial = match self {
            // The connection this dial made: the same dial, still being judged.
            Self::Dialling { dial } => *dial,
            // A connection nobody dialled for — the peer's own — is the next dial.
            Self::Waiting { dial, .. } => dial.saturating_add(1),
            // An episode that is used up stays used up: a peer dialling in is not a reason
            // to speed the pair up again, or a peer that accepts and drops and also dials in
            // would escape the cap.
            Self::Exhausted { dials, .. } => *dials,
            // A stop is a decision — trust, or configuration — and a connection arriving does
            // not overrule it. A pair no keeper has run for stays unwatched too: a connection
            // nothing will re-dial after is not a retry, and the state must not promise one.
            Self::Stopped { .. } | Self::Unwatched | Self::Connected => return,
        };
        *self = Self::Dialling { dial };
    }

    /// The pair got to use its connection, or lost it as ordinary churn: the run of dials
    /// is over and the next one is due at once.
    ///
    /// A connection that carried anything and then died is a link failure, and a link
    /// failure is recovery rather than a loop: the dial that follows it is not made to wait
    /// out a gap it did not earn. Neither is one lost to a peer that went quiet: that is the
    /// peer's silence, not a dial that produced nothing.
    ///
    /// A stop stays a stop. A second keeper for the pair can be judging a connection while the
    /// first stops it, and that judgement must not overrule the stop; only [`Self::restarted`]
    /// clears one.
    pub(crate) fn settled(&mut self, now: Instant) {
        if !matches!(self, Self::Stopped { .. }) {
            *self = Self::waiting(now, 0, None);
        }
    }

    /// A caller runs the keeper for the pair again: a person's answer to whatever stopped the
    /// last one, so a stop is cleared and the episode starts over.
    pub(crate) fn restarted(&mut self, now: Instant) {
        *self = Self::waiting(now, 0, None);
    }

    /// A reason to start over: a fresh address for the peer, or a person asking again. A
    /// fresh episode starts now, remembering nothing: what the last one met is not the
    /// reason anything is happening.
    ///
    /// A stopped pair is not woken — trust is a person's business, and a pair with nowhere
    /// to dial has nothing to dial; [`Self::trust_restored`] and [`Self::located`] are how a
    /// stop whose cause has gone comes back. Neither is a dialling one, a connected one
    /// (`Connected` is never stored) or an unwatched one: a connection that works is not
    /// replaced because something arrived, and a pair no keeper watches has no episode for
    /// news to start.
    pub(crate) fn wake(&mut self, now: Instant) {
        match self {
            Self::Unwatched | Self::Connected | Self::Dialling { .. } | Self::Stopped { .. } => {}
            Self::Waiting { .. } | Self::Exhausted { .. } => *self = Self::waiting(now, 0, None),
        }
    }

    /// Proof that the peer is somewhere arrived: a dial that reached it through an address,
    /// or the peer's own connection, whose source address the record now holds.
    ///
    /// A pair that stopped because it had nowhere to dial is open again — a stop that
    /// outlived the proof of an address is the pair dead for good, which is what the retry
    /// policy exists to prevent. A hint alone is not proof: it is a claim about where the
    /// peer might be, and a dial through it is what turns the claim into this. Trust is not
    /// affected: an address says where the peer is, not that a person paired with it.
    pub(crate) fn located(&mut self, now: Instant) {
        self.reopen(now, |cause| matches!(cause, StopCause::Nowhere));
    }

    /// A reason to dial that is a standing condition rather than news: a message waiting to
    /// be delivered, a transfer waiting for the pair, or a coordination payload's re-arm. The
    /// next dial is due now; the episode goes on.
    ///
    /// The count is kept, because a peer that keeps dropping a connection while the queue
    /// or the transfer waits must not escape the bound by having it re-armed every time.
    pub(crate) fn hurry(&mut self, now: Instant) {
        match self {
            Self::Waiting { until, .. } | Self::Exhausted { until, .. } => *until = now,
            Self::Unwatched | Self::Connected | Self::Dialling { .. } | Self::Stopped { .. } => {}
        }
    }

    /// A stop whose cause has gone: a person restored this machine's trust in the peer. The
    /// episode starts again, because what ended it was not a network state that passed.
    ///
    /// Only the trust is decided here. A pair that stopped with nowhere to dial is re-opened
    /// by [`Self::located`], which is what an address that arrived is; and one that stopped
    /// for no trust is not re-opened by an address, because an address says where the peer
    /// is and not that a person paired with it.
    pub(crate) fn trust_restored(&mut self, now: Instant) {
        self.reopen(now, |cause| matches!(cause, StopCause::NotTrusted(_)));
    }

    /// Re-open a stop whose cause `gone` says has gone.
    ///
    /// One transition behind the two names above: both are "the stop's cause is no longer
    /// there, so the episode starts again", and a state that is not stopped by that cause is
    /// left alone.
    fn reopen(&mut self, now: Instant, gone: impl FnOnce(&StopCause) -> bool) {
        if let Self::Stopped { cause } = self
            && gone(cause)
        {
            *self = Self::waiting(now, 0, None);
        }
    }

    /// Why the pair is not up, in the words a caller that asked for one delivery is owed.
    ///
    /// The last dial's failure, or — when no dial has run — the local fault that deferred the
    /// next one, or the stop's cause; `None` while nothing is known and while a dial is in
    /// flight. The conversion from a cause to a failure lives here so the layers above do not
    /// each carry their own copy of it.
    pub(crate) fn down(&self, peer: Fingerprint) -> Option<ConnectFailure> {
        match self {
            Self::Waiting { last, .. } => last.clone(),
            Self::Exhausted { last, .. } => Some(last.clone()),
            Self::Stopped { cause } => Some(cause.clone().failure(peer)),
            Self::Unwatched | Self::Connected | Self::Dialling { .. } => None,
        }
    }

    /// Stop the pair: no timer dials it again until its cause has gone.
    pub(crate) fn stop(&mut self, cause: StopCause) {
        *self = Self::Stopped { cause };
    }
}

impl fmt::Display for Recovery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unwatched => f.write_str("no keeper is running for this pair"),
            Self::Connected => f.write_str("connected"),
            Self::Dialling { dial } => {
                write!(f, "dialling, dial {dial} of {RECOVERY_DIALS}")
            }
            // A wait with no dial behind it is a local fault's deferral, and the words say so
            // rather than counting a dial that did not run — and say it once: the failure the
            // wait carries already says the record could not be read and that the pair is not
            // refused. What a state is doing, never when its next dial will be or what will
            // cause it: a reason to dial can move the moment, so a sentence about the moment
            // cannot stay true. The policy never records a dial without what it met, so a wait
            // with dials behind it and nothing to name is one a caller built by hand; the words
            // then say what is known — the count — and claim nothing more.
            Self::Waiting { dial, last, .. } => {
                if *dial == 0 {
                    f.write_str("waiting to dial")?;
                    if let Some(last) = last {
                        write!(f, ", held up by a local fault: {last}")?;
                    }
                } else {
                    write!(
                        f,
                        "waiting to dial again, {dial} of {RECOVERY_DIALS} dials done"
                    )?;
                    if let Some(last) = last {
                        write!(f, ", the last of which met {last}")?;
                    }
                }
                Ok(())
            }
            Self::Exhausted { dials, last, .. } => write!(
                f,
                "not connected: {dials} dials done, the last of which met {last}; the episode is \
                 used up"
            ),
            Self::Stopped { cause } => write!(f, "stopped: {cause}"),
        }
    }
}

impl fmt::Display for StopCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotTrusted(cause) => write!(f, "this machine does not trust the peer: {cause}"),
            Self::Nowhere => write!(f, "{NOWHERE}, so there is nothing to dial"),
        }
    }
}

impl std::error::Error for StopCause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotTrusted(cause) => Some(cause),
            Self::Nowhere => None,
        }
    }
}

impl StopCause {
    /// The same answer as one of the failures, for a caller that asked to dial once and was
    /// told the pair will not be dialled again.
    pub(crate) fn failure(self, peer: Fingerprint) -> ConnectFailure {
        match self {
            Self::NotTrusted(cause) => ConnectFailure::NotTrusted { peer, cause },
            Self::Nowhere => ConnectFailure::Nowhere { peer },
        }
    }
}
