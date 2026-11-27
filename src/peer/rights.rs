//! The decision: may this connection, as this assistant, exercise this capability
//! on this machine now?
//!
//! # The one question
//!
//! Everything the peer layer records exists to answer [`Rights::decide`], in the
//! plan's order and no other: authenticate, right, the host's own floor. The answer
//! names either the right that allowed it or the step and the reason that refused,
//! and a reason is one of six: not authenticated, the machine is not trusted, no
//! right for this pair, the right was withdrawn, the right ended, or the host's
//! floor refused it. Each refusal belongs to exactly one step, so none can be
//! reported as another's; [`Refusal::step`] is the one place that mapping lives.
//!
//! Nothing executes here. The decision is an answer; whatever asked the question acts
//! on it.
//!
//! # Who may write
//!
//! Only this machine's own person, or this machine's own default policy. A write
//! attributed to a peer — or to any other machine — is refused before it changes
//! anything, and the refusal is written down: a peer asking for a right is a fact
//! worth keeping. The default has one act per pair: exactly "write to me", once,
//! when the pair comes into being, and again only when a person returns the machine
//! from a withdrawn trust. It covers messages and the addressed reply and nothing
//! else — file ingress is [`Capability::PUT_FILES`], a person's explicit grant on the
//! machine that bears the effect. It never re-creates a right a person withdrew or one that
//! ended, and it renews nothing; a right a person withdrew or one that ended stays
//! on file, and its presence is what stops the default acting again. The default is
//! not reachable through [`Rights::grant`]: its two moments are
//! [`Rights::on_acquaintance`] (and [`Rights::bind`]) and [`Rights::restore_trust`].
//!
//! # The host's own floor
//!
//! The floor is this machine's standing say over what it will allow at all. It is
//! applied after a right exists and can only refuse what the right already gives,
//! never add. A refusal at the floor is not a withdrawal: the right stays on file
//! and simply does not reach past the floor, and both facts are written down.
//!
//! # A fresh answer, never a stale one
//!
//! The record is re-read before every question and every write, so a right withdrawn
//! or ended while a connection was up refuses the next question — including when the
//! process that withdrew it is the other one the self-update window keeps on this
//! root. The crate still reads no clock: every moment, including the moment a grant
//! is dated and the moment an ending is noticed, is the caller's.
//!
//! # The record of what happened
//!
//! Every grant, refusal, ending, withdrawal, return and attempt-lock clearing is
//! appended to [`crate::peer::audit`] before the record changes, so a crash may leave a
//! recorded act that did not happen and never an act nobody recorded. The entries a
//! peer causes by asking — the audit module names them — can be caused again and again,
//! so the log keeps room below its cap for a person's acts: one that finds no room
//! there is answered without an entry — a refusal changes nothing, and an ending is a
//! fact of the clock whether or not its row records it — while a person's grant,
//! withdrawal, trust withdrawal, return and attempt-lock clearing may use the whole
//! file. A peer therefore cannot fill the log and take away the acts that stop it.

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use crate::identity::PeerId;
use crate::peer::access::{
    Authority, Binding, Capability, Issuer, Pair, PersonName, Right, Standing,
};
use crate::peer::audit::{Act, AuditError, AuditLog, Entry, GrantKind, WriteRefusal};
use crate::peer::record::{PeerRecord, RecordError, RecordStore, Timestamp};

/// One step of the plan's order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// The connection proved no key, or not this pair's machine.
    Authenticate,
    /// The pair holds no right the question could use.
    Right,
    /// The host's own floor.
    Floor,
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authenticate => f.write_str("authenticate"),
            Self::Right => f.write_str("right"),
            Self::Floor => f.write_str("the host's floor"),
        }
    }
}

/// Why the answer is no.
///
/// One variant per reason, and the step each belongs to is [`Refusal::step`]'s: no
/// step's refusal can be reported as another's, because the step is derived from the
/// reason and never carried beside it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The connection did not prove the pair's machine.
    NotAuthenticated,
    /// The machine is not trusted: no pairing, a closed pair, or a withdrawn trust.
    Untrusted,
    /// The pair holds no right for this capability.
    NoRight,
    /// A person withdrew the right.
    Withdrawn { at: Timestamp },
    /// The right's term passed, at `at`. The moment is the term's end, so the same
    /// ending reads the same however often it is asked.
    Ended { at: Timestamp },
    /// The host's floor refused what the right gives, in the host's own words.
    Floor { reason: String },
}

impl Refusal {
    /// The step that refused.
    #[must_use]
    pub const fn step(&self) -> Step {
        match self {
            Self::NotAuthenticated | Self::Untrusted => Step::Authenticate,
            Self::NoRight | Self::Withdrawn { .. } | Self::Ended { .. } => Step::Right,
            Self::Floor { .. } => Step::Floor,
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The step names itself and the reason says what it refused, so the floor's
        // reason is the host's own words and not a second mention of the step.
        let reason = match self {
            Self::NotAuthenticated => "the connection is not authenticated".to_owned(),
            Self::Untrusted => "the machine is not trusted".to_owned(),
            Self::NoRight => "no right for this pair".to_owned(),
            Self::Withdrawn { at } => format!("the right was withdrawn at {at}"),
            Self::Ended { at } => format!("the right ended at {at}"),
            Self::Floor { reason } => reason.clone(),
        };
        write!(f, "{}: {reason}", self.step())
    }
}

/// Who is asking: the key a completed handshake proved, or nobody.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Speaker {
    /// The key a completed handshake proved. The caller takes it from the
    /// connection, never from a message.
    Authenticated(PeerId),
    /// No completed handshake stands behind the question.
    Unauthenticated,
}

/// The one question: may this connection, as this assistant, exercise this
/// capability on this machine now?
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    /// Who is asking.
    pub speaker: Speaker,
    /// The pair the product names: the machine and the assistant it is connected
    /// to. On the machine that decided the binding that is the binding's pair; on
    /// the other side it is the pair the claim names for its own person.
    pub pair: Pair,
    /// What is asked for.
    pub capability: Capability,
}

/// The answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// The right that allowed it.
    Allowed { right: Right },
    /// The step and reason that refused.
    Refused { refusal: Refusal },
}

impl Decision {
    /// The right that allowed it, if it did.
    ///
    /// The product's capability asks this before it acts; a refusal is read through the
    /// [`Decision::Refused`] variant, whose [`Refusal`] names the step and the reason.
    #[must_use]
    pub const fn allowed(&self) -> Option<&Right> {
        match self {
            Self::Allowed { right } => Some(right),
            Self::Refused { .. } => None,
        }
    }
}

/// Whether this machine may speak to a peer now, and as which pair.
///
/// The sender's side of the decision: `Rights::writing` answers it from the record alone.
/// It is not [`Decision`], because the floor is not applied here — the floor is what this
/// machine allows others to do, not what it may do — and because the answer names the pair
/// a message would travel under. The message layer's own question; a product asks
/// [`crate::peer::messages::Messages::state`] instead, which is this answer for a queue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Writing {
    /// The pair may be written to, and this is the pair.
    Allowed(Pair),
    /// Neither a binding this machine decided nor a claim has arrived: there is no
    /// pair to name.
    Unbound,
    /// The machine is not trusted: no pairing, a closed pair, or a withdrawn trust.
    Untrusted,
    /// The record is trusted, but the pair's "write to me" is not live here.
    Refused(Refusal),
}

/// Whether this machine may take a peer's message, run a peer's action or let a peer's file
/// land now, and as which pair.
///
/// The receiver's side of the decision: `Rights::may_take_message`, `Rights::may_run_action` and
/// `Rights::may_take_file` answer it with the same fixed order and the same record as
/// [`Rights::decide`], and the layer above turns it into one wire answer. The capability is the
/// layer's, never the body's: a message asks "write to me", an action asks "work on me" and a
/// file asks "put files on me", and none of them names one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Admission {
    /// The request may be taken, as this pair and under this right.
    Allowed {
        /// The pair the request travels under.
        pair: Pair,
        /// The right that allowed it, which the action layer names in its record of the run.
        right: Right,
        /// This machine's most recent withdrawal of trust in the peer, from the same record
        /// read that named the pair. The action memory treats everything recorded before it as
        /// gone; the message layer ignores it.
        since: Option<Timestamp>,
    },
    /// Neither a binding this machine decided nor a claim has arrived: there is no pair to
    /// name yet, so the sender is told nothing and asks again.
    Unbound,
    /// The decision refused this request.
    Refused(Refusal),
}

/// This machine's standing say over what it will allow at all.
///
/// The crate never decides what the floor says: the product supplies it. It can only
/// refuse what a right already gives — `None` keeps the right, `Some(reason)` refuses
/// it in the host's own words — and a refusal is not a withdrawal.
pub trait Floor {
    /// `None` when the floor keeps what the right gives, the host's own words when it
    /// does not.
    fn refuses(&self, pair: &Pair, capability: Capability) -> Option<String>;
}

impl<F> Floor for F
where
    F: Fn(&Pair, Capability) -> Option<String>,
{
    fn refuses(&self, pair: &Pair, capability: Capability) -> Option<String> {
        self(pair, capability)
    }
}

/// The floor that refuses nothing: this machine's own say, named by the caller, not
/// the crate's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NoFloor;

impl Floor for NoFloor {
    fn refuses(&self, _pair: &Pair, _capability: Capability) -> Option<String> {
        None
    }
}

/// A machine's own floor over the caller's: the caller's policy, plus the one refusal this
/// machine makes for itself.
///
/// A product that gave the transfer layer nowhere to put a file has not granted "put files on
/// me", and the refusal is a floor's — the same step, and the same recorded entry, as a host
/// policy's. That is what keeps the crate from reading a product's configuration as a rights
/// fact: it asks the floor, and the floor is where a machine's own policy lives.
pub(crate) struct FileIngress {
    floor: Arc<dyn Floor + Send + Sync>,
    has_sink: bool,
}

impl FileIngress {
    /// `floor`, with file ingress refused unless this machine has somewhere to put a file.
    pub(crate) fn new(floor: Arc<dyn Floor + Send + Sync>, has_sink: bool) -> Self {
        Self { floor, has_sink }
    }
}

impl Floor for FileIngress {
    fn refuses(&self, pair: &Pair, capability: Capability) -> Option<String> {
        if !self.has_sink && capability == Capability::PUT_FILES {
            return Some("this machine has nowhere to put a file".to_owned());
        }
        self.floor.refuses(pair, capability)
    }
}

/// What a return from a withdrawn trust left standing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Restored {
    /// The right the return left the pair with, when it left one.
    ///
    /// `None` means the pair's "write to me" row was stopped — withdrawn or ended — so
    /// the default re-created nothing and the pair holds no live right. A live row a
    /// person wrote is answered as issued: it is the right the pair has, and the
    /// default added nothing to it.
    pub issued: Option<Right>,
    /// The pairing attempt lock, when it still closes the pair after the return.
    ///
    /// The lock is a separate person act — [`Rights::clear_attempt_lock`] — so a
    /// return does not clear it; it says it is there rather than answering a right
    /// that cannot be used. `None` means the failed comparisons no longer close the
    /// pair; an unfinished attempt is not reported, because it stops a new ceremony
    /// until it expires and never a right.
    pub closed: Option<Closed>,
}

/// A pairing attempt lock that still closes a pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Closed {
    /// The failed comparisons counted against the pair.
    pub failures: u8,
    /// The count that closes it: [`crate::peer::Limits::max_failures`].
    pub max_failures: u8,
}

/// This machine's rights, the decision and the record of it.
///
/// Cheap to clone: the record and the log are handles. The caller builds both from
/// one storage root, and nothing here checks that it did: a mismatched pair is a caller
/// error, and making construction fallible for it would charge every correct caller
/// for a state only a bug produces.
#[derive(Clone, Debug)]
pub struct Rights {
    records: RecordStore,
    audit: AuditLog,
    /// The act lock: one act — a check and the writes it leads to — at a time for one
    /// `Rights` and its clones, so two callers of one value cannot interleave a
    /// default's check with a person's grant. Two `Rights` built separately over one
    /// store do not share it; the record's own write guard is what keeps their writes
    /// from being lost, and a doubled default entry is two true statements rather than
    /// a wrong record.
    acts: Arc<Mutex<()>>,
}

impl Rights {
    /// Build the decision over a record and the log that records it.
    #[must_use]
    pub fn new(records: RecordStore, audit: AuditLog) -> Self {
        Self {
            records,
            audit,
            acts: Arc::new(Mutex::new(())),
        }
    }

    /// The act lock, held across one act's check and its writes.
    fn acts(&self) -> MutexGuard<'_, ()> {
        self.acts.lock().expect("the act lock is not poisoned")
    }

    /// The record this decision reads.
    pub(crate) const fn records(&self) -> &RecordStore {
        &self.records
    }

    /// Decide the one question, in the plan's order.
    ///
    /// The record is re-read first, so the answer never comes from a stale view. A
    /// refusal is appended to the log before it is returned — unless the log's room
    /// for a person's acts is all that is left, in which case the refusal is answered
    /// without an entry: nothing changed, and a peer must not be able to fill the log
    /// and take away the acts that stop it. An allowance is not appended: it changes
    /// nothing, and the act that follows it is the caller's to record with the right it
    /// names.
    ///
    /// The pair the question names must be the pair this machine decided, when it
    /// decided one: a machine bound to another assistant is that pair, and the rows
    /// of the pair it left are the record of what it held, not a right it still has.
    /// A question naming a pair the binding does not is refused at the right step.
    /// On the other side there is no binding, and the pair is the one the claim names
    /// for its own person — [`Pair::of_claim`] — which is that person's act.
    pub fn decide(
        &self,
        question: &Question,
        floor: &dyn Floor,
        now: Timestamp,
    ) -> Result<Decision, RightsError> {
        let _acts = self.acts();
        let pair = &question.pair;
        let authenticated = match question.speaker {
            Speaker::Authenticated(peer) => peer == *pair.peer(),
            Speaker::Unauthenticated => false,
        };
        if !authenticated {
            return self.refuse(question, Refusal::NotAuthenticated, now);
        }
        let record = self.records.reread(pair.peer())?;
        let Some(record) = record else {
            return self.refuse(question, Refusal::Untrusted, now);
        };
        if !record.trusted(&self.records.limits()) {
            return self.refuse(question, Refusal::Untrusted, now);
        }
        if record
            .binding()
            .is_some_and(|binding| binding.fact().assistant() != pair.assistant())
        {
            return self.refuse(question, Refusal::NoRight, now);
        }
        let Some(right) = record.right(pair, question.capability).cloned() else {
            return self.refuse(question, Refusal::NoRight, now);
        };
        match right.standing(now) {
            Standing::Live => {}
            Standing::Withdrawn(at) => {
                return self.refuse(question, Refusal::Withdrawn { at }, now);
            }
            Standing::Ended(at) => {
                if right.ended_at().is_none()
                    && self.record_ending(pair, question.capability, now)?
                {
                    // The ending is written down before the row records it, like every
                    // other act: a crash may leave an ending that the row does not show,
                    // never a row whose ending nobody recorded. A log with no room for it
                    // leaves the row unmarked — the right refuses either way, because its
                    // term passed, and the row's own `expires_at` still names the moment.
                    self.records
                        .mark_ended(pair.peer(), pair, question.capability, now)?;
                }
                return self.refuse(question, Refusal::Ended { at }, now);
            }
        }
        if let Some(reason) = floor.refuses(pair, question.capability) {
            return self.refuse(question, Refusal::Floor { reason }, now);
        }
        Ok(Decision::Allowed { right })
    }

    /// Whether this machine may speak to `peer` now, and as which pair.
    ///
    /// The sender's question, answered from one fresh read of the record. The record
    /// must be trusted; when this machine decided the binding, the pair is the
    /// binding's and its "write to me" must be live; when it did not, the claim names
    /// the pair and the receiver decides, so the claim alone allows. `Unbound` when
    /// neither a binding nor a claim has arrived.
    ///
    /// The floor is not applied: the floor is what this machine allows others to do,
    /// and a message this machine offers is its own act. Nothing is written and nothing
    /// is recorded — the answer changes no state, and the entry that matters is the
    /// receiver's.
    ///
    /// # Errors
    ///
    /// The record's own refusal.
    pub(crate) fn writing(&self, peer: &PeerId, now: Timestamp) -> Result<Writing, RightsError> {
        let Some(record) = self.records.reread(peer)? else {
            return Ok(Writing::Untrusted);
        };
        if !record.trusted(&self.records.limits()) {
            return Ok(Writing::Untrusted);
        }
        if let Some(binding) = record.binding() {
            let pair = Pair::of_binding(*peer, binding);
            let Some(right) = record.right(&pair, Capability::WRITE) else {
                return Ok(Writing::Refused(Refusal::NoRight));
            };
            return Ok(match right.standing(now) {
                Standing::Live => Writing::Allowed(pair),
                Standing::Withdrawn(at) => Writing::Refused(Refusal::Withdrawn { at }),
                Standing::Ended(at) => Writing::Refused(Refusal::Ended { at }),
            });
        }
        if let Some(claim) = record.claim() {
            return Ok(Writing::Allowed(Pair::of_claim(&claim)));
        }
        Ok(Writing::Unbound)
    }

    /// The receiver's question: may a message from `peer` be taken now?
    ///
    /// The same fixed order and the same record of what happened as [`Self::decide`]: the
    /// question is the pair's assistant asking to "write to me", with the host's floor. The
    /// pair is the binding's when this machine decided one, the claim's otherwise; with neither
    /// there is no pair to name, so the answer is [`Admission::Unbound`] — nothing decided,
    /// nothing recorded — and the sender offers again rather than losing its message to a state
    /// that is about to change. A peer with no record at all is [`Refusal::Untrusted`], the
    /// authenticate step's answer.
    ///
    /// # Errors
    ///
    /// The record's and the log's own refusals.
    pub(crate) fn may_take_message(
        &self,
        peer: &PeerId,
        floor: &dyn Floor,
        now: Timestamp,
    ) -> Result<Admission, RightsError> {
        self.admission(peer, Capability::WRITE, floor, now)
    }

    /// The receiver's question: may an action from `peer` be run now?
    ///
    /// The same order and the same record as [`Self::may_take_message`], with the right the
    /// plan gives a command: "work on me". The capability is fixed here and never comes from
    /// the action's body or its kind; the action layer names no capability at all, which is
    /// what the `actions.no_capability_from_a_body` invariant scans for. A second kind of
    /// action would extend this mapping where the right belongs, not in the layer that carries
    /// the bytes.
    ///
    /// # Errors
    ///
    /// The record's and the log's own refusals.
    pub(crate) fn may_run_action(
        &self,
        peer: &PeerId,
        floor: &dyn Floor,
        now: Timestamp,
    ) -> Result<Admission, RightsError> {
        self.admission(peer, Capability::WORK, floor, now)
    }

    /// The receiver's question: may a file from `peer` land on this machine now?
    ///
    /// The same order and the same record as [`Self::may_take_message`], with the right
    /// the plan gives a file: "put files on me". It is never the default, so a pair
    /// that holds only the default is refused at the right step and learns nothing
    /// about what this machine holds. The capability is fixed here and never comes
    /// from the transfer's name or its bytes, which is what the
    /// `transfers.name_decides_nothing` invariant scans for: the layer above names
    /// the permission only through the right this answer returns.
    ///
    /// The decision is asked once, when a transfer is authorised: a transfer that
    /// resumes after a reconnect is the same transfer, and a right withdrawn while it
    /// runs ends the next one, not this one. The binding is re-checked when it
    /// resumes, by the transfer layer, against the pair this answer names.
    ///
    /// # Errors
    ///
    /// The record's and the log's own refusals.
    pub(crate) fn may_take_file(
        &self,
        peer: &PeerId,
        floor: &dyn Floor,
        now: Timestamp,
    ) -> Result<Admission, RightsError> {
        self.admission(peer, Capability::PUT_FILES, floor, now)
    }

    /// The one admission every service asks: a fresh record, the pair it names, the decision.
    fn admission(
        &self,
        peer: &PeerId,
        capability: Capability,
        floor: &dyn Floor,
        now: Timestamp,
    ) -> Result<Admission, RightsError> {
        let Some(record) = self.records.reread(peer)? else {
            // No record is no acquaintance: the handshake would already have refused this
            // peer, so the answer is the one the authenticate step gives.
            return Ok(Admission::Refused(Refusal::Untrusted));
        };
        let pair = record
            .binding()
            .map(|binding| Pair::of_binding(*peer, binding))
            .or_else(|| record.claim().map(|claim| Pair::of_claim(&claim)));
        let since = record.last_withdrawn_at();
        let Some(pair) = pair else {
            return Ok(Admission::Unbound);
        };
        match self.decide(
            &Question {
                speaker: Speaker::Authenticated(*peer),
                pair: pair.clone(),
                capability,
            },
            floor,
            now,
        )? {
            Decision::Allowed { right } => Ok(Admission::Allowed { pair, right, since }),
            Decision::Refused { refusal } => Ok(Admission::Refused(refusal)),
        }
    }

    /// Write the refusal down and answer it.
    ///
    /// A log with no room left in the part a peer may fill answers the same refusal
    /// without an entry: a refusal changes nothing, so the answer does not depend on
    /// the record of it, and a peer that keeps asking must not be able to take the
    /// room a person's own acts need.
    fn refuse(
        &self,
        question: &Question,
        refusal: Refusal,
        now: Timestamp,
    ) -> Result<Decision, RightsError> {
        self.record_softly(&Entry {
            at: now,
            act: Act::Refused {
                pair: question.pair.clone(),
                capability: question.capability,
                refusal: refusal.clone(),
            },
        })?;
        Ok(Decision::Refused { refusal })
    }

    /// Create, widen or restore a right, on the authority the product names.
    ///
    /// A person's grant sets the term it names and becomes the row's issuer, so a
    /// guest assistant a person widens past "write to me" records that person's act.
    /// The default is not reachable here: its two moments are
    /// [`Self::on_acquaintance`] and [`Self::restore_trust`], so there is one path to
    /// its one act per pair. A grant for a pair the binding does not name is kept — a
    /// person's act is not unmade — and [`Self::decide`] refuses it while the machine
    /// is bound to another assistant; a move back to that assistant resumes the
    /// pair's rows.
    ///
    /// # Errors
    ///
    /// [`RightsError::Write`] for a write attributed to a peer — the one refusal a
    /// peer's word always gets — and the record's and the log's own errors.
    pub fn grant(
        &self,
        pair: &Pair,
        capability: Capability,
        by: Authority,
        term: Option<Duration>,
        now: Timestamp,
    ) -> Result<Right, RightsError> {
        let _acts = self.acts();
        match by {
            Authority::Peer(peer) => {
                let refusal = WriteRefusal::RemoteAuthority { peer };
                self.refuse_write(pair, capability, refusal.clone(), now)?;
                Err(refusal.into())
            }
            Authority::Person(person) => {
                self.write(pair, capability, Issuer::Person(person), term, now)
            }
        }
    }

    /// A person's grant: create, widen or restore the pair's row.
    fn write(
        &self,
        pair: &Pair,
        capability: Capability,
        issuer: Issuer,
        term: Option<Duration>,
        now: Timestamp,
    ) -> Result<Right, RightsError> {
        let record = self.paired(pair.peer())?;
        let expires_at = term.map(|term| now.plus(term));
        let (right, kind) = match record.right(pair, capability) {
            None => (
                Right::new(pair.assistant().clone(), capability, expires_at, issuer),
                GrantKind::Created,
            ),
            Some(existing) => {
                let kind = match existing.standing(now) {
                    Standing::Live => GrantKind::Widened,
                    Standing::Withdrawn(_) | Standing::Ended(_) => GrantKind::Restored,
                };
                (existing.clone().regranted(expires_at, issuer), kind)
            }
        };
        self.audit.append(&Entry {
            at: now,
            act: Act::Granted {
                pair: pair.clone(),
                capability,
                issuer: right.issuer().clone(),
                expires_at,
                kind,
            },
        })?;
        self.records.put_right(pair.peer(), right.clone())?;
        Ok(right)
    }

    /// Issue "write to me" for the pair unless the default already acted for it.
    ///
    /// This is the default's whole policy: one capability, once per pair, and again
    /// only when a person returns the machine from a withdrawn trust — which removes
    /// the rows and the marker, so the pair comes into being again. A row a person
    /// already wrote is left as it stands: a live one is answered as the pair's, and a
    /// stopped one is answered with `None`, because the default never re-creates what
    /// a person withdrew or what a term ended.
    fn issue_default(&self, pair: &Pair, now: Timestamp) -> Result<Option<Right>, RightsError> {
        let record = self.paired(pair.peer())?;
        if record.default_spent(pair).is_some() {
            return Ok(None);
        }
        // A row a person already wrote is left as it stands: the default has nothing
        // to add. A live one is the pair's "write to me" and is answered as issued; a
        // stopped one is not re-created, and the answer is `None` — the pair holds no
        // live right, and the marker still records that the default's one act is spent.
        let (right, kind, issued) = match record.right(pair, Capability::WRITE) {
            Some(existing) => (
                existing.clone(),
                GrantKind::AlreadyHeld,
                existing.standing(now) == Standing::Live,
            ),
            None => (
                Right::new(
                    pair.assistant().clone(),
                    Capability::WRITE,
                    None,
                    Issuer::Default,
                ),
                GrantKind::Created,
                true,
            ),
        };
        self.audit.append(&Entry {
            at: now,
            act: Act::Granted {
                pair: pair.clone(),
                capability: Capability::WRITE,
                // The row's own issuer: when a person already wrote this capability,
                // the default added nothing and the log must not attribute that
                // person's right to the default.
                issuer: right.issuer().clone(),
                expires_at: right.expires_at(),
                kind,
            },
        })?;
        if kind == GrantKind::Created {
            self.records.put_right(pair.peer(), right.clone())?;
        }
        self.records.mark_default(pair.peer(), pair, now)?;
        Ok(issued.then_some(right))
    }

    /// Issue the default for a pair that has just come into being.
    ///
    /// The product calls this when two machines become acquainted. The pair is the
    /// binding's whenever this machine decided one, and the caller's otherwise — the
    /// other side of a connection, where the pair comes from the claim. `None` means
    /// the default already acted for the pair, so nothing was written and nothing was
    /// recorded: the default never acts again.
    pub fn on_acquaintance(
        &self,
        pair: &Pair,
        now: Timestamp,
    ) -> Result<Option<Right>, RightsError> {
        let _acts = self.acts();
        let pair = decided_pair(&self.paired(pair.peer())?, pair);
        self.issue_default(&pair, now)
    }

    /// Decide the connection level for `peer`, and issue the default for the pair
    /// the binding makes.
    ///
    /// The binding is this machine's own decision; the other side is shown it as a
    /// claim and allows nothing on its strength. A new assistant is a new pair, which
    /// starts from the default and inherits nothing from the pair the machine left.
    pub fn bind(
        &self,
        peer: &PeerId,
        binding: Binding,
        now: Timestamp,
    ) -> Result<Option<Right>, RightsError> {
        let _acts = self.acts();
        let pair = Pair::of_binding(*peer, &binding);
        self.paired(peer)?;
        self.records.set_binding(peer, binding)?;
        self.issue_default(&pair, now)
    }

    /// A person withdraws a right. The next question about it is refused, with no new
    /// connection needed, and the row stays on file.
    ///
    /// A right already withdrawn is answered as it stands and nothing is recorded:
    /// a repeated withdrawal is not a new act.
    pub fn withdraw(
        &self,
        pair: &Pair,
        capability: Capability,
        by: PersonName,
        now: Timestamp,
    ) -> Result<Right, RightsError> {
        let _acts = self.acts();
        let record = self.paired(pair.peer())?;
        let Some(right) = record.right(pair, capability).cloned() else {
            return Err(RightsError::NoSuchRight {
                pair: pair.clone(),
                capability,
            });
        };
        if right.withdrawn_at().is_some() {
            return Ok(right);
        }
        let right = right.withdrawn(now);
        self.audit.append(&Entry {
            at: now,
            act: Act::Withdrawn {
                pair: pair.clone(),
                capability,
                by,
            },
        })?;
        self.records.put_right(pair.peer(), right.clone())?;
        Ok(right)
    }

    /// A person withdraws trust in a whole machine: the rights it held are removed,
    /// its next handshake is refused, and the connection manager stops reaching for
    /// it.
    ///
    /// Nothing on this call depends on who holds which handle. The manager reads the
    /// record from disk on every round — before a dial, before a handshake and while a
    /// connection is up — so a withdrawal written through this handle, another one, or
    /// the other process the self-update window keeps on this root stops it, and the
    /// live connection is closed within one keeper round, which is at most
    /// [`crate::peer::TRUST_POLL`]: the settle window only cuts a round shorter. A caller
    /// that wants it closed now calls [`crate::peer::Connections::disconnect`] in the
    /// same act; the keeper then stops with [`crate::peer::NotTrustedCause::Withdrawn`].
    /// A manager that is not running for the pair is not reached at all, and a product
    /// that dials on demand asks the record again before each dial.
    ///
    /// The withdrawal is one record publish — the flag, the rights and the default
    /// markers together — so there is no state in which the trust is gone and the
    /// rights still stand. The count is how many rights rows this call read on its way
    /// in; the publish removes what its own re-read finds, which is the same set unless
    /// another writer added a row in between. A repeated withdrawal answers zero,
    /// because the first act removed them and its entry says how many. A right a newer
    /// build wrote for a capability this build does not know is removed by the same
    /// publish and is not counted, because this build cannot read the row.
    ///
    /// The binding stays: the key did not change, so a return needs no new
    /// comparison.
    pub fn withdraw_trust(
        &self,
        peer: &PeerId,
        by: PersonName,
        now: Timestamp,
    ) -> Result<usize, RightsError> {
        let _acts = self.acts();
        let record = self.existing(peer)?;
        if !record.is_paired() {
            return Err(RightsError::NotPaired { peer: *peer });
        }
        if record.is_withdrawn() {
            // The act is over and its entry says how many rows it removed. A record that
            // still holds rights under the flag — one an older build wrote before the
            // withdrawal became a single publish — is finished here, and this call
            // removed none.
            if !self.records.withdraw_trust(peer, now)? {
                return Err(RightsError::NotPaired { peer: *peer });
            }
            return Ok(0);
        }
        let rights = record.rights().len();
        self.audit.append(&Entry {
            at: now,
            act: Act::TrustWithdrawn {
                peer: *peer,
                by,
                rights,
            },
        })?;
        if !self.records.withdraw_trust(peer, now)? {
            return Err(RightsError::NotPaired { peer: *peer });
        }
        Ok(rights)
    }

    /// A person restores a withdrawn machine: acquaintance returns with no new
    /// comparison, and the default issues again for the pair the machine is bound to.
    ///
    /// The pair is the binding's whenever this machine decided one — the same pair a
    /// question names — and the caller's otherwise, which is the other side of a
    /// connection, where the pair comes from the claim and is the person's act. A
    /// caller that passes a claim-derived pair after a rebind therefore cannot issue
    /// the default for a pair this machine is not bound to. Nothing a person granted
    /// before the withdrawal comes back.
    ///
    /// # One act, finished by calling again
    ///
    /// The return is the flag's clearing *and* the default's issue, and a caller that
    /// stops between them would leave a machine that came back with no right. So the
    /// act is over only when the default has acted for the pair: a call that finds
    /// the trust already restored and the default already issued answers
    /// [`RightsError::NotWithdrawn`], and a call that finds the trust restored and
    /// the default still owed issues it. A retry after a failure therefore finishes
    /// the act instead of reporting that it is over.
    ///
    /// The same finish applies to a pair whose trust was never withdrawn: a call for a
    /// machine this one trusts, whose default is still owed, issues the default and
    /// answers [`Restored`] with a `Granted` entry and no `TrustRestored` — the right is
    /// owed, and the return is the act that owes it. That entry names the row's own
    /// issuer: the default when the default created the right, the person when a row
    /// that person already wrote is reused. That is not a way to grant a right to the
    /// wrong peer: the pair is the binding's, so a caller passing a claim-derived pair
    /// after a rebind still issues for the pair this machine is bound to.
    ///
    /// # What still stands
    ///
    /// The pairing attempt lock is a separate person act, so the return does not
    /// clear it. When it still closes the pair — the machine failed its comparisons
    /// three times — every question about it is refused as untrusted however the
    /// return went, and [`Restored::closed`] says so plainly instead of answering a
    /// right that cannot be used.
    ///
    /// # Errors
    ///
    /// [`RightsError::NotPaired`] for a machine this one never paired,
    /// [`RightsError::NotWithdrawn`] for a return that is over, and the record's and
    /// the log's own errors.
    pub fn restore_trust(
        &self,
        pair: &Pair,
        by: PersonName,
        now: Timestamp,
    ) -> Result<Restored, RightsError> {
        let _acts = self.acts();
        let record = self.existing(pair.peer())?;
        if !record.is_paired() {
            return Err(RightsError::NotPaired { peer: *pair.peer() });
        }
        let pair = decided_pair(&record, pair);
        if record.is_withdrawn() {
            self.audit.append(&Entry {
                at: now,
                act: Act::TrustRestored {
                    peer: *pair.peer(),
                    by,
                },
            })?;
            self.records.restore_trust(pair.peer())?;
        } else if record.default_spent(&pair).is_some() {
            return Err(RightsError::NotWithdrawn { peer: *pair.peer() });
        }
        let issued = self.issue_default(&pair, now)?;
        let record = self.existing(pair.peer())?;
        let limits = self.records.limits();
        let closed = (record.failures() >= limits.max_failures).then_some(Closed {
            failures: record.failures(),
            max_failures: limits.max_failures,
        });
        Ok(Restored { issued, closed })
    }

    /// A person clears the pairing attempt lock: the failures and any unfinished
    /// attempt, not the pairing and not a right.
    ///
    /// A lock with nothing to clear is answered as cleared and records nothing: an
    /// act that changed nothing is not an act, and the log is the record of what
    /// happened.
    pub fn clear_attempt_lock(
        &self,
        peer: &PeerId,
        by: PersonName,
        now: Timestamp,
    ) -> Result<(), RightsError> {
        let _acts = self.acts();
        let record = self.existing(peer)?;
        if record.failures() == 0 && record.attempt().is_none() {
            return Ok(());
        }
        self.audit.append(&Entry {
            at: now,
            act: Act::AttemptLockCleared { peer: *peer, by },
        })?;
        self.records.clear(peer)?;
        Ok(())
    }

    /// Record every right whose term has passed, answering how many endings were
    /// written down.
    ///
    /// A product calls this at start-up and on whatever cadence it keeps, so a term
    /// that passes with no question asked still leaves a record. The sweep covers the
    /// peers this store has loaded; a record another process on the same root wrote is
    /// swept by that process. An ending the log has no room for is skipped like any
    /// peer-driven entry: the right refuses either way, and its row's `expires_at`
    /// still names the moment.
    pub fn end_expired(&self, now: Timestamp) -> Result<usize, RightsError> {
        let _acts = self.acts();
        let mut ended = 0;
        for peer in self.records.peers() {
            let Some(record) = self.records.reread(&peer)? else {
                continue;
            };
            for right in record.rights().to_vec() {
                if right.ended_at().is_some() || !matches!(right.standing(now), Standing::Ended(_))
                {
                    continue;
                }
                let pair = Pair::from_parts(peer, right.assistant().clone());
                if !self.record_ending(&pair, right.capability(), now)? {
                    continue;
                }
                self.records
                    .mark_ended(&peer, &pair, right.capability(), now)?;
                ended += 1;
            }
        }
        Ok(ended)
    }

    /// The rights on file for one pair, read fresh.
    ///
    /// This is what a person is shown when the product lists what a machine may do here:
    /// the rows as the record holds them, with their issuers, terms and standings.
    pub fn rights(&self, pair: &Pair) -> Result<Vec<Right>, RightsError> {
        Ok(self
            .records
            .reread(pair.peer())?
            .map(|record| record.rights_of(pair).cloned().collect())
            .unwrap_or_default())
    }

    /// The log this decision writes, for the product that shows a person what happened.
    #[must_use]
    pub const fn audit(&self) -> &AuditLog {
        &self.audit
    }

    /// The pair this machine decided for `peer`, read fresh.
    ///
    /// The product asks with this on the machine that made the decision, so the pair a
    /// question names is that decision and not a label from a message. On the other
    /// side there is no binding, and the pair is the one its person names from the
    /// claim — [`Pair::of_claim`] — which is the person's act and not the crate's.
    pub fn bound_pair(&self, peer: &PeerId) -> Result<Option<Pair>, RightsError> {
        let Some(record) = self.records.reread(peer)? else {
            return Ok(None);
        };
        Ok(record
            .binding()
            .map(|binding| Pair::of_binding(*peer, binding)))
    }

    /// Write a refused write down; a log with no room for it changes nothing, because
    /// the refusal is the answer either way.
    fn refuse_write(
        &self,
        pair: &Pair,
        capability: Capability,
        reason: WriteRefusal,
        now: Timestamp,
    ) -> Result<(), RightsError> {
        self.record_softly(&Entry {
            at: now,
            act: Act::WriteRefused {
                pair: pair.clone(),
                capability,
                reason,
            },
        })?;
        Ok(())
    }

    /// Append a peer-driven entry, answering whether the log took it.
    ///
    /// A log with no room in the part a peer may fill is nothing to record rather than a
    /// failure: a refusal is answered either way, and an ending is a fact of the clock.
    fn record_softly(&self, entry: &Entry) -> Result<bool, RightsError> {
        match self.audit.append(entry) {
            Ok(()) => Ok(true),
            Err(AuditError::NoRoom { .. } | AuditError::TooLarge { .. }) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    /// Write down the ending a question or a sweep noticed, answering whether the log
    /// took it.
    fn record_ending(
        &self,
        pair: &Pair,
        capability: Capability,
        now: Timestamp,
    ) -> Result<bool, RightsError> {
        self.record_softly(&Entry {
            at: now,
            act: Act::Ended {
                pair: pair.clone(),
                capability,
            },
        })
    }

    /// The peer's record, read fresh, held to being a pair this machine may write
    /// rights for: paired, and not withdrawn.
    fn paired(&self, peer: &PeerId) -> Result<PeerRecord, RightsError> {
        let record = self.existing(peer)?;
        if !record.is_paired() {
            return Err(RightsError::NotPaired { peer: *peer });
        }
        if record.is_withdrawn() {
            return Err(RightsError::Withdrawn { peer: *peer });
        }
        Ok(record)
    }

    /// The peer's record, read fresh, whatever state it is in.
    fn existing(&self, peer: &PeerId) -> Result<PeerRecord, RightsError> {
        self.records
            .reread(peer)?
            .ok_or(RightsError::NotPaired { peer: *peer })
    }
}

/// The pair this machine decided for `record`'s machine, when it decided one; the
/// caller's pair otherwise.
///
/// The binding is this machine's own decision, so on the deciding machine the pair a
/// default is issued for is the binding's and never a label a caller passed. The other
/// side has no binding, and its pair comes from the claim, which is its person's act.
fn decided_pair(record: &PeerRecord, pair: &Pair) -> Pair {
    record.binding().map_or_else(
        || pair.clone(),
        |binding| Pair::of_binding(*pair.peer(), binding),
    )
}

/// Why a write or a question could not be answered.
#[derive(Debug)]
pub enum RightsError {
    /// The record could not be read or written.
    Record(RecordError),
    /// The log could not be read or written.
    Audit(AuditError),
    /// No record says a person paired this machine with the peer.
    NotPaired { peer: PeerId },
    /// This machine's trust in the peer was withdrawn; a person must restore it.
    Withdrawn { peer: PeerId },
    /// The peer's trust is not withdrawn and the return's default has already acted
    /// for the pair, so the return is over.
    NotWithdrawn { peer: PeerId },
    /// The write was refused before it changed anything; the log has the reason.
    Write(WriteRefusal),
    /// There is no such right on file to withdraw.
    NoSuchRight { pair: Pair, capability: Capability },
}

impl fmt::Display for RightsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Record(error) => write!(f, "{error}"),
            Self::Audit(error) => write!(f, "{error}"),
            Self::NotPaired { peer } => write!(
                f,
                "{peer:?} is not paired on this machine, so it has no connection level"
            ),
            Self::Withdrawn { peer } => write!(
                f,
                "this machine's trust in {peer:?} is withdrawn; a person must restore it first"
            ),
            Self::NotWithdrawn { peer } => write!(
                f,
                "this machine's trust in {peer:?} is not withdrawn, and the return's default already acted for the pair"
            ),
            Self::Write(refusal) => write!(f, "{refusal}"),
            Self::NoSuchRight { pair, capability } => write!(
                f,
                "{:?} holds no `{capability}` right for `{}`",
                pair.peer(),
                pair.assistant()
            ),
        }
    }
}

impl std::error::Error for RightsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Record(error) => Some(error),
            Self::Audit(error) => Some(error),
            Self::NotPaired { .. }
            | Self::Withdrawn { .. }
            | Self::NotWithdrawn { .. }
            | Self::Write(_)
            | Self::NoSuchRight { .. } => None,
        }
    }
}

impl From<RecordError> for RightsError {
    fn from(error: RecordError) -> Self {
        Self::Record(error)
    }
}

impl From<AuditError> for RightsError {
    fn from(error: AuditError) -> Self {
        Self::Audit(error)
    }
}

impl From<WriteRefusal> for RightsError {
    fn from(refusal: WriteRefusal) -> Self {
        Self::Write(refusal)
    }
}
