//! The second level of the peer record: the connection, the pair and the rights.
//!
//! # Two levels
//!
//! A peer record has a machine level and a connection level. The machine level is
//! [`crate::peer::record`]'s: the key, the pairing, the address, the trust. This
//! module is the connection level's vocabulary: which account on which instance a
//! machine is connected to, which assistant it is bound to, the claim the other
//! side's decision left here, the four capabilities, the rights this machine holds
//! for the pair, and the moments that decide them. The record stores them in the
//! same per-peer file; [`crate::peer::rights`] is the decision and
//! [`crate::peer::audit`] is the record of it.
//!
//! # The pair
//!
//! The unit is a machine together with the assistant it is connected to. A right
//! belongs to that pair and to no other, so a machine moved to another assistant
//! starts with the new pair's rights and never inherits the previous pair's. The
//! assistant a machine is connected to is decided by the machine it is connected
//! to, and only that machine's binding decides it; the other side is shown a
//! [`Claim`], which names the pair for its own person and grants nothing.
//!
//! The plan's guest rule is the default's own shape: one capability, "write to me",
//! for every assistant, so a guest is never defaulted "work on me" or "see the
//! screen". Which assistant the product calls a guest therefore changes no decision
//! here, and the crate keeps the assistant's name without the declaration; see
//! [`Binding`].
//!
//! # Labels
//!
//! An account, an instance, an assistant and a person are labels the product
//! supplies, in its own words. The crate never invents one, never derives one from
//! a key, and never reads an account label to decide anything: a peer's name is its
//! key, and a key never becomes an account name. A label is 1 to
//! [`MAX_LABEL_BYTES`] bytes of UTF-8, not only whitespace, and holds nothing that
//! would break or reorder the line a person reads it on: no control character, no
//! line or paragraph separator, no direction mark.
//!
//! # The four capabilities
//!
//! Write to me, take files from me, work on me, see the screen. The list is closed: a
//! capability that is not one of the four is never satisfied by anything. "See the
//! screen" is one capability covering both watching and acting. A right stored by a
//! newer build for a capability this build does not know is kept and written back
//! untouched, and no question this build can ask matches it.
//!
//! # What is not here
//!
//! The plan's scope field. No capability yet names a resource it would narrow, and
//! an invented vocabulary would fix a permanent format on a guess; the record is
//! additive, so the field arrives as its own tag when the first capability needs
//! it, and nothing written before it has to be unmade. A later field is a new tag of
//! the record, never a longer body: a binding or a right body this build cannot read
//! whole is a refusal, so a body's shape is fixed once and grows only outside.

use std::fmt;

use crate::identity::PeerId;
use crate::peer::record::Timestamp;
use crate::peer::tlv;

/// The most bytes a label may have.
///
/// Bounded so a peer cannot grow a record with one field, and so a label shown to a
/// person stays a label. A hundred and twenty-eight bytes is far more than any
/// account, instance or assistant name the product supplies.
pub const MAX_LABEL_BYTES: usize = 128;

/// The bytes a [`Fact`] opens with. Its version and fields are stated where it is
/// encoded, below.
const FACT_MAGIC: &[u8] = b"mahbot-peer-binding";

/// The fact format this build writes. A fact of a higher version is read as this
/// version's prefix: its known fields are read and its unknown ones are ignored,
/// because a fact is never rewritten by the receiver.
const FACT_VERSION: u8 = 1;

/// The fact's field tags. Unknown tags are ignored, not refused.
mod fact_tag {
    pub const ACCOUNT: u8 = 0x01;
    pub const INSTANCE: u8 = 0x02;
    pub const ASSISTANT: u8 = 0x03;
    pub const DECIDED_AT: u8 = 0x04;
}

/// Why a label is not one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LabelError {
    /// The label is empty or holds only whitespace. A name that names nothing a
    /// person can see cannot be shown as one.
    Empty,
    /// The label is longer than [`MAX_LABEL_BYTES`].
    TooLong { bytes: usize },
    /// The label holds a character that would break or reorder the line a person
    /// reads it on: a control character, a line or paragraph separator, or a
    /// direction mark.
    Control,
}

/// Whether `character` would break or reorder the line a label is shown on: a
/// control character, a line or paragraph separator, or a direction mark — including
/// the Arabic letter mark, which reorders a line exactly as the right-to-left mark
/// does.
fn breaks_a_line(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

impl fmt::Display for LabelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("a label cannot be empty or only whitespace"),
            Self::TooLong { bytes } => {
                write!(
                    f,
                    "a label of {bytes} bytes is longer than {MAX_LABEL_BYTES}"
                )
            }
            Self::Control => {
                f.write_str("a label cannot hold a character that breaks or reorders the line")
            }
        }
    }
}

impl std::error::Error for LabelError {}

/// A name the product supplies: an account, an instance, an assistant or a person.
///
/// Constructed only through [`Label::new`], so a label that reaches a record or a
/// wire fact is one a person can be shown: not blank, not oversized, and nothing in
/// it that would break or reorder the line it is shown on.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Label(String);

impl Label {
    /// Read a label, refusing one that is empty or only whitespace, oversized, or
    /// carrying a character that breaks or reorders a line.
    pub fn new(text: &str) -> Result<Self, LabelError> {
        if text.trim().is_empty() {
            return Err(LabelError::Empty);
        }
        if text.len() > MAX_LABEL_BYTES {
            return Err(LabelError::TooLong { bytes: text.len() });
        }
        if text.chars().any(breaks_a_line) {
            return Err(LabelError::Control);
        }
        Ok(Self(text.to_owned()))
    }

    /// The label's text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The label's bytes, as a record and a wire fact carry them.
    pub(crate) fn encode_into(&self, bytes: &mut Vec<u8>) {
        let length = u16::try_from(self.0.len()).expect("a label is at most 128 bytes");
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(self.0.as_bytes());
    }

    /// Read one `[len u16][bytes]` label, answering it and the rest.
    pub(crate) fn decode_from(bytes: &[u8]) -> Result<(Self, &[u8]), String> {
        let (length, rest) = bytes
            .split_first_chunk::<2>()
            .ok_or_else(|| "has no label length".to_owned())?;
        let length = usize::from(u16::from_be_bytes(*length));
        let (text, rest) = rest
            .split_at_checked(length)
            .ok_or_else(|| "a label runs past the end".to_owned())?;
        let text = std::str::from_utf8(text).map_err(|_| "a label is not UTF-8".to_owned())?;
        let label = Self::new(text).map_err(|error| error.to_string())?;
        Ok((label, rest))
    }

    /// Read one label that must be the whole field it sits in.
    ///
    /// Bytes after the value are not this build's shape of the field, so they are
    /// refused rather than read as the value's prefix: a field's shape is fixed once,
    /// and a longer body is a newer build's field, not this one's.
    pub(crate) fn decode_whole(bytes: &[u8]) -> Result<Self, String> {
        let (label, rest) = Self::decode_from(bytes)?;
        if rest.is_empty() {
            Ok(label)
        } else {
            Err("has bytes after its label".to_owned())
        }
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Define a role's label: the product's own word for one role, kept a distinct type so
/// an account cannot be passed where an instance is meant. The crate never reads one to
/// decide anything; a role label is shown, and nothing else. The first argument names
/// the role in the accessors' docs.
macro_rules! label_role {
    ($role:literal, $(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Label);

        impl $name {
            #[doc = concat!("Read the ", $role, " label.")]
            pub fn new(text: &str) -> Result<Self, LabelError> {
                Label::new(text).map(Self)
            }

            #[doc = concat!("The ", $role, " label.")]
            #[must_use]
            pub fn label(&self) -> &Label {
                &self.0
            }

            /// Wrap a label this crate has already validated.
            pub(crate) const fn from_label(label: Label) -> Self {
                Self(label)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}

label_role! {
    "account",
    /// The account on an instance, as the deciding machine names it.
    Account
}

label_role! {
    "instance",
    /// The instance the account lives on, as the deciding machine names it.
    Instance
}

label_role! {
    "person",
    /// A person on this machine, as the product names them.
    ///
    /// The crate never invents one: a person is the product's fact, and the record
    /// carries the product's own words for who acted.
    PersonName
}

/// One machine and the assistant it is connected to: the unit a right belongs to.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Pair {
    peer: PeerId,
    assistant: Label,
}

impl Pair {
    /// The pair of `peer` and the assistant the product names.
    #[must_use]
    pub fn new(peer: PeerId, assistant: &Label) -> Self {
        Self {
            peer,
            assistant: assistant.clone(),
        }
    }

    /// The pair the binding names.
    #[must_use]
    pub fn of_binding(peer: PeerId, binding: &Binding) -> Self {
        Self::new(peer, binding.fact().assistant())
    }

    /// The pair the claim names.
    ///
    /// A claim names the pair for this machine's own person and grants nothing: the
    /// rights it selects are this machine's, and the other side's word is what
    /// labelled them, not what allowed them.
    #[must_use]
    pub fn of_claim(claim: &Claim) -> Self {
        Self {
            peer: claim.peer,
            assistant: claim.fact.assistant.clone(),
        }
    }

    /// The pair a record's fields name, for a decoder that read them apart.
    pub(crate) const fn from_parts(peer: PeerId, assistant: Label) -> Self {
        Self { peer, assistant }
    }

    /// The machine.
    #[must_use]
    pub const fn peer(&self) -> &PeerId {
        &self.peer
    }

    /// The assistant's name.
    #[must_use]
    pub const fn assistant(&self) -> &Label {
        &self.assistant
    }
}

/// The four capabilities, as a closed list.
///
/// A value outside the list exists only in a right a newer build wrote: it is kept
/// in the record and never matches a question, so a name that is not one of the four
/// is satisfied by nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Capability(u8);

impl Capability {
    /// Write to me: a message addressed to this machine's assistant.
    pub const WRITE: Self = Self(1);
    /// Take files from me.
    pub const TAKE_FILES: Self = Self(2);
    /// Work on me: run a tool, act on this machine.
    pub const WORK: Self = Self(3);
    /// See the screen: one capability covering watching and acting.
    pub const SEE_SCREEN: Self = Self(4);

    /// The capability with this byte, when it is one of the four.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        if byte >= Self::WRITE.0 && byte <= Self::SEE_SCREEN.0 {
            Some(Self(byte))
        } else {
            None
        }
    }

    /// The byte a record carries.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self.0
    }

    /// The capability a stored byte names, known or not.
    ///
    /// Only a decoder uses this: a right or an audit entry a newer build wrote for a
    /// capability this build does not know is kept and shown as "capability N", and no
    /// question this build can ask matches it.
    pub(crate) const fn from_raw(byte: u8) -> Self {
        Self(byte)
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::WRITE => f.write_str("write to me"),
            Self::TAKE_FILES => f.write_str("take files from me"),
            Self::WORK => f.write_str("work on me"),
            Self::SEE_SCREEN => f.write_str("see the screen"),
            Self(byte) => write!(f, "capability {byte}"),
        }
    }
}

/// What issued a right: this machine's default policy, or a person on this machine.
///
/// Nothing else can. A row attributed to a peer is refused when it is written; see
/// [`Authority`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Issuer {
    /// The default: one act at a pair's coming-into-being, and the return from a
    /// withdrawn trust.
    Default,
    /// A person on this machine, named by the product.
    Person(PersonName),
}

impl fmt::Display for Issuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => f.write_str("the default"),
            Self::Person(person) => write!(f, "{person}"),
        }
    }
}

/// Whose authority a write to the rights claims.
///
/// The product hands in who asked, so the crate can refuse the one source that is
/// never a source: a peer, or any other machine. The refusal is recorded, because a
/// peer trying to grant itself a right is a fact worth keeping. The default is not
/// here: its one act per pair is the pair's coming-into-being and the return from a
/// withdrawn trust, and neither is a write a caller asks for — see
/// [`crate::peer::rights::Rights::on_acquaintance`] and
/// [`crate::peer::rights::Rights::restore_trust`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Authority {
    /// A person on this machine.
    Person(PersonName),
    /// A peer on the other side of a connection. Never a source of rights.
    Peer(PeerId),
}

/// How a right stands at a moment, with the moment that decided it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// The right holds: it was issued, not withdrawn, and its term has not passed.
    Live,
    /// A person withdrew it at this moment.
    Withdrawn(Timestamp),
    /// Its term ended at this moment. The moment is the term's end, never when this
    /// machine noticed it, so one ending reads the same however often it is asked.
    Ended(Timestamp),
}

/// A right's term: when it ends, and when this machine recorded the ending.
///
/// The two are one value because an ending is only ever a term's: a right with no
/// term cannot name one, so no reader has to invent a moment for a shape that cannot
/// exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Term {
    end: Timestamp,
    ended_at: Option<Timestamp>,
}

/// One right: a capability, the pair it belongs to, its term, who issued it, and
/// the two ways it stops.
///
/// The plan's row also names a scope; see the module docs on why it waits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Right {
    assistant: Label,
    capability: Capability,
    term: Option<Term>,
    issuer: Issuer,
    withdrawn_at: Option<Timestamp>,
}

impl Right {
    /// A right as a write builds it. The record's store is the only caller that
    /// publishes one, and [`crate::peer::rights`] is the only caller of the store.
    pub(crate) fn new(
        assistant: Label,
        capability: Capability,
        expires_at: Option<Timestamp>,
        issuer: Issuer,
    ) -> Self {
        Self {
            assistant,
            capability,
            term: expires_at.map(|end| Term {
                end,
                ended_at: None,
            }),
            issuer,
            withdrawn_at: None,
        }
    }

    /// The assistant's name.
    #[must_use]
    pub const fn assistant(&self) -> &Label {
        &self.assistant
    }

    /// The capability.
    #[must_use]
    pub const fn capability(&self) -> Capability {
        self.capability
    }

    /// When the right's term passes, if it was given one.
    #[must_use]
    pub const fn expires_at(&self) -> Option<Timestamp> {
        match self.term {
            Some(term) => Some(term.end),
            None => None,
        }
    }

    /// Who issued the right.
    #[must_use]
    pub const fn issuer(&self) -> &Issuer {
        &self.issuer
    }

    /// When a person withdrew it, if they did.
    #[must_use]
    pub const fn withdrawn_at(&self) -> Option<Timestamp> {
        self.withdrawn_at
    }

    /// When the ending was recorded, if it was. Only a right with a term has one.
    #[must_use]
    pub const fn ended_at(&self) -> Option<Timestamp> {
        match self.term {
            Some(term) => term.ended_at,
            None => None,
        }
    }

    /// How the right stands at `now`, with the moment that decided it. A withdrawal is
    /// reported before a term that passed while it was already withdrawn: both stop it,
    /// and the person's act is the one that explains why. An ending reports the term's
    /// end, never when this machine noticed it.
    #[must_use]
    pub fn standing(&self, now: Timestamp) -> Standing {
        if let Some(at) = self.withdrawn_at {
            return Standing::Withdrawn(at);
        }
        match self.term {
            Some(term) if term.ended_at.is_some() || now >= term.end => Standing::Ended(term.end),
            _ => Standing::Live,
        }
    }

    /// The same right, withdrawn at `at`.
    pub(crate) fn withdrawn(mut self, at: Timestamp) -> Self {
        self.withdrawn_at = Some(at);
        self
    }

    /// The same right, with its term's ending recorded at `at`.
    pub(crate) fn ended(mut self, at: Timestamp) -> Self {
        self.term = self.term.map(|term| Term {
            ended_at: Some(at),
            ..term
        });
        self
    }

    /// The same right after a person's grant: no withdrawal, no recorded ending,
    /// the term the grant names, and the person as its issuer. A live row is widened
    /// and a stopped one restored by the same act; the grant kind says which it was.
    pub(crate) fn regranted(mut self, expires_at: Option<Timestamp>, issuer: Issuer) -> Self {
        self.term = expires_at.map(|end| Term {
            end,
            ended_at: None,
        });
        self.issuer = issuer;
        self.withdrawn_at = None;
        self
    }

    /// The body of the record's right field.
    pub(crate) fn encode_body(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(32);
        body.push(self.capability.as_byte());
        self.assistant.encode_into(&mut body);
        put_moment(&mut body, self.expires_at());
        match &self.issuer {
            Issuer::Default => body.push(1),
            Issuer::Person(person) => {
                body.push(2);
                person.label().encode_into(&mut body);
            }
        }
        put_moment(&mut body, self.withdrawn_at);
        put_moment(&mut body, self.ended_at());
        body
    }

    /// Read a right's body. A capability this build does not know is not a
    /// malformation: the record keeps the field and nothing satisfies it, so
    /// `Ok(None)` answers "keep it untouched".
    pub(crate) fn decode_body(body: &[u8]) -> Result<Option<Self>, String> {
        let (capability, rest) = body
            .split_first()
            .ok_or_else(|| "names no capability".to_owned())?;
        if *capability == 0 {
            return Err("names no capability".to_owned());
        }
        let (assistant, rest) = Label::decode_from(rest)?;
        let (expires_at, rest) = take_moment(rest)?;
        let (&kind, rest) = rest
            .split_first()
            .ok_or_else(|| "names no issuer".to_owned())?;
        let (issuer, rest) = match kind {
            1 => (Issuer::Default, rest),
            2 => {
                let (name, rest) = Label::decode_from(rest)?;
                (Issuer::Person(PersonName::from_label(name)), rest)
            }
            other => return Err(format!("has issuer kind {other}")),
        };
        let (withdrawn_at, rest) = take_moment(rest)?;
        let (ended_at, rest) = take_moment(rest)?;
        if !rest.is_empty() {
            return Err("has bytes after the right".to_owned());
        }
        let Some(capability) = Capability::from_byte(*capability) else {
            return Ok(None);
        };
        // An ending is what a term does: a row that names one and no term cannot be
        // read, so the moment an ended right reports is always the term's end. The
        // check follows the capability so that a newer build's row for a capability
        // this build does not know is kept untouched, shape and all.
        let term = match expires_at {
            Some(end) => Some(Term { end, ended_at }),
            None if ended_at.is_none() => None,
            None => return Err("names an ending with no term".to_owned()),
        };
        Ok(Some(Self {
            assistant,
            capability,
            term,
            issuer,
            withdrawn_at,
        }))
    }
}

/// Append `[present u8][moment u64]`.
fn put_moment(bytes: &mut Vec<u8>, moment: Option<Timestamp>) {
    match moment {
        Some(moment) => {
            bytes.push(1);
            bytes.extend_from_slice(&moment.unix_seconds().to_be_bytes());
        }
        None => bytes.push(0),
    }
}

/// Read `[present u8][moment u64]`.
fn take_moment(bytes: &[u8]) -> Result<(Option<Timestamp>, &[u8]), String> {
    let (&present, rest) = bytes
        .split_first()
        .ok_or_else(|| "has no moment".to_owned())?;
    match present {
        0 => Ok((None, rest)),
        1 => {
            let (seconds, rest) = rest
                .split_first_chunk::<8>()
                .ok_or_else(|| "has a moment shorter than eight bytes".to_owned())?;
            Ok((
                Some(Timestamp::from_unix_seconds(u64::from_be_bytes(*seconds))),
                rest,
            ))
        }
        other => Err(format!("has moment presence {other}")),
    }
}

/// The connection level as the deciding machine recorded it: the account on the
/// instance, the assistant it bound the machine to, and when it decided.
///
/// The binding is this machine's own decision, and it is exactly the [`Fact`] that
/// travels: one field set, one encoder, one decoder, and the record's body is the
/// fact's bytes. What the other side receives is a [`Claim`] — never authority. Its
/// fields are [`Fact`]'s, reached through [`Self::fact`], the way a [`Claim`]'s are.
///
/// The guest declaration the product makes about an assistant is not part of it;
/// [`Fact`] says why, and no decision reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    fact: Fact,
}

impl Binding {
    /// The binding a person on the deciding machine made.
    #[must_use]
    pub const fn new(
        account: Account,
        instance: Instance,
        assistant: Label,
        decided_at: Timestamp,
    ) -> Self {
        Self {
            fact: Fact {
                account,
                instance,
                assistant,
                decided_at,
            },
        }
    }

    /// The fact the other side is shown: the binding as it travels.
    #[must_use]
    pub const fn fact(&self) -> &Fact {
        &self.fact
    }

    /// The body of the record's binding field: the fact's own bytes.
    pub(crate) fn encode_body(&self) -> Result<Vec<u8>, String> {
        self.fact.encode().map_err(|error| error.to_string())
    }

    /// Read a binding's body.
    pub(crate) fn decode_body(body: &[u8]) -> Result<Self, String> {
        Fact::decode(body)
            .map(|fact| Self { fact })
            .map_err(|error| error.to_string())
    }
}

/// What the other side's decision says, as this machine keeps it.
///
/// A claim names the pair for this machine's person and grants nothing: nothing is
/// allowed because another machine said so. The crate never reads it to decide. The
/// machine it came from is the record's own peer, and [`Pair::of_claim`] is the one
/// reader of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    peer: PeerId,
    fact: Fact,
}

impl Claim {
    /// The fact the deciding machine sent, as this build read it.
    ///
    /// A claim is a fact and nothing else: the account, the instance, the assistant and
    /// the moment are [`Fact`]'s, and this type adds only the machine it came from.
    #[must_use]
    pub const fn fact(&self) -> &Fact {
        &self.fact
    }
}

/// The binding as it travels: the connection level's small, versioned fact.
///
/// # The bytes
///
/// `mahbot-peer-binding`, one version byte, then `[tag][len u16 big-endian][body]`
/// fields: `0x01` the account label, `0x02` the instance label, `0x03` the
/// assistant's name, `0x04` the decision moment (8, seconds). A label is
/// `[len u16][bytes]`. A version above this build's is read as this version's prefix
/// and its unknown tags are ignored.
///
/// # What a newer build's fields are worth
///
/// The two sides keep this differently. The receiver keeps the bytes it was sent
/// verbatim — a [`Claim`] — so a field this build does not know survives there
/// untouched. The deciding machine keeps its own decision as a [`Binding`], and rewrites
/// it from the fields it knows on every record publish, so a field a newer build added
/// to a binding is dropped by an older build that rewrites that record. That is the
/// price of the binding being this machine's own words; a field that must survive a
/// rewrite is a new *record* tag, which the record keeps as an unknown field.
///
/// The guest declaration the product makes about an assistant is not in it: who is a
/// guest is a property of the assistant on the machine that decided, and no peer may
/// state it. It changes no decision either — the default issues one capability, "write
/// to me", for every assistant, which is the plan's guest floor, and a person may widen
/// it explicitly. Storing a declaration nothing reads would freeze it in a permanent
/// body; the formats are additive, so it arrives when a decision depends on it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fact {
    account: Account,
    instance: Instance,
    assistant: Label,
    decided_at: Timestamp,
}

impl Fact {
    /// The fact's bytes.
    ///
    /// The refusal is unreachable — every field body is a label of at most
    /// [`MAX_LABEL_BYTES`] plus its length, or a moment — but it is a refusal and not
    /// a panic, so a field that grew past what a `u16` length can name would be
    /// reported rather than taken down with the process.
    pub fn encode(&self) -> Result<Vec<u8>, FactError> {
        let mut bytes = Vec::with_capacity(32);
        bytes.extend_from_slice(FACT_MAGIC);
        bytes.push(FACT_VERSION);
        let mut body = Vec::new();
        self.account.label().encode_into(&mut body);
        put_fact_field(&mut bytes, fact_tag::ACCOUNT, &body)?;
        let mut body = Vec::new();
        self.instance.label().encode_into(&mut body);
        put_fact_field(&mut bytes, fact_tag::INSTANCE, &body)?;
        let mut body = Vec::new();
        self.assistant.encode_into(&mut body);
        put_fact_field(&mut bytes, fact_tag::ASSISTANT, &body)?;
        put_fact_field(
            &mut bytes,
            fact_tag::DECIDED_AT,
            &self.decided_at.unix_seconds().to_be_bytes(),
        )?;
        Ok(bytes)
    }

    /// Read a fact. A missing field, a bad label, a field with bytes after its value
    /// or a version of zero is a refusal; a higher version is this build's prefix.
    pub fn decode(bytes: &[u8]) -> Result<Self, FactError> {
        let rest = bytes.strip_prefix(FACT_MAGIC).ok_or(FactError::Magic)?;
        let (&version, rest) = rest.split_first().ok_or(FactError::Magic)?;
        if version == 0 {
            return Err(FactError::Version { found: version });
        }
        let mut account = None;
        let mut instance = None;
        let mut assistant = None;
        let mut decided_at = None;
        for field in tlv::Fields::new(rest) {
            let (tag, body) = field.map_err(|error| FactError::Field {
                tag: error.tag,
                detail: error.detail.to_owned(),
            })?;
            match tag {
                fact_tag::ACCOUNT => account = Some(Account::from_label(read_label(tag, body)?)),
                fact_tag::INSTANCE => instance = Some(Instance::from_label(read_label(tag, body)?)),
                fact_tag::ASSISTANT => assistant = Some(read_label(tag, body)?),
                fact_tag::DECIDED_AT => {
                    let seconds: [u8; 8] = body.try_into().map_err(|_| FactError::Field {
                        tag,
                        detail: "is not eight bytes".to_owned(),
                    })?;
                    decided_at = Some(Timestamp::from_unix_seconds(u64::from_be_bytes(seconds)));
                }
                _ => {}
            }
        }
        Ok(Self {
            account: account.ok_or(FactError::Missing { field: "account" })?,
            instance: instance.ok_or(FactError::Missing { field: "instance" })?,
            assistant: assistant.ok_or(FactError::Missing { field: "assistant" })?,
            decided_at: decided_at.ok_or(FactError::Missing {
                field: "decision moment",
            })?,
        })
    }

    /// The account label.
    #[must_use]
    pub const fn account(&self) -> &Account {
        &self.account
    }

    /// The instance label.
    #[must_use]
    pub const fn instance(&self) -> &Instance {
        &self.instance
    }

    /// The assistant's name.
    #[must_use]
    pub const fn assistant(&self) -> &Label {
        &self.assistant
    }

    /// When the deciding machine decided.
    #[must_use]
    pub const fn decided_at(&self) -> Timestamp {
        self.decided_at
    }

    /// The claim this fact makes about `peer`.
    pub(crate) fn claim(self, peer: PeerId) -> Claim {
        Claim { peer, fact: self }
    }
}

/// Append one `[tag][len u16][body]` fact field.
fn put_fact_field(bytes: &mut Vec<u8>, tag: u8, body: &[u8]) -> Result<(), FactError> {
    tlv::put(bytes, tag, body).map_err(|error| FactError::Field {
        tag,
        detail: format!("is {} bytes long", error.len),
    })
}

/// Read one label field whole: a value with bytes after it is not this build's shape
/// of the field, so it is refused rather than read as its prefix.
fn read_label(tag: u8, body: &[u8]) -> Result<Label, FactError> {
    Label::decode_whole(body).map_err(|detail| FactError::Field { tag, detail })
}

/// Why a fact could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FactError {
    /// The bytes do not open with the fact magic.
    Magic,
    /// The version byte is zero, which is not a fact.
    Version { found: u8 },
    /// A field is malformed.
    Field { tag: u8, detail: String },
    /// The fact lacks a field this build needs.
    Missing { field: &'static str },
}

impl fmt::Display for FactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Magic => f.write_str("the bytes are not a connection fact"),
            Self::Version { found } => {
                write!(f, "the fact's version byte is {found}, which is not a fact")
            }
            Self::Field { tag, detail } => write!(f, "fact field {tag:#04x} {detail}"),
            Self::Missing { field } => write!(f, "the fact names no {field}"),
        }
    }
}

impl std::error::Error for FactError {}
