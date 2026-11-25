//! The acquaintance ceremony: commit-then-reveal over the beacon, six symbols two
//! people compare, and a record written only after both people confirmed.
//!
//! # The ceremony
//!
//! The side that starts supplies the other machine's fingerprint; the other learns
//! who is calling from the signed introduction it receives. Their addresses and
//! their fresh exchange values travel in the payload the beacon relays. The
//! initiator commits to its fresh value first; the responder sends its own value
//! before it sees the initiator's; the initiator then reveals, bound by its
//! commitment. So neither side can steer the result by choosing its value after
//! seeing the other's, and an intermediary gets one guess per comparison. Both then
//! derive the same six symbols from the whole transcript — both keys and both fresh
//! values — and a person compares them on the two machines. The string is a check,
//! not a secret: the beacon can compute it from what it relays, and what it must
//! never do is carry or store it.
//!
//! The flights, in order:
//!
//! 1. the initiator's commitment;
//! 2. the responder's fresh value, bound to that commitment;
//! 3. the initiator's fresh value, checked against its commitment;
//! 4. the initiator's confirmation;
//! 5. the responder's confirmation.
//!
//! Every flight is an introduction the sender signed, and the receiver refuses one
//! whose signature does not verify; the beacon can neither alter nor re-attribute a
//! flight. What it can do is replay an old one: the answer is bound to the
//! initiator's commitment, the reveal is checked against that commitment, and both
//! confirmations carry a value derived from this attempt's transcript. A replayed
//! flight does not match what it is checked against, and the state machine refuses
//! it. An opening is the one flight nothing binds: one that arrives after the opening
//! is either the simultaneous start the fingerprint rule settles or a replay of an
//! attempt that is not this one, which changes nothing. A beacon can stop a pair from
//! forming, but it cannot make a machine record a pairing the other machine did not
//! confirm.
//!
//! A machine writes its record only when its own person confirmed and it has
//! received the other machine's confirmation. Each flight carries whether its
//! sender already holds the pair, so a machine that holds it can say so: if both
//! do, the responder answers "paired" and no comparison is shown; if only one does,
//! both compare again, which is the whole repair rule for a one-sided record.
//!
//! # Both sides starting at once
//!
//! When a machine that started an attempt receives the other machine's opening
//! flight instead of a reply, the attempt of the machine with the smaller
//! fingerprint wins: the smaller one drops the incoming flight and keeps waiting for
//! its reply, and the larger one abandons its own attempt — counting nothing against
//! anybody — and answers the smaller one's. Both compute the same decision, so the
//! people see one comparison, not two. A link that delivers the loser's opening
//! flight late, after the winner has revealed, changes nothing: it is not a flight
//! of the surviving attempt.
//!
//! # What the record holds
//!
//! Nothing about the ceremony is stored except its result: the pairing moment and
//! the attempt's expiry. The comparison is never written, never sent, and never
//! stored by the beacon. An address travels in the flights, but it is a hint the
//! caller may dial; the record learns an address only from an authenticated
//! connection.

use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use crate::beacon::{BeaconError, Introduction, timeout};
use crate::identity::{Fingerprint, Identity, PeerId};
use crate::peer::address;
use crate::peer::presence::{Flights, Presence};
use crate::peer::record::{RecordError, RecordStore, Timestamp};

/// How many symbols two people compare.
pub const COMPARISON_SYMBOLS: usize = 6;

/// The alphabet RFC 4648 base32 uses, minus padding: the six symbols are letters
/// A–Z and digits 2–7.
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The length of one fresh exchange value.
const NONCE_LEN: usize = 32;

/// The length of a commitment to a fresh value, and of every binding derived from
/// an attempt.
const COMMITMENT_LEN: usize = 32;

/// How long one machine-to-machine flight of a ceremony may wait before the
/// attempt is abandoned.
///
/// This is the bound on the cryptographic flights — a commitment, a fresh value —
/// which one machine sends to another. The wait for the other machine's *person*
/// is the attempt's own lifetime instead: a human comparing six symbols may take
/// minutes, and the attempt is what expires. An abandoned attempt counts against
/// nobody; it is left to expire, so a person can start again once its lifetime
/// passes.
pub const PAIR_FLIGHT_TIMEOUT: Duration = Duration::from_secs(30);

/// The domain separator of the transcript, so the six symbols cannot be confused
/// with any other hash of the same keys.
const TRANSCRIPT_DOMAIN: &[u8] = b"mahbot-peers pairing transcript v1";

/// The domain separator of a commitment.
const COMMIT_DOMAIN: &[u8] = b"mahbot-peers pairing commitment v1";

/// The domain separator of the responder's fresh value.
const ANSWER_DOMAIN: &[u8] = b"mahbot-peers pairing answer v1";

/// The domain separator of a confirmation.
const CONFIRM_DOMAIN: &[u8] = b"mahbot-peers pairing confirmation v1";

/// The domain separator of the "already paired" answer.
const PAIRED_DOMAIN: &[u8] = b"mahbot-peers pairing already-paired v1";

/// The payload version every ceremony message carries.
const PAYLOAD_VERSION: u8 = 1;

/// The six symbols two people compare, in RFC 4648's alphabet.
///
/// It is a rendering, not a secret: a value is six characters long, `Display`
/// prints them, and nothing else has a textual form.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Comparison([u8; COMPARISON_SYMBOLS]);

impl Comparison {
    /// The symbols as the bytes `Display` writes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; COMPARISON_SYMBOLS] {
        &self.0
    }

    /// Six symbols from the top thirty bits of a digest, most significant first.
    fn of_digest(digest: &[u8]) -> Self {
        let value = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) >> 2;
        let mut symbols = [0u8; COMPARISON_SYMBOLS];
        for (index, symbol) in symbols.iter_mut().enumerate() {
            let shift = 5 * (COMPARISON_SYMBOLS - 1 - index);
            let slot = u8::try_from((value >> shift) & 0x1f).expect("five bits fit a byte");
            *symbol = ALPHABET[usize::from(slot)];
        }
        Self(symbols)
    }
}

impl fmt::Display for Comparison {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for symbol in self.0 {
            write!(f, "{}", char::from(symbol))?;
        }
        Ok(())
    }
}

impl fmt::Debug for Comparison {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Which side of one ceremony a machine plays.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// This machine supplied the peer's fingerprint and sent the first flight.
    Initiator,
    /// This machine learned who was calling from the introduction it received.
    Responder,
}

/// One ceremony message, as the beacon relays it.
///
/// The type is the schema: the body is one of a closed set, each with the exact
/// bytes its kind carries. There is no field for the comparison, so no message can
/// carry one.
#[derive(Clone, PartialEq, Eq, Debug)]
struct Message {
    already_paired: bool,
    address: Option<SocketAddr>,
    body: Body,
}

/// The closed set of ceremony bodies, and the bytes each carries.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Body {
    /// The initiator's commitment to its fresh value.
    Commitment([u8; COMMITMENT_LEN]),
    /// The responder's fresh value, bound to the initiator's commitment so a
    /// replayed value from an earlier attempt does not match.
    Answer {
        nonce: [u8; NONCE_LEN],
        binding: [u8; COMMITMENT_LEN],
    },
    /// The initiator's fresh value; the responder checks it against the commitment.
    Nonce([u8; NONCE_LEN]),
    /// One side's confirmation, bound to this attempt's transcript.
    Confirmation {
        accepted: bool,
        binding: [u8; COMMITMENT_LEN],
    },
    /// Both sides already hold the pair, bound to the initiator's commitment.
    Paired { binding: [u8; COMMITMENT_LEN] },
}

/// The wire kind of each body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Commit,
    Answer,
    Reveal,
    Confirm,
    Paired,
}

impl Kind {
    const fn byte(self) -> u8 {
        match self {
            Self::Commit => 0x01,
            Self::Answer => 0x02,
            Self::Reveal => 0x03,
            Self::Confirm => 0x04,
            Self::Paired => 0x05,
        }
    }

    const fn of(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Commit),
            0x02 => Some(Self::Answer),
            0x03 => Some(Self::Reveal),
            0x04 => Some(Self::Confirm),
            0x05 => Some(Self::Paired),
            _ => None,
        }
    }
}

impl Body {
    const fn kind(&self) -> Kind {
        match self {
            Self::Commitment(_) => Kind::Commit,
            Self::Answer { .. } => Kind::Answer,
            Self::Nonce(_) => Kind::Reveal,
            Self::Confirmation { .. } => Kind::Confirm,
            Self::Paired { .. } => Kind::Paired,
        }
    }

    fn encode_into(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Commitment(commitment) => bytes.extend_from_slice(commitment),
            Self::Answer { nonce, binding } => {
                bytes.extend_from_slice(nonce);
                bytes.extend_from_slice(binding);
            }
            Self::Nonce(nonce) => bytes.extend_from_slice(nonce),
            Self::Confirmation { accepted, binding } => {
                bytes.push(u8::from(*accepted));
                bytes.extend_from_slice(binding);
            }
            Self::Paired { binding } => bytes.extend_from_slice(binding),
        }
    }
}

/// Whether a flight can start a ceremony: only an opening does, so only an opening is worth
/// holding for a person who has not started yet.
pub(crate) fn opens_a_ceremony(payload: &[u8]) -> bool {
    matches!(Message::parse(payload), Ok(message) if message.kind() == Kind::Commit)
}

/// Whether a flight's sender waits for the attempt's own lifetime rather than for one machine
/// flight: a confirmation does, because the peer's person may still be comparing the same string.
pub(crate) fn waits_for_the_attempt(payload: &[u8]) -> bool {
    matches!(Message::parse(payload), Ok(message) if message.kind() == Kind::Confirm)
}

impl Message {
    /// Read a message, refusing anything the closed set does not produce.
    fn parse(bytes: &[u8]) -> Result<Self, PairError> {
        let (&version, rest) = bytes
            .split_first()
            .ok_or(PairError::Malformed("the message is empty"))?;
        if version != PAYLOAD_VERSION {
            return Err(PairError::Malformed("the message version is not this one"));
        }
        let (&kind, rest) = rest
            .split_first()
            .ok_or(PairError::Malformed("the message has no kind"))?;
        let kind = Kind::of(kind).ok_or(PairError::Malformed("the kind is not in the set"))?;
        let (&flags, rest) = rest
            .split_first()
            .ok_or(PairError::Malformed("the message has no flags"))?;
        let (address, body) = address::decode(rest)
            .ok_or(PairError::Malformed("the message has no address field"))?;
        let body = match kind {
            Kind::Commit => Body::Commitment(array(body, "the commitment is not 32 bytes")?),
            Kind::Answer => {
                let nonce = body
                    .get(..NONCE_LEN)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or(PairError::Malformed("the fresh value is not 32 bytes"))?;
                let binding = body
                    .get(NONCE_LEN..)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or(PairError::Malformed("the binding is not 32 bytes"))?;
                Body::Answer { nonce, binding }
            }
            Kind::Reveal => Body::Nonce(array(body, "the fresh value is not 32 bytes")?),
            Kind::Confirm => {
                let (&accepted, binding) = body
                    .split_first()
                    .ok_or(PairError::Malformed("the confirmation has no bit"))?;
                Body::Confirmation {
                    accepted: accepted != 0,
                    binding: array(binding, "the confirmation binding is not 32 bytes")?,
                }
            }
            Kind::Paired => Body::Paired {
                binding: array(body, "the paired binding is not 32 bytes")?,
            },
        };
        Ok(Self {
            already_paired: flags & 1 != 0,
            address,
            body,
        })
    }

    /// The message's bytes, as the beacon relays them.
    fn encode(&self) -> Vec<u8> {
        // Version, kind and flag, the longest address (an IPv6 one with flow info
        // and scope), and the longest body (a 32-byte nonce and a 32-byte binding).
        let mut bytes = Vec::with_capacity(3 + 27 + 65);
        bytes.push(PAYLOAD_VERSION);
        bytes.push(self.body.kind().byte());
        bytes.push(u8::from(self.already_paired));
        address::encode(&mut bytes, self.address);
        self.body.encode_into(&mut bytes);
        bytes
    }

    /// What kind of message this is.
    const fn kind(&self) -> Kind {
        self.body.kind()
    }
}

/// Exactly `N` bytes, or a malformed message.
fn array<const N: usize>(bytes: &[u8], detail: &'static str) -> Result<[u8; N], PairError> {
    bytes.try_into().map_err(|_| PairError::Malformed(detail))
}

/// What one turn of the ceremony asks its caller to do.
#[derive(Debug, Default)]
pub struct Turn {
    /// Bytes to hand to the peer.
    pub send: Option<Vec<u8>>,
    /// The string to show a person. The caller answers with
    /// [`Ceremony::confirm`].
    pub show: Option<Comparison>,
    /// The ceremony is over.
    pub outcome: Option<Outcome>,
}

/// How a ceremony ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Both people confirmed: write the pair. `address` is the peer's own address
    /// from its flight — a hint the caller may dial. `role` is the side this machine
    /// played, which tells a simultaneous start which attempt survived.
    Paired {
        peer: PeerId,
        address: Option<SocketAddr>,
        role: Role,
    },
    /// Both sides already held the pair: nothing was compared and nothing written.
    AlreadyPaired { peer: PeerId },
    /// This machine's person rejected the comparison: count one failure.
    Rejected { peer: PeerId },
    /// The other machine's person rejected: count nothing.
    PeerRejected { peer: PeerId },
}

/// One side of one ceremony, as a state machine.
///
/// It holds no I/O: a caller feeds it the peer's payloads and sends what it asks
/// for. [`run`] is the driver that does both over this machine's registration at
/// the beacon; the test rig drives the machine directly when it has to stand
/// between two of them.
pub struct Ceremony {
    me: PeerId,
    peer: PeerId,
    role: Role,
    own_address: Option<SocketAddr>,
    nonce: [u8; NONCE_LEN],
    peer_commitment: Option<[u8; COMMITMENT_LEN]>,
    peer_nonce: Option<[u8; NONCE_LEN]>,
    peer_address: Option<SocketAddr>,
    already_here: bool,
    accepted: Option<bool>,
    peer_accepted: Option<bool>,
    state: State,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// The initiator has sent its commitment and waits for the responder's answer.
    AwaitAnswer,
    /// The responder has sent its fresh value and waits for the initiator's.
    AwaitNonce,
    /// Both fresh values are known; this machine waits for a person and for the
    /// other machine's confirmation.
    AwaitConfirmation,
    /// The ceremony is over.
    Done,
}

impl fmt::Debug for Ceremony {
    /// The nonce is a fresh value, not a secret that outlives the ceremony, but it
    /// has no place in a log either: this prints the shape and not the values.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ceremony")
            .field("me", &self.me)
            .field("peer", &self.peer)
            .field("role", &self.role)
            .field("state", &self.state)
            .field("already_here", &self.already_here)
            .finish_non_exhaustive()
    }
}

impl Ceremony {
    /// Start a ceremony toward `peer`, supplying this machine's own address and
    /// whether it already holds the pair.
    ///
    /// Returns the ceremony and the first flight's bytes.
    pub fn initiate(
        me: PeerId,
        peer: Fingerprint,
        own_address: Option<SocketAddr>,
        already: bool,
    ) -> Result<(Self, Vec<u8>), PairError> {
        let peer = peer.peer_id();
        if peer == me {
            return Err(PairError::OwnIdentity);
        }
        let nonce = random_nonce()?;
        let own_commitment = commitment_of(&nonce);
        let ceremony = Self {
            me,
            peer,
            role: Role::Initiator,
            own_address,
            nonce,
            peer_commitment: None,
            peer_nonce: None,
            peer_address: None,
            already_here: already,
            accepted: None,
            peer_accepted: None,
            state: State::AwaitAnswer,
        };
        let message = Message {
            already_paired: already,
            address: own_address,
            body: Body::Commitment(own_commitment),
        };
        Ok((ceremony, message.encode()))
    }

    /// Answer an introduction that opens a ceremony.
    ///
    /// The peer is the introduction's sender, as its signature proved. When both
    /// sides already hold the pair the answer is "paired" and no comparison is
    /// shown; otherwise it is this machine's fresh value, bound to the initiator's
    /// commitment.
    pub fn respond(
        me: PeerId,
        introduction: &Introduction,
        own_address: Option<SocketAddr>,
        already: bool,
    ) -> Result<(Self, Turn), PairError> {
        Self::answer(
            me,
            introduction,
            &Message::parse(introduction.payload())?,
            own_address,
            already,
        )
    }

    /// Answer an opening flight whose bytes the caller already parsed.
    fn answer(
        me: PeerId,
        introduction: &Introduction,
        message: &Message,
        own_address: Option<SocketAddr>,
        already: bool,
    ) -> Result<(Self, Turn), PairError> {
        if introduction.to() != me {
            return Err(PairError::WrongPeer {
                expected: me,
                got: introduction.to(),
            });
        }
        if introduction.from() == me {
            return Err(PairError::OwnIdentity);
        }
        let Body::Commitment(peer_commitment) = &message.body else {
            return Err(PairError::Malformed(
                "the opening flight is not a commitment",
            ));
        };
        let peer_commitment = *peer_commitment;
        let nonce = random_nonce()?;
        let mut ceremony = Self {
            me,
            peer: introduction.from(),
            role: Role::Responder,
            own_address,
            nonce,
            peer_commitment: Some(peer_commitment),
            peer_nonce: None,
            peer_address: message.address,
            already_here: already,
            accepted: None,
            peer_accepted: None,
            state: State::AwaitNonce,
        };
        if already && message.already_paired {
            ceremony.state = State::Done;
            let paired = Message {
                already_paired: true,
                address: None,
                body: Body::Paired {
                    binding: paired_binding(&peer_commitment),
                },
            };
            let peer = ceremony.peer;
            return Ok((
                ceremony,
                Turn {
                    send: Some(paired.encode()),
                    show: None,
                    outcome: Some(Outcome::AlreadyPaired { peer }),
                },
            ));
        }
        let answer = Message {
            already_paired: already,
            address: own_address,
            body: Body::Answer {
                nonce,
                binding: answer_binding(&peer_commitment, &nonce),
            },
        };
        Ok((
            ceremony,
            Turn {
                send: Some(answer.encode()),
                show: None,
                outcome: None,
            },
        ))
    }

    /// Feed one payload from the peer.
    pub fn receive(&mut self, payload: &[u8]) -> Result<Turn, PairError> {
        self.receive_message(Message::parse(payload)?)
    }

    /// Feed one flight whose bytes the caller already parsed.
    fn receive_message(&mut self, message: Message) -> Result<Turn, PairError> {
        match (self.state, message.body) {
            (State::AwaitAnswer, Body::Paired { binding }) => {
                if !self.already_here {
                    return Err(PairError::NotPaired);
                }
                if binding != paired_binding(&commitment_of(&self.nonce)) {
                    return Err(PairError::BindingMismatch);
                }
                self.state = State::Done;
                Ok(Turn {
                    outcome: Some(Outcome::AlreadyPaired { peer: self.peer }),
                    ..Turn::default()
                })
            }
            (State::AwaitAnswer, Body::Answer { nonce, binding }) => {
                if binding != answer_binding(&commitment_of(&self.nonce), &nonce) {
                    return Err(PairError::BindingMismatch);
                }
                self.peer_nonce = Some(nonce);
                if message.address.is_some() {
                    self.peer_address = message.address;
                }
                self.state = State::AwaitConfirmation;
                let comparison = self.transcript()?;
                let reveal = Message {
                    already_paired: self.already_here,
                    address: None,
                    body: Body::Nonce(self.nonce),
                };
                Ok(Turn {
                    send: Some(reveal.encode()),
                    show: Some(comparison),
                    outcome: None,
                })
            }
            (State::AwaitNonce, Body::Nonce(nonce)) => {
                let commitment = self.peer_commitment.ok_or(PairError::Malformed(
                    "no commitment to check the value against",
                ))?;
                if commitment_of(&nonce) != commitment {
                    return Err(PairError::CommitmentMismatch);
                }
                self.peer_nonce = Some(nonce);
                self.state = State::AwaitConfirmation;
                let comparison = self.transcript()?;
                Ok(Turn {
                    send: None,
                    show: Some(comparison),
                    outcome: None,
                })
            }
            (State::AwaitConfirmation, Body::Confirmation { accepted, binding }) => {
                if binding != confirm_binding(&self.transcript_digest()?, accepted) {
                    return Err(PairError::BindingMismatch);
                }
                self.peer_accepted = Some(accepted);
                let outcome = self.settle();
                Ok(Turn {
                    outcome,
                    ..Turn::default()
                })
            }
            // The peer's opening flight after the opening: a reordered or duplicated
            // flight from a simultaneous start, or a replay. The attempt it opened is
            // not this one, so it changes nothing and must not end the ceremony — a
            // link that delivers it late is not a failed comparison.
            (State::AwaitConfirmation | State::AwaitNonce | State::Done, Body::Commitment(_)) => {
                Ok(Turn::default())
            }
            _ => Err(PairError::OutOfOrder),
        }
    }

    /// Answer the comparison this machine showed its person.
    ///
    /// A rejection is terminal here: it counts one failure, and the other side
    /// counts nothing when it hears it. A confirmation waits for the other side's.
    pub fn confirm(&mut self, accepted: bool) -> Result<Turn, PairError> {
        if self.state != State::AwaitConfirmation {
            return Err(PairError::OutOfOrder);
        }
        self.accepted = Some(accepted);
        let message = Message {
            already_paired: self.already_here,
            address: None,
            body: Body::Confirmation {
                accepted,
                binding: confirm_binding(&self.transcript_digest()?, accepted),
            },
        };
        let outcome = self.settle();
        Ok(Turn {
            send: Some(message.encode()),
            show: None,
            outcome,
        })
    }

    /// This machine's id.
    #[must_use]
    const fn me(&self) -> PeerId {
        self.me
    }

    /// The peer's id.
    #[must_use]
    const fn peer(&self) -> PeerId {
        self.peer
    }

    /// This machine's own address, as it sent it.
    #[must_use]
    const fn own_address(&self) -> Option<SocketAddr> {
        self.own_address
    }

    /// Whether this machine started the ceremony.
    #[must_use]
    const fn started(&self) -> bool {
        matches!(self.role, Role::Initiator)
    }

    /// Whether this machine is still waiting for the reply to its opening flight.
    #[must_use]
    const fn awaits_reply(&self) -> bool {
        matches!(self.state, State::AwaitAnswer)
    }

    /// Whether both fresh values are known and a person's answer is what is left.
    #[must_use]
    const fn awaits_confirmation(&self) -> bool {
        matches!(self.state, State::AwaitConfirmation)
    }

    /// Whether the ceremony is over.
    #[must_use]
    pub const fn finished(&self) -> bool {
        matches!(self.state, State::Done)
    }

    /// The transcript digest: both keys and both fresh values, in fingerprint
    /// order, so both machines hash the same bytes whatever side they play.
    ///
    /// The order is the key order: an ed25519 SPKI is a fixed prefix followed by
    /// the 32-byte key, so ordering the keys orders the fingerprints.
    fn transcript_digest(&self) -> Result<[u8; COMMITMENT_LEN], PairError> {
        let peer_nonce = self
            .peer_nonce
            .ok_or(PairError::Malformed("the peer's fresh value is not known"))?;
        let (low, high, low_nonce, high_nonce) = if self.me < self.peer {
            (self.me, self.peer, &self.nonce, &peer_nonce)
        } else {
            (self.peer, self.me, &peer_nonce, &self.nonce)
        };
        Ok(digest_of(&[
            TRANSCRIPT_DOMAIN,
            low.fingerprint().as_bytes(),
            high.fingerprint().as_bytes(),
            low_nonce,
            high_nonce,
        ]))
    }

    /// The six symbols, once both fresh values are known.
    fn transcript(&self) -> Result<Comparison, PairError> {
        Ok(Comparison::of_digest(&self.transcript_digest()?))
    }

    /// The outcome both answers decide, once both are known.
    fn settle(&mut self) -> Option<Outcome> {
        let accepted = self.accepted;
        let peer = self.peer_accepted;
        let outcome = match (accepted, peer) {
            (Some(false), _) => Some(Outcome::Rejected { peer: self.peer }),
            (Some(true) | None, Some(false)) => Some(Outcome::PeerRejected { peer: self.peer }),
            (Some(true), Some(true)) => Some(Outcome::Paired {
                peer: self.peer,
                address: self.peer_address,
                role: self.role,
            }),
            _ => None,
        };
        if outcome.is_some() {
            self.state = State::Done;
        }
        outcome
    }
}

/// How a machine enters a ceremony.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Opening {
    /// This machine starts, supplying the peer's fingerprint as a person did.
    Initiate(Fingerprint),
    /// This machine waits for an introduction from whoever starts.
    Respond,
}

/// The human comparison, as the ceremony asks it.
///
/// The ceremony awaits the answer, so a person who takes minutes does not block the
/// reactor: a caller with a blocking UI implements this over an async channel. The
/// blanket implementation below is the immediate answer a test or a scripted policy
/// gives.
pub trait Person: Send {
    /// Show the six symbols and answer whether they matched the other machine's.
    fn ask(&mut self, comparison: Comparison) -> impl Future<Output = bool> + Send;
}

impl<F> Person for F
where
    F: FnMut(Comparison) -> bool + Send,
{
    fn ask(&mut self, comparison: Comparison) -> impl Future<Output = bool> + Send {
        std::future::ready(self(comparison))
    }
}

/// Run one ceremony over this machine's registration at the beacon.
///
/// `presence` is the machine's one [`Presence`]: the ceremony neither opens a session of its own
/// nor registers one, because a second registration would displace the machine's and a session
/// nobody reads would take the flights it is waiting for. A flight is delivered to the ceremony
/// for the peer it comes from — this one — and an opening that arrives before this side's
/// person has started is held by the presence, not dropped; any other flight for a peer no
/// ceremony waits on is dropped, because nothing could take it.
///
/// `now` supplies every moment the record needs — the attempt's start and the pairing's —
/// because the library never reads a clock. `person` is the human comparison: it is given the
/// six symbols and answers whether they matched the other machine's. It is awaited, so a person
/// who takes minutes does not block the reactor; a caller with a blocking UI implements
/// [`Person`] over an async channel.
///
/// A machine that starts and receives the other machine's opening flight applies the fingerprint
/// rule: the smaller fingerprint's attempt wins, and the loser's is dropped without counting
/// against anybody.
///
/// A responder waits for the other machine for as long as its person might still start on their
/// side, so this call does not end because nothing has arrived yet, and it never names a cause
/// about the peer: the peer has done nothing the crate observed. A machine whose own registration
/// is not held at the beacon cannot be reached by the other side at all, and says so through
/// [`Presence::state`], which is where a product reads a beacon outage during a ceremony.
pub async fn run<N, P>(
    presence: &Presence,
    me: &Identity,
    opening: Opening,
    store: &RecordStore,
    now: N,
    person: P,
) -> Result<Outcome, PairError>
where
    N: Fn() -> Timestamp,
    P: Person,
{
    let mut person = person;
    let me_id = me.peer_id();
    // The attempt is written once the opening flight is decided: a ceremony that
    // cannot start at all — this machine's own identity, a closed pair — is not an
    // attempt. A flight that then fails ends the attempt, so it blocks no retry.
    let (peer, mut ceremony, first, flights) = match opening {
        Opening::Initiate(peer) => {
            let peer_id = peer.peer_id();
            if peer_id == me_id {
                return Err(PairError::OwnIdentity);
            }
            if store.is_closed(&peer_id) {
                return Err(PairError::Closed { peer: peer_id });
            }
            let already = store.is_paired(&peer_id);
            // The address is a hint the peer may dial, not identity: a beacon that
            // cannot answer it does not stop the ceremony, which fails with a beacon
            // error at its first flight if the beacon is really gone.
            let address = presence.observed_address().await.ok();
            // The claim is taken before the first flight is sent, so the answer cannot arrive
            // before anyone waits for it.
            let flights = presence.flights(peer_id);
            let (ceremony, first) = Ceremony::initiate(me_id, peer, address, already)?;
            (
                peer_id,
                ceremony,
                Turn {
                    send: Some(first),
                    ..Turn::default()
                },
                flights,
            )
        }
        Opening::Respond => {
            let openings = presence.openings();
            loop {
                // Waiting to be paired is the caller's wait: a machine that nobody
                // starts with is not a broken ceremony.
                let introduction = openings.next().await;
                let peer_id = introduction.from();
                if peer_id == me_id {
                    return Err(PairError::OwnIdentity);
                }
                // The presence holds only openings, so this flight can start a ceremony; a
                // peer this machine has closed is the one case it cannot know about, and
                // another machine may still start.
                if store.is_closed(&peer_id) {
                    continue;
                }
                let already = store.is_paired(&peer_id);
                // Best effort, like the initiator's: the answer is a hint, and a beacon
                // that cannot give it has not ended this machine's wait.
                let address = presence.observed_address().await.ok();
                let (ceremony, turn) = Ceremony::respond(me_id, &introduction, address, already)?;
                // From here the ceremony is this peer's: every later flight of it arrives on
                // this handle, and no other peer's does. A flight that arrived while the
                // opening was being answered is in the peer's slot only if a ceremony had
                // already claimed it; otherwise only an opening was held, and this claim takes
                // that in.
                let flights = presence.flights(peer_id);
                break (peer_id, ceremony, turn, flights);
            }
        }
    };
    // An opening that already decides the ceremony — both sides hold the pair —
    // writes no attempt: nothing is being attempted.
    if let Some(outcome) = first.outcome {
        if let Some(bytes) = first.send {
            send(presence, peer, &bytes).await?;
        }
        return finish(store, &now, outcome);
    }
    let attempt = store
        .begin_attempt(&peer, now())
        .map_err(PairError::Record)?;
    let flight = Flight {
        presence,
        store,
        now: &now,
        expires_at: attempt.expires_at,
    };
    let outcome = drive(&mut ceremony, first, peer, &mut person, &flight, &flights).await;
    if outcome.is_err() {
        // The ceremony ended without a comparison: it counts against nobody and
        // must not block a retry. A crash is the case the attempt's expiry is for.
        let _ = store.end_attempt(&peer);
    }
    outcome
}

/// Hand one ceremony flight to the peer.
///
/// The beacon's one answer about a delivery is [`BeaconError::UnknownPeer`], which says what
/// became of the flight and nothing about the peer: it covers both a peer the beacon holds no
/// registration for and a connection that could not take the frame, so a sentence naming either
/// would be a cause this machine did not observe.
async fn send(presence: &Presence, peer: PeerId, bytes: &[u8]) -> Result<(), PairError> {
    presence
        .introduce(peer, bytes)
        .await
        .map_err(PairError::Beacon)
}

/// What the driver and the turn applier share: the machine's presence, the flights it is waiting
/// on, the record, the caller's moment and the instant the attempt stops being one.
struct Flight<'a, N> {
    presence: &'a Presence,
    store: &'a RecordStore,
    now: &'a N,
    expires_at: Timestamp,
}

/// The flights after the opening one, until an outcome or a failure.
///
/// Every wait is measured from the attempt's expiry, never from the moment the last
/// flight arrived: a stranger's introduction, or a peer that keeps sending stale
/// flights, cannot extend the attempt.
async fn drive<N, P>(
    ceremony: &mut Ceremony,
    first: Turn,
    peer: PeerId,
    person: &mut P,
    flight: &Flight<'_, N>,
    flights: &Flights<'_>,
) -> Result<Outcome, PairError>
where
    N: Fn() -> Timestamp,
    P: Person,
{
    if let Some(outcome) = apply(first, ceremony, peer, person, flight).await? {
        return Ok(outcome);
    }
    let now = flight.now;
    let expires_at = flight.expires_at;
    loop {
        // A machine flight waits at most PAIR_FLIGHT_TIMEOUT. A confirmation waits for what is
        // left of the attempt: the peer's own person is comparing the same string, and a slow
        // human is not a dropped link.
        let remaining = expires_at.remaining(now());
        if remaining.is_zero() {
            return Err(PairError::AttemptExpired { peer });
        }
        let bound = if ceremony.awaits_confirmation() {
            remaining
        } else {
            PAIR_FLIGHT_TIMEOUT.min(remaining)
        };
        let Some(introduction) = timeout(&**flight.presence.runtime(), bound, flights.next()).await
        else {
            if now() >= expires_at {
                return Err(PairError::AttemptExpired { peer });
            }
            return Err(PairError::FlightTimeout { peer, after: bound });
        };
        let message = Message::parse(introduction.payload())?;
        // Both sides started at once: the smaller fingerprint's attempt wins.
        if ceremony.started() && ceremony.awaits_reply() && message.kind() == Kind::Commit {
            if ceremony.me() > ceremony.peer() {
                // Ours yields, counting nothing, and answers theirs: the attempt is
                // restarted in one write.
                flight
                    .store
                    .restart_attempt(&peer, now())
                    .map_err(PairError::Record)?;
                let already = flight.store.is_paired(&peer);
                let (responder, turn) = Ceremony::answer(
                    ceremony.me(),
                    &introduction,
                    &message,
                    ceremony.own_address(),
                    already,
                )?;
                *ceremony = responder;
                if let Some(outcome) = apply(turn, ceremony, peer, person, flight).await? {
                    return Ok(outcome);
                }
            }
            // The smaller fingerprint's attempt wins: the incoming one is dropped
            // without counting against anybody, and ours keeps waiting.
            continue;
        }
        let turn = ceremony.receive_message(message)?;
        if let Some(outcome) = apply(turn, ceremony, peer, person, flight).await? {
            return Ok(outcome);
        }
    }
}

/// Send what a turn asks for, show its comparison, and report an outcome.
///
/// The person's answer is awaited against what is left of the attempt, so a person
/// who walks away expires the attempt instead of parking the ceremony for ever.
async fn apply<N, P>(
    turn: Turn,
    ceremony: &mut Ceremony,
    peer: PeerId,
    person: &mut P,
    flight: &Flight<'_, N>,
) -> Result<Option<Outcome>, PairError>
where
    N: Fn() -> Timestamp,
    P: Person,
{
    if let Some(bytes) = turn.send {
        send(flight.presence, peer, &bytes).await?;
    }
    if let Some(comparison) = turn.show {
        let remaining = flight.expires_at.remaining((flight.now)());
        if remaining.is_zero() {
            return Err(PairError::AttemptExpired { peer });
        }
        let Some(accepted) = timeout(
            &**flight.presence.runtime(),
            remaining,
            person.ask(comparison),
        )
        .await
        else {
            return Err(PairError::AttemptExpired { peer });
        };
        let answer = ceremony.confirm(accepted)?;
        if let Some(bytes) = answer.send {
            send(flight.presence, peer, &bytes).await?;
        }
        if let Some(outcome) = answer.outcome {
            return finish(flight.store, flight.now, outcome).map(Some);
        }
    }
    match turn.outcome {
        Some(outcome) => finish(flight.store, flight.now, outcome).map(Some),
        None => Ok(None),
    }
}

/// Record what an outcome means and hand it back.
fn finish<N: Fn() -> Timestamp>(
    store: &RecordStore,
    now: &N,
    outcome: Outcome,
) -> Result<Outcome, PairError> {
    match &outcome {
        Outcome::Paired { peer, .. } => {
            store
                .record_pairing(peer, now())
                .map_err(PairError::Record)?;
        }
        Outcome::Rejected { peer } => {
            store.record_failure(peer).map_err(PairError::Record)?;
        }
        Outcome::AlreadyPaired { peer } | Outcome::PeerRejected { peer } => {
            store.end_attempt(peer).map_err(PairError::Record)?;
        }
    }
    Ok(outcome)
}

/// A fresh exchange value.
fn random_nonce() -> Result<[u8; NONCE_LEN], PairError> {
    let mut nonce = [0u8; NONCE_LEN];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut nonce)
        .map_err(|_| PairError::Entropy)?;
    Ok(nonce)
}

/// The commitment to a fresh value.
fn commitment_of(nonce: &[u8; NONCE_LEN]) -> [u8; COMMITMENT_LEN] {
    digest_of(&[COMMIT_DOMAIN, nonce])
}

/// The responder's binding of its fresh value to the initiator's commitment.
fn answer_binding(
    commitment: &[u8; COMMITMENT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> [u8; COMMITMENT_LEN] {
    digest_of(&[ANSWER_DOMAIN, commitment, nonce])
}

/// A confirmation's binding to this attempt's transcript and its bit.
fn confirm_binding(transcript: &[u8; COMMITMENT_LEN], accepted: bool) -> [u8; COMMITMENT_LEN] {
    digest_of(&[CONFIRM_DOMAIN, transcript, &[u8::from(accepted)]])
}

/// The "already paired" answer's binding to the initiator's commitment.
fn paired_binding(commitment: &[u8; COMMITMENT_LEN]) -> [u8; COMMITMENT_LEN] {
    digest_of(&[PAIRED_DOMAIN, commitment])
}

/// SHA-256 over the domain and the parts, as a fixed-size value.
fn digest_of(parts: &[&[u8]]) -> [u8; COMMITMENT_LEN] {
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    for part in parts {
        context.update(part);
    }
    let digest = context.finish();
    let mut value = [0u8; COMMITMENT_LEN];
    value.copy_from_slice(digest.as_ref());
    value
}

/// Why a ceremony could not run or did not finish.
#[derive(Debug)]
pub enum PairError {
    /// The peer's fingerprint is this machine's own: a copy of the storage root,
    /// which no ceremony can make into a second machine.
    OwnIdentity,
    /// Failed comparisons have closed the pair on this machine. A person must
    /// clear it here; a restart does not.
    Closed { peer: PeerId },
    /// A payload is not a ceremony message this version reads.
    Malformed(&'static str),
    /// A revealed value does not match the commitment the peer made.
    CommitmentMismatch,
    /// A flight's binding does not match this attempt: a replayed or foreign
    /// message, not a fresh one.
    BindingMismatch,
    /// The peer answered "already paired" but this machine holds no record of the
    /// pair: the two sides disagree, and the ceremony does not paper over it.
    NotPaired,
    /// A message arrived out of order or after the ceremony ended.
    OutOfOrder,
    /// No flight from the peer arrived within the wait this machine was under: a machine flight
    /// waits [`PAIR_FLIGHT_TIMEOUT`], and a confirmation waits what is left of the attempt,
    /// because its sender waits as long as the other person compares. The wait ended with
    /// nothing, which is what this machine observed and no more.
    FlightTimeout { peer: PeerId, after: Duration },
    /// The attempt's lifetime passed before the ceremony reached an outcome: a person did not
    /// answer the comparison in time, or a flight did not arrive in what was left of the attempt.
    AttemptExpired { peer: PeerId },
    /// The introduction was addressed to, or came from, the wrong machine.
    WrongPeer { expected: PeerId, got: PeerId },
    /// The system's randomness source is unavailable, so no fresh value could be
    /// made and no ceremony could start.
    Entropy,
    /// The beacon refused, was unreachable, or the payload was too large.
    Beacon(BeaconError),
    /// The record could not be written.
    Record(RecordError),
}

impl fmt::Display for PairError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OwnIdentity => {
                f.write_str("the peer's fingerprint is this machine's own identity")
            }
            Self::Closed { peer } => write!(
                f,
                "the pair with {} is closed on this machine until a person clears it",
                peer.fingerprint()
            ),
            Self::Malformed(detail) => write!(f, "the ceremony message is malformed: {detail}"),
            Self::CommitmentMismatch => {
                f.write_str("the revealed value does not match the commitment")
            }
            Self::BindingMismatch => {
                f.write_str("a ceremony flight does not belong to this attempt")
            }
            Self::NotPaired => f.write_str(
                "the peer answered that it holds the pair, but this machine holds no record of it",
            ),
            Self::OutOfOrder => f.write_str("the ceremony message arrived out of order"),
            Self::FlightTimeout { peer, after } => write!(
                f,
                "no ceremony flight from {} arrived within {after:?}",
                peer.fingerprint()
            ),
            Self::AttemptExpired { peer } => write!(
                f,
                "the attempt with {} expired before the ceremony reached an outcome",
                peer.fingerprint()
            ),
            Self::WrongPeer { expected, got } => write!(
                f,
                "the ceremony expected {} and the introduction named {}",
                expected.fingerprint(),
                got.fingerprint()
            ),
            Self::Entropy => f.write_str("the system randomness source is unavailable"),
            Self::Beacon(error) => write!(f, "{error}"),
            Self::Record(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for PairError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Beacon(error) => Some(error),
            Self::Record(error) => Some(error),
            _ => None,
        }
    }
}

impl From<BeaconError> for PairError {
    fn from(error: BeaconError) -> Self {
        Self::Beacon(error)
    }
}
