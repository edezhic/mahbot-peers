//! The punch: the candidate set one dial may try, the payload that carries it, and the three
//! combinators that poll a set of dials at once.
//!
//! # What a punch is
//!
//! A punch is one [`crate::peer::Connections::connect`] call that tries the addresses the peer
//! says it can be reached at, while the peer tries this machine's, in the same round trip. There
//! is no separate connectivity check: the authenticated handshake *is* the check — the module
//! note in [`crate::peer::connect`] states that rule and what it implies. What is here is the
//! set, bounded by [`MAX_CANDIDATES`] and filtered before anything is dialled, and the machinery
//! that polls several dials at once: a punch needs both machines' packets in flight at the same
//! time, and eight sequential dials of ten seconds each do not fit one dial's budget — so the set
//! goes out at once, and a candidate dial is bounded by [`PUNCH_DIAL_BUDGET`] rather than by a
//! lone dial's ten seconds.
//!
//! # The coordination payload
//!
//! A candidate list travels as a signed, opaque introduction payload — the beacon relays it
//! without reading it, and it carries the same signature every introduction does, over both ids
//! and the payload, so the list is authenticated as coming from the peer. It is signed and not
//! encrypted: the beacon can read it, and that exposure is named where the payload is sent.
//!
//! The payload opens with a magic of its own, so a payload that is not a candidate list cannot
//! be taken for one: [`classify`] answers [`Payload::Coordination`] only when the magic, the
//! version, the count and every address in it decode. Any family is carried and tried — the
//! payload uses the same family-tagged codec the ceremony does — and nothing here prefers one:
//! the crate cannot know which family a path will work over. A ceremony flight can never start with
//! that magic, because a flight starts with the ceremony's own version byte, and the magic
//! starts with `m`.
//!
//! # The filter
//!
//! [`acceptable`] is the one place a candidate that arrived from the network is judged. Only
//! addresses that came from the peer pass through it: the caller's hint and the beacon's
//! observed address are dialled unfiltered, because a product may legitimately redial a private
//! or local address, and because filtering the beacon's own answer would change every existing
//! case.
//!
//! # Why nothing here is a protocol
//!
//! The combinators are three small functions over `poll_fn` rather than a dependency: a punch
//! polls a fixed set of futures to completion and needs no scheduler, no timer of its own (the
//! dials carry their own bounds) and no runtime. Nothing in this module reads a clock, opens a
//! socket or holds state between calls.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;

use crate::peer::address;
use crate::peer::pair;

/// The most candidates one punch may dial. Bounds both the payload and the dial set.
pub const MAX_CANDIDATES: usize = 8;

/// The payload's count is one byte, so a set that stopped fitting would write a payload its own
/// decoder refuses.
const _: () = assert!(MAX_CANDIDATES <= u8::MAX as usize);

/// How long a punch waits for the peer's coordination payload before dialling what it has.
pub(crate) const PUNCH_WINDOW: Duration = Duration::from_secs(5);

/// How long the candidate dials themselves may take. Shorter than a first dial: a
/// punch that works completes in one round trip, and the budget is the bound on the whole set
/// because a candidate that answers nothing spends all of it.
pub(crate) const PUNCH_DIAL_BUDGET: Duration = Duration::from_secs(5);

/// The least time between two re-arms of the same pair from coordination payloads.
pub const PUNCH_REARM: Duration = Duration::from_secs(5);

/// The bytes every coordination payload opens with.
///
/// The name carries the version as well as the version byte that follows it, so a payload of
/// another version is refused at its first byte rather than read as this one — and it starts with
/// `m`, which no ceremony flight does.
const MAGIC: &[u8] = b"mahbot-peers coordinate v1";

/// The coordination format this build writes.
const VERSION: u8 = 1;

/// The addresses one punch may dial, deduplicated and capped at [`MAX_CANDIDATES`].
#[derive(Clone)]
pub(crate) struct Candidates {
    addresses: Vec<SocketAddr>,
}

impl Candidates {
    /// The set of `addresses`: the first [`MAX_CANDIDATES`] distinct ones, in the order given.
    ///
    /// Order is kept because it is the order a reader acts on — the beacon's observed address
    /// first, then the peer's own — and a repeat costs a dial that cannot answer differently
    /// from the one before it. The rule itself is [`address::distinct`]'s, shared with the
    /// record's list.
    pub(crate) fn new(addresses: impl IntoIterator<Item = SocketAddr>) -> Self {
        Self {
            addresses: address::distinct(addresses, MAX_CANDIDATES),
        }
    }

    /// The addresses, in the order the set was built.
    pub(crate) fn addresses(&self) -> &[SocketAddr] {
        &self.addresses
    }

    /// The payload's bytes; see the module note for the format.
    ///
    /// `None` for an empty set: the format refuses a count of zero, so a machine that knows of
    /// no address of its own sends nothing rather than a payload the peer would drop.
    pub(crate) fn encode(&self) -> Option<Vec<u8>> {
        if self.addresses.is_empty() {
            return None;
        }
        let mut bytes = Vec::with_capacity(MAGIC.len() + 2 + self.addresses.len() * 27);
        bytes.extend_from_slice(MAGIC);
        bytes.push(VERSION);
        // The count always has a byte: [`Self::new`] caps the set at [`MAX_CANDIDATES`].
        bytes.push(
            u8::try_from(self.addresses.len())
                .expect("a candidate set is capped at MAX_CANDIDATES, which fits a byte"),
        );
        for candidate in &self.addresses {
            address::encode(&mut bytes, Some(*candidate));
        }
        Some(bytes)
    }

    /// The set a payload carries, or `None` when the payload is not a coordination payload of
    /// this version.
    ///
    /// Every way of not being one is `None`: another magic, another version, a count of zero or
    /// past [`MAX_CANDIDATES`], an address that does not decode, and a byte after the last
    /// address. A payload that is not a candidate list must never be read as one, so the answer
    /// is the whole payload's verdict and not a prefix of it.
    pub(crate) fn decode(payload: &[u8]) -> Option<Self> {
        let rest = payload.strip_prefix(MAGIC)?;
        let (&version, rest) = rest.split_first()?;
        if version != VERSION {
            return None;
        }
        let (&count, mut rest) = rest.split_first()?;
        let count = usize::from(count);
        if count == 0 || count > MAX_CANDIDATES {
            return None;
        }
        let mut addresses = Vec::with_capacity(count);
        for _ in 0..count {
            let (candidate, after) = address::decode(rest)?;
            addresses.push(candidate?);
            rest = after;
        }
        if !rest.is_empty() {
            return None;
        }
        Some(Self { addresses })
    }
}

/// What an introduction payload is, decided before it reaches anything that acts on it.
pub(crate) enum Payload {
    /// A ceremony flight, and whether it can start a ceremony: only an opening is worth holding
    /// for a person who has not started yet.
    Ceremony {
        /// Whether it is an opening.
        opens: bool,
    },
    /// A coordination payload: the candidate list above.
    Coordination(Candidates),
    /// Neither. Dropped without touching a ceremony or a punch.
    Unknown,
}

/// What `payload` is, by its own bytes and nothing else.
///
/// Coordination is asked first, because a coordination payload is not a ceremony flight and the
/// magic makes that structural: the two cannot be confused in either direction. A payload that
/// is neither is [`Payload::Unknown`], and the caller drops it — an unrecognised payload must
/// never be allowed to end a ceremony, which is what an older build would do with one it did not
/// understand. A flight is parsed once, and the same parse answers whether it opens a ceremony.
pub(crate) fn classify(payload: &[u8]) -> Payload {
    if let Some(candidates) = Candidates::decode(payload) {
        return Payload::Coordination(candidates);
    }
    match pair::ceremony_flight(payload) {
        Some(opens) => Payload::Ceremony { opens },
        None => Payload::Unknown,
    }
}

/// Whether a candidate that arrived from the peer may be dialled.
///
/// Only addresses from the network pass through this. The caller's hint and the beacon's
/// observed address are not filtered: a product may legitimately redial a private or local
/// address, and filtering the beacon's answer would change every existing case.
///
/// Refused unconditionally: loopback, link-local, multicast, the limited broadcast
/// (`255.255.255.255`), unspecified, and this machine's own endpoints — the address of the socket
/// this crate was handed and every address the product declared, each compared as an address
/// *and a port*. A candidate naming one of this machine's own addresses on another port is
/// therefore not refused here: it is dialled, and it ends as
/// [`crate::peer::ConnectFailure::WrongPeer`] when that port is this machine's own endpoint and as
/// an ordinary dial failure otherwise. This machine's external address — the one the beacon
/// observes — is not in the filter's knowledge, because the crate never learns it: a peer that
/// names it makes this machine dial itself, the transport refuses its own key, and the dial
/// reports the failure.
///
/// A private address is refused unless `declared` holds an address in the same block: the same /8
/// for 10/8, the same /12 for 172.16/12, the same /16 for 192.168/16, the same /10 for the
/// carrier-shared 100.64/10, and the same /7 for fc00::/7. The block is the whole RFC 1918 block
/// (or shared block) and not a subnet of it, and that is the accepted cost of needing one
/// declaration: a peer behind this machine's own router is dialled, and so is one behind a
/// neighbour's on the same block. The ceiling, the re-arm interval and the handshake bound what a
/// paired peer makes of that. A subnet-directed broadcast inside a declared block — say
/// `192.168.1.255` with `192.168.0.0/16` declared — cannot be told from a host address without
/// the block's prefix, so it is dialled and bounded the same way. An IPv4-mapped IPv6 address is
/// judged by the IPv4 rules.
///
/// The socket's own address is not a declaration: a product that binds the wildcard gets an
/// unspecified address and declares nothing, and a private candidate is then refused, so a
/// peer can never use this machine to sweep its network. Only what the product declared opens
/// that gate.
///
/// A global unicast address is accepted. A paired peer can still name a global address that is
/// not the peer's, and that is an accepted cost: the set is bounded by [`MAX_CANDIDATES`], a
/// re-arm by [`PUNCH_REARM`], and the handshake still proves the key at whatever answers.
pub(crate) fn acceptable(
    candidate: SocketAddr,
    declared: &[SocketAddr],
    local: Option<SocketAddr>,
) -> bool {
    if Some(candidate) == local || declared.contains(&candidate) {
        return false;
    }
    match candidate.ip() {
        IpAddr::V4(ip) => {
            if ip.is_loopback()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_broadcast()
                || ip.is_unspecified()
            {
                return false;
            }
            match private_block(ip) {
                None => true,
                Some(block) => declared.iter().any(|declared| match declared.ip() {
                    IpAddr::V4(declared) => private_block(declared) == Some(block),
                    IpAddr::V6(_) => false,
                }),
            }
        }
        IpAddr::V6(ip) => {
            // An IPv4-mapped address is an IPv4 address in IPv6 clothing: judging it by the IPv6
            // rules would let `::ffff:127.0.0.1` and `::ffff:10.0.0.1` past the refusals below.
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return acceptable(
                    SocketAddr::from((mapped, candidate.port())),
                    declared,
                    local,
                );
            }
            if ip.is_loopback()
                || ip.is_unicast_link_local()
                || ip.is_multicast()
                || ip.is_unspecified()
            {
                return false;
            }
            if unique_local(ip) {
                return declared.iter().any(|declared| match declared.ip() {
                    IpAddr::V6(declared) => unique_local(declared),
                    IpAddr::V4(_) => false,
                });
            }
            true
        }
    }
}

/// The RFC 1918 block an address belongs to, named by the two octets that decide it.
///
/// Two addresses are in the same block exactly when this answer is the same for both: 10/8 is
/// named by `(10, 0)`, 172.16/12 by `(172, 16..=31)`, and 192.168/16 by `(192, 168)`.
fn private_block(ip: Ipv4Addr) -> Option<(u8, u8)> {
    let [first, second, ..] = ip.octets();
    match (first, second) {
        (10, _) => Some((10, 0)),
        (172, 16..=31) => Some((172, 16)),
        (192, 168) => Some((192, 168)),
        // The carrier-shared space is not global unicast either, and a peer behind carrier
        // translation naming one is dialled only by a machine that declared it is behind the
        // same shared block.
        (100, 64..=127) => Some((100, 64)),
        _ => None,
    }
}

/// Whether `ip` is an IPv6 unique-local address: fc00::/7.
fn unique_local(ip: Ipv6Addr) -> bool {
    ip.octets()[0] & 0xfe == 0xfc
}

/// One address's dial, boxed so a set of them is polled together.
///
/// `T` and `E` are the dial's own answers — the manager's are a connection and its one-address
/// failure — and nothing here needs to know either. `Send` because the dial that owns the set runs
/// on whatever task the caller gave it: the manager spawns none of its own for a dial, and a
/// caller's task may be any runtime's.
pub(crate) type Dial<'a, T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'a>>;

/// Either of two answers, told apart. Which one it is says which future answered first.
pub(crate) enum Either<A, B> {
    /// The first future answered.
    First(A),
    /// The second future answered.
    Second(B),
}

/// Run both futures to the end and answer both outputs.
///
/// Neither is dropped early and neither can cancel the other: a lookup that failed does not turn
/// an introduction that was delivered into a failure, and an introduction the beacon refused does
/// not throw away an address it did answer with. The caller bounds the pair with one deadline.
pub(crate) async fn join2<A, B>(first: A, second: B) -> (A::Output, B::Output)
where
    A: Future,
    B: Future,
{
    let mut first = std::pin::pin!(first);
    let mut second = std::pin::pin!(second);
    let mut done_first = None;
    let mut done_second = None;
    std::future::poll_fn(|context| {
        if done_first.is_none()
            && let Poll::Ready(output) = first.as_mut().poll(context)
        {
            done_first = Some(output);
        }
        if done_second.is_none()
            && let Poll::Ready(output) = second.as_mut().poll(context)
        {
            done_second = Some(output);
        }
        match (done_first.take(), done_second.take()) {
            (Some(one), Some(other)) => Poll::Ready((one, other)),
            (one, other) => {
                done_first = one;
                done_second = other;
                Poll::Pending
            }
        }
    })
    .await
}

/// Run both futures and answer whichever finishes first, dropping the other.
///
/// The loser is a wait that has been overtaken — a pause beside a payload that arrived — and
/// returning is what ends it: it is not polled again. A wait dropped this way leaves its waker in
/// the list it registered with, and that costs nothing there: the list is deduplicated by
/// `Waker::will_wake`, and waking a waker whose future nobody polls is a no-op.
pub(crate) async fn race2<A, B>(first: A, second: B) -> Either<A::Output, B::Output>
where
    A: Future,
    B: Future,
{
    let mut first = std::pin::pin!(first);
    let mut second = std::pin::pin!(second);
    std::future::poll_fn(|context| {
        if let Poll::Ready(output) = first.as_mut().poll(context) {
            return Poll::Ready(Either::First(output));
        }
        if let Poll::Ready(output) = second.as_mut().poll(context) {
            return Poll::Ready(Either::Second(output));
        }
        Poll::Pending
    })
    .await
}

/// One dial of a set, and what it answered.
///
/// A dial that failed keeps its fault rather than reporting it: the whole set is answered in
/// input order once every one of them is over, so a caller reads the addresses in the order it
/// asked for them.
struct Pending<'a, T, E> {
    address: SocketAddr,
    dial: Option<Dial<'a, T, E>>,
    failure: Option<E>,
}

/// Dial every address at once and answer everything that happened.
///
/// Concurrent because a punch only works while both machines' packets are in flight at the same
/// time; the module note states the budget that makes the whole set fit one dial.
///
/// Every dial is polled to its own end, and every connection one of them completes is handed
/// back rather than dropped: the peer accepts a handshake the moment it completes, so a dial
/// this side abandoned could leave the pair holding a connection this side does not know about,
/// and the two machines would keep different ones. A dial that fails keeps its fault; the
/// failures are in input order and the successes in the order they completed, and the caller
/// builds the set with at most [`MAX_CANDIDATES`] entries.
pub(crate) async fn dial_all<T, E>(
    dials: Vec<(SocketAddr, Dial<'_, T, E>)>,
) -> (Vec<(SocketAddr, T)>, Vec<(SocketAddr, E)>) {
    let mut pending: Vec<Pending<'_, T, E>> = dials
        .into_iter()
        .map(|(address, dial)| Pending {
            address,
            dial: Some(dial),
            failure: None,
        })
        .collect();
    let mut reached: Vec<(SocketAddr, T)> = Vec::new();
    std::future::poll_fn(|context| {
        for each in &mut pending {
            let Some(dial) = each.dial.as_mut() else {
                continue;
            };
            match dial.as_mut().poll(context) {
                Poll::Pending => {}
                Poll::Ready(Ok(connection)) => {
                    each.dial = None;
                    reached.push((each.address, connection));
                }
                Poll::Ready(Err(error)) => {
                    each.dial = None;
                    each.failure = Some(error);
                }
            }
        }
        if pending.iter().all(|each| each.dial.is_none()) {
            let failures = pending
                .iter_mut()
                .filter_map(|each| each.failure.take().map(|failure| (each.address, failure)))
                .collect();
            return Poll::Ready((std::mem::take(&mut reached), failures));
        }
        Poll::Pending
    })
    .await
}
