//! The networks between the machines: what one network does to a datagram, and
//! what it leaves behind.
//!
//! # What is modelled
//!
//! One network is a NAT, described by the three properties RFC 4787 names — its
//! mapping, its filtering and its address pooling — plus whether it carries a
//! hairpin and whether it stands in a row of two. That is the whole model: no
//! timers, no port prediction, no classification probe. A case configures the
//! network, and the translation below answers where a datagram goes from the traffic
//! that came before it, so a run replays.
//!
//! # The address space
//!
//! IPv4 only, and every address is a name: nothing is bound. A machine behind
//! nothing keeps the loopback address the link has always handed out, which stands
//! for a host on the open internet. A machine behind network `n` lives at
//! `10.n.0.<host>` and is presented to the outside at one of three documentation
//! addresses — `198.51.100.n`, `203.0.113.n`, `192.0.2.n` — so a trace says which
//! side of a network a datagram was on, and no case can be surprised by a test
//! packet escaping onto a real network. Behind two networks in a row, the inner one
//! presents itself from inside the outer one's private block (`10.n.1.1`), and only
//! the outer one reaches the documentation block.
//!
//! # The translation
//!
//! A datagram leaves through every network its sender is behind, innermost first,
//! and arrives through every network its destination is behind, outermost first.
//! Each hop out rewrites the source to the external endpoint that hop's mapping
//! table holds for it, making the mapping and opening the filter hole on first use;
//! each hop in reads the same tables back, so a reply is translated by the same
//! rules as the datagram it answers. The source is decided when the datagram is
//! sent and travels with it, which is what a socket's `RecvMeta` reports.
//!
//! Three shapes do not go through both loops. Two machines inside one network are
//! delivered to each other directly, which is what a network does with traffic that
//! never leaves it. A datagram addressed to the external side of the sender's own
//! network is carried out and back in when that network has a hairpin, and dropped
//! when it has none. A datagram addressed into a private block that is not the
//! network it is leaving is dropped: nothing outside a private block can reach one.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// How a network picks the external endpoint a machine's traffic leaves from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mapping {
    /// One external endpoint per internal endpoint, whatever the destination: the
    /// address one peer observed stays valid for every other peer.
    EndpointIndependent,
    /// One per internal endpoint and destination address: the port is chosen for
    /// the destination's address, so a second address gets a second port.
    AddressDependent,
    /// One per internal endpoint and destination endpoint: even a second port at
    /// the same address gets a new mapping.
    AddressAndPortDependent,
}

/// Which outside sources a network lets in through a mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Filtering {
    /// Any source the mapping admits.
    EndpointIndependent,
    /// Only a source at an address the machine has sent to.
    AddressDependent,
    /// Only a source the machine has sent to, endpoint for endpoint.
    AddressAndPortDependent,
}

/// Which external address a network presents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pooling {
    /// One external address for every destination.
    Shared,
    /// A different external address per destination, so the address one peer
    /// observed is not the one another peer sees.
    PerDestination,
}

/// One network between the machines, as a case configures it.
///
/// The constructors name the four networks the outcome table is written about; the
/// builders change one property of one of them. Every one of them is `const`, so a
/// case can keep its network in a constant beside the addresses it dials.
///
/// A network carries no traffic state of its own: it is a description, and the state the
/// network it makes accumulates — its mappings, its filter, its hairpins — belongs to the
/// link. Two machines are behind one network when a case asks the link for it once and
/// attaches both ([`crate::link::Link::network`] and [`crate::link::Link::attach_on`]);
/// two machines behind the same description are two homes with the same router.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Nat {
    mapping: Mapping,
    filtering: Filtering,
    pooling: Pooling,
    hairpin: bool,
    hops: u8,
}

impl Nat {
    /// Endpoint-independent mapping and filtering, one shared external address: the
    /// network a punch completes through on the first dial.
    #[must_use]
    pub const fn full_cone() -> Self {
        Self::new(Mapping::EndpointIndependent, Filtering::EndpointIndependent)
    }

    /// Endpoint-independent mapping with address-dependent filtering: a peer may
    /// answer from an address the machine has sent to, and only from one.
    #[must_use]
    pub const fn restricted_cone() -> Self {
        Self::new(Mapping::EndpointIndependent, Filtering::AddressDependent)
    }

    /// Endpoint-independent mapping with address-and-port-dependent filtering: a
    /// peer may answer from an endpoint the machine has sent to.
    #[must_use]
    pub const fn port_restricted_cone() -> Self {
        Self::new(
            Mapping::EndpointIndependent,
            Filtering::AddressAndPortDependent,
        )
    }

    /// Address-and-port-dependent mapping and filtering: the external endpoint is
    /// the destination's, so the address one peer observed is useless to another.
    #[must_use]
    pub const fn symmetric() -> Self {
        Self::new(
            Mapping::AddressAndPortDependent,
            Filtering::AddressAndPortDependent,
        )
    }

    const fn new(mapping: Mapping, filtering: Filtering) -> Self {
        Self {
            mapping,
            filtering,
            pooling: Pooling::Shared,
            hairpin: false,
            hops: 1,
        }
    }

    /// Choose how this network maps internal endpoints to external ones.
    #[must_use]
    pub const fn with_mapping(mut self, mapping: Mapping) -> Self {
        self.mapping = mapping;
        self
    }

    /// Choose which sources this network lets back in through a mapping.
    #[must_use]
    pub const fn with_filtering(mut self, filtering: Filtering) -> Self {
        self.filtering = filtering;
        self
    }

    /// Choose how this network picks the external address it presents.
    #[must_use]
    pub const fn with_pooling(mut self, pooling: Pooling) -> Self {
        self.pooling = pooling;
        self
    }

    /// Carry a datagram addressed to this network's own external side out and back
    /// in, as a network that supports hairpinning does.
    ///
    /// Off by default: a hairpin is a behaviour of the device, and a case that wants
    /// one asks for it.
    #[must_use]
    pub const fn with_hairpin(mut self, on: bool) -> Self {
        self.hairpin = on;
        self
    }

    /// Stand two of this network in a row, as a machine behind a home router behind
    /// a carrier's does.
    ///
    /// The inner network presents itself from inside the outer one's private block,
    /// so every datagram this machine sends is translated twice. Both are the same
    /// description, which is the shape the outcome table needs.
    #[must_use]
    pub const fn twice(mut self) -> Self {
        self.hops = 2;
        self
    }

    /// How this network maps internal endpoints to external ones.
    #[must_use]
    pub const fn mapping(&self) -> Mapping {
        self.mapping
    }

    /// Which sources this network lets back in.
    #[must_use]
    pub const fn filtering(&self) -> Filtering {
        self.filtering
    }

    /// How this network picks the external address it presents.
    #[must_use]
    pub const fn pooling(&self) -> Pooling {
        self.pooling
    }
}

/// One mapping a network made: the external endpoint a machine's traffic leaves
/// from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Translation {
    /// The endpoint inside the network.
    pub internal: SocketAddr,
    /// The endpoint the outside sees.
    pub external: SocketAddr,
    /// The destination the mapping was made for; `None` when it serves every one.
    pub destination: Option<SocketAddr>,
}

/// One hole a network's filter opened: a destination an internal machine sent to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hole {
    /// The machine whose filter opened.
    pub internal: SocketAddr,
    /// The destination the hole admits.
    pub destination: SocketAddr,
}

/// One datagram a network carried out through its external side and back in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hairpin {
    /// The machine that sent it.
    pub from: SocketAddr,
    /// The machine it reached.
    pub to: SocketAddr,
    /// The external endpoint it was addressed to.
    pub at: SocketAddr,
}

/// What the networks between the machines did: the mappings they made, the holes
/// their filters opened, and the hairpins they carried.
///
/// [`crate::link::Link::set_plan`] starts a new run, so it empties this and the
/// tables behind it: a run that begins here begins on cold networks.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Traversal {
    /// One entry per mapping made, in the order the networks were made and, within one network,
    /// hop by hop from the innermost.
    pub mappings: Vec<Translation>,
    /// One entry per destination a datagram went out to through a network, in the same order —
    /// what each machine has written to, which is the list its filter reads. A filter that admits
    /// any sender records one too: this is the log of sends, not of what a filter would admit. A
    /// datagram that never leaves its network, or is dropped before a mapping is made, opens none.
    ///
    /// This is the punch's observable. A hole is opened by a machine's own send, so a punch — both
    /// sides sending to each other — leaves one on each side towards the other's address. A
    /// one-sided dial leaves one on the dialling side, and one on the dialled side only where that
    /// side's filter admits the handshake it did not ask for and it replies. A side behind no
    /// network translates nothing and opens no hole at all.
    pub holes: Vec<Hole>,
    /// One entry per datagram that left a network and came back into it.
    pub hairpins: Vec<Hairpin>,
}

/// Where one datagram went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Route {
    /// The source the datagram carried when the link last had it: the sender's own
    /// address until a network translates it, and the translated one after.
    pub(crate) source: SocketAddr,
    /// The socket it is handed to, or `None` when a network dropped it.
    pub(crate) destination: Option<SocketAddr>,
}

/// The networks on one link, in the order the cases made them.
#[derive(Debug, Default)]
pub(crate) struct Nats {
    networks: Vec<Row>,
}

/// One description's network, as the model holds it: the hops a machine behind it sends
/// through, innermost first. A row, because a description may stand two in a row.
#[derive(Debug)]
struct Row {
    hops: Vec<Hop>,
}

/// One NAT in a network's row.
#[derive(Debug)]
struct Hop {
    mapping: Mapping,
    filtering: Filtering,
    pooling: Pooling,
    hairpin: bool,
    /// The private side of this hop, as the first three octets of its `/24`.
    private: Block,
    /// The three addresses this hop presents to the outside, in the order it hands
    /// them out.
    pool: [Ipv4Addr; 3],
    /// The destination endpoints this hop has given an address of its own, when it
    /// pools per destination.
    ///
    /// Keyed by the endpoint and not by its address alone: every host on the open
    /// internet is at one loopback address here, so the endpoint is what tells two
    /// destinations apart.
    assigned: BTreeMap<SocketAddr, usize>,
    /// The next entry of `pool` to hand out.
    next_pool: usize,
    /// The next external port to hand out.
    next_port: u16,
    mappings: Vec<Translation>,
    /// The filter list — RFC 4787's `sent_to` — in the order the holes were opened:
    /// one entry per destination an internal machine has sent to, which is what the
    /// filter above admits a source against and what [`Traversal::holes`] reports.
    holes: Vec<Hole>,
    hairpins: Vec<Hairpin>,
}

/// The first three octets of a private `/24`.
type Block = [u8; 3];

/// The first octet of every private block the link hands out.
const PRIVATE: u8 = 10;

/// The first host inside a block: the gateway is `.1`, and the inner network of a
/// row of two presents itself there.
const FIRST_HOST: u8 = 2;

/// The last host inside a block.
const LAST_HOST: u8 = 254;

/// The port every machine inside a network listens on. One machine per address, so
/// the port says nothing.
const INTERNAL_PORT: u16 = 41_000;

/// The first external port a network hands out.
const FIRST_EXTERNAL_PORT: u16 = 50_000;

/// The documentation blocks a network presents itself from, one address each.
const EXTERNAL_BLOCKS: [Block; 3] = [[198, 51, 100], [203, 0, 113], [192, 0, 2]];

impl Nats {
    /// Make one network of `spec`, now.
    ///
    /// Two machines are behind one network only when a case asks for one network and
    /// attaches both to it: two machines behind the same *description* are two homes
    /// with the same router, which is what the outcome table needs.
    ///
    /// # Panics
    ///
    /// When the link has already handed out every network its address space holds.
    pub(crate) fn fresh(&mut self, spec: Nat) -> usize {
        let id = u8::try_from(self.networks.len() + 1).expect("the link has room for 255 networks");
        let hops = (0..spec.hops).map(|hop| Hop::new(spec, id, hop)).collect();
        self.networks.push(Row { hops });
        self.networks.len() - 1
    }

    /// The network a machine at `addr` is behind, by the block it lives in.
    pub(crate) fn network_of(&self, addr: SocketAddr) -> Option<usize> {
        self.networks.iter().position(|network| {
            network
                .hops
                .first()
                .is_some_and(|hop| inside(hop.private, addr))
        })
    }

    /// The network whose external side `addr` is, when it is one's.
    fn network_of_external(&self, addr: SocketAddr) -> Option<usize> {
        self.networks
            .iter()
            .position(|network| network.hops.last().is_some_and(|hop| hop.owns(addr)))
    }

    /// The block a network's machines live in.
    ///
    /// # Panics
    ///
    /// When the network does not exist, which the link never asks for.
    pub(crate) fn private_of(&self, network: usize) -> Block {
        self.networks[network].hops[0].private
    }

    /// The address traffic from `addr` comes from once it has left every network the
    /// machine is behind.
    ///
    /// A machine behind nothing answers with its own address. A machine behind a
    /// network answers with the mapping its network has made for it — the oldest one,
    /// which is the one the first peer to hear from it was told — and `None` before it
    /// has sent anything, because until then its network has made no mapping and
    /// nothing outside can name it.
    pub(crate) fn external(&self, addr: SocketAddr) -> Option<SocketAddr> {
        let Some(index) = self.network_of(addr) else {
            return Some(addr);
        };
        let mut source = addr;
        for hop in &self.networks[index].hops {
            source = hop
                .mappings
                .iter()
                .find(|mapping| mapping.internal == source)?
                .external;
        }
        Some(source)
    }

    /// Everything the networks have done since the last run began.
    pub(crate) fn traversal(&self) -> Traversal {
        let mut traversal = Traversal::default();
        for network in &self.networks {
            for hop in &network.hops {
                traversal.mappings.extend_from_slice(&hop.mappings);
                traversal.holes.extend_from_slice(&hop.holes);
                traversal.hairpins.extend_from_slice(&hop.hairpins);
            }
        }
        traversal
    }

    /// Start a new run: no mapping, no hole, no hairpin, and the next datagram's
    /// mapping is made as if the network had just come up.
    pub(crate) fn clear(&mut self) {
        for network in &mut self.networks {
            for hop in &mut network.hops {
                hop.clear();
            }
        }
    }

    /// Translate one datagram from the socket that sent it to the socket that
    /// receives it.
    ///
    /// This is the whole network model: the outbound loop, the inbound loop, and the
    /// three shapes that are neither.
    pub(crate) fn route(&mut self, from: SocketAddr, to: SocketAddr) -> Route {
        let Some(index) = self.network_of(from) else {
            // Nothing translates the sender. A destination inside a network's private block
            // is reachable only through that network's external side, so a datagram
            // addressed straight at it is dropped; with no network at all the link delivers
            // as it always did.
            if is_private(to) && self.network_of(to).is_some() {
                return Route {
                    source: from,
                    destination: None,
                };
            }
            return self.arrive(from, to);
        };
        let hops = self.networks[index].hops.len();
        let mut source = from;
        let destination = to;
        for hop in 0..hops {
            let private = self.networks[index].hops[hop].private;
            if inside(private, destination) {
                // Both ends are inside one network: the datagram never leaves it, and
                // a network routes that traffic itself.
                return Route {
                    source,
                    destination: Some(destination),
                };
            }
            if self.owns_external(index, hop, destination) {
                return self.hairpin(index, hop, source, destination);
            }
            if is_private(destination) {
                return Route {
                    source,
                    destination: None,
                };
            }
            source = self.map(index, hop, source, destination);
        }
        self.arrive(source, destination)
    }

    /// Whether `hop` of `network` presents itself at `addr`.
    fn owns_external(&self, network: usize, hop: usize, addr: SocketAddr) -> bool {
        self.networks[network].hops[hop].owns(addr)
    }

    /// Take a datagram out through `hop`'s external side and back in through the
    /// same network, as a network with a hairpin does.
    fn hairpin(&mut self, network: usize, hop: usize, from: SocketAddr, at: SocketAddr) -> Route {
        if !self.networks[network].hops[hop].hairpin {
            return Route {
                source: from,
                destination: None,
            };
        }
        let source = self.map(network, hop, from, at);
        let Some(internal) = self.unmap(network, hop, at, source) else {
            return Route {
                source,
                destination: None,
            };
        };
        self.networks[network].hops[hop].hairpins.push(Hairpin {
            from,
            to: internal,
            at,
        });
        self.arrive_below(network, hop, source, internal)
    }

    /// Take a datagram that reached the public side into the network its destination
    /// is behind.
    fn arrive(&mut self, source: SocketAddr, destination: SocketAddr) -> Route {
        let Some(network) = self.network_of_external(destination) else {
            return Route {
                source,
                destination: Some(destination),
            };
        };
        let hops = self.networks[network].hops.len();
        self.arrive_below(network, hops, source, destination)
    }

    /// Translate through the hops of `network` below `below`, outermost first: the
    /// network the destination is behind reads the same tables back.
    fn arrive_below(
        &mut self,
        network: usize,
        below: usize,
        source: SocketAddr,
        mut destination: SocketAddr,
    ) -> Route {
        for hop in (0..below).rev() {
            if !self.owns_external(network, hop, destination) {
                // Nothing on this network presents itself at that address.
                return Route {
                    source,
                    destination: None,
                };
            }
            let Some(internal) = self.unmap(network, hop, destination, source) else {
                return Route {
                    source,
                    destination: None,
                };
            };
            destination = internal;
        }
        Route {
            source,
            destination: Some(destination),
        }
    }

    /// The external endpoint `internal`'s traffic leaves from at `hop`, making the
    /// mapping and opening the filter for `destination` if this is the first one.
    fn map(
        &mut self,
        network: usize,
        hop: usize,
        internal: SocketAddr,
        destination: SocketAddr,
    ) -> SocketAddr {
        self.networks[network].hops[hop].map(internal, destination)
    }

    /// The internal endpoint a datagram from `source` to `external` reaches at `hop`,
    /// or `None` when the network has nothing to translate it to or its filter does
    /// not admit the source.
    fn unmap(
        &mut self,
        network: usize,
        hop: usize,
        external: SocketAddr,
        source: SocketAddr,
    ) -> Option<SocketAddr> {
        self.networks[network].hops[hop].unmap(external, source)
    }
}

impl Hop {
    fn new(spec: Nat, network: u8, hop: u8) -> Self {
        let private = [PRIVATE, network, hop];
        let outer = hop + 1 == spec.hops;
        let pool = if outer {
            EXTERNAL_BLOCKS.map(|block| Ipv4Addr::new(block[0], block[1], block[2], network))
        } else {
            // Inside the next hop's private block: the gateway and the two addresses
            // beside it, which is the row's inner side.
            [1, 2, 3].map(|host| Ipv4Addr::new(PRIVATE, network, hop + 1, host))
        };
        Self {
            mapping: spec.mapping,
            filtering: spec.filtering,
            pooling: spec.pooling,
            hairpin: spec.hairpin,
            private,
            pool,
            assigned: BTreeMap::new(),
            next_pool: 0,
            next_port: FIRST_EXTERNAL_PORT,
            mappings: Vec::new(),
            holes: Vec::new(),
            hairpins: Vec::new(),
        }
    }

    fn clear(&mut self) {
        self.assigned.clear();
        self.next_pool = 0;
        self.next_port = FIRST_EXTERNAL_PORT;
        self.mappings.clear();
        self.holes.clear();
        self.hairpins.clear();
    }

    /// Whether this hop presents itself at `addr`.
    fn owns(&self, addr: SocketAddr) -> bool {
        matches!(addr.ip(), IpAddr::V4(ip) if self.pool.contains(&ip))
    }

    /// The mapping this hop already holds for `internal` and `destination`, under its
    /// own mapping mode — the same rule [`Self::scoped`] applies inbound, so the
    /// destination-scoping is written once.
    fn find(&self, internal: SocketAddr, destination: SocketAddr) -> Option<&Translation> {
        self.mappings
            .iter()
            .find(|mapping| mapping.internal == internal && self.scoped(mapping, destination))
    }

    /// The external endpoint `internal`'s traffic leaves from, making the mapping and
    /// opening the filter for `destination` when this is the first one.
    fn map(&mut self, internal: SocketAddr, destination: SocketAddr) -> SocketAddr {
        self.open(internal, destination);
        if let Some(mapping) = self.find(internal, destination) {
            return mapping.external;
        }
        let address = self.external_for(destination);
        let port = self.next_port;
        self.next_port = self.next_port.saturating_add(1);
        let external = SocketAddr::from((address, port));
        let destination = match self.mapping {
            Mapping::EndpointIndependent => None,
            Mapping::AddressDependent | Mapping::AddressAndPortDependent => Some(destination),
        };
        self.mappings.push(Translation {
            internal,
            external,
            destination,
        });
        external
    }

    /// The internal endpoint a datagram from `source` to `external` reaches, or `None`
    /// when this hop holds no such mapping or its filter does not admit the source.
    fn unmap(&self, external: SocketAddr, source: SocketAddr) -> Option<SocketAddr> {
        let mapping = self
            .mappings
            .iter()
            .find(|mapping| mapping.external == external && self.scoped(mapping, source))?;
        if !self.filters(mapping.internal, source) {
            return None;
        }
        Some(mapping.internal)
    }

    /// Whether a mapping is scoped to `source`, which is what makes an inbound
    /// mapping destination-scoped: a mapping made for one destination answers only
    /// that destination.
    ///
    /// RFC 4787 makes a mapping's own dependence outbound-only. This model scopes the
    /// inbound lookup too, because a mapping here is identified by the destination it
    /// was made for and one made for one destination must not admit another — the
    /// conservative reading, and it is load-bearing rather than incidental: it is what
    /// makes the destination-dependent rows of the outcome table fail in the reverse
    /// orientation. A side whose mapping depends on the destination keeps a mapping
    /// made towards the beacon, and that mapping does not translate the peer's
    /// handshake, so the address the beacon observed does not reach it. Without this
    /// rule endpoint-independent filtering would deliver that datagram, the handshake
    /// would complete, and the rig would record a success the real transport refuses.
    fn scoped(&self, mapping: &Translation, source: SocketAddr) -> bool {
        match self.mapping {
            Mapping::EndpointIndependent => true,
            Mapping::AddressDependent => mapping
                .destination
                .is_some_and(|held| held.ip() == source.ip()),
            Mapping::AddressAndPortDependent => mapping.destination == Some(source),
        }
    }

    /// Whether this hop's filter admits `source` for `internal`: the source has to be
    /// one the machine has sent to, as far as the filter looks.
    fn filters(&self, internal: SocketAddr, source: SocketAddr) -> bool {
        match self.filtering {
            Filtering::EndpointIndependent => true,
            Filtering::AddressDependent => self
                .holes
                .iter()
                .any(|hole| hole.internal == internal && hole.destination.ip() == source.ip()),
            Filtering::AddressAndPortDependent => self
                .holes
                .iter()
                .any(|hole| hole.internal == internal && hole.destination == source),
        }
    }

    /// Open this hop's filter for `internal` towards `destination`, once.
    fn open(&mut self, internal: SocketAddr, destination: SocketAddr) {
        if self
            .holes
            .iter()
            .any(|hole| hole.internal == internal && hole.destination == destination)
        {
            return;
        }
        self.holes.push(Hole {
            internal,
            destination,
        });
    }

    /// The address this hop presents to `destination`.
    fn external_for(&mut self, destination: SocketAddr) -> Ipv4Addr {
        if self.pooling == Pooling::Shared {
            return self.pool[0];
        }
        if let Some(index) = self.assigned.get(&destination) {
            return self.pool[*index];
        }
        let index = self.next_pool % self.pool.len();
        self.next_pool += 1;
        self.assigned.insert(destination, index);
        self.pool[index]
    }
}

/// Whether `addr` is inside the `/24` `block` names.
fn inside(block: Block, addr: SocketAddr) -> bool {
    let IpAddr::V4(ip) = addr.ip() else {
        return false;
    };
    ip.octets()[..3] == block
}

/// Whether `addr` is inside a block that is not routable from the open internet.
///
/// The link's own space is loopback, which stands for a host on the open internet,
/// so it is not private here; the private blocks are the ones a network hands out
/// and the ones a real network would refuse to route.
fn is_private(addr: SocketAddr) -> bool {
    let IpAddr::V4(ip) = addr.ip() else {
        return false;
    };
    let [first, second, ..] = ip.octets();
    first == 10
        || (first == 172 && (16..32).contains(&second))
        || (first == 192 && second == 168)
        || (first == 100 && (64..128).contains(&second))
}

/// The address the link hands out for `host` inside `block`, which is the port every
/// machine inside a network listens on.
pub(crate) fn host_at(block: Block, host: u8) -> SocketAddr {
    SocketAddr::from((
        Ipv4Addr::new(block[0], block[1], block[2], host),
        INTERNAL_PORT,
    ))
}

/// The hosts a block hands out, lowest first.
pub(crate) const HOSTS: std::ops::RangeInclusive<u8> = FIRST_HOST..=LAST_HOST;
