//! The capability inventory and the check that pairs it with recorded cases.
//!
//! Every behaviour this workspace exposes is an entry here: either witnessed by
//! a recorded case or recorded as unproducible with a stated reason. The check
//! runs in both directions, because either half can drift: an entry with no case
//! fails, and a case whose entry no longer exists fails.
//!
//! The list is maintained by hand and the check cannot prove it exhaustive; it
//! proves that what is listed is witnessed, and that nothing is witnessed that
//! is not listed. The inventory is data, so the check can be handed a
//! deliberately broken one in-process and must report it: that is how the check
//! itself is tested, with no subprocess and no manual step.

use std::fmt;

/// One behaviour this workspace exposes, and whether a case witnesses it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capability {
    /// Stable id, namespaced by owner: `library.identity.…`, `harness.link.…`.
    pub id: &'static str,
    /// What is claimed, in one sentence a reader can check against the case.
    pub claim: &'static str,
    /// `Some(reason)` when no case can exist; the reason must say why.
    pub unproducible: Option<&'static str>,
}

impl Capability {
    /// An entry that a recorded case must witness.
    #[must_use]
    pub const fn witnessed(id: &'static str, claim: &'static str) -> Self {
        Self {
            id,
            claim,
            unproducible: None,
        }
    }

    /// An entry that no case can witness, with the reason stated.
    #[must_use]
    pub const fn unproducible(id: &'static str, claim: &'static str, reason: &'static str) -> Self {
        Self {
            id,
            claim,
            unproducible: Some(reason),
        }
    }
}

/// A recorded case that witnesses exactly one capability.
#[derive(Clone, Copy)]
pub struct Witness {
    /// Stable id, unique across the table; this is the "recorded case".
    pub id: &'static str,
    /// The capability id this case speaks for.
    pub capability: &'static str,
    /// The case itself. It returns `Err` with the reason it failed.
    pub case: fn() -> Result<(), String>,
}

impl fmt::Debug for Witness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Witness")
            .field("id", &self.id)
            .field("capability", &self.capability)
            .finish_non_exhaustive()
    }
}

/// One way the inventory and the witness table disagree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Violation {
    DuplicateCapability(&'static str),
    DuplicateWitness(&'static str),
    /// The inventory is empty, so the check proves nothing.
    NoCapabilities,
    /// A case speaks for an entry already declared impossible.
    WitnessForUnproducible {
        witness: &'static str,
        capability: &'static str,
    },
    /// A capability no case speaks for and no reason excuses.
    Unwitnessed {
        capability: &'static str,
    },
    /// A case for a capability the inventory no longer lists.
    OrphanWitness {
        witness: &'static str,
        capability: &'static str,
    },
    /// An entry marked unproducible without saying why.
    EmptyReason {
        capability: &'static str,
    },
    /// The case ran and its claim did not hold.
    Failed {
        witness: &'static str,
        capability: &'static str,
        detail: String,
    },
    /// The case panicked instead of returning a verdict.
    Panicked {
        witness: &'static str,
        capability: &'static str,
        detail: String,
    },
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateCapability(id) => write!(f, "capability {id} is listed twice"),
            Self::DuplicateWitness(id) => write!(f, "witness {id} is listed twice"),
            Self::NoCapabilities => f.write_str("the inventory is empty"),
            Self::WitnessForUnproducible {
                witness,
                capability,
            } => write!(
                f,
                "witness {witness} speaks for {capability}, which is declared unproducible"
            ),
            Self::Unwitnessed { capability } => {
                write!(f, "capability {capability} has no witness")
            }
            Self::OrphanWitness {
                witness,
                capability,
            } => {
                write!(
                    f,
                    "witness {witness} speaks for unknown capability {capability}"
                )
            }
            Self::EmptyReason { capability } => {
                write!(
                    f,
                    "capability {capability} is unproducible without a reason"
                )
            }
            Self::Failed {
                witness,
                capability,
                detail,
            } => write!(f, "witness {witness} for {capability} failed: {detail}"),
            Self::Panicked {
                witness,
                capability,
                detail,
            } => {
                write!(f, "witness {witness} for {capability} panicked: {detail}")
            }
        }
    }
}

/// What the check found.
pub type Report = crate::report::Report<Violation>;

/// The claims this workspace makes: the library's and the harness's together.
///
/// An entry is a behaviour a caller may rely on. The harness is a deliverable in
/// its own right, so its machines, link, clock, beacon rig and checks are
/// claimed here exactly like the library's seams.
pub const CAPABILITIES: &[Capability] = &[
    // The library: identity, the pinned handshake, the transport seam, the
    // beacon.
    Capability::witnessed(
        "library.identity.spki_fingerprint",
        "a generated identity is a 44-byte Ed25519 SubjectPublicKeyInfo, its peer id is the key inside it, and the parser accepts exactly that shape",
    ),
    Capability::witnessed(
        "library.identity.distinct",
        "two generated identities differ in fingerprint and in peer id",
    ),
    Capability::witnessed(
        "library.tls.pinned_handshake",
        "two endpoints that pin each other's fingerprint complete a TLS 1.3 raw-public-key handshake and carry an application datagram",
    ),
    Capability::witnessed(
        "library.tls.untrusted_peer_refused",
        "a peer whose fingerprint is not pinned is refused at the handshake",
    ),
    Capability::witnessed(
        "library.beacon.alpn",
        "the beacon speaks its own ALPN: a client that pins the beacon's key but offers the peer layer's protocol gets no answer",
    ),
    Capability::witnessed(
        "library.beacon.lookup",
        "two clients registered on a fresh beacon find each other by id, each at the address the beacon observes on its path",
    ),
    Capability::witnessed(
        "library.beacon.address",
        "a client learns its own address as observed on the path it uses for peers, a peer reaches it there, and a session on another socket reports that socket instead",
    ),
    Capability::witnessed(
        "library.beacon.state_volatile",
        "a restarted beacon remembers nothing, its old sessions answer nothing, and both clients recover on their next need by registering again",
    ),
    Capability::witnessed(
        "library.beacon.register_identity",
        "a registration is bound to the key the handshake proved: a third party registers only itself, and a frame that asserts an address is refused and changes nothing",
    ),
    Capability::witnessed(
        "library.beacon.register_ttl",
        "a registration is answered for its documented lifetime, forgotten after it, and live again after a refresh",
    ),
    Capability::witnessed(
        "library.beacon.introduction_authenticated",
        "an introduction is signed by its sender over both ids and the payload; a beacon holding the pinned key cannot pass one off under a false sender id or with an altered payload",
    ),
    Capability::witnessed(
        "library.beacon.introduction_live_only",
        "an introduction is delivered only while the addressee is registered: a closed or expired registration collects nothing, and nothing is stored for a later registration to collect",
    ),
    Capability::witnessed(
        "library.beacon.introduction_opaque",
        "the beacon relays an introduction payload byte for byte and remembers none of it: its whole memory is the registrations",
    ),
    Capability::witnessed(
        "library.beacon.wire_closed",
        "the message set is closed: an unknown kind, an answer or a push sent as a request, a wrong body length, a trailing frame and an oversized frame are all refused",
    ),
    Capability::witnessed(
        "library.beacon.wire_version",
        "every frame carries the version: a request under another version is refused with the version named, and a client reading another version reports a mismatch instead of misreading the body",
    ),
    Capability::witnessed(
        "library.beacon.pin",
        "a client pointed at an impostor that does not hold the beacon's pinned key gets no usable answer",
    ),
    Capability::witnessed(
        "library.beacon.auth",
        "an unauthenticated caller gets nothing: a client that presents no key is refused and nothing is registered",
    ),
    Capability::witnessed(
        "library.beacon.address_codec",
        "an observed address round-trips through the wire exactly as it was given, including an IPv6 scope id",
    ),
    Capability::witnessed(
        "library.beacon.session_liveness",
        "a session whose beacon was killed reports the loss within the request bound instead of waiting on a session that looks open, and the next need recovers by connecting and registering again",
    ),
    Capability::witnessed(
        "library.beacon.relay_bounded",
        "a recipient that never reads its pushes cannot stall the sender: the push gives up within the server's bound, the sender's own registration stays served, and the recipient stays registered — a third party cannot use a failed push to evict it",
    ),
    Capability::witnessed(
        "library.beacon.exchange_bounded",
        "a peer that opens a stream and does not finish its frame is answered `Slow` within the server's bound, and the same connection keeps serving complete requests",
    ),
    Capability::witnessed(
        "library.beacon.handshake_bounded",
        "a half-open handshake gives its connection slot back within the server's bound instead of holding it until the idle timeout, so a stalled dialer cannot occupy the cap",
    ),
    Capability::witnessed(
        "server.transport_advertisement",
        "the beacon advertises only what it serves: no unidirectional stream and no QUIC datagram, so a peer cannot pin receive window on a channel the server would never drain, and the connection still answers requests",
    ),
    Capability::witnessed(
        "library.net.injected_seams",
        "an endpoint is built over a caller-supplied datagram socket and clock: it reports the socket's address and needs no real socket",
    ),
    Capability::witnessed(
        "library.net.idle_timeout_bounds",
        "an idle timeout that does not fit a QUIC variable integer is refused with a typed error and a readable message",
    ),
    Capability::witnessed(
        "library.net.default_idle_timeout",
        "the default transport carries the documented idle timeout, and a connection built on it stays open until that virtual instant and no longer",
    ),
    Capability::witnessed(
        "library.tls.alpn",
        "both TLS configurations offer exactly the crate's ALPN and nothing else, and a peer offering a different one is refused at the handshake",
    ),
    Capability::witnessed(
        "library.beacon.payload_limit",
        "an introduction is built only through a checked constructor: exactly the documented size is accepted and one byte more is refused as `PayloadTooLarge`, by the client before it sends and by the server if it arrives anyway",
    ),
    Capability::unproducible(
        "library.beacon.check_code",
        "the short check code never passes through the beacon, and the beacon cannot force two machines to compare the same code",
        "the code is derived by the pairing ceremony, which this workspace does not implement: nothing here produces a code, so no case can compare one. What is provable here is witnessed instead — the payload is relayed opaquely (`library.beacon.introduction_opaque`), an alteration is refused (`library.beacon.introduction_authenticated`), and the message set has no field for a code (`library.beacon.wire_closed`).",
    ),
    // The harness: machines, the link, the clock, the beacon rig, the raw
    // client, the connect helper and the checks themselves.
    Capability::witnessed(
        "harness.check.inventory_two_way",
        "the inventory check reports an empty inventory, a duplicate entry or case, an entry with no witness, a witness with no entry, a failing case, a panicking case, an empty reason and a case for an unproducible entry",
    ),
    Capability::witnessed(
        "harness.check.invariant_two_way",
        "the invariant check reports an empty scan, an empty list, an uncaught control, a duplicate id, an out-of-scope invariant and a violated invariant",
    ),
    Capability::witnessed(
        "harness.machine.disjoint_roots_and_identities",
        "two machines in one process have distinct roots, distinct identities and distinct addresses",
    ),
    Capability::witnessed(
        "harness.machine.root_isolation",
        "another machine's root is refused by the storage capability, and a name that tries to leave a root is refused too",
    ),
    Capability::witnessed(
        "harness.machine.independent_disposal",
        "a machine is created and disposed of on its own: dropping one leaves the other working",
    ),
    Capability::witnessed(
        "harness.machine.dead_root_refused",
        "a machine whose simulation is gone refuses to write or read instead of quietly recreating its root",
    ),
    Capability::witnessed(
        "harness.machine.no_path_on_handle",
        "the file holding the machine handle names no filesystem path type",
    ),
    Capability::witnessed(
        "harness.link.address_exclusivity",
        "no two live sockets can share an address: attaching or rebinding onto a taken one is refused and leaves both where they were",
    ),
    Capability::witnessed(
        "harness.link.scripted_faults",
        "drop, delay, reorder, duplicate and reroute are applied from a script and each is recorded in the trace; a dropped datagram releases nothing held, and the next datagram that is sent does",
    ),
    Capability::witnessed(
        "harness.link.seeded_reproducibility",
        "the same seed over the same traffic produces the same trace, and a recorded trace replays to itself",
    ),
    Capability::witnessed(
        "harness.link.address_change",
        "a machine's apparent address can change mid-run, and later datagrams and connections use the new one",
    ),
    Capability::witnessed(
        "harness.clock.monotonic",
        "the clock never moves backwards: a timer armed for an instant already behind it, and an explicit move to the past, both leave the reading where it was",
    ),
    Capability::witnessed(
        "harness.connect.dead_link_times_out",
        "a connection attempt over a link that drops everything ends at a deterministic virtual instant instead of hanging",
    ),
    Capability::witnessed(
        "harness.clock.drives_transport_timers",
        "a quinn idle timeout fires only after the test advances the clock",
    ),
    Capability::unproducible(
        "harness.clock.no_wall_clock_wait",
        "no case in the suite waits on wall time",
        "no single case can prove an absence across the suite; it is enforced structurally instead — in a default build the harness's tokio has no `time` feature, so a timer sleep does not compile, the runtime it builds has no timer driver, so a sleep that did compile would panic, and the single-source-of-time invariant forbids a thread sleep. Measuring elapsed wall time inside a case would itself need the clock this harness forbids, and would be flaky besides.",
    ),
    Capability::witnessed(
        "harness.beacon.in_process_server",
        "the real server runs in-process over the simulated link: it answers while running and answers nothing once stopped",
    ),
    Capability::witnessed(
        "server.config",
        "the command line is read into a listening address and a key path, `--help` is its own outcome, an unknown or incomplete argument is refused with the usage, and a key file's mode is read as private only when neither group nor other may touch it",
    ),
    Capability::witnessed(
        "server.connection_cap",
        "a server at its connection limit refuses a further connection instead of accepting it",
    ),
    Capability::witnessed(
        "harness.sim.no_shared_state",
        "two simulations in one process share no clock, no link and no storage",
    ),
    Capability::witnessed(
        "harness.invariant.ambient_forms",
        "the ambient-configuration scanner catches every way the process environment can be read, and leaves look-alikes alone",
    ),
    Capability::witnessed(
        "harness.invariant.global_state_forms",
        "the process-global-state scanner catches a `static` under every visibility, attribute and keyword form, and leaves look-alikes alone",
    ),
    Capability::witnessed(
        "harness.clock.deadline_order",
        "each deadline fires at its own virtual instant, even when a callback queues another for the instant just visited",
    ),
    Capability::witnessed(
        "harness.clock.poll_budget",
        "a case that never parks is stopped by the poll budget and reported, instead of hanging the suite",
    ),
    Capability::witnessed(
        "harness.clock.walk_is_bounded",
        "a callback that keeps scheduling another deadline inside one advance stops the walk with a message instead of crawling through every instant",
    ),
    Capability::witnessed(
        "harness.clock.drive_bounds_await",
        "an await that never resolves is bounded by a virtual budget, so a case waiting on a datagram that never arrives fails instead of hanging",
    ),
    Capability::witnessed(
        "harness.connect.concurrent_dialers",
        "two machines dialing one machine at once each receive the connection they dialed, not the other's",
    ),
    Capability::witnessed(
        "harness.connect.retry_after_abandoned",
        "an attempt abandoned mid-handshake leaves nothing behind: the next attempt on the same pair refuses the aborted connection and completes",
    ),
    Capability::witnessed(
        "harness.connect.retry_after_timeout",
        "an attempt that timed out can be retried on the same pair at once: the retry is a working connection, and the server keeps at most one filed connection per dialer",
    ),
    Capability::witnessed(
        "harness.connect.custom_endpoint",
        "an endpoint the caller built serves one attempt: a closed endpoint is reported as closed instead of timing out",
    ),
    Capability::witnessed(
        "harness.link.oversized_datagram_dropped",
        "a datagram larger than the receiver's buffer is dropped rather than delivered truncated",
    ),
];

/// Check the inventory against the witness table, then run every witness whose
/// capability exists. Both directions are checked: an entry with no witness and
/// a witness with no entry are each a violation.
#[must_use]
pub fn check(inventory: &[Capability], witnesses: &[Witness]) -> Report {
    let mut report = Report::new(
        ("capabilities", inventory.len()),
        ("witnesses", witnesses.len()),
    );

    if inventory.is_empty() {
        report.violations.push(Violation::NoCapabilities);
    }
    for (index, capability) in inventory.iter().enumerate() {
        if inventory[..index]
            .iter()
            .any(|earlier| earlier.id == capability.id)
        {
            report
                .violations
                .push(Violation::DuplicateCapability(capability.id));
        }
        if capability
            .unproducible
            .is_some_and(|reason| reason.trim().is_empty())
        {
            report.violations.push(Violation::EmptyReason {
                capability: capability.id,
            });
        }
        let has_case = witnesses
            .iter()
            .any(|witness| witness.capability == capability.id);
        if capability.unproducible.is_none() && !has_case {
            report.violations.push(Violation::Unwitnessed {
                capability: capability.id,
            });
        }
    }

    for (index, witness) in witnesses.iter().enumerate() {
        if witnesses[..index]
            .iter()
            .any(|earlier| earlier.id == witness.id)
        {
            report
                .violations
                .push(Violation::DuplicateWitness(witness.id));
        }
        let Some(capability) = inventory
            .iter()
            .find(|capability| capability.id == witness.capability)
        else {
            report.violations.push(Violation::OrphanWitness {
                witness: witness.id,
                capability: witness.capability,
            });
            continue;
        };
        if capability.unproducible.is_some() {
            report.violations.push(Violation::WitnessForUnproducible {
                witness: witness.id,
                capability: witness.capability,
            });
            continue;
        }
        match std::panic::catch_unwind(witness.case) {
            Ok(Ok(())) => {}
            Ok(Err(detail)) => report.violations.push(Violation::Failed {
                witness: witness.id,
                capability: witness.capability,
                detail,
            }),
            Err(payload) => report.violations.push(Violation::Panicked {
                witness: witness.id,
                capability: witness.capability,
                detail: crate::report::panic_message(payload.as_ref()),
            }),
        }
    }

    report
}
