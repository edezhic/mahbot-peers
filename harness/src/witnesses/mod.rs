//! The recorded cases.
//!
//! Each case is a plain function returning `Result<(), String>`, and the table
//! below is the one place a case is listed. The summary check in
//! `tests/summary.rs` runs the whole table through the inventory check, so a
//! failure names the case that failed; there are no per-case `#[test]` wrappers
//! to keep in step with it.
//!
//! Cases that need the transport drive it on a current-thread runtime with no
//! timer or I/O driver, and the harness's `tokio` has no `time` feature, so a
//! timer sleep does not compile and a wall-clock wait cannot pass quietly.
//!
//! The cases are grouped by the seam they exercise. Each is `pub(crate)` and
//! reached only through the table below, so a case that is not in the table is
//! an unused function and fails the lint gate.

use crate::inventory::Witness;

mod beacon;
mod checks;
mod clock;
mod identity;
mod link;
mod machines;
mod support;
mod transport;

/// Every recorded case, and the capability it speaks for.
pub const WITNESSES: &[Witness] = &[
    Witness {
        id: "identity_fingerprint_is_spki",
        capability: "library.identity.spki_fingerprint",
        case: identity::identity_fingerprint_is_spki,
    },
    Witness {
        id: "identities_are_distinct",
        capability: "library.identity.distinct",
        case: identity::identities_are_distinct,
    },
    Witness {
        id: "pinned_handshake",
        capability: "library.tls.pinned_handshake",
        case: transport::pinned_handshake,
    },
    Witness {
        id: "untrusted_peer_is_refused",
        capability: "library.tls.untrusted_peer_refused",
        case: transport::untrusted_peer_is_refused,
    },
    Witness {
        id: "beacon_carries_opaque_payload",
        capability: "library.beacon.seam",
        case: beacon::beacon_carries_opaque_payload,
    },
    Witness {
        id: "introduction_size_limit",
        capability: "library.beacon.payload_limit",
        case: beacon::introduction_size_limit,
    },
    Witness {
        id: "endpoint_from_injected_seams",
        capability: "library.net.injected_seams",
        case: transport::endpoint_from_injected_seams,
    },
    Witness {
        id: "idle_timeout_bounds",
        capability: "library.net.idle_timeout_bounds",
        case: transport::idle_timeout_bounds,
    },
    Witness {
        id: "default_idle_timeout_applies",
        capability: "library.net.default_idle_timeout",
        case: transport::default_idle_timeout_applies,
    },
    Witness {
        id: "alpn_mismatch_is_refused",
        capability: "library.tls.alpn",
        case: transport::alpn_mismatch_is_refused,
    },
    Witness {
        id: "inventory_check_is_two_way",
        capability: "harness.check.inventory_two_way",
        case: checks::inventory_check_is_two_way,
    },
    Witness {
        id: "invariant_check_is_two_way",
        capability: "harness.check.invariant_two_way",
        case: checks::invariant_check_is_two_way,
    },
    Witness {
        id: "ambient_forms_are_caught",
        capability: "harness.invariant.ambient_forms",
        case: checks::ambient_forms_are_caught,
    },
    Witness {
        id: "global_state_forms_are_caught",
        capability: "harness.invariant.global_state_forms",
        case: checks::global_state_forms_are_caught,
    },
    Witness {
        id: "machines_are_distinct",
        capability: "harness.machine.disjoint_roots_and_identities",
        case: machines::machines_are_distinct,
    },
    Witness {
        id: "foreign_root_is_refused",
        capability: "harness.machine.root_isolation",
        case: machines::foreign_root_is_refused,
    },
    Witness {
        id: "machines_are_disposed_independently",
        capability: "harness.machine.independent_disposal",
        case: machines::machines_are_disposed_independently,
    },
    Witness {
        id: "dead_root_is_refused",
        capability: "harness.machine.dead_root_refused",
        case: machines::dead_root_is_refused,
    },
    Witness {
        id: "machine_handle_names_no_path",
        capability: "harness.machine.no_path_on_handle",
        case: machines::machine_handle_names_no_path,
    },
    Witness {
        id: "addresses_are_exclusive",
        capability: "harness.link.address_exclusivity",
        case: link::addresses_are_exclusive,
    },
    Witness {
        id: "link_applies_scripted_faults",
        capability: "harness.link.scripted_faults",
        case: link::link_applies_scripted_faults,
    },
    Witness {
        id: "clock_never_goes_back",
        capability: "harness.clock.monotonic",
        case: clock::clock_never_goes_back,
    },
    Witness {
        id: "clock_fires_each_deadline_at_its_instant",
        capability: "harness.clock.deadline_order",
        case: clock::clock_fires_each_deadline_at_its_instant,
    },
    Witness {
        id: "a_spinning_case_is_stopped",
        capability: "harness.clock.poll_budget",
        case: clock::a_spinning_case_is_stopped,
    },
    Witness {
        id: "a_runaway_walk_is_stopped",
        capability: "harness.clock.walk_is_bounded",
        case: clock::a_runaway_walk_is_stopped,
    },
    Witness {
        id: "drive_bounds_a_parked_await",
        capability: "harness.clock.drive_bounds_await",
        case: clock::drive_bounds_a_parked_await,
    },
    Witness {
        id: "concurrent_dialers_pair_correctly",
        capability: "harness.connect.concurrent_dialers",
        case: transport::concurrent_dialers_pair_correctly,
    },
    Witness {
        id: "retry_after_an_abandoned_attempt",
        capability: "harness.connect.retry_after_abandoned",
        case: transport::retry_after_an_abandoned_attempt,
    },
    Witness {
        id: "retry_after_a_timeout",
        capability: "harness.connect.retry_after_timeout",
        case: transport::retry_after_a_timeout,
    },
    Witness {
        id: "closed_custom_endpoint_is_reported",
        capability: "harness.connect.custom_endpoint",
        case: transport::closed_custom_endpoint_is_reported,
    },
    Witness {
        id: "oversized_datagram_is_dropped",
        capability: "harness.link.oversized_datagram_dropped",
        case: link::oversized_datagram_is_dropped,
    },
    Witness {
        id: "link_trace_is_reproducible",
        capability: "harness.link.seeded_reproducibility",
        case: link::link_trace_is_reproducible,
    },
    Witness {
        id: "machine_address_can_change",
        capability: "harness.link.address_change",
        case: transport::machine_address_can_change,
    },
    Witness {
        id: "connect_times_out_on_a_dead_link",
        capability: "harness.connect.dead_link_times_out",
        case: transport::connect_times_out_on_a_dead_link,
    },
    Witness {
        id: "transport_timer_follows_clock",
        capability: "harness.clock.drives_transport_timers",
        case: transport::transport_timer_follows_clock,
    },
    Witness {
        id: "beacon_starts_stops_and_wipes",
        capability: "harness.beacon.start_stop_wipe",
        case: beacon::beacon_starts_stops_and_wipes,
    },
    Witness {
        id: "simulations_share_no_state",
        capability: "harness.sim.no_shared_state",
        case: machines::simulations_share_no_state,
    },
];
