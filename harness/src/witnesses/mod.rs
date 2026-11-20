//! The recorded cases.
//!
//! Each case is a plain function returning `Result<(), String>`, and the tables
//! below are the one place a case is listed. The summary check in
//! `tests/summary.rs` runs the whole table through the inventory check, so a
//! failure names the case that failed; there are no per-case `#[test]` wrappers
//! to keep in step with it.
//!
//! Cases that need the transport drive it on a current-thread runtime with no
//! timer or I/O driver, and the harness's `tokio` has no `time` feature, so a
//! timer sleep does not compile and a wall-clock wait cannot pass quietly.
//!
//! The cases are grouped by the seam they exercise. Each is `pub(crate)` and
//! reached only through the tables below, so a case that is not in one of them is
//! an unused function and fails the lint gate.
//!
//! Some cases are per platform: a case about unix mode bits or a macOS extended
//! access entry cannot run on a host that has neither, and the inventory then
//! records the capability as unproducible with the procedure that produces it. The
//! tables are composed for the host rather than silently shortened, so what this
//! host cannot produce is named as unreachable, with what to do about it.

use crate::inventory::Witness;

mod beacon;
mod checks;
mod clock;
mod identity;
mod link;
mod machines;
mod server;
mod support;
mod transport;

/// Every recorded case this host can run, and the capability it speaks for.
#[must_use]
pub fn witnesses() -> Vec<Witness> {
    let mut all = WITNESSES.to_vec();
    all.extend_from_slice(UNIX_WITNESSES);
    all.extend_from_slice(MACOS_WITNESSES);
    all
}

/// The cases that need unix modes, links and ownership.
#[cfg(unix)]
pub const UNIX_WITNESSES: &[Witness] = &[
    Witness {
        id: "key_file_refuses_other_readers",
        capability: "library.identity.key_file.insecure_file",
        case: identity::key_file_refuses_other_readers,
    },
    Witness {
        id: "unix_account_names_are_exact",
        capability: "library.identity.access.unix_account_names",
        case: identity::unix_account_names_are_exact,
    },
];

/// Nothing on a host without unix modes; `platform_capabilities` records the case
/// as unproducible here, with the procedure that produces the file states.
#[cfg(not(unix))]
pub const UNIX_WITNESSES: &[Witness] = &[];

/// The cases that need an extended access list.
#[cfg(target_os = "macos")]
pub const MACOS_WITNESSES: &[Witness] = &[
    Witness {
        id: "key_file_refuses_an_extended_entry",
        capability: "library.identity.key_file.extended_acl",
        case: identity::key_file_refuses_an_extended_entry,
    },
    Witness {
        id: "key_file_refuses_a_sharing_root",
        capability: "library.identity.key_file.root_access_list",
        case: identity::key_file_refuses_a_sharing_root,
    },
];

/// Nothing on a host without extended access lists; `platform_capabilities` records
/// the case as unproducible here, with the procedure that produces the file state.
#[cfg(not(target_os = "macos"))]
pub const MACOS_WITNESSES: &[Witness] = &[];

/// Every recorded case every host runs, and the capability it speaks for.
const WITNESSES: &[Witness] = &[
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
        id: "beacon_alpn_is_its_own",
        capability: "library.beacon.alpn",
        case: beacon::beacon_alpn_is_its_own,
    },
    Witness {
        id: "two_clients_find_each_other",
        capability: "library.beacon.lookup",
        case: beacon::two_clients_find_each_other,
    },
    Witness {
        id: "observed_address_is_the_peer_path",
        capability: "library.beacon.address",
        case: beacon::observed_address_is_the_peer_path,
    },
    Witness {
        id: "beacon_restart_forgets_and_recovers",
        capability: "library.beacon.state_volatile",
        case: beacon::beacon_restart_forgets_and_recovers,
    },
    Witness {
        id: "registration_is_bound_to_the_caller_key",
        capability: "library.beacon.register_identity",
        case: beacon::registration_is_bound_to_the_caller_key,
    },
    Witness {
        id: "registration_ttl_is_the_beacons_housekeeping",
        capability: "library.beacon.register_ttl",
        case: beacon::registration_ttl_is_the_beacons_housekeeping,
    },
    Witness {
        id: "introduction_is_signed_by_its_sender",
        capability: "library.beacon.introduction_authenticated",
        case: beacon::introduction_is_signed_by_its_sender,
    },
    Witness {
        id: "beacon_relays_introductions_live_only",
        capability: "library.beacon.introduction_live_only",
        case: beacon::beacon_relays_introductions_live_only,
    },
    Witness {
        id: "introduction_payload_is_opaque_to_the_beacon",
        capability: "library.beacon.introduction_opaque",
        case: beacon::introduction_payload_is_opaque_to_the_beacon,
    },
    Witness {
        id: "introduction_size_limit",
        capability: "library.beacon.payload_limit",
        case: beacon::introduction_size_limit,
    },
    Witness {
        id: "closed_message_set_refuses_unknown_kinds",
        capability: "library.beacon.wire_closed",
        case: beacon::closed_message_set_refuses_unknown_kinds,
    },
    Witness {
        id: "version_mismatch_is_explicit",
        capability: "library.beacon.wire_version",
        case: beacon::version_mismatch_is_explicit,
    },
    Witness {
        id: "impostor_beacon_gives_no_answers",
        capability: "library.beacon.pin",
        case: beacon::impostor_beacon_gives_no_answers,
    },
    Witness {
        id: "unauthenticated_caller_gets_nothing",
        capability: "library.beacon.auth",
        case: beacon::unauthenticated_caller_gets_nothing,
    },
    Witness {
        id: "beacon_starts_and_stops",
        capability: "harness.beacon.in_process_server",
        case: beacon::beacon_starts_and_stops,
    },
    Witness {
        id: "addresses_round_trip",
        capability: "library.beacon.address_codec",
        case: beacon::addresses_round_trip,
    },
    Witness {
        id: "a_dead_beacon_is_noticed",
        capability: "library.beacon.session_liveness",
        case: beacon::a_dead_beacon_is_noticed,
    },
    Witness {
        id: "a_stalled_stream_is_refused",
        capability: "library.beacon.exchange_bounded",
        case: beacon::a_stalled_stream_is_refused,
    },
    Witness {
        id: "a_stalled_handshake_gives_its_place_back",
        capability: "library.beacon.handshake_bounded",
        case: beacon::a_stalled_handshake_gives_its_place_back,
    },
    Witness {
        id: "the_beacon_advertises_only_what_it_serves",
        capability: "server.transport_advertisement",
        case: server::the_beacon_advertises_only_what_it_serves,
    },
    Witness {
        id: "a_recipient_that_never_reads_does_not_stall_the_sender",
        capability: "library.beacon.relay_bounded",
        case: beacon::a_recipient_that_never_reads_does_not_stall_the_sender,
    },
    Witness {
        id: "server_config_parse",
        capability: "server.config",
        case: server::config_parse,
    },
    Witness {
        id: "server_connection_cap",
        capability: "server.connection_cap",
        case: server::connection_cap,
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
        id: "procedures_are_runnable",
        capability: "harness.inventory.procedures_are_runnable",
        case: checks::procedures_are_runnable,
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
        id: "simulations_share_no_state",
        capability: "harness.sim.no_shared_state",
        case: machines::simulations_share_no_state,
    },
    Witness {
        id: "key_file_is_one_identity_per_root",
        capability: "library.identity.key_file.one_identity_per_root",
        case: identity::key_file_is_one_identity_per_root,
    },
    Witness {
        id: "key_file_is_created_once_under_race",
        capability: "library.identity.key_file.created_once",
        case: identity::key_file_is_created_once_under_race,
    },
    Witness {
        id: "key_file_refuses_a_broken_key",
        capability: "library.identity.key_file.malformed",
        case: identity::key_file_refuses_a_broken_key,
    },
    Witness {
        id: "unix_rule_is_exact",
        capability: "library.identity.access.unix_rule",
        case: identity::unix_rule_is_exact,
    },
    Witness {
        id: "extended_access_rule_is_exact",
        capability: "library.identity.access.extended_rule",
        case: identity::extended_access_rule_is_exact,
    },
    Witness {
        id: "windows_dacl_rule_is_exact",
        capability: "library.identity.access.dacl_rule",
        case: identity::windows_dacl_rule_is_exact,
    },
    Witness {
        id: "one_rendering_round_trips",
        capability: "library.identity.one_rendering",
        case: identity::one_rendering_round_trips,
    },
    Witness {
        id: "no_key_rotation_is_proven",
        capability: "harness.invariant.no_key_rotation",
        case: identity::no_key_rotation_is_proven,
    },
    Witness {
        id: "own_identity_is_refused",
        capability: "library.tls.own_identity_refused",
        case: transport::own_identity_is_refused,
    },
    Witness {
        id: "handshake_value_is_the_pinned_bytes",
        capability: "library.tls.pinned_value",
        case: transport::handshake_value_is_the_pinned_bytes,
    },
];

// The host-independent part of the table, which the platform tables add to. This is
// the floor that keeps a shrinking table from looking like a pass.
const _: () = assert!(WITNESSES.len() >= 68, "the shared witness table shrank");
