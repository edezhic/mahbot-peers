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
mod binding;
mod checks;
mod clock;
mod connection;
mod identity;
mod link;
mod machines;
mod peer;
mod rights;
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
        capabilities: &["library.identity.key_file.insecure_file"],
        case: identity::key_file_refuses_other_readers,
    },
    Witness {
        id: "the_audit_is_written_before_the_record_changes",
        capabilities: &["library.peer.audit.before_effect"],
        case: rights::the_audit_is_written_before_the_record_changes,
    },
    Witness {
        id: "unix_account_names_are_exact",
        capabilities: &["library.identity.access.unix_account_names"],
        case: identity::unix_account_names_are_exact,
    },
    Witness {
        id: "peer_record_refuses_other_readers",
        capabilities: &["library.peer.record.insecure_file"],
        case: peer::peer_record_refuses_other_readers,
    },
    Witness {
        id: "peer_record_refuses_other_writers",
        capabilities: &["library.peer.record.insecure_directory"],
        case: peer::peer_record_refuses_other_writers,
    },
    Witness {
        id: "peer_record_creates_a_private_directory",
        capabilities: &["library.peer.record.private_directory"],
        case: peer::peer_record_creates_a_private_directory,
    },
    Witness {
        id: "peer_record_opens_a_read_only_directory",
        capabilities: &["library.peer.record.opens_read_only"],
        case: peer::peer_record_opens_a_read_only_directory,
    },
    Witness {
        id: "peer_record_refuses_a_symlinked_directory",
        capabilities: &["library.peer.record.symlinked_directory"],
        case: peer::peer_record_refuses_a_symlinked_directory,
    },
    Witness {
        id: "the_audit_is_private_to_the_account",
        capabilities: &["library.peer.audit.private"],
        case: rights::the_audit_is_private_to_the_account,
    },
    Witness {
        id: "the_audit_rechecks_privacy_on_every_append",
        capabilities: &["library.peer.audit.private_on_write"],
        case: rights::the_audit_rechecks_privacy_on_every_append,
    },
    Witness {
        id: "an_unreadable_record_is_not_an_unpaired_machine",
        capabilities: &["library.peer.connect.unreadable_record"],
        case: connection::an_unreadable_record_is_not_an_unpaired_machine,
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
        capabilities: &["library.identity.key_file.extended_acl"],
        case: identity::key_file_refuses_an_extended_entry,
    },
    Witness {
        id: "key_file_refuses_a_sharing_root",
        capabilities: &["library.identity.key_file.root_access_list"],
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
        capabilities: &["library.identity.spki_fingerprint"],
        case: identity::identity_fingerprint_is_spki,
    },
    Witness {
        id: "identities_are_distinct",
        capabilities: &["library.identity.distinct"],
        case: identity::identities_are_distinct,
    },
    Witness {
        id: "pinned_handshake",
        capabilities: &["library.tls.pinned_handshake"],
        case: transport::pinned_handshake,
    },
    Witness {
        id: "untrusted_peer_is_refused",
        capabilities: &["library.tls.untrusted_peer_refused"],
        case: transport::untrusted_peer_is_refused,
    },
    Witness {
        id: "beacon_alpn_is_its_own",
        capabilities: &["library.beacon.alpn"],
        case: beacon::beacon_alpn_is_its_own,
    },
    Witness {
        id: "two_clients_find_each_other",
        capabilities: &["library.beacon.lookup"],
        case: beacon::two_clients_find_each_other,
    },
    Witness {
        id: "observed_address_is_the_peer_path",
        capabilities: &["library.beacon.address"],
        case: beacon::observed_address_is_the_peer_path,
    },
    Witness {
        id: "beacon_restart_forgets_and_recovers",
        capabilities: &["library.beacon.state_volatile"],
        case: beacon::beacon_restart_forgets_and_recovers,
    },
    Witness {
        id: "registration_is_bound_to_the_caller_key",
        capabilities: &["library.beacon.register_identity"],
        case: beacon::registration_is_bound_to_the_caller_key,
    },
    Witness {
        id: "registration_ttl_is_the_beacons_housekeeping",
        capabilities: &["library.beacon.register_ttl"],
        case: beacon::registration_ttl_is_the_beacons_housekeeping,
    },
    Witness {
        id: "introduction_is_signed_by_its_sender",
        capabilities: &["library.beacon.introduction_authenticated"],
        case: beacon::introduction_is_signed_by_its_sender,
    },
    Witness {
        id: "beacon_relays_introductions_live_only",
        capabilities: &["library.beacon.introduction_live_only"],
        case: beacon::beacon_relays_introductions_live_only,
    },
    Witness {
        id: "introduction_payload_is_opaque_to_the_beacon",
        capabilities: &["library.beacon.introduction_opaque"],
        case: beacon::introduction_payload_is_opaque_to_the_beacon,
    },
    Witness {
        id: "introduction_size_limit",
        capabilities: &["library.beacon.payload_limit"],
        case: beacon::introduction_size_limit,
    },
    Witness {
        id: "closed_message_set_refuses_unknown_kinds",
        capabilities: &["library.beacon.wire_closed"],
        case: beacon::closed_message_set_refuses_unknown_kinds,
    },
    Witness {
        id: "version_mismatch_is_explicit",
        capabilities: &["library.beacon.wire_version"],
        case: beacon::version_mismatch_is_explicit,
    },
    Witness {
        id: "impostor_beacon_gives_no_answers",
        capabilities: &["library.beacon.pin"],
        case: beacon::impostor_beacon_gives_no_answers,
    },
    Witness {
        id: "unauthenticated_caller_gets_nothing",
        capabilities: &["library.beacon.auth"],
        case: beacon::unauthenticated_caller_gets_nothing,
    },
    Witness {
        id: "beacon_starts_and_stops",
        capabilities: &["harness.beacon.in_process_server"],
        case: beacon::beacon_starts_and_stops,
    },
    Witness {
        id: "addresses_round_trip",
        capabilities: &["library.beacon.address_codec"],
        case: beacon::addresses_round_trip,
    },
    Witness {
        id: "a_dead_beacon_is_noticed",
        capabilities: &["library.beacon.session_liveness"],
        case: beacon::a_dead_beacon_is_noticed,
    },
    Witness {
        id: "a_stalled_stream_is_refused",
        capabilities: &["library.beacon.exchange_bounded"],
        case: beacon::a_stalled_stream_is_refused,
    },
    Witness {
        id: "deadlines_are_ordered",
        capabilities: &["library.beacon.deadline_ordering"],
        case: beacon::deadlines_are_ordered,
    },
    Witness {
        id: "a_stalled_handshake_gives_its_place_back",
        capabilities: &["library.beacon.handshake_bounded"],
        case: beacon::a_stalled_handshake_gives_its_place_back,
    },
    Witness {
        id: "the_beacon_advertises_only_what_it_serves",
        capabilities: &["server.transport_advertisement"],
        case: server::the_beacon_advertises_only_what_it_serves,
    },
    Witness {
        id: "a_recipient_that_never_reads_does_not_stall_the_sender",
        capabilities: &["library.beacon.relay_bounded"],
        case: beacon::a_recipient_that_never_reads_does_not_stall_the_sender,
    },
    Witness {
        id: "server_config_parse",
        capabilities: &["server.config"],
        case: server::config_parse,
    },
    Witness {
        id: "server_connection_cap",
        capabilities: &["server.connection_cap"],
        case: server::connection_cap,
    },
    Witness {
        id: "endpoint_from_injected_seams",
        capabilities: &["library.net.injected_seams"],
        case: transport::endpoint_from_injected_seams,
    },
    Witness {
        id: "idle_timeout_bounds",
        capabilities: &["library.net.idle_timeout_bounds"],
        case: transport::idle_timeout_bounds,
    },
    Witness {
        id: "default_idle_timeout_applies",
        capabilities: &["library.net.default_idle_timeout"],
        case: transport::default_idle_timeout_applies,
    },
    Witness {
        id: "keep_alive_holds_a_quiet_connection",
        capabilities: &["library.net.keep_alive"],
        case: transport::keep_alive_holds_a_quiet_connection,
    },
    Witness {
        id: "alpn_mismatch_is_refused",
        capabilities: &["library.tls.alpn"],
        case: transport::alpn_mismatch_is_refused,
    },
    Witness {
        id: "inventory_check_is_two_way",
        capabilities: &["harness.check.inventory_two_way"],
        case: checks::inventory_check_is_two_way,
    },
    Witness {
        id: "procedures_are_runnable",
        capabilities: &["harness.inventory.procedures_are_runnable"],
        case: checks::procedures_are_runnable,
    },
    Witness {
        id: "invariant_check_is_two_way",
        capabilities: &["harness.check.invariant_two_way"],
        case: checks::invariant_check_is_two_way,
    },
    Witness {
        id: "ambient_forms_are_caught",
        capabilities: &["harness.invariant.ambient_forms"],
        case: checks::ambient_forms_are_caught,
    },
    Witness {
        id: "global_state_forms_are_caught",
        capabilities: &["harness.invariant.global_state_forms"],
        case: checks::global_state_forms_are_caught,
    },
    Witness {
        id: "machines_are_distinct",
        capabilities: &["harness.machine.disjoint_roots_and_identities"],
        case: machines::machines_are_distinct,
    },
    Witness {
        id: "foreign_root_is_refused",
        capabilities: &["harness.machine.root_isolation"],
        case: machines::foreign_root_is_refused,
    },
    Witness {
        id: "machines_are_disposed_independently",
        capabilities: &["harness.machine.independent_disposal"],
        case: machines::machines_are_disposed_independently,
    },
    Witness {
        id: "dead_root_is_refused",
        capabilities: &["harness.machine.dead_root_refused"],
        case: machines::dead_root_is_refused,
    },
    Witness {
        id: "machine_handle_names_no_path",
        capabilities: &["harness.machine.no_path_on_handle"],
        case: machines::machine_handle_names_no_path,
    },
    Witness {
        id: "addresses_are_exclusive",
        capabilities: &["harness.link.address_exclusivity"],
        case: link::addresses_are_exclusive,
    },
    Witness {
        id: "link_applies_scripted_faults",
        capabilities: &["harness.link.scripted_faults"],
        case: link::link_applies_scripted_faults,
    },
    Witness {
        id: "clock_never_goes_back",
        capabilities: &["harness.clock.monotonic"],
        case: clock::clock_never_goes_back,
    },
    Witness {
        id: "clock_fires_each_deadline_at_its_instant",
        capabilities: &["harness.clock.deadline_order"],
        case: clock::clock_fires_each_deadline_at_its_instant,
    },
    Witness {
        id: "a_spinning_case_is_stopped",
        capabilities: &["harness.clock.poll_budget"],
        case: clock::a_spinning_case_is_stopped,
    },
    Witness {
        id: "a_runaway_walk_is_stopped",
        capabilities: &["harness.clock.walk_is_bounded"],
        case: clock::a_runaway_walk_is_stopped,
    },
    Witness {
        id: "drive_bounds_a_parked_await",
        capabilities: &["harness.clock.drive_bounds_await"],
        case: clock::drive_bounds_a_parked_await,
    },
    Witness {
        id: "concurrent_dialers_pair_correctly",
        capabilities: &["harness.connect.concurrent_dialers"],
        case: transport::concurrent_dialers_pair_correctly,
    },
    Witness {
        id: "retry_after_an_abandoned_attempt",
        capabilities: &["harness.connect.retry_after_abandoned"],
        case: transport::retry_after_an_abandoned_attempt,
    },
    Witness {
        id: "retry_after_a_timeout",
        capabilities: &["harness.connect.retry_after_timeout"],
        case: transport::retry_after_a_timeout,
    },
    Witness {
        id: "closed_custom_endpoint_is_reported",
        capabilities: &["harness.connect.custom_endpoint"],
        case: transport::closed_custom_endpoint_is_reported,
    },
    Witness {
        id: "oversized_datagram_is_dropped",
        capabilities: &["harness.link.oversized_datagram_dropped"],
        case: link::oversized_datagram_is_dropped,
    },
    Witness {
        id: "link_trace_is_reproducible",
        capabilities: &["harness.link.seeded_reproducibility"],
        case: link::link_trace_is_reproducible,
    },
    Witness {
        id: "machine_address_can_change",
        capabilities: &["harness.link.address_change"],
        case: transport::machine_address_can_change,
    },
    Witness {
        id: "connect_times_out_on_a_dead_link",
        capabilities: &["harness.connect.dead_link_times_out"],
        case: transport::connect_times_out_on_a_dead_link,
    },
    Witness {
        id: "transport_timer_follows_clock",
        capabilities: &["harness.clock.drives_transport_timers"],
        case: transport::transport_timer_follows_clock,
    },
    Witness {
        id: "simulations_share_no_state",
        capabilities: &["harness.sim.no_shared_state"],
        case: machines::simulations_share_no_state,
    },
    Witness {
        id: "key_file_is_one_identity_per_root",
        capabilities: &["library.identity.key_file.one_identity_per_root"],
        case: identity::key_file_is_one_identity_per_root,
    },
    Witness {
        id: "key_file_is_created_once_under_race",
        capabilities: &["library.identity.key_file.created_once"],
        case: identity::key_file_is_created_once_under_race,
    },
    Witness {
        id: "key_file_refuses_a_broken_key",
        capabilities: &["library.identity.key_file.malformed"],
        case: identity::key_file_refuses_a_broken_key,
    },
    Witness {
        id: "unix_rule_is_exact",
        capabilities: &["library.identity.access.unix_rule"],
        case: identity::unix_rule_is_exact,
    },
    Witness {
        id: "extended_access_rule_is_exact",
        capabilities: &["library.identity.access.extended_rule"],
        case: identity::extended_access_rule_is_exact,
    },
    Witness {
        id: "windows_dacl_rule_is_exact",
        capabilities: &["library.identity.access.dacl_rule"],
        case: identity::windows_dacl_rule_is_exact,
    },
    Witness {
        id: "one_rendering_round_trips",
        capabilities: &["library.identity.one_rendering"],
        case: identity::one_rendering_round_trips,
    },
    Witness {
        id: "no_key_rotation_is_proven",
        capabilities: &["harness.invariant.no_key_rotation"],
        case: identity::no_key_rotation_is_proven,
    },
    Witness {
        id: "own_identity_is_refused",
        capabilities: &["library.tls.own_identity_refused"],
        case: transport::own_identity_is_refused,
    },
    Witness {
        id: "handshake_value_is_the_pinned_bytes",
        capabilities: &["library.tls.pinned_value"],
        case: transport::handshake_value_is_the_pinned_bytes,
    },
    Witness {
        id: "peer_record_round_trips",
        capabilities: &["library.peer.record.round_trip"],
        case: peer::peer_record_round_trips,
    },
    Witness {
        id: "peer_record_requires_its_root",
        capabilities: &["library.peer.record.root_required"],
        case: peer::peer_record_requires_its_root,
    },
    Witness {
        id: "peer_record_drops_expired_attempts",
        capabilities: &["library.peer.record.drops_expired_attempts"],
        case: peer::peer_record_drops_expired_attempts,
    },
    Witness {
        id: "peer_record_refuses_garbage",
        capabilities: &["library.peer.record.malformed"],
        case: peer::peer_record_refuses_garbage,
    },
    Witness {
        id: "peer_record_reads_unknown_fields",
        capabilities: &["library.peer.record.additive"],
        case: peer::peer_record_reads_unknown_fields,
    },
    Witness {
        id: "peer_record_never_unpairs",
        capabilities: &["library.peer.record.never_unpairs"],
        case: peer::peer_record_never_unpairs,
    },
    Witness {
        id: "peer_record_survives_restart",
        capabilities: &["library.peer.record.survives_restart"],
        case: peer::peer_record_survives_restart,
    },
    Witness {
        id: "peer_record_reload_sees_another_process",
        capabilities: &["library.peer.record.self_update_reload"],
        case: peer::peer_record_reload_sees_another_process,
    },
    Witness {
        id: "an_ending_without_a_term_is_not_a_record",
        capabilities: &["library.peer.record.ending_without_term"],
        case: peer::an_ending_without_a_term_is_not_a_record,
    },
    Witness {
        id: "peer_record_refuses_an_oversized_write",
        capabilities: &["library.peer.record.oversized_write"],
        case: peer::peer_record_refuses_an_oversized_write,
    },
    Witness {
        id: "peer_record_drops_an_empty_attempt",
        capabilities: &["library.peer.record.empty_attempt"],
        case: peer::peer_record_drops_an_empty_attempt,
    },
    Witness {
        id: "pairing_computes_one_string",
        capabilities: &["library.peer.pairing.same_string"],
        case: peer::pairing_computes_one_string,
    },
    Witness {
        id: "pairing_records_only_after_both_confirm",
        capabilities: &["library.peer.pairing.both_confirm"],
        case: peer::pairing_records_only_after_both_confirm,
    },
    Witness {
        id: "pairing_is_repeatable_until_both_hold",
        capabilities: &["library.peer.pairing.one_sided"],
        case: peer::pairing_is_repeatable_until_both_hold,
    },
    Witness {
        id: "pairing_refuses_own_identity",
        capabilities: &["library.peer.pairing.own_identity"],
        case: peer::pairing_refuses_own_identity,
    },
    Witness {
        id: "pairing_closes_after_three_rejections",
        capabilities: &["library.peer.pairing.attempt_limit"],
        case: peer::pairing_closes_after_three_rejections,
    },
    Witness {
        id: "pairing_attempt_expires",
        capabilities: &["library.peer.pairing.attempt_expiry"],
        case: peer::pairing_attempt_expires,
    },
    Witness {
        id: "pairing_failure_leaves_no_attempt",
        capabilities: &["library.peer.pairing.failure_leaves_no_attempt"],
        case: peer::pairing_failure_leaves_no_attempt,
    },
    Witness {
        id: "pairing_payload_never_carries_the_string",
        capabilities: &["library.peer.pairing.string_not_carried"],
        case: peer::pairing_payload_never_carries_the_string,
    },
    Witness {
        id: "pairing_ignores_a_foreign_opening",
        capabilities: &["library.peer.pairing.foreign_opening"],
        case: peer::pairing_ignores_a_foreign_opening,
    },
    Witness {
        id: "pairing_respond_waits_for_its_peer",
        capabilities: &["library.peer.pairing.respond_waits"],
        case: peer::pairing_respond_waits_for_its_peer,
    },
    Witness {
        id: "pairing_mediator_yields_different_strings",
        capabilities: &["library.peer.pairing.mediator", "harness.pair.mediator"],
        case: peer::pairing_mediator_yields_different_strings,
    },
    Witness {
        id: "pairing_simultaneous_start_keeps_one",
        capabilities: &["library.peer.pairing.simultaneous"],
        case: peer::pairing_simultaneous_start_keeps_one,
    },
    Witness {
        id: "pairing_tolerates_a_reordered_opening",
        capabilities: &["library.peer.pairing.reordered_opening"],
        case: peer::pairing_tolerates_a_reordered_opening,
    },
    Witness {
        id: "pairing_rejects_a_replayed_flight",
        capabilities: &["library.peer.pairing.bound_flights"],
        case: peer::pairing_rejects_a_replayed_flight,
    },
    Witness {
        id: "pairing_respond_ignores_a_foreign_payload",
        capabilities: &["library.peer.pairing.respond_ignores_strangers"],
        case: peer::pairing_respond_ignores_a_foreign_payload,
    },
    Witness {
        id: "pairing_flight_timeout_is_not_a_beacon_outage",
        capabilities: &["library.peer.pairing.flight_timeout"],
        case: peer::pairing_flight_timeout_is_not_a_beacon_outage,
    },
    Witness {
        id: "pairing_attempt_expiry_is_its_own_failure",
        capabilities: &["library.peer.pairing.attempt_expired"],
        case: peer::pairing_attempt_expiry_is_its_own_failure,
    },
    Witness {
        id: "pairing_abandoned_comparison_expires",
        capabilities: &["library.peer.pairing.person_wait"],
        case: peer::pairing_abandoned_comparison_expires,
    },
    Witness {
        id: "pairing_then_direct_connection",
        capabilities: &["library.peer.connect.direct"],
        case: connection::pairing_then_direct_connection,
    },
    Witness {
        id: "reconnect_uses_remembered_address_first",
        capabilities: &["library.peer.connect.remembered_first"],
        case: connection::reconnect_uses_remembered_address_first,
    },
    Witness {
        id: "connect_with_tries_the_hint_first",
        capabilities: &["library.peer.connect.hint_first"],
        case: connection::connect_with_tries_the_hint_first,
    },
    Witness {
        id: "reconnect_falls_back_to_the_beacon",
        capabilities: &["library.peer.connect.beacon_second"],
        case: connection::reconnect_falls_back_to_the_beacon,
    },
    Witness {
        id: "reconnect_stops_after_both_fail",
        capabilities: &["library.peer.connect.stops"],
        case: connection::reconnect_stops_after_both_fail,
    },
    Witness {
        id: "four_failures_are_distinct",
        capabilities: &["library.peer.connect.four_failures"],
        case: connection::four_failures_are_distinct,
    },
    Witness {
        id: "manager_refuses_an_unwatchable_transport",
        capabilities: &["library.peer.connect.unwatchable_transport"],
        case: connection::manager_refuses_an_unwatchable_transport,
    },
    Witness {
        id: "one_connection_per_pair",
        capabilities: &["library.peer.connect.one_per_pair"],
        case: connection::one_connection_per_pair,
    },
    Witness {
        id: "asymmetric_liveness_does_not_split_the_pair",
        capabilities: &["library.peer.connect.asymmetric_liveness"],
        case: connection::asymmetric_liveness_does_not_split_the_pair,
    },
    Witness {
        id: "closed_pair_is_not_trusted",
        capabilities: &["library.peer.connect.closed_not_trusted"],
        case: connection::closed_pair_is_not_trusted,
    },
    Witness {
        id: "same_starter_tie_break_keeps_one",
        capabilities: &["library.peer.connect.same_starter"],
        case: connection::same_starter_tie_break_keeps_one,
    },
    Witness {
        id: "tie_break_closes_the_dropped_connection",
        capabilities: &["library.peer.connect.tie_break_closes"],
        case: connection::tie_break_closes_the_dropped_connection,
    },
    Witness {
        id: "tie_break_drop_records_no_address",
        capabilities: &["library.peer.connect.tie_break_teaches_no_address"],
        case: connection::tie_break_drop_records_no_address,
    },
    Witness {
        id: "closed_connection_is_not_live",
        capabilities: &["library.peer.connect.closed_not_live"],
        case: connection::closed_connection_is_not_live,
    },
    Witness {
        id: "reconnect_cause_names_the_remembered_address",
        capabilities: &["library.peer.connect.remembered_cause"],
        case: connection::reconnect_cause_names_the_remembered_address,
    },
    Witness {
        id: "pairing_then_reconnect_after_restart",
        capabilities: &["library.peer.connect.reconnect_after_restart"],
        case: connection::pairing_then_reconnect_after_restart,
    },
    Witness {
        id: "keeper_reconnects_without_a_caller",
        capabilities: &["library.peer.connect.keep_connected"],
        case: connection::keeper_reconnects_without_a_caller,
    },
    Witness {
        id: "keeper_stops_when_the_peer_keeps_closing",
        capabilities: &["library.peer.connect.keeper_bound"],
        case: connection::keeper_stops_when_the_peer_keeps_closing,
    },
    Witness {
        id: "keeper_stops_when_a_dial_fails",
        capabilities: &["library.peer.connect.keeper_failed"],
        case: connection::keeper_stops_when_a_dial_fails,
    },
    Witness {
        id: "keeper_survives_a_failed_dial_while_the_pair_connects",
        capabilities: &["library.peer.connect.transient_adoption"],
        case: connection::keeper_survives_a_failed_dial_while_the_pair_connects,
    },
    Witness {
        id: "keeper_resets_after_a_settled_connection",
        capabilities: &["library.peer.connect.keeper_settle"],
        case: connection::keeper_resets_after_a_settled_connection,
    },
    Witness {
        id: "keeper_survives_a_supersession",
        capabilities: &["library.peer.connect.keeper_supersession"],
        case: connection::keeper_survives_a_supersession,
    },
    Witness {
        id: "keeper_redials_a_link_failure",
        capabilities: &["library.peer.connect.keeper_link_failure"],
        case: connection::keeper_redials_a_link_failure,
    },
    Witness {
        id: "keeper_redials_a_used_connection",
        capabilities: &["library.peer.connect.keeper_carried"],
        case: connection::keeper_redials_a_used_connection,
    },
    Witness {
        id: "pairing_restart_then_keeper_reconnects",
        capabilities: &["library.peer.connect.keeper_after_restart"],
        case: connection::pairing_restart_then_keeper_reconnects,
    },
    Witness {
        id: "quiet_pair_stays_connected",
        capabilities: &["library.net.quiet_pair_default"],
        case: connection::quiet_pair_stays_connected,
    },
    Witness {
        id: "connection_binding_is_decided_by_one_machine",
        capabilities: &[
            "library.peer.access.binding",
            "library.peer.access.claim_not_authority",
        ],
        case: rights::connection_binding_is_decided_by_one_machine,
    },
    Witness {
        id: "default_issues_write_to_me_and_nothing_else",
        capabilities: &["library.peer.rights.default_write"],
        case: rights::default_issues_write_to_me_and_nothing_else,
    },
    Witness {
        id: "the_default_never_acts_again",
        capabilities: &["library.peer.rights.default_once"],
        case: rights::the_default_never_acts_again,
    },
    Witness {
        id: "a_guest_assistant_gets_the_default_and_a_person_may_widen_it",
        capabilities: &["library.peer.rights.guest_widened"],
        case: rights::a_guest_assistant_gets_the_default_and_a_person_may_widen_it,
    },
    Witness {
        id: "a_right_withdrawn_refuses_the_next_question",
        capabilities: &["library.peer.rights.withdrawn"],
        case: rights::a_right_withdrawn_refuses_the_next_question,
    },
    Witness {
        id: "a_right_that_ends_refuses_and_is_recorded_once",
        capabilities: &["library.peer.rights.ended"],
        case: rights::a_right_that_ends_refuses_and_is_recorded_once,
    },
    Witness {
        id: "the_hosts_floor_refuses_a_granted_right_and_the_grant_stays",
        capabilities: &["library.peer.rights.floor"],
        case: rights::the_hosts_floor_refuses_a_granted_right_and_the_grant_stays,
    },
    Witness {
        id: "a_peer_attributed_write_is_refused_and_recorded",
        capabilities: &["library.peer.rights.remote_write"],
        case: rights::a_peer_attributed_write_is_refused_and_recorded,
    },
    Witness {
        id: "an_untrusted_machine_is_refused_before_any_right",
        capabilities: &["library.peer.rights.untrusted"],
        case: rights::an_untrusted_machine_is_refused_before_any_right,
    },
    Witness {
        id: "an_unauthenticated_question_is_refused",
        capabilities: &["library.peer.rights.unauthenticated"],
        case: rights::an_unauthenticated_question_is_refused,
    },
    Witness {
        id: "rights_survive_a_restart_of_both_machines",
        capabilities: &["library.peer.rights.survive_restart"],
        case: rights::rights_survive_a_restart_of_both_machines,
    },
    Witness {
        id: "withdrawing_trust_removes_the_rights",
        capabilities: &["library.peer.rights.trust_withdrawn"],
        case: rights::withdrawing_trust_removes_the_rights,
    },
    Witness {
        id: "restoring_trust_reissues_only_the_default",
        capabilities: &["library.peer.rights.trust_restored"],
        case: rights::restoring_trust_reissues_only_the_default,
    },
    Witness {
        id: "restoring_trust_issues_the_default_for_the_binding_pair",
        capabilities: &["library.peer.rights.restore_binding"],
        case: rights::restoring_trust_issues_the_default_for_the_binding_pair,
    },
    Witness {
        id: "a_moved_machine_starts_from_the_new_pairs_default",
        capabilities: &["library.peer.rights.moved_pair"],
        case: rights::a_moved_machine_starts_from_the_new_pairs_default,
    },
    Witness {
        id: "a_question_for_a_pair_the_machine_left_is_refused",
        capabilities: &["library.peer.rights.bound_pair_only"],
        case: rights::a_question_for_a_pair_the_machine_left_is_refused,
    },
    Witness {
        id: "clearing_the_attempt_lock_is_recorded",
        capabilities: &["library.peer.rights.attempt_lock"],
        case: rights::clearing_the_attempt_lock_is_recorded,
    },
    Witness {
        id: "clearing_an_open_lock_records_nothing",
        capabilities: &["library.peer.rights.attempt_lock_open"],
        case: rights::clearing_an_open_lock_records_nothing,
    },
    Witness {
        id: "a_return_finishes_what_it_started",
        capabilities: &["library.peer.rights.return_idempotent"],
        case: rights::a_return_finishes_what_it_started,
    },
    Witness {
        id: "a_return_reports_a_still_closed_pair",
        capabilities: &["library.peer.rights.return_closed"],
        case: rights::a_return_reports_a_still_closed_pair,
    },
    Witness {
        id: "the_audit_discards_a_torn_tail",
        capabilities: &["library.peer.audit.torn_tail"],
        case: rights::the_audit_discards_a_torn_tail,
    },
    Witness {
        id: "an_append_cuts_a_torn_tail_left_by_another_process",
        capabilities: &["library.peer.audit.torn_tail_on_append"],
        case: rights::an_append_cuts_a_torn_tail_left_by_another_process,
    },
    Witness {
        id: "a_torn_tail_past_the_cap_is_cut_before_the_cap_is_judged",
        capabilities: &["library.peer.audit.torn_tail_past_cap"],
        case: rights::a_torn_tail_past_the_cap_is_cut_before_the_cap_is_judged,
    },
    Witness {
        id: "a_full_log_keeps_room_for_a_person",
        capabilities: &["library.peer.audit.person_room"],
        case: rights::a_full_log_keeps_room_for_a_person,
    },
    Witness {
        id: "an_ending_with_no_room_is_answered_without_marking_the_row",
        capabilities: &["library.peer.audit.ending_room"],
        case: rights::an_ending_with_no_room_is_answered_without_marking_the_row,
    },
    Witness {
        id: "the_audit_repairs_a_torn_header",
        capabilities: &["library.peer.audit.torn_header"],
        case: rights::the_audit_repairs_a_torn_header,
    },
    Witness {
        id: "an_audit_field_with_bytes_after_its_label_keeps_its_code",
        capabilities: &["library.peer.audit.label_rule"],
        case: rights::an_audit_field_with_bytes_after_its_label_keeps_its_code,
    },
    Witness {
        id: "every_refusal_names_its_own_step",
        capabilities: &["library.peer.rights.steps"],
        case: rights::every_refusal_names_its_own_step,
    },
    Witness {
        id: "the_audit_records_every_act",
        capabilities: &["library.peer.audit.every_act"],
        case: rights::the_audit_records_every_act,
    },
    Witness {
        id: "the_defaults_already_held_entry_names_the_person",
        capabilities: &["library.peer.audit.already_held"],
        case: rights::the_defaults_already_held_entry_names_the_person,
    },
    Witness {
        id: "a_right_for_an_unknown_capability_is_never_satisfied",
        capabilities: &["library.peer.record.unknown_capability"],
        case: rights::a_right_for_an_unknown_capability_is_never_satisfied,
    },
    Witness {
        id: "a_claim_keeps_the_newer_decision",
        capabilities: &["library.peer.access.claim_newest"],
        case: binding::a_claim_keeps_the_newer_decision,
    },
    Witness {
        id: "a_fact_of_a_newer_version_is_read_as_this_versions_prefix",
        capabilities: &["library.peer.access.fact_version"],
        case: binding::a_fact_of_a_newer_version_is_read_as_this_versions_prefix,
    },
    Witness {
        id: "a_label_is_a_name_a_person_can_be_shown",
        capabilities: &["library.peer.access.label_rules"],
        case: binding::a_label_is_a_name_a_person_can_be_shown,
    },
    Witness {
        id: "a_malformed_fact_changes_nothing",
        capabilities: &["library.peer.access.fact_malformed"],
        case: binding::a_malformed_fact_changes_nothing,
    },
    Witness {
        id: "a_peer_without_a_binding_leaves_no_claim",
        capabilities: &["library.peer.binding.no_fact"],
        case: binding::a_peer_without_a_binding_leaves_no_claim,
    },
    Witness {
        id: "a_binding_only_connection_carried_nothing",
        capabilities: &["library.peer.connect.binding_not_traffic"],
        case: binding::a_binding_only_connection_carried_nothing,
    },
    Witness {
        id: "a_withdrawn_machine_is_not_reached",
        capabilities: &["library.peer.connect.withdrawn_stops"],
        case: binding::a_withdrawn_machine_is_not_reached,
    },
    Witness {
        id: "a_withdrawal_is_seen_by_another_store",
        capabilities: &["library.peer.connect.withdrawn_any_store"],
        case: binding::a_withdrawal_is_seen_by_another_store,
    },
    Witness {
        id: "the_tls_configurations_offer_no_resumption",
        capabilities: &["library.tls.resumption_off"],
        case: transport::the_tls_configurations_offer_no_resumption,
    },
    Witness {
        id: "a_rebind_takes_effect_at_the_next_connection",
        capabilities: &["library.peer.access.rebind"],
        case: binding::a_rebind_takes_effect_at_the_next_connection,
    },
    Witness {
        id: "a_right_withdrawn_or_ended_while_connected_refuses",
        capabilities: &[
            "library.peer.rights.withdrawn_while_connected",
            "library.peer.rights.ended_while_connected",
        ],
        case: binding::a_right_withdrawn_or_ended_while_connected_refuses,
    },
    Witness {
        id: "a_withdrawal_by_another_store_refuses_the_next_question",
        capabilities: &["library.peer.rights.fresh_view"],
        case: binding::a_withdrawal_by_another_store_refuses_the_next_question,
    },
    Witness {
        id: "presence_keeps_registration_alive",
        capabilities: &["library.peer.presence.refresh"],
        case: connection::presence_keeps_registration_alive,
    },
    Witness {
        id: "machine_restarts_over_the_same_root",
        capabilities: &["harness.machine.restart"],
        case: connection::machine_restarts_over_the_same_root,
    },
];

// The host-independent part of the table, which the platform tables add to. This is
// the floor that keeps a shrinking table from looking like a pass.
const _: () = assert!(WITNESSES.len() >= 119, "the shared witness table shrank");
