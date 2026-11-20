//! The summary checks: cross-cutting claims, made once over the whole workspace.
//!
//! These are the tests that must not pass vacuously. The inventory check runs
//! every recorded case and refuses both a capability with no case and a case for
//! a capability that no longer exists; each table asserts its host-independent
//! floor at compile time, so what is compared here is exactly what the host
//! composes. The invariant check scans every source file and refuses an empty
//! scan, an invariant whose own control it fails to catch, and an invariant that
//! does not hold. A source file may be exempt from named invariants: `check` itself
//! keeps the exemption narrow (nothing the file still trips goes unreported), and
//! the test below proves it load-bearing (every exempted invariant still trips it).
//! Every scanned source must also belong to a declared scope, so a new crate cannot
//! sit outside the claims about shipped code.
//!
//! The checks themselves are proven able to fail in-process by two cases in the
//! witness table (`harness.check.*`), which the first test runs like any other.

use mahbot_peers_harness::invariants::{
    ENTRY_FILE, EXEMPT, INVARIANTS, SHIPPED_SCOPE, Source, UNSHIPPED_SCOPE,
    check as check_invariants, find, workspace_sources,
};
use mahbot_peers_harness::inventory::{capabilities, check};
use mahbot_peers_harness::witnesses;

#[test]
fn every_capability_has_a_witness_and_every_witness_a_capability() {
    let report = check(&capabilities(), &witnesses::witnesses());
    assert!(report.is_ok(), "{}", report.describe());
}

#[test]
fn invariants_hold_over_every_source() {
    let sources = workspace_sources();
    assert!(
        sources.len() >= 40,
        "the scan covered {} files; an empty scan must not look like a pass",
        sources.len()
    );
    let report = check_invariants(INVARIANTS, &sources);
    assert!(report.is_ok(), "{}", report.describe());
}

#[test]
fn every_exemption_is_exactly_the_invariants_the_entry_point_trips() {
    assert_eq!(
        EXEMPT.len(),
        1,
        "the scan exempts {} files; a second exception must be argued for here",
        EXEMPT.len()
    );
    assert_eq!(EXEMPT[0].path, ENTRY_FILE);
    assert!(
        !EXEMPT[0].reason.trim().is_empty(),
        "an exemption without a reason is not documented"
    );

    // That the file trips nothing outside this list is what `check` enforces in
    // `invariants_hold_over_every_source`: it skips only the named claims. What
    // needs saying here is the other direction — an exemption the file no longer
    // needs is a stale excuse — and that every named id really covers the file,
    // since a typo would excuse nothing and pass quietly.
    let sources = workspace_sources();
    let source = entry_source(&sources);
    assert_eq!(
        EXEMPT[0].exempt_from.len(),
        3,
        "a fourth exemption needs the entry point's docs and the README updated with it"
    );
    for id in EXEMPT[0].exempt_from {
        let invariant = find(id).expect("an exemption names a listed invariant");
        assert!(
            invariant.covers(&source.path),
            "{id} does not cover {ENTRY_FILE}, so exempting it excuses nothing"
        );
        assert!(
            !(invariant.check)(source).is_empty(),
            "{id} no longer trips {ENTRY_FILE}; drop the exemption"
        );
    }
}

#[test]
fn the_persistent_state_invariant_covers_every_beacon_library_source() {
    let invariant = find("beacon.no_persistent_state")
        .expect("the beacon's no-state-on-disk invariant is listed");
    let sources = workspace_sources();
    let library_sources: Vec<&Source> = sources
        .iter()
        .filter(|source| {
            source.path.starts_with("src/beacon") || source.path.starts_with("beacon/")
        })
        .collect();
    assert!(
        !library_sources.is_empty(),
        "the beacon's library sources are not in the scan"
    );
    // The scope is a hand-kept list; a new file in the beacon's library must be
    // added to it, not silently left outside the claim.
    for source in library_sources {
        assert!(
            invariant.covers(&source.path),
            "{} is outside the no-state-on-disk invariant; add it to the scope",
            source.path
        );
    }
    // The process entry point is not part of it: it binds the socket and writes the
    // key file, so its key handling is scanned by the identity claims instead.
    assert!(
        !invariant.covers(ENTRY_FILE),
        "the entry point became part of the beacon's no-state claim; the claim is about the library"
    );
}

#[test]
fn the_entry_point_is_scanned_by_the_key_name_invariant() {
    assert!(
        find("identity.key_file_name_is_one_place")
            .expect("the key file's name is an invariant")
            .covers(ENTRY_FILE),
        "the entry point's key handling is not scanned at all"
    );
}

/// The shipped scope is a hand-kept list, so a crate added beside the listed ones
/// would be scanned and yet outside every claim scoped to shipped code — the
/// key-name invariant included. Every scanned source must be in one list or the
/// other, which makes adding a crate a deliberate act.
#[test]
fn every_scanned_source_is_shipped_code_or_the_test_rig() {
    for source in workspace_sources() {
        let listed = SHIPPED_SCOPE
            .iter()
            .chain(UNSHIPPED_SCOPE)
            .any(|scope| source.path.starts_with(scope));
        assert!(
            listed,
            "{} is scanned but in neither scope: add its crate to SHIPPED_SCOPE if it ships, or its tree to UNSHIPPED_SCOPE if it is test rig or dev tooling",
            source.path
        );
    }
}

/// The beacon's no-state claim has a hand-kept scope, so a second source in the
/// entry-point crate would sit outside it unseen. The crate holds the entry point
/// and nothing else.
#[test]
fn the_beacon_entry_crate_holds_only_the_entry_point() {
    let sources = workspace_sources();
    let entry_crate: Vec<&str> = sources
        .iter()
        .filter(|source| source.path.starts_with("beacon-server/"))
        .map(|source| source.path.as_str())
        .collect();
    assert_eq!(
        entry_crate,
        [ENTRY_FILE],
        "a second source in the entry-point crate must be added to the beacon's no-state claim or exempted here"
    );
}

/// The entry point as the source scan sees it.
fn entry_source(sources: &[Source]) -> &Source {
    sources
        .iter()
        .find(|source| source.path == ENTRY_FILE)
        .expect("the entry point is in the scan")
}
