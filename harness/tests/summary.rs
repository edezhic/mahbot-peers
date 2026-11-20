//! The summary checks: cross-cutting claims, made once over the whole workspace.
//!
//! These are the tests that must not pass vacuously. The inventory check runs
//! every recorded case and refuses both a capability with no case and a case for
//! a capability that no longer exists. The invariant check scans every source
//! file and refuses an empty scan, an invariant whose own control it fails to
//! catch, and an invariant that does not hold.
//!
//! The checks themselves are proven able to fail in-process by two cases in the
//! witness table (`harness.check.*`), which the first test runs like any other.

use std::path::Path;

use mahbot_peers_harness::invariants::{
    ENTRY_FILE, EXCLUDED, INVARIANTS, Source, check as check_invariants, find, workspace_sources,
};
use mahbot_peers_harness::inventory::{CAPABILITIES, check};
use mahbot_peers_harness::witnesses;

#[test]
fn every_capability_has_a_witness_and_every_witness_a_capability() {
    let report = check(CAPABILITIES, witnesses::WITNESSES);
    assert!(
        report.scanned() >= 59,
        "the check scanned {} capabilities; a shrinking inventory must not look like a pass",
        report.scanned()
    );
    assert!(
        report.checked() >= 57,
        "the table holds {} witnesses; a shrinking table must not look like a pass",
        report.checked()
    );
    assert!(report.is_ok(), "{}", report.describe());
}

#[test]
fn invariants_hold_over_every_source() {
    let sources = workspace_sources();
    assert!(
        sources.len() >= 35,
        "the scan covered {} files; an empty scan must not look like a pass",
        sources.len()
    );
    let report = check_invariants(INVARIANTS, &sources);
    assert_eq!(
        report.scanned(),
        sources.len(),
        "the check walked {} of {} files",
        report.scanned(),
        sources.len()
    );
    assert!(report.is_ok(), "{}", report.describe());
}

#[test]
fn the_excluded_surface_is_exactly_the_beacon_entry_point() {
    assert_eq!(
        EXCLUDED.len(),
        1,
        "the scan excludes {} files; a second exception must be argued for here",
        EXCLUDED.len()
    );
    assert_eq!(EXCLUDED[0].path, ENTRY_FILE);
    assert!(
        !EXCLUDED[0].reason.trim().is_empty(),
        "an exclusion without a reason is not documented"
    );

    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the harness sits in the workspace");
    let entry = root.join(EXCLUDED[0].path);
    let text = std::fs::read_to_string(&entry).expect("the excluded entry point exists");
    let source = Source {
        path: EXCLUDED[0].path.to_owned(),
        text,
    };
    // The exception is load-bearing: the file is flagged by at least one
    // invariant, so it still needs it. A file that stopped needing the exclusion
    // must lose it rather than keep a stale excuse.
    assert!(
        INVARIANTS
            .iter()
            .filter(|invariant| invariant.covers(&source.path))
            .any(|invariant| !(invariant.check)(&source).is_empty()),
        "the excluded entry point no longer needs its exclusion; remove it"
    );
}

#[test]
fn the_persistent_state_invariant_covers_every_beacon_source() {
    let invariant = find("beacon.no_persistent_state")
        .expect("the beacon's no-state-on-disk invariant is listed");
    let sources = workspace_sources();
    let beacon_sources: Vec<&Source> = sources
        .iter()
        .filter(|source| {
            source.path == "src/beacon.rs"
                || source.path.starts_with("src/beacon/")
                || source.path.starts_with("beacon/")
                || source.path.starts_with("beacon-server/")
        })
        .collect();
    assert!(
        !beacon_sources.is_empty(),
        "the beacon's sources are not in the scan"
    );
    // The invariant's scope is a hand-kept list; a new file under the beacon must
    // be added to it, not silently left outside the claim. Every file in the
    // entry-point crate is either the one documented exclusion or inside the
    // claim, because the scan walks that crate and skips only `EXCLUDED`.
    for source in beacon_sources {
        assert!(
            invariant.covers(&source.path),
            "{} is outside the no-state-on-disk invariant; add it to the scope",
            source.path
        );
    }
}
