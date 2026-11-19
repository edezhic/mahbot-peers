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

use mahbot_peers_harness::invariants::{INVARIANTS, check as check_invariants, workspace_sources};
use mahbot_peers_harness::inventory::{CAPABILITIES, check};
use mahbot_peers_harness::witnesses;

#[test]
fn every_capability_has_a_witness_and_every_witness_a_capability() {
    let report = check(CAPABILITIES, witnesses::WITNESSES);
    assert!(
        report.scanned() >= 38,
        "the check scanned {} capabilities; a shrinking inventory must not look like a pass",
        report.scanned()
    );
    assert!(
        report.checked() >= 37,
        "the check ran {} witnesses; a shrinking table must not look like a pass",
        report.checked()
    );
    assert!(report.is_ok(), "{}", report.describe());
}

#[test]
fn invariants_hold_over_every_source() {
    let sources = workspace_sources();
    assert!(
        sources.len() >= 20,
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
