//! The two-way checks: the inventory check and the invariant check must each
//! catch a broken entry as well as pass a good one.

use std::fmt;

use crate::invariants::{
    Invariant, Violation as InvariantViolation, check as check_invariants, forbidden,
};
use crate::inventory::{
    Capability, Violation as InventoryViolation, Witness, check as check_inventory,
};
use crate::report::Report;

use super::support::source;

fn ok_case() -> Result<(), String> {
    Ok(())
}

fn failing_case() -> Result<(), String> {
    Err("the claim does not hold".to_owned())
}

fn panicking_case() -> Result<(), String> {
    panic!("this case cannot answer");
}

fn must_report<V>(report: &Report<V>, expected: &V) -> Result<(), String>
where
    V: PartialEq + fmt::Display,
{
    if report.violations.contains(expected) {
        Ok(())
    } else {
        Err(format!("expected {expected}, got: {}", report.describe()))
    }
}

fn must_report_where<V>(
    report: &Report<V>,
    what: &str,
    predicate: impl Fn(&V) -> bool,
) -> Result<(), String>
where
    V: fmt::Display,
{
    if report.violations.iter().any(predicate) {
        Ok(())
    } else {
        Err(format!("expected {what}, got: {}", report.describe()))
    }
}

/// The procedure rules, run over every recorded procedure whatever this host can
/// produce: a capability that carries one on this host is judged even when this host
/// witnesses the state it describes, so a stale procedure cannot hide behind a passing
/// case. Each entry carries its own text, so there is no id to type twice.
pub(crate) fn procedures_are_runnable() -> Result<(), String> {
    let recorded: Vec<(&'static str, &'static str)> = crate::inventory::capabilities()
        .into_iter()
        .filter_map(|entry| entry.procedure.map(|how| (entry.id, how)))
        .collect();
    // A record nobody can read is as bad as none: the floor keeps a shrinking identity
    // set from looking like a pass. The two procedures outside that module are judged
    // too but do not count towards the six.
    let identity = recorded
        .iter()
        .filter(|(id, _)| id.starts_with("library.identity."))
        .count();
    if identity < 6 {
        return Err(format!(
            "{identity} identity procedures are recorded, not the six the module has"
        ));
    }
    for (id, how) in &recorded {
        let violations = crate::inventory::procedure_violations(id, how);
        if !violations.is_empty() {
            return Err(format!(
                "the procedure for {id} breaks {} rule(s): {}",
                violations.len(),
                violations
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        }
    }
    Ok(())
}

pub(crate) fn inventory_check_is_two_way() -> Result<(), String> {
    let claim = Capability::witnessed("test.claim", "a claim");
    let case = |case: fn() -> Result<(), String>| Witness {
        id: "test.case",
        capability: "test.claim",
        case,
    };

    let sound = check_inventory(&[claim], &[case(ok_case)]);
    if !sound.is_ok() || sound.scanned() != 1 || sound.checked() != 1 {
        return Err(format!(
            "a sound inventory did not pass: {}",
            sound.describe()
        ));
    }
    let empty = check_inventory(&[], &[]);
    must_report(&empty, &InventoryViolation::NoCapabilities)?;
    let impossible = check_inventory(
        &[Capability::unproducible(
            "test.impossible",
            "a claim",
            "no case can exist here",
            "a host that can runs the procedure",
        )],
        &[Witness {
            id: "test.case",
            capability: "test.impossible",
            case: ok_case,
        }],
    );
    must_report(
        &impossible,
        &InventoryViolation::WitnessForUnproducible {
            witness: "test.case",
            capability: "test.impossible",
        },
    )?;
    must_report(
        &check_inventory(&[claim], &[]),
        &InventoryViolation::Unwitnessed {
            capability: "test.claim",
        },
    )?;
    must_report(
        &check_inventory(
            &[],
            &[Witness {
                id: "test.case",
                capability: "test.gone",
                case: ok_case,
            }],
        ),
        &InventoryViolation::OrphanWitness {
            witness: "test.case",
            capability: "test.gone",
        },
    )?;
    must_report_where(
        &check_inventory(&[claim], &[case(failing_case)]),
        "a failing case",
        |violation| matches!(violation, InventoryViolation::Failed { witness, .. } if *witness == "test.case"),
    )?;
    must_report_where(
        &check_inventory(
            &[Capability::unproducible(
                "test.blank",
                "a claim",
                "   ",
                "a procedure",
            )],
            &[],
        ),
        "an unproducible entry with no reason",
        |violation| matches!(violation, InventoryViolation::NoReason { .. }),
    )?;
    must_report_where(
        &check_inventory(
            &[Capability::unproducible(
                "test.blank",
                "a claim",
                "a reason",
                "   ",
            )],
            &[],
        ),
        "an unproducible entry with no procedure",
        |violation| matches!(violation, InventoryViolation::NoProcedure { .. }),
    )?;
    must_report_where(
        &check_inventory(
            &[Capability::unproducible(
                "test.placeholder",
                "a claim",
                "a reason",
                "run `chmod 644 <root>/identity.key`",
            )],
            &[],
        ),
        "an unproducible entry with a placeholder",
        |violation| {
            matches!(
                violation,
                InventoryViolation::Placeholder {
                    placeholder: "<root>",
                    ..
                }
            )
        },
    )?;
    must_report_where(
        &check_inventory(
            &[Capability::unproducible(
                "test.live",
                "a claim",
                "a reason",
                "run `chmod 644 identity.key` in the product's own root",
            )],
            &[],
        ),
        "an unproducible entry that changes a live key file",
        |violation| matches!(violation, InventoryViolation::NotOnScratchRoot { .. }),
    )?;
    must_report_where(
        &check_inventory(
            &[Capability::unproducible(
                "test.stale",
                "a claim",
                "a reason",
                "it offers the repair `chmod 600 it`",
            )],
            &[],
        ),
        "an unproducible entry quoting a pathless repair",
        |violation| matches!(violation, InventoryViolation::PathlessCommand { .. }),
    )?;
    must_report_where(
        &check_inventory(&[claim], &[case(panicking_case)]),
        "a case that panicked",
        |violation| matches!(violation, InventoryViolation::Panicked { witness, .. } if *witness == "test.case"),
    )?;
    let duplicated = check_inventory(&[claim, claim], &[case(ok_case), case(ok_case)]);
    must_report(
        &duplicated,
        &InventoryViolation::DuplicateCapability("test.claim"),
    )?;
    must_report(
        &duplicated,
        &InventoryViolation::DuplicateWitness("test.case"),
    )
}

fn needle_invariant() -> Invariant {
    Invariant {
        id: "test.needle",
        claim: "a source containing the needle is reported",
        scope: &[],
        control: "let forbidden_needle = 1;",
        check: |source| forbidden(source, &["forbidden_needle"]),
    }
}

/// The process-global-state scanner must catch every way a `static` can be
/// written and leave look-alikes alone: the claim it enforces is only as wide as
/// its needles.
pub(crate) fn global_state_forms_are_caught() -> Result<(), String> {
    let invariant = crate::invariants::find("workspace.no_process_global_state")
        .ok_or_else(|| "the process-global-state invariant is not in the table".to_owned())?;
    for form in crate::invariants::STATIC_FORMS {
        if (invariant.check)(&source("test.rs", form)).is_empty() {
            return Err(format!("the scanner missed `{form}`"));
        }
    }
    for clean in crate::invariants::STATIC_LOOKALIKES {
        if !(invariant.check)(&source("test.rs", clean)).is_empty() {
            return Err(format!("the scanner flagged the clean line `{clean}`"));
        }
    }
    Ok(())
}

/// The ambient-configuration scanner must catch every way the process's own
/// environment can be read, and leave look-alikes alone: the claim it enforces is
/// only as wide as its needles.
pub(crate) fn ambient_forms_are_caught() -> Result<(), String> {
    let invariant = crate::invariants::find("workspace.no_ambient_configuration")
        .ok_or_else(|| "the ambient-configuration invariant is not in the table".to_owned())?;
    for form in crate::invariants::AMBIENT_FORMS {
        if (invariant.check)(&source("test.rs", form)).is_empty() {
            return Err(format!("the scanner missed `{form}`"));
        }
    }
    for clean in crate::invariants::AMBIENT_LOOKALIKES {
        if !(invariant.check)(&source("test.rs", clean)).is_empty() {
            return Err(format!("the scanner flagged the clean line `{clean}`"));
        }
    }
    Ok(())
}

pub(crate) fn invariant_check_is_two_way() -> Result<(), String> {
    let invariant = needle_invariant();
    let clean = check_invariants(&[invariant], &[source("test.rs", "let clean = 1;")]);
    if !clean.is_ok() || clean.scanned() != 1 || clean.checked() != 1 {
        return Err(format!("a clean scan did not pass: {}", clean.describe()));
    }
    must_report(
        &check_invariants(
            &[invariant, invariant],
            &[source("test.rs", "let clean = 1;")],
        ),
        &InvariantViolation::Duplicate("test.needle"),
    )?;
    let empty = check_invariants(&[invariant], &[]);
    if empty.violations != vec![InvariantViolation::ScannedNothing] {
        return Err(format!(
            "an empty scan reported more or less than its own emptiness: {}",
            empty.describe()
        ));
    }
    let blind = Invariant {
        id: "test.blind",
        claim: "a check that cannot fail",
        scope: &[],
        control: "nothing to see here",
        check: |source| forbidden(source, &["forbidden_needle"]),
    };
    must_report(
        &check_invariants(&[blind], &[source("test.rs", "let clean = 1;")]),
        &InvariantViolation::ControlNotCaught {
            invariant: "test.blind",
        },
    )?;
    must_report_where(
        &check_invariants(
            &[invariant],
            &[source("test.rs", "let forbidden_needle = 1;")],
        ),
        "a violated invariant",
        |violation| matches!(violation, InvariantViolation::Found { invariant, .. } if *invariant == "test.needle"),
    )?;
    must_report(
        &check_invariants(&[], &[source("test.rs", "let clean = 1;")]),
        &InvariantViolation::NoInvariants,
    )?;
    let out_of_scope = Invariant {
        scope: &["only/this.rs"],
        ..needle_invariant()
    };
    must_report(
        &check_invariants(&[out_of_scope], &[source("test.rs", "let clean = 1;")]),
        &InvariantViolation::ScopeNotFound {
            invariant: "test.needle",
        },
    )
}
