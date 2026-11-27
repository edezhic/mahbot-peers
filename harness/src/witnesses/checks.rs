//! The two-way checks: the inventory check and the invariant check must each
//! catch a broken entry as well as pass a good one.

use std::fmt;

use crate::invariants::{
    Invariant, Source, Violation as InvariantViolation, check as check_invariants, forbidden,
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
        capabilities: &["test.claim"],
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
            capabilities: &["test.impossible"],
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
                capabilities: &["test.gone"],
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

/// The two transfer invariants must be able to fail as well as pass.
///
/// Each is checked three ways: its own positive control is flagged, snippets of the code the
/// layer really holds are not, and every source under its scope — the transfer module and its
/// submodules, which the summary scan reads too — is clean. A checker that had gone blind fails
/// here instead of passing over nothing. The name's opacity is a second claim inside the first
/// invariant, so an interpretation of the text is checked against the module that owns a name
/// and against the frame codec, which parses frames and not names.
pub(crate) fn the_transfer_invariants_are_two_way() -> Result<(), String> {
    let sources = crate::invariants::workspace_sources();
    for (id, clean) in [
        (
            "transfers.name_decides_nothing",
            "let right = rights.may_take_file(&peer, &*floor, now)?;",
        ),
        // A name carried, and two names compared: the whole of what the layer may do with one.
        (
            "transfers.name_decides_nothing",
            "let key = (peer, offer.name.clone());",
        ),
        (
            "transfers.name_decides_nothing",
            "if authorised.name == offer.name {",
        ),
        (
            "transfers.name_is_not_a_path",
            "let name = offer.name.as_str();",
        ),
    ] {
        let invariant = crate::invariants::find(id)
            .ok_or_else(|| format!("{id} is not in the invariant table"))?;
        if (invariant.check)(&source("test.rs", invariant.control)).is_empty() {
            return Err(format!("{id} does not flag its own control"));
        }
        if !(invariant.check)(&source("test.rs", clean)).is_empty() {
            return Err(format!("{id} flags the clean line `{clean}`"));
        }
        let covered: Vec<&Source> = sources
            .iter()
            .filter(|each| invariant.covers(&each.path))
            .collect();
        if covered.is_empty() {
            return Err(format!("{id} covers no source in this workspace"));
        }
        for each in covered {
            if let Some(finding) = (invariant.check)(each).first() {
                return Err(format!("{id} does not hold in {}: {finding}", each.path));
            }
        }
    }
    // A name is opaque in the module that owns it: an interpretation of the text — a split, a
    // trim, a prefix or suffix match, a parse, a case fold — is flagged there, and the same
    // line elsewhere in the layer is not, because the frame codec parses frames.
    let opaque = crate::invariants::find("transfers.name_decides_nothing")
        .ok_or_else(|| "transfers.name_decides_nothing is not in the invariant table".to_owned())?;
    for control in [
        r#"let stem = name.as_str().split('.').next();"#,
        r#"let trimmed = name.as_str().trim();"#,
        r#"if name.as_str().starts_with("report") {"#,
        r#"let offset: u64 = name.as_str().parse()?;"#,
    ] {
        if (opaque.check)(&source(crate::invariants::TRANSFER_MODULE, control)).is_empty() {
            return Err(format!(
                "transfers.name_decides_nothing does not flag `{control}` in the module that \
                 owns a name"
            ));
        }
        if !(opaque.check)(&source("src/peer/transfer/wire.rs", control)).is_empty() {
            return Err(format!(
                "transfers.name_decides_nothing flags `{control}` in the frame codec, which \
                 parses frames"
            ));
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

/// The source check behind the runtime case: the action layer names no capability and asks no
/// question of its own, so no path leads from a body to a right. The summary scan runs the
/// invariant over the whole tree and proves its one control is caught; this case adds the forms
/// that control does not exercise, so a checker that only catches its own control fails here.
pub(crate) fn an_action_body_cannot_reach_a_capability_by_source() -> Result<(), String> {
    use crate::invariants::find;
    let invariant = find("actions.no_capability_from_a_body")
        .ok_or_else(|| "actions.no_capability_from_a_body is not in the table".to_owned())?;
    // The scope must keep scanning the layer's submodules: `ScopeNotFound` only fires when a
    // scope entry matches no file, so narrowing the directory to one file would silently stop
    // the scan.
    for path in ["src/peer/actions/wire.rs", "src/peer/actions/store.rs"] {
        if !invariant.covers(path) {
            return Err(format!("the claim no longer covers {path}"));
        }
    }
    let at = |text: &str| source("src/peer/actions.rs", text);
    for form in [
        "let question = Question { .. };",
        "rights.grant(&pair, capability, &authority, None, now)?;",
        "rights.decide(&question, &*floor, now)?;",
    ] {
        if (invariant.check)(&at(form)).is_empty() {
            return Err(format!("the claim no longer flags `{form}`"));
        }
    }
    if !(invariant.check)(&at(
        "let right = rights.may_run_action(&peer, &*floor, now)?;",
    ))
    .is_empty()
    {
        return Err("the claim flags the layer's own decision".to_owned());
    }
    Ok(())
}

/// The pair's connection has two stream acceptors and no third, and each of the two has one
/// `accept_bi` call site. The summary scan proves the property over the whole tree; this case
/// proves both checks are awake — an acceptor in a third file and a second call site in an
/// acceptor file are each flagged — and that the two allowed files are excused by the documented
/// table rather than by a path comparison inside the check.
pub(crate) fn the_pair_has_one_stream_acceptor() -> Result<(), String> {
    use crate::invariants::{ACCEPTOR_FILES, exempt, find};
    let third = find("peer.one_stream_acceptor")
        .ok_or_else(|| "peer.one_stream_acceptor is not in the table".to_owned())?;
    let per_file = find("peer.one_acceptor_per_file")
        .ok_or_else(|| "peer.one_acceptor_per_file is not in the table".to_owned())?;
    // The two acceptor files are excused by the documented table, not by a path comparison
    // inside the check.
    for path in ACCEPTOR_FILES {
        if !exempt("peer.one_stream_acceptor", path) {
            return Err(format!(
                "{path} accepts a stream but has no documented exemption"
            ));
        }
    }
    // The two services' files must stay in scope: `ScopeNotFound` only fires when a scope entry
    // matches no file, so a narrowed scope would stop the scan without failing.
    for path in ["src/peer/messages.rs", "src/peer/actions.rs"] {
        if !third.covers(path) {
            return Err(format!("the claim no longer covers {path}"));
        }
    }
    let accepted = "let (send, recv) = connection.accept_bi().await?;";
    // A third file's acceptor is a finding; the two allowed files answer through the documented
    // exemption instead, which is why the scan passes with them in it.
    if (third.check)(&source("src/peer/messages.rs", accepted)).is_empty() {
        return Err("the claim does not flag an acceptor outside the two allowed files".to_owned());
    }
    for path in ACCEPTOR_FILES {
        if !(per_file.check)(&source(path, accepted)).is_empty() {
            return Err(format!("the claim flags the single acceptor in {path}"));
        }
        let twice = format!("{accepted}\n{accepted}");
        if (per_file.check)(&source(path, &twice)).is_empty() {
            return Err(format!("a second acceptor in {path} is not flagged"));
        }
        // Two calls on one line are two call sites, not one.
        let together = "let first = connection.accept_bi(); let second = connection.accept_bi();";
        if (per_file.check)(&source(path, together)).is_empty() {
            return Err(format!(
                "two acceptors on one line in {path} are not flagged"
            ));
        }
    }
    Ok(())
}
