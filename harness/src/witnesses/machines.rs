//! Machine cases: disjoint roots and identities, isolation, disposal and no
//! shared state.

use std::io;
use std::time::Duration;

use crate::clock::block_on;
use crate::invariants as table;
use crate::machine::{GONE_ROOT, IsolationRefused};
use crate::sim::Sim;

use super::support::io_error;

pub(crate) fn machines_are_distinct() -> Result<(), String> {
    let sim = Sim::new().map_err(io_error)?;
    let first = sim.machine().map_err(io_error)?;
    let second = sim.machine().map_err(io_error)?;
    if first.root_id() == second.root_id() {
        return Err("two machines share a root".to_owned());
    }
    if first.peer_id() == second.peer_id() {
        return Err("two machines share an identity".to_owned());
    }
    if first.fingerprint() == second.fingerprint() {
        return Err("two machines share a fingerprint".to_owned());
    }
    if first.addr() == second.addr() {
        return Err("two machines share an address".to_owned());
    }
    Ok(())
}

pub(crate) fn foreign_root_is_refused() -> Result<(), String> {
    let sim = Sim::new().map_err(io_error)?;
    let first = sim.machine().map_err(io_error)?;
    let second = sim.machine().map_err(io_error)?;
    first
        .storage()
        .write("note.txt", b"from the first")
        .map_err(io_error)?;
    // A file in one root is simply absent from the other: the roots are
    // disjoint, not merely separately addressed.
    match second.storage().read("note.txt") {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        other => {
            return Err(format!(
                "the other machine's root already holds a file of that name: {other:?}"
            ));
        }
    }
    second
        .storage()
        .write("note.txt", b"from the second")
        .map_err(io_error)?;
    if first.storage().read("note.txt").map_err(io_error)? != b"from the first" {
        return Err("a machine saw another machine's write".to_owned());
    }
    match second.storage().open(first.root_id()) {
        Err(IsolationRefused { asked, own })
            if asked == first.root_id() && own == second.root_id() =>
        {
            Ok(())
        }
        Ok(_) => Err("a storage capability opened another machine's root".to_owned()),
        Err(other) => Err(format!("the refusal named the wrong pair: {other}")),
    }?;
    if second.storage().open(second.root_id()).is_err() {
        return Err("a storage capability refused its own root".to_owned());
    }
    for name in [
        "../escape",
        "/etc/passwd",
        "a/../../escape",
        "./note.txt",
        "",
    ] {
        match first.storage().read(name) {
            Err(error) if error.kind() == io::ErrorKind::InvalidInput => {}
            other => {
                return Err(format!(
                    "`{name}` was not refused as a name that leaves the root: {other:?}"
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn machines_are_disposed_independently() -> Result<(), String> {
    let sim = Sim::new().map_err(io_error)?;
    let first = sim.machine().map_err(io_error)?;
    let second = sim.machine().map_err(io_error)?;
    first
        .storage()
        .write("keep.txt", b"first")
        .map_err(io_error)?;
    second
        .storage()
        .write("keep.txt", b"second")
        .map_err(io_error)?;
    if sim.live_roots() != 2 {
        return Err(format!(
            "two machines left {} roots behind",
            sim.live_roots()
        ));
    }
    drop(first);
    if sim.live_roots() != 1 {
        return Err(format!(
            "dropping one machine left {} roots, not one",
            sim.live_roots()
        ));
    }
    if second.storage().read("keep.txt").map_err(io_error)? != b"second" {
        return Err("the surviving machine lost its data".to_owned());
    }
    drop(second);
    if sim.live_roots() != 0 {
        return Err(format!(
            "the simulation still holds {} roots",
            sim.live_roots()
        ));
    }
    Ok(())
}

pub(crate) fn machine_handle_names_no_path() -> Result<(), String> {
    let invariant = table::find("harness.handle_names_no_path")
        .ok_or_else(|| "the handle invariant is not in the table".to_owned())?;
    let handle = table::workspace_sources()
        .into_iter()
        .find(|source| source.path == table::MACHINE_FILE)
        .ok_or_else(|| format!("{} was not scanned", table::MACHINE_FILE))?;
    match (invariant.check)(&handle).first() {
        None => Ok(()),
        Some(finding) => Err(format!("the machine handle names a path at {finding}")),
    }
}

pub(crate) fn simulations_share_no_state() -> Result<(), String> {
    let one = Sim::new().map_err(io_error)?;
    let other = Sim::new().map_err(io_error)?;
    let first = one.machine().map_err(io_error)?;
    let second = other.machine().map_err(io_error)?;
    // Same name, different simulations: neither may see the other's bytes.
    first
        .storage()
        .write("state.txt", b"one")
        .map_err(io_error)?;
    second
        .storage()
        .write("state.txt", b"two")
        .map_err(io_error)?;
    if first.storage().read("state.txt").map_err(io_error)? != b"one" {
        return Err("two simulations share a storage root".to_owned());
    }
    one.link().send(first.addr(), second.addr(), vec![7]);
    if !other.link().trace().is_empty() {
        return Err("a datagram crossed between simulations".to_owned());
    }
    let untouched = other.clock().elapsed();
    block_on(one.clock().advance(Duration::from_secs(1)));
    if other.clock().elapsed() != untouched {
        return Err("advancing one clock moved another".to_owned());
    }
    if one.live_roots() != 1 || other.live_roots() != 1 {
        return Err("the simulations do not own one root each".to_owned());
    }
    Ok(())
}

pub(crate) fn dead_root_is_refused() -> Result<(), String> {
    let sim = Sim::new().map_err(io_error)?;
    let machine = sim.machine().map_err(io_error)?;
    machine
        .storage()
        .write("keep.txt", b"still here")
        .map_err(io_error)?;
    // The simulation owns the temporary parent; its removal takes every machine
    // root with it, and a handle to a gone root must not quietly recreate one or
    // answer "no such file" for a root that vanished. The refusal carries its own
    // message, so a read that merely found no file cannot be mistaken for it.
    drop(sim);
    let refuse = |operation: &str, result: io::Result<()>| -> Result<(), String> {
        match result {
            Err(error) if error.to_string() == GONE_ROOT => Ok(()),
            other => Err(format!(
                "a machine whose root is gone did not refuse a {operation}: {other:?}"
            )),
        }
    };
    refuse("write", machine.storage().write("keep.txt", b"gone"))?;
    refuse("read", machine.storage().read("keep.txt").map(|_| ()))
}
