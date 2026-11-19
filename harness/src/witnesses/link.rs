//! Link cases: scripted faults and a trace that replays from its seed.

use std::time::Duration;

use crate::clock::{MockClock, block_on};
use crate::link::{Fault, FaultPlan, Link, Rates, Trace};

use super::support::{drain, socket};

pub(crate) fn link_applies_scripted_faults() -> Result<(), String> {
    let clock = MockClock::new();
    let link = Link::new(clock.clone());
    let sender = socket(8001);
    let receiver = socket(8002);
    let elsewhere = socket(8003);
    let receiver_socket = link.attach(receiver).expect("the receiver address is free");
    let _elsewhere = link.attach(elsewhere).expect("the other address is free");
    link.set_plan(FaultPlan::Scripted(vec![
        vec![Fault::Delay(Duration::from_millis(5))],
        vec![Fault::Reorder],
        vec![Fault::Duplicate],
        vec![Fault::Reroute(elsewhere)],
        vec![Fault::Drop],
    ]));
    for payload in 1..=5u8 {
        link.send(sender, receiver, vec![payload]);
    }
    let arrived = drain(&receiver_socket);
    let expected = vec![vec![3u8], vec![3], vec![2]];
    if arrived != expected {
        return Err(format!(
            "before time moved the receiver got {arrived:?}, not {expected:?}"
        ));
    }
    let before = link.trace();
    if before.len() != 5 {
        return Err(format!("the trace holds {} events, not five", before.len()));
    }
    if before[0].delivered() {
        return Err("a delayed datagram arrived before time moved".to_owned());
    }
    if !before[3]
        .deliveries
        .iter()
        .all(|delivery| delivery.to == elsewhere)
    {
        return Err("a rerouted datagram did not reach the other address".to_owned());
    }
    if before[4].delivered() {
        return Err("a dropped datagram was delivered".to_owned());
    }
    block_on(clock.advance(Duration::from_millis(10)));
    let arrived = drain(&receiver_socket);
    if arrived != vec![vec![1u8]] {
        return Err(format!(
            "after time moved the receiver got {arrived:?}, not the delayed datagram"
        ));
    }
    let after = link.trace();
    match after[0].deliveries.first() {
        Some(delivery) if delivery.at == Duration::from_millis(5) => {}
        other => {
            return Err(format!(
                "the delayed datagram landed at {other:?}, not at 5 ms"
            ));
        }
    }

    // A second run on the same link: faults compose, and the previous run
    // leaves nothing behind. The datagram queued before the reset is dropped.
    link.send(sender, receiver, vec![99]);
    link.set_plan(FaultPlan::Scripted(vec![
        vec![Fault::Drop, Fault::Duplicate],
        vec![Fault::Duplicate, Fault::Reorder],
        vec![Fault::Delay(Duration::from_millis(5))],
    ]));
    let stale = drain(&receiver_socket);
    if !stale.is_empty() {
        return Err(format!("the new run began with {stale:?} still queued"));
    }
    for payload in 11..=13u8 {
        link.send(sender, receiver, vec![payload]);
    }
    if !drain(&receiver_socket).is_empty() {
        return Err("a dropped datagram was delivered despite its duplicate".to_owned());
    }
    block_on(clock.advance(Duration::from_millis(10)));
    let arrived = drain(&receiver_socket);
    let expected = vec![vec![13u8], vec![12], vec![12]];
    if arrived != expected {
        return Err(format!(
            "the released run delivered {arrived:?}, not {expected:?}: a reordered duplicate must keep both copies"
        ));
    }
    let trace = link.trace();
    if trace[0].delivered() {
        return Err("a datagram with drop and duplicate faults was delivered".to_owned());
    }
    if trace[1].deliveries.len() != 2 {
        return Err(format!(
            "a reordered duplicate was recorded as {} deliveries",
            trace[1].deliveries.len()
        ));
    }

    // A third run: a reordered datagram keeps its own delay, and can therefore
    // land after the one that released it. The release is not a promise of
    // arrival order, only of never arriving first.
    let base = clock.elapsed();
    link.set_plan(FaultPlan::Scripted(vec![
        vec![Fault::Reorder, Fault::Delay(Duration::from_millis(20))],
        vec![Fault::Delay(Duration::from_millis(5))],
    ]));
    link.send(sender, receiver, vec![21]);
    link.send(sender, receiver, vec![22]);
    block_on(clock.advance(Duration::from_millis(25)));
    let arrived = drain(&receiver_socket);
    if arrived != vec![vec![22u8], vec![21]] {
        return Err(format!(
            "a delayed reordered datagram arrived as {arrived:?}, not after its releaser"
        ));
    }
    let trace = link.trace();
    let landed = |seq: usize| trace[seq].deliveries.first().map(|delivery| delivery.at);
    if landed(0) != Some(base + Duration::from_millis(20)) {
        return Err(format!(
            "the reordered datagram landed at {:?}, not at its own 20 ms",
            landed(0)
        ));
    }
    if landed(1) != Some(base + Duration::from_millis(5)) {
        return Err(format!(
            "the releasing datagram landed at {:?}, not at its 5 ms",
            landed(1)
        ));
    }

    // A fourth run: a drop is not a send. The held datagram waits for the next
    // one that is actually sent, and the dropped one is recorded with no
    // deliveries of its own.
    link.set_plan(FaultPlan::Scripted(vec![
        vec![Fault::Reorder],
        vec![Fault::Drop],
        vec![],
    ]));
    link.send(sender, receiver, vec![31]);
    link.send(sender, receiver, vec![32]);
    if !drain(&receiver_socket).is_empty() {
        return Err("a datagram was delivered before it was released".to_owned());
    }
    let waiting = link.trace();
    if waiting[0].delivered() || waiting[1].delivered() {
        return Err("a held or dropped datagram was delivered on the spot".to_owned());
    }
    link.send(sender, receiver, vec![33]);
    let arrived = drain(&receiver_socket);
    if arrived != vec![vec![33u8], vec![31]] {
        return Err(format!(
            "the datagram held across a drop arrived as {arrived:?}, not after its releaser"
        ));
    }
    let trace = link.trace();
    if trace[1].delivered() {
        return Err("a dropped datagram was delivered".to_owned());
    }
    if trace[0].deliveries.len() != 1 {
        return Err(format!(
            "the held datagram was recorded as {} deliveries",
            trace[0].deliveries.len()
        ));
    }
    Ok(())
}

pub(crate) fn link_trace_is_reproducible() -> Result<(), String> {
    let plan = FaultPlan::Seeded {
        seed: 0x5eed,
        rates: Rates {
            drop: 25,
            delay: 25,
            duplicate: 15,
            reorder: 15,
        },
    };
    let first = seeded_run(&plan)?;
    let second = seeded_run(&plan)?;
    if first != second {
        return Err("the same seed produced a different trace".to_owned());
    }
    if first.is_empty() {
        return Err("the seeded run recorded nothing".to_owned());
    }
    let replay = seeded_run(&FaultPlan::from_trace(&first))?;
    if replay != first {
        return Err("a recorded trace did not replay to itself".to_owned());
    }
    let other = seeded_run(&FaultPlan::Seeded {
        seed: 0x5eee,
        rates: Rates {
            drop: 25,
            delay: 25,
            duplicate: 15,
            reorder: 15,
        },
    })?;
    if other == first {
        return Err("two different seeds produced the same trace".to_owned());
    }
    Ok(())
}

fn seeded_run(plan: &FaultPlan) -> Result<Trace, String> {
    let clock = MockClock::new();
    let link = Link::new(clock.clone());
    let sender = socket(7001);
    let receiver = socket(7002);
    let _socket = link.attach(receiver).expect("the receiver address is free");
    link.set_plan(plan.clone());
    for payload in 0..64u8 {
        link.send(sender, receiver, vec![payload]);
    }
    block_on(clock.advance(Duration::from_millis(100)));
    Ok(link.trace())
}

pub(crate) fn oversized_datagram_is_dropped() -> Result<(), String> {
    let clock = MockClock::new();
    let link = Link::new(clock);
    let sender = socket(8101);
    let receiver = socket(8102);
    let receiver_socket = link.attach(receiver).map_err(|error| error.to_string())?;
    link.send(sender, receiver, vec![7u8; 512]);
    let trace = link.trace();
    if trace.len() != 1 || !trace[0].delivered() {
        return Err("the link did not carry the oversized datagram to its socket".to_owned());
    }
    // `drain` reads through a 256-byte buffer: a truncated datagram would come
    // back as 256 bytes of payload, so an empty read is the only correct answer.
    let arrived = drain(&receiver_socket);
    if !arrived.is_empty() {
        return Err(format!(
            "an oversized datagram was delivered as {arrived:?}"
        ));
    }
    Ok(())
}

pub(crate) fn addresses_are_exclusive() -> Result<(), String> {
    let clock = MockClock::new();
    let link = Link::new(clock);
    let first_addr = socket(5001);
    let second_addr = socket(5002);
    let _first = link.attach(first_addr).map_err(|error| error.to_string())?;
    match link.attach(first_addr) {
        Err(crate::link::AddressTaken(addr)) if addr == first_addr => {}
        other => {
            return Err(format!("a second socket took a live address: {other:?}"));
        }
    }
    let second = link
        .attach(second_addr)
        .map_err(|error| error.to_string())?;
    match link.rebind(&second, first_addr) {
        Err(crate::link::AddressTaken(addr)) if addr == first_addr => {}
        other => return Err(format!("a rebind stole a live address: {other:?}")),
    }
    if second.addr() != second_addr {
        return Err("a refused rebind moved the socket anyway".to_owned());
    }
    let third = link.attach_next();
    if third.addr() == first_addr || third.addr() == second_addr {
        return Err(format!(
            "the link handed out the live address {}",
            third.addr()
        ));
    }
    Ok(())
}
