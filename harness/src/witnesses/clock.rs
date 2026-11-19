//! Clock cases: each deadline fires at its own instant, time never moves back,
//! and a case that cannot make progress is stopped instead of hanging the suite.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::clock::{MockClock, block_on};
use crate::report::panic_message;

pub(crate) fn clock_fires_each_deadline_at_its_instant() -> Result<(), String> {
    let clock = MockClock::new();
    let fired = Arc::new(Mutex::new(Vec::<u128>::new()));
    let at_five = clock.clone();
    let record_five = Arc::clone(&fired);
    clock.schedule(Duration::from_millis(5), move || {
        record_five
            .lock()
            .expect("the log is not poisoned")
            .push(at_five.elapsed().as_millis());
        // Queued for the instant just visited: it must not drag the 15 ms
        // deadline to the end of the jump.
        at_five.schedule(Duration::ZERO, || {});
    });
    let at_fifteen = clock.clone();
    let record_fifteen = Arc::clone(&fired);
    clock.schedule(Duration::from_millis(15), move || {
        record_fifteen
            .lock()
            .expect("the log is not poisoned")
            .push(at_fifteen.elapsed().as_millis());
    });
    block_on(clock.advance(Duration::from_millis(20)));
    let log = fired.lock().expect("the log is not poisoned").clone();
    if log != vec![5, 15] {
        return Err(format!(
            "the deadlines fired at {log:?} ms of virtual time, not at 5 and 15"
        ));
    }
    Ok(())
}

pub(crate) fn clock_never_goes_back() -> Result<(), String> {
    let clock = MockClock::new();
    let before = clock.now();
    // A timer armed for an instant already behind us must not drag time with it.
    let past = before.checked_sub(Duration::from_secs(1)).unwrap_or(before);
    let _armed_in_the_past = clock.runtime().new_timer(past);
    block_on(clock.advance(Duration::from_millis(1)));
    if clock.now() < before {
        return Err(format!(
            "the clock went back from {before:?} to {:?}",
            clock.now()
        ));
    }
    // Nor may an explicit move to the past: the clamp is the clock's whole
    // monotonic guarantee, and it is aimed at directly here.
    let moved = clock.now();
    let behind = moved.checked_sub(Duration::from_secs(5)).unwrap_or(moved);
    clock.advance_to(behind);
    if clock.now() != moved {
        return Err(format!(
            "an explicit move to {behind:?} dragged the clock from {moved:?} to {:?}",
            clock.now()
        ));
    }
    clock.advance_to(moved + Duration::from_secs(1));
    if clock.now() != moved + Duration::from_secs(1) {
        return Err("a forward move did not take".to_owned());
    }
    Ok(())
}

pub(crate) fn a_spinning_case_is_stopped() -> Result<(), String> {
    let outcome = std::panic::catch_unwind(|| {
        block_on(async {
            loop {
                tokio::task::yield_now().await;
            }
        });
    });
    match outcome {
        Err(payload) => {
            let message = panic_message(payload.as_ref());
            if message.contains("without parking") {
                Ok(())
            } else {
                Err(format!(
                    "the spin was stopped for another reason: {message}"
                ))
            }
        }
        Ok(()) => Err("a case that never parks ran to completion".to_owned()),
    }
}

pub(crate) fn drive_bounds_a_parked_await() -> Result<(), String> {
    let clock = MockClock::new();
    let budget = Duration::from_millis(50);
    let outcome = block_on(clock.drive(budget, std::future::pending::<()>()));
    if outcome.is_some() {
        return Err("a future that never resolves reported an output".to_owned());
    }
    let spent = clock.elapsed();
    if spent != budget {
        return Err(format!(
            "the drive gave up after {spent:?}, not at its {budget:?} budget"
        ));
    }
    Ok(())
}

pub(crate) fn a_runaway_walk_is_stopped() -> Result<(), String> {
    // Queue the next callback a nanosecond later, inside whatever advance is
    // running: one walk would step through a million instants.
    fn reschedule(clock: &MockClock) {
        let next = clock.clone();
        clock.schedule(Duration::from_nanos(1), move || reschedule(&next));
    }

    let clock = MockClock::new();
    reschedule(&clock);
    let advance = clock.advance(Duration::from_millis(1));
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| block_on(advance))) {
        Err(payload) => {
            let message = panic_message(payload.as_ref());
            if message.contains("keeps scheduling") {
                Ok(())
            } else {
                Err(format!(
                    "the walk was stopped for another reason: {message}"
                ))
            }
        }
        Ok(()) => Err("a walk through a million instants ran to completion".to_owned()),
    }
}
