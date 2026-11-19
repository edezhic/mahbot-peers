//! What a check found: the counts it walked and the violations it reported.
//!
//! The inventory check and the invariant check answer in the same shape, so a
//! case can assert on either with one helper.

use std::fmt;

/// What a check found.
#[derive(Debug)]
pub struct Report<V> {
    /// What the check walked, and how many: capabilities, files.
    pub walked: (&'static str, usize),
    /// What it matched each entry against, and how many: witnesses, invariants.
    pub matched: (&'static str, usize),
    pub violations: Vec<V>,
}

impl<V> Report<V> {
    #[must_use]
    pub fn new(walked: (&'static str, usize), matched: (&'static str, usize)) -> Self {
        Self {
            walked,
            matched,
            violations: Vec::new(),
        }
    }

    /// How many entries were walked, e.g. capabilities or files.
    #[must_use]
    pub fn scanned(&self) -> usize {
        self.walked.1
    }

    /// How many cases were checked, e.g. witnesses or invariants.
    #[must_use]
    pub fn checked(&self) -> usize {
        self.matched.1
    }

    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.violations.is_empty()
    }
}

impl<V: fmt::Display> Report<V> {
    /// Every count and violation on its own line, for a failing assertion.
    #[must_use]
    pub fn describe(&self) -> String {
        use std::fmt::Write as _;
        let (walked, walked_count) = self.walked;
        let (matched, matched_count) = self.matched;
        let mut out = format!(
            "{walked_count} {walked}, {matched_count} {matched}, {} violations",
            self.violations.len()
        );
        for violation in &self.violations {
            let _ = write!(out, "\n  - {violation}");
        }
        out
    }
}

/// What a panic payload says, for the report: the message a reader needs to see
/// which claim blew up and why.
#[must_use]
pub fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|message| (*message).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "a panic with no message".to_owned())
}
