//! Lowercase hex: the one spelling of a byte string in a name or a fingerprint.
//!
//! Uppercase is not accepted: an identity and a record file have one spelling, so
//! two names for one value cannot exist.

use std::fmt;

/// One lowercase hex digit, and nothing else.
pub(crate) fn digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Write `bytes` as lowercase hex.
pub(crate) fn write(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(f, "{byte:02x}")?;
    }
    Ok(())
}

/// `bytes` as lowercase hex.
pub(crate) fn encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The bytes lowercase hex names, or `None` for anything else.
pub(crate) fn decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let digits = text.as_bytes();
    let mut bytes = Vec::with_capacity(text.len() / 2);
    for pair in digits.as_chunks::<2>().0 {
        bytes.push(digit(pair[0])? << 4 | digit(pair[1])?);
    }
    Some(bytes)
}
