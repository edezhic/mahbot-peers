//! `[tag][len u16 big-endian][body]`: the one framing every peer file and frame shares.
//!
//! Every format this crate writes spells it — a record's fields, an audit entry's fields, a
//! fact's fields, a queue or action file's fields (and those of the records inside one), and
//! the message, action and answer frames — and each reader must refuse a length that runs
//! past the end the same way.

use std::fmt;

/// A body longer than the `u16` length a field can name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TooLong {
    /// The body's length, so a caller can name the file's size in its own error.
    pub len: usize,
}

/// Append one field.
pub(crate) fn put(bytes: &mut Vec<u8>, tag: u8, body: &[u8]) -> Result<(), TooLong> {
    let length = u16::try_from(body.len()).map_err(|_| TooLong { len: body.len() })?;
    bytes.push(tag);
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(body);
    Ok(())
}

/// One field's body as a `u64`, or the field's frame fault.
pub(crate) fn u64_of(tag: u8, body: &[u8]) -> Result<u64, FieldError> {
    let bytes: [u8; 8] = body.try_into().map_err(|_| FieldError {
        tag,
        detail: "is not eight bytes",
    })?;
    Ok(u64::from_be_bytes(bytes))
}

/// One field's body as the sixteen bytes an envelope identifier is spelled in.
pub(crate) fn id_of(tag: u8, body: &[u8]) -> Result<[u8; 16], FieldError> {
    body.try_into().map_err(|_| FieldError {
        tag,
        detail: "is not 16 bytes",
    })
}

/// What is wrong with one field's frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FieldError {
    /// The field's tag, which the caller names in its own error.
    pub tag: u8,
    /// The frame's fault, in words the caller prefixes with its own field name.
    pub detail: &'static str,
}

/// The fields of `bytes`, in order. The walk stops at the first malformed frame.
pub(crate) struct Fields<'a> {
    rest: &'a [u8],
}

impl<'a> Fields<'a> {
    /// Walk `bytes`.
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }
}

impl<'a> Iterator for Fields<'a> {
    type Item = Result<(u8, &'a [u8]), FieldError>;

    fn next(&mut self) -> Option<Self::Item> {
        let (&tag, after) = self.rest.split_first()?;
        let Some((length, after)) = after.split_first_chunk::<2>() else {
            self.rest = &[];
            return Some(Err(FieldError {
                tag,
                detail: "has no length",
            }));
        };
        let length = usize::from(u16::from_be_bytes(*length));
        let Some((body, after)) = after.split_at_checked(length) else {
            self.rest = &[];
            return Some(Err(FieldError {
                tag,
                detail: "runs past the end",
            }));
        };
        self.rest = after;
        Some(Ok((tag, body)))
    }
}

/// What is wrong with the framing of a layer's bytes: the four faults a file and a frame can
/// share.
///
/// A file's own refusal adds the faults only a file can have, so a fault a frame cannot
/// produce is not expressible where a frame's reason is expected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FramingFault {
    /// The bytes do not open with the magic they should.
    Magic,
    /// The bytes open with the magic and stop before their version byte.
    Truncated,
    /// The version byte is zero, which no build writes.
    Version { found: u8 },
    /// A known field has the wrong shape or length.
    Field { tag: u8, detail: String },
}

impl fmt::Display for FramingFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Magic => f.write_str("it does not begin with the magic"),
            Self::Truncated => f.write_str("it stops before its version byte"),
            Self::Version { found } => write!(f, "its version is {found}, which no build writes"),
            Self::Field { tag, detail } => write!(f, "its field {tag:#04x} {detail}"),
        }
    }
}
