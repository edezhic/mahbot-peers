//! The two frames the message layer speaks: one offer and one answer.
//!
//! # The bytes
//!
//! Both are `magic`, one version byte, then `[tag][len u16 big-endian][body]` fields,
//! the same framing the record, the log and the binding use.
//!
//! A message is `mahbot-peer-message`: `0x01` the envelope's identifier (exactly 16
//! bytes), `0x02` its count (8, big-endian, at least one), `0x03` the moment it was
//! composed (8, seconds), `0x04` the body (0 to [`MAX_BODY_BYTES`]). All four are
//! required and the body is the only variable-length field, so a message is at most
//! [`MAX_MESSAGE_BYTES`].
//!
//! An answer is `mahbot-peer-answer`: `0x01` the status (one byte: 1 taken, 2 refused,
//! 3 throttled, 4 unreadable, 5 already taken) and `0x02` the delay in whole seconds (4,
//! big-endian, only with a throttle). A refusal carries no text: the class is the answer,
//! and the receiver's words stay on the receiver. The set grows by appending, and no
//! meaning moves once a build has shipped: a peer's answer must read as this build wrote it.
//! A reader takes an answer whole or not at all, and reads up to a cap well above this
//! frame, so a field appended to the answer must still fit that cap.
//!
//! # What a version means
//!
//! Version 1 is what this build writes. A version of zero is not a frame and is
//! refused. A version above this build's is read as this version's prefix: its fields
//! are read and its unknown tags are ignored, so a newer build's message reaches an
//! older one as long as the older one understands the four fields it needs. A missing
//! required field is a refusal, and so is a body longer than the cap — a frame is
//! read whole or not at all.
//!
//! A known field that appears twice is read with the last occurrence winning, as the
//! binding's fact is: the framing has one spelling and a repeat is the writer's, not a
//! second meaning. A field frame that runs past the end is a refusal, and so is any
//! byte after the last whole field.

use std::time::Duration;

use crate::peer::messages::{
    Answer, Envelope, EnvelopeId, FramingFault, MAX_BODY_BYTES, Message, MessageError,
};
use crate::peer::record::Timestamp;
use crate::peer::tlv;

/// The bytes a message opens with.
const MESSAGE_MAGIC: &[u8] = b"mahbot-peer-message";

/// The bytes an answer opens with.
const ANSWER_MAGIC: &[u8] = b"mahbot-peer-answer";

/// The frame version this build writes. A higher version is read as this version's
/// prefix.
const VERSION: u8 = 1;

/// A message's field tags. Unknown tags are ignored.
mod message_tag {
    pub const ID: u8 = 0x01;
    pub const COUNT: u8 = 0x02;
    pub const COMPOSED_AT: u8 = 0x03;
    pub const BODY: u8 = 0x04;
}

/// An answer's field tags. Unknown tags are ignored.
mod answer_tag {
    pub const STATUS: u8 = 0x01;
    pub const RETRY_AFTER: u8 = 0x02;
}

/// A message's bytes.
pub(super) fn encode_message(message: &Message) -> Result<Vec<u8>, MessageError> {
    let body = message.body();
    if body.len() > MAX_BODY_BYTES {
        return Err(MessageError::Body {
            bytes: body.len(),
            limit: MAX_BODY_BYTES,
        });
    }
    let envelope = message.envelope();
    let mut bytes = Vec::with_capacity(48 + body.len());
    bytes.extend_from_slice(MESSAGE_MAGIC);
    bytes.push(VERSION);
    put(&mut bytes, message_tag::ID, envelope.id().as_bytes())?;
    put(
        &mut bytes,
        message_tag::COUNT,
        &envelope.count().to_be_bytes(),
    )?;
    put(
        &mut bytes,
        message_tag::COMPOSED_AT,
        &envelope.composed_at().unix_seconds().to_be_bytes(),
    )?;
    put(&mut bytes, message_tag::BODY, body)?;
    Ok(bytes)
}

/// One message, from its bytes.
pub(super) fn decode_message(bytes: &[u8]) -> Result<Message, MessageError> {
    let rest = bytes
        .strip_prefix(MESSAGE_MAGIC)
        .ok_or_else(|| frame(FramingFault::Magic))?;
    let (&version, rest) = rest
        .split_first()
        .ok_or_else(|| frame(FramingFault::Truncated))?;
    if version == 0 {
        return Err(frame(FramingFault::Version { found: version }));
    }
    let mut id = None;
    let mut count = None;
    let mut composed_at = None;
    let mut body = None;
    for field in tlv::Fields::new(rest) {
        let (tag, field) = field.map_err(field_error)?;
        match tag {
            message_tag::ID => {
                id = Some(EnvelopeId::from_bytes(
                    tlv::id_of(tag, field).map_err(field_error)?,
                ));
            }
            message_tag::COUNT => {
                let found = tlv::u64_of(tag, field).map_err(field_error)?;
                if found == 0 {
                    return Err(field_fault(tag, "is zero"));
                }
                count = Some(found);
            }
            message_tag::COMPOSED_AT => {
                composed_at = Some(Timestamp::from_unix_seconds(
                    tlv::u64_of(tag, field).map_err(field_error)?,
                ));
            }
            message_tag::BODY => {
                if field.len() > MAX_BODY_BYTES {
                    return Err(field_fault(tag, "is longer than the body cap"));
                }
                body = Some(field.to_vec());
            }
            _ => {}
        }
    }
    Ok(Message {
        envelope: Envelope {
            id: id.ok_or_else(|| field_fault(message_tag::ID, "is missing"))?,
            count: count.ok_or_else(|| field_fault(message_tag::COUNT, "is missing"))?,
            composed_at: composed_at
                .ok_or_else(|| field_fault(message_tag::COMPOSED_AT, "is missing"))?,
        },
        body: body.ok_or_else(|| field_fault(message_tag::BODY, "is missing"))?,
    })
}

/// One answer's bytes.
pub(super) fn encode_answer(answer: &Answer) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32);
    bytes.extend_from_slice(ANSWER_MAGIC);
    bytes.push(VERSION);
    let (status, delay) = match answer {
        Answer::Taken => (1, None),
        Answer::Refused => (2, None),
        Answer::Throttled { retry_after } => {
            let seconds = u32::try_from(retry_after.as_secs()).unwrap_or(u32::MAX);
            (3, Some(seconds.to_be_bytes()))
        }
        Answer::Unreadable => (4, None),
        Answer::AlreadyTaken => (5, None),
    };
    short(&mut bytes, answer_tag::STATUS, &[status]);
    if let Some(delay) = delay {
        short(&mut bytes, answer_tag::RETRY_AFTER, &delay);
    }
    bytes
}

/// One answer, from its bytes.
pub(super) fn decode_answer(bytes: &[u8]) -> Result<Answer, MessageError> {
    let rest = bytes
        .strip_prefix(ANSWER_MAGIC)
        .ok_or_else(|| frame(FramingFault::Magic))?;
    let (&version, rest) = rest
        .split_first()
        .ok_or_else(|| frame(FramingFault::Truncated))?;
    if version == 0 {
        return Err(frame(FramingFault::Version { found: version }));
    }
    let mut status = None;
    let mut retry_after = None;
    for field in tlv::Fields::new(rest) {
        let (tag, field) = field.map_err(field_error)?;
        match tag {
            answer_tag::STATUS => {
                let [status_byte] = field else {
                    return Err(field_fault(tag, "is not one byte"));
                };
                status = Some(*status_byte);
            }
            answer_tag::RETRY_AFTER => {
                let seconds: [u8; 4] = field
                    .try_into()
                    .map_err(|_| field_fault(tag, "is not four bytes"))?;
                retry_after = Some(Duration::from_secs(u64::from(u32::from_be_bytes(seconds))));
            }
            _ => {}
        }
    }
    match status.ok_or_else(|| field_fault(answer_tag::STATUS, "is missing"))? {
        1 => Ok(Answer::Taken),
        2 => Ok(Answer::Refused),
        3 => Ok(Answer::Throttled {
            retry_after: retry_after
                .ok_or_else(|| field_fault(answer_tag::RETRY_AFTER, "is missing"))?,
        }),
        4 => Ok(Answer::Unreadable),
        5 => Ok(Answer::AlreadyTaken),
        other => Err(field_fault(
            answer_tag::STATUS,
            &format!("is {other}, which is not one this build knows"),
        )),
    }
}

/// Append one field, refusing a body longer than a field can name.
fn put(bytes: &mut Vec<u8>, tag: u8, body: &[u8]) -> Result<(), MessageError> {
    tlv::put(bytes, tag, body).map_err(|_| {
        frame(FramingFault::Field {
            tag,
            detail: "is longer than 65535 bytes".to_owned(),
        })
    })
}

/// Append one field whose body is known to be short.
///
/// Both bodies this is used for are bounded — a status is one byte and a delay is four —
/// so the framing cannot refuse, and an answer is never lost to a length.
fn short(bytes: &mut Vec<u8>, tag: u8, body: &[u8]) {
    let _ = tlv::put(bytes, tag, body);
}

/// A wire fault: a frame has no path, so it is the frame's spelling and not a file's.
fn frame(reason: FramingFault) -> MessageError {
    MessageError::Frame { reason }
}

fn field_fault(tag: u8, detail: &str) -> MessageError {
    frame(FramingFault::Field {
        tag,
        detail: detail.to_owned(),
    })
}

fn field_error(error: tlv::FieldError) -> MessageError {
    field_fault(error.tag, error.detail)
}
