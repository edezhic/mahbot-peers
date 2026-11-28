//! The two frames the action layer speaks: one request and one answer.
//!
//! # The bytes
//!
//! Both are `magic`, one version byte, then `[tag][len u16 big-endian][body]` fields, the same
//! framing the record, the log, the binding and the message frames use.
//!
//! An action is `mahbot-peer-action`: `0x01` the operation's identifier (exactly 16 bytes),
//! `0x02` its kind (one byte, `1` for a command) and `0x03` the body (0 to
//! [`MAX_ACTION_BODY_BYTES`]). All three are required and the body is the only variable-length
//! field, so an action is at most [`MAX_ACTION_FRAME_BYTES`].
//!
//! An answer is `mahbot-peer-action-answer`: `0x01` the status (one byte), `0x02` the step that
//! refused (one byte, only with a refusal), `0x03` the result (0 to [`MAX_RESULT_BYTES`], only
//! with a run) and `0x04` the delay in whole seconds (4, big-endian, only with a slow-down,
//! clamped to [`ACTION_WINDOW`] when read: the sender's window is the one this build bounds,
//! and a delay this machine writes is already bounded by its own window). A
//! refusal carries no text: the step is the answer, and the receiver's words stay on the
//! receiver. The set grows by appending, and no meaning moves once a build has shipped: a
//! peer's answer must read as this build wrote it. A reader takes an answer whole or not at
//! all, and reads up to a cap well above this frame.
//!
//! # What a version means
//!
//! Version 1 is what this build writes. A version of zero is not a frame and is refused. A
//! version above this build's is read as this version's prefix: its fields are read and its
//! unknown tags are ignored. A missing required field is a refusal, and so is a body or a
//! result longer than its cap — a frame is read whole or not at all. A known field that appears
//! twice is read with the last occurrence winning, as the binding's fact is.

use std::time::Duration;

use crate::peer::FramingFault;
use crate::peer::actions::{
    ACTION_WINDOW, Action, ActionAnswer, ActionError, ActionId, ActionKind, MAX_ACTION_BODY_BYTES,
    MAX_RESULT_BYTES,
};
use crate::peer::rights::Step;
use crate::peer::tlv;

/// The bytes an action opens with.
pub(super) const ACTION_MAGIC: &[u8] = b"mahbot-peer-action";

/// The bytes an answer opens with.
const ANSWER_MAGIC: &[u8] = b"mahbot-peer-action-answer";

/// The frame version this build writes. A higher version is read as this version's prefix.
const VERSION: u8 = 1;

/// An action's field tags. Unknown tags are ignored.
mod action_tag {
    pub const ID: u8 = 0x01;
    pub const KIND: u8 = 0x02;
    pub const BODY: u8 = 0x03;
}

/// An answer's field tags. Unknown tags are ignored.
mod answer_tag {
    pub const STATUS: u8 = 0x01;
    pub const STEP: u8 = 0x02;
    pub const RESULT: u8 = 0x03;
    pub const RETRY_AFTER: u8 = 0x04;
}

/// An action's bytes.
pub(super) fn encode_action(action: &Action) -> Vec<u8> {
    let body = action.body();
    let mut bytes = Vec::with_capacity(32 + body.len());
    bytes.extend_from_slice(ACTION_MAGIC);
    bytes.push(VERSION);
    short(&mut bytes, action_tag::ID, action.id().as_bytes());
    short(&mut bytes, action_tag::KIND, &[action.kind().as_byte()]);
    short(&mut bytes, action_tag::BODY, body);
    bytes
}

/// One action, from its bytes.
pub(super) fn decode_action(bytes: &[u8]) -> Result<Action, ActionError> {
    let rest = bytes
        .strip_prefix(ACTION_MAGIC)
        .ok_or_else(|| frame(FramingFault::Magic))?;
    let (&version, rest) = rest
        .split_first()
        .ok_or_else(|| frame(FramingFault::Truncated))?;
    if version == 0 {
        return Err(frame(FramingFault::Version { found: version }));
    }
    let mut id = None;
    let mut kind = None;
    let mut body = None;
    for field in tlv::Fields::new(rest) {
        let (tag, field) = field.map_err(field_error)?;
        match tag {
            action_tag::ID => {
                id = Some(ActionId::from_bytes(
                    tlv::id_of(tag, field).map_err(field_error)?,
                ));
            }
            action_tag::KIND => {
                let [byte] = field else {
                    return Err(field_fault(tag, "is not one byte"));
                };
                kind = Some(ActionKind::from_raw(*byte));
            }
            action_tag::BODY => {
                if field.len() > MAX_ACTION_BODY_BYTES {
                    return Err(field_fault(tag, "is longer than the body cap"));
                }
                body = Some(field.to_vec());
            }
            _ => {}
        }
    }
    Ok(Action {
        id: id.ok_or_else(|| field_fault(action_tag::ID, "is missing"))?,
        kind: kind.ok_or_else(|| field_fault(action_tag::KIND, "is missing"))?,
        body: body.ok_or_else(|| field_fault(action_tag::BODY, "is missing"))?,
    })
}

/// One answer's bytes.
pub(super) fn encode_answer(answer: &ActionAnswer) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32);
    bytes.extend_from_slice(ANSWER_MAGIC);
    bytes.push(VERSION);
    let (status, step, result, delay) = match answer {
        ActionAnswer::Ran { result } => (1, None, Some(result.as_slice()), None),
        ActionAnswer::RanNotCarried => (2, None, None, None),
        ActionAnswer::AlreadyExecuted => (3, None, None, None),
        ActionAnswer::NotRun => (4, None, None, None),
        ActionAnswer::Refused { step } => (5, Some(step_byte(*step)), None, None),
        ActionAnswer::NotReady => (6, None, None, None),
        ActionAnswer::Unsupported => (7, None, None, None),
        ActionAnswer::Unknown => (8, None, None, None),
        ActionAnswer::SlowDown { retry_after } => {
            let seconds = u32::try_from(retry_after.as_secs()).unwrap_or(u32::MAX);
            (9, None, None, Some(seconds.to_be_bytes()))
        }
        ActionAnswer::MemoryFull => (10, None, None, None),
        ActionAnswer::NotRecorded => (11, None, None, None),
        ActionAnswer::Busy => (12, None, None, None),
        ActionAnswer::Unreadable => (13, None, None, None),
    };
    short(&mut bytes, answer_tag::STATUS, &[status]);
    if let Some(step) = step {
        short(&mut bytes, answer_tag::STEP, &[step]);
    }
    if let Some(result) = result {
        short(&mut bytes, answer_tag::RESULT, result);
    }
    if let Some(delay) = delay {
        short(&mut bytes, answer_tag::RETRY_AFTER, &delay);
    }
    bytes
}

/// One answer, from its bytes.
pub(super) fn decode_answer(bytes: &[u8]) -> Result<ActionAnswer, ActionError> {
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
    let mut step = None;
    let mut result = None;
    let mut retry_after = None;
    for field in tlv::Fields::new(rest) {
        let (tag, field) = field.map_err(field_error)?;
        match tag {
            answer_tag::STATUS => {
                let [byte] = field else {
                    return Err(field_fault(tag, "is not one byte"));
                };
                status = Some(*byte);
            }
            answer_tag::STEP => {
                let [byte] = field else {
                    return Err(field_fault(tag, "is not one byte"));
                };
                step = Some(
                    step_of(*byte)
                        .ok_or_else(|| field_fault(tag, "names no step this build knows"))?,
                );
            }
            answer_tag::RESULT => {
                if field.len() > MAX_RESULT_BYTES {
                    return Err(field_fault(tag, "is longer than the result cap"));
                }
                result = Some(field.to_vec());
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
        1 => Ok(ActionAnswer::Ran {
            result: result.ok_or_else(|| field_fault(answer_tag::RESULT, "is missing"))?,
        }),
        2 => Ok(ActionAnswer::RanNotCarried),
        3 => Ok(ActionAnswer::AlreadyExecuted),
        4 => Ok(ActionAnswer::NotRun),
        5 => Ok(ActionAnswer::Refused {
            step: step.ok_or_else(|| field_fault(answer_tag::STEP, "is missing"))?,
        }),
        6 => Ok(ActionAnswer::NotReady),
        7 => Ok(ActionAnswer::Unsupported),
        8 => Ok(ActionAnswer::Unknown),
        9 => Ok(ActionAnswer::SlowDown {
            retry_after: retry_after
                .ok_or_else(|| field_fault(answer_tag::RETRY_AFTER, "is missing"))?
                .min(ACTION_WINDOW),
        }),
        10 => Ok(ActionAnswer::MemoryFull),
        11 => Ok(ActionAnswer::NotRecorded),
        12 => Ok(ActionAnswer::Busy),
        13 => Ok(ActionAnswer::Unreadable),
        other => Err(field_fault(
            answer_tag::STATUS,
            &format!("is {other}, which is not one this build knows"),
        )),
    }
}

/// The byte a step is written as.
const fn step_byte(step: Step) -> u8 {
    match step {
        Step::Authenticate => 1,
        Step::Right => 2,
        Step::Floor => 3,
    }
}

/// The step a byte names, when it is one this build knows.
const fn step_of(byte: u8) -> Option<Step> {
    match byte {
        1 => Some(Step::Authenticate),
        2 => Some(Step::Right),
        3 => Some(Step::Floor),
        _ => None,
    }
}

/// Append one short field, whose body is bounded by its own type.
fn short(bytes: &mut Vec<u8>, tag: u8, body: &[u8]) {
    tlv::put(bytes, tag, body).expect("a short field fits its frame");
}

/// A frame fault.
fn frame(reason: FramingFault) -> ActionError {
    ActionError::Frame { reason }
}

/// One field's framing fault, in the frame's vocabulary.
fn field_error(error: tlv::FieldError) -> ActionError {
    frame(FramingFault::Field {
        tag: error.tag,
        detail: error.detail.to_owned(),
    })
}

/// A known field with the wrong shape.
fn field_fault(tag: u8, detail: &str) -> ActionError {
    frame(FramingFault::Field {
        tag,
        detail: detail.to_owned(),
    })
}
