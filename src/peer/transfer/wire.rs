//! The two frames a transfer speaks, and the closed answer set they carry.
//!
//! # The bytes
//!
//! Both frames are `magic`, one version byte, then a four-byte big-endian body length,
//! then `[tag][len u16 big-endian][body]` fields — the framing the record, the log, the
//! binding, a message and an action use, with one difference: the body's length is
//! stated, because a transfer's stream carries raw file bytes after its offer and a
//! reader must know where the frame ends.
//!
//! An offer is `mahbot-peer-transfer`: `0x01` the name, `0x02` the file's length in
//! bytes and `0x03` its SHA-256 digest. All three are required. The frame is at most
//! [`OFFER_CAP`], which is far below the message layer's body cap, so a peer that
//! does not know transfers reads the offer whole as a message it cannot parse and
//! answers "unreadable" — the older-peer path this crate keeps.
//!
//! An answer is `mahbot-peer-transfer-answer`: `0x01` the status (one byte), `0x02`
//! the receiver's offset (8, with `resume` and with `running`), `0x03` the delay in whole
//! seconds (4, only with a limit that throttles) and `0x04` which limit (one byte, only with
//! `limit`). A refusal carries no text: the class travels, and the receiver's words
//! stay on the receiver. The set grows by appending, and no meaning moves once a build
//! has shipped.
//!
//! A `running` answer travels twice, and both times it says the same thing: a transfer under
//! that name is running on the receiving machine, and this is how far it has got. It is the
//! answer to an offer whose name another stream already holds, and it is the word a receiving
//! machine sends on the same stream while its sink is slow — which is what keeps a sender parked
//! at the transport's window edge from calling a working transfer stopped. The sending side
//! tells the two apart by where it reads them, not by anything in the frame: the answer to an
//! offer is the first frame on the stream, and a progress word is one that follows a `resume`.
//!
//! A start limit that names no delay is still a throttle — one look — because the class is what
//! the answer means; a peer cannot end a transfer by leaving the field out.
//!
//! The delay is the one number in either frame that comes from the peer, and it is decoded as the
//! peer wrote it: what bounds it is the transfer's own rule, applied where a start limit is taken
//! as the throttle it means — see [`TRANSFER_THROTTLE_CAP`](crate::peer::TRANSFER_THROTTLE_CAP).
//!
//! # Which direction each answer travels
//!
//! Every answer is the receiving machine's word to the sender. The one signal that travels the
//! other way is not a frame: a sending product that stops a running transfer resets the stream
//! with the transfer's stop code, because a transfer's stream carries raw file bytes after the
//! offer and a reader cannot tell a frame in the middle of them from bytes.
//!
//! # What a version means
//!
//! Version 1 is what this build writes. A version of zero is not a frame and is not
//! read. A version above this build's is read as this version's prefix: its fields
//! are read and its unknown tags are ignored. A missing required field is a frame this
//! build cannot read, and so is a body longer than the cap, and so is a stream that ends
//! before the body its header states — a frame written short is a frame the sender
//! finished. A status byte this build does not know is not a guess: it reaches the sender
//! as "not understood", which is what the sender does with any answer it cannot read. The
//! set is closed, so a class added after this build shipped is not a wire value this build
//! can write.
//!
//! Nothing here says why a frame could not be read: a decoder answers `None`, and the two
//! call sites turn that into the one word the layer has for it — `malformed` on the
//! receiving side, "not understood" on the sending one.

use crate::peer::transfer::{Digest, TransferAnswer, TransferLimit, TransferName};
use crate::peer::{Step, tlv};
use std::time::Duration;

/// The most bytes one offer frame may have: a name at its bound, a length and a digest, and
/// room for the tags around them.
pub(super) const OFFER_CAP: usize = 512;

/// The most bytes one answer frame may have.
pub(super) const ANSWER_CAP: usize = 256;

/// The bytes an offer opens with: what the inbox tells a transfer from a message.
pub(crate) const OFFER_MAGIC: &[u8] = b"mahbot-peer-transfer";

/// The bytes an answer opens with.
pub(super) const ANSWER_MAGIC: &[u8] = b"mahbot-peer-transfer-answer";

// The inbox recognises an answer on a prefix of `stream::PREFIX_BYTES`; a magic the prefix
// cannot hold whole would make every answer read as a message, and the sender would learn
// "not understood" for the whole vocabulary. The coupling is checked here rather than found
// on a wire.
const _: () = assert!(ANSWER_MAGIC.len() < crate::peer::stream::PREFIX_BYTES);

/// The frame version this build writes.
const VERSION: u8 = 1;

/// How many bytes a frame's magic, version and body length take.
pub(super) const HEADER_BYTES: usize = OFFER_MAGIC.len() + 1 + 4;

/// The same for an answer, whose magic is longer than an offer's.
pub(super) const ANSWER_HEADER_BYTES: usize = ANSWER_MAGIC.len() + 1 + 4;

/// An offer's field tags. Unknown tags are ignored.
mod offer_tag {
    pub const NAME: u8 = 0x01;
    pub const LENGTH: u8 = 0x02;
    pub const DIGEST: u8 = 0x03;
}

/// An answer's field tags. Unknown tags are ignored.
mod answer_tag {
    pub const STATUS: u8 = 0x01;
    pub const OFFSET: u8 = 0x02;
    pub const RETRY_AFTER: u8 = 0x03;
    pub const WHICH: u8 = 0x04;
}

/// The status bytes this build writes, and the only ones it reads. The set is closed: a
/// byte outside this list is not an answer, and status 10 is not one either — no build
/// ever wrote it.
mod status {
    pub const ALREADY_COMPLETE: u8 = 1;
    pub const RUNNING: u8 = 2;
    pub const REFUSED: u8 = 3;
    pub const NOT_RECORDED: u8 = 4;
    pub const LIMIT: u8 = 5;
    pub const CONFLICT: u8 = 6;
    pub const DIGEST_MISMATCH: u8 = 7;
    pub const STORE_FAILED: u8 = 8;
    pub const STOPPED: u8 = 9;
    pub const RESUME: u8 = 11;
    pub const COMPLETE: u8 = 12;
    pub const MALFORMED: u8 = 13;
}

/// What one offer says, as a reader takes it.
pub(super) struct Offer {
    pub name: TransferName,
    pub length: u64,
    pub digest: Digest,
}

/// An offer's bytes.
pub(super) fn encode_offer(name: &TransferName, length: u64, digest: &Digest) -> Vec<u8> {
    let mut body = Vec::with_capacity(64);
    put(&mut body, offer_tag::NAME, name.as_bytes());
    put(&mut body, offer_tag::LENGTH, &length.to_be_bytes());
    put(&mut body, offer_tag::DIGEST, digest.as_bytes());
    frame(OFFER_MAGIC, &body)
}

/// One offer, from its bytes.
pub(super) fn decode_offer(bytes: &[u8]) -> Option<Offer> {
    let body = body_of(OFFER_MAGIC, bytes)?;
    let mut name = None;
    let mut length = None;
    let mut digest = None;
    for field in tlv::Fields::new(body) {
        let (tag, body) = field.ok()?;
        match tag {
            offer_tag::NAME => {
                name = Some(TransferName::new(std::str::from_utf8(body).ok()?).ok()?);
            }
            offer_tag::LENGTH => length = Some(tlv::u64_of(tag, body).ok()?),
            offer_tag::DIGEST => digest = Some(Digest::from_slice(body)?),
            _ => {}
        }
    }
    Some(Offer {
        name: name?,
        length: length?,
        digest: digest?,
    })
}

/// An answer's bytes.
pub(super) fn encode_answer(answer: &TransferAnswer) -> Vec<u8> {
    let mut body = Vec::with_capacity(24);
    let (status, offset, retry_after, which) = match answer {
        TransferAnswer::AlreadyComplete => (status::ALREADY_COMPLETE, None, None, None),
        TransferAnswer::Running { have } => (status::RUNNING, Some(*have), None, None),
        TransferAnswer::Refused { step } => (status::REFUSED, None, None, Some(step_byte(*step))),
        TransferAnswer::NotRecorded => (status::NOT_RECORDED, None, None, None),
        TransferAnswer::Limit { which, retry_after } => (
            status::LIMIT,
            None,
            retry_after.map(|after| after.as_secs()),
            Some(limit_byte(*which)),
        ),
        TransferAnswer::Conflict => (status::CONFLICT, None, None, None),
        TransferAnswer::DigestMismatch => (status::DIGEST_MISMATCH, None, None, None),
        TransferAnswer::StoreFailed => (status::STORE_FAILED, None, None, None),
        TransferAnswer::Stopped => (status::STOPPED, None, None, None),
        TransferAnswer::Resume { have } => (status::RESUME, Some(*have), None, None),
        TransferAnswer::Complete => (status::COMPLETE, None, None, None),
        TransferAnswer::Malformed => (status::MALFORMED, None, None, None),
    };
    put(&mut body, answer_tag::STATUS, &[status]);
    if let Some(offset) = offset {
        put(&mut body, answer_tag::OFFSET, &offset.to_be_bytes());
    }
    if let Some(which) = which {
        put(&mut body, answer_tag::WHICH, &[which]);
    }
    if let Some(after) = retry_after {
        let seconds = u32::try_from(after).unwrap_or(u32::MAX);
        put(&mut body, answer_tag::RETRY_AFTER, &seconds.to_be_bytes());
    }
    frame(ANSWER_MAGIC, &body)
}

/// One answer, from its bytes.
pub(super) fn decode_answer(bytes: &[u8]) -> Option<TransferAnswer> {
    let body = body_of(ANSWER_MAGIC, bytes)?;
    let mut status = None;
    let mut offset = None;
    let mut retry_after = None;
    let mut which = None;
    for field in tlv::Fields::new(body) {
        let (tag, body) = field.ok()?;
        match tag {
            answer_tag::STATUS => status = Some(one_byte(body)?),
            answer_tag::OFFSET => offset = Some(tlv::u64_of(tag, body).ok()?),
            answer_tag::RETRY_AFTER => {
                let seconds: [u8; 4] = body.try_into().ok()?;
                retry_after = Some(u64::from(u32::from_be_bytes(seconds)));
            }
            answer_tag::WHICH => which = Some(one_byte(body)?),
            _ => {}
        }
    }
    Some(match status? {
        status::ALREADY_COMPLETE => TransferAnswer::AlreadyComplete,
        status::RUNNING => TransferAnswer::Running { have: offset? },
        status::REFUSED => TransferAnswer::Refused {
            step: step_of(which?)?,
        },
        status::NOT_RECORDED => TransferAnswer::NotRecorded,
        status::LIMIT => {
            let which = limit_of(which?)?;
            // Only a start limit names a delay: a limit on running transfers is terminal, so a
            // delay beside it would be a peer's number nothing acts on. The delay a start limit
            // carries is decoded as the frame has it; bounding it is the transfer's own rule,
            // applied once, where the limit is taken as the throttle it means.
            TransferAnswer::Limit {
                which,
                retry_after: match which {
                    TransferLimit::Starts => retry_after.map(Duration::from_secs),
                    TransferLimit::Transfers => None,
                },
            }
        }
        status::CONFLICT => TransferAnswer::Conflict,
        status::DIGEST_MISMATCH => TransferAnswer::DigestMismatch,
        status::STORE_FAILED => TransferAnswer::StoreFailed,
        status::STOPPED => TransferAnswer::Stopped,
        status::RESUME => TransferAnswer::Resume { have: offset? },
        status::COMPLETE => TransferAnswer::Complete,
        status::MALFORMED => TransferAnswer::Malformed,
        // A status this build does not know: an answer in a vocabulary it cannot read, which
        // reaches the sender as "not understood" and never as a guess.
        _ => return None,
    })
}

/// The bytes a frame with `magic` and `body` has.
fn frame(magic: &[u8], body: &[u8]) -> Vec<u8> {
    let length = u32::try_from(body.len()).expect("a transfer frame is far below four gibibytes");
    let mut bytes = Vec::with_capacity(magic.len() + 5 + body.len());
    bytes.extend_from_slice(magic);
    bytes.push(VERSION);
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(body);
    bytes
}

/// The body of a frame, or `None` when the bytes are not one this build reads.
fn body_of<'a>(magic: &[u8], bytes: &'a [u8]) -> Option<&'a [u8]> {
    let rest = bytes.strip_prefix(magic)?;
    let (&version, rest) = rest.split_first()?;
    if version == 0 {
        return None;
    }
    let (length, rest) = rest.split_first_chunk::<4>()?;
    let length = usize::try_from(u32::from_be_bytes(*length)).ok()?;
    rest.get(..length)
}

/// Whether `bytes` could still be a frame opening with `magic`: the magic's own first bytes, or
/// the magic and more.
pub(super) fn is_open_magic(magic: &[u8], bytes: &[u8]) -> bool {
    let open = magic.len().min(bytes.len());
    magic.get(..open) == bytes.get(..open)
}

/// The body length a frame's header states, when the `header`-byte header is whole.
pub(super) fn body_length(bytes: &[u8], header: usize) -> Option<usize> {
    let rest = bytes.get(header.checked_sub(4)?..header)?;
    usize::try_from(u32::from_be_bytes(<[u8; 4]>::try_from(rest).ok()?)).ok()
}

fn put(body: &mut Vec<u8>, tag: u8, bytes: &[u8]) {
    tlv::put(body, tag, bytes).expect("a transfer field is far below 64 KiB");
}

fn one_byte(body: &[u8]) -> Option<u8> {
    let [byte] = body else {
        return None;
    };
    Some(*byte)
}

const fn step_byte(step: Step) -> u8 {
    match step {
        Step::Authenticate => 1,
        Step::Right => 2,
        Step::Floor => 3,
    }
}

fn step_of(byte: u8) -> Option<Step> {
    match byte {
        1 => Some(Step::Authenticate),
        2 => Some(Step::Right),
        3 => Some(Step::Floor),
        _ => None,
    }
}

const fn limit_byte(which: TransferLimit) -> u8 {
    match which {
        TransferLimit::Transfers => 1,
        TransferLimit::Starts => 2,
    }
}

fn limit_of(byte: u8) -> Option<TransferLimit> {
    match byte {
        1 => Some(TransferLimit::Transfers),
        2 => Some(TransferLimit::Starts),
        _ => None,
    }
}
