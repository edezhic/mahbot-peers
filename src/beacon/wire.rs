//! The beacon's closed message set, as bytes.
//!
//! One frame is `[version][kind][body_len u32][body]`; every frame carries the
//! protocol version, so a change to the set is a version mismatch a caller can
//! name rather than a field it silently misreads. The set is closed: a kind that
//! is not listed here, a body that is not exactly the length its kind implies,
//! or a stream that carries a second frame after the first is refused.
//!
//! This module is sans-I/O apart from [`Frame::read`] and [`write()`], which
//! take a `quinn` stream and nothing else: the server's state machine and the
//! client's request loop both speak these types, so the wire has one definition.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;

use quinn::{RecvStream, SendStream};

use super::{BeaconError, Introduction};
use crate::identity::{PEER_ID_LEN, PeerId, SIGNATURE_LEN};

/// The protocol version every frame carries. The ALPN does not carry it: a change
/// to the message set bumps this number only, so a peer that predates the change
/// still completes the handshake and is then named in a refusal — "the beacon
/// speaks 2, this client speaks 1" — instead of failing TLS with a generic
/// transport error.
pub const PROTOCOL_VERSION: u8 = 1;

/// The largest frame this protocol reads or writes, header included. A peer that
/// announces more is refused before a byte of its body is buffered.
pub const MAX_FRAME_BYTES: usize = 16 * 1024;

/// `[version][kind][body_len u32 big-endian]`.
const HEADER_BYTES: usize = 6;

/// The kind byte of every message in the closed set. Requests, answers and
/// server-initiated pushes occupy separate ranges, so a message sent the wrong
/// way is an unknown kind rather than a plausible request.
mod kind {
    pub const REGISTER: u8 = 0x01;
    pub const LOOKUP: u8 = 0x02;
    pub const OBSERVED_ADDRESS: u8 = 0x03;
    pub const INTRODUCE: u8 = 0x04;

    pub const REGISTERED: u8 = 0x81;
    pub const ADDRESS: u8 = 0x82;
    pub const OBSERVED: u8 = 0x83;
    pub const DELIVERED: u8 = 0x84;
    pub const UNKNOWN_PEER: u8 = 0x85;
    pub const REFUSED: u8 = 0x8F;

    pub const INTRODUCTION: u8 = 0xC1;
}

/// One frame: the version it was written under, its kind, and its body.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Frame {
    version: u8,
    kind: u8,
    body: Vec<u8>,
}

impl Frame {
    /// Build a frame. Nothing is validated: this is the constructor the test rig
    /// uses to speak bytes the typed messages would not produce.
    #[must_use]
    pub fn new(version: u8, kind: u8, body: Vec<u8>) -> Self {
        Self {
            version,
            kind,
            body,
        }
    }

    #[must_use]
    pub const fn version(&self) -> u8 {
        self.version
    }

    #[must_use]
    pub const fn kind(&self) -> u8 {
        self.kind
    }

    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Refuse a frame written under another protocol version, naming both.
    ///
    /// The decoders below are deliberately version-agnostic: they read the body
    /// only after the caller has established that the version is this one, so a
    /// future message set is never misread as this one.
    pub fn require_version(&self) -> Result<(), BeaconError> {
        if self.version == PROTOCOL_VERSION {
            Ok(())
        } else {
            Err(BeaconError::VersionMismatch {
                beacon: self.version,
                client: PROTOCOL_VERSION,
            })
        }
    }

    /// The whole frame, header included.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let len = u32::try_from(self.body.len()).unwrap_or(u32::MAX);
        let mut bytes = Vec::with_capacity(HEADER_BYTES + self.body.len());
        bytes.push(self.version);
        bytes.push(self.kind);
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend_from_slice(&self.body);
        bytes
    }

    /// Read exactly one frame from a stream that must end after it.
    ///
    /// The length is checked before the body is read, so an oversized frame costs
    /// a header and no buffer; a second frame on the same stream is refused, which
    /// is what makes the message set closed rather than merely enumerated.
    pub async fn read(recv: &mut RecvStream) -> Result<Self, BeaconError> {
        let mut header = [0u8; HEADER_BYTES];
        recv.read_exact(&mut header)
            .await
            .map_err(|error| read_error(&error))?;
        let body_len = usize::try_from(u32::from_be_bytes([
            header[2], header[3], header[4], header[5],
        ]))
        .unwrap_or(usize::MAX);
        if body_len > MAX_FRAME_BYTES - HEADER_BYTES {
            return Err(BeaconError::Malformed);
        }
        let mut bytes = vec![0u8; HEADER_BYTES + body_len];
        bytes[..HEADER_BYTES].copy_from_slice(&header);
        recv.read_exact(&mut bytes[HEADER_BYTES..])
            .await
            .map_err(|error| read_error(&error))?;
        let mut trailing = [0u8; 1];
        match recv.read(&mut trailing).await {
            Ok(None | Some(0)) => {}
            Err(error) => return Err(trailing_error(&error)),
            _ => return Err(BeaconError::Malformed),
        }
        Self::parse(&bytes)
    }

    /// Parse one complete frame from bytes, refusing a header that disagrees with
    /// the body's length and a frame larger than [`MAX_FRAME_BYTES`].
    ///
    /// # Errors
    ///
    /// [`BeaconError::Malformed`] when `bytes` is not exactly one frame.
    pub fn parse(bytes: &[u8]) -> Result<Self, BeaconError> {
        if bytes.len() < HEADER_BYTES || bytes.len() > MAX_FRAME_BYTES {
            return Err(BeaconError::Malformed);
        }
        let body_len =
            usize::try_from(u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]))
                .unwrap_or(usize::MAX);
        if bytes.len() != HEADER_BYTES + body_len {
            return Err(BeaconError::Malformed);
        }
        Ok(Self {
            version: bytes[0],
            kind: bytes[1],
            body: bytes[HEADER_BYTES..].to_vec(),
        })
    }
}

/// A stream that ended before its frame did is a malformed frame; a stream the
/// peer reset, or one whose connection is gone, is a dead exchange, not a frame
/// problem — a caller switching on the error to decide whether to reconnect must
/// not read it as malformed bytes.
fn read_error(error: &quinn::ReadExactError) -> BeaconError {
    match error {
        quinn::ReadExactError::FinishedEarly(_) => BeaconError::Malformed,
        quinn::ReadExactError::ReadError(error) => trailing_error(error),
    }
}

fn trailing_error(error: &quinn::ReadError) -> BeaconError {
    match error {
        quinn::ReadError::Reset(_)
        | quinn::ReadError::ConnectionLost(_)
        | quinn::ReadError::ClosedStream => BeaconError::Unavailable,
        quinn::ReadError::IllegalOrderedRead | quinn::ReadError::ZeroRttRejected => {
            BeaconError::Malformed
        }
    }
}

/// Write one frame and end the stream.
pub async fn write(send: &mut SendStream, bytes: &[u8]) -> Result<(), BeaconError> {
    send.write_all(bytes)
        .await
        .map_err(|_| BeaconError::Unavailable)?;
    send.finish().map_err(|_| BeaconError::Unavailable)
}

/// One request, from a client to the beacon.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Request {
    /// The caller is reachable at the address the beacon observes on this
    /// connection. No address and no id travel in the frame: the key is the
    /// connection's and the address is the path's.
    Register,
    /// Where `id` currently is.
    Lookup(PeerId),
    /// How the caller appears from outside, on this connection's path.
    ObservedAddress,
    /// Hand an opaque signed payload to `to`, live.
    Introduce {
        to: PeerId,
        signature: [u8; SIGNATURE_LEN],
        payload: Vec<u8>,
    },
}

impl Request {
    /// The whole frame, header included.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let (kind, body) = match self {
            Self::Register => (kind::REGISTER, Vec::new()),
            Self::Lookup(id) => (kind::LOOKUP, id.as_bytes().to_vec()),
            Self::ObservedAddress => (kind::OBSERVED_ADDRESS, Vec::new()),
            Self::Introduce {
                to,
                signature,
                payload,
            } => {
                let mut body = Vec::with_capacity(PEER_ID_LEN + SIGNATURE_LEN + 4 + payload.len());
                body.extend_from_slice(to.as_bytes());
                body.extend_from_slice(signature);
                body.extend_from_slice(
                    &u32::try_from(payload.len())
                        .unwrap_or(u32::MAX)
                        .to_be_bytes(),
                );
                body.extend_from_slice(payload);
                (kind::INTRODUCE, body)
            }
        };
        Frame::new(PROTOCOL_VERSION, kind, body).encode()
    }

    /// Decode a frame as a request, refusing any other kind.
    pub fn decode(frame: &Frame) -> Result<Self, BeaconError> {
        let mut body = Reader::new(frame.body());
        let request = match frame.kind() {
            kind::REGISTER => {
                body.finish()?;
                Self::Register
            }
            kind::LOOKUP => {
                let id = body.peer_id()?;
                body.finish()?;
                Self::Lookup(id)
            }
            kind::OBSERVED_ADDRESS => {
                body.finish()?;
                Self::ObservedAddress
            }
            kind::INTRODUCE => {
                let to = body.peer_id()?;
                let signature = body.signature()?;
                let payload = body.payload()?;
                body.finish()?;
                Self::Introduce {
                    to,
                    signature,
                    payload,
                }
            }
            other => return Err(BeaconError::UnknownMessage(other)),
        };
        Ok(request)
    }

    /// The introduce request carrying `introduction`'s parts, moved rather than
    /// copied: the sender and the verifier build the same value.
    pub(crate) fn introduce(introduction: Introduction) -> Self {
        let Introduction {
            to,
            signature,
            payload,
            ..
        } = introduction;
        Self::Introduce {
            to,
            signature,
            payload,
        }
    }
}

/// One answer, from the beacon to a client.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Response {
    /// The caller is registered until `lifetime` from the moment it registered.
    Registered { lifetime: Duration },
    /// Where the id is, if it is registered at all.
    Address(Option<SocketAddr>),
    /// The caller's own address, as observed on the connection it asked over.
    Observed(SocketAddr),
    /// The frame was written to the addressee's live connection. It is not proof
    /// that the addressee's application read it — delivery is at-least-once — and
    /// nothing is stored for a later attempt.
    Delivered,
    /// The beacon did not hand the frame to the addressee: it holds no registration for it, or
    /// the connection it is registered on could not take the frame within the server's exchange
    /// bound. Either way nothing was stored. This is the beacon's one answer about a delivery,
    /// and it is not a statement about the peer.
    UnknownPeer(PeerId),
    /// The request was not understood. See [`Refusal`].
    Refused(Refusal),
}

impl Response {
    /// The answer's name, for an error that must say what arrived instead.
    pub(crate) const fn name(&self) -> &'static str {
        match self {
            Self::Registered { .. } => "Registered",
            Self::Address(_) => "Address",
            Self::Observed(_) => "Observed",
            Self::Delivered => "Delivered",
            Self::UnknownPeer(_) => "UnknownPeer",
            Self::Refused(_) => "Refused",
        }
    }

    /// The whole frame, header included.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let (kind, body) = match self {
            Self::Registered { lifetime } => {
                let seconds = u32::try_from(lifetime.as_secs()).unwrap_or(u32::MAX);
                (kind::REGISTERED, seconds.to_be_bytes().to_vec())
            }
            Self::Address(address) => (kind::ADDRESS, encode_optional_address(*address)),
            Self::Observed(address) => (kind::OBSERVED, encode_address(*address)),
            Self::Delivered => (kind::DELIVERED, Vec::new()),
            Self::UnknownPeer(id) => (kind::UNKNOWN_PEER, id.as_bytes().to_vec()),
            Self::Refused(refusal) => (kind::REFUSED, vec![refusal.code()]),
        };
        Frame::new(PROTOCOL_VERSION, kind, body).encode()
    }

    /// Decode a frame as an answer, refusing any other kind.
    pub fn decode(frame: &Frame) -> Result<Self, BeaconError> {
        let mut body = Reader::new(frame.body());
        let response = match frame.kind() {
            kind::REGISTERED => {
                let seconds = body.u32()?;
                body.finish()?;
                Self::Registered {
                    lifetime: Duration::from_secs(u64::from(seconds)),
                }
            }
            kind::ADDRESS => {
                let address = body.optional_address()?;
                body.finish()?;
                Self::Address(address)
            }
            kind::OBSERVED => {
                let address = body.address()?;
                body.finish()?;
                Self::Observed(address)
            }
            kind::DELIVERED => {
                body.finish()?;
                Self::Delivered
            }
            kind::UNKNOWN_PEER => {
                let id = body.peer_id()?;
                body.finish()?;
                Self::UnknownPeer(id)
            }
            kind::REFUSED => {
                let refusal = Refusal::decode(body.u8()?)?;
                body.finish()?;
                Self::Refused(refusal)
            }
            other => return Err(BeaconError::UnknownMessage(other)),
        };
        Ok(response)
    }
}

/// One message the beacon pushes to a client, unprompted.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Push {
    /// An opaque payload a peer asked the beacon to hand over.
    Introduction {
        from: PeerId,
        to: PeerId,
        signature: [u8; SIGNATURE_LEN],
        payload: Vec<u8>,
    },
}

impl Push {
    /// The whole frame, header included.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let Self::Introduction {
            from,
            to,
            signature,
            payload,
        } = self;
        let mut body = Vec::with_capacity(2 * PEER_ID_LEN + SIGNATURE_LEN + 4 + payload.len());
        body.extend_from_slice(from.as_bytes());
        body.extend_from_slice(to.as_bytes());
        body.extend_from_slice(signature);
        body.extend_from_slice(
            &u32::try_from(payload.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        body.extend_from_slice(payload);
        Frame::new(PROTOCOL_VERSION, kind::INTRODUCTION, body).encode()
    }

    /// Decode a frame as a push, refusing any other kind.
    pub fn decode(frame: &Frame) -> Result<Self, BeaconError> {
        if frame.kind() != kind::INTRODUCTION {
            return Err(BeaconError::UnknownMessage(frame.kind()));
        }
        let mut body = Reader::new(frame.body());
        let from = body.peer_id()?;
        let to = body.peer_id()?;
        let signature = body.signature()?;
        let payload = body.payload()?;
        body.finish()?;
        Ok(Self::Introduction {
            from,
            to,
            signature,
            payload,
        })
    }
}

/// Why the beacon refused a request. The set is closed like the messages it
/// answers: an unknown code is reported as an unknown message, never guessed at.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// The frame was written under another protocol version.
    VersionMismatch,
    /// The kind is not in the message set, or was sent in the wrong direction.
    UnknownMessage,
    /// The body is not what its kind implies.
    Malformed,
    /// An introduction payload is over [`MAX_PAYLOAD_BYTES`](super::MAX_PAYLOAD_BYTES).
    PayloadTooLarge,
    /// The exchange did not complete within the beacon's bound: a peer opened a
    /// stream and did not finish its frame in time.
    Slow,
}

impl Refusal {
    const fn code(self) -> u8 {
        match self {
            Self::VersionMismatch => 1,
            Self::UnknownMessage => 2,
            Self::Malformed => 3,
            Self::PayloadTooLarge => 4,
            Self::Slow => 5,
        }
    }

    const fn decode(code: u8) -> Result<Self, BeaconError> {
        match code {
            1 => Ok(Self::VersionMismatch),
            2 => Ok(Self::UnknownMessage),
            3 => Ok(Self::Malformed),
            4 => Ok(Self::PayloadTooLarge),
            5 => Ok(Self::Slow),
            other => Err(BeaconError::UnknownMessage(other)),
        }
    }
}

/// A cursor over a frame body. Every read is length-checked, so a body that is
/// short, long or shaped differently from its kind is [`BeaconError::Malformed`].
struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], BeaconError> {
        if self.bytes.len() < len {
            return Err(BeaconError::Malformed);
        }
        let (taken, rest) = self.bytes.split_at(len);
        self.bytes = rest;
        Ok(taken)
    }

    fn u8(&mut self) -> Result<u8, BeaconError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, BeaconError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn peer_id(&mut self) -> Result<PeerId, BeaconError> {
        let bytes = self.take(PEER_ID_LEN)?;
        let mut id = [0u8; PEER_ID_LEN];
        id.copy_from_slice(bytes);
        Ok(PeerId::from_bytes(id))
    }

    fn signature(&mut self) -> Result<[u8; SIGNATURE_LEN], BeaconError> {
        let bytes = self.take(SIGNATURE_LEN)?;
        let mut signature = [0u8; SIGNATURE_LEN];
        signature.copy_from_slice(bytes);
        Ok(signature)
    }

    fn payload(&mut self) -> Result<Vec<u8>, BeaconError> {
        let len = usize::try_from(self.u32()?).unwrap_or(usize::MAX);
        super::check_payload_len(len)?;
        Ok(self.take(len)?.to_vec())
    }

    fn address(&mut self) -> Result<SocketAddr, BeaconError> {
        match self.u8()? {
            4 => {
                let octets = self.take(4)?;
                let port = self.u16()?;
                Ok(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]),
                    port,
                )))
            }
            6 => {
                let octets = self.take(16)?;
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(octets);
                let port = self.u16()?;
                let flowinfo = self.u32()?;
                let scope_id = self.u32()?;
                Ok(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(bytes),
                    port,
                    flowinfo,
                    scope_id,
                )))
            }
            _ => Err(BeaconError::Malformed),
        }
    }

    fn optional_address(&mut self) -> Result<Option<SocketAddr>, BeaconError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.address()?)),
            _ => Err(BeaconError::Malformed),
        }
    }

    fn u16(&mut self) -> Result<u16, BeaconError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn finish(self) -> Result<(), BeaconError> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(BeaconError::Malformed)
        }
    }
}

fn encode_address(address: SocketAddr) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(1 + 16 + 2 + 8);
    match address {
        SocketAddr::V4(v4) => {
            bytes.push(4);
            bytes.extend_from_slice(&v4.ip().octets());
            bytes.extend_from_slice(&v4.port().to_be_bytes());
        }
        SocketAddr::V6(v6) => {
            bytes.push(6);
            bytes.extend_from_slice(&v6.ip().octets());
            bytes.extend_from_slice(&v6.port().to_be_bytes());
            // A link-local address is meaningless without its scope, so the codec
            // carries both extra fields rather than decoding a different address
            // than the one it was given.
            bytes.extend_from_slice(&v6.flowinfo().to_be_bytes());
            bytes.extend_from_slice(&v6.scope_id().to_be_bytes());
        }
    }
    bytes
}

fn encode_optional_address(address: Option<SocketAddr>) -> Vec<u8> {
    match address {
        Some(address) => {
            let mut bytes = vec![1];
            bytes.extend_from_slice(&encode_address(address));
            bytes
        }
        None => vec![0],
    }
}
