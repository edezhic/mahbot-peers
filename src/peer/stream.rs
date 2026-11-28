//! The stream half every peer service shares: read a frame's kind, read the rest under a cap,
//! and write an answer back under a bound.
//!
//! Exactly one place accepts a stream after the binding exchange — [`crate::peer::inbox`] — and it
//! classifies the frame by its magic before handing it to the layer that owns it.

use std::future::Future;
use std::pin::pin;
use std::time::Duration;

use quinn::{RecvStream, Runtime, SendStream};

use crate::beacon::timeout;

/// How many bytes of a frame the dispatcher reads before it knows whose frame it is.
///
/// The longest request magic is `mahbot-peer-transfer`; a whole prefix is enough to tell a
/// message from an action or a transfer, and the layer that owns the frame reads the rest.
pub(crate) const PREFIX_BYTES: usize = 32;

/// How long the dispatcher waits for a frame's first bytes.
///
/// A peer that opens a stream and writes nothing is not visible to `accept_bi` until it
/// writes; one that writes a byte and stalls spends this bound, and the layer that owns the
/// frame spends its own budget on the rest.
const PREFIX_BUDGET: Duration = Duration::from_secs(10);

/// What became of a frame's bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReadFault {
    /// The stream carried more than the layer's cap.
    TooLong,
    /// The stream was reset, or the budget passed before the frame was whole.
    Stalled,
}

/// Read a frame's first bytes, bounded by [`PREFIX_BUDGET`] as a whole: whatever arrived is the
/// answer, and the layer that owns the frame tells a slow frame from one that will never arrive.
pub(crate) async fn read_prefix(runtime: &dyn Runtime, recv: &mut RecvStream) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(PREFIX_BYTES);
    let _ = read_upto(runtime, recv, &mut bytes, PREFIX_BYTES, PREFIX_BUDGET).await;
    bytes
}

/// Read up to `want` bytes of a frame into `bytes`, bounded by `budget` as a whole.
///
/// The budget covers the whole read, not one call of `read`: a peer that dribbles a byte at a
/// time spends at most the budget rather than re-arming the bound on every byte. `read` is
/// cancel-safe, so a budget that passes leaves the stream where it was and what arrived so far
/// in `bytes`; the caller decides whether a frame it has not finished is worth waiting for.
/// The flag says the stream ended or was reset before `want` was reached.
pub(crate) async fn read_upto(
    runtime: &dyn Runtime,
    recv: &mut RecvStream,
    bytes: &mut Vec<u8>,
    want: usize,
    budget: Duration,
) -> bool {
    let mut buffer = [0u8; 256];
    let ended = timeout(runtime, budget, async {
        while bytes.len() < want {
            let room = (want - bytes.len()).min(buffer.len());
            match recv.read(&mut buffer[..room]).await {
                Ok(Some(count)) if count > 0 => bytes.extend_from_slice(&buffer[..count]),
                _ => return true,
            }
        }
        false
    })
    .await;
    ended.unwrap_or(false)
}

/// Read the rest of a frame after `prefix`, refusing one longer than `cap`.
///
/// The whole frame is returned — the prefix and what followed it — because every decoder in
/// this crate reads its magic from the first byte. A frame longer than `cap` is refused
/// without being read whole; the caller answers the sender with its own unreadable answer.
pub(crate) async fn read_rest(
    runtime: &dyn Runtime,
    recv: &mut RecvStream,
    mut prefix: Vec<u8>,
    cap: usize,
    budget: Duration,
) -> Result<Vec<u8>, ReadFault> {
    if prefix.len() > cap {
        return Err(ReadFault::TooLong);
    }
    let room = cap - prefix.len();
    let rest = timeout(runtime, budget, recv.read_to_end(room)).await;
    match rest {
        Some(Ok(bytes)) => {
            prefix.extend_from_slice(&bytes);
            Ok(prefix)
        }
        Some(Err(quinn::ReadToEndError::TooLong)) => Err(ReadFault::TooLong),
        Some(Err(quinn::ReadToEndError::Read(_))) | None => Err(ReadFault::Stalled),
    }
}

/// Write `bytes` whole, bounded; `false` when the stream took less than all of them.
///
/// A budget that passes cancels `write_all` where it stands, so a caller that gets `false` has
/// a fragment on the stream and must treat it as broken rather than writing after it.
pub(crate) async fn write_whole(
    runtime: &dyn Runtime,
    send: &mut SendStream,
    bytes: &[u8],
    budget: Duration,
) -> bool {
    matches!(
        timeout(runtime, budget, send.write_all(bytes)).await,
        Some(Ok(()))
    )
}

/// Write one answer back, bounded like every other wait this crate makes.
///
/// A peer that stops reading — or advertises a stream window smaller than the answer — would
/// otherwise park the answering task for good, while keep-alives kept the connection looking
/// healthy. On a timeout the stream is dropped, which ends it after whatever part of the
/// answer the window took, so the sender reads a partial answer or an error rather than
/// waiting for a stream this machine never finishes.
pub(crate) async fn write_reply(
    runtime: &dyn Runtime,
    mut send: SendStream,
    bytes: &[u8],
    budget: Duration,
) {
    if write_whole(runtime, &mut send, bytes, budget).await {
        let _ = send.finish();
    }
}

/// Poll `first` and `second` together, returning the first result either produces.
///
/// The two services of a pair — the message offer loop and the stream reader — belong to one
/// task and one caller, so one ending reaches whoever started them. A future that returns
/// `Ok` ends the pair's service; both are infinite loops that return only a refusal.
pub(crate) async fn either<F, S, T, E>(first: F, second: S) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
    S: Future<Output = Result<T, E>>,
{
    let mut first = pin!(first);
    let mut second = pin!(second);
    std::future::poll_fn(|context| {
        if let std::task::Poll::Ready(result) = first.as_mut().poll(context) {
            return std::task::Poll::Ready(result);
        }
        if let std::task::Poll::Ready(result) = second.as_mut().poll(context) {
            return std::task::Poll::Ready(result);
        }
        std::task::Poll::Pending
    })
    .await
}
