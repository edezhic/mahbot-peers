//! The connection level's wire fact and the one exchange that carries it.
//!
//! # What travels
//!
//! The binding is this machine's own decision about the pair. When a connection is
//! established, each side sends the fact it holds — a [`Fact`], or nothing — over one
//! bidirectional stream, and takes the other side's as a
//! [`crate::peer::access::Claim`]. The claim names the pair for its person and grants
//! nothing: the decision never reads it, and the crate never allows anything because
//! another machine said so.
//!
//! # Why the exchange is best effort
//!
//! A peer built before this exchange existed does not answer, and a fact is a fact
//! that can be re-sent on the next connection: the exchange never fails a connection
//! and never closes one. The whole exchange is bounded by [`EXCHANGE_BUDGET`] of the
//! injected runtime's time, so a peer that opens a stream and stalls cannot park a
//! task. What comes back is the peer's fact as it arrived, byte for byte, and a peer
//! with no fact writes nothing.
//!
//! # What the exchange is not
//!
//! It is not the pair's traffic. A connection that only exchanged its binding and
//! then died carried nothing; `peer::connect` measures the frames the exchange itself
//! writes and does not count them.

use std::time::Duration;

use quinn::{Connection, Runtime};

use crate::beacon::timeout;
use crate::peer::access::Fact;
use crate::peer::connect::Started;

/// The most bytes one side may send in the exchange.
///
/// A fact is under five hundred bytes; the cap keeps a peer from making the reader
/// allocate by opening a stream and writing.
const MAX_FACT_BYTES: usize = 1024;

/// How long the exchange may take, measured by the injected runtime.
pub const EXCHANGE_BUDGET: Duration = Duration::from_secs(10);

/// Exchange the connection level's fact over a live connection, best effort.
///
/// The answer is the bytes the other side sent, or `None` when the exchange
/// failed — a peer that does not answer, a stream that stalls, bytes that are not a
/// fact. The connection stands either way, and the next one tries again.
pub(crate) async fn exchange(
    connection: &Connection,
    local: Option<Fact>,
    started: Started,
    runtime: &dyn Runtime,
) -> Option<Vec<u8>> {
    timeout(
        runtime,
        EXCHANGE_BUDGET,
        exchange_within(connection, local, started),
    )
    .await
    .flatten()
}

async fn exchange_within(
    connection: &Connection,
    local: Option<Fact>,
    started: Started,
) -> Option<Vec<u8>> {
    // A fact this build cannot encode is one it does not send: the refusal is
    // unreachable for a fact built from labels and a moment, and a peer is better
    // served by the next connection than by a connection failed here.
    let own = match local {
        Some(fact) => fact.encode().ok()?,
        None => Vec::new(),
    };
    let bytes = match started {
        Started::Here => {
            let (mut send, mut recv) = connection.open_bi().await.ok()?;
            send.write_all(&own).await.ok()?;
            send.finish().ok()?;
            recv.read_to_end(MAX_FACT_BYTES).await.ok()?
        }
        Started::There => {
            let (mut send, mut recv) = connection.accept_bi().await.ok()?;
            let bytes = recv.read_to_end(MAX_FACT_BYTES).await.ok()?;
            send.write_all(&own).await.ok()?;
            send.finish().ok()?;
            bytes
        }
    };
    Some(bytes)
}
