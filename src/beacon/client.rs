//! The client half: one configured beacon, and one live session with it.
//!
//! A [`Beacon`] is the address, the pinned key, the runtime that measures every
//! bound, and the identity the caller presents. A [`Session`] is one connection to
//! it: register, look an id up, ask how this connection appears from outside, hand
//! an introduction over, and take the introductions the beacon pushes while the
//! session is open.
//!
//! The endpoint a [`Beacon`] is built over is the caller's, and it must be the
//! endpoint the caller uses for peers: the address the beacon reports is the one
//! it observes on *this* connection's path, and hole punching depends on that
//! being the peer-facing path rather than some other socket.
//!
//! A session carries no state of its own: there is no mailbox to poll and no
//! pending introduction to recover. If the connection is gone, the next need is
//! a new [`Beacon::connect`] and a new `register`.
//!
//! A request waits until the transport answers, and never longer than
//! [`BEACON_REQUEST_TIMEOUT`] of the injected runtime's time: a beacon that is
//! gone is a bounded failure, not a session that looks open forever. That covers
//! the handshake and the frame of a pushed introduction too;
//! [`Session::next_introduction`]'s wait for the beacon to speak first is the
//! caller's.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::{Connection, Endpoint, RecvStream, Runtime};

use crate::identity::{Fingerprint, Identity, PeerId};

use super::time::timeout;
use super::{
    BEACON_REQUEST_TIMEOUT, BeaconError, Frame, Introduction, Push, Request, Response, SERVER_NAME,
    client_config,
};

/// A beacon this machine is configured to use: where it is, which key it must
/// present, and which identity this machine presents to it.
#[derive(Clone, Debug)]
pub struct Beacon {
    endpoint: Endpoint,
    runtime: Arc<dyn Runtime>,
    address: SocketAddr,
    key: Fingerprint,
    me: Identity,
}

impl Beacon {
    /// Configure a beacon on the endpoint this machine also uses for peers.
    ///
    /// `runtime` is the runtime the endpoint runs on: it measures the bound on
    /// each request, so the protocol never reads a clock of its own.
    #[must_use]
    pub fn new(
        endpoint: Endpoint,
        runtime: Arc<dyn Runtime>,
        address: SocketAddr,
        key: Fingerprint,
        me: Identity,
    ) -> Self {
        Self {
            endpoint,
            runtime,
            address,
            key,
            me,
        }
    }

    /// The runtime that measures every bound, so a caller can wait on it — the
    /// registration refresh does, and so does any other timer a caller needs to
    /// line up with the beacon's.
    #[must_use]
    pub fn runtime(&self) -> &Arc<dyn Runtime> {
        &self.runtime
    }

    /// Open a session, pinning the beacon's key.
    ///
    /// # Errors
    ///
    /// [`BeaconError::Transport`] when the connection cannot be made or the
    /// handshake fails — an impostor at the address does not hold the pinned key,
    /// so it cannot complete one — and [`BeaconError::Unavailable`] when the
    /// handshake does not complete within [`BEACON_REQUEST_TIMEOUT`].
    pub async fn connect(&self) -> Result<Session, BeaconError> {
        let config = client_config(&self.me, self.key)?;
        let connecting = self
            .endpoint
            .connect_with(config, self.address, SERVER_NAME)
            .map_err(|error| BeaconError::Transport(error.to_string()))?;
        let connection = match timeout(&*self.runtime, BEACON_REQUEST_TIMEOUT, connecting).await {
            Some(Ok(connection)) => connection,
            Some(Err(error)) => return Err(BeaconError::Transport(error.to_string())),
            None => return Err(BeaconError::Unavailable),
        };
        Ok(Session {
            connection,
            runtime: Arc::clone(&self.runtime),
            me: self.me.clone(),
        })
    }
}

/// One live connection to the beacon.
pub struct Session {
    connection: Connection,
    runtime: Arc<dyn Runtime>,
    me: Identity,
}

impl Session {
    /// The runtime this session's timers run on, for a caller that has to bound a
    /// wait of its own.
    pub(crate) fn runtime(&self) -> &Arc<dyn Runtime> {
        &self.runtime
    }

    /// Close the session, telling the beacon why.
    pub fn close(&self, reason: &[u8]) {
        self.connection.close(0u32.into(), reason);
    }

    /// Announce that this machine is reachable, refreshed while it wants to be
    /// findable. The beacon records the caller's key and the address it observes
    /// on this connection; neither is asserted by the frame. The answer is how
    /// long the registration lasts.
    ///
    /// # Errors
    ///
    /// [`BeaconError::Unavailable`] when the session is closed, or the beacon's
    /// refusal.
    pub async fn register(&self) -> Result<Duration, BeaconError> {
        match self.request(Request::Register).await? {
            Response::Registered { lifetime } => Ok(lifetime),
            other => Err(unexpected(&other)),
        }
    }

    /// Where `id` currently is, if it is registered at all.
    ///
    /// # Errors
    ///
    /// [`BeaconError::Unavailable`] when the session is closed, or the beacon's
    /// refusal.
    pub async fn lookup(&self, id: &PeerId) -> Result<Option<SocketAddr>, BeaconError> {
        match self.request(Request::Lookup(*id)).await? {
            Response::Address(address) => Ok(address),
            other => Err(unexpected(&other)),
        }
    }

    /// This machine's own address, as the beacon observes it on this connection.
    ///
    /// The answer is only as good as the path it was asked over: a session on a
    /// socket the peers never see reports that socket, and punching would then
    /// aim at the wrong place.
    ///
    /// # Errors
    ///
    /// [`BeaconError::Unavailable`] when the session is closed, or the beacon's
    /// refusal.
    pub async fn observed_address(&self) -> Result<SocketAddr, BeaconError> {
        match self.request(Request::ObservedAddress).await? {
            Response::Observed(address) => Ok(address),
            other => Err(unexpected(&other)),
        }
    }

    /// Hand `payload` to `to` on a live connection, signed by this machine's key.
    ///
    /// The introduction is built by [`Introduction::signed`] — the same checked
    /// constructor the recipient verifies against — and sent as its parts; the
    /// beacon adds the sender's id from the connection, never from the frame.
    ///
    /// The beacon does not read the payload and does not store it. If `to` is not
    /// registered, or its live connection cannot take the frame within the
    /// server's exchange bound — a recipient that has left
    /// [`crate::beacon::MAX_CONCURRENT_STREAMS`] introductions unread — the call
    /// fails with [`BeaconError::UnknownPeer`] and nothing is kept for later.
    /// `Delivered` means the frame was written to the addressee's connection, not
    /// that its application read it. The call is bounded by
    /// [`BEACON_REQUEST_TIMEOUT`], like every request.
    ///
    /// # Errors
    ///
    /// [`BeaconError::PayloadTooLarge`], [`BeaconError::UnknownPeer`],
    /// [`BeaconError::Unavailable`], or the beacon's refusal.
    pub async fn introduce(&self, to: PeerId, payload: &[u8]) -> Result<(), BeaconError> {
        let introduction = Introduction::signed(&self.me, to, payload.to_vec())?;
        match self.request(Request::introduce(introduction)).await? {
            Response::Delivered => Ok(()),
            Response::UnknownPeer(id) => Err(BeaconError::UnknownPeer(id)),
            other => Err(unexpected(&other)),
        }
    }

    /// The next introduction the beacon pushes to this session.
    ///
    /// The wait for the beacon to speak first is the caller's: a machine that has
    /// nothing to introduce to it may wait indefinitely, and this crate has no
    /// opinion on how long that should be. Once a stream is accepted, its frame
    /// must arrive within [`BEACON_REQUEST_TIMEOUT`], so a beacon that opens a
    /// stream and stalls it cannot park the caller.
    ///
    /// An introduction whose signature does not verify under its `from` id is
    /// reported as [`BeaconError::UnauthenticatedIntroduction`] and never handed
    /// back as a message: a relay can deliver bytes, but it cannot make them
    /// speak for a key it does not hold.
    ///
    /// # Errors
    ///
    /// [`BeaconError::Unavailable`] when the session is closed or the frame does
    /// not arrive, or the beacon's refusal.
    pub async fn next_introduction(&self) -> Result<Introduction, BeaconError> {
        let recv = self
            .connection
            .accept_uni()
            .await
            .map_err(|_| BeaconError::Unavailable)?;
        self.read_introduction(recv).await
    }

    /// The next introduction, waiting at most `after` for the beacon to speak.
    ///
    /// [`Self::next_introduction`] waits for the caller; this one puts a bound on
    /// the wait for a stream as well, for a caller with its own deadline — a
    /// ceremony whose flight must not wait forever. `Ok(None)` is the bound
    /// passing with nothing to read: the beacon is fine and the peer was silent,
    /// which is not the same failure as a closed session. Both bounds are measured
    /// by the injected runtime.
    ///
    /// # Errors
    ///
    /// [`BeaconError::Unavailable`] when the session is closed, or the beacon's
    /// refusal.
    pub async fn next_introduction_within(
        &self,
        after: Duration,
    ) -> Result<Option<Introduction>, BeaconError> {
        match timeout(&*self.runtime, after, self.connection.accept_uni()).await {
            Some(Ok(recv)) => self.read_introduction(recv).await.map(Some),
            Some(Err(_)) => Err(BeaconError::Unavailable),
            None => Ok(None),
        }
    }

    /// Read and authenticate one pushed introduction from an accepted stream.
    async fn read_introduction(&self, mut recv: RecvStream) -> Result<Introduction, BeaconError> {
        let frame = match timeout(
            &*self.runtime,
            BEACON_REQUEST_TIMEOUT,
            Frame::read(&mut recv),
        )
        .await
        {
            Some(frame) => frame?,
            None => return Err(BeaconError::Unavailable),
        };
        frame.require_version()?;
        let Push::Introduction {
            from,
            to,
            signature,
            payload,
        } = Push::decode(&frame)?;
        let introduction = Introduction::new(from, to, signature, payload)?;
        if !introduction.is_authentic() {
            return Err(BeaconError::UnauthenticatedIntroduction { from });
        }
        if to != self.me.peer_id() {
            return Err(BeaconError::Malformed);
        }
        Ok(introduction)
    }

    /// One request on its own bidirectional stream, and the one answer to it.
    ///
    /// The exchange is bounded by [`BEACON_REQUEST_TIMEOUT`]: a beacon that is
    /// gone answers nothing, and waiting on it must end.
    async fn request(&self, request: Request) -> Result<Response, BeaconError> {
        match timeout(
            &*self.runtime,
            BEACON_REQUEST_TIMEOUT,
            self.exchange(request),
        )
        .await
        {
            Some(result) => result,
            None => Err(BeaconError::Unavailable),
        }
    }

    async fn exchange(&self, request: Request) -> Result<Response, BeaconError> {
        // A connection the transport has already declared dead answers nothing;
        // saying so at once is better than opening a stream on it.
        if self.connection.close_reason().is_some() {
            return Err(BeaconError::Unavailable);
        }
        let (mut send, mut recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|_| BeaconError::Unavailable)?;
        super::wire::write(&mut send, &request.encode()).await?;
        let frame = Frame::read(&mut recv).await?;
        frame.require_version()?;
        match Response::decode(&frame)? {
            Response::Refused(refusal) => Err(BeaconError::Refused(refusal)),
            response => Ok(response),
        }
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session")
            .field("me", &self.me.fingerprint())
            .field("close_reason", &self.connection.close_reason())
            .finish_non_exhaustive()
    }
}

/// An answer whose kind does not belong to the request: a protocol violation, not
/// a refusal the beacon named.
fn unexpected(response: &Response) -> BeaconError {
    BeaconError::Unexpected(response.name())
}
