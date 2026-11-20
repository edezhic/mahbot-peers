//! What the beacon remembers, and what it answers.
//!
//! One map: id → (address, live connection, expiry). Nothing else — no payload,
//! no pending introduction, no attempt counter. A request is answered from that
//! map and the caller's own connection, and an introduction is turned into a
//! frame for the addressee's connection in the same step, so the beacon never
//! holds the bytes it relays.
//!
//! Time is a parameter. The map is swept on every request, so an expired
//! registration is never answered even if the connection that made it is still
//! open, and the sweep needs no timer of its own.
//!
//! The latest registration for an id wins. A machine that presents a copied key
//! therefore displaces the original here — which is why the product drops a
//! connection that presents this machine's own id before it ever reaches a peer;
//! the beacon has no way to tell a copy from the real machine and is not asked to.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use mahbot_peers::beacon::{Push, Request, Response};
use mahbot_peers::identity::PeerId;

/// How long a registration lasts without a refresh. It is housekeeping, not an
/// attempt limit: it never gates an acquaintance and says nothing about trust.
pub const REGISTRATION_TTL: Duration = Duration::from_secs(120);

/// One live connection to the beacon, as the server numbers it. The core never
/// sees a socket, so it names connections by number and the server resolves them.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ConnectionId(pub u64);

#[derive(Debug)]
struct Entry {
    address: SocketAddr,
    connection: ConnectionId,
    expires: Duration,
}

/// What the server must do with one request.
#[derive(Debug)]
pub enum Action {
    /// Answer the caller with this.
    Reply(Response),
    /// Hand `frame` to the addressee's live connection, then answer `Delivered`
    /// if the write succeeded and `UnknownPeer(peer)` if it did not.
    Deliver {
        connection: ConnectionId,
        peer: PeerId,
        frame: Vec<u8>,
    },
}

/// The whole of the beacon's memory.
#[derive(Debug, Default)]
pub struct Registry {
    entries: HashMap<PeerId, Entry>,
}

impl Registry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Answer one request from `caller`, whose connection is `connection` and
    /// whose path the beacon observes as `observed`.
    ///
    /// The caller's id and address are never taken from the request: there is no
    /// field for either. They come from the handshake and the path.
    pub fn handle(
        &mut self,
        caller: PeerId,
        connection: ConnectionId,
        observed: SocketAddr,
        now: Duration,
        request: Request,
    ) -> Action {
        self.expire(now);
        match request {
            Request::Register => {
                self.entries.insert(
                    caller,
                    Entry {
                        address: observed,
                        connection,
                        expires: now.saturating_add(REGISTRATION_TTL),
                    },
                );
                Action::Reply(Response::Registered {
                    lifetime: REGISTRATION_TTL,
                })
            }
            Request::Lookup(id) => Action::Reply(Response::Address(
                self.entries.get(&id).map(|entry| entry.address),
            )),
            Request::ObservedAddress => Action::Reply(Response::Observed(observed)),
            Request::Introduce {
                to,
                signature,
                payload,
            } => {
                let Some(entry) = self.entries.get(&to) else {
                    return Action::Reply(Response::UnknownPeer(to));
                };
                Action::Deliver {
                    connection: entry.connection,
                    peer: to,
                    frame: Push::Introduction {
                        from: caller,
                        to,
                        signature,
                        payload,
                    }
                    .encode(),
                }
            }
        }
    }

    /// Forget every registration made over a connection that has gone.
    pub fn disconnect(&mut self, connection: ConnectionId) {
        self.entries
            .retain(|_, entry| entry.connection != connection);
    }

    /// Drop every registration whose lifetime has run out. The sweep is lazy:
    /// it runs at the start of every request, so no timer is needed.
    fn expire(&mut self, now: Duration) {
        self.entries.retain(|_, entry| entry.expires > now);
    }

    /// Every registration the beacon holds as of the last request — the sweep is
    /// lazy — and nothing else: no payload, no queue, no counter.
    #[must_use]
    pub fn snapshot(&self) -> Vec<(PeerId, SocketAddr)> {
        let mut entries: Vec<(PeerId, SocketAddr)> = self
            .entries
            .iter()
            .map(|(id, entry)| (*id, entry.address))
            .collect();
        entries.sort_by_key(|(id, _)| *id);
        entries
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
