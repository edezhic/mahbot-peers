//! A raw client and a rogue server: the rig's way to speak bytes the typed
//! messages would not produce, and to play a compromised beacon.
//!
//! The raw client connects with the library's own pinned configuration and then
//! writes whatever frame the case builds, so the closed message set, the version
//! check and the authentication of an introduction are all exercised against the
//! real server. The rogue server holds the real beacon's key — it passes the pin
//! — and still cannot make a forged introduction pass, because the recipient
//! checks the sender's signature.

use std::net::SocketAddr;

use mahbot_peers::beacon::Frame;
use mahbot_peers::identity::Identity;
use quinn::{Connection, Endpoint};

use crate::beacon::TestBeacon;
use crate::machine::Machine;
use crate::sim::Sim;

/// One client connection the case drives frame by frame.
pub struct RawClient {
    connection: Connection,
}

impl RawClient {
    /// Connect with the library's pinned configuration and `machine`'s identity.
    pub async fn connect(machine: &Machine, beacon: &TestBeacon) -> Result<Self, String> {
        let connection = Self::start(machine, beacon)?
            .await
            .map_err(|error| error.to_string())?;
        Ok(Self { connection })
    }

    /// Connect with a configuration the case built, so a case can present no
    /// identity at all.
    pub async fn connect_with(
        machine: &Machine,
        address: SocketAddr,
        config: quinn::ClientConfig,
    ) -> Result<Self, String> {
        let connection = Self::start_with(machine, address, config)?
            .await
            .map_err(|error| error.to_string())?;
        Ok(Self { connection })
    }

    /// Begin a handshake and hand it back unpolled: the Initial goes out and the
    /// client never takes it further, which is what a peer that walked away
    /// mid-handshake looks like from the server.
    pub fn start(machine: &Machine, beacon: &TestBeacon) -> Result<quinn::Connecting, String> {
        let config = mahbot_peers::beacon::client_config(&machine.identity, beacon.key())
            .map_err(|error| error.to_string())?;
        Self::start_with(machine, beacon.address(), config)
    }

    fn start_with(
        machine: &Machine,
        address: SocketAddr,
        config: quinn::ClientConfig,
    ) -> Result<quinn::Connecting, String> {
        let endpoint = machine.endpoint().map_err(|error| error.to_string())?;
        endpoint
            .connect_with(config, address, mahbot_peers::beacon::SERVER_NAME)
            .map_err(|error| error.to_string())
    }

    /// Write one request's bytes, end the stream, and read the one answer frame.
    pub async fn send(&self, bytes: &[u8]) -> Result<Frame, String> {
        self.exchange(bytes, true).await
    }

    /// Write `bytes` on a stream and never finish it: the server must give up on
    /// its own, and the answer it sends is what this returns.
    pub async fn stall(&self, bytes: &[u8]) -> Result<Frame, String> {
        self.exchange(bytes, false).await
    }

    /// The largest QUIC datagram the peer says it will accept, if it says so.
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.connection.max_datagram_size()
    }

    /// Ask the beacon for a stream this client may write to unprompted, which is
    /// what a peer that wants to push would ask for.
    pub async fn open_uni(&self) -> Result<quinn::SendStream, String> {
        self.connection
            .open_uni()
            .await
            .map_err(|error| error.to_string())
    }

    /// One request frame and one answer; `finish` is the whole difference between
    /// a complete request and a stalled one.
    async fn exchange(&self, bytes: &[u8], finish: bool) -> Result<Frame, String> {
        let (mut send, mut recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|error| error.to_string())?;
        send.write_all(bytes)
            .await
            .map_err(|error| error.to_string())?;
        if finish {
            send.finish().map_err(|error| error.to_string())?;
        }
        Frame::read(&mut recv)
            .await
            .map_err(|error| error.to_string())
    }
}

/// What a rogue server does with every connection it accepts.
#[derive(Clone)]
pub enum Rogue {
    /// Push these bytes on a server-initiated stream and keep the connection.
    Push(Vec<u8>),
    /// Answer every request stream with these bytes, whatever the request was.
    Reply(Vec<u8>),
}

/// A beacon at the real one's address and key that behaves as a case tells it to.
pub struct RogueBeacon {
    address: SocketAddr,
    endpoint: Endpoint,
    task: tokio::task::JoinHandle<()>,
}

impl RogueBeacon {
    /// Start a rogue at the next free address, presenting `identity` — the key
    /// the client pins — so only the protocol, not the handshake, can refuse it.
    pub fn start(sim: &Sim, identity: &Identity, script: Rogue) -> Result<Self, String> {
        let socket = sim.link().attach_next();
        let address = socket.addr();
        let config =
            mahbot_beacon::config::server_config(identity).map_err(|error| error.to_string())?;
        let endpoint = crate::beacon::endpoint(&socket, config, sim.clock().runtime())
            .map_err(|error| error.to_string())?;
        let accepting = endpoint.clone();
        let task = tokio::spawn(async move {
            while let Some(incoming) = accepting.accept().await {
                let Ok(connecting) = incoming.accept() else {
                    continue;
                };
                let Ok(connection) = connecting.await else {
                    continue;
                };
                let script = script.clone();
                tokio::spawn(async move {
                    script.serve(connection).await;
                });
            }
        });
        Ok(Self {
            address,
            endpoint,
            task,
        })
    }

    #[must_use]
    pub fn address(&self) -> SocketAddr {
        self.address
    }
}

impl Rogue {
    async fn serve(&self, connection: Connection) {
        match self {
            Self::Push(bytes) => {
                if let Ok(mut send) = connection.open_uni().await {
                    let _ = send.write_all(bytes).await;
                    let _ = send.finish();
                }
                // Keep the connection until the client closes it, so the push is
                // readable rather than cut short by a dropped server side.
                let _ = connection.closed().await;
            }
            Self::Reply(bytes) => {
                while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                    let _ = Frame::read(&mut recv).await;
                    if send.write_all(bytes).await.is_err() || send.finish().is_err() {
                        break;
                    }
                }
            }
        }
    }
}

impl Drop for RogueBeacon {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"rogue dropped");
        self.task.abort();
    }
}
