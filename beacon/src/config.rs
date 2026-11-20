//! The beacon's configuration and its server-side TLS.
//!
//! Parsing the command line is a pure function: the process entry point reads the
//! arguments and hands them here, which keeps the exempted surface — the part that
//! really touches the environment — down to the calls themselves. The key file is
//! not here at all: its format, its one create and its privacy rule are the
//! library's, the same ones a machine's identity uses.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use mahbot_peers::beacon::{ALPN, BeaconError, transport_config};
use mahbot_peers::identity::{Fingerprint, Identity};
use mahbot_peers::tls::{self, PeerPolicy};

/// What the binary tells its operator, verbatim.
pub const USAGE: &str = "\
usage: mahbot-beacon-server --listen ADDRESS --root DIR

  --listen ADDRESS   the UDP address to bind, e.g. 0.0.0.0:4433
  --root DIR         the directory holding the beacon's key: `identity.key`,
                     created if absent, private by the rule a machine's key
                     file follows: mode 0600 on unix; on Windows a protected
                     access list naming the account the process runs as,
                     SYSTEM and Administrators, with that account as the
                     file's owner. The directory must already exist

The key is the beacon's identity, not its state: clients pin it, so it must
survive a restart. Registrations do not — they live in memory and nowhere else.
";

/// Where the beacon listens, and where its key lives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub listen: SocketAddr,
    pub root: PathBuf,
}

/// What one command line asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Invocation {
    Serve(Config),
    Help,
}

impl Invocation {
    /// Parse the arguments after the program name.
    ///
    /// # Errors
    ///
    /// A message naming the offending argument, ending with [`USAGE`].
    pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut listen = None;
        let mut root = None;
        let mut args = args.into_iter();
        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--listen" => {
                    let value = args.next().ok_or("--listen needs an address")?;
                    listen = Some(
                        value
                            .parse()
                            .map_err(|_| format!("`{value}` is not a socket address"))?,
                    );
                }
                "--root" => {
                    let value = args.next().ok_or("--root needs a directory")?;
                    root = Some(PathBuf::from(value));
                }
                "--help" | "-h" => return Ok(Self::Help),
                other => return Err(format!("unknown argument `{other}`\n\n{USAGE}")),
            }
        }
        match (listen, root) {
            (Some(listen), Some(root)) => Ok(Self::Serve(Config { listen, root })),
            _ => Err(USAGE.to_owned()),
        }
    }
}

/// A server configuration for the beacon: it presents its own key, accepts any
/// caller's, and speaks [`ALPN`].
///
/// Accepting any key is the point: the beacon authenticates a caller (the
/// handshake proves the key) but does not authorize it. Trust is the product's,
/// from the pinned key and the ceremony, never the beacon's.
///
/// # Errors
///
/// [`BeaconError::Transport`] when rustls or quinn refuses the configuration.
pub fn server_config(me: &Identity) -> Result<quinn::ServerConfig, BeaconError> {
    let tls = tls::server_config(me, Arc::new(AnyCaller), ALPN)
        .map_err(|error| BeaconError::Transport(error.to_string()))?;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|error| BeaconError::Transport(format!("{error:?}")))?;
    let mut transport = transport_config()?;
    // The server never accepts a unidirectional stream: clients open bidirectional
    // ones and nothing else, so advertising credit for a stream it would not read
    // is receive window a peer could pin on the only internet-facing process.
    transport.max_concurrent_uni_streams(quinn::VarInt::from_u32(0));
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

/// The beacon accepts every caller. Its policy is authentication, not
/// authorization: the handshake proves which key is calling, and the beacon binds
/// a registration to that key. Whether a machine may talk to another is decided
/// by the machines, from pinned keys and the ceremony.
#[derive(Debug)]
struct AnyCaller;

impl PeerPolicy for AnyCaller {
    fn trusts(&self, _peer: &Fingerprint) -> bool {
        true
    }
}
