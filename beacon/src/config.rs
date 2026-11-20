//! The beacon's configuration and its server-side TLS.
//!
//! Parsing the command line and deciding whether a key file is private are pure
//! functions: the process entry point reads the arguments and the file mode, and
//! hands both here. That keeps the excluded surface — the part that really touches
//! the environment — down to the calls themselves, while every decision it makes
//! is compiled and witnessed in a default build.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use mahbot_peers::beacon::{ALPN, BeaconError, transport_config};
use mahbot_peers::identity::{Fingerprint, Identity};
use mahbot_peers::tls::{self, PeerPolicy};

/// What the binary tells its operator, verbatim.
pub const USAGE: &str = "\
usage: mahbot-beacon-server --listen ADDRESS --key PATH

  --listen ADDRESS   the UDP address to bind, e.g. 0.0.0.0:4433
  --key PATH         the beacon's ed25519 key; created with mode 0600 if absent

The key is the beacon's identity, not its state: clients pin it, so it must
survive a restart. Registrations do not — they live in memory and nowhere else.
";

/// Where the beacon listens, and where its key lives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub listen: SocketAddr,
    pub key: PathBuf,
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
        let mut key = None;
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
                "--key" => {
                    let value = args.next().ok_or("--key needs a path")?;
                    key = Some(PathBuf::from(value));
                }
                "--help" | "-h" => return Ok(Self::Help),
                other => return Err(format!("unknown argument `{other}`\n\n{USAGE}")),
            }
        }
        match (listen, key) {
            (Some(listen), Some(key)) => Ok(Self::Serve(Config { listen, key })),
            _ => Err(USAGE.to_owned()),
        }
    }
}

/// Whether a key file's mode keeps it private: no permission for group or other.
///
/// Modes are a unix notion, so the predicate is only asked there; it is a pure
/// function of the number so the rule is witnessed everywhere.
#[must_use]
// The mask is the rule: group and other permissions, and nothing else.
#[allow(clippy::verbose_bit_mask)]
pub const fn mode_is_private(mode: u32) -> bool {
    mode & 0o077 == 0
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
