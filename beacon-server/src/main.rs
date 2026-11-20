//! The beacon's process entry point.
//!
//! This file is the workspace's one documented exception to the source scan: it
//! binds a real UDP socket, reads the environment and the wall clock, owns the
//! executor, and owns the key file — creating it exclusively, refusing one other
//! users can read, and retrying the create race. Every decision it makes is either
//! a pure function in `mahbot-beacon` (what the command line means, whether a key
//! file is private, how the server is configured), which the scan covers, or the
//! key-file I/O named in the exclusion's reason; the scan's summary test proves
//! this exclusion is exactly this file and that the file still needs it.

#![warn(clippy::pedantic)]
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

use std::fs;
use std::io::Write;
use std::net::UdpSocket;
use std::path::Path;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mahbot_beacon::clock::Clock;
use mahbot_beacon::config::{self, Invocation, USAGE};
use mahbot_beacon::core::Registry;
use mahbot_beacon::server::BeaconServer;
use mahbot_peers::identity::Identity;
use quinn::{Endpoint, EndpointConfig};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("mahbot-beacon-server: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = match Invocation::parse(std::env::args().skip(1))? {
        Invocation::Serve(config) => config,
        Invocation::Help => {
            print!("{USAGE}");
            return Ok(());
        }
    };
    let identity = load_or_create(&config.key)?;
    println!("identity {}", identity.fingerprint());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let socket = UdpSocket::bind(config.listen)?;
        socket.set_nonblocking(true)?;
        let runtime: Arc<dyn quinn::Runtime> = Arc::new(quinn::TokioRuntime);
        let endpoint = Endpoint::new(
            EndpointConfig::default(),
            Some(config::server_config(&identity)?),
            socket,
            Arc::clone(&runtime),
        )?;
        println!("listening on {}", endpoint.local_addr()?);
        let registry = Arc::new(Mutex::new(Registry::new()));
        BeaconServer::new(endpoint, runtime, Arc::new(SystemClock::new()), registry)
            .run()
            .await;
        Ok(())
    })
}

/// Read the beacon's key, or create it once.
///
/// The key is configuration, not state: the protocol never writes it, and a
/// restart must keep the same identity or every client's pin breaks. The file is
/// created exclusively with mode 0600 on unix, so a second process racing the
/// first loses the create and reads the winner's key — retrying if it catches the
/// file before the winner's write lands — and an existing file that other users
/// can read is refused rather than used.
fn load_or_create(path: &Path) -> Result<Identity, Box<dyn std::error::Error>> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        match fs::read(path) {
            Ok(bytes) => {
                ensure_private(path)?;
                if let Some(identity) = Identity::from_pkcs8(&bytes) {
                    return Ok(identity);
                }
                // A racer can read the file between the winner's create and its
                // write; the same file is a key a moment later.
                if attempt < 3 {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
                return Err(format!(
                    "{} is not a PKCS#8 ed25519 key (a concurrent start may still be writing it)",
                    path.display()
                )
                .into());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let identity = Identity::generate();
                let mut options = fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                match options.open(path) {
                    Ok(mut file) => {
                        file.write_all(identity.pkcs8())?;
                        file.sync_all()?;
                        ensure_private(path)?;
                        return Ok(identity);
                    }
                    Err(error)
                        if error.kind() == std::io::ErrorKind::AlreadyExists && attempt < 3 => {}
                    Err(error) => return Err(error.into()),
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
}

struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }
}

/// Refuse a key file other users can read. The beacon's key is what clients pin,
/// so a readable copy is an impostor waiting to happen.
#[cfg(unix)]
fn ensure_private(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    if !config::mode_is_private(mode) {
        return Err(format!(
            "{} is accessible to other users (mode {mode:o}); chmod 600 it",
            path.display()
        )
        .into());
    }
    Ok(())
}

/// Windows file permissions are the profile's, not the file's: there is no mode
/// bit to check, and the beacon runs on the owner's server.
#[cfg(not(unix))]
fn ensure_private(_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}
