//! The beacon's process entry point.
//!
//! This file is exempt from three source-scan invariants, and only those: it binds
//! a real UDP socket, reads the environment and the wall clock, and owns the
//! executor. Every other invariant judges it like any other source — what the
//! command line means and how the server is configured are pure functions in
//! `mahbot-beacon`, and its key file is the peer library's `identity.key`, reached
//! only through `keyfile::load_or_create` — so the key claims cover it as they cover
//! a machine's identity: it is never replaced, its name appears in no file here, and
//! nothing here mints a key. The scan's summary test proves the exemption list is
//! exactly these three and that each of them is still needed.

#![warn(clippy::pedantic)]
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

use std::net::UdpSocket;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mahbot_beacon::clock::Clock;
use mahbot_beacon::config::{self, Invocation, USAGE};
use mahbot_beacon::core::Registry;
use mahbot_beacon::server::BeaconServer;
use mahbot_peers::identity::keyfile;
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
    // The key is configuration, not state: the protocol never writes it, and a
    // restart must keep the same identity or every client's pin breaks. The rules
    // are the library's — one create, published only if the name is free, and a
    // file other accounts can reach is refused rather than used. The beacon's key
    // is `identity.key` in the directory on the command line, the same name and the
    // same format as a machine's.
    let identity = keyfile::load_or_create(&config.root)?;
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
