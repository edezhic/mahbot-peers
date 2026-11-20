//! The server as the owner runs it: what its command line means, what it
//! advertises to a peer, and what it refuses to serve.
//!
//! The decisions are the library's, so they are cases like any other; the process
//! entry point only reads the arguments, the file and the clock and hands them
//! here.

use std::path::Path;
use std::time::Duration;

use mahbot_beacon::config::{Config, Invocation};
use mahbot_beacon::server::EXCHANGE_TIMEOUT;
use mahbot_peers::beacon::{Request, Response};

use crate::beacon::TestBeacon;
use crate::clock::block_on;
use crate::raw::RawClient;
use crate::sim::Sim;

use super::support::{BUDGET, io_error, within};

pub(crate) fn config_parse() -> Result<(), String> {
    let invocation = Invocation::parse(
        ["--listen", "0.0.0.0:4433", "--root", "/var/lib/beacon"].map(str::to_owned),
    )
    .map_err(|error| error.to_string())?;
    match invocation {
        Invocation::Serve(Config { listen, root }) => {
            if listen != "0.0.0.0:4433".parse().expect("a literal address") {
                return Err(format!("the listening address was read as {listen}"));
            }
            if root != Path::new("/var/lib/beacon") {
                return Err(format!(
                    "the key's directory was read as {}",
                    root.display()
                ));
            }
        }
        Invocation::Help => return Err("a full command line was read as --help".to_owned()),
    }
    if !matches!(
        Invocation::parse(["--help".to_owned()]),
        Ok(Invocation::Help)
    ) {
        return Err("--help was not read as a request for the usage".to_owned());
    }

    for bad in [
        vec!["--listen".to_owned()],
        vec!["--root".to_owned()],
        vec!["--listen".to_owned(), "not-an-address".to_owned()],
        vec!["--unknown".to_owned()],
    ] {
        if let Ok(invocation) = Invocation::parse(bad.clone()) {
            return Err(format!("{bad:?} was accepted as {invocation:?}"));
        }
    }
    // A missing required argument reports the usage, not a half configuration.
    match Invocation::parse(["--listen".to_owned(), "0.0.0.0:1".to_owned()]) {
        Err(message) if message.contains("usage:") => {}
        other => return Err(format!("a missing --root was answered {other:?}")),
    }
    Ok(())
}

pub(crate) fn connection_cap() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start_with_limit(&sim, 1).map_err(io_error)?;
        let first = sim.machine().map_err(io_error)?;
        let second = sim.machine().map_err(io_error)?;
        let _held = within(&sim, BUDGET, beacon.client(&first)?.connect())
            .await?
            .map_err(|error| error.to_string())?;

        // The one place is taken: a further connection is refused promptly. A
        // handshake that merely timed out would take the idle timeout and fail
        // this budget, so the answer has to be the refusal itself.
        match within(
            &sim,
            EXCHANGE_TIMEOUT + Duration::from_secs(2),
            beacon.client(&second)?.connect(),
        )
        .await?
        {
            Err(_) => Ok(()),
            Ok(_) => Err("a beacon at its connection limit accepted another".to_owned()),
        }
    })
}

/// What the beacon advertises to a peer is what it actually serves: no
/// unidirectional stream and no QUIC datagrams, both of which would be receive
/// window a peer could pin on the only internet-facing process.
pub(crate) fn the_beacon_advertises_only_what_it_serves() -> Result<(), String> {
    block_on(async {
        let sim = Sim::new().map_err(io_error)?;
        let beacon = TestBeacon::start(&sim).map_err(io_error)?;
        let machine = sim.machine().map_err(io_error)?;
        let raw = RawClient::connect(&machine, &beacon).await?;

        // A unidirectional stream is granted by credit and nothing else: a peer
        // that asks and waits was granted none.
        match within(&sim, Duration::from_millis(100), raw.open_uni()).await {
            Err(_) | Ok(Err(_)) => {}
            Ok(Ok(_)) => {
                return Err("the beacon granted a unidirectional stream it never reads".to_owned());
            }
        }
        if let Some(size) = raw.max_datagram_size() {
            return Err(format!(
                "the beacon advertises a {size}-byte datagram it never reads"
            ));
        }

        // And the connection is otherwise healthy.
        match Response::decode(&raw.send(&Request::ObservedAddress.encode()).await?)
            .map_err(|error| error.to_string())?
        {
            Response::Observed(address) if address == machine.addr() => Ok(()),
            other => Err(format!(
                "the connection stopped serving after the advertisement probe: {other:?}"
            )),
        }
    })
}
