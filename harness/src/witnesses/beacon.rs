//! Beacon cases: the opaque payload seam and the start, stop and wipe lifecycle.

use std::sync::Arc;

use mahbot_peers::beacon::{BeaconError, Introduction, MAX_INTRODUCTION_BYTES, Rendezvous};
use mahbot_peers::identity::Identity;

use crate::beacon::FakeBeacon;
use crate::clock::block_on;

use super::support::socket;

pub(crate) fn beacon_carries_opaque_payload() -> Result<(), String> {
    block_on(async {
        let beacon = FakeBeacon::start();
        let seam = beacon.handle();
        let first = Identity::generate().peer_id();
        let second = Identity::generate().peer_id();
        let first_addr = socket(9001);
        let second_addr = socket(9002);
        seam.register(first, first_addr)
            .await
            .map_err(|e| e.to_string())?;
        seam.register(second, second_addr)
            .await
            .map_err(|e| e.to_string())?;
        if seam.lookup(&first).await.map_err(|e| e.to_string())? != Some(first_addr) {
            return Err("a registered id did not look up to its address".to_owned());
        }
        let stranger = Identity::generate().peer_id();
        if seam
            .lookup(&stranger)
            .await
            .map_err(|e| e.to_string())?
            .is_some()
        {
            return Err("an unregistered id looked up to an address".to_owned());
        }
        let payload = vec![0x00, 0x01, 0xfe, 0xff];
        seam.introduce(first, second, payload.clone())
            .await
            .map_err(|e| e.to_string())?;
        let Some(introduction) = seam
            .take_introduction(&second)
            .await
            .map_err(|e| e.to_string())?
        else {
            return Err("the introduction never arrived".to_owned());
        };
        if introduction.from() != first || introduction.payload() != payload.as_slice() {
            return Err("the introduction was altered on the way".to_owned());
        }
        if seam
            .take_introduction(&second)
            .await
            .map_err(|e| e.to_string())?
            .is_some()
        {
            return Err("an introduction was delivered twice".to_owned());
        }
        match seam.introduce(first, stranger, payload).await {
            Err(BeaconError::UnknownPeer(id)) if id == stranger => Ok(()),
            other => Err(format!(
                "an introduction to an unregistered id was not refused: {other:?}"
            )),
        }
    })
}

pub(crate) fn introduction_size_limit() -> Result<(), String> {
    block_on(async {
        let sender = Identity::generate().peer_id();
        // The checked constructor is where the limit lives, so a service built
        // on it cannot store an introduction the seam promised to refuse.
        match Introduction::new(sender, vec![0u8; MAX_INTRODUCTION_BYTES]) {
            Ok(introduction) if introduction.payload().len() == MAX_INTRODUCTION_BYTES => {}
            other => {
                return Err(format!(
                    "the largest documented introduction was refused: {other:?}"
                ));
            }
        }
        match Introduction::new(sender, vec![0u8; MAX_INTRODUCTION_BYTES + 1]) {
            Err(BeaconError::PayloadTooLarge(len)) if len == MAX_INTRODUCTION_BYTES + 1 => {}
            other => {
                return Err(format!("an oversized introduction was built: {other:?}"));
            }
        }

        // And the stand-in service, which builds every introduction through it.
        let beacon = FakeBeacon::start();
        let seam = beacon.handle();
        let first = Identity::generate().peer_id();
        let second = Identity::generate().peer_id();
        seam.register(first, socket(9101))
            .await
            .map_err(|e| e.to_string())?;
        seam.register(second, socket(9102))
            .await
            .map_err(|e| e.to_string())?;
        let at_limit = vec![0u8; MAX_INTRODUCTION_BYTES];
        seam.introduce(first, second, at_limit.clone())
            .await
            .map_err(|e| e.to_string())?;
        let taken = seam
            .take_introduction(&second)
            .await
            .map_err(|e| e.to_string())?;
        if taken.map(|introduction| introduction.payload().to_vec()) != Some(at_limit) {
            return Err("the largest documented introduction did not arrive intact".to_owned());
        }
        let over = vec![0u8; MAX_INTRODUCTION_BYTES + 1];
        match seam.introduce(first, second, over).await {
            Err(BeaconError::PayloadTooLarge(len)) if len == MAX_INTRODUCTION_BYTES + 1 => Ok(()),
            other => Err(format!(
                "an oversized introduction was not refused: {other:?}"
            )),
        }
    })
}

pub(crate) fn beacon_starts_stops_and_wipes() -> Result<(), String> {
    block_on(async {
        let beacon = FakeBeacon::start();
        let seam: Arc<dyn Rendezvous> = beacon.handle();
        let first = Identity::generate().peer_id();
        let second = Identity::generate().peer_id();
        let first_addr = socket(6001);
        let second_addr = socket(6002);
        seam.register(first, first_addr)
            .await
            .map_err(|e| e.to_string())?;
        seam.register(second, second_addr)
            .await
            .map_err(|e| e.to_string())?;
        if seam.lookup(&first).await.map_err(|e| e.to_string())? != Some(first_addr) {
            return Err("a started service did not keep a registration".to_owned());
        }
        beacon.stop();
        if beacon.is_running() {
            return Err("a stopped service still reports itself running".to_owned());
        }
        for refusal in [
            seam.lookup(&first).await.err(),
            seam.register(first, first_addr).await.err(),
            seam.introduce(first, second, vec![1]).await.err(),
            seam.take_introduction(&second).await.err(),
        ] {
            if refusal != Some(BeaconError::Unavailable) {
                return Err(format!(
                    "a stopped service answered instead of refusing: {refusal:?}"
                ));
            }
        }
        beacon.restart();
        if seam.lookup(&first).await.map_err(|e| e.to_string())? != Some(first_addr) {
            return Err("a restarted service forgot its registrations".to_owned());
        }
        beacon.wipe();
        if seam
            .lookup(&first)
            .await
            .map_err(|e| e.to_string())?
            .is_some()
        {
            return Err("a wipe left a registration behind".to_owned());
        }
        if seam
            .take_introduction(&second)
            .await
            .map_err(|e| e.to_string())?
            .is_some()
        {
            return Err("a wipe left an introduction behind".to_owned());
        }
        Ok(())
    })
}
