//! Identity cases: the fingerprint is the SPKI, and two identities differ.

use mahbot_peers::identity::{Fingerprint, Identity};

pub(crate) fn identity_fingerprint_is_spki() -> Result<(), String> {
    let identity = Identity::generate();
    let fingerprint = identity.fingerprint();
    if Fingerprint::from_spki(fingerprint.as_bytes()) != Some(fingerprint) {
        return Err("the fingerprint does not parse back to itself".to_owned());
    }
    if fingerprint.peer_id() != identity.peer_id() {
        return Err("the peer id is not the key inside the fingerprint".to_owned());
    }
    if Fingerprint::from_spki(&fingerprint.as_bytes()[..43]).is_some() {
        return Err("a 43-byte key was accepted as an SPKI".to_owned());
    }
    let mut tampered = *fingerprint.as_bytes();
    tampered[0] ^= 0xff;
    if Fingerprint::from_spki(&tampered).is_some() {
        return Err("a key with a broken SPKI prefix was accepted".to_owned());
    }
    Ok(())
}

pub(crate) fn identities_are_distinct() -> Result<(), String> {
    let first = Identity::generate();
    let second = Identity::generate();
    if first.fingerprint() == second.fingerprint() {
        return Err("two generated identities share a fingerprint".to_owned());
    }
    if first.peer_id() == second.peer_id() {
        return Err("two generated identities share a peer id".to_owned());
    }
    Ok(())
}
