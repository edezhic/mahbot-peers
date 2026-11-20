//! Identity cases: the fingerprint is the SPKI, two roots are two identities, the
//! key file is created once and never replaced, and only its owner can read it.

use std::fs;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use mahbot_peers::identity::access::{
    Account, Dacl, DaclEntry, Entry, Insecurity, acl_refusal, dacl_refusal, unix_refusal,
};
use mahbot_peers::identity::keyfile::{self, KeyFileError, Malformed};
use mahbot_peers::identity::{FINGERPRINT_LEN, Fingerprint, Identity};

use crate::root;
use crate::witnesses::support::temp_root;

/// The message a refusal about the key file prints, with the path every pin quotes and
/// every command in it must name.
fn refusal(reason: Insecurity) -> String {
    KeyFileError::Insecure {
        path: Path::new("/key").to_owned(),
        reason,
    }
    .to_string()
}

/// A refusal about a storage root rather than the key file: the prefix, the clause
/// saying which fact has to change, and no command — a directory's mode is not
/// `chmod 600`'s business, and handing an owner back is a command for the account the
/// product runs as rather than for the process that found the root.
fn root_clause(reason: Insecurity, clause: &str) -> Result<(), String> {
    let root = KeyFileError::RootNotPrivate {
        root: Path::new("/root").to_owned(),
        reason,
    }
    .to_string();
    if !root
        .starts_with("the storage root /root gives a new key file an access that is not private: ")
        || !root.contains(clause)
        || root.contains("chmod")
        || root.contains("icacls")
    {
        return Err(format!("the refusal about a root reads `{root}`"));
    }
    Ok(())
}

pub(crate) fn identity_fingerprint_is_spki() -> Result<(), String> {
    let identity = root::detached_identity().map_err(|error| error.to_string())?;
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
    let first = root::detached_identity().map_err(|error| error.to_string())?;
    let second = root::detached_identity().map_err(|error| error.to_string())?;
    if first.fingerprint() == second.fingerprint() {
        return Err("two generated identities share a fingerprint".to_owned());
    }
    if first.peer_id() == second.peer_id() {
        return Err("two generated identities share a peer id".to_owned());
    }
    Ok(())
}

/// One root, one identity: read twice, restored from a copy, and lost on purpose.
pub(crate) fn key_file_is_one_identity_per_root() -> Result<(), String> {
    let first_root = temp_root()?;
    let second_root = temp_root()?;
    let first = load(first_root.path())?;
    if load(first_root.path())?.fingerprint() != first.fingerprint() {
        return Err("loading one root twice gave two identities".to_owned());
    }
    if load(second_root.path())?.fingerprint() == first.fingerprint() {
        return Err("two roots gave one identity".to_owned());
    }
    // A restored backup keeps the machine: the copy carries the same key.
    crate::root::copy_key(first_root.path(), second_root.path())
        .map_err(|error| error.to_string())?;
    if load(second_root.path())?.fingerprint() != first.fingerprint() {
        return Err("a copy of a root did not give back the same identity".to_owned());
    }
    // Losing the key is the one way to become a new machine, and it is the
    // operator's act: nothing the library does deletes or rewrites the file.
    fs::remove_file(keyfile::file_in(first_root.path())).map_err(|error| error.to_string())?;
    let replaced = load(first_root.path())?;
    if replaced.fingerprint() == first.fingerprint() {
        return Err("a root whose key file was deleted kept its identity".to_owned());
    }
    let bytes = fs::read(keyfile::file_in(first_root.path())).map_err(|error| error.to_string())?;
    // The format is the permanent contract: PKCS#8 v2, which for ed25519 is 83
    // bytes and carries the public key beside the seed.
    if bytes.len() != 83 {
        return Err(format!(
            "the key file is {} bytes, not the 83 of a PKCS#8 v2 ed25519 key",
            bytes.len()
        ));
    }
    if Identity::from_pkcs8(&bytes).map(|identity| identity.fingerprint())
        != Some(replaced.fingerprint())
    {
        return Err("the file written for a new identity is not that identity's key".to_owned());
    }
    // The root is the caller's: a missing one is refused as a failed create, never
    // created — the error kind is the one a missing path gives, which is what tells
    // "there is no root" from "the key is unreadable".
    let missing = first_root.path().join("no-such-root");
    match keyfile::load_or_create(&missing) {
        Err(KeyFileError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {}
        other => return Err(format!("a missing storage root was answered {other:?}")),
    }
    if missing.exists() {
        return Err("the library created a storage root of its own".to_owned());
    }
    Ok(())
}

/// Two creators, one root: one identity, and no half-written key is ever visible.
pub(crate) fn key_file_is_created_once_under_race() -> Result<(), String> {
    for round in 0..8 {
        let root = temp_root()?;
        let path = keyfile::file_in(root.path());
        // Set once both creators are done, so the observer can stop: it samples
        // through the whole creation instead of guessing how long to wait, and it
        // never waits on anything but this flag, so a creator that fails ends the
        // case instead of parking it.
        let finished = AtomicBool::new(false);
        let (outcomes, seen) = std::thread::scope(|scope| {
            // Publishing is one operation, so a reader sees the same whole key or
            // nothing: the first observation is kept and every later one is compared
            // with it, which bounds the memory and still covers the whole window.
            let observer = scope.spawn(|| {
                let mut seen: Option<Vec<u8>> = None;
                let sample = |seen: &mut Option<Vec<u8>>| match fs::read(&path) {
                    Ok(bytes) => match seen {
                        Some(first) if *first != bytes => Err(format!(
                            "round {round}: the file at the key's path changed while it was watched"
                        )),
                        Some(_) => Ok(()),
                        None => {
                            *seen = Some(bytes);
                            Ok(())
                        }
                    },
                    Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                    Err(error) => Err(error.to_string()),
                };
                while !finished.load(Ordering::Acquire) {
                    sample(&mut seen)?;
                    std::thread::yield_now();
                }
                // The creators are done, so a key exists unless one of them failed,
                // and then its outcome carries the reason. This read also keeps the
                // check below from passing over an empty observation.
                sample(&mut seen)?;
                Ok(seen)
            });
            let creators: Vec<_> = (0..2).map(|_| scope.spawn(|| load(root.path()))).collect();
            let outcomes: Vec<Result<Identity, String>> = creators
                .into_iter()
                .map(|creator| match creator.join() {
                    Ok(outcome) => outcome,
                    Err(_) => Err(format!("round {round}: a creator thread panicked")),
                })
                .collect();
            finished.store(true, Ordering::Release);
            let seen = match observer.join() {
                Ok(seen) => seen,
                Err(_) => Err(format!("round {round}: the observer thread panicked")),
            };
            (outcomes, seen)
        });
        let mut fingerprints = Vec::new();
        for outcome in outcomes {
            fingerprints.push(outcome?.fingerprint());
        }
        // With both creators done a key exists, so no observation means the
        // partial-file check would have nothing behind it.
        let Some(observed) = seen? else {
            return Err(format!(
                "round {round}: no key was ever observed during the creation"
            ));
        };
        if fingerprints[0] != fingerprints[1] {
            return Err(format!(
                "round {round}: two racing creators minted two identities"
            ));
        }
        if load(root.path())?.fingerprint() != fingerprints[0] {
            return Err(format!(
                "round {round}: the published key is not the one the creators hold"
            ));
        }
        if Identity::from_pkcs8(&observed).map(|identity| identity.fingerprint())
            != Some(fingerprints[0])
        {
            return Err(format!(
                "round {round}: a reader observed something that is not the published key ({} bytes)",
                observed.len()
            ));
        }
        // Nothing but the key is left behind: a temporary file that survived would
        // be a second copy of the private key.
        let left: Vec<String> = fs::read_dir(root.path())
            .map_err(|error| error.to_string())?
            .map(|entry| {
                entry
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .map_err(|error| error.to_string())
            })
            .collect::<Result<_, _>>()?;
        let key_name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .ok_or("the key's path has no file name")?;
        if left != [key_name] {
            return Err(format!(
                "round {round}: the root holds {left:?}, not one key file"
            ));
        }
    }
    Ok(())
}

/// A key file other accounts can reach is refused, and the refusal is not a miss.
///
/// Unix only: the states are a mode, a link and a directory, and a Windows host has
/// none of them in these terms. Its own case is the DACL rule, and the inventory
/// records what this host cannot produce.
#[cfg(unix)]
pub(crate) fn key_file_refuses_other_readers() -> Result<(), String> {
    let root = temp_root()?;
    let path = keyfile::file_in(root.path());
    let identity = load(root.path())?;
    let key = fs::read(&path).map_err(|error| error.to_string())?;
    if let Some(mode) = insecure_mode(&path) {
        return Err(format!(
            "a fresh key file is readable by others (mode {mode:03o})"
        ));
    }
    for mode in [0o644, 0o640, 0o604, 0o700, 0o400] {
        set_mode(&path, mode)?;
        let expected_refusal = mode & 0o077 != 0;
        match (expected_refusal, keyfile::load_or_create(root.path())) {
            (true, Err(KeyFileError::Insecure { .. })) => {
                if fs::read(&path).map_err(|error| error.to_string())? != key {
                    return Err(format!(
                        "refusing mode {mode:03o} rewrote the key file; a refusal must never re-key"
                    ));
                }
            }
            (false, Ok(found)) if found.fingerprint() == identity.fingerprint() => {}
            (false, other) => {
                return Err(format!(
                    "the stricter mode {mode:03o} was refused: {other:?}"
                ));
            }
            (true, other) => {
                return Err(format!(
                    "mode {mode:03o} was not refused as insecure: {other:?}"
                ));
            }
        }
    }

    // A link is never followed: the file it names is somebody else's file, and its
    // permissions are not the permissions that were checked.
    let elsewhere = temp_root()?;
    let target = keyfile::file_in(elsewhere.path());
    fs::copy(&path, &target).map_err(|error| error.to_string())?;
    fs::remove_file(&path).map_err(|error| error.to_string())?;
    symlink(&target, &path)?;
    match keyfile::load_or_create(root.path()) {
        Err(KeyFileError::Insecure {
            reason: Insecurity::Symlink,
            ..
        }) => {}
        other => return Err(format!("a symbolic link was not refused as one: {other:?}")),
    }
    fs::remove_file(&path).map_err(|error| error.to_string())?;

    // A link where the key belongs must not be written through either: creating the
    // key behind a stranger's link would put the private half wherever the link
    // points.
    let target = elsewhere.path().join("never-written");
    symlink(&target, &path)?;
    match keyfile::load_or_create(root.path()) {
        Err(KeyFileError::Insecure {
            reason: Insecurity::Symlink,
            ..
        }) if !target.exists() => {}
        other => {
            return Err(format!(
                "a key was written through a link, or the link was read as a key: {other:?}"
            ));
        }
    }
    fs::remove_file(&path).map_err(|error| error.to_string())?;

    // A directory where the key belongs is not a key either.
    fs::create_dir(&path).map_err(|error| error.to_string())?;
    match keyfile::load_or_create(root.path()) {
        Err(KeyFileError::Insecure {
            reason: Insecurity::NotRegular,
            ..
        }) => Ok(()),
        other => Err(format!("a directory was not refused as no key: {other:?}")),
    }
}

/// The unix rule, decided on facts nothing else can supply: bits, and two accounts.
///
/// Pinned here, because these are decided as data on every host: the mode message with
/// its POSIX `chmod`, the two shapes both readers refuse (a symbolic link, and something
/// that is not a regular file), and the two storage-root clauses unix owns. The
/// ownership wording needs the account directory, so it is pinned in
/// `unix_account_names_are_exact`; the Windows clauses are pinned beside the Windows
/// rule.
pub(crate) fn unix_rule_is_exact() -> Result<(), String> {
    let me = 501;
    if unix_refusal(0o600, me, me).is_some() || unix_refusal(0o400, me, me).is_some() {
        return Err("an owner-only mode was refused".to_owned());
    }
    match unix_refusal(0o644, me, me) {
        Some(Insecurity::Mode { mode: 0o644 }) => {}
        other => return Err(format!("mode 0644 was not refused as a mode: {other:?}")),
    }
    match unix_refusal(0o600, me + 1, me) {
        Some(Insecurity::Owner { owner, me: found }) if owner == me + 1 && found == me => {}
        other => return Err(format!("another owner was not refused as one: {other:?}")),
    }
    // The messages are the ones the docs quote. The quoting follows the cause, not the
    // host: a unix mode is repaired by `chmod`, so it is a POSIX argument wherever the
    // rule is decided.
    for (what, reason, expected) in [
        (
            "the mode refusal",
            Insecurity::Mode { mode: 0o644 },
            "/key is not private: group or other permission bits are set (mode 0644); \
             chmod 600 '/key'",
        ),
        (
            "the symbolic-link refusal",
            Insecurity::Symlink,
            "/key is not private: it is a symbolic link, which is never followed",
        ),
        (
            "the non-regular-file refusal",
            Insecurity::NotRegular,
            "/key is not private: it is not a regular file",
        ),
    ] {
        let printed = refusal(reason);
        if printed != expected {
            return Err(format!("{what} reads `{printed}`, not `{expected}`"));
        }
    }
    // The two clauses a storage root can carry on unix. The two Windows owns are
    // pinned beside the Windows rule.
    root_clause(
        Insecurity::Owner { owner: 0, me: 0 },
        "the account the new file belongs to is what has to change",
    )?;
    root_clause(
        Insecurity::Mode { mode: 0o755 },
        "the directory is what has to change",
    )?;
    // A mode that reaches past the owner is the more useful refusal of the two.
    match unix_refusal(0o640, me + 1, me) {
        Some(Insecurity::Mode { .. }) => Ok(()),
        other => Err(format!(
            "a file that is both foreign and group-readable was reported as {other:?}"
        )),
    }
}

/// The naming half of the unix ownership refusal: two accounts, looked up by number.
///
/// Unix only, because the lookup is the platform's account directory; the inventory
/// records the capability as unproducible on a host that has none, instead of letting
/// this claim pass unexamined.
#[cfg(unix)]
pub(crate) fn unix_account_names_are_exact() -> Result<(), String> {
    for (owner, me, expected) in [
        (
            0,
            0,
            "it belongs to account `root` (0), not to account `root` (0)",
        ),
        (
            0,
            4_000_000_000,
            "it belongs to account `root` (0), not to account `4000000000`",
        ),
        (
            4_000_000_000,
            0,
            "it belongs to account `4000000000`, not to account `root` (0)",
        ),
    ] {
        let printed = Insecurity::Owner { owner, me }.to_string();
        if printed != expected {
            return Err(format!(
                "the ownership refusal reads `{printed}`, not `{expected}`"
            ));
        }
    }
    Ok(())
}

/// The macOS rule: a deny entry narrows, the owner's own entry is theirs, and any
/// other allow entry is a refusal. Its message is pinned here too: the rule is decided
/// as data on every host, and the command it appends is a `chmod` wherever that is.
pub(crate) fn extended_access_rule_is_exact() -> Result<(), String> {
    let deny = Entry {
        allows: false,
        owner: false,
    };
    let mine = Entry {
        allows: true,
        owner: true,
    };
    let theirs = Entry {
        allows: true,
        owner: false,
    };
    if acl_refusal(&[]).is_some()
        || acl_refusal(&[deny]).is_some()
        || acl_refusal(&[mine]).is_some()
    {
        return Err("an access list that keeps the file to its owner was refused".to_owned());
    }
    // A deny entry narrows, the owner's own entry is theirs, an allow entry for
    // anyone else is a refusal.
    let reason =
        acl_refusal(&[mine, theirs]).ok_or("an allow entry for another account was accepted")?;
    let printed = refusal(reason);
    let expected = "/key is not private: extended access entries allow an account other than the \
                    owner; chmod -N '/key'";
    if printed != expected {
        return Err(format!(
            "the extended-entry refusal reads `{printed}`, not `{expected}`"
        ));
    }
    Ok(())
}

/// The Windows rule: the owner, `SYSTEM` and `Administrators`, and nothing else.
///
/// Every message the documentation table quotes is pinned here, with the quoting the
/// cause produces rather than the quoting this host would choose: a Windows refusal is
/// decided as data here even when no Windows host is running.
pub(crate) fn windows_dacl_rule_is_exact() -> Result<(), String> {
    let allow = |account: Account| DaclEntry {
        allows: true,
        account: Some(account),
    };
    let allowed = Dacl {
        owner: Some(Account::Owner),
        present: true,
        protected: true,
        entries: vec![
            allow(Account::Owner),
            allow(Account::System),
            allow(Account::Administrators),
        ],
    };
    if dacl_refusal(&allowed).is_some() {
        return Err(
            "an access list of the owner, SYSTEM and Administrators was refused".to_owned(),
        );
    }
    // A deny entry only narrows access, and a protected list that names nobody is
    // stricter than the allowed set rather than looser.
    let narrowed = Dacl {
        entries: vec![DaclEntry {
            allows: false,
            account: Some(Account::Other("DOMAIN\\someone".to_owned())),
        }],
        ..allowed.clone()
    };
    if dacl_refusal(&narrowed).is_some() {
        return Err("a deny entry was refused as if it granted access".to_owned());
    }
    if dacl_refusal(&Dacl {
        entries: Vec::new(),
        ..allowed.clone()
    })
    .is_some()
    {
        return Err("an empty, protected access list was refused".to_owned());
    }
    // Each shape that is refused: what it is, the list that has it, and the message an
    // operator reads. The messages are the module documentation's table; the repairs
    // travel as prose when the rule cannot print them, because they name an account the
    // message reports or are two calls. `/key` stands for the file, because a command
    // must name it where its own tool takes it.
    for (what, dacl, expected) in [
        (
            "an inherited list",
            Dacl {
                protected: false,
                ..allowed.clone()
            },
            "/key is not private: its access list is inherited from the directory; \
             icacls \"/key\" /inheritance:r /grant:r \"%USERNAME%\":F",
        ),
        (
            "no list at all",
            Dacl {
                present: false,
                ..allowed.clone()
            },
            "/key is not private: it carries no access list at all, so every account is allowed",
        ),
        (
            "a fourth account",
            Dacl {
                entries: vec![allow(Account::Other("Everyone".to_owned()))],
                ..allowed.clone()
            },
            "/key is not private: it allows `Everyone`, which is not the owner, SYSTEM or \
             Administrators",
        ),
        (
            "an entry this reader cannot attribute",
            Dacl {
                entries: vec![DaclEntry {
                    allows: true,
                    account: None,
                }],
                ..allowed.clone()
            },
            "/key is not private: it has an access entry this reader cannot attribute to an \
             account, which may allow an account that is not the owner, SYSTEM or \
             Administrators",
        ),
    ] {
        let Some(reason) = dacl_refusal(&dacl) else {
            return Err(format!("{what} was accepted"));
        };
        if !matches!(reason, Insecurity::AccessList { .. }) {
            return Err(format!(
                "{what} was not refused as an access-list problem: {reason:?}"
            ));
        }
        let printed = refusal(reason);
        if printed != expected {
            return Err(format!("{what} reads `{printed}`, not `{expected}`"));
        }
    }
    // Ownership is a different fact with a different repair: an owner may rewrite the
    // list of what it owns, so a file owned by SYSTEM, an administrator or anyone else is
    // refused as ownership naming that account, and a file nobody owns is refused as
    // ownerless with no account invented. Each row builds the reason once and pins the
    // kind and the wording of that one refusal; the repair hands the file to `%USERNAME%`.
    let owned = |owner: Option<Account>| Dacl {
        owner,
        ..allowed.clone()
    };
    for (what, owner, expected) in [
        (
            "a file owned by SYSTEM",
            Some(Account::System),
            "/key is not private: it belongs to `SYSTEM`, which may rewrite the list; \
             icacls \"/key\" /setowner \"%USERNAME%\"",
        ),
        (
            "a file owned by an administrator",
            Some(Account::Administrators),
            "/key is not private: it belongs to `Administrators`, which may rewrite the list; \
             icacls \"/key\" /setowner \"%USERNAME%\"",
        ),
        (
            "a file owned by another account",
            Some(Account::Other("DOMAIN\\someone".to_owned())),
            "/key is not private: it belongs to `DOMAIN\\someone`, which may rewrite the \
             list; icacls \"/key\" /setowner \"%USERNAME%\"",
        ),
        (
            "a file nobody owns",
            None,
            "/key is not private: it has no owner at all, so no account can be named as \
             owning it; icacls \"/key\" /setowner \"%USERNAME%\"",
        ),
    ] {
        let Some(reason) = dacl_refusal(&owned(owner)) else {
            return Err(format!("{what} was accepted"));
        };
        if !matches!(
            reason,
            Insecurity::ForeignOwner { .. } | Insecurity::Unowned
        ) {
            return Err(format!(
                "{what} was not refused as an ownership problem: {reason:?}"
            ));
        }
        let printed = refusal(reason);
        if printed != expected {
            return Err(format!("{what} reads `{printed}`, not `{expected}`"));
        }
    }
    // The two ownership clauses a storage root can carry: the account a new file
    // belongs to, and no owner at all.
    root_clause(
        Insecurity::ForeignOwner {
            owner: "Administrators".to_owned(),
        },
        "the account the new file belongs to is what has to change",
    )?;
    root_clause(
        Insecurity::Unowned,
        "the ownership of the new file is what has to change",
    )?;
    Ok(())
}

/// A file that is not a key is refused, and nothing is written in its place.
///
/// The nonsense is written over the key the module itself created, so the file
/// keeps the access the module gave it. What has to refuse these files is their
/// contents, and the case then says the same thing on a host whose permissions are
/// an access list rather than a mode.
pub(crate) fn key_file_refuses_a_broken_key() -> Result<(), String> {
    let root = temp_root()?;
    let path = keyfile::file_in(root.path());
    load(root.path())?;
    // A real document of the older form, not bytes that merely happen to be 48: the
    // documented refusal of PKCS#8 v1 is the one thing here that would otherwise rest
    // on what a library does with a shape this crate never writes.
    let v1 = pkcs8_v1([7u8; 32]);
    for (bytes, expected) in [
        (Vec::new(), Malformed::Empty),
        (v1, Malformed::NotAKey { bytes: 48 }),
        (vec![0u8; 48], Malformed::NotAKey { bytes: 48 }),
        (b"not a key".to_vec(), Malformed::NotAKey { bytes: 9 }),
    ] {
        fs::write(&path, &bytes).map_err(|error| error.to_string())?;
        match keyfile::load_or_create(root.path()) {
            Err(KeyFileError::Malformed { reason, .. }) if reason == expected => {}
            other => {
                return Err(format!(
                    "{} bytes of nonsense were not refused as {expected:?}: {other:?}",
                    bytes.len()
                ));
            }
        }
        if fs::read(&path).map_err(|error| error.to_string())? != bytes {
            return Err("refusing a broken key file rewrote it".to_owned());
        }
    }
    Ok(())
}

/// A PKCS#8 v1 Ed25519 key: 48 bytes, the seed alone and no public key beside it.
///
/// The crate writes and accepts v2 (83 bytes, seed and public key), because a file
/// whose public key cannot be checked is a file it will not use.
fn pkcs8_v1(seed: [u8; 32]) -> Vec<u8> {
    let mut der = vec![
        0x30, 0x2e, // SEQUENCE of 46 bytes
        0x02, 0x01, 0x00, // version 0, which is what makes it v1
        0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, // the Ed25519 algorithm
        0x04, 0x22, 0x04, 0x20, // privateKey: an OCTET STRING of 32 bytes
    ];
    der.extend_from_slice(&seed);
    der
}

/// The macOS check reads the extended access list, not only the mode: a 0600 file
/// with an entry that grants everyone read is refused.
#[cfg(target_os = "macos")]
pub(crate) fn key_file_refuses_an_extended_entry() -> Result<(), String> {
    let root = temp_root()?;
    let path = keyfile::file_in(root.path());
    let identity = load(root.path())?;
    let key = fs::read(&path).map_err(|error| error.to_string())?;

    // The owner's own entry is theirs to have: a stricter list is accepted.
    acl::set(
        &path,
        acl::Entry {
            allows: true,
            everyone: false,
        },
    )?;
    if load(root.path())?.fingerprint() != identity.fingerprint() {
        return Err("an access entry naming the owner was refused".to_owned());
    }
    // A deny entry only narrows, so it is accepted too: this one denies write,
    // which no reader of the key needs.
    acl::set(
        &path,
        acl::Entry {
            allows: false,
            everyone: true,
        },
    )?;
    if load(root.path())?.fingerprint() != identity.fingerprint() {
        return Err("an access entry that denies everyone was refused".to_owned());
    }
    // An allow entry for everybody is exactly what a mode cannot show, and it is
    // what makes a 0600 file readable.
    acl::set(
        &path,
        acl::Entry {
            allows: true,
            everyone: true,
        },
    )?;
    match keyfile::load_or_create(root.path()) {
        Err(KeyFileError::Insecure {
            reason: Insecurity::AccessList { .. },
            ..
        }) => {}
        other => {
            return Err(format!(
                "a 0600 key file with an extended allow entry was not refused: {other:?}"
            ));
        }
    }
    if fs::read(&path).map_err(|error| error.to_string())? != key {
        return Err("refusing an extended access entry rewrote the key file".to_owned());
    }
    Ok(())
}

/// A root whose access list a new key file inherits is refused before the key
/// exists: there is no file to fix, the root is what has to change.
///
/// macOS only: the state is an extended access entry marked for inheritance, which
/// no mode can express and no other platform here has. The entry survives the
/// private mode `make_private` sets, so the check that runs before the key is
/// written is what refuses.
#[cfg(target_os = "macos")]
pub(crate) fn key_file_refuses_a_sharing_root() -> Result<(), String> {
    let parent = temp_root()?;
    acl::inherit_read_for_everyone(parent.path())?;
    let root = parent.path().join("sharing");
    fs::create_dir(&root).map_err(|error| error.to_string())?;
    let refusal = match keyfile::load_or_create(&root) {
        Err(error @ KeyFileError::RootNotPrivate { .. }) => error,
        other => {
            return Err(format!(
                "a root that hands its list to a new key file was not refused as one: {other:?}"
            ));
        }
    };
    match &refusal {
        KeyFileError::RootNotPrivate {
            root: named,
            reason: Insecurity::AccessList { .. },
        } if *named == root => {}
        other => {
            return Err(format!(
                "a root that hands its list was refused as {other:?}"
            ));
        }
    }
    // The message names the root and carries the repair for it: the root exists,
    // unlike the key file a refusal is usually about.
    let message = refusal.to_string();
    let command = format!("chmod -N '{}'", root.display());
    if !message.contains(&root.display().to_string())
        || !message.contains("the directory is what has to change")
        || !message.contains(&command)
    {
        return Err(format!(
            "the sharing-root refusal does not name the root and its repair `{command}`: \
             `{message}`"
        ));
    }
    let left = fs::read_dir(&root)
        .map_err(|error| error.to_string())?
        .count();
    if left != 0 {
        return Err(format!(
            "a refused create left {left} entries under the root"
        ));
    }
    // Clearing that root's list is the fix, and the machine then exists and reads
    // back as one: the refusal cost nothing.
    acl::clear(&root)?;
    let identity = load(&root)?;
    if load(&root)?.fingerprint() != identity.fingerprint() {
        return Err("the root gave two identities once its list was cleared".to_owned());
    }
    Ok(())
}

/// One rendering of an identity, and the same 44 bytes however they were reached.
pub(crate) fn one_rendering_round_trips() -> Result<(), String> {
    let identity = root::detached_identity().map_err(|error| error.to_string())?;
    let fingerprint = identity.fingerprint();
    let shown = fingerprint.to_string();
    if shown.len() != FINGERPRINT_LEN * 2 {
        return Err(format!("the rendering is {} characters", shown.len()));
    }
    if !shown
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("the rendering `{shown}` is not lowercase hex"));
    }
    if Fingerprint::from_hex(&shown) != Some(fingerprint) {
        return Err("the rendering does not read back to the same 44 bytes".to_owned());
    }
    if Fingerprint::from_hex(&shown[..shown.len() - 2]).is_some()
        || Fingerprint::from_hex(&shown.to_uppercase()).is_some()
        || Fingerprint::from_hex(&format!("{shown}00")).is_some()
    {
        return Err("a shortened, uppercase or overlong rendering was accepted".to_owned());
    }
    // A peer id is the key inside the fingerprint, so its one rendering is the same
    // string: a machine has one spelling.
    if format!("{:?}", fingerprint.peer_id()) != shown {
        return Err(format!(
            "the peer id renders as `{:?}`, the fingerprint as `{shown}`",
            fingerprint.peer_id()
        ));
    }
    Ok(())
}

/// The key under `root`, with a refusal rendered as its message. The cases that
/// are about *why* a file was refused call `keyfile::load_or_create` directly.
fn load(root: &Path) -> Result<Identity, String> {
    keyfile::load_or_create(root).map_err(|error| error.to_string())
}

/// The rotation ban is three source-scan invariants, and the scan that proves them
/// holds runs as a summary check over every source. What this case pins is the wiring
/// that would let it go quiet: the name the crate writes and the needle the scan looks
/// for, the needles and the two reaches of the claims — a renamed or copied path and a
/// removed directory judged everywhere, single-file writes only where the key is written
/// — the key file's own module being in the scan and inside the claims that judge it,
/// and the mint claim covering the whole tree.
pub(crate) fn no_key_rotation_is_proven() -> Result<(), String> {
    use crate::invariants as table;
    // The permanent contract, spelled out where a change to it cannot pass: the
    // path the crate builds is the root plus `identity.key`, and the scan's needle
    // is that same name.
    let path = mahbot_peers::identity::keyfile::file_in(Path::new("root"));
    if path != Path::new("root").join("identity.key") {
        return Err(format!(
            "the key file is at {}, not directly in the root",
            path.display()
        ));
    }
    let Some(name) = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
    else {
        return Err("the key file's path has no file name".to_owned());
    };
    if table::KEY_FILE_NAME != format!("\"{name}\"") {
        return Err(format!(
            "the crate builds `{name}` and the scan looks for `{}`",
            table::KEY_FILE_NAME
        ));
    }
    if !table::workspace_sources()
        .iter()
        .any(|source| source.path == table::KEY_FILE_SOURCE)
    {
        return Err(format!(
            "{} is not in the scan, so nothing proves the key is never replaced",
            table::KEY_FILE_SOURCE
        ));
    }
    // Both claims' needles are spelled out here rather than read from the table, so a
    // form dropped from a check fails instead of quietly widening its claim.
    let replacing = table::find("identity.key_is_never_replaced")
        .ok_or_else(|| "identity.key_is_never_replaced is not in the table".to_owned())?;
    let naming = table::find("identity.key_file_name_is_one_place")
        .ok_or_else(|| "identity.key_file_name_is_one_place is not in the table".to_owned())?;
    let at = |path: &str, text: &str| table::Source {
        path: path.to_owned(),
        text: text.to_owned(),
    };
    for form in [
        "std::fs::remove_dir_all(&root)?",
        "std::fs::rename(&a, &b)?",
        "std::fs::copy(&a, &b)?",
    ] {
        if (replacing.check)(&at("src/net.rs", form)).is_empty() {
            return Err(format!(
                "the replacement claim no longer flags `{form}`, which can take the key with \
                 the path it lives in"
            ));
        }
    }
    for form in [
        "std::fs::remove_file(&key)?",
        "std::fs::write(&key, bytes)?",
        "temp.persist(&key)?",
        "file.set_len(0)?",
    ] {
        if (replacing.check)(&at(table::KEY_FILE_SOURCE, form)).is_empty() {
            return Err(format!(
                "the replacement claim no longer flags `{form}` in the key's own module"
            ));
        }
        if !(replacing.check)(&at("src/net.rs", form)).is_empty() {
            return Err(format!(
                "the replacement claim flags `{form}` outside the identity module, where \
                 writing a file is ordinary work"
            ));
        }
    }
    if (naming.check)(&at("src/net.rs", "let key = keyfile::file_in(root);")).is_empty() {
        return Err("the name claim no longer flags a second route to the key's path".to_owned());
    }
    for (id, scoped) in [
        ("identity.key_is_never_replaced", true),
        ("identity.key_file_name_is_one_place", true),
        ("identity.key_is_minted_in_one_place", false),
    ] {
        let invariant =
            table::find(id).ok_or_else(|| format!("invariant {id} is not in the table"))?;
        // A scoped claim must name the key file's module; the mint claim is the one
        // that must cover everything instead, since a rig that could mint would be a
        // second way to become a machine.
        let covered = if scoped {
            invariant.covers(table::KEY_FILE_SOURCE)
        } else {
            invariant.scope.is_empty()
        };
        if !covered {
            return Err(format!(
                "{id} does not cover {} as claimed",
                table::KEY_FILE_SOURCE
            ));
        }
    }
    Ok(())
}

/// The permission bits of a file, when they are not owner-only.
#[cfg(unix)]
fn insecure_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    let mode = fs::metadata(path).ok()?.mode() & 0o777;
    (mode & 0o077 != 0).then_some(mode)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|error| error.to_string())
}

#[cfg(unix)]
fn symlink(target: &Path, link: &Path) -> Result<(), String> {
    std::os::unix::fs::symlink(target, link).map_err(|error| error.to_string())
}

/// Writing an extended access list, which is the only way to produce the file state
/// these cases are about. It is the one place the harness writes one: `set_mode` and
/// `symlink` above set a mode and a link, which no list can express.
///
/// The declarations mirror `src/identity/access/unix.rs`, which reads an extended
/// list through the same three calls: they cannot be shared, because the library
/// exports no Darwin FFI — a differing constant shows up here as the case failing
/// to produce the state it is about, not as a silent pass.
#[cfg(target_os = "macos")]
mod acl {
    use std::ffi::{CString, c_char, c_int, c_void};
    use std::path::Path;

    /// `ACL_TYPE_EXTENDED`, `ACL_EXTENDED_ALLOW`, `ACL_EXTENDED_DENY`,
    /// `ACL_READ_DATA`, `ACL_ENTRY_FILE_INHERIT` and `ACL_ENTRY_DIRECTORY_INHERIT`
    /// from `sys/acl.h`.
    const ACL_TYPE_EXTENDED: u32 = 0x100;
    const ACL_EXTENDED_ALLOW: u32 = 1;
    const ACL_EXTENDED_DENY: u32 = 2;
    const ACL_READ_DATA: u32 = 1 << 1;
    const ACL_WRITE_DATA: u32 = 1 << 2;
    const ACL_ENTRY_FILE_INHERIT: u32 = 1 << 5;
    const ACL_ENTRY_DIRECTORY_INHERIT: u32 = 1 << 6;

    /// `group:everyone`, the account `chmod +a 'everyone …'` names.
    const EVERYONE_GID: u32 = 12;

    #[repr(C)]
    struct Acl {
        _private: [u8; 0],
    }

    #[repr(C)]
    struct AclEntry {
        _private: [u8; 0],
    }

    #[repr(C)]
    struct AclPermset {
        _private: [u8; 0],
    }

    #[repr(C)]
    struct AclFlagset {
        _private: [u8; 0],
    }

    unsafe extern "C" {
        fn acl_init(count: c_int) -> *mut Acl;
        fn acl_create_entry(acl: *mut *mut Acl, entry: *mut *mut AclEntry) -> c_int;
        fn acl_set_tag_type(entry: *mut AclEntry, tag: u32) -> c_int;
        fn acl_get_permset(entry: *mut AclEntry, permset: *mut *mut AclPermset) -> c_int;
        fn acl_add_perm(permset: *mut AclPermset, perm: u32) -> c_int;
        fn acl_set_qualifier(entry: *mut AclEntry, qualifier: *const c_void) -> c_int;
        fn acl_get_flagset_np(entry: *mut AclEntry, flagset: *mut *mut AclFlagset) -> c_int;
        fn acl_add_flag_np(flagset: *mut AclFlagset, flag: u32) -> c_int;
        fn acl_set_flagset_np(entry: *mut AclEntry, flagset: *mut AclFlagset) -> c_int;
        fn acl_set_file(path: *const c_char, acl_type: u32, acl: *mut Acl) -> c_int;
        fn acl_free(object: *mut c_void) -> c_int;
        fn mbr_uid_to_uuid(id: u32, uuid: *mut u8) -> c_int;
        fn mbr_gid_to_uuid(id: u32, uuid: *mut u8) -> c_int;
        fn geteuid() -> u32;
    }

    /// One entry of an extended access list, as these cases write it: whether it
    /// allows or denies, and whether it names everyone or the owner.
    pub(super) struct Entry {
        pub(super) allows: bool,
        pub(super) everyone: bool,
    }

    pub(super) fn set(path: &Path, entry: Entry) -> Result<(), String> {
        // An allow grants read, which is what makes a 0600 file reachable. A deny
        // takes write, which nobody needs to load a key: denying read would deny the
        // owner too, and the owner has to be able to read the case's result.
        let (tag, permission) = if entry.allows {
            (ACL_EXTENDED_ALLOW, ACL_READ_DATA)
        } else {
            (ACL_EXTENDED_DENY, ACL_WRITE_DATA)
        };
        let qualifier = qualifier(entry.everyone)?;
        install(path, 1, "setting an extended access entry", |acl| {
            add_entry(acl, tag, permission, &qualifier, false)
        })
    }

    /// Give `path` an entry everything created inside it inherits: `chmod +a
    /// 'everyone allow read,file_inherit,directory_inherit' path`.
    pub(super) fn inherit_read_for_everyone(path: &Path) -> Result<(), String> {
        let qualifier = qualifier(true)?;
        install(path, 1, "setting an inheritable access entry", |acl| {
            add_entry(acl, ACL_EXTENDED_ALLOW, ACL_READ_DATA, &qualifier, true)
        })
    }

    /// Add one entry to `acl`: `tag`, `permission` and `qualifier`, marked for
    /// inheritance when `inheritable`.
    fn add_entry(
        acl: *mut *mut Acl,
        tag: u32,
        permission: u32,
        qualifier: &[u8; 16],
        inheritable: bool,
    ) -> bool {
        let mut created = std::ptr::null_mut();
        let mut permset = std::ptr::null_mut();
        let mut flagset = std::ptr::null_mut();
        // SAFETY: `created`, `permset` and `flagset` are written by the calls that
        // fill them, and the qualifier is a uuid_t the caller owns.
        unsafe {
            let entry = acl_create_entry(acl, &raw mut created) == 0
                && acl_set_tag_type(created, tag) == 0
                && acl_get_permset(created, &raw mut permset) == 0
                && acl_add_perm(permset, permission) == 0
                && acl_set_qualifier(created, qualifier.as_ptr().cast::<c_void>()) == 0;
            entry
                && (!inheritable
                    || (acl_get_flagset_np(created, &raw mut flagset) == 0
                        && acl_add_flag_np(flagset, ACL_ENTRY_FILE_INHERIT) == 0
                        && acl_add_flag_np(flagset, ACL_ENTRY_DIRECTORY_INHERIT) == 0
                        && acl_set_flagset_np(created, flagset) == 0))
        }
    }

    /// Remove every entry: `chmod -N path`.
    pub(super) fn clear(path: &Path) -> Result<(), String> {
        install(path, 0, "clearing an extended access list", |_| true)
    }

    /// The account a qualifier names: `group:everyone` for an entry naming
    /// everybody, this account otherwise. A real account either way, so the file
    /// state is the one the claim is about and not a qualifier that resolves to
    /// nobody.
    fn qualifier(everyone: bool) -> Result<[u8; 16], String> {
        let mut uuid = [0u8; 16];
        // SAFETY: the system's account tables write into this frame's array.
        let looked_up = unsafe {
            if everyone {
                mbr_gid_to_uuid(EVERYONE_GID, uuid.as_mut_ptr())
            } else {
                mbr_uid_to_uuid(geteuid(), uuid.as_mut_ptr())
            }
        };
        if looked_up == 0 {
            Ok(uuid)
        } else {
            Err(format!(
                "resolving an entry's account: {}",
                std::io::Error::last_os_error()
            ))
        }
    }

    /// Install a list of `entries` entries, built by `build`, on `path`.
    fn install(
        path: &Path,
        entries: c_int,
        what: &str,
        build: impl FnOnce(*mut *mut Acl) -> bool,
    ) -> Result<(), String> {
        let path =
            CString::new(path.as_os_str().as_encoded_bytes()).map_err(|error| error.to_string())?;
        // SAFETY: `acl` is this frame's list, freed once at the end; `build` writes
        // only into it, and the path is a C string that outlives the call.
        unsafe {
            let mut acl = acl_init(entries);
            if acl.is_null() {
                return Err(format!("acl_init: {}", std::io::Error::last_os_error()));
            }
            let applied =
                build(&raw mut acl) && acl_set_file(path.as_ptr(), ACL_TYPE_EXTENDED, acl) == 0;
            let error = std::io::Error::last_os_error();
            acl_free(acl.cast::<c_void>());
            if applied {
                Ok(())
            } else {
                Err(format!("{what}: {error}"))
            }
        }
    }
}
