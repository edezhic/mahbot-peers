//! The capability inventory and the check that pairs it with recorded cases.
//!
//! Every behaviour this workspace exposes is an entry here: either witnessed by
//! a recorded case or recorded as unproducible, with the fact that puts the case out
//! of reach here and the procedure that produces it elsewhere. The check runs in
//! both directions, because either half can drift: an entry with no case fails, and
//! a case whose entry no longer exists fails.
//!
//! The list is maintained by hand and the check cannot prove it exhaustive; it
//! proves that what is listed is witnessed, and that nothing is witnessed that
//! is not listed. It also reads each unproducible entry's procedure, because a
//! record nobody here can run is worth only what an operator can follow: a blank
//! one, one with an unfilled `<placeholder>`, one that changes a key file without
//! saying its root is a scratch one, and one that quotes a repair ending in `it`
//! instead of naming the file are each a violation. The inventory is data, so the
//! check can be handed a deliberately broken one in-process and must report it:
//! that is how the check itself is tested, with no subprocess and no manual step.

use std::fmt;

/// One behaviour this workspace exposes, and whether a case witnesses it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capability {
    /// Stable id, namespaced by owner: `library.identity.…`, `harness.link.…`.
    pub id: &'static str,
    /// What is claimed, in one sentence a reader can check against the case.
    pub claim: &'static str,
    /// `Some` with the fact that puts the case out of reach, when no case can exist
    /// here; the procedure an operator elsewhere follows is the entry's own, so the
    /// two cannot part company.
    pub unproducible: Option<&'static str>,
    /// The recorded procedure that produces the state elsewhere, if this entry has
    /// one — attached to the entry so no id can be typed twice or misspelt, and set
    /// whichever branch of a `cfg!` built the entry.
    pub procedure: Option<&'static str>,
}

impl Capability {
    /// An entry that a recorded case must witness.
    #[must_use]
    pub const fn witnessed(id: &'static str, claim: &'static str) -> Self {
        Self {
            id,
            claim,
            unproducible: None,
            procedure: None,
        }
    }

    /// An entry that no case here can witness: why not, and how a host that can
    /// produces it.
    #[must_use]
    pub const fn unproducible(
        id: &'static str,
        claim: &'static str,
        why: &'static str,
        how: &'static str,
    ) -> Self {
        Self {
            id,
            claim,
            unproducible: Some(why),
            procedure: Some(how),
        }
    }

    /// The same entry with its recorded procedure, for a host that witnesses the state
    /// and still has to judge the text an operator elsewhere follows.
    #[must_use]
    pub const fn with_procedure(mut self, how: &'static str) -> Self {
        self.procedure = Some(how);
        self
    }
}

/// A recorded case that witnesses exactly one capability.
#[derive(Clone, Copy)]
pub struct Witness {
    /// Stable id, unique across the table; this is the "recorded case".
    pub id: &'static str,
    /// The capability id this case speaks for.
    pub capability: &'static str,
    /// The case itself. It returns `Err` with the reason it failed.
    pub case: fn() -> Result<(), String>,
}

impl fmt::Debug for Witness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Witness")
            .field("id", &self.id)
            .field("capability", &self.capability)
            .finish_non_exhaustive()
    }
}

/// One way the inventory and the witness table disagree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Violation {
    DuplicateCapability(&'static str),
    DuplicateWitness(&'static str),
    /// The inventory is empty, so the check proves nothing.
    NoCapabilities,
    /// A case speaks for an entry already declared impossible.
    WitnessForUnproducible {
        witness: &'static str,
        capability: &'static str,
    },
    /// A capability no case speaks for and no reason excuses.
    Unwitnessed {
        capability: &'static str,
    },
    /// A case for a capability the inventory no longer lists.
    OrphanWitness {
        witness: &'static str,
        capability: &'static str,
    },
    /// An entry marked unproducible without saying what puts the case out of reach.
    NoReason {
        capability: &'static str,
    },
    /// An entry marked unproducible without saying how a host that can produces it.
    NoProcedure {
        capability: &'static str,
    },
    /// A procedure with an unfilled placeholder such as `<root>` or `<path>`: the
    /// operator cannot run it, and could aim it at anything.
    Placeholder {
        capability: &'static str,
        placeholder: &'static str,
    },
    /// A procedure that changes a key file without saying its root is a scratch one.
    /// Aimed at an installation's own root while it runs, it would leave that machine
    /// unable to load its key.
    NotOnScratchRoot {
        capability: &'static str,
    },
    /// A procedure quoting a repair that ends in `it` rather than naming the file: the
    /// runtime message carries the path, so a quote without one is stale and not a
    /// command an operator can run.
    PathlessCommand {
        capability: &'static str,
    },
    /// The case ran and its claim did not hold.
    Failed {
        witness: &'static str,
        capability: &'static str,
        detail: String,
    },
    /// The case panicked instead of returning a verdict.
    Panicked {
        witness: &'static str,
        capability: &'static str,
        detail: String,
    },
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateCapability(id) => write!(f, "capability {id} is listed twice"),
            Self::DuplicateWitness(id) => write!(f, "witness {id} is listed twice"),
            Self::NoCapabilities => f.write_str("the inventory is empty"),
            Self::WitnessForUnproducible {
                witness,
                capability,
            } => write!(
                f,
                "witness {witness} speaks for {capability}, which is declared unproducible"
            ),
            Self::Unwitnessed { capability } => {
                write!(f, "capability {capability} has no witness")
            }
            Self::OrphanWitness {
                witness,
                capability,
            } => {
                write!(
                    f,
                    "witness {witness} speaks for unknown capability {capability}"
                )
            }
            Self::NoReason { capability } => {
                write!(
                    f,
                    "capability {capability} is unproducible without saying why"
                )
            }
            Self::NoProcedure { capability } => {
                write!(
                    f,
                    "capability {capability} is unproducible without saying how it is produced"
                )
            }
            Self::Placeholder {
                capability,
                placeholder,
            } => write!(
                f,
                "capability {capability} has the unfilled placeholder {placeholder} in its \
                 procedure, so an operator cannot run it as written"
            ),
            Self::NotOnScratchRoot { capability } => write!(
                f,
                "capability {capability} changes a key file without saying its root is a \
                 scratch one, so an operator could aim it at a live installation"
            ),
            Self::PathlessCommand { capability } => write!(
                f,
                "capability {capability} quotes a repair that ends in `it` instead of \
                 naming the file, which is not the command the program prints"
            ),
            Self::Failed {
                witness,
                capability,
                detail,
            } => write!(f, "witness {witness} for {capability} failed: {detail}"),
            Self::Panicked {
                witness,
                capability,
                detail,
            } => {
                write!(f, "witness {witness} for {capability} panicked: {detail}")
            }
        }
    }
}

/// What the check found.
pub type Report = crate::report::Report<Violation>;

/// The claims this workspace makes, for this host: the library's and the
/// harness's together.
///
/// An entry is a behaviour a caller may rely on. The harness is a deliverable in
/// its own right, so its machines, link, clock, beacon rig and checks are claimed
/// here exactly like the library's seams. Entries only one platform can produce are
/// added by the platform table, so a host that cannot produce them says so with the
/// procedure that does, instead of passing over them.
#[must_use]
pub fn capabilities() -> Vec<Capability> {
    let mut all = CAPABILITIES.to_vec();
    all.extend(platform_capabilities());
    all
}

/// The claims only one platform can decide, for this host.
///
/// Both variants are compiled on every host and only one is chosen: a claim stated
/// with `#[cfg]` in two places is a branch nobody on the other platform ever
/// type-checks, which is how a table that cannot build elsewhere ships green.
fn platform_capabilities() -> Vec<Capability> {
    let insecure_file = if cfg!(unix) {
        Capability::witnessed(
            "library.identity.key_file.insecure_file",
            INSECURE_FILE_CLAIM,
        )
        .with_procedure(UNIX_MODE_HOW)
    } else {
        Capability::unproducible(
            "library.identity.key_file.insecure_file",
            INSECURE_FILE_CLAIM,
            "the case is unix-only: this host has none of the facts it is built on — no mode bits, no ownership numbers, and no second account. A link or a directory at the key's path is refused by the Windows reader as well, but no case here builds those states for it — creating a link needs an elevated prompt or Developer Mode — and the access-list states have their own entry (`library.identity.key_file.windows_dacl`)",
            UNIX_MODE_HOW,
        )
    };
    let extended_acl = if cfg!(target_os = "macos") {
        Capability::witnessed("library.identity.key_file.extended_acl", EXTENDED_ACL_CLAIM)
            .with_procedure(MACOS_ACL_HOW)
    } else {
        Capability::unproducible(
            "library.identity.key_file.extended_acl",
            EXTENDED_ACL_CLAIM,
            "the extended access list that this reader reads is Darwin's `acl(3)`, a macOS fact: a Linux POSIX ACL that grants another account also raises the group bits, so the mode rule refuses it first, and this host reads no such list",
            MACOS_ACL_HOW,
        )
    };
    let root_access_list = if cfg!(target_os = "macos") {
        Capability::witnessed(
            "library.identity.key_file.root_access_list",
            ROOT_ACCESS_LIST_CLAIM,
        )
        .with_procedure(MACOS_ROOT_HOW)
    } else {
        Capability::unproducible(
            "library.identity.key_file.root_access_list",
            ROOT_ACCESS_LIST_CLAIM,
            "only macOS is witnessed: the state is an access entry a directory hands to the files created inside it, and an extended entry survives the mode `create` sets. A Windows directory hands its list on too, but the writer protects the new file's list before the check runs, so a run that publishes the key does not raise this refusal there — only the swap `keyfile::create` documents, where the list is applied to one path and read from another, does; a Linux host reads no access list at all, so the state does not exist there",
            MACOS_ROOT_HOW,
        )
    };
    let unix_names = if cfg!(unix) {
        Capability::witnessed(
            "library.identity.access.unix_account_names",
            UNIX_NAMES_CLAIM,
        )
        .with_procedure(UNIX_NAMES_HOW)
    } else {
        Capability::unproducible(
            "library.identity.access.unix_account_names",
            UNIX_NAMES_CLAIM,
            "the names come from the platform's account directory, a unix fact: this host has no uid to resolve, so every unix refusal it prints carries numbers only",
            UNIX_NAMES_HOW,
        )
    };
    vec![insecure_file, extended_acl, root_access_list, unix_names]
}

/// The claim about a unix file's mode, ownership and links, the same on every host:
/// only whether this host can produce the file states differs. Foreign ownership is
/// not part of it: that file state needs a second account and is its own entry.
const INSECURE_FILE_CLAIM: &str = "a key file that group or other permission bits reach, a symbolic link in its place, a directory in its place and a link a key would be written through are each refused and left byte for byte as they were, while an owner-only mode, including a read-only one, is accepted";

/// The claim about a macOS extended access list on an existing key file, the same
/// on every host.
const EXTENDED_ACL_CLAIM: &str = "the macOS reader refuses a 0600 key file that carries an extended access entry allowing an account other than its owner, and accepts a deny entry and the owner's own entry";

/// The claim about a storage root whose access list a new key file inherits.
const ROOT_ACCESS_LIST_CLAIM: &str = "a storage root whose access list a new key file inherits is refused before a key is minted, with the root named and nothing left behind, and clearing that list gives the root an identity";

/// The claim about the login names a unix ownership refusal adds to the numbers.
const UNIX_NAMES_CLAIM: &str = "a unix ownership refusal names both accounts by login name and number, and reports the number alone when the platform has no name for it";

/// What a host that can produce [`UNIX_NAMES_CLAIM`] does: the account directory is
/// the platform's, so the suite on a unix host is the whole procedure.
const UNIX_NAMES_HOW: &str = "On a unix host, `cargo test -p mahbot-peers-harness` runs the case `unix_account_names_are_exact` itself: each side of the refusal is pinned, with `root` (0) for a resolved account and the number alone — 4000000000 — for an id the directory does not have.";

// The paragraphs every procedure shares, written once: each expands to a string
// literal, so a record splices it in with `concat!` instead of repeating the sentence
// most likely to drift.
macro_rules! build_once {
    () => {
        "From the checkout's root, build once as yourself: `cargo build -p mahbot-beacon-server`, the binary that loads a key through the library's `load_or_create` — the same call a machine uses. It is `target/debug/mahbot-beacon-server`; no step runs `cargo` under `sudo`, so `target/` stays yours. "
    };
}
macro_rules! loopback_port {
    () => {
        "Every run uses `--listen 127.0.0.1:0`, which asks the OS for a free loopback port and prints it, so no step depends on a fixed port. "
    };
}
macro_rules! unix_scratch_root {
    () => {
        "(1) A scratch root, never the product's own: `root=\"$(mktemp -d)\"` and `key=\"$root/identity.key\"`. "
    };
}
macro_rules! first_run {
    () => {
        "(2) With no key there yet, run `target/debug/mahbot-beacon-server --listen 127.0.0.1:0 --root \"$root\"`: it loads the key before it binds, prints `identity …` and serves until Ctrl-C; `\"$key\"` now exists, 83 bytes, mode 0600. Stop it with Ctrl-C before the next step. "
    };
}
macro_rules! protected_list {
    () => {
        "icacls \"%key%\" /inheritance:r /grant:r \"%USERNAME%\":F"
    };
}
macro_rules! stop_and_clean {
    () => {
        "Ctrl-C, then `rm -rf \"$root\"`; nothing outside the scratch root was touched."
    };
}

// The recorded procedures. Each one names a scratch root of its own before it changes
// anything, says which state it needs before it runs a command, and checks the result
// of each change — the refusal it must raise, or the same identity once repaired — so a
// reader can follow it without filling in a placeholder, and none of them touches the
// root the product uses. The inventory check refuses a procedure that leaves an
// unfilled `<placeholder>`, quotes a repair that ends in `it` instead of naming the
// file, or changes a key file without saying its root is a scratch one.
const UNIX_MODE_HOW: &str = concat!(
    "On a unix host, where `cargo test -p mahbot-peers-harness` runs the case `key_file_refuses_other_readers` itself. ",
    build_once!(),
    loopback_port!(),
    unix_scratch_root!(),
    first_run!(),
    "(3) With the key from (2), `chmod 644 \"$key\"`, then the same command: it must refuse, naming the file, saying group or other permission bits are set (mode 0644), appending `chmod 600` with this file's path, and exit non-zero. ",
    "(4) `chmod 600 \"$key\"`, then the same command again: the same `identity …` line as (2), because the key never changed. ",
    stop_and_clean!(),
);

const MACOS_ACL_HOW: &str = concat!(
    "On a macOS host, where `cargo test -p mahbot-peers-harness` runs the case `key_file_refuses_an_extended_entry` itself; only macOS reads the extended access list this check is about, which a POSIX ACL on another unix is not. ",
    build_once!(),
    loopback_port!(),
    unix_scratch_root!(),
    first_run!(),
    "(3) `chmod +a 'everyone allow read' \"$key\"` and `ls -le \"$key\"` to see the entry; `everyone` is an ACL word of the platform, not a name from its display language. ",
    "Run the same command: it must refuse, naming the file, saying extended access entries allow an account other than the owner and appending `chmod -N` with this file's path. ",
    "(4) `chmod -N \"$key\"`, then the same command again: the same `identity …` line as (2). ",
    stop_and_clean!(),
);

const MACOS_ROOT_HOW: &str = concat!(
    "On a macOS host, where `cargo test -p mahbot-peers-harness` runs the case `key_file_refuses_a_sharing_root` itself. ",
    build_once!(),
    loopback_port!(),
    "(1) A scratch root with no key yet, never the product's own: `root=\"$(mktemp -d)/sharing\"` and `mkdir -p \"$root\"`. ",
    "(2) `chmod +a 'everyone allow read,file_inherit,directory_inherit' \"$root\"` and `ls -led \"$root\"` to see the entry every new file inside it inherits. ",
    "(3) Run `target/debug/mahbot-beacon-server --listen 127.0.0.1:0 --root \"$root\"`: it must refuse, naming that root, saying extended access entries allow an account other than the owner, that no key was written and that the directory is what has to change, and appending `chmod -N` with the root's path; `ls -A \"$root\"` must be empty — no key, not even a temporary. ",
    "(4) `chmod -N \"$root\"`, then the same command again: it prints `identity …`, and `ls -A \"$root\"` now holds exactly `identity.key`. ",
    "Ctrl-C, then `rm -rf \"$(dirname \"$root\")\"`.",
);

const UNIX_OWNER_HOW: &str = concat!(
    "On a unix host with a second account, run the shell as the account that should own the key, not as root: every step that needs root says `sudo`, and the rest run as that account. This suite runs as one unprivileged account and spawns no process, so it never produces a file owned by another. ",
    build_once!(),
    loopback_port!(),
    unix_scratch_root!(),
    first_run!(),
    "(3) `sudo chown nobody \"$key\"` gives the file to a second account (`nobody` resolves on macOS and Linux). ",
    "With that owner, run `sudo target/debug/mahbot-beacon-server --listen 127.0.0.1:0 --root \"$root\"`: root can still open the file, and the loader must refuse it, naming `nobody` with its number and `root` (0) — the account that owns the file and the account that runs the process — appending no command, because the repair is a hand-back to the account the product runs as and is a command for that account rather than for the root-run process that found the file; nothing is written. ",
    "(4) `sudo chown \"$(id -un)\" \"$key\"` gives it back to the account you run as, and the same command without `sudo` prints the same `identity …` line as (2), because the key never changed. ",
    "On Windows the same fact is produced by step (8) of `library.identity.key_file.windows_dacl`. ",
    stop_and_clean!(),
);

const WINDOWS_DACL_HOW: &str = concat!(
    "On a Windows host, in a command prompt of the account the product runs as and with the checkout's root as the working directory; the host needs a C toolchain for `ring` (the MSVC build tools with the Windows SDK, or a MinGW `x86_64-w64-mingw32-gcc`), because `ring` compiles C for its target. ",
    "Every step below changes the key file's access list or owner, so every step is on a scratch root and none may be aimed at the product's own root; a run that prints `identity …` then serves until Ctrl-C, so stop each one with Ctrl-C before the next step. ",
    "(1) `cargo build -p mahbot-beacon-server`, the binary that loads a key through the library's `load_or_create` — the same call a machine uses; it is `target\\debug\\mahbot-beacon-server.exe`. ",
    loopback_port!(),
    "(2) `set root=%TEMP%\\peers-scratch`, `rmdir /s /q \"%root%\" 2>nul` in case an earlier run left it, `mkdir \"%root%\"`, then `set key=%root%\\identity.key` — a fixed name, so every shell this procedure opens can define the same two paths. ",
    "(3) With no key there yet, run `target\\debug\\mahbot-beacon-server.exe --listen 127.0.0.1:0 --root \"%root%\"`: it loads the key before it binds, prints `identity …` and serves until Ctrl-C; `%key%` now exists, 83 bytes. ",
    "`dir /q \"%key%\"` names the account you ran as in the owner column, and `icacls \"%key%\"` lists that account and the two built-in accounts — the ones `S-1-5-18` and `S-1-5-32-544` name, spelled as this machine spells them — with full control and no (I) inherited mark: a protected list written by the create. ",
    "(4) `cargo test -p mahbot-peers-harness` — this harness's first Windows build — runs the rule and every all-host key-file case against the real reader and writer. The rest produces, one at a time, the states no case can: a command creates a state, the next clears it, and the run after the clearing prints the same `identity …` line again. ",
    "(5) With the key from (3), a fourth account: `icacls \"%key%\" /grant \"*S-1-1-0\":R` grants Everyone by its SID, so the command reads the same whatever the display language. ",
    "The same command must refuse, naming that SID's account as this machine spells it (`Everyone` on an English install) and saying that account is neither the owner, SYSTEM nor Administrators. The message appends no command; `identity::access` gives the reason and the repair, and `icacls \"%key%\" /remove:g \"*S-1-1-0\"` removes the entry in that one call, after which the same command prints the same `identity …` line. ",
    "(6) With the key from (3), an absent list, which no `icacls` flag writes: run `powershell` from this command prompt — the child inherits `%key%` as `$env:key` — and in it run ",
    "`$sig = '[DllImport(\"advapi32.dll\", SetLastError=true, CharSet=System.Runtime.InteropServices.CharSet.Unicode)] public static extern uint SetNamedSecurityInfo(string p, int t, uint s, System.IntPtr o, System.IntPtr g, System.IntPtr d, System.IntPtr sa);'`, ",
    "`$adv = Add-Type -MemberDefinition $sig -Name Adv -Namespace Win32 -PassThru`, then ",
    "`[void]$adv::SetNamedSecurityInfo($env:key, 1, 4, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)` — object type 1 is a file, security information 4 is its DACL, and a null DACL is the absent list. ",
    "`exit` returns to this command prompt, where `%key%` is still defined and every remaining command belongs. ",
    "Back in the command prompt, the same server command must refuse, saying the file carries no access list at all, so every account is allowed; `icacls \"%key%\" /reset` gives the default inherited list, then `",
    protected_list!(),
    "` restores a protected one, and the same server command prints `identity …` again. ",
    "(7) With the key from (3), an inherited list: `icacls \"%key%\" /inheritance:e` must make it refuse, saying the list is inherited from the directory and appending `icacls` with this file's path and `/inheritance:r /grant:r \"%USERNAME%\":F`. ",
    "`icacls \"%key%\" /reset` gives the default inherited list and `",
    protected_list!(),
    "` restores a protected list, after which the same command prints `identity …` again. ",
    "(8) With the key from (3), a foreign owner: start an elevated prompt of the same account — not another administrator's, whose `%TEMP%` and `%USERNAME%` would name a different directory and a different account — and in it define the same two paths again, `set root=%TEMP%\\peers-scratch` and `set key=%root%\\identity.key`, then run `icacls \"%key%\" /setowner \"*S-1-5-32-544\"`, which gives the file to Administrators. ",
    "Back in the original command prompt, where `%key%` is still defined, the same server command must refuse, naming `Administrators`, saying it may rewrite the list, and appending `icacls` with this file's path and `/setowner \"%USERNAME%\"`; ",
    "return to the elevated prompt and run `icacls \"%key%\" /setowner \"%USERNAME%\"`, after which the server command in the original prompt prints the same `identity …` line again, because ownership is a fact of its own, read apart from the list. ",
    "Two shapes no step here produces: a file with no owner at all, and an access entry this reader cannot attribute to an account. The rule refuses them as `Unowned` and as an unattributable entry in the case that step (4) runs against both as data. The message for the unowned file appends `icacls` with this file's path and `/setowner \"%USERNAME%\"`; the one for the unattributable entry appends nothing, and the two calls that repair it are the `/reset` and the protected list of steps (6) and (7). ",
    "(9) `rmdir /s /q \"%root%\"`.",
);

/// The claims every host witnesses: the library's and the harness's together.
const CAPABILITIES: &[Capability] = &[
    // The library: identity, the pinned handshake, the transport seam, the
    // beacon.
    Capability::witnessed(
        "library.identity.spki_fingerprint",
        "a generated identity is a 44-byte Ed25519 SubjectPublicKeyInfo, its peer id is the key inside it, and the parser accepts exactly that shape",
    ),
    Capability::witnessed(
        "library.identity.distinct",
        "two generated identities differ in fingerprint and in peer id",
    ),
    Capability::witnessed(
        "library.tls.pinned_handshake",
        "two endpoints that pin each other's fingerprint complete a TLS 1.3 raw-public-key handshake and carry an application datagram",
    ),
    Capability::witnessed(
        "library.tls.untrusted_peer_refused",
        "a peer whose fingerprint is not pinned is refused at the handshake",
    ),
    Capability::witnessed(
        "library.beacon.alpn",
        "the beacon speaks its own ALPN: a client that pins the beacon's key but offers the peer layer's protocol gets no answer",
    ),
    Capability::witnessed(
        "library.beacon.lookup",
        "two clients registered on a fresh beacon find each other by id, each at the address the beacon observes on its path",
    ),
    Capability::witnessed(
        "library.beacon.address",
        "a client learns its own address as observed on the path it uses for peers, a peer reaches it there, and a session on another socket reports that socket instead",
    ),
    Capability::witnessed(
        "library.beacon.state_volatile",
        "a restarted beacon remembers nothing, its old sessions answer nothing, and both clients recover on their next need by registering again",
    ),
    Capability::witnessed(
        "library.beacon.register_identity",
        "a registration is bound to the key the handshake proved: a third party registers only itself, and a frame that asserts an address is refused and changes nothing",
    ),
    Capability::witnessed(
        "library.beacon.register_ttl",
        "a registration is answered for its documented lifetime, forgotten after it, and live again after a refresh",
    ),
    Capability::witnessed(
        "library.beacon.introduction_authenticated",
        "an introduction is signed by its sender over both ids and the payload; a beacon holding the pinned key cannot pass one off under a false sender id or with an altered payload",
    ),
    Capability::witnessed(
        "library.beacon.introduction_live_only",
        "an introduction is delivered only while the addressee is registered: a closed or expired registration collects nothing, and nothing is stored for a later registration to collect",
    ),
    Capability::witnessed(
        "library.beacon.introduction_opaque",
        "the beacon relays an introduction payload byte for byte and remembers none of it: its whole memory is the registrations",
    ),
    Capability::witnessed(
        "library.beacon.wire_closed",
        "the message set is closed: an unknown kind, an answer or a push sent as a request, a wrong body length, a trailing frame and an oversized frame are all refused",
    ),
    Capability::witnessed(
        "library.beacon.wire_version",
        "every frame carries the version: a request under another version is refused with the version named, and a client reading another version reports a mismatch instead of misreading the body",
    ),
    Capability::witnessed(
        "library.beacon.pin",
        "a client pointed at an impostor that does not hold the beacon's pinned key gets no usable answer",
    ),
    Capability::witnessed(
        "library.beacon.auth",
        "an unauthenticated caller gets nothing: a client that presents no key is refused and nothing is registered",
    ),
    Capability::witnessed(
        "library.beacon.address_codec",
        "an observed address round-trips through the wire exactly as it was given, including an IPv6 scope id",
    ),
    Capability::witnessed(
        "library.beacon.session_liveness",
        "a session whose beacon was killed reports the loss within the request bound instead of waiting on a session that looks open, and the next need recovers by connecting and registering again",
    ),
    Capability::witnessed(
        "library.beacon.relay_bounded",
        "a recipient that never reads its pushes cannot stall the sender: the push gives up within the server's bound, the sender's own registration stays served, and the recipient stays registered — a third party cannot use a failed push to evict it",
    ),
    Capability::witnessed(
        "library.beacon.exchange_bounded",
        "a peer that opens a stream and does not finish its frame is answered `Slow` within the server's bound, and the same connection keeps serving complete requests",
    ),
    Capability::witnessed(
        "library.beacon.deadline_ordering",
        "an introduction's three sequential server exchanges fit strictly inside the client's request bound, which fits strictly inside the idle timeout, so a live but slow beacon is not reported as dead",
    ),
    Capability::witnessed(
        "library.beacon.handshake_bounded",
        "a half-open handshake gives its connection slot back within the server's bound instead of holding it until the idle timeout, so a stalled dialer cannot occupy the cap",
    ),
    Capability::witnessed(
        "server.transport_advertisement",
        "the beacon advertises only what it serves: no unidirectional stream and no QUIC datagram, so a peer cannot pin receive window on a channel the server would never drain, and the connection still answers requests",
    ),
    Capability::witnessed(
        "library.net.injected_seams",
        "an endpoint is built over a caller-supplied datagram socket and clock: it reports the socket's address and needs no real socket",
    ),
    Capability::witnessed(
        "library.net.idle_timeout_bounds",
        "an idle timeout that does not fit a QUIC variable integer is refused with a typed error and a readable message",
    ),
    Capability::witnessed(
        "library.net.default_idle_timeout",
        "the default transport carries the documented idle timeout, and a connection built on it stays open until that virtual instant and no longer",
    ),
    Capability::witnessed(
        "library.tls.alpn",
        "both TLS configurations offer exactly the crate's ALPN and nothing else, and a peer offering a different one is refused at the handshake",
    ),
    Capability::witnessed(
        "library.beacon.payload_limit",
        "an introduction is built only through a checked constructor: exactly the documented size is accepted and one byte more is refused as `PayloadTooLarge`, by the client before it sends and by the server if it arrives anyway",
    ),
    Capability::unproducible(
        "library.beacon.check_code",
        "the short check code never passes through the beacon, and the beacon cannot force two machines to compare the same code",
        "the code is derived by the pairing ceremony, which this workspace does not implement, so nothing here produces a code for a case to compare",
        "implement the ceremony and add a case that derives the code from a transcript; what is already proven is what the beacon cannot do — the payload is relayed opaquely (`library.beacon.introduction_opaque`), an alteration is refused (`library.beacon.introduction_authenticated`), and the message set has no field for a code (`library.beacon.wire_closed`)",
    ),
    // The harness: machines, the link, the clock, the beacon rig, the raw
    // client, the connect helper and the checks themselves.
    Capability::witnessed(
        "harness.inventory.procedures_are_runnable",
        "every recorded procedure fills in no `<placeholder>`, quotes no repair that ends in `it`, and one that changes a key file says its root is a scratch one — judged on every host, including the procedures whose capability this host witnesses, and carried by the entry it belongs to, so a procedure cannot name a capability the inventory does not hold",
    ),
    Capability::witnessed(
        "harness.check.inventory_two_way",
        "the inventory check reports an empty inventory, a duplicate entry or case, an entry with no witness, a witness with no entry, a failing case, a panicking case, an entry unproducible without a reason, one without a procedure, one whose procedure has an unfilled placeholder, one whose procedure changes a key file without saying its root is a scratch one, one whose procedure quotes a repair ending in `it`, and a case for an unproducible entry",
    ),
    Capability::witnessed(
        "harness.check.invariant_two_way",
        "the invariant check reports an empty scan, an empty list, an uncaught control, a duplicate id, an out-of-scope invariant and a violated invariant",
    ),
    Capability::witnessed(
        "harness.machine.disjoint_roots_and_identities",
        "two machines in one process have distinct roots, distinct identities and distinct addresses",
    ),
    Capability::witnessed(
        "harness.machine.root_isolation",
        "another machine's root is refused by the storage capability, and a name that tries to leave a root is refused too",
    ),
    Capability::witnessed(
        "harness.machine.independent_disposal",
        "a machine is created and disposed of on its own: dropping one leaves the other working",
    ),
    Capability::witnessed(
        "harness.machine.dead_root_refused",
        "a machine whose simulation is gone refuses to write or read instead of quietly recreating its root",
    ),
    Capability::witnessed(
        "harness.machine.no_path_on_handle",
        "the file holding the machine handle names no filesystem path type",
    ),
    Capability::witnessed(
        "harness.link.address_exclusivity",
        "no two live sockets can share an address: attaching or rebinding onto a taken one is refused and leaves both where they were",
    ),
    Capability::witnessed(
        "harness.link.scripted_faults",
        "drop, delay, reorder, duplicate and reroute are applied from a script and each is recorded in the trace; a dropped datagram releases nothing held, and the next datagram that is sent does",
    ),
    Capability::witnessed(
        "harness.link.seeded_reproducibility",
        "the same seed over the same traffic produces the same trace, and a recorded trace replays to itself",
    ),
    Capability::witnessed(
        "harness.link.address_change",
        "a machine's apparent address can change mid-run, and later datagrams and connections use the new one",
    ),
    Capability::witnessed(
        "harness.clock.monotonic",
        "the clock never moves backwards: a timer armed for an instant already behind it, and an explicit move to the past, both leave the reading where it was",
    ),
    Capability::witnessed(
        "harness.connect.dead_link_times_out",
        "a connection attempt over a link that drops everything ends at a deterministic virtual instant instead of hanging",
    ),
    Capability::witnessed(
        "harness.clock.drives_transport_timers",
        "a quinn idle timeout fires only after the test advances the clock",
    ),
    Capability::unproducible(
        "harness.clock.no_wall_clock_wait",
        "no case in the suite waits on wall time",
        "no single case can prove an absence across the suite, and measuring elapsed wall time inside one would need the clock this harness forbids, and would be flaky besides; the absence is enforced structurally instead — in a default build the harness's tokio has no `time` feature, so a timer sleep does not compile, the runtime it builds has no timer driver, so a sleep that did compile would panic, and the single-source-of-time invariant forbids a thread sleep",
        "read `harness/Cargo.toml` for the absent `time` feature, and run the default suite; a change that adds the feature or a driver fails the review of that file, and a thread sleep anywhere fails `workspace.single_source_of_time`",
    ),
    Capability::witnessed(
        "harness.beacon.in_process_server",
        "the real server runs in-process over the simulated link: it answers while running and answers nothing once stopped",
    ),
    Capability::witnessed(
        "server.config",
        "the command line is read into a listening address and a key directory, `--help` is its own outcome, and an unknown or incomplete argument is refused with the usage",
    ),
    Capability::witnessed(
        "server.connection_cap",
        "a server at its connection limit refuses a further connection instead of accepting it",
    ),
    Capability::witnessed(
        "harness.sim.no_shared_state",
        "two simulations in one process share no clock, no link and no storage",
    ),
    Capability::witnessed(
        "harness.invariant.ambient_forms",
        "the ambient-configuration scanner catches every way the process environment can be read, and leaves look-alikes alone",
    ),
    Capability::witnessed(
        "harness.invariant.global_state_forms",
        "the process-global-state scanner catches a `static` under every visibility, attribute and keyword form, and leaves look-alikes alone",
    ),
    Capability::witnessed(
        "harness.clock.deadline_order",
        "each deadline fires at its own virtual instant, even when a callback queues another for the instant just visited",
    ),
    Capability::witnessed(
        "harness.clock.poll_budget",
        "a case that never parks is stopped by the poll budget and reported, instead of hanging the suite",
    ),
    Capability::witnessed(
        "harness.clock.walk_is_bounded",
        "a callback that keeps scheduling another deadline inside one advance stops the walk with a message instead of crawling through every instant",
    ),
    Capability::witnessed(
        "harness.clock.drive_bounds_await",
        "an await that never resolves is bounded by a virtual budget, so a case waiting on a datagram that never arrives fails instead of hanging",
    ),
    Capability::witnessed(
        "harness.connect.concurrent_dialers",
        "two machines dialing one machine at once each receive the connection they dialed, not the other's",
    ),
    Capability::witnessed(
        "harness.connect.retry_after_abandoned",
        "an attempt abandoned mid-handshake leaves nothing behind: the next attempt on the same pair refuses the aborted connection and completes",
    ),
    Capability::witnessed(
        "harness.connect.retry_after_timeout",
        "an attempt that timed out can be retried on the same pair at once: the retry is a working connection, and the server keeps at most one filed connection per dialer",
    ),
    Capability::witnessed(
        "harness.connect.custom_endpoint",
        "an endpoint the caller built serves one attempt: a closed endpoint is reported as closed instead of timing out",
    ),
    Capability::witnessed(
        "harness.link.oversized_datagram_dropped",
        "a datagram larger than the receiver's buffer is dropped rather than delivered truncated",
    ),
    // The key file: one identity per root, created once, readable only by the
    // accounts the rule allows, and never replaced.
    Capability::witnessed(
        "library.identity.key_file.one_identity_per_root",
        "one root is one identity: two loads agree, a copy of the root gives the same identity back, and deleting the key file is the only way to become a new machine",
    ),
    Capability::witnessed(
        "library.identity.key_file.created_once",
        "two creators racing on one root end with one identity, the key is published atomically so no reader ever observes a partial file, and the root is left holding nothing but the key — a crash between writing and publishing can leave only a `.identity.key.*` temporary, holding the same private half under the access the key file was about to be given",
    ),
    Capability::witnessed(
        "library.identity.key_file.malformed",
        "a zero-length key file, a real PKCS#8 v1 key of the older 48-byte form and a file that is not a key at all are refused as malformed, and no new key is written in their place",
    ),
    Capability::witnessed(
        "library.identity.access.unix_rule",
        "the unix rule refuses group and other bits before ownership, accepts owner-only modes including read-only, refuses another owner as ownership, and reports the more useful of the two facts when both hold; the mode refusal, the two shapes both readers refuse — a symbolic link and a non-regular file — and the storage root's unix clauses print the documented wording on every host",
    ),
    Capability::witnessed(
        "library.identity.access.extended_rule",
        "the extended-access-list rule accepts a deny entry and an allow entry naming the owner, and refuses any other allow entry",
    ),
    Capability::witnessed(
        "library.identity.access.dacl_rule",
        "the Windows rule accepts a protected list whose entries name at most the owner, SYSTEM and Administrators, refuses an inherited list, an absent one, an allowed fourth account and an entry it cannot attribute to an account as access-list problems, refuses as a foreign owner — naming the account — any file whose owner is not the account the product runs as, and refuses a file with no owner at all without inventing one; a storage root's clauses for the account a new file belongs to and for a new file with no owner print the documented wording with no command appended",
    ),
    Capability::witnessed(
        "library.identity.one_rendering",
        "an identity has one rendering — the 88 lowercase hex characters of the 44 pinned bytes — which reads back to the same bytes, and a peer id renders as that same string",
    ),
    Capability::unproducible(
        "library.identity.key_file.foreign_owner",
        "on unix, a key file owned by another account is refused with that account and this one named by login name and number (the number alone when the platform has no name for it); on Windows the refusal names the owning account and the repair hands the file back to `%USERNAME%` — the account the product runs as",
        "the case needs a file owned by a second account, and the suite runs as one unprivileged account that spawns no processes; the decision itself is witnessed as data (`library.identity.access.unix_rule`), and the wording that names the two accounts is pinned in `library.identity.access.unix_account_names`. On Windows the same fact is pinned by `library.identity.access.dacl_rule` (`windows_dacl_rule_is_exact`): the refusal names the owning account, and the command hands the file to `%USERNAME%`",
        UNIX_OWNER_HOW,
    ),
    Capability::unproducible(
        "library.identity.key_file.windows_dacl",
        "on Windows a key file whose DACL is inherited, absent, names an account outside the owner, SYSTEM and Administrators, or carries an entry this reader cannot attribute to an account — or whose owner is not the account the product runs as, or is absent — is refused, and a new key file is written with a protected DACL and this process's account as owner",
        "no case produces a refusing access-list state: an inherited list, an absent list and an allowed fourth account each needs an access-list edit, a foreign owner needs another account or a privileged write, and this suite spawns no process and holds one account. Two shapes the procedure cannot show being produced — a file with no owner and an entry this reader cannot attribute — are named as unproducible beside the rule that decides them. The rule those states feed is witnessed on every host as data (`library.identity.access.dacl_rule`), and the writer and reader are exercised by the all-host key-file cases wherever the harness runs: `load_or_create` writes the protected list, sets the owner and reads both back before a key byte is written. The Windows reader and writer are type-checked for both Windows targets by `windows-check`, which any host builds; the first run of this harness on Windows is the operator's, and its output is not recorded here",
        WINDOWS_DACL_HOW,
    ),
    Capability::witnessed(
        "library.tls.own_identity_refused",
        "a peer that presents this machine's own key is refused at the handshake, with a reason distinguishable from the one an untrusted peer gets",
    ),
    Capability::witnessed(
        "library.tls.pinned_value",
        "the 44 bytes the handshake pins on each side are the peer's fingerprint and what the trusting policy was asked about, and they read back from the 88 characters a human is shown",
    ),
    Capability::witnessed(
        "harness.invariant.no_key_rotation",
        "the three source-scan invariants that forbid replacing, renaming or re-minting a key are in the table; the replacement claim judges every shipped source for a renamed or copied path and a removed directory, and the identity module for single-file writes; the name claim judges every shipped source, the mint claim the whole tree; and the name the crate writes is the name the scan looks for",
    ),
];

// The host-independent part of the inventory, which the platform tables add to. This
// is the floor that keeps a shrinking list from looking like a pass.
const _: () = assert!(
    CAPABILITIES.len() >= 72,
    "the shared capability inventory shrank"
);

/// The first `<placeholder>` in a procedure.
///
/// A record is for an operator, who can fill nothing in: a path or an account left
/// as `<root>` is one the reader has to guess, and the guess can be the live storage
/// root. The shape is narrow — a short run of name characters between angle
/// brackets — so ordinary prose is not caught.
fn placeholder(text: &'static str) -> Option<&'static str> {
    fn name_like(inner: &str) -> bool {
        !inner.is_empty()
            && inner.len() <= 24
            && inner.chars().all(|character| {
                character.is_ascii_alphanumeric() || " _-./\\:".contains(character)
            })
    }
    for (start, _) in text.match_indices('<') {
        let rest = &text[start + 1..];
        let Some(end) = rest.find('>') else {
            break;
        };
        if name_like(&rest[..end]) {
            return Some(&text[start..=start + 1 + end]);
        }
    }
    None
}

/// Whether a procedure quotes a repair that names no file.
///
/// The runtime message carries the path, so a quoted `chmod 600 it` is both stale and
/// unrunnable; only a code span that holds one of the tools is judged, so prose that
/// says "run it" is left alone.
fn quotes_a_pathless_command(how: &str) -> bool {
    how.split('`').skip(1).step_by(2).any(|span| {
        (span.contains("chmod") || span.contains("icacls")) && span.trim_end().ends_with(" it")
    })
}

/// Whether a procedure changes a key file, by the commands that would.
///
/// Such a record must also say that its root is a scratch one: aimed at the root an
/// installation uses, `chmod 644` on the key leaves that machine unable to load it.
fn changes_a_key_file(how: &str) -> bool {
    ["identity.key", "chmod", "chown", "icacls"]
        .iter()
        .any(|needle| how.contains(needle))
}

/// The rules that judge a recorded procedure, whatever host reads it.
///
/// A case runs them over every recorded procedure, not only the ones this host cannot
/// produce: the check itself only sees the entries unproducible here, and a stale
/// procedure for the host that produces its case would otherwise go unread.
#[must_use]
pub(crate) fn procedure_violations(capability: &'static str, how: &'static str) -> Vec<Violation> {
    let mut violations = Vec::new();
    if let Some(placeholder) = placeholder(how) {
        violations.push(Violation::Placeholder {
            capability,
            placeholder,
        });
    }
    if changes_a_key_file(how) && !how.to_ascii_lowercase().contains("scratch root") {
        violations.push(Violation::NotOnScratchRoot { capability });
    }
    if quotes_a_pathless_command(how) {
        violations.push(Violation::PathlessCommand { capability });
    }
    violations
}

/// Check the inventory against the witness table, then run every witness whose
/// capability exists. Both directions are checked: an entry with no witness and
/// a witness with no entry are each a violation.
#[must_use]
pub fn check(inventory: &[Capability], witnesses: &[Witness]) -> Report {
    let mut report = Report::new(
        ("capabilities", inventory.len()),
        ("witnesses", witnesses.len()),
    );

    if inventory.is_empty() {
        report.violations.push(Violation::NoCapabilities);
    }
    for (index, capability) in inventory.iter().enumerate() {
        if inventory[..index]
            .iter()
            .any(|earlier| earlier.id == capability.id)
        {
            report
                .violations
                .push(Violation::DuplicateCapability(capability.id));
        }
        if let Some(why) = capability.unproducible {
            if why.trim().is_empty() {
                report.violations.push(Violation::NoReason {
                    capability: capability.id,
                });
            }
            match capability.procedure {
                Some(how) if !how.trim().is_empty() => {
                    report
                        .violations
                        .extend(procedure_violations(capability.id, how));
                }
                _ => report.violations.push(Violation::NoProcedure {
                    capability: capability.id,
                }),
            }
        }
        let has_case = witnesses
            .iter()
            .any(|witness| witness.capability == capability.id);
        if capability.unproducible.is_none() && !has_case {
            report.violations.push(Violation::Unwitnessed {
                capability: capability.id,
            });
        }
    }

    for (index, witness) in witnesses.iter().enumerate() {
        if witnesses[..index]
            .iter()
            .any(|earlier| earlier.id == witness.id)
        {
            report
                .violations
                .push(Violation::DuplicateWitness(witness.id));
        }
        let Some(capability) = inventory
            .iter()
            .find(|capability| capability.id == witness.capability)
        else {
            report.violations.push(Violation::OrphanWitness {
                witness: witness.id,
                capability: witness.capability,
            });
            continue;
        };
        if capability.unproducible.is_some() {
            report.violations.push(Violation::WitnessForUnproducible {
                witness: witness.id,
                capability: witness.capability,
            });
            continue;
        }
        match std::panic::catch_unwind(witness.case) {
            Ok(Ok(())) => {}
            Ok(Err(detail)) => report.violations.push(Violation::Failed {
                witness: witness.id,
                capability: witness.capability,
                detail,
            }),
            Err(payload) => report.violations.push(Violation::Panicked {
                witness: witness.id,
                capability: witness.capability,
                detail: crate::report::panic_message(payload.as_ref()),
            }),
        }
    }

    report
}
