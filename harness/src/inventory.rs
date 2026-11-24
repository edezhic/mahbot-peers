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

/// A recorded case that witnesses one capability, or two when one case carries two
/// claims. The case runs once, whatever the number.
#[derive(Clone, Copy)]
pub struct Witness {
    /// Stable id, unique across the table; this is the "recorded case".
    pub id: &'static str,
    /// The capability ids this case speaks for.
    pub capabilities: &'static [&'static str],
    /// The case itself. It returns `Err` with the reason it failed.
    pub case: fn() -> Result<(), String>,
}

impl fmt::Debug for Witness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Witness")
            .field("id", &self.id)
            .field("capabilities", &self.capabilities)
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
    let peer_record_insecure = if cfg!(unix) {
        Capability::witnessed(
            "library.peer.record.insecure_file",
            PEER_RECORD_INSECURE_CLAIM,
        )
        .with_procedure(PEER_RECORD_INSECURE_HOW)
    } else {
        Capability::unproducible(
            "library.peer.record.insecure_file",
            PEER_RECORD_INSECURE_CLAIM,
            "the case sets a unix mode on the record file: this host has no mode bits, and the access-list state it would need instead has its own entry (`library.peer.record.windows_dacl`)",
            PEER_RECORD_INSECURE_HOW,
        )
    };
    let peer_record_insecure_dir = if cfg!(unix) {
        Capability::witnessed(
            "library.peer.record.insecure_directory",
            PEER_RECORD_INSECURE_DIR_CLAIM,
        )
        .with_procedure(PEER_RECORD_INSECURE_DIR_HOW)
    } else {
        Capability::unproducible(
            "library.peer.record.insecure_directory",
            PEER_RECORD_INSECURE_DIR_CLAIM,
            "the case sets a unix mode on the records directory: this host has no mode bits, and the access-list state it would need instead has its own entry (`library.peer.record.windows_dacl`)",
            PEER_RECORD_INSECURE_DIR_HOW,
        )
    };
    let peer_record_private_dir = if cfg!(unix) {
        Capability::witnessed(
            "library.peer.record.private_directory",
            PEER_RECORD_PRIVATE_DIR_CLAIM,
        )
        .with_procedure(PEER_RECORD_PRIVATE_DIR_HOW)
    } else {
        Capability::unproducible(
            "library.peer.record.private_directory",
            PEER_RECORD_PRIVATE_DIR_CLAIM,
            "the case reads the created directory's unix mode: this host has no mode bits, and the access list a created directory is given instead is covered by `library.peer.record.windows_dacl`",
            PEER_RECORD_PRIVATE_DIR_HOW,
        )
    };
    let peer_record_read_only = if cfg!(unix) {
        Capability::witnessed(
            "library.peer.record.opens_read_only",
            PEER_RECORD_READ_ONLY_CLAIM,
        )
        .with_procedure(PEER_RECORD_READ_ONLY_HOW)
    } else {
        Capability::unproducible(
            "library.peer.record.opens_read_only",
            PEER_RECORD_READ_ONLY_CLAIM,
            "the case makes the records directory read-only with a unix mode: this host has no mode bits, and the access list it would need instead is not built by any case here",
            PEER_RECORD_READ_ONLY_HOW,
        )
    };
    let peer_record_symlink = if cfg!(unix) {
        Capability::witnessed(
            "library.peer.record.symlinked_directory",
            PEER_RECORD_SYMLINK_CLAIM,
        )
        .with_procedure(PEER_RECORD_SYMLINK_HOW)
    } else {
        Capability::unproducible(
            "library.peer.record.symlinked_directory",
            PEER_RECORD_SYMLINK_CLAIM,
            "the case replaces `peers/` with a symbolic link: this host has no unix links, and the access-list state it would need instead has its own entry (`library.peer.record.windows_dacl`)",
            PEER_RECORD_SYMLINK_HOW,
        )
    };
    let audit_before_effect = if cfg!(unix) {
        Capability::witnessed(
            "library.peer.audit.before_effect",
            AUDIT_BEFORE_EFFECT_CLAIM,
        )
        .with_procedure(AUDIT_BEFORE_EFFECT_HOW)
    } else {
        Capability::unproducible(
            "library.peer.audit.before_effect",
            AUDIT_BEFORE_EFFECT_CLAIM,
            "the case makes the record write fail by closing a directory to writes with a unix mode: this host has no mode bits, and the access-list state it would need instead has its own entry (`library.peer.record.windows_dacl`)",
            AUDIT_BEFORE_EFFECT_HOW,
        )
    };
    let audit_private = if cfg!(unix) {
        Capability::witnessed("library.peer.audit.private", AUDIT_PRIVATE_CLAIM)
            .with_procedure(AUDIT_PRIVATE_HOW)
    } else {
        Capability::unproducible(
            "library.peer.audit.private",
            AUDIT_PRIVATE_CLAIM,
            "the case sets a unix mode on the log: this host has no mode bits, and the access-list state it would need instead has its own entry (`library.peer.audit.windows_dacl`)",
            AUDIT_PRIVATE_HOW,
        )
    };
    let audit_private_on_write = if cfg!(unix) {
        Capability::witnessed(
            "library.peer.audit.private_on_write",
            AUDIT_PRIVATE_ON_WRITE_CLAIM,
        )
        .with_procedure(AUDIT_PRIVATE_ON_WRITE_HOW)
    } else {
        Capability::unproducible(
            "library.peer.audit.private_on_write",
            AUDIT_PRIVATE_ON_WRITE_CLAIM,
            "the case sets a unix mode on the log between two appends: this host has no mode bits, and the access-list state it would need instead has its own entry (`library.peer.audit.windows_dacl`)",
            AUDIT_PRIVATE_ON_WRITE_HOW,
        )
    };
    let unreadable_record = if cfg!(unix) {
        Capability::witnessed(
            "library.peer.connect.unreadable_record",
            UNREADABLE_RECORD_CLAIM,
        )
        .with_procedure(UNREADABLE_RECORD_HOW)
    } else {
        Capability::unproducible(
            "library.peer.connect.unreadable_record",
            UNREADABLE_RECORD_CLAIM,
            "the case makes a record unreadable by loosening its unix mode: this host has no mode bits, and the access-list state it would need instead has its own entry (`library.peer.record.windows_dacl`)",
            UNREADABLE_RECORD_HOW,
        )
    };
    let messages_private = if cfg!(unix) {
        Capability::witnessed("library.peer.messages.private", MESSAGES_PRIVATE_CLAIM)
            .with_procedure(MESSAGES_PRIVATE_HOW)
    } else {
        Capability::unproducible(
            "library.peer.messages.private",
            MESSAGES_PRIVATE_CLAIM,
            "the case sets a unix mode on the messages directory and on one queue file: this host has no mode bits, and the access-list state it would need instead is the one `library.peer.record.windows_dacl` records, which no case builds here",
            MESSAGES_PRIVATE_HOW,
        )
    };
    let actions_private = if cfg!(unix) {
        Capability::witnessed("library.peer.actions.private", ACTIONS_PRIVATE_CLAIM)
            .with_procedure(ACTIONS_PRIVATE_HOW)
    } else {
        Capability::unproducible(
            "library.peer.actions.private",
            ACTIONS_PRIVATE_CLAIM,
            "the case sets a unix mode on the actions directory and on one action memory: this host has no mode bits, and the access-list state it would need instead is the one `library.peer.record.windows_dacl` records, which no case builds here",
            ACTIONS_PRIVATE_HOW,
        )
    };
    let actions_untraced = if cfg!(unix) {
        Capability::witnessed("library.peer.actions.untraced", ACTIONS_UNTRACED_CLAIM)
            .with_procedure(ACTIONS_UNTRACED_HOW)
    } else {
        Capability::unproducible(
            "library.peer.actions.untraced",
            ACTIONS_UNTRACED_CLAIM,
            "the case makes the actions directory readable but not writable with a unix mode: this host has no mode bits, and the access-list state it would need instead is the one `library.peer.record.windows_dacl` records, which no case builds here",
            ACTIONS_UNTRACED_HOW,
        )
    };
    vec![
        insecure_file,
        extended_acl,
        root_access_list,
        unix_names,
        peer_record_insecure,
        peer_record_insecure_dir,
        audit_before_effect,
        audit_private,
        audit_private_on_write,
        unreadable_record,
        peer_record_private_dir,
        peer_record_read_only,
        peer_record_symlink,
        messages_private,
        actions_private,
        actions_untraced,
        record_fault(
            "library.peer.connect.transient_record",
            TRANSIENT_RECORD_CLAIM,
            TRANSIENT_RECORD_HOW,
        ),
        record_fault(
            "library.peer.connect.transient_record_live",
            TRANSIENT_RECORD_LIVE_CLAIM,
            TRANSIENT_RECORD_LIVE_HOW,
        ),
        record_fault(
            "library.peer.actions.deferred_record",
            DEFERRED_RECORD_CLAIM,
            DEFERRED_RECORD_HOW,
        ),
    ]
}

/// The three entries the record fault speaks for, on this host.
///
/// The fault is an operating-system refusal of a record's path, and a unix host is the one this
/// suite can produce it on; [`RECORD_FAULT_WHY`] states why the same cannot be claimed elsewhere.
fn record_fault(id: &'static str, claim: &'static str, how: &'static str) -> Capability {
    if cfg!(unix) {
        Capability::witnessed(id, claim).with_procedure(how)
    } else {
        Capability::unproducible(id, claim, RECORD_FAULT_WHY, how)
    }
}

/// The claim about a peer record reachable by another account.
const PEER_RECORD_INSECURE_CLAIM: &str = "a peer record whose mode lets group or other read it is refused as insecure, distinct from unreadable and from malformed, and never becomes trust";

/// What a host that can produce [`PEER_RECORD_INSECURE_CLAIM`] does: the mode is
/// unix's, so a unix host runs the case and the procedure only records it.
const PEER_RECORD_INSECURE_HOW: &str = "In a scratch root, run the case `peer_record_refuses_other_readers` (`cargo test -p mahbot-peers-harness` on a unix host runs it): it writes one record, `chmod 644` on that record file in the scratch root, and opens the store again, which refuses with `is not private`. `chmod 600` on the same file in the same scratch root makes the same store open and the pairing readable.";

/// The claim about the records directory itself being writable by another account.
const PEER_RECORD_INSECURE_DIR_CLAIM: &str = "a peer-record directory whose mode lets group or other write it is refused as insecure, distinct from unreadable and from malformed, and never becomes trust";

/// The claim about the directory this crate creates for its records.
const PEER_RECORD_PRIVATE_DIR_CLAIM: &str = "the `peers/` directory the store creates is private before it is read — owner read, write and search and nothing else";

/// What a host that can produce [`PEER_RECORD_PRIVATE_DIR_CLAIM`] does.
const PEER_RECORD_PRIVATE_DIR_HOW: &str = "In a scratch root, run the case `peer_record_creates_a_private_directory` (`cargo test -p mahbot-peers-harness` on a unix host runs it): it opens the store on an empty root, which creates `peers/`, and reads the directory's mode — it is 0700.";

/// The claim about opening a records directory its owner cannot write.
const PEER_RECORD_READ_ONLY_CLAIM: &str = "opening the store writes nothing, so a records directory its owner can read and search but not write still opens and reads the records it holds";

/// What a host that can produce [`PEER_RECORD_READ_ONLY_CLAIM`] does.
const PEER_RECORD_READ_ONLY_HOW: &str = "In a scratch root, run the case `peer_record_opens_a_read_only_directory` (`cargo test -p mahbot-peers-harness` on a unix host runs it): it opens the store once to create `peers/`, writes a record, `chmod 500` on the directory and opens the store again, which succeeds and reads the same record.";

/// The claim about the records directory being a symbolic link.
const PEER_RECORD_SYMLINK_CLAIM: &str = "a `peers/` directory that is a symbolic link is refused as insecure, as a linked key file is, so records cannot be made to land outside the root";

/// What a host that can produce [`PEER_RECORD_INSECURE_DIR_CLAIM`] does.
const PEER_RECORD_INSECURE_DIR_HOW: &str = "In a scratch root, run the case `peer_record_refuses_other_writers` (`cargo test -p mahbot-peers-harness` on a unix host runs it): it writes one record, `chmod 777` on the `peers/` directory in the scratch root, and opens the store again, which refuses with `is not private`. `chmod 700` on the same directory makes the same store open and the pairing readable.";

/// What a host that can produce [`PEER_RECORD_SYMLINK_CLAIM`] does.
const PEER_RECORD_SYMLINK_HOW: &str = "In a scratch root, run the case `peer_record_refuses_a_symlinked_directory` (`cargo test -p mahbot-peers-harness` on a unix host runs it): it writes one record, renames `peers/` aside and puts a symbolic link in its place, then opens the store again, which refuses with `it is a symbolic link, which is never followed`. Replacing the link with the real directory makes the same store open and the pairing readable.";

/// The claim about a unix file's mode, ownership and links, the same on every host:
/// only whether this host can produce the file states differs. Foreign ownership is
/// not part of it: that file state needs a second account and is its own entry.
const INSECURE_FILE_CLAIM: &str = "a key file that group or other permission bits reach, a symbolic link in its place, a directory in its place and a link a key would be written through are each refused and left byte for byte as they were, while an owner-only mode, including a read-only one, is accepted";

/// The claim about a macOS extended access list on an existing key file, the same
/// on every host.
const EXTENDED_ACL_CLAIM: &str = "the macOS reader refuses a 0600 key file that carries an extended access entry allowing an account other than its owner, and accepts a deny entry and the owner's own entry";

/// The claim about a storage root whose access list a new key file inherits.
const ROOT_ACCESS_LIST_CLAIM: &str = "a storage root whose access list a new key file inherits is refused before a key is minted, with the root named and nothing left behind, and clearing that list gives the root an identity";

/// The claim about the order of an act's two writes.
const AUDIT_BEFORE_EFFECT_CLAIM: &str = "a grant is appended to the log before the record changes, so a record write that fails leaves the act recorded and the right unwritten, never the reverse";

/// What a host that can produce [`AUDIT_BEFORE_EFFECT_CLAIM`] does.
const AUDIT_BEFORE_EFFECT_HOW: &str = "In a scratch root, run the case `the_audit_is_written_before_the_record_changes` (`cargo test -p mahbot-peers-harness` on a unix host runs it): it closes the record's directory to writes with `chmod 555`, grants a right, sees the record write fail, and reads the log — the grant is there and the right is not; `chmod 700` on the same directory restores it.";

/// The claim about an audit log another account can read.
const AUDIT_PRIVATE_CLAIM: &str = "an audit log whose mode lets group or other read it is refused as insecure, with a message naming the file, and never trusted";

/// What a host that can produce [`AUDIT_PRIVATE_CLAIM`] does.
const AUDIT_PRIVATE_HOW: &str = "In a scratch root, run the case `the_audit_is_private_to_the_account` (`cargo test -p mahbot-peers-harness` on a unix host runs it): it writes one entry, `chmod 644` on `audit.log` in the scratch root, and opens the log again, which refuses with `is not private`. `chmod 600` on the same file in the same scratch root makes the same log open and the entry readable.";

/// The claim about the audit's privacy being re-checked on every append.
const AUDIT_PRIVATE_ON_WRITE_CLAIM: &str = "the audit log re-checks its privacy on every append, on the descriptor it writes through, so a log another account can read refuses the next append naming the file, and restoring its owner-only mode lets the one after it land";

/// What a host that can produce [`AUDIT_PRIVATE_ON_WRITE_CLAIM`] does.
const AUDIT_PRIVATE_ON_WRITE_HOW: &str = "In a scratch root, run the case `the_audit_rechecks_privacy_on_every_append` (`cargo test -p mahbot-peers-harness` on a unix host runs it): it opens the log and appends one entry, `chmod 644` on `audit.log` in the scratch root, and appends again, which refuses with `is not private` and names the file. `chmod 600` on the same file in the same scratch root makes the next append land and the entry readable.";

/// The claim about a record that is there and cannot be read.
const UNREADABLE_RECORD_CLAIM: &str = "a peer record that is present and cannot be read is refused as its own cause, naming the file, and is never reported as a machine this one never paired; the handshake fails closed over it too";

/// The claim about a message queue and its directory being private to the account.
const MESSAGES_PRIVATE_CLAIM: &str = "a message file and its directory are private to the account the product runs as: a directory another account can write, a linked directory and a queue another account can read are each refused with the file named, and restoring the owner-only mode reads the same queue";

/// What a host that can produce [`MESSAGES_PRIVATE_CLAIM`] does: the mode is unix's, so a
/// unix host runs the case and the procedure only records it.
const MESSAGES_PRIVATE_HOW: &str = "In a scratch root, run the case `a_message_file_is_private_to_the_account` (`cargo test -p mahbot-peers-harness` on a unix host runs it): it opens the message layer on an empty root, which creates `messages/` mode 0700, and queues one message; `chmod 777` on the `messages/` directory in the scratch root makes the next open refuse with `is not private`, and `chmod 700` on the same directory opens it again; `chmod 644` on the queue file makes `pending` refuse with `is not private`, and `chmod 600` on the same file reads the queue.";

/// The claim about an action memory and its directory.
const ACTIONS_PRIVATE_CLAIM: &str = "an action memory and its directory are private to the account the product runs as: a directory another account can write, a linked directory and a memory another account can read are each refused with the file named, and restoring the owner-only mode reads the same memory";

/// What a host that can produce [`ACTIONS_PRIVATE_CLAIM`] does: the mode is unix's, so a
/// unix host runs the case and the procedure only records it.
const ACTIONS_PRIVATE_HOW: &str = "In a scratch root, run the case `an_action_file_is_private_to_the_account` (`cargo test -p mahbot-peers-harness` on a unix host runs it): it opens the action layer on an empty root, which creates `actions/` mode 0700, and records one identifier; `chmod 777` on the `actions/` directory in the scratch root makes the next open refuse with `is not private`, and `chmod 700` on the same directory opens it again; `chmod 644` on the memory file makes `unknown` refuse with `is not private`, and `chmod 600` on the same file reads it.";

/// The claim about an unknown trace that cannot be kept.
const ACTIONS_UNTRACED_CLAIM: &str = "an unknown outcome whose trace cannot be kept answers a fault that names both the outcome and the storage refusal, and the receiver's journal still answers a repeat as already executed";

/// What a host that can produce [`ACTIONS_UNTRACED_CLAIM`] does.
const ACTIONS_UNTRACED_HOW: &str = "In a scratch root, run the case `an_untraceable_unknown_names_both_outcomes` (`cargo test -p mahbot-peers-harness` on a unix host runs it): it pairs two machines, holds the receiving machine's execution past `EXECUTION_BUDGET`, makes the sender's `actions/` directory readable but not writable with `chmod 500`, and asks one action; the call answers a fault naming both outcomes, and `chmod 700` on the same directory lets a repeat be answered as already executed.";

/// What a host that can produce [`UNREADABLE_RECORD_CLAIM`] does.
const UNREADABLE_RECORD_HOW: &str = "In a scratch root, run the case `an_unreadable_record_is_not_an_unpaired_machine` (`cargo test -p mahbot-peers-harness` on a unix host runs it): it pairs two machines, `chmod 644` on the peer's record file in the scratch root, and dials, which refuses with `not trusted: its record cannot be read` and names the record. `chmod 600` on the same file in the same scratch root makes the same dial connect.";

/// The claim about a record fault the operating system refused just now.
const TRANSIENT_RECORD_CLAIM: &str = "a record read the operating system refused — an I/O fault, not a refusal of the file — defers the dial instead of ending the pair: the keeper keeps running, the state names the record, the dial is not counted against the peer; and a pair whose last dial met a network failure keeps that reason through the fault, in the state and in the answer, whether the caller asked the policy for one dial or dialled once";

/// The claim about the same fault while a connection is up.
const TRANSIENT_RECORD_LIVE_CLAIM: &str = "a record read the operating system refused while a connection is up is a deferral and not a refusal: the dial a caller asks for is answered `ConnectFailure::Deferred` naming the record, the keeper's own rounds defer too rather than stopping the pair, so the connection stays the one the pair holds and still carries while the fault lasts, and it is still there and still carrying once the record is readable again";

/// The claim about the same fault on a person's action.
const DEFERRED_RECORD_CLAIM: &str = "a record read the operating system refused defers an action's dial instead of failing it: the ask waits a round and reads the record again rather than answering at once, a fault that clears while the ask is still reading — inside the budget less one dial — still reaches the dial, with the link showing the ask's own dial once the record is readable and no record or trust failure reported, a fault still unread when the budget's last dial-length begins is answered as `ConnectFailure::Deferred` naming the record and not as a trust decision, with the pair not stopped by it, and over a pair whose last dial met a network failure the same fault is answered with that reason instead of the deferral";

/// Why the three record-fault cases cannot be produced on every host.
const RECORD_FAULT_WHY: &str = "the case produces the fault by putting a regular file where the records directory belongs. A unix host answers a record read through it as an I/O fault. Whether a Windows host does the same is unverified: this workspace has no Windows host, and the reader answers only a missing path as \"no record\", so a host that reports this path as one that does not resolve would see a refusal instead of the deferral. A directory at a record's own path is not this fault and cannot stand in for it: the reader refuses a non-regular file as insecure before it reads a byte, on every platform, and that is a refusal rather than a deferral. The fault cannot be arranged on such a host without an access-list edit, and this suite builds none. The Windows reader and writer are type-checked for both Windows targets by `windows-check`, which any host builds";

/// What a host that can produce [`TRANSIENT_RECORD_CLAIM`] does.
const TRANSIENT_RECORD_HOW: &str = "In a scratch root, run the case `a_transient_record_fault_defers_the_dial` (`cargo test -p mahbot-peers-harness` on a unix host runs it): it pairs two machines, replaces the `peers` directory of one machine's scratch root with a regular file, and dials — the answer is `ConnectFailure::Deferred` naming the record, the keeper keeps running, the dial count does not advance, and the directory is put back when the case ends. Nothing in the scratch root is kept.";

/// What a host that can produce [`TRANSIENT_RECORD_LIVE_CLAIM`] does.
const TRANSIENT_RECORD_LIVE_HOW: &str = "In a scratch root, run the case `a_transient_record_fault_keeps_the_connection`: it pairs two machines, connects them, replaces the `peers` directory of one machine's scratch root with a regular file, and asks for a dial — the answer is `ConnectFailure::Deferred` naming the record, the pair keeps the connection it holds and still carries on it, no stop is written, and once the directory is back the same connection still carries. Nothing in the scratch root is kept.";

/// What a host that can produce [`DEFERRED_RECORD_CLAIM`] does.
const DEFERRED_RECORD_HOW: &str = "In a scratch root, run the case `a_transient_record_fault_defers_an_action`: it pairs two machines and replaces the laptop's `peers` directory with a regular file — an ask whose record fault is still unread when the budget's last dial-length begins is answered `ActionError::Connect` with `ConnectFailure::Deferred` naming the record and does not stop the pair; when the directory is put back while a second ask waits, the ask reads trust again and the link shows its own dial; and after a dial that met a silent peer, the fault is answered with that failure rather than the deferral. Nothing in the scratch root is kept.";

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
        "a transport carries the documented idle timeout, and a connection built on it with no keep-alive stays open until that virtual instant and no longer",
    ),
    Capability::witnessed(
        "library.net.keep_alive",
        "a transport with a keep-alive shorter than its idle timeout keeps a quiet connection open past the instant the timeout would otherwise close it",
    ),
    Capability::witnessed(
        "library.net.quiet_pair_default",
        "the default transport carries a keep-alive, so a quiet pair with nothing to carry stays connected for twice the idle timeout, and a datagram crosses the connection that survived",
    ),
    Capability::witnessed(
        "library.tls.alpn",
        "both TLS configurations offer exactly the crate's ALPN and nothing else, and a peer offering a different one is refused at the handshake",
    ),
    Capability::witnessed(
        "library.beacon.payload_limit",
        "an introduction is built only through a checked constructor: exactly the documented size is accepted and one byte more is refused as `PayloadTooLarge`, by the client before it sends and by the server if it arrives anyway",
    ),
    // The peer layer: the durable record, the ceremony and the manager.
    Capability::witnessed(
        "library.peer.record.root_required",
        "opening the store refuses a missing storage root with a typed error naming it, and creates neither the root nor its parents: a mistyped or deleted root cannot pass for a machine that knows nobody",
    ),
    Capability::witnessed(
        "library.peer.record.drops_expired_attempts",
        "dropping expired attempts removes a record left holding nothing and keeps a pairing and a failure count, while an attempt that has not expired — including one another process restarted after the load, because the prune re-reads the file and checks the expiry again — survives the drop and an open of the store, and one record that cannot be read does not stop the sweep: the rest are still pruned and the refusal names the file",
    ),
    Capability::witnessed(
        "library.peer.record.round_trip",
        "a peer record is written beside the identity, read back by a second open of the same root with its key, pairing moment, address and failure count intact, an IPv4 address and both an IPv6 address and a link-local one with its scope and flow info survive, and the fingerprint is derived from the stored key rather than stored beside it",
    ),
    Capability::witnessed(
        "library.peer.record.malformed",
        "an empty file, a foreign magic, version zero and a body with no key are each refused as `Malformed`, distinct from an unreadable file and from an insecure one, none is read as a record, and the refusal names the file so a person can act on it",
    ),
    Capability::witnessed(
        "library.peer.record.additive",
        "a record of a higher version with a field this build does not know is read, keeps its pairing, and has the unknown field written back by a later write, so a format change never un-pairs a machine",
    ),
    Capability::witnessed(
        "library.peer.record.never_unpairs",
        "a later write of the address or a failure never removes the pairing or re-dates it, and the store keeps trusting the peer",
    ),
    Capability::witnessed(
        "library.peer.record.survives_restart",
        "a record written before a restart of the machine holding it is read after the restart, with the same identity, the same address and an unfinished attempt with the expiry it was given — the attempt still guards the peer and its expiry still ends it",
    ),
    Capability::witnessed(
        "library.peer.record.self_update_reload",
        "two stores over one root see each other's writes after a reload: a pairing written by one is seen by the other, and a write by the other re-reads the file first, so the pairing survives and the address it added is seen after a reload",
    ),
    Capability::witnessed(
        "library.peer.record.oversized_write",
        "a record a newer build left near the size cap is refused with `TooLarge` before an additive write would cross it; the file is left byte for byte as it was and still opens",
    ),
    Capability::witnessed(
        "library.peer.record.empty_attempt",
        "an attempt recorded on a peer this machine remembers nothing else about is removed when it ends, so a ceremony with a stranger leaves no file; a clear on that peer creates nothing and removes a record whose only facts were the failures and the attempt, and a record holding a pairing is kept",
    ),
    Capability::witnessed(
        "library.peer.pairing.same_string",
        "two machines pairing through the beacon compute the same six RFC 4648 base32 symbols from the whole transcript in the same attempt, each showing exactly one comparison, both record the pair, and the outcome carries the peer's beacon-observed address while the record stores no address until a connection authenticates one",
    ),
    Capability::witnessed(
        "library.peer.pairing.both_confirm",
        "a pair is recorded only when both people confirmed: one rejection leaves both sides unpaired, counts one failure on the side that saw it and none on the other, and the side that confirmed keeps no record at all",
    ),
    Capability::witnessed(
        "library.peer.pairing.one_sided",
        "a one-sided record does not wedge the pair: the side that holds it keeps it and compares again, both then hold it, and a third ceremony answers `AlreadyPaired` without showing a comparison",
    ),
    Capability::witnessed(
        "library.peer.pairing.own_identity",
        "a ceremony whose peer fingerprint is this machine's own is refused before anything is written",
    ),
    Capability::witnessed(
        "library.peer.pairing.attempt_limit",
        "three rejections close the pair on that machine, a fresh open of the same root still sees it closed, a ceremony is refused while it is closed, a dial reports `NotTrusted` with the closure as its cause rather than a missing record, and a person's clear reopens it",
    ),
    Capability::witnessed(
        "library.peer.pairing.flight_timeout",
        "a peer that is registered and reachable but never answers a ceremony flight ends the attempt as a flight timeout, distinct from a beacon failure, with the attempt counted against nobody and cleared",
    ),
    Capability::witnessed(
        "library.peer.pairing.attempt_expired",
        "a comparison nobody answered ends the attempt as expired when its lifetime passes, distinct from a beacon failure, and the expired attempt is cleared",
    ),
    Capability::witnessed(
        "library.peer.pairing.person_wait",
        "a person who never answers the comparison expires the attempt at its lifetime instead of parking the ceremony, distinct from a beacon failure, and the expired attempt is cleared",
    ),
    Capability::witnessed(
        "library.peer.pairing.attempt_expiry",
        "an unfinished attempt is recorded with its expiry, refuses a second attempt while it is live, and stops blocking once its lifetime has passed without a person doing anything",
    ),
    Capability::witnessed(
        "library.peer.pairing.failure_leaves_no_attempt",
        "a ceremony that fails before its first flight — the beacon does not answer — leaves no attempt behind, so the retry a person makes when the beacon is back is not refused for the attempt's lifetime",
    ),
    Capability::witnessed(
        "library.peer.pairing.string_not_carried",
        "every ceremony flight is parsed by the side that receives it — the case fails if any does not — and the message schema has no field for the comparison, so none of the bytes the ceremony sends carries the string; that the beacon stores no part of the ceremony is the claim of `library.beacon.introduction_opaque`, which this case does not inspect",
    ),
    Capability::witnessed(
        "library.peer.pairing.foreign_opening",
        "an opening flight from a machine that is not the one this ceremony is with is dropped: a third machine cannot end a pairing or have an attempt booked against it, and the pair still completes with one comparison each",
    ),
    Capability::witnessed(
        "library.peer.pairing.respond_waits",
        "a machine waiting to be paired is not bound by the beacon's request timeout: an introduction that arrives a minute later still starts the ceremony, and the pair completes",
    ),
    Capability::witnessed(
        "library.peer.pairing.bound_flights",
        "a confirmation or an already-paired flight replayed from an earlier attempt is refused as `BindingMismatch`, and a machine that holds no record refuses an already-paired claim as `NotPaired`: the flights after the reveal are bound to this attempt's transcript or to its commitment, so a relay cannot make a machine record a pairing the other machine did not confirm",
    ),
    Capability::witnessed(
        "library.peer.pairing.respond_ignores_strangers",
        "a machine waiting to be paired drops a malformed payload and a well-formed non-opening flight from a stranger, keeps waiting, and still pairs with the real initiator, with one comparison each and no record for the stranger",
    ),
    Capability::witnessed(
        "library.peer.pairing.mediator",
        "a party with its own key between two machines produces a different string on each side, so two people who see the difference reject and the pair is recorded on neither side",
    ),
    Capability::witnessed(
        "library.peer.pairing.simultaneous",
        "when both machines start at once, the attempt of the smaller fingerprint wins, both people see one comparison each, the pair is recorded on both sides, and the dropped attempt counts against nobody",
    ),
    Capability::witnessed(
        "library.peer.pairing.reordered_opening",
        "the loser's opening flight delivered after the winner revealed changes nothing — it sends no flight, shows no comparison and records no outcome — and the ceremony still completes with the one comparison both people saw",
    ),
    Capability::witnessed(
        "library.peer.connect.direct",
        "after pairing, two machines connect at the peer's own address — the beacon is asked once for the address because the pairing stored none, and the data path that follows touches no beacon — and carry a datagram machine to machine",
    ),
    Capability::witnessed(
        "library.peer.connect.hint_first",
        "a fresh address carried in an introduction is dialed before the remembered one, and the stale remembered address is not touched when the hint works",
    ),
    Capability::witnessed(
        "library.peer.connect.remembered_first",
        "a reconnect dials the remembered address first and does not consult the beacon when it works, and the accepting side records the address authenticated data arrived from",
    ),
    Capability::witnessed(
        "library.peer.connect.beacon_second",
        "when the remembered address is stale the beacon is asked after it, in that order, the fresh address it answers is dialed, and the dialing side does not rewrite the address it dialed",
    ),
    Capability::witnessed(
        "library.peer.connect.stops",
        "one call to the manager's connect makes one dial and no more: after the remembered address and the beacon both fail it reports `PeerUnknown` with the remembered address's dial failure as its cause, and moves nothing afterwards — the retry belongs to the keeper and the pair's policy, not to the call",
    ),
    Capability::witnessed(
        "library.peer.connect.recovery_state",
        "the pair's recovery is readable at any time and names what it is doing: nothing yet (`Unwatched`), dialling, waiting until a stated moment after a stated failure, an episode used up with its last failure, or stopped with the reason — and a pair that was off comes back to `Connected` with nobody acting; the sentence a product may show states a condition and never a schedule, so a used-up episode says it is used up instead of predicting when the next dial will be",
    ),
    Capability::witnessed(
        "library.peer.connect.nowhere",
        "a pair with no beacon configured and no remembered address stops with `Nowhere` and sends nothing: configuration, not a network state that can pass; the keeper stops on its first round, and a service path that meets the same state makes the same stop rather than counting it as a failed dial",
    ),
    Capability::witnessed(
        "library.peer.connect.nowhere_failure",
        "a pair whose record holds no address and whose manager has no beacon reports `ConnectFailure::Nowhere` — configuration, not a network failure — from a direct `Connections::connect`, from a service's `Connections::ensure`, and from an action asked for that pair, which answers the same failure instead of a bare unprepared; a stop a service's ask only found rather than wrote is answered with its cause too, so no caller is told only that nothing happened",
    ),
    Capability::witnessed(
        "library.peer.connect.a_stop_reopens_when_its_cause_goes",
        "a stop outlives nothing: a hint that reaches the peer re-opens a pair stopped with `Nowhere` — read with that connection gone, because a live pair answers connected whatever the policy says — an address another handle writes to the record re-opens it for good because the ask after a round reads the file rather than a cached record, an address the peer's own connection taught the record re-opens it, and a keeper the caller starts afterwards brings the pair up with nobody handing it an address",
    ),
    Capability::witnessed(
        "library.peer.connect.not_trusted_never_retried",
        "a pair this machine does not trust is never retried: the live connection is closed, the keeper returns the refusal naming the cause, the state is stopped, and no dial is made however much time passes; when the record behind the stop is removed, the next ask answers and stores the cause the file now gives rather than the one the state remembered",
    ),
    Capability::witnessed(
        "library.peer.connect.ensure_stops_and_reopens",
        "a service's dial to a pair this machine does not trust is answered with the refusal and the pair is stopped naming the same cause, so the answer and the readable state never name two reasons, and a trust a person restores is dialled by the next call: the restored pair is live and carries a datagram; a stop a keeper left for the withdrawal is re-opened by that next call, and a plain `Connections::connect` that reaches the peer re-opens it too, because the record and the handshake have both disproved its cause",
    ),
    Capability::witnessed(
        "library.peer.connect.watched",
        "who makes the next dial is readable beside what the policy is doing: a pair a keeper runs for reads watched while its state is the wait the keeper will act on, and a keeper whose task is cancelled — mid-dial or mid-wait — leaves the pair reading `watched` false with the episode it had used up still on record, so a product can say that nothing will dial it next rather than looking as though a retry is coming",
    ),
    Capability::witnessed(
        "library.peer.connect.beacon_restart",
        "a pair whose beacon went down recovers by itself when the beacon comes back: while it is down both sides report the beacon as unreachable rather than silence, and afterwards the pair reconnects and carries a datagram with no person and no restart",
    ),
    Capability::witnessed(
        "library.peer.connect.moved_address",
        "a peer that restarted on a new port is found again through the beacon by the other machine's own re-check: the stale address is tried, the beacon answers the new one, the pair connects at it and carries a datagram, and the accepting side records the address authenticated data arrived from",
    ),
    Capability::witnessed(
        "library.peer.presence.rearms",
        "this machine's own registration comes back by itself when the beacon does: while the beacon is gone the state names it as unreachable with the count of failed registration dials, once it returns the registration is held again with no person and no restart, and a run that is dropped leaves the state idle rather than claiming a registration nothing refreshes",
    ),
    Capability::witnessed(
        "library.peer.connect.vanish_bound",
        "the bound is stated in this machine's own terms and kept: with a keep-alive a peer that has gone silent is noticed within this machine's liveness bound — `VANISH_BOUND`, or twice the keep-alive when that is longer — plus the two keeper rounds that cover the manager's own liveness poll and the round that closes the connection, the connection is closed by this machine and dialled again, and the loss is not counted as a failure against the pair",
    ),
    Capability::witnessed(
        "library.peer.connect.vanish_bound_without_keep_alive",
        "without a keep-alive the stated bound is the transport's own idle timeout plus the one keeper round it takes to see the close — nothing this machine sends would make a silent peer answer — and that bound is kept too: a pair that says nothing at all is noticed gone inside it, the connection ends with the transport's timeout rather than a goodbye, the loss is a redial and not a strike, and the pair comes back with nobody acting",
    ),
    Capability::witnessed(
        "library.peer.connect.quiet_pair_outlives_the_bound",
        "a healthy pair that carries nothing is not declared gone by its own keeper: with the default transport, both keepers run over a quiet connection for longer than `vanish_bound()`, the connection is the same one afterwards, the state reads connected, the keeper is still running, and a datagram still crosses",
    ),
    Capability::witnessed(
        "library.peer.connect.shorter_timeout",
        "a peer built with a shorter idle timeout than this machine's does not turn an ordinary quiet drop into a failure counted against the pair: the timeout is a redial and not a strike, and the pair comes back",
    ),
    Capability::witnessed(
        "library.peer.connect.unmeasured_silence",
        "a machine that cannot measure a peer's silence does not conclude it: with a keep-alive but a liveness reader that cannot be heard from, `vanish_bound` answers `Vanish::Unmeasured` and no connection is closed or re-dialled however long the peer stays quiet, while a machine whose reader runs answers `Vanish::Measured` and states the fixed bound plus two keeper rounds",
    ),
    Capability::witnessed(
        "library.peer.connect.recheck_spread",
        "the slow re-check is this machine's own and never longer than `RECOVERY_RECHECK`, so two machines that lost the same beacon do not come back at the same instant and the stated bound is still the bound: a used-up episode names a wait no longer than the bound, the same machine names the same wait every time, and two machines name different ones",
    ),
    Capability::witnessed(
        "library.peer.connect.fresh_wins",
        "a connection that has stopped answering does not keep a working one out: a held connection that has shown no sign of life for the vanish bound loses the tie-break to a fresh one, which the pair keeps and which carries a datagram; the sign of life is sampled by the manager's own reader, so the rule holds for a pair nobody is watching and does not depend on how often anybody reads the connection",
    ),
    Capability::witnessed(
        "library.peer.connect.accept_burst",
        "a burst of half-finished handshakes does not stop the machine accepting new ones: with several stalled handshakes in flight a properly paired peer still connects and carries a datagram",
    ),
    Capability::unproducible(
        "library.peer.connect.outcomes_extensible",
        "the outcome vocabulary the retry policy has to express — `ConnectFailure`, `NotTrustedCause`, `Recovery`, `StopCause`, `Registration` and `ManagerError` — is non-exhaustive, so a consumer compiled against an earlier version still builds when a variant is added and must match with a wildcard arm",
        "a non-exhaustive enum is a compile-time property: the compiler refuses an exhaustive match in a downstream crate, so no case inside this workspace can observe it, and nothing here is a downstream crate",
        "in a checkout of this crate, write `fn f(c: mahbot_peers::peer::ConnectFailure) { match c { mahbot_peers::peer::ConnectFailure::Nowhere { .. } => {} } }` in a separate crate that depends on it: the build fails with `non-exhaustive patterns`, which is the property; then add `_ => {}` and it builds",
    ),
    Capability::witnessed(
        "library.peer.connect.four_failures",
        "the four failures — beacon unreachable, peer unknown, no direct path, not trusted — are reported as themselves, each with its own words, and none as another",
    ),
    Capability::witnessed(
        "library.peer.connect.unwatchable_transport",
        "a transport whose idle timeout is not longer than the keeper's settle window is refused when the manager is built, with a typed error naming the timeout, so a caller cannot turn an ordinary silent drop into a strike by configuring this machine's transport; a keep-alive that is not shorter than its idle timeout — one that could never fire — is refused the same way, naming both; one second above the window with a keep-alive just below the timeout builds a manager",
    ),
    Capability::witnessed(
        "library.peer.connect.slow_keep_alive_raises_the_bound",
        "a keep-alive slower than half of `VANISH_BOUND` is accepted and raises this machine's own liveness bound to twice the keep-alive, which `vanish_bound()` states, so a live quiet peer is never declared gone between two pings; with such a transport a keeper runs over a pair that carries nothing for longer than the fixed bound, the connection stays the one the pair holds, and the state reads connected",
    ),
    Capability::witnessed(
        "library.peer.connect.one_per_pair",
        "when both machines dial at once each keeps the connection started by the smaller fingerprint, both sides keep the same connection, each keeper is a direct path to the other machine's own address, and a datagram crosses it",
    ),
    Capability::witnessed(
        "library.peer.connect.asymmetric_liveness",
        "a connection one side has closed and the other has not observed is not replaced by a connection the two sides would hold differently; once the stale one times out, the next dial reconnects the pair and a datagram crosses it",
    ),
    Capability::witnessed(
        "library.peer.connect.closed_not_trusted",
        "a record that was paired and then closed by rejections is not trusted: the manager refuses it with the closure as its cause, the handshake refuses the peer, and a person's clear reopens it",
    ),
    Capability::witnessed(
        "library.peer.connect.same_starter",
        "when both connections are started by the same machine, both sides keep the one whose TLS exporter is smaller — a value both endpoints derive identically — and a datagram crosses the keeper",
    ),
    Capability::witnessed(
        "library.peer.connect.tie_break_closes",
        "the connection the tie-break does not keep is closed with the tie-break's reason and reports that close to its own side, while the kept connection carries a datagram: the pair is left with one connection, not two",
    ),
    Capability::witnessed(
        "library.peer.connect.tie_break_teaches_no_address",
        "a dial whose connection loses the tie-break to the pair's existing connection records no address: the record keeps the last address authenticated data arrived from, never the address this machine dialled, even when the kept connection is this machine's own outbound one",
    ),
    Capability::witnessed(
        "library.peer.connect.closed_not_live",
        "a connection that has closed is not reported by the manager's live or started-by query; its entry is replaced or dropped by the next adoption for that peer, so a peer never dialled again keeps a dead handle until the manager is dropped",
    ),
    Capability::witnessed(
        "library.peer.connect.keep_connected",
        "the manager's keeper re-dials the pair when its connection is gone, with no caller dialling: it keeps the new connection, the old one is gone, and a datagram crosses the replacement",
    ),
    Capability::witnessed(
        "library.peer.connect.keeper_failed",
        "a keeper whose dial fails while the pair holds no connection does not stop: the failure keeps its own name in the pair's state — a peer the beacon does not know, after the remembered address timed out — the pause before each next dial is the gap that dial earned, read as the distance from the end of one dial to the start of the next, and the episode is used up at the stated cap, where the pair reads `Exhausted` with that cap's dial count; one re-check adds at most one dial and never restarts the episode",
    ),
    Capability::witnessed(
        "library.peer.connect.keeper_bound",
        "a peer that accepts a fresh connection and closes it at once does not turn the keeper into a handshake loop and does not end the pair either: after the stated number of dials that produced a connection which carried nothing and ended inside the settle window, the episode is used up, the pair waits a stated re-check, the keeper is still running, and when the peer stops closing the pair comes back with nobody acting",
    ),
    Capability::witnessed(
        "library.peer.connect.keeper_settle",
        "a connection the pair used restarts the episode, so ordinary churn never adds up to the slow state: six closes across two settled connections are re-dialled inside the settle window and the pair never reads an episode used up",
    ),
    Capability::witnessed(
        "library.peer.connect.cancelled_dial",
        "a dial whose task is dropped mid-handshake gives the pair its next dial back instead of leaving it marked as dialling: the state is one a dial is due from, and that holds even after the pair has already had and lost a connection the keeper judged, and whether the task dropped was a caller's dial or a keeper's; a pair left with no keeper reads unwatched, and one started again dials it",
    ),
    Capability::witnessed(
        "library.peer.connect.inbound_keeps_the_episode",
        "an authenticated inbound connection from the peer does not restart a used-up episode: it takes the next dial number and the count stays at the cap, so a peer that accepts and drops and also dials in cannot escape the bound; and a one-shot `Connections::connect` on a pair no keeper runs for promises nothing — once its connection is gone the pair reads `Unwatched` when no dial had run before it, and `watched` says no keeper will make the next one",
    ),
    Capability::witnessed(
        "library.peer.connect.one_episode_per_pair",
        "a second keeper started for a pair one already watches does not hand it a second episode, whether it starts between dials or while one is in flight: the dial count stays where the running keeper left it — the dial that was running finishes as that episode's dial and not as the first of a new run — so a peer that keeps dropping a connection cannot be given a fresh run of dials by starting another keeper, and the pair keeps reading watched while either keeper lives",
    ),
    Capability::witnessed(
        "library.peer.connect.keeper_supersession",
        "two keepers that start together each dial before either can adopt the other's connection — the link is silenced and the trace shows one datagram from each side — the pair converges on the connection the smaller fingerprint started, and neither keeper stops on the collision",
    ),
    Capability::unproducible(
        "library.peer.connect.keeper_strike_cleared",
        "a connection that dies carrying nothing is counted against the peer even when another dialer has connected by then, so a peer that accepts and drops cannot escape the bound by racing a second dial; a dial that fails outright while the pair is connected is not counted, because a pair that is connected has nothing to recover from",
        "the rig cannot land the second adoption between the death of one connection and the keeper's judgement of it: its accept loop and the keeper share one simulated clock, and the keeper judges the connection in the same poll that sees it closed",
        "on two machines on a real network, pair them and make the peer accept a connection and drop it inside the settle window while a second dial from this machine is in flight — a peer script that closes every accepted connection at once does it, and so does a breakpoint in `Connections::adopt` held between the close and the keeper's judgement; the pair's recovery then counts the dropped connection as a dial that carried nothing even though the second dial connected, which `Connections::recovery` shows as the dial count growing after a connection was kept",
    ),
    Capability::witnessed(
        "library.peer.connect.transient_adoption",
        "a dial that fails while an inbound connection has already been accepted does not stop the keeper: it asks whether the pair is connected before it reports the dial failure, and the pair it took carries a datagram",
    ),
    Capability::witnessed(
        "library.peer.connect.keeper_link_failure",
        "a connection the peer kept past the settle window is ordinary churn: when an idle timeout on both sides of a transport with no keep-alive ends it, the keeper re-dials after each of three such losses and is still running, and the pair carries a datagram afterwards",
    ),
    Capability::witnessed(
        "library.peer.connect.keeper_carried",
        "a connection that carried a datagram and then died inside the settle window is a link failure, not a strike: a peer that sends one datagram and closes each connection more times than the episode's cap of dials leaves the keeper running",
    ),
    Capability::witnessed(
        "library.peer.connect.keeper_after_restart",
        "a pair made by a real ceremony and then broken by a restart of one machine reconnects with no caller dialling and no second ceremony: the restarted machine's own start is the trigger, its keeper dials the remembered address by itself, a datagram crosses the new connection, and the pairing is unchanged",
    ),
    Capability::witnessed(
        "library.peer.connect.remembered_cause",
        "when the remembered address fails and no beacon is configured, the failure is `BeaconUnreachable` whose cause names the address and its dial failure and says no beacon is configured, not a claim that no address was remembered",
    ),
    Capability::witnessed(
        "library.peer.connect.reconnect_after_restart",
        "two machines that ran a real ceremony reconnect after one restarts over its own root: the pairing survives, no new ceremony runs, and the beacon's answer supplies the fresh address",
    ),
    Capability::witnessed(
        "library.peer.access.binding",
        "the machine that decides the connection level records which account on which instance and which assistant it bound the peer to, durably across a restart, and the other side is shown that fact as a claim over the direct connection",
    ),
    Capability::witnessed(
        "library.peer.access.claim_not_authority",
        "a claim names the pair for the other machine's person and allows nothing on its strength: the decision on that pair refuses for want of a right",
    ),
    Capability::witnessed(
        "library.peer.rights.default_write",
        "a pair's acquaintance issues exactly one right, `write to me` by the default, and the audit's last entry records that grant as created",
    ),
    Capability::witnessed(
        "library.peer.rights.default_once",
        "the default acts once per pair: a second acquaintance issues nothing, and neither a right a person withdrew nor one whose term passed is re-created by it",
    ),
    Capability::witnessed(
        "library.peer.rights.guest_widened",
        "the default is one right for every assistant — the plan's guest floor, so a guest is never defaulted `work to me` or `see the screen` — and a person may widen it with a right the log records as issued by that person; the crate stores the assistant's name and not the product's guest declaration, which changes no decision it makes",
    ),
    Capability::witnessed(
        "library.peer.rights.withdrawn",
        "a right a person withdrew refuses the next question with the withdrawal's exact moment at the right step, stays on file as withdrawn, and is recorded with the person's name",
    ),
    Capability::witnessed(
        "library.peer.rights.ended",
        "a right whose term passed refuses with the term's moment at the right step however often it is asked, the ending is recorded once by the question and not again by the sweep, and a person's later grant restores it as a restore",
    ),
    Capability::witnessed(
        "library.peer.rights.floor",
        "the host's floor refuses a right that exists without withdrawing it, is recorded as a refusal rather than a withdrawal, keeps a right it does not name, and cannot add a right the pair never held",
    ),
    Capability::witnessed(
        "library.peer.rights.remote_write",
        "a write attributed to a peer is refused as a remote authority before it changes anything, leaves no right on file, and is recorded as a refused write naming the peer",
    ),
    Capability::witnessed(
        "library.peer.rights.untrusted",
        "a machine the store holds no record for is refused at the authenticate step, and so is a paired machine whose trust was withdrawn, whose record says so",
    ),
    Capability::witnessed(
        "library.peer.rights.unauthenticated",
        "a question with no completed handshake behind it is refused at the authenticate step, and so is a question whose key is not the pair's machine",
    ),
    Capability::witnessed(
        "library.peer.rights.survive_restart",
        "rights granted on both machines of a pair are still allowed after both stores and logs are reopened from their roots, so the decision reads the files and not a process's memory",
    ),
    Capability::witnessed(
        "library.peer.rights.trust_withdrawn",
        "withdrawing trust removes every right the machine held, answers how many, leaves no default marker, refuses the next question as untrusted, and is recorded with the count and the person",
    ),
    Capability::witnessed(
        "library.peer.rights.trust_restored",
        "restoring trust reissues only the default `write to me` right, issued for the pair the binding names whatever pair the caller passed, leaves a person's earlier right gone, and is recorded with the return and the default's grant",
    ),
    Capability::witnessed(
        "library.peer.rights.restore_binding",
        "restoring trust and a new acquaintance issue the default for the pair the record's binding names, so a caller that passes a claim-derived pair after a rebind cannot write a right for a pair this machine never bound the machine to",
    ),
    Capability::witnessed(
        "library.peer.rights.moved_pair",
        "a machine bound to a new assistant starts from the new pair's default and inherits nothing, while the pair it left keeps the right a person granted it",
    ),
    Capability::witnessed(
        "library.peer.rights.bound_pair_only",
        "a question naming a pair this machine did not bind the machine to is refused for want of a right and recorded against that pair, while the pair it left keeps its row as a record and the new pair's default allows `write to me`",
    ),
    Capability::witnessed(
        "library.peer.rights.attempt_lock",
        "clearing a closed pair's attempt lock reopens it and is recorded with the person and the moment",
    ),
    Capability::witnessed(
        "library.peer.rights.attempt_lock_open",
        "clearing an attempt lock that holds nothing changes nothing and records nothing, while a machine this one never paired is refused as unpaired",
    ),
    Capability::witnessed(
        "library.peer.rights.return_idempotent",
        "a call that finds the trust back and the default not yet issued finishes the act instead of reporting that it is over, and only a return whose default has acted answers that there is nothing to restore; the state a return that failed after clearing the trust is in has the same record shape",
    ),
    Capability::witnessed(
        "library.peer.rights.return_closed",
        "a return from a withdrawal on a machine whose pairing attempt lock is also closed issues the default and reports the lock it left standing, rather than answering a right the machine cannot use; the second, separate act reopens it",
    ),
    Capability::witnessed(
        "library.peer.audit.torn_tail",
        "opening a log whose last entry was cut short keeps every complete entry, cuts the file back to the last one, and leaves a real entry's bytes untouched",
    ),
    Capability::witnessed(
        "library.peer.audit.torn_tail_on_append",
        "an append finds a torn tail another process left — a length word and part of a body, with nothing after them — cuts it before writing past it, and leaves the log whole and readable",
    ),
    Capability::witnessed(
        "library.peer.audit.person_room",
        "the bytes below the log's cap that are kept for a person's acts are not available to a peer's refusals: with the part a peer may fill full, a refusal is answered without an entry and the log stays under its cap, while a person's withdrawal is written and takes effect",
    ),
    Capability::witnessed(
        "library.peer.audit.torn_tail_past_cap",
        "a half-written entry that pushes a log just past its cap is cut before the cap is judged, so the log opens and comes back under the cap instead of becoming unopenable for ever",
    ),
    Capability::witnessed(
        "library.peer.audit.ending_room",
        "a question that notices an ending when the log has no room left for the entries a peer causes answers the ending at the right step, writes no entry, and leaves the row unmarked, so the record never claims an ending nobody recorded",
    ),
    Capability::unproducible(
        "library.peer.audit.private_on_create",
        "the log carries the privacy rule before its first byte lands: it is created as a private temporary file and published without replacing, so no instant exists in which another account can open it",
        "no case can observe an instant that does not exist: the window was a race between creating the file and tightening its mode, and the suite holds one account, so it cannot watch a second one open the file between the two; what a case can show is the final rule, which `library.peer.audit.private` does",
        "on a host with a second account, run the process that opens the log on an empty root in a loop, and from the second account loop opening the same path: every open either fails with `ENOENT` before the publish or with `EACCES` after it, never succeeds, and `ls -l` on the file shows `-rw-------` from the instant it exists",
    ),
    Capability::witnessed(
        "library.peer.audit.torn_header",
        "opening a log whose first write was cut inside the header completes the header rather than refusing it, and a file whose bytes are not that header's prefix is refused as malformed",
    ),
    Capability::witnessed(
        "library.peer.audit.label_rule",
        "a known act whose label field carries bytes after its value is kept as its code rather than read as that value's prefix",
    ),
    Capability::witnessed(
        "library.peer.rights.steps",
        "the six refusals each report the step they belong to — authenticate, right, or the host's floor — and no two refusals are the same",
    ),
    Capability::witnessed(
        "library.peer.audit.every_act",
        "one run's grant, refusal, ending, withdrawal, trust withdrawal, trust return and attempt-lock clearing each appear in the log at the caller's moment, with the person's name where a person acted",
    ),
    Capability::witnessed(
        "library.peer.audit.already_held",
        "a default that finds the pair already holds the capability a person granted records the grant as already held, naming that person and that person's term, and leaves the row on file unchanged",
    ),
    Capability::witnessed(
        "library.peer.record.ending_without_term",
        "a right field that names an ending and no term is refused as that field, naming the missing term, so no row the decision reads is without the moment its refusal reports",
    ),
    Capability::witnessed(
        "library.peer.record.unknown_capability",
        "a right for a capability this build does not know is kept out of the pair's rights and satisfies no question, and a later rewrite of the record writes the field back untouched",
    ),
    Capability::witnessed(
        "library.peer.access.claim_newest",
        "a claim keeps the deciding machine's newer decision: a re-delivered older fact changes nothing, and a newer fact replaces the claim on file",
    ),
    Capability::witnessed(
        "library.peer.access.fact_version",
        "a fact of a newer version is read as this build's prefix with its unknown fields ignored, while a version of zero, bytes that are not a fact and a fact naming no assistant are each refused by their own error",
    ),
    Capability::witnessed(
        "library.peer.access.label_rules",
        "a label that says nothing, runs too long or carries a control character or a direction mark is refused with its own error, and a fact field with bytes after its label is refused as that field rather than read as the value's prefix",
    ),
    Capability::witnessed(
        "library.peer.access.fact_malformed",
        "a fact this build cannot read is refused as `RecordError::Claim` naming the machine that sent the bytes, not this machine's record, and the claim already on file is unchanged",
    ),
    Capability::witnessed(
        "library.peer.binding.no_fact",
        "a peer with no binding writes nothing: the empty body is kept as no fact, no claim is written, the pairing's record stays as it was, the connection stands, and an empty body handed to the store is answered `Ok` with nothing written rather than refused",
    ),
    Capability::witnessed(
        "library.peer.connect.binding_not_traffic",
        "a connection that only exchanged its binding carried nothing: the keeper counts it as a dial that carried nothing, so a peer that keeps doing it uses the episode up instead of the pair being re-dialled in a loop, and the exchange left the claim it sent",
    ),
    Capability::witnessed(
        "library.peer.connect.withdrawn_stops",
        "a machine whose trust was withdrawn is closed by the manager on its next round, refused by the keeper with the withdrawal as its cause, and its next handshake is refused as untrusted because resumption is off and the pin runs",
    ),
    Capability::witnessed(
        "library.peer.connect.withdrawn_any_store",
        "a withdrawal written through one store over a root stops a manager built over another store of it — the live connection closed and the keeper stopped naming the withdrawal — with nothing asked of the caller, the manager will not dial the machine again, and the handshake's own trust question, asked of a handle opened before the withdrawal, refuses the key it trusted a moment before",
    ),
    Capability::witnessed(
        "library.tls.resumption_off",
        "neither TLS configuration offers resumption and the server sends no tickets, so a session cannot be resumed past the raw-key pin; the handshake after a withdrawal is the case beside this one",
    ),
    Capability::witnessed(
        "library.peer.access.rebind",
        "a binding changed while the connection is up takes effect at the next connection, whose claim names the new assistant while still allowing nothing on its strength",
    ),
    Capability::witnessed(
        "library.peer.rights.withdrawn_while_connected",
        "a right withdrawn while the connection is up refuses the next question with the withdrawal's own step and moment, and the connection stays live",
    ),
    Capability::witnessed(
        "library.peer.rights.ended_while_connected",
        "a right whose term passes while the connection is up refuses the next question naming the term's end, and the connection stays live",
    ),
    Capability::witnessed(
        "library.peer.rights.fresh_view",
        "a decision reads the record afresh, so a right withdrawn through another store over the same root refuses the next question on this one",
    ),
    Capability::witnessed(
        "library.peer.presence.refresh",
        "a registration that is never refreshed is forgotten on the beacon's own lifetime while its session stays open, and a registration refreshed by `Presence` outlives that lifetime",
    ),
    // The message layer: the queue a sender keeps, the offer it makes, the answers a
    // receiver gives, and the rights around both.
    Capability::witnessed(
        "library.peer.messages.compose",
        "a message is durable in the sender's queue before any connection, with an identifier unique for that sender, a count within the pair and the composed moment",
    ),
    Capability::witnessed(
        "library.peer.messages.body_stored_as_written",
        "a body is stored and handed over exactly as composed, never escaped or rendered",
    ),
    Capability::witnessed(
        "library.peer.messages.queue_bounded",
        "a pair's queue is bounded and a full queue is refused rather than dropping an older message",
    ),
    Capability::witnessed(
        "library.peer.messages.too_large",
        "a queue that would grow past its file cap is refused and left exactly as it was, so nothing is truncated",
    ),
    Capability::witnessed(
        "library.peer.messages.body_bounded",
        "a body of exactly the cap is queued and one byte more is refused before anything is written",
    ),
    Capability::witnessed(
        "library.peer.messages.composed_moment",
        "the moment a message says it was composed is a remark: the queue orders by count and measures retention from when it stored the message",
    ),
    Capability::witnessed(
        "library.peer.messages.closed_pair",
        "a message for a pair closed by three failed comparisons is refused before it is written, and a withdrawn trust is still answered as withdrawn",
    ),
    Capability::witnessed(
        "library.peer.messages.queue_survives_restart",
        "a sender's queue survives its restart",
    ),
    Capability::witnessed(
        "library.peer.messages.retention",
        "a message untaken after 72 hours is dropped and the drop is recorded",
    ),
    Capability::witnessed(
        "library.peer.messages.trust_withdrawn",
        "withdrawing trust drops that pair's queue and records it",
    ),
    Capability::witnessed(
        "library.peer.messages.taken_once",
        "the same envelope offered three times reaches the receiver's caller once",
    ),
    Capability::witnessed(
        "library.peer.messages.dedup_survives_restart",
        "the receiver's memory of taken identifiers survives its restart",
    ),
    Capability::witnessed(
        "library.peer.messages.taken_retention",
        "a taken identifier is remembered for a week and then forgotten: a retry inside it is answered `already taken`, one after it is delivered again, and a fresh identifier under a count already used is delivered with the rewind declared — a sender whose queue was lost is never wedged for the pair's life",
    ),
    Capability::witnessed(
        "library.peer.messages.delivery_declined",
        "a caller that cannot store is handed the message again and nothing is recorded as taken until it says it kept it",
    ),
    Capability::witnessed(
        "library.peer.messages.rewind",
        "a count that does not move forward is declared as a rewind and its message is delivered: only a remembered identifier suppresses a message, and a drop is never written for one that reached a caller",
    ),
    Capability::witnessed(
        "library.peer.messages.offered_when_connected",
        "a message composed while the peer was away arrives when it returns",
    ),
    Capability::witnessed(
        "library.peer.messages.waiting_for_binding",
        "a pair whose binding has not arrived is not spoken to, and the queue says so",
    ),
    Capability::witnessed(
        "library.peer.messages.order",
        "messages from one machine arrive in the order of the sender's count, and two peers' orders are independent",
    ),
    Capability::witnessed(
        "library.peer.messages.gap",
        "a count that jumps forward is declared as the number of missing messages instead of being renumbered or silently continued",
    ),
    Capability::witnessed(
        "library.peer.messages.authorship",
        "the sender is the transport's attested peer; a body's claim about its author is text",
    ),
    Capability::witnessed(
        "library.peer.messages.right",
        "a message is offered only under the pair's live write right, and service resumes when it is given",
    ),
    Capability::witnessed(
        "library.peer.messages.floor",
        "the host's own floor can refuse a message a right gives, and the host's words stay on the receiver while the right stays live",
    ),
    Capability::witnessed(
        "library.peer.messages.refusal_is_final",
        "a refusal is recorded, the message is dropped at the sender, and the queue moves on",
    ),
    Capability::witnessed(
        "library.peer.messages.peer_cannot_fill_the_log",
        "a peer's refusals stop at the log's room kept for a person's acts, so a peer cannot fill the log, and the message is still answered",
    ),
    Capability::witnessed(
        "library.peer.messages.service_reports_a_broken_queue",
        "a queue or record the service cannot read or write ends it and reaches whoever started it, whether the service's own round or a receiving task it started met the refusal",
    ),
    Capability::witnessed(
        "library.peer.messages.unreadable_answered",
        "a frame the receiver cannot read — bytes that are not a message, or a frame longer than any message this build writes — is answered `unreadable`, so the sender drops it instead of keeping it for the retention",
    ),
    Capability::witnessed(
        "library.peer.messages.held_queue",
        "another writer holding a queue is not a fault: the service keeps the message, waits a round, and the message leaves when the writer lets go, delivered once; a refusal repeated while the queue is held is written once a second, not once an offer",
    ),
    Capability::witnessed(
        "library.peer.messages.delivery_panic",
        "a caller whose delivery panics ends the service with that bug named, and the message stays queued, rather than the pair going silent",
    ),
    Capability::witnessed(
        "library.peer.messages.answer_write_bounded",
        "writing an answer back is bounded like every other wait this crate makes: a peer whose stream window will not take it costs one budget and an ended stream, and the receiving task takes the next offer instead of parking the pair for the connection's life",
    ),
    Capability::witnessed(
        "library.peer.messages.taken_is_not_a_drop",
        "a message the receiver took is never recorded as a drop: offered again — after a removal another writer held, or from a restored queue — it is answered `already taken`, the sender drops its copy, and the log gains nothing",
    ),
    Capability::witnessed(
        "library.peer.messages.busy",
        "a queue another writer holds — the second process a self-update leaves on one root — answers `busy` and the same call is worth making again, rather than waiting unboundedly",
    ),
    Capability::witnessed(
        "library.peer.messages.service_sweeps",
        "a running service sweeps its own peer, so a retention and a trust withdrawn while it runs drop that queue and record it without the caller sweeping by hand",
    ),
    Capability::witnessed(
        "library.peer.messages.unanswered_offer",
        "an offer nobody answers costs one round a second, so a peer that resets each offer stream cannot make the sender spin through its queue files",
    ),
    Capability::witnessed(
        "library.peer.messages.reconnect",
        "after the pair's connection is replaced — a reconnection, a tie-break — the pair still receives: the layer attaches a receiving task to the new connection. A case cannot force a dropped connection's address to be handed out again, so the rule that tells the two apart is not mutation-checked; the behaviour is",
    ),
    Capability::witnessed(
        "library.peer.messages.throttle",
        "a flood is throttled, the sender is told, and a throttle is not a refusal",
    ),
    Capability::witnessed(
        "library.peer.messages.not_on_the_beacon",
        "the beacon carries no message",
    ),
    Capability::witnessed(
        "library.peer.messages.queued_causes_dial",
        "a message waiting to be delivered causes a dial with no keeper and no caller dialling, and the ask keeps the episode rather than starting a fresh one: the queue's poll does not become a dial per second, the gaps between the dials it causes do not shrink and grow as the failures accumulate, and a peer that keeps dropping a connection while the message waits is still bounded by the episode's cap",
    ),
    Capability::witnessed(
        "library.peer.messages.queued_capped_by_the_episode",
        "a message standing in the queue does not let a peer that accepts every connection and drops it escape the episode's bound: with the queue the only thing dialling, the peer's accept-and-drop costs it the episode's stated dials and no more, and the peer really took each of them",
    ),
    Capability::witnessed(
        "library.peer.messages.already_taken_is_traffic",
        "an `already taken` answer counts as the pair having carried traffic: by the peer's own account the message reached it, so the connection that carried that answer is a used connection and not a dial that carried nothing",
    ),
    Capability::witnessed(
        "library.peer.messages.offering_is_not_traffic",
        "offering a message does not count as the pair's traffic for the keeper, so a connection closed with an offer still unanswered is one dial of the pair's recovery — counted, with the connection that carried nothing as its cause — and not a pair that was used",
    ),
    Capability::witnessed(
        "library.peer.messages.body_cannot_reach_a_capability",
        "the message layer names no capability, so no body can select one or reach a grant",
    ),
    Capability::witnessed(
        "library.peer.messages.format",
        "a message file's unknown fields are kept and written back, so the format is additive",
    ),
    Capability::witnessed(
        "library.peer.messages.malformed",
        "a file that is not a message file is refused, not believed",
    ),
    // The action layer: the identifier the caller names, the at-most-once memory, the answer
    // that never guesses, the right, and the one connection it shares with messages.
    Capability::witnessed(
        "library.peer.actions.identifier_from_caller",
        "the crate never mints an operation's identifier: the caller names it, a repeat under it is answered already executed, and a new identifier is a new operation that runs",
    ),
    Capability::witnessed(
        "library.peer.actions.identifier_is_one_operation",
        "an identifier belongs to one operation: the same identifier with a different body is answered already executed, and the second body never reaches the machine's own code",
    ),
    Capability::witnessed(
        "library.peer.actions.at_most_once",
        "the same operation offered three times is executed once, and the two repeats are answered already executed without a result",
    ),
    Capability::witnessed(
        "library.peer.actions.memory_survives_restart",
        "the receiving machine's journal of executed identifiers survives its restart",
    ),
    Capability::witnessed(
        "library.peer.actions.memory_retention",
        "an executed identifier is remembered for a week and then forgotten: a repeat after the week runs again, which is the honest cost of remembering",
    ),
    Capability::witnessed(
        "library.peer.actions.unknown_mark",
        "an action whose result never came back is marked unknown, and the mark is durable and read back by the caller",
    ),
    Capability::witnessed(
        "library.peer.actions.unknown_survives_restart",
        "the unknown mark survives the sender's restart, so the one trace that something may have run is not lost",
    ),
    Capability::witnessed(
        "library.peer.actions.never_retried",
        "the same identifier is never offered again after its outcome is unknown: a repeat is a person's new operation with a new identifier",
    ),
    Capability::witnessed(
        "library.peer.actions.trust_withdrawal_clears",
        "a person's trust withdrawal clears that peer's executed identifiers and unknown marks, which is the way out of a full journal; the record keeps the withdrawal's moment, so the clearing works even when the peer's service is stopped for the whole withdrawal, and the same identifier runs again once the trust is back",
    ),
    Capability::witnessed(
        "library.peer.actions.in_flight_repeat",
        "a repeat that arrives while the first execution is still running is answered already executed and is not run",
    ),
    Capability::witnessed(
        "library.peer.actions.memory_full",
        "a full journal refuses a new action rather than forgetting an old identifier, and an identifier already there is still answered already executed",
    ),
    Capability::witnessed(
        "library.peer.actions.expired_cleared_first",
        "expired identifiers are cleared before the journal is called full, so a week-old memory does not refuse a new action",
    ),
    Capability::witnessed(
        "library.peer.actions.result_bounded",
        "a result too large to carry is answered as ran-but-not-carried, never truncated, and the identifier stays remembered; a result of exactly the cap is carried whole",
    ),
    Capability::witnessed(
        "library.peer.actions.body_stored_as_written",
        "a body is handed to the machine's own code exactly as composed, never escaped or rendered",
    ),
    Capability::witnessed(
        "library.peer.actions.body_bounded",
        "a body of exactly the cap is carried and one byte more is refused before anything is sent",
    ),
    Capability::witnessed(
        "library.peer.actions.format",
        "an action memory's unknown fields are kept and written back, so the format is additive",
    ),
    Capability::witnessed(
        "library.peer.actions.malformed",
        "a file that is not an action memory, or one past its byte cap, is refused, not believed",
    ),
    Capability::witnessed(
        "library.peer.actions.right",
        "an action is decided by the pair's work-on-me right and the host's floor, in the plan's order, and a refusal names the step that refused it",
    ),
    Capability::witnessed(
        "library.peer.actions.refusal_not_remembered",
        "a refused action is not remembered: the same identifier runs once the right is given",
    ),
    Capability::witnessed(
        "library.peer.actions.declined",
        "an action the receiving machine's own code declines is answered as not run and is not remembered, and the decline is answered before a memory that cannot release the identifier ends the service, so it never becomes an unknown",
    ),
    Capability::witnessed(
        "library.peer.actions.not_ready",
        "a pair whose binding has not arrived is answered as not ready, which is neither a refusal nor an execution, and the same identifier runs once the binding arrives",
    ),
    Capability::witnessed(
        "library.peer.actions.closed_pair",
        "a pair closed by three failed comparisons is refused before the dial",
    ),
    Capability::witnessed(
        "library.peer.actions.body_cannot_reach_a_capability",
        "nothing in an action body chooses a right: a body that looks like a grant runs under the fixed work-on-me right and changes nothing",
    ),
    Capability::witnessed(
        "library.peer.actions.source_has_no_capability",
        "the summary scan proves the action layer's sources name no `Capability` value and ask no question of their own, so no path leads from a body to a right; the capability the layer records is the one the decision returned, and the case pins the checker's controls",
    ),
    Capability::witnessed(
        "library.peer.actions.kind_closed",
        "an action of a kind this build does not know is answered unsupported rather than run as a command, and the right is settled before the kind, so a peer without it is refused at the right whatever kind it names",
    ),
    Capability::witnessed(
        "library.peer.actions.one_budget",
        "one request has one total ACTION_BUDGET: a dial that spends its connect bound leaves the answer only the rest, so the request resolves at the budget's end rather than after another full one",
    ),
    Capability::witnessed(
        "library.peer.actions.connect_failure",
        "an action a person asks for against a peer that is not there is answered with the pair's own failure — `Connect` naming the peer and what the dial met — rather than a bare `unprepared`, and the ask makes one dial rather than a dial a second, so the wait is the retry policy's pace",
    ),
    Capability::witnessed(
        "library.peer.actions.audit_cap_stops",
        "a log at its own file cap — not merely past the room kept for a person — also stops the peer from acting, answers `not recorded`, and leaves the service up",
    ),
    Capability::witnessed(
        "library.peer.actions.audit_first",
        "the execution is recorded before it runs, and an action that cannot be recorded does not run",
    ),
    Capability::witnessed(
        "library.peer.actions.audit_full_stops",
        "a log with no room left for a peer's act stops the peer from acting visibly, and the identifier is not remembered for an execution that did not run",
    ),
    Capability::witnessed(
        "library.peer.actions.audit_entry",
        "the execution entry names the peer, the pair, the right it ran under and the identifier",
    ),
    Capability::witnessed(
        "library.peer.actions.audit_no_body",
        "the audit log never carries the action's body: what the command was is the product's own record, keyed by the identifier",
    ),
    Capability::witnessed(
        "library.peer.actions.busy",
        "a second writer on the root is answered busy, nothing runs and nothing is remembered, and the same call succeeds once the writer lets go",
    ),
    Capability::witnessed(
        "library.peer.actions.sweep_busy",
        "the public sweep of the action memory answers `busy` when another writer holds it, and the same call compacts the file once the writer lets go",
    ),
    Capability::witnessed(
        "library.peer.actions.shared_connection",
        "messages and actions share the pair's connection, and each is taken for itself under a link that drops and reorders",
    ),
    Capability::witnessed(
        "library.peer.messages.shared_connection",
        "a message is never taken for an action on the shared connection",
    ),
    Capability::witnessed(
        "library.peer.inbox.dispatch",
        "one reader decides by the frame's magic which layer owns a stream, so a message is never taken for an action nor an action for a message, in either direction",
    ),
    Capability::witnessed(
        "library.peer.inbox.one_reader",
        "the summary scan proves the pair's connection is accepted in two files and no third — the binding exchange and the inbox, the only two the exemption table excuses — and that each of them has at most one `accept_bi` call site, held to at least one by the exemption test, with the exemption table and the acceptor list pinned to name the same files; the case pins both checkers' controls",
    ),
    Capability::witnessed(
        "library.peer.actions.unreadable_answered",
        "a malformed action frame is answered unreadable rather than executed or ignored",
    ),
    Capability::witnessed(
        "library.peer.actions.throttle",
        "a peer that sends too many actions is told to slow down rather than ignored, and the crate never re-offers by itself",
    ),
    Capability::witnessed(
        "library.peer.actions.separate_window",
        "the action window is its own, so a flood of actions cannot throttle the same peer's messages",
    ),
    Capability::witnessed(
        "library.peer.actions.slow_down_not_traffic",
        "a slow-down means the receiving side took nothing, so it is not the pair's traffic and a connection that drops after one is not a link failure",
    ),
    Capability::witnessed(
        "library.peer.actions.retry_after_bounded",
        "a peer's slow-down delay never reaches the caller above one ACTION_WINDOW: the wire clamps it when it is read, and a delay this machine writes is already bounded by its own window",
    ),
    Capability::witnessed(
        "library.peer.actions.not_on_the_beacon",
        "the beacon never carries an action and never holds one, and an action still runs with the beacon gone",
    ),
    Capability::witnessed(
        "library.peer.actions.dial_on_demand",
        "an action asked for while the pair is away waits for the dial and then runs",
    ),
    Capability::witnessed(
        "library.peer.actions.no_queue",
        "a failed dial holds nothing: there is no action queue and no store-and-forward",
    ),
    Capability::witnessed(
        "library.peer.actions.execution_bounded",
        "a slow execution is reported as unknown and its identifier stays remembered, because the action may have run",
    ),
    Capability::witnessed(
        "library.peer.actions.one_pair_at_a_time",
        "a slow execution holds its own pair and no other",
    ),
    Capability::witnessed(
        "library.peer.actions.service_reports_a_broken_memory",
        "an action memory that cannot be read or written ends the service with that refusal rather than being stepped over",
    ),
    Capability::witnessed(
        "library.peer.actions.offering_is_not_traffic",
        "an action in flight does not count as the pair's traffic for the keeper, so a connection closed with the request still unanswered is one dial of the pair's recovery — counted, with the connection that carried nothing as its cause — and not a pair that was used",
    ),
    Capability::witnessed(
        "library.peer.actions.answered_is_traffic",
        "only an answer that means the receiving side accepted the operation — it ran, ran with a result too large to carry, or the identifier was already spent — is the pair's traffic; a refusal or a slow-down is not, so a machine holding one unanswered action is not re-dialled for ever",
    ),
    Capability::witnessed(
        "library.peer.actions.execution_panic",
        "a panicking executor ends the service with the bug named; the sender keeps the identifier's durable unknown mark and the crate never offers it again",
    ),
    Capability::witnessed(
        "library.peer.actions.execution_panic_eager",
        "an executor that panics before it returns its future ends the service with the bug named, exactly as one that panics while running does",
    ),
    Capability::witnessed(
        "library.peer.actions.identifier_hex",
        "an identifier has one lowercase-hex spelling, and `ActionId::from_hex` reads exactly that text back; uppercase, the wrong length and non-hex are refused",
    ),
    Capability::witnessed(
        "library.peer.actions.audit_fault",
        "a log the machine cannot write at all — the append's hard fault, not the cap's refusal — stops the action from running, answers the sender `not recorded`, and ends the service with the log's fault named",
    ),
    Capability::witnessed(
        "library.peer.actions.not_sent_not_spent",
        "a request that never left the machine — the stream could not be opened before the budget passed — is answered `not sent`, the identifier is not marked unknown, and the same operation runs once the peer has stream credit again",
    ),
    Capability::unproducible(
        "library.peer.connect.real_network",
        "a direct path over a real network: two machines reach each other at their own addresses with no relay in the path",
        "the suite opens no socket and starts no process, so no real path exists here; the simulated link proves the address and the topology, not the network",
        "on two hosts with a reachable beacon: start the beacon, run one installation per host with its own storage root, pair them by the six-symbol comparison, then dial the peer and read `Connection::remote_address` — it is the peer's own address, the beacon's address never appears on the path, and `ss -u` on either host shows no relay",
    ),
    Capability::unproducible(
        "library.peer.record.crash_mid_publish",
        "a crash between writing a record beside its path and publishing it leaves the previous record in place, never a partial one",
        "the suite starts no process, so it cannot kill one at the instant between the write and the rename; every publish is flushed before the rename, so what a crash can still lose is the directory entry, not the file's contents",
        "in a scratch root, run a process that rewrites one peer record in a loop and kill it with SIGKILL at a random instant; reopen the store — the record is the previous one or the new one, never a partial file, and a leftover `.peer.` temporary file is ignored because it is not a `*.record`",
    ),
    Capability::unproducible(
        "library.peer.record.windows_dacl",
        "a peer record or the `peers/` directory reachable by an account other than the product's, SYSTEM and Administrators is refused loudly on Windows",
        "no case builds the access-list state the Windows reader refuses: granting a second account read access needs an elevated prompt and a second account, and the suite spawns no process and holds one account; the rule is type-checked for both Windows targets and witnessed as data (`library.identity.access.dacl_rule`), and the first run on Windows is the operator's. The first open on an empty root is not a refusal: the store gives the `peers/` directory it creates the explicit three-account list, with inheritance switched off, before it reads it",
        "in a scratch root on Windows, open the store once on an empty root — it creates `peers/`, and `icacls \"%peers%\"` shows the owner, SYSTEM and Administrators with no `(I)` entries — then run `icacls` to grant a second account read access to one `*.record` file and reopen the store: the refusal names the file and the account; repeat on the `peers/` directory itself, which the store checks on every open; `icacls \"%record%\" /inheritance:r /grant:r \"%USERNAME%\":F` restores it and the same store opens",
    ),
    Capability::unproducible(
        "library.peer.audit.crash_mid_append",
        "a crash between appending an entry and the act it describes leaves the entry on file and never an act nobody recorded, and a half-written entry is cut back on the next open",
        "the suite starts no process, so it cannot kill one between the append's flush and the record's write; the order is what the case can prove — the entry is flushed before the record changes — and what a crash can still leave is a recorded act that did not happen",
        "in a scratch root, run a process that grants and withdraws one right in a loop and kill it with SIGKILL at a random instant; reopen the log — every complete entry is there, at most the last is cut back, and every grant on file has either the right it names or a later refusal of it",
    ),
    Capability::unproducible(
        "library.peer.audit.windows_dacl",
        "an audit log reachable by an account other than the product's, SYSTEM and Administrators is refused loudly on Windows",
        "no case builds the access-list state the Windows reader refuses: granting a second account read access needs an elevated prompt and a second account, and the suite spawns no process and holds one account; the rule is type-checked for both Windows targets and witnessed as data (`library.identity.access.dacl_rule`)",
        "in a scratch root on Windows, open the log once on an empty root — it creates `audit.log`, and `icacls \"%audit%\"` shows the owner, SYSTEM and Administrators with no `(I)` entries — then run `icacls` to grant a second account read access and reopen: the refusal names the file and the account; `icacls \"%audit%\" /inheritance:r /grant:r \"%USERNAME%\":F` restores it and the same log opens",
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
        "harness.pair.mediator",
        "the rig's mediator is a party with its own key, its own address and its own registration at the beacon — checked by the interposition case — so the two transcripts it sits between genuinely differ",
    ),
    Capability::witnessed(
        "harness.machine.restart",
        "a machine restarts over its own root: the identity and the record survive, the address is new, and the transport has let go of the old socket before the new one is attached",
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
        "a dial over a link that drops everything ends at a deterministic virtual instant instead of hanging",
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
        "a dial abandoned mid-handshake leaves nothing behind: the next dial on the same pair refuses the aborted connection and completes",
    ),
    Capability::witnessed(
        "harness.connect.retry_after_timeout",
        "a dial that timed out can be retried on the same pair at once: the retry is a working connection, and the server keeps at most one filed connection per dialer",
    ),
    Capability::witnessed(
        "harness.connect.custom_endpoint",
        "an endpoint the caller built serves one dial: a closed endpoint is reported as closed instead of timing out",
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
        "the unix rule refuses group and other bits before ownership, accepts owner-only modes including read-only, refuses another owner as ownership, and reports the more useful of the two facts when both hold; the mode refusal — with the directory's own repair, `chmod 700`, and a file's `chmod 600` — the two shapes both readers refuse (a symbolic link and a non-regular file) and the storage root's unix clauses print the documented wording on every host",
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
///
/// A witness names every capability its case speaks for — the rig's mediator speaks
/// for both the ceremony's interposition and the harness capability — and its case
/// runs once; each entry gets the verdict.
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
            .any(|witness| witness.capabilities.contains(&capability.id));
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
        let mut runs = Vec::new();
        for capability in witness.capabilities {
            let Some(entry) = inventory.iter().find(|entry| entry.id == *capability) else {
                report.violations.push(Violation::OrphanWitness {
                    witness: witness.id,
                    capability,
                });
                continue;
            };
            if entry.unproducible.is_some() {
                report.violations.push(Violation::WitnessForUnproducible {
                    witness: witness.id,
                    capability,
                });
                continue;
            }
            runs.push(*capability);
        }
        if runs.is_empty() {
            continue;
        }
        let outcome = std::panic::catch_unwind(witness.case);
        for capability in runs {
            match &outcome {
                Ok(Ok(())) => {}
                Ok(Err(detail)) => report.violations.push(Violation::Failed {
                    witness: witness.id,
                    capability,
                    detail: detail.clone(),
                }),
                Err(payload) => report.violations.push(Violation::Panicked {
                    witness: witness.id,
                    capability,
                    detail: crate::report::panic_message(payload.as_ref()),
                }),
            }
        }
    }

    report
}
