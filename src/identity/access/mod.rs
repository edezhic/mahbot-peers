//! Who may reach the key file.
//!
//! The rule is one sentence — nobody but the owner, and on Windows the two system
//! accounts a backup needs — but the facts that decide it come from three different
//! places: unix mode bits and ownership, a macOS extended access list, a Windows
//! DACL. Each platform reader gathers facts and a pure rule answers, so the decision
//! itself is compiled and witnessed on every host, and only the reading is bound to
//! its platform.
//!
//! # What a refusal says
//!
//! A refusal is a [`KeyFileError`](crate::identity::keyfile::KeyFileError). It prints
//! the path, then `is not private:`, then the fact, then — where its platform has
//! one command that repairs that fact — that command, with the same path, quoted for
//! the shell that platform's tool takes. The command is therefore runnable as
//! printed, and names the object the message is about. The repair is never presented
//! as a general rule: `chmod` repairs a unix mode, `chmod -N` a macOS entry, `icacls`
//! a Windows list, and each is quoted for its own tool rather than for the host that
//! happens to print the message. A unix ownership refusal has no command of its own:
//! the rule accepts one owner, the account the process runs as, so handing the file
//! back is a command run as that account — not as this process, if the operator started
//! it as root. On Windows the owner is a name, so `icacls /setowner` is the command.
//!
//! The fact is [`Insecurity`](crate::identity::access::Insecurity)'s `Display` and the
//! command is built from the same path, so this table is the exact text and not a
//! paraphrase. `'<path>'` is a POSIX-quoted path and `"<path>"` a `cmd.exe` one; an
//! account is a login name and number on unix, and on Windows the name the platform
//! gives it — or, when it has none, the platform's own SDDL spelling of the SID
//! (`S-1-…`, which `icacls` takes with a leading `*`). Account names and SID spellings
//! come from `LookupAccountSidW` and `ConvertSidToStringSidW`, so they are the
//! platform's text, and this table quotes the fact around them rather than them.
//! `0644`, `nobody`, the account the product runs as and `Everyone` stand for the mode,
//! the accounts and the entry a message finds. Each name and number in a message is the
//! platform's own — `nobody` is 4294967294 on macOS and 65534 on Linux, a login's number
//! is whatever that machine gave it — so the table prints the shape and the platform
//! fills it in.
//!
//! | Refusal | Platform | What it says | What it appends |
//! | --- | --- | --- | --- |
//! | `Mode` | unix | group or other permission bits are set (mode 0644) | `chmod 600 '<path>'` |
//! | `Owner` | unix | it belongs to account `<owner>`, not to account `<me>`, each with the login name and number the platform reports | nothing |
//! | `ForeignOwner` | Windows | it belongs to `Administrators`, which may rewrite the list | `icacls "<path>" /setowner "%USERNAME%"` |
//! | `Unowned` | Windows | it has no owner at all, so no account can be named as owning it | `icacls "<path>" /setowner "%USERNAME%"` |
//! | `Symlink` | unix, Windows | it is a symbolic link, which is never followed | nothing |
//! | `NotRegular` | unix, Windows | it is not a regular file | nothing |
//! | `AccessList`, macOS entry | macOS | extended access entries allow an account other than the owner | `chmod -N '<path>'` |
//! | `AccessList`, inherited | Windows | its access list is inherited from the directory | `icacls "<path>" /inheritance:r /grant:r "%USERNAME%":F` |
//! | `AccessList`, no list | Windows | it carries no access list at all, so every account is allowed | nothing |
//! | `AccessList`, fourth account | Windows | it allows `Everyone`, which is not the owner, SYSTEM or Administrators | nothing |
//! | `AccessList`, unattributable entry | Windows | it has an access entry this reader cannot attribute to an account, which may allow an account that is not the owner, SYSTEM or Administrators | nothing |
//!
//! The four Windows access-list shapes and the macOS one each have their own fact. The
//! rule appends a command only when the path and this process's own account are all it
//! takes: `chmod -N` for the macOS entry, and the protected list for the inherited one,
//! which grants the file back to `%USERNAME%`. The repairs it cannot emit are given once
//! below, one bullet per cause — the owner's, the two calls for a missing or
//! unattributable list, the one call that removes a fourth account, which must name the
//! account the message reports, and the object replaced for a link or a non-regular
//! file.
//!
//! - `Owner`: `chown <account> '<path>'`, run by root, with the account the product
//!   runs as in place of `<account>`; `sudo chown "$(id -un)" '<path>'` does it when
//!   you are already that account and are not root.
//! - no list: `icacls "<path>" /reset`, then the protected list of the inherited row.
//! - fourth account: `icacls "<path>" /remove:g "<account>"`, with the account the
//!   message names in place of `<account>` — preceded by `*` inside the quotes when the
//!   message gave a `S-1-…` SID instead of a name, because `icacls` requires it before
//!   a SID.
//! - unattributable entry: `icacls "<path>" /reset`, then the protected list of the
//!   inherited row; no `icacls` flag writes an access entry of a type this reader does
//!   not parse, and a SID the platform can neither name nor spell has no command of its
//!   own either.
//! - link or non-regular file: the object at the path is removed, so the next create
//!   mints a key file where a regular file belongs.
//!
//! A storage root is refused with its own message rather than the file's:
//! `the storage root <root> gives a new key file an access that is not private: `, then
//! the same fact, then `; no key was written, and the directory is what has to change`
//! (or `and the account the new file belongs to`, when the ownership is the cause, or
//! `and the ownership of the new file`, when there is no owner), then the command for
//! the root only when one repairs the directory in place: a macOS entry and an
//! inherited Windows list do, every other cause does not.
//!
//! Two accounts are named where the refused file belongs to another: on unix by login
//! name and number (the number alone when it cannot be resolved); on Windows by the
//! owning account's name, except the two built-in accounts, which are always spelled
//! `SYSTEM` and `Administrators` — the names the rule itself uses — with `%USERNAME%`
//! in the command for the account that runs the product. `%USERNAME%` is a cmd.exe
//! expansion, so the Windows commands are run in a command prompt of that account. A
//! message about a storage root rather than a file names the root and appends the
//! repair for the root, which exists, when the cause has one.
//!
//! Refusing too much is the safe direction — a key file that only its owner can read
//! is accepted even when it is stricter still.
//!
//! The rules — [`unix_refusal`](crate::identity::access::unix_refusal),
//! [`acl_refusal`](crate::identity::access::acl_refusal),
//! [`dacl_refusal`](crate::identity::access::dacl_refusal) and the plain types they
//! take — are public on purpose: the harness decides them as data on every host, so
//! a rule bound to a platform nothing here runs is still witnessed where it can be.
//! That exposure is part of this crate's surface, like `tls`'s refusal type.

use std::fmt;
use std::fs::File;
use std::path::Path;

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

/// Why the key file is reachable by someone other than its owner.
///
/// The variants are per platform because the facts are: mode bits exist on unix,
/// access lists on macOS and Windows. A variant that only one reader can produce says
/// so in its own documentation; [`Self::Symlink`], [`Self::NotRegular`] and
/// [`Self::AccessList`] are produced by more than one. `Display` prints the fact
/// alone; the command that repairs it is built when the message is printed, because it
/// needs the path, and [`crate::identity::keyfile::KeyFileError`] prints the two
/// together — the table in the module documentation is the exact wording of both.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Insecurity {
    /// Group or other permission bits are set. Unix only: a Windows file has no
    /// mode, and what makes it reachable there is reported as [`Self::AccessList`]
    /// or [`Self::ForeignOwner`].
    Mode {
        /// The permission bits that were found, `0o777`-masked.
        mode: u32,
    },
    /// The file belongs to another account. Unix's spelling, reported with both
    /// accounts: the owner and this process's, each as its login name and number
    /// where the platform that prints the message has a name for it, and as the
    /// number alone where it does not. Its fact is
    /// `it belongs to account <owner>, not to account <me>`, with the platform's own
    /// names and numbers in place of the two.
    ///
    /// This rule speaks when the process can still open the file — as root, or
    /// through an access list — because otherwise the open itself is what refuses the
    /// key. No command is appended: the rule accepts one owner, the account the process
    /// runs as, so the repair is to hand the file back to the account the product is
    /// meant to run as and start it there, which is a command for that account rather
    /// than for a process the operator started as root.
    ///
    /// Windows reports the same fact as [`Self::ForeignOwner`], because the account
    /// there is a name rather than a number.
    Owner {
        /// The account that owns the file.
        owner: u32,
        /// The account this process runs as.
        me: u32,
    },
    /// The file belongs to another account. An owner may rewrite the access list of
    /// what it owns, so that account can open the key whatever the list says. This
    /// is Windows's spelling of the fact [`Self::Owner`] reports on unix, kept apart
    /// because the name it carries is what `icacls /setowner` takes.
    ///
    /// The fact names that account, and the command is
    /// `icacls "<path>" /setowner "%USERNAME%"`; `%USERNAME%` is the account the
    /// product runs as, so the repair is run in a cmd.exe prompt of that account.
    ForeignOwner {
        /// The owning account, as the platform names it.
        owner: String,
    },
    /// The file has no owner at all, so no account can be named as owning it — and
    /// an object nobody owns is an object whose access list is the only thing keeping
    /// it private. Windows only: its reader reports a null owner SID this way. The
    /// repair is the one [`Self::ForeignOwner`] uses: make the account the product runs
    /// as its owner. The list itself is judged on the next load, after the owner is
    /// repaired, so a file that is also unprotected reports that then rather than
    /// hiding it.
    Unowned,
    /// The path is a symbolic link. It is never followed: the link is somebody
    /// else's choice of file, and its target's permissions are not this file's.
    Symlink,
    /// The path is not a regular file.
    NotRegular,
    /// The platform's own access list grants access past the owner: a macOS extended
    /// allow entry, or a Windows DACL that is absent, inherited from the directory,
    /// names an account outside the owner, `SYSTEM` and `Administrators`, or carries
    /// an entry this reader cannot attribute to an account.
    ///
    /// The four Windows shapes and the macOS one have different facts and different
    /// repairs, given in the module documentation; `detail` is the fact and `remedy`
    /// is the one command the rule can emit for this cause, if any. The repair of
    /// every other shape is in the module documentation's bullets, and none of them is
    /// restated here.
    AccessList {
        /// What the list says, in the platform's own terms, as a predicate about
        /// the file.
        detail: String,
        /// The command the rule can emit for this cause: only the macOS entry and an
        /// inherited Windows list have one, the other shapes' repairs being in the
        /// module documentation.
        remedy: Option<Remedy>,
    },
}

/// The one command that repairs an access-list refusal, on the platform that produced
/// it.
///
/// A command rather than a string because `icacls` takes the file first and `chmod`
/// last: the path is supplied when the message is printed, so the command an operator
/// reads names this file in the position its own tool requires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Remedy {
    /// `chmod -N <path>`: removes every extended access entry from a macOS file, the
    /// entries that reach past its owner included.
    ClearExtendedEntries,
    /// `icacls <path> /inheritance:r /grant:r "%USERNAME%":F`: replaces a Windows
    /// list with a protected one granting the process's account full control, because
    /// removing inheritance alone would leave a list that denies that account too.
    ProtectWindowsList,
}

impl Remedy {
    /// The shell this command is written for: the one its own tool parses, not the
    /// one the host printing the message has.
    const fn shell(self) -> Shell {
        match self {
            Self::ClearExtendedEntries => Shell::Posix,
            Self::ProtectWindowsList => Shell::Cmd,
        }
    }

    /// The command, with `path` in the position the tool takes it.
    fn command(self, path: &Path) -> String {
        let path = self.shell().quote(path);
        match self {
            Self::ClearExtendedEntries => format!("chmod -N {path}"),
            Self::ProtectWindowsList => {
                format!(r#"icacls {path} /inheritance:r /grant:r "%USERNAME%":F"#)
            }
        }
    }
}

/// The shell a refusal's command is written for.
///
/// A Windows refusal is decided as data on every host (the rule is compiled and
/// witnessed everywhere), so the quoting follows the platform that produced the
/// refusal rather than the one that prints it: otherwise `icacls` would be handed a
/// single-quoted path on a unix host, which is not the command Windows prints.
#[derive(Clone, Copy)]
enum Shell {
    /// A POSIX shell: single quotes, with an embedded quote written `'\''`.
    Posix,
    /// `cmd.exe`: double quotes, which is what `icacls` expects around a path with
    /// spaces. A Windows path cannot contain a double quote.
    Cmd,
}

impl Shell {
    fn quote(self, path: &Path) -> String {
        let text = path.display().to_string();
        match self {
            Self::Posix => format!("'{}'", text.replace('\'', r"'\''")),
            Self::Cmd => format!("\"{text}\""),
        }
    }
}

impl Insecurity {
    /// Write the fact alone, without the remedy.
    ///
    /// A refusal about a storage root uses this: the object that has to change is the
    /// root rather than the key file, and the root is named in front of it. The root's
    /// own message prints the command from [`Self::remedy`] after it when the cause has
    /// one — about the root, which exists — so an access entry an inheriting root hands
    /// to a new key file still says `chmod -N`.
    pub(crate) fn write_fact(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mode { mode } => {
                write!(
                    f,
                    "group or other permission bits are set (mode {mode:04o})"
                )
            }
            Self::Owner { owner, me } => {
                write!(
                    f,
                    "it belongs to account {}, not to account {}",
                    account(*owner),
                    account(*me)
                )
            }
            Self::ForeignOwner { owner } => {
                write!(f, "it belongs to `{owner}`, which may rewrite the list")
            }
            Self::Unowned => {
                f.write_str("it has no owner at all, so no account can be named as owning it")
            }
            Self::Symlink => f.write_str("it is a symbolic link, which is never followed"),
            Self::NotRegular => f.write_str("it is not a regular file"),
            Self::AccessList { detail, .. } => f.write_str(detail),
        }
    }

    /// The command that fixes this refusal, where one does, for the file or directory
    /// at `path`.
    ///
    /// The quoting is the shell of the platform that produced the refusal, decided by
    /// the cause rather than by the host: `chmod` takes a POSIX argument and `icacls`
    /// a `cmd.exe` one on every host. The unix ownership cause has no command — the
    /// module documentation gives the form for the account the product runs as; on
    /// Windows the owner is a name, so `icacls /setowner` repairs it.
    pub(crate) fn remedy(&self, path: &Path) -> Option<String> {
        match self {
            Self::Mode { .. } => Some(format!("chmod 600 {}", Shell::Posix.quote(path))),
            Self::ForeignOwner { .. } | Self::Unowned => Some(format!(
                r#"icacls {} /setowner "%USERNAME%""#,
                Shell::Cmd.quote(path)
            )),
            Self::AccessList {
                remedy: Some(remedy),
                ..
            } => Some(remedy.command(path)),
            Self::Owner { .. } | Self::Symlink | Self::NotRegular | Self::AccessList { .. } => None,
        }
    }
}

/// An account as a message names it: its login name and number when the platform
/// resolves the number, the number alone when it does not.
///
/// Names are read here rather than in the rule because the rule is decided as data
/// on every host, and a host that is not unix has no account directory to read.
fn account(uid: u32) -> String {
    #[cfg(unix)]
    {
        if let Some(name) = unix::account_name(uid) {
            return format!("`{name}` ({uid})");
        }
    }
    format!("`{uid}`")
}

/// The fact alone. [`crate::identity::keyfile::KeyFileError`] prints the path and,
/// when the cause has one, the command: a command without the path it applies to is
/// not a command an operator can run.
impl fmt::Display for Insecurity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_fact(f)
    }
}

/// What opening the key file found.
pub(crate) enum Opening {
    /// The file is there, and this descriptor is what a key must be read from:
    /// the facts checked and the bytes read describe the same file.
    File(File),
    /// Nothing is at that path.
    Absent,
    /// Something is at that path that must not be read as a key.
    Refused(Insecurity),
}

/// Open the key file for reading without following a link and without waiting on
/// anything that is not a regular file.
pub(crate) fn open(path: &Path) -> std::io::Result<Opening> {
    #[cfg(unix)]
    {
        unix::open(path)
    }
    #[cfg(windows)]
    {
        windows::open(path)
    }
}

/// Check the open key file, and answer with the reason it is reachable by
/// somebody other than its owner.
///
/// The facts are read from the descriptor, not from the path: what is checked and
/// what is read are then the same file, whatever a link or a rename did in
/// between.
pub(crate) fn check(file: &File) -> std::io::Result<Option<Insecurity>> {
    #[cfg(unix)]
    {
        unix::check(file)
    }
    #[cfg(windows)]
    {
        windows::check(file)
    }
}

/// Give a freshly created key file the access its rule requires.
///
/// Unix pins the mode on the descriptor; Windows writes its list and the file's owner
/// by path, because the handle the key file is created through is opened without the
/// right to change either (see `windows::make_private`). Both run before the key's
/// bytes are written, so no private half ever sits behind the wrong access.
#[cfg(unix)]
pub(crate) fn make_private(file: &File, _path: &Path) -> std::io::Result<()> {
    unix::make_private(file)
}

#[cfg(windows)]
pub(crate) fn make_private(_file: &File, path: &Path) -> std::io::Result<()> {
    windows::make_private(path)
}

/// Whether unix mode bits and ownership keep the file to its owner.
///
/// Owner read and write is the intended state; owner-only execute or a read-only
/// file is stricter and accepted. Group and other bits are refused whatever they
/// grant: a mode is a summary of many accounts, and the key is one machine's.
///
/// A file that belongs to another account is [`Insecurity::Owner`], which names both
/// accounts when the platform printing the message can resolve them. This rule takes
/// numbers because it is decided as data on every host; the login names are added by
/// the message, where this host can read them.
#[must_use]
// The mask is the rule: group and other bits, and nothing else.
#[allow(clippy::verbose_bit_mask)]
pub fn unix_refusal(mode: u32, owner: u32, me: u32) -> Option<Insecurity> {
    if mode & 0o077 != 0 {
        return Some(Insecurity::Mode { mode: mode & 0o777 });
    }
    if owner != me {
        return Some(Insecurity::Owner { owner, me });
    }
    None
}

/// One entry of a macOS extended access list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    /// Whether the entry allows or denies.
    pub allows: bool,
    /// Whether the entry names the account this process runs as.
    pub owner: bool,
}

/// Whether an extended access list keeps the file to its owner.
///
/// A deny entry only narrows access and is accepted. An allow entry that names the
/// account this process runs as is that account's own right and is accepted. Any
/// other allow entry is refused: the reader maps an entry's UUID to a directory
/// account and compares it with the effective account, so an entry naming a
/// different account counts, and so does one it cannot attribute — an entry with no
/// qualifier names everyone — since a refusal here costs an operator one `chmod -N`.
///
/// The remedy it reports is macOS's, and this rule is decided on every host as
/// data; only the macOS reader feeds it in production, so no other host's message
/// ever advises `chmod -N` about a file.
#[must_use]
pub fn acl_refusal(entries: &[Entry]) -> Option<Insecurity> {
    let reaches = entries.iter().any(|entry| entry.allows && !entry.owner);
    reaches.then(|| Insecurity::AccessList {
        detail: "extended access entries allow an account other than the owner".to_owned(),
        remedy: Some(Remedy::ClearExtendedEntries),
    })
}

/// An account a Windows DACL names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Account {
    /// The account this process runs as. As a file's owner it is the only ownership
    /// accepted; as an entry, a permission the product already has.
    Owner,
    /// `NT AUTHORITY\SYSTEM`.
    System,
    /// `BUILTIN\Administrators`.
    Administrators,
    /// Any other account, as the platform printed it: its name when the platform has
    /// one, or its SID in `S-1-…` form when it has none — a spelling the platform
    /// produces, and which `icacls` takes with a leading `*`.
    Other(String),
}

/// One entry of a Windows DACL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaclEntry {
    /// Whether the entry allows or denies. An entry whose type the reader does not
    /// parse is recorded as allowing, because reading past it would be the one way a
    /// grant could be hidden.
    pub allows: bool,
    /// The account the entry names, or `None` when the reader cannot attribute it: its
    /// type is one this reader does not parse, or its SID can be neither named nor
    /// spelled, so no account can be named.
    pub account: Option<Account>,
}

/// A Windows DACL as the platform reader found it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dacl {
    /// The account the object belongs to, which may rewrite the list whatever it
    /// says, or `None` when the object has no owner at all.
    pub owner: Option<Account>,
    /// `false` when the object carries no DACL at all, which grants everything to
    /// everyone.
    pub present: bool,
    /// Whether inheritance from the parent directory is switched off.
    pub protected: bool,
    /// The entries, in the order the object lists them.
    pub entries: Vec<DaclEntry>,
}

/// Whether a DACL keeps the file to its owner.
///
/// The allowed *entries* are the owner, `SYSTEM` and `Administrators`: enforcing
/// that a real installation lists literally one entry would break the key file the
/// first time a backup or an antivirus tool touched it, and would teach operators to
/// loosen the check instead of keeping it. Anything else — an absent or inherited
/// list, a fourth account, or an entry this reader cannot attribute to an account — is
/// a refusal.
///
/// The *owner* must be the account the product runs as, which is a different
/// question from the entries: an owner may rewrite the list of what it owns, so a key
/// file owned by an administrator or by `SYSTEM` is a key that account can read by
/// changing permissions. The Windows writer gives a new key file this process's
/// account as owner, so first creation works whatever token created it; a backup or a
/// restore that changes the owner afterwards is refused as
/// [`Insecurity::ForeignOwner`], and one that leaves the file with no owner at all as
/// [`Insecurity::Unowned`], rather than accepted as a file another account may open.
///
/// A refusal carries the command the rule emits for it, and only an inherited list has
/// one: `icacls <path> /inheritance:r /grant:r "%USERNAME%":F` protects the file and
/// grants it back to the account running the product in one call — removing inheritance
/// alone would leave a list that denies that account too. The absent list, a fourth
/// account and an unattributable entry carry none; the module documentation gives the
/// repair of each, and none of them is a command the path and this process's account
/// are enough to build.
#[must_use]
pub fn dacl_refusal(dacl: &Dacl) -> Option<Insecurity> {
    let list = |detail: &str, remedy: Option<Remedy>| Insecurity::AccessList {
        detail: detail.to_owned(),
        remedy,
    };
    let owner = match &dacl.owner {
        None => return Some(Insecurity::Unowned),
        Some(Account::Owner) => None,
        Some(Account::System) => Some("SYSTEM".to_owned()),
        Some(Account::Administrators) => Some("Administrators".to_owned()),
        Some(Account::Other(name)) => Some(name.clone()),
    };
    if let Some(owner) = owner {
        return Some(Insecurity::ForeignOwner { owner });
    }
    if !dacl.present {
        return Some(list(
            "it carries no access list at all, so every account is allowed",
            None,
        ));
    }
    if !dacl.protected {
        // Removing inheritance alone leaves an empty list, which denies the owner
        // too, so the repair writes the protected list in the same call.
        return Some(list(
            "its access list is inherited from the directory",
            Some(Remedy::ProtectWindowsList),
        ));
    }
    // A named stranger first: it is the shape an operator can act on with a single
    // `/remove:g`, and naming it is more useful than reporting an entry beside it.
    if let Some(name) = dacl
        .entries
        .iter()
        .filter(|entry| entry.allows)
        .find_map(|entry| match &entry.account {
            Some(Account::Other(name)) => Some(name),
            _ => None,
        })
    {
        return Some(list(
            &format!("it allows `{name}`, which is not the owner, SYSTEM or Administrators"),
            None,
        ));
    }
    if dacl
        .entries
        .iter()
        .any(|entry| entry.allows && entry.account.is_none())
    {
        return Some(list(
            "it has an access entry this reader cannot attribute to an account, which may allow \
             an account that is not the owner, SYSTEM or Administrators",
            None,
        ));
    }
    None
}
