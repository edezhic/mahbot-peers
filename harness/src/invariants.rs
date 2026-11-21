//! The workspace's cross-cutting invariants, and the scan that proves each one
//! awake.
//!
//! An invariant is a claim no single module can demonstrate on its own — "nothing
//! reads ambient configuration", "there is one source of time" — so it is checked
//! by scanning sources instead. Two guards keep the check honest: an empty scan
//! is a violation, and every invariant carries a positive control, a snippet its
//! own check must flag. An invariant that has gone blind fails instead of passing
//! over nothing.
//!
//! This file holds the checkers and the table together, and the scan skips it for
//! what it is: it contains the forbidden constructs as data, and a checker's own
//! pattern list is not evidence.
//!
//! One source file beyond this one is exempt from some invariants, and the
//! exemption is data too: the beacon server's process entry point binds a real
//! socket, reads the environment and reads the wall clock, because that is what a
//! process entry point is for. [`EXEMPT`] names it, the invariants it does not
//! answer to, and why; every other invariant judges it like any other source, so
//! its key handling is scanned. The summary check proves the list is exactly that
//! one file, that each exemption is needed, and that nothing else about the file
//! is excused.

use std::fmt;
use std::path::{Path, PathBuf};

/// One source file as the checks see it: a display path and its text.
#[derive(Clone, Debug)]
pub struct Source {
    pub path: String,
    pub text: String,
}

/// One place an invariant does not hold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub path: String,
    pub line: usize,
    pub detail: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.path, self.line, self.detail)
    }
}

/// A claim about the sources, with the control that proves the check can fail.
#[derive(Clone, Copy)]
pub struct Invariant {
    pub id: &'static str,
    pub claim: &'static str,
    /// The files this invariant covers, by display path; an entry ending in `/`
    /// covers everything under that directory. Empty means every source, which is
    /// the usual case; a claim about one module names it here rather than hiding a
    /// path comparison inside its check. A file that does not answer to this
    /// invariant at all says so in [`EXEMPT`].
    pub scope: &'static [&'static str],
    /// A snippet this invariant's check must flag. It is scanned in-process, so
    /// the proof that the check is awake costs no subprocess and no fixture.
    pub control: &'static str,
    pub check: fn(&Source) -> Vec<Finding>,
}

impl Invariant {
    #[must_use]
    pub fn covers(&self, path: &str) -> bool {
        self.scope.is_empty() || in_scope(self.scope, path)
    }
}

/// Whether `path` is one of `scopes`: a file named outright, or anything under an
/// entry that ends in `/`.
fn in_scope(scopes: &[&str], path: &str) -> bool {
    scopes.iter().any(|entry| match entry.strip_suffix('/') {
        Some(_) => path.starts_with(entry),
        None => *entry == path,
    })
}

impl fmt::Debug for Invariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Invariant")
            .field("id", &self.id)
            .field("claim", &self.claim)
            .finish_non_exhaustive()
    }
}

/// One way the invariant set failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Violation {
    Duplicate(&'static str),
    /// The invariant list is empty, so the check proves nothing.
    NoInvariants,
    /// The scan covered no files at all, so every invariant passed vacuously.
    ScannedNothing,
    /// A scoped invariant found no file in its scope, so it checked nothing.
    ScopeNotFound {
        invariant: &'static str,
    },
    /// The invariant's own positive control was not flagged.
    ControlNotCaught {
        invariant: &'static str,
    },
    /// The invariant does not hold somewhere in the scanned sources.
    Found {
        invariant: &'static str,
        finding: Finding,
    },
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duplicate(id) => write!(f, "invariant {id} is listed twice"),
            Self::NoInvariants => f.write_str("the invariant list is empty"),
            Self::ScannedNothing => f.write_str("the scan covered no source files"),
            Self::ScopeNotFound { invariant } => {
                write!(f, "invariant {invariant} found no file in its scope")
            }
            Self::ControlNotCaught { invariant } => {
                write!(f, "invariant {invariant} did not catch its own control")
            }
            Self::Found { invariant, finding } => {
                write!(f, "invariant {invariant} does not hold at {finding}")
            }
        }
    }
}

/// What the scan found.
pub type Report = crate::report::Report<Violation>;

/// Check every invariant over every source, and prove each check awake with its
/// control. An empty source list is a violation, not a pass.
#[must_use]
pub fn check(invariants: &[Invariant], sources: &[Source]) -> Report {
    let mut report = Report::new(("files", sources.len()), ("invariants", invariants.len()));
    if invariants.is_empty() {
        report.violations.push(Violation::NoInvariants);
    }
    if sources.is_empty() {
        report.violations.push(Violation::ScannedNothing);
    }
    for (index, invariant) in invariants.iter().enumerate() {
        if invariants[..index]
            .iter()
            .any(|earlier| earlier.id == invariant.id)
        {
            report.violations.push(Violation::Duplicate(invariant.id));
        }
        let control = Source {
            path: "<control>".to_owned(),
            text: invariant.control.to_owned(),
        };
        if (invariant.check)(&control).is_empty() {
            report.violations.push(Violation::ControlNotCaught {
                invariant: invariant.id,
            });
        }
        if !sources.is_empty()
            && !sources
                .iter()
                .any(|source| invariant.covers(&source.path) && !exempt(invariant.id, &source.path))
        {
            report.violations.push(Violation::ScopeNotFound {
                invariant: invariant.id,
            });
        }
        for source in sources
            .iter()
            .filter(|source| invariant.covers(&source.path) && !exempt(invariant.id, &source.path))
        {
            for finding in (invariant.check)(source) {
                report.violations.push(Violation::Found {
                    invariant: invariant.id,
                    finding,
                });
            }
        }
    }
    report
}

/// The code lines of a source, with line numbers: comment-only lines are
/// skipped, so prose may name a forbidden construct while the check still
/// forbids it in code.
fn code_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line))
        .filter(|(_, line)| !line.trim_start().starts_with("//"))
}

/// Every code line of `source` that contains one of `needles`.
///
/// This is the whole of most invariants: a needle is a construct the workspace
/// promises not to use, and the finding names the line that uses it.
#[must_use]
pub fn forbidden(source: &Source, needles: &[&str]) -> Vec<Finding> {
    code_lines(&source.text)
        .filter_map(|(line, text)| {
            let needle = needles.iter().find(|needle| text.contains(**needle))?;
            Some(Finding {
                path: source.path.clone(),
                line,
                detail: format!("uses `{needle}`: {}", text.trim()),
            })
        })
        .collect()
}

/// The one file allowed to read the wall clock: it captures the origin every
/// virtual instant is measured from.
pub const CLOCK_FILE: &str = "harness/src/clock.rs";

/// The file that holds the checkers and this table. It is not scanned: it
/// contains the forbidden constructs as data, and a checker's own pattern list is
/// not evidence.
pub const TABLE_FILE: &str = "harness/src/invariants.rs";

/// The beacon server's process entry point: the one file with an exemption.
pub const ENTRY_FILE: &str = "beacon-server/src/main.rs";

/// A source file that some invariants do not cover, and why.
///
/// The exemption is per invariant, not per file: a file listed here is scanned
/// like any other by every invariant not named in [`Exemption::exempt_from`], so an
/// exemption cannot hide a claim the file is still supposed to answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Exemption {
    pub path: &'static str,
    /// The invariants this file does not answer to, by id.
    pub exempt_from: &'static [&'static str],
    pub reason: &'static str,
}

/// The documented exemptions: exactly one file, and the summary check proves both
/// that each listed invariant is still tripped by the file and that no other one
/// is.
pub const EXEMPT: &[Exemption] = &[Exemption {
    path: ENTRY_FILE,
    exempt_from: &[
        "workspace.no_ambient_configuration",
        "workspace.no_real_sockets",
        "workspace.single_source_of_time",
    ],
    reason: "the process entry point: it binds the UDP socket, reads the listening address and the directory holding its key from the command line, owns the executor and the wall clock. Everything else is scanned here like anywhere: how the command line is read, what it means and how the server is configured are pure functions in `mahbot-beacon`, and the key file is the peer library's `identity.key`, reached only through `keyfile::load_or_create` — so it stays under `identity.key_is_never_replaced`, `identity.key_file_name_is_one_place` and `identity.key_is_minted_in_one_place`, as a machine's identity is.",
}];

/// Whether `path` does not answer to the invariant `id`: only a documented
/// exemption excuses a file, and only from the invariants it names.
#[must_use]
pub fn exempt(id: &str, path: &str) -> bool {
    EXEMPT
        .iter()
        .any(|exemption| exemption.path == path && exemption.exempt_from.contains(&id))
}

/// The handle that must not name a path.
pub const MACHINE_FILE: &str = "harness/src/machine.rs";

/// The only source that may name or write the key file, and the only one that may
/// mint a key.
pub const KEY_FILE_SOURCE: &str = "src/identity/keyfile.rs";

/// The module that owns the key file, as a directory scope: the invariant that no
/// source replaces it covers these files, and reaching the key from anywhere else
/// would take its name, which `identity.key_file_name_is_one_place` forbids.
pub const IDENTITY_SCOPE: &[&str] = &["src/identity.rs", "src/identity/"];

/// The crates the scan covers, as directory scopes: a claim about what this
/// workspace ships leaves the test rig out, since the rig produces the very file
/// states the key invariants forbid.
///
/// A summary check asserts that every scanned source is inside this list or inside
/// [`UNSHIPPED_SCOPE`], so a crate added beside these cannot stay outside the
/// key-name invariant by being forgotten here.
pub const SHIPPED_SCOPE: &[&str] = &["src/", "beacon/", "beacon-server/"];

/// The scanned trees that are not shipped library code: the test rig, the Windows
/// type-check crate, and the root package's dev targets and build script.
pub const UNSHIPPED_SCOPE: &[&str] = &[
    "harness/",
    "windows-check/",
    "tests/",
    "benches/",
    "examples/",
    "build.rs",
];

/// The literal name of the key file, as a code path that means to reach it has to
/// spell it, for the invariant that only one file does.
pub const KEY_FILE_NAME: &str = r#""identity.key""#;

/// The call that mints a key, for the invariant that only one place does.
pub const KEY_MINT: &str = "generate_pkcs8";

/// Every other way to build a key pair, so a second minting path cannot be added
/// under a different name.
pub const MINT_FORMS: &[&str] = &[KEY_MINT, "from_seed", "maybe_unchecked"];

/// Every form of ambient read the configuration scanner must catch, and the
/// look-alikes it must leave alone. They live in this file because it is the one
/// file the scan skips: a scanner's own pattern list is not evidence, but the
/// witness that proves the scanner awake needs the patterns somewhere.
pub const AMBIENT_FORMS: &[&str] = &[
    r#"let root = std::env::var("MAHBOT_ROOT");"#,
    "use std::env;",
    "let dir = env::temp_dir();",
    "let exe = env::current_exe();",
    "let home = env::home_dir();",
    "let args: Vec<_> = env::args_os().collect();",
    "let cwd = env::current_dir();",
    "let root = std::env::temp_dir();",
];

pub const AMBIENT_LOOKALIKES: &[&str] = &[
    r#"let name = "MAHBOT_ROOT";"#,
    r#"const ENV_PREFIX: &str = "env";"#,
    r#"let value = configuration::lookup("root");"#,
    "// std::env::var is forbidden here",
];

/// Every form of `static` declaration the process-global-state scanner must
/// catch, and the look-alikes it must leave alone.
pub const STATIC_FORMS: &[&str] = &[
    "static A: u32 = 0;",
    "pub static B: u32 = 0;",
    "pub(crate) static C: u32 = 0;",
    "pub (crate) static C2: u32 = 0;",
    "pub(self) static D: u32 = 0;",
    "pub(super) static E: u32 = 0;",
    "pub(in crate::x) static F: u32 = 0;",
    "#[cfg(test)] static G: u32 = 0;",
    "#[cfg(test)] pub(super) static H: u32 = 0;",
    "static mut I: u32 = 0;",
    "pub static",
];

pub const STATIC_LOOKALIKES: &[&str] = &[
    "let static_value = 1;",
    "const LIMIT: u32 = 1;",
    "pub(crate) const OTHER: u32 = 1;",
    "pub(in crate::x) const THIRD: u32 = 1;",
    "pub use foo::statics;",
    "pub fn statically() {}",
];

pub const INVARIANTS: &[Invariant] = &[
    Invariant {
        id: "workspace.no_ambient_configuration",
        claim: "no source performs a runtime environment lookup — a variable, an argument, the working, home or temporary directory, or the executable's own path",
        scope: &[],
        control: r#"let root = std::env::var("MAHBOT_ROOT").unwrap();"#,
        check: no_ambient_configuration,
    },
    Invariant {
        id: "workspace.no_process_global_state",
        claim: "no source opens a line with a `static` item — any visibility, any attribute prefix — and no source names a once, lazy or thread-local cell",
        scope: &[],
        control: "#[cfg(test)]\npub(super) static CURRENT_ROOT: AtomicU64 = AtomicU64::new(0);",
        check: no_process_global_state,
    },
    Invariant {
        id: "workspace.single_source_of_time",
        claim: "time comes from the injected clock: no wall-clock instant, no sleep, no runtime timer",
        scope: &[],
        control: "let started = std::time::Instant::now();",
        check: single_source_of_time,
    },
    Invariant {
        id: "workspace.no_real_sockets",
        claim: "datagrams travel only through the abstract-socket seam; no source creates a real socket",
        scope: &[],
        control: r#"let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;"#,
        check: no_real_sockets,
    },
    Invariant {
        id: "workspace.no_external_processes",
        claim: "the suite needs no external host: no source spawns a process",
        scope: &[],
        control: r#"let out = std::process::Command::new("git").output()?;"#,
        check: no_external_processes,
    },
    Invariant {
        id: "harness.handle_names_no_path",
        claim: "the file holding the machine handle names no `Path` type, so a direct path accessor cannot be added unnoticed",
        scope: &[MACHINE_FILE],
        control: "pub fn root(&self) -> &Path { &self.root }",
        check: handle_names_no_path,
    },
    Invariant {
        id: "identity.key_is_never_replaced",
        claim: "no shipped source removes a directory, copies a path or calls `fs::rename` — any can take the key with the path it lives in or clone the identity; the peer record's publish renames a temporary file of its own into place through `tempfile`, which moves no key and replaces no file but the record it just wrote; and no source of the identity module truncates, deletes, copies onto or overwrites the key file: the one write path publishes a new file beside it, and a publish that would clobber an existing key is not on this list",
        scope: SHIPPED_SCOPE,
        control: "std::fs::remove_dir_all(&root)?;",
        check: no_key_replacement,
    },
    Invariant {
        id: "identity.key_file_name_is_one_place",
        claim: "the quoted literal `\"identity.key\"` and the bare name `file_in` — the function that builds the key's path — appear in one source file the crates ship, the key file's own module. Prose that mentions the name reaches no file, and `file_in` is matched at identifier boundaries, so a longer name that ends in it does not count",
        scope: SHIPPED_SCOPE,
        control: r#"let key = root.join("identity.key");"#,
        check: key_file_name_is_one_place,
    },
    Invariant {
        id: "identity.key_is_minted_in_one_place",
        claim: "a key is minted in exactly one place — the create path of the key file's module — and no other source, the test rig included, can generate an identity at all",
        scope: &[],
        control: "let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)?;",
        check: key_is_minted_in_one_place,
    },
    Invariant {
        id: "beacon.no_persistent_state",
        claim: "the beacon keeps no state on disk: neither its protocol and client nor its server library touches a file, so a restart loses every registration by construction",
        scope: &[
            "src/beacon.rs",
            "src/beacon/client.rs",
            "src/beacon/time.rs",
            "src/beacon/wire.rs",
            "beacon/src/clock.rs",
            "beacon/src/config.rs",
            "beacon/src/core.rs",
            "beacon/src/lib.rs",
            "beacon/src/server.rs",
        ],
        control: "std::fs::write(path, bytes)?;",
        check: no_persistent_state,
    },
];

/// The invariant with this id, for a case that has to run one directly.
#[must_use]
pub fn find(id: &str) -> Option<&'static Invariant> {
    INVARIANTS.iter().find(|invariant| invariant.id == id)
}

/// Every source file the invariants cover: the whole workspace, because a
/// wall-clock sleep or an environment lookup in a test breaks the same promises as
/// one in the code under test, and a `build.rs`, `benches/` or `examples/` added to
/// a crate is scanned without this function changing. Two kinds of directory are
/// passed over: `target/`, which holds the dependencies' sources, and dotted
/// directories, which hold tool state. The table is skipped too, and a file's
/// [`EXEMPT`] entry only takes it out of the invariants it names.
///
/// Paths are relative to the workspace root and always use `/`, so a finding
/// reads the same on every host.
#[must_use]
pub fn workspace_sources() -> Vec<Source> {
    let workspace_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the harness sits in the workspace");
    let mut sources = Vec::new();
    for file in rs_files_under(workspace_dir) {
        let relative = file
            .strip_prefix(workspace_dir)
            .expect("sources live under the workspace")
            .components()
            .map(|component| component.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        if relative == TABLE_FILE {
            continue;
        }
        let text = std::fs::read_to_string(&file).expect("a source file reads as utf-8");
        sources.push(Source {
            path: relative,
            text,
        });
    }
    sources.sort_by(|left, right| left.path.cmp(&right.path));
    sources
}

fn rs_files_under(dir: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("a source directory reads") {
            let path = entry.expect("a directory entry reads").path();
            if path.is_dir() {
                // `target/` holds the dependencies' sources and a dotted directory
                // holds tool state: neither is this workspace's code, so both are
                // passed over. A vendored dependency would need its own rule.
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                if name != "target" && !name.starts_with('.') {
                    walk(&path, out);
                }
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                out.push(path);
            }
        }
    }
    let mut files = Vec::new();
    walk(dir, &mut files);
    files
}

fn no_ambient_configuration(source: &Source) -> Vec<Finding> {
    // `env::` catches every runtime lookup, whatever the name — `var`, `args`,
    // `current_dir`, `temp_dir`, `current_exe`, `home_dir`, … — and `std::env`
    // catches the import that would put it behind a shorter path.
    forbidden(source, &["std::env", "std::{env", "env::"])
}

fn no_process_global_state(source: &Source) -> Vec<Finding> {
    let mut findings = forbidden(
        source,
        &[
            "OnceLock",
            "OnceCell",
            "LazyLock",
            "lazy_static",
            "once_cell",
            "thread_local",
        ],
    );
    // A `static` item is process-wide whatever its type: `static mut` and
    // `static AtomicU64` are the same hazard, so the declaration is what is
    // checked, not the mutability keyword.
    for (line, text) in code_lines(&source.text) {
        if declares_static(text) {
            findings.push(Finding {
                path: source.path.clone(),
                line,
                detail: format!("declares process-wide state: {}", text.trim()),
            });
        }
    }
    findings
}

/// Whether one code line opens a `static` item, whatever its visibility and
/// attribute prefix.
///
/// The item may be split across lines (`pub static` and the name on the next),
/// so a line that ends at the `static` keyword counts: the declaration is what
/// matters, not what follows it.
fn declares_static(line: &str) -> bool {
    let mut rest = line.trim();
    // An attribute written on the same line as the item: `#[cfg(test)] static …`.
    while let Some(attribute) = rest.strip_prefix("#[") {
        let Some(end) = attribute.find(']') else {
            return false;
        };
        rest = attribute[end + 1..].trim_start();
    }
    if let Some(visibility) = rest.strip_prefix("pub") {
        let visibility = visibility.trim_start();
        rest = match visibility.strip_prefix('(') {
            Some(group) => match group.find(')') {
                Some(end) => group[end + 1..].trim_start(),
                None => return false,
            },
            None => visibility,
        };
    }
    rest.strip_prefix("static")
        .is_some_and(|after| after.is_empty() || after.starts_with(|c: char| c.is_whitespace()))
}

fn single_source_of_time(source: &Source) -> Vec<Finding> {
    if source.path == CLOCK_FILE {
        return Vec::new();
    }
    forbidden(
        source,
        &[
            "Instant::now",
            "SystemTime::now",
            "thread::sleep",
            "tokio::time",
        ],
    )
}

fn no_real_sockets(source: &Source) -> Vec<Finding> {
    forbidden(
        source,
        &[
            "UdpSocket::bind",
            "TcpListener::bind",
            "TcpStream::connect",
            "UnixListener::bind",
            "UnixStream::connect",
            "UnixDatagram::bind",
            "Socket::new(",
            "Endpoint::new(",
            "Endpoint::client(",
            "Endpoint::server(",
            "from_raw_fd",
        ],
    )
}

fn no_external_processes(source: &Source) -> Vec<Finding> {
    forbidden(source, &["process::Command", "Command::new"])
}

fn handle_names_no_path(source: &Source) -> Vec<Finding> {
    forbidden(source, &["Path"])
}

/// The ways the key can be replaced, or taken away with the path that holds it.
///
/// Removing a directory, copying a path and renaming a path judge every shipped
/// source: the first destroys the key with the directory it lives in, the second
/// clones the identity, and the third can move the storage root or publish over the
/// key. The record publishes with `tempfile`'s persist, not `fs::rename`, so no
/// shipped source needs a rename. The forms that write one file judge the identity
/// module.
fn no_key_replacement(source: &Source) -> Vec<Finding> {
    // Removing a directory, copying a path or renaming a path can take the key with
    // it, wherever it happens: these judge every shipped source.
    let mut findings = forbidden(source, &["remove_dir", "fs::copy", "fs::rename"]);
    if !in_scope(IDENTITY_SCOPE, &source.path) {
        return findings;
    }
    // Writing one file judges the module that owns the key. `create_new` is the one
    // write it performs, and it lives in `tempfile`, which is not on this list
    // because its temporary file is not the key. `persist(` is the overwriting
    // publish beside the one this crate uses; `persist_noclobber(` does not contain
    // it, so the safe call stays legal while the one that clobbers a racing
    // creator's key does not.
    findings.extend(forbidden(
        source,
        &[
            "remove_file",
            "fs::write",
            "File::create",
            "persist(",
            "truncate",
            "set_len",
            ".append(",
            "create(true)",
            ".write(true)",
        ],
    ));
    findings
}

fn key_file_name_is_one_place(source: &Source) -> Vec<Finding> {
    if source.path == KEY_FILE_SOURCE {
        return Vec::new();
    }
    // The literal a new code path would write, and the function it would use to
    // build the key's path: either is a second way to the key, which is what this
    // claim forbids. The function is matched by its bare name, so
    // `keyfile::file_in(..)`, a brace import and an alias all count; a longer name
    // that merely ends in it (`tempfile_in`) does not.
    let mut findings = forbidden(source, &[KEY_FILE_NAME]);
    for (line, text) in code_lines(&source.text) {
        if names_file_in(text) {
            findings.push(Finding {
                path: source.path.clone(),
                line,
                detail: format!("uses `file_in`: {}", text.trim()),
            });
        }
    }
    findings
}

/// Whether a line names the function `file_in`, not a longer identifier it ends.
fn names_file_in(text: &str) -> bool {
    let ident = |character: char| character.is_alphanumeric() || character == '_';
    text.match_indices("file_in").any(|(at, _)| {
        let before = text[..at].chars().next_back();
        let after = text[at + "file_in".len()..].chars().next();
        !before.is_some_and(ident) && !after.is_some_and(ident)
    })
}

fn key_is_minted_in_one_place(source: &Source) -> Vec<Finding> {
    if source.path != KEY_FILE_SOURCE {
        return forbidden(source, MINT_FORMS);
    }
    // The key file's own module must mint, and mint once: a second call would be a
    // second way to become a new machine. Occurrences are counted, not lines, so two
    // mints written on one line are two.
    let mints: Vec<usize> = code_lines(&source.text)
        .flat_map(|(line, text)| {
            let count: usize = MINT_FORMS
                .iter()
                .map(|form| text.match_indices(form).count())
                .sum();
            std::iter::repeat_n(line, count)
        })
        .collect();
    match mints.as_slice() {
        [_] => Vec::new(),
        [] => vec![Finding {
            path: KEY_FILE_SOURCE.to_owned(),
            line: 1,
            detail: "the key file's module mints no key at all".to_owned(),
        }],
        [_, second, ..] => vec![Finding {
            path: KEY_FILE_SOURCE.to_owned(),
            line: *second,
            detail: format!(
                "the key file's module mints a key {} times; there must be one",
                mints.len()
            ),
        }],
    }
}

fn no_persistent_state(source: &Source) -> Vec<Finding> {
    forbidden(source, &["std::fs", "OpenOptions", "File::"])
}
