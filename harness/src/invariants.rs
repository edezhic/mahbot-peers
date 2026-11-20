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
//! One source file beyond this one is excluded, and the exclusion is data too: the
//! beacon server's process entry point binds a real socket, reads the
//! environment and reads the wall clock, because that is what a process entry
//! point is for. [`EXCLUDED`] names it and says why, the summary check proves the
//! list is exactly that one file, and the same check proves the file still needs
//! its exclusion — so the exception cannot quietly grow or go stale.

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
    /// The files this invariant covers, by display path. Empty means every
    /// source, which is the usual case; a claim about one file names it here
    /// rather than hiding a path comparison inside its check.
    pub scope: &'static [&'static str],
    /// A snippet this invariant's check must flag. It is scanned in-process, so
    /// the proof that the check is awake costs no subprocess and no fixture.
    pub control: &'static str,
    pub check: fn(&Source) -> Vec<Finding>,
}

impl Invariant {
    #[must_use]
    pub fn covers(&self, path: &str) -> bool {
        self.scope.is_empty() || self.scope.contains(&path)
    }
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
        if !sources.is_empty() && !sources.iter().any(|source| invariant.covers(&source.path)) {
            report.violations.push(Violation::ScopeNotFound {
                invariant: invariant.id,
            });
        }
        for source in sources
            .iter()
            .filter(|source| invariant.covers(&source.path))
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

/// The beacon server's process entry point: the one file the scan excludes.
pub const ENTRY_FILE: &str = "beacon-server/src/main.rs";

/// A source file the scan skips, and the reason it must.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Exclusion {
    pub path: &'static str,
    pub reason: &'static str,
}

/// The documented exclusions: exactly one, and the summary check proves it.
pub const EXCLUDED: &[Exclusion] = &[Exclusion {
    path: ENTRY_FILE,
    reason: "the process entry point: it binds the UDP socket, reads the listening address and key path from the command line, owns the executor and the wall clock, and owns the key file — the exclusive create with mode 0600 on unix, the retry when a racing process wins the create or is caught mid-write, and the refusal of a file other users can read. What the command line means, whether a mode is private and how the server is configured are pure functions in the `mahbot-beacon` library, which the scan covers.",
}];

/// The handle that must not name a path.
pub const MACHINE_FILE: &str = "harness/src/machine.rs";

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
        id: "beacon.no_persistent_state",
        claim: "the beacon keeps no state on disk: neither its protocol and client nor its server library touches a file, so a restart loses every registration by construction, and only the process entry point may touch one, for its own key",
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

/// Every source file the invariants cover: the library, the beacon crates, the
/// harness and its tests, because a wall-clock sleep or an environment lookup in
/// a test breaks the same promises as one in the code under test. The table and
/// the documented exclusions are skipped; nothing else is.
///
/// Paths are relative to the workspace root and always use `/`, so a finding
/// reads the same on every host.
#[must_use]
pub fn workspace_sources() -> Vec<Source> {
    let harness_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_dir = harness_dir
        .parent()
        .expect("the harness sits in the workspace");
    let mut sources = Vec::new();
    for root in [
        workspace_dir.join("src"),
        workspace_dir.join("tests"),
        workspace_dir.join("beacon/src"),
        workspace_dir.join("beacon-server/src"),
        harness_dir.join("src"),
        harness_dir.join("tests"),
    ] {
        if !root.is_dir() {
            continue;
        }
        for file in rs_files_under(&root) {
            let relative = file
                .strip_prefix(workspace_dir)
                .expect("sources live under the workspace")
                .components()
                .map(|component| component.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            if relative == TABLE_FILE || EXCLUDED.iter().any(|skip| skip.path == relative) {
                continue;
            }
            let text = std::fs::read_to_string(&file).expect("a source file reads as utf-8");
            sources.push(Source {
                path: relative,
                text,
            });
        }
    }
    sources.sort_by(|left, right| left.path.cmp(&right.path));
    sources
}

fn rs_files_under(dir: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("a source directory reads") {
            let path = entry.expect("a directory entry reads").path();
            if path.is_dir() {
                walk(&path, out);
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

fn no_persistent_state(source: &Source) -> Vec<Finding> {
    forbidden(source, &["std::fs", "OpenOptions", "File::"])
}
