//! The bwrap dependency checks, run before a sandbox starts (ADR-0014).
//!
//! bwrap is the only tool: ADR-0014 drops upstream's `socat` and `rg` checks.

use core::fmt;
use std::env;
use std::ffi::OsStr;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const BWRAP: &str = "bwrap";

/// The oldest bwrap that supports everything a sandbox asks of it.
const OLDEST_FULLY_SUPPORTED: Version = Version([0, 5, 0]);

/// `CAP_SETFCAP`'s number in `linux/capability.h`.
const CAP_SETFCAP: u32 = 31;

/// Why the machine cannot run a sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// A check that fails for a new reason adds a variant without breaking a
// caller's `match`.
#[non_exhaustive]
pub enum DepsError {
    /// `tool` is not on `PATH`, or is there but not executable.
    Missing {
        /// The program's name.
        tool: &'static str,
    },
    /// The process is uid 0 without `CAP_SETFCAP` in its bounding set, and a
    /// run of bwrap could not make a user namespace.
    Uid0WithoutSetfcap,
}

impl fmt::Display for DepsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing { tool } => write!(f, "{tool} is missing or not executable"),
            Self::Uid0WithoutSetfcap => write!(
                f,
                "running as uid 0 without CAP_SETFCAP, so bwrap cannot make a user namespace: \
                 run as another user, or start the container with CAP_SETFCAP"
            ),
        }
    }
}

impl core::error::Error for DepsError {}

/// A bwrap version, `major.minor.patch`. A two-part version has a patch of 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version([u64; 3]);

impl Version {
    /// The first two or three part version number in `text`, which may have
    /// words around it, as `bwrap --version` prints `bubblewrap 0.9.0`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        text.split_whitespace().find_map(|word| {
            let mut parts = [0; 3];
            let mut count = 0;
            for part in word.split('.') {
                *parts.get_mut(count)? = part.parse().ok()?;
                count += 1;
            }
            (count >= 2).then_some(Self(parts))
        })
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [major, minor, patch] = self.0;
        write!(f, "{major}.{minor}.{patch}")
    }
}

/// Checks that bwrap can run a sandbox, and returns where it is.
///
/// `path` is the `PATH` to look for bwrap on, and `proc_status` the text of
/// `/proc/self/status`, if it could be read. A bwrap older than 0.5.0 is
/// written a warning on `warn` and the check goes on.
///
/// A process that is uid 0 and lacks `CAP_SETFCAP` cannot write its user
/// namespace's uid map, but a bwrap installed setuid does not need one, so the
/// status only makes the case doubtful, and a run of `bwrap --unshare-user
/// --dev-bind / / true` settles it. A status that cannot be read raises no
/// doubt.
///
/// # Errors
///
/// [`DepsError::Missing`] when `path` has no executable bwrap, and
/// [`DepsError::Uid0WithoutSetfcap`] when the process is uid 0 without
/// `CAP_SETFCAP` and the confirming run fails.
pub fn check(
    path: &OsStr,
    proc_status: Option<&str>,
    warn: &mut dyn Write,
) -> Result<PathBuf, DepsError> {
    let bwrap = find_executable(BWRAP, path).ok_or(DepsError::Missing { tool: BWRAP })?;
    if let Some(version) = probe_version(&bwrap)
        && version < OLDEST_FULLY_SUPPORTED
    {
        // A closed stderr is no reason to refuse a sandbox.
        let _ = writeln!(
            warn,
            "Warning: bwrap {version} is older than {OLDEST_FULLY_SUPPORTED}, which \
             sandboxes may need to work in full. Upgrade bubblewrap."
        );
    }
    if proc_status.is_some_and(is_doubtful_uid_0) && !user_namespace_works(&bwrap) {
        return Err(DepsError::Uid0WithoutSetfcap);
    }
    Ok(bwrap)
}

/// [`check`] on this process: `PATH`, `/proc/self/status` and stderr.
///
/// # Errors
///
/// As [`check`].
pub fn check_here() -> Result<PathBuf, DepsError> {
    let status = std::fs::read_to_string("/proc/self/status").ok();
    check(
        &env::var_os("PATH").unwrap_or_default(),
        status.as_deref(),
        &mut std::io::stderr(),
    )
}

/// The first executable file called `name` in a directory of `path`. An empty
/// entry is skipped, since a path found there has no directory, and a command
/// run by it would search `PATH` again.
fn find_executable(name: &str, path: &OsStr) -> Option<PathBuf> {
    env::split_paths(path)
        .filter(|dir| !dir.as_os_str().is_empty())
        .map(|dir| dir.join(name))
        .find(|candidate| is_executable(candidate))
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use nix::unistd::{AccessFlags, access};

    path.is_file() && access(path, AccessFlags::X_OK).is_ok()
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

fn probe_version(bwrap: &Path) -> Option<Version> {
    let output = Command::new(bwrap).arg("--version").output().ok()?;
    Version::parse(&String::from_utf8_lossy(&output.stdout))
}

/// Whether the status is uid 0 with no `CAP_SETFCAP` in the bounding set.
fn is_doubtful_uid_0(status: &str) -> bool {
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix(':'))
            .map(str::trim)
    };
    let is_uid_0 = field("Uid")
        .and_then(|ids| ids.split_whitespace().next())
        .is_some_and(|real| real == "0");
    let has_setfcap = field("CapBnd")
        .and_then(|mask| u64::from_str_radix(mask, 16).ok())
        .is_some_and(|mask| mask & (1 << CAP_SETFCAP) != 0);
    is_uid_0 && !has_setfcap
}

fn user_namespace_works(bwrap: &Path) -> bool {
    Command::new(bwrap)
        .args(["--unshare-user", "--dev-bind", "/", "/", "true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use core::cmp::Ordering;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    const WITH_SETFCAP: &str = "Uid:\t0\t0\t0\t0\nCapBnd:\t000001ffffffffff\n";
    const WITHOUT_SETFCAP: &str = "Uid:\t0\t0\t0\t0\nCapBnd:\t000001ff7fffffff\n";
    const NOT_ROOT: &str = "Uid:\t1000\t1000\t1000\t1000\nCapBnd:\t0000000000000000\n";

    /// A directory of its own holding a `bwrap` with `script` as its body and
    /// `mode` as its permissions.
    fn bin_dir(test: &str, script: Option<(&str, u32)>) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("crabpot-deps-{test}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("a directory");
        if let Some((script, mode)) = script {
            let bwrap = dir.join("bwrap");
            fs::write(&bwrap, format!("#!/bin/sh\n{script}\n")).expect("a script");
            fs::set_permissions(&bwrap, fs::Permissions::from_mode(mode)).expect("a mode");
        }
        dir
    }

    fn run(dir: &Path, status: Option<&str>) -> (Result<PathBuf, DepsError>, String) {
        let mut warning = Vec::new();
        let result = check(dir.as_os_str(), status, &mut warning);
        (result, String::from_utf8(warning).expect("text"))
    }

    const MODERN: &str = r#"[ "$1" = --version ] && echo "bubblewrap 0.9.0""#;

    #[test]
    fn a_missing_bwrap_is_missing() {
        let dir = bin_dir("missing", None);
        let (result, warning) = run(&dir, Some(NOT_ROOT));
        assert_eq!(result, Err(DepsError::Missing { tool: "bwrap" }));
        assert_eq!(warning, "");
    }

    #[test]
    fn a_bwrap_that_is_not_executable_is_missing() {
        let dir = bin_dir("not-executable", Some((MODERN, 0o644)));
        let (result, _) = run(&dir, Some(NOT_ROOT));
        assert_eq!(result, Err(DepsError::Missing { tool: "bwrap" }));
    }

    #[test]
    fn a_bwrap_only_another_user_can_execute_is_passed_over() {
        // A root process can execute any file with an execute bit.
        if nix::unistd::geteuid().is_root() {
            return;
        }
        let theirs = bin_dir("theirs", Some((MODERN, 0o010)));
        let ours = bin_dir("ours", Some((MODERN, 0o755)));
        let path = env::join_paths([&theirs, &ours]).expect("a path");
        let result = check(&path, Some(NOT_ROOT), &mut Vec::new());
        assert_eq!(result, Ok(ours.join("bwrap")));
    }

    #[test]
    fn an_empty_path_entry_does_not_find_a_bwrap_in_the_working_directory() {
        let cwd = std::env::current_dir().expect("a working directory");
        let bwrap = cwd.join("bwrap");
        // The working directory is the package's, which has no `bwrap`.
        assert!(!bwrap.exists(), "{bwrap:?}");
        fs::write(&bwrap, "#!/bin/sh\n").expect("a script");
        fs::set_permissions(&bwrap, fs::Permissions::from_mode(0o755)).expect("a mode");
        let result = check(OsStr::new(""), Some(NOT_ROOT), &mut Vec::new());
        fs::remove_file(&bwrap).expect("removed");
        assert_eq!(result, Err(DepsError::Missing { tool: "bwrap" }));
    }

    #[test]
    fn a_bwrap_below_0_5_0_warns_and_goes_on() {
        let dir = bin_dir(
            "old",
            Some((r#"[ "$1" = --version ] && echo "bubblewrap 0.4.1""#, 0o755)),
        );
        let (result, warning) = run(&dir, Some(NOT_ROOT));
        assert_eq!(result, Ok(dir.join("bwrap")));
        assert!(warning.contains("0.4.1"), "{warning}");
        assert!(warning.contains("0.5.0"), "{warning}");
    }

    #[test]
    fn a_bwrap_at_0_5_0_does_not_warn() {
        let dir = bin_dir(
            "oldest",
            Some((r#"[ "$1" = --version ] && echo "bubblewrap 0.5""#, 0o755)),
        );
        let (result, warning) = run(&dir, Some(NOT_ROOT));
        assert_eq!(result, Ok(dir.join("bwrap")));
        assert_eq!(warning, "");
    }

    #[test]
    fn version_comparison_reads_two_and_three_part_versions() {
        let version = |text| Version::parse(text).expect(text);
        assert_eq!(version("0.5"), version("0.5.0"));
        assert!(version("0.4.1") < version("0.5"));
        assert!(version("0.5.1") > version("0.5"));
        assert!(version("0.10.0") > version("0.9.9"));
        assert_eq!(version("bubblewrap 0.9.0\n"), version("0.9"));
        assert_eq!(Version::parse("bubblewrap"), None);
        assert_eq!(version("1.0").cmp(&version("0.99.99")), Ordering::Greater);
    }

    #[test]
    fn uid_0_without_cap_setfcap_is_refused() {
        let dir = bin_dir("no-setfcap", Some((&format!("{MODERN}\nexit 1"), 0o755)));
        let (result, _) = run(&dir, Some(WITHOUT_SETFCAP));
        assert_eq!(result, Err(DepsError::Uid0WithoutSetfcap));
    }

    #[test]
    fn uid_0_with_cap_setfcap_is_allowed() {
        let dir = bin_dir("setfcap", Some((&format!("{MODERN}\nexit 1"), 0o755)));
        let (result, _) = run(&dir, Some(WITH_SETFCAP));
        assert_eq!(result, Ok(dir.join("bwrap")));
    }

    #[test]
    fn the_confirming_run_settles_a_doubtful_uid_0() {
        let dir = bin_dir(
            "confirmed",
            Some((&format!("{MODERN}\n[ \"$1\" = --unshare-user ]"), 0o755)),
        );
        let (result, _) = run(&dir, Some(WITHOUT_SETFCAP));
        assert_eq!(result, Ok(dir.join("bwrap")));
    }
}
