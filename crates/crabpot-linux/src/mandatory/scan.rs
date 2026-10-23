//! The walk that stands in for upstream's `rg --files` call.
//!
//! Upstream runs `rg --files --hidden --no-ignore --no-config --max-depth
//! <depth + 1>` with an `--iglob` for each dangerous name and
//! `-g '!**/node_modules/**'`, in the working directory, for ten seconds.
//! This lists the same files with `std::fs`: hidden names are listed, no file
//! decides what is, names match without case, a symbolic link is neither
//! listed nor followed, and `node_modules` is mostly not entered.
//!
//! "Mostly" is `rg`'s own. It puts every `--iglob` after every `-g`, and the
//! last glob to match a path wins. So `!**/node_modules/**` prunes a directory
//! beneath a `node_modules` that no `--iglob` matches, and a dangerous file
//! directly in one is listed all the same. Upstream's mapping then denies it.

use std::{
    collections::BTreeSet,
    ffi::OsStr,
    fmt, fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use crabpot_core::dangerous::{DANGEROUS_DIRECTORIES, DANGEROUS_FILES};
use nix::unistd::{AccessFlags, access, getuid};

/// What a walk found, as paths relative to the directory it walked.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Scan {
    /// The files with a dangerous name, as `rg --files` lists them.
    pub listed: Vec<PathBuf>,
    /// Directories that could not be read, absolute: what is in one is not
    /// known, so it is denied whole. A directory counts only when this user
    /// owns it, so its mode can be given back from outside, and no link is on
    /// the way to it.
    pub unreadable: Vec<PathBuf>,
}

/// The walk ran past its time limit. What it had found by then counts, since
/// upstream keeps what `rg` had listed when it is killed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimedOut {
    /// The limit that passed.
    pub limit: Duration,
    /// What was found before it did.
    pub found: Scan,
}

impl fmt::Display for TimedOut {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the mandatory-deny scan ran past {:?} with {} files listed",
            self.limit,
            self.found.listed.len()
        )
    }
}

impl core::error::Error for TimedOut {}

/// Lists the files below `cwd` that upstream's `rg` call lists, down to
/// `max_depth` (upstream's `maxDepth`, so files lie at most `max_depth + 1`
/// levels down) and for at most `limit`.
///
/// `cwd` is a real path, as `process.cwd()` is.
///
/// # Errors
///
/// [`TimedOut`] when `limit` passes before the walk is done.
pub fn scan(
    cwd: &Path,
    max_depth: usize,
    allow_git_config: bool,
    limit: Duration,
) -> Result<Scan, TimedOut> {
    let started = Instant::now();
    let names = Names::new(allow_git_config);
    let mut found = Scan::default();
    let mut unreadable = BTreeSet::new();
    let mut stack = vec![PathBuf::new()];
    let mut timed_out = false;
    'walk: while let Some(dir) = stack.pop() {
        if started.elapsed() >= limit {
            timed_out = true;
            break;
        }
        // The level the entries of `dir` lie at.
        let depth = dir.components().count() + 1;
        let entries = match fs::read_dir(cwd.join(&dir)) {
            Ok(entries) => entries,
            Err(_) => {
                unreadable.extend(unreadable_directory(cwd, &dir, max_depth));
                continue;
            }
        };
        for entry in entries.flatten() {
            if started.elapsed() >= limit {
                timed_out = true;
                break 'walk;
            }
            // From the entry itself, so that a link is a link.
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let name = entry.file_name();
            let relative = dir.join(&name);
            if kind.is_dir() {
                if depth <= max_depth && (!in_node_modules(&relative) || names.matches(&relative)) {
                    stack.push(relative);
                }
            } else if kind.is_file() && names.matches(&relative) {
                found.listed.push(relative);
            }
        }
    }
    found.listed.sort();
    found.unreadable = unreadable.into_iter().collect();
    if timed_out {
        return Err(TimedOut { limit, found });
    }
    Ok(found)
}

/// The directory to deny whole for one that could not be read, if there is
/// one: `dir`, or the nearest one above it that can be looked at. Upstream's
/// `unreadableDirectories`.
///
/// THREAT: a bind of `link/x` would bring in what the link leads to, and nobody
/// else's mode can be given back from inside the sandbox, with thousands of
/// those (`/home`) each a mount.
fn unreadable_directory(cwd: &Path, dir: &Path, max_depth: usize) -> Option<PathBuf> {
    let mut at = dir;
    while !at.as_os_str().is_empty() {
        let absolute = cwd.join(at);
        match fs::symlink_metadata(&absolute) {
            // What cannot be looked at, because what holds it cannot be
            // searched, is stood in for by the directory above it.
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                at = at.parent()?;
            }
            Err(_) => return None,
            Ok(metadata) => {
                let ours = metadata.is_dir()
                    && metadata.uid() == getuid().as_raw()
                    && fs::canonicalize(&absolute).is_ok_and(|real| real == absolute);
                let readable = access(&absolute, AccessFlags::R_OK | AccessFlags::X_OK).is_ok();
                return (ours && !readable && at.components().count() <= max_depth)
                    .then_some(absolute);
            }
        }
    }
    None
}

/// Whether `relative` lies beneath a directory named `node_modules`, which
/// `-g '!**/node_modules/**'` matches. That glob is case-sensitive.
fn in_node_modules(relative: &Path) -> bool {
    relative
        .parent()
        .is_some_and(|parent| parent.iter().any(|part| part == OsStr::new("node_modules")))
}

/// The dangerous names, lowercased, to match a path against.
struct Names {
    files: Vec<String>,
    /// Names that a file lies somewhere beneath: `**/<name>/**`.
    directories: Vec<Vec<String>>,
    /// Names that are a file: `**/.git/HEAD`.
    paths: Vec<Vec<String>>,
}

impl Names {
    fn new(allow_git_config: bool) -> Self {
        let split = |name: &str| name.to_lowercase().split('/').map(str::to_owned).collect();
        let mut paths = vec![split(".git/HEAD")];
        if !allow_git_config {
            paths.push(split(".git/config"));
        }
        Self {
            files: DANGEROUS_FILES
                .iter()
                .map(|name| name.to_lowercase())
                .collect(),
            directories: DANGEROUS_DIRECTORIES
                .iter()
                .chain(&[".git/hooks"])
                .map(|name| split(name))
                .collect(),
            paths,
        }
    }

    /// Whether an `--iglob` matches `relative`, of a file or a directory.
    fn matches(&self, relative: &Path) -> bool {
        let lower = lowercase_components(relative);
        let Some((name, parents)) = lower.split_last() else {
            return false;
        };
        self.files.contains(name)
            || self
                .directories
                .iter()
                .any(|beneath| parents.windows(beneath.len()).any(|at| at == beneath))
            || self.paths.iter().any(|path| lower.ends_with(path))
    }
}

pub(super) fn lowercase_components(path: &Path) -> Vec<String> {
    path.components()
        .map(|part| part.as_os_str().to_string_lossy().to_lowercase())
        .collect()
}
