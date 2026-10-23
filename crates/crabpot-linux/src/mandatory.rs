//! The write denies that are always on, inside the working directory.
//!
//! Upstream's `linuxGetMandatoryDenyPaths` and `linuxGetCwdMandatoryDenyPaths`,
//! with the `rg` call replaced by a walk with `std::fs` (ADR-0014). The walk is
//! [`scan`]. Nothing here reads a sandbox's configuration or starts a process.

mod scan;
#[cfg(test)]
mod tests;

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use crabpot_core::dangerous::{DANGEROUS_DIRECTORIES, DANGEROUS_FILES};

pub use scan::{Scan, TimedOut, scan};

/// How deep below the working directory dangerous names are looked for:
/// upstream's `DEFAULT_MANDATORY_DENY_SEARCH_DEPTH`.
pub const DEFAULT_MANDATORY_DENY_SEARCH_DEPTH: usize = 3;

/// How long the walk may take before what it has found is all there is:
/// `ripGrep`'s `timeout` in `src/utils/ripgrep.ts`.
pub const SCAN_TIME_LIMIT: Duration = Duration::from_secs(10);

/// What `.git` is in a directory, and so what is denied there.
enum DotGit {
    /// A repository: its hooks and config are denied.
    Directory,
    /// The pointer of a worktree or a submodule. There are no `.git/hooks` for
    /// as long as it is a file, so the file is denied, which keeps it one.
    File,
    /// Nothing is denied: a mount at `.git` would keep `git init` from making
    /// it.
    Absent,
}

impl DotGit {
    /// Upstream's `dotGitKindAt`: what is there, links followed.
    fn at(path: &Path) -> Self {
        match fs::metadata(path) {
            Ok(metadata) if metadata.is_dir() => Self::Directory,
            Ok(_) => Self::File,
            Err(_) => Self::Absent,
        }
    }
}

/// The part of the mandatory deny set that follows from `cwd` alone: the
/// dangerous files and directories in it, plus `.git/hooks` and, unless
/// `allow_git_config`, `.git/config`, or a `.git` that is a file.
///
/// Only `cwd`'s own `.git`: a `.git` file below it is git's to rewrite and
/// remove, as a checkout that recurses into submodules does.
pub fn cwd_deny_paths(cwd: &Path, allow_git_config: bool) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = DANGEROUS_FILES
        .iter()
        .chain(&DANGEROUS_DIRECTORIES)
        .map(|name| cwd.join(name))
        .collect();
    let dot_git = cwd.join(".git");
    match DotGit::at(&dot_git) {
        DotGit::File => paths.push(dot_git),
        DotGit::Directory => {
            paths.push(dot_git.join("hooks"));
            if !allow_git_config {
                paths.push(dot_git.join("config"));
            }
        }
        DotGit::Absent => {}
    }
    paths
}

/// Every path to deny writes to in and below `cwd`, down to `max_depth`: the
/// ones of [`cwd_deny_paths`], the directories the walk could not read, and
/// the nested matches it finds.
///
/// A walk that passes [`SCAN_TIME_LIMIT`] counts for what it had found by then,
/// as upstream's does when it kills `rg`. `cwd` is a real path.
pub fn mandatory_deny_paths(cwd: &Path, max_depth: usize, allow_git_config: bool) -> Vec<PathBuf> {
    let found = scan(cwd, max_depth, allow_git_config, SCAN_TIME_LIMIT)
        .unwrap_or_else(|timed_out| timed_out.found);
    // The names a match can lie under, by path component.
    let directories: Vec<Vec<String>> = DANGEROUS_DIRECTORIES
        .iter()
        .chain(&[".git/hooks", ".git/config", ".git/HEAD"])
        .map(|name| name.to_lowercase().split('/').map(str::to_owned).collect())
        .collect();
    let mut paths = cwd_deny_paths(cwd, allow_git_config);
    paths.extend(found.unreadable);
    paths.extend(
        found
            .listed
            .iter()
            .filter_map(|listed| denied_beneath(listed, &directories, max_depth))
            .map(|relative| cwd.join(relative)),
    );
    let mut seen = HashSet::new();
    paths.retain(|path| seen.insert(path.clone()));
    paths
}

/// What to deny for one listed file, relative to `cwd`: the dangerous
/// directory it lies in, else the file itself, unless that lies too deep.
/// Upstream's mapping loop in `linuxGetMandatoryDenyPaths`.
fn denied_beneath(listed: &Path, directories: &[Vec<String>], max_depth: usize) -> Option<PathBuf> {
    let segments: Vec<_> = listed.components().collect();
    let lower = scan::lowercase_components(listed);
    // Where the dangerous name begins and how long it is: the first of
    // `directories` on the way down, else the file itself.
    let mut at = segments.len() - 1;
    let mut length = 1;
    // How deep the directory holding the name, `at`, may lie. One level less
    // for a directory name: each costs mounts that keep what holds it from
    // being renamed or removed, and bwrap's start grows with them.
    let mut deepest = max_depth.checked_sub(1);
    'search: for i in 0..lower.len() {
        for name in directories {
            if lower[i..].starts_with(name) {
                at = i;
                length = name.len();
                deepest = max_depth.checked_sub(2);
                break 'search;
            }
        }
    }
    if at > deepest? {
        return None;
    }
    let mut found: Vec<PathBuf> = segments[..at + length]
        .iter()
        .map(|segment| PathBuf::from(segment.as_os_str()))
        .collect();
    if lower[at] == ".git" && lower.get(at + 1).is_some_and(|next| next == "head") {
        found[at + 1] = PathBuf::from("hooks");
    }
    Some(found.iter().collect())
}
