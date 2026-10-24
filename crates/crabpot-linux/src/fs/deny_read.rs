//! What `filesystem.denyRead` hides: a directory is covered by an empty tmpfs
//! and a file is bound over from `/dev/null`.
//!
//! Upstream's `pushReadDenyDirMounts` and `readDenyEntries`. A mount follows
//! the root bind, which would otherwise cover it. A path that is not there is
//! skipped, since bwrap would have to create a mount point for it in the
//! read-only root.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;

use crabpot_core::PathError;
use crabpot_core::config::Config;

use super::Draft;
use super::glob_walk::{self, KERNEL_MOUNTS};

/// One mount over a denied path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Mount {
    /// Where it lands.
    pub(super) path: PathBuf,
    /// A tmpfs over a directory, else `/dev/null` over a file.
    pub(super) is_dir: bool,
}

impl Mount {
    /// The words that make the mount.
    pub(super) fn words(&self) -> Vec<OsString> {
        let path = self.path.clone().into_os_string();
        if self.is_dir {
            vec!["--tmpfs".into(), path]
        } else {
            vec!["--ro-bind".into(), "/dev/null".into(), path]
        }
    }
}

pub(super) fn words(config: &Config, draft: &mut Draft) -> Result<Vec<OsString>, PathError> {
    let mounts = mounts(config)?;
    let words = mounts.iter().flat_map(Mount::words).collect();
    draft.protected.extend(
        mounts
            .iter()
            .filter_map(|mount| mount.path.to_str().map(str::to_owned)),
    );
    draft.read_mounts = mounts;
    Ok(words)
}

fn mounts(config: &Config) -> Result<Vec<Mount>, PathError> {
    let mut found = BTreeMap::new();
    for entry in config.filesystem.read_denies()? {
        for path in glob_walk::matches(&entry) {
            if let Some((located, is_dir)) = locate(path) {
                found.insert(located, is_dir);
            }
        }
    }
    Ok(collapse(found)
        .into_iter()
        .map(|(path, is_dir)| Mount { path, is_dir })
        .collect())
}

/// Where `path` is mounted over, and whether it is a directory; `None` when it
/// is not there. Links are resolved, so two spellings of one path mount once.
/// A path in a kernel mount keeps its spelling: `/proc/self` resolves to a host
/// pid the sandbox's own `/proc` does not hold.
fn locate(path: PathBuf) -> Option<(PathBuf, bool)> {
    if KERNEL_MOUNTS.iter().any(|mount| path.starts_with(mount)) {
        let is_dir = fs::metadata(&path).ok()?.is_dir();
        return Some((path, is_dir));
    }
    let real = fs::canonicalize(path).ok()?;
    let is_dir = real.is_dir();
    Some((real, is_dir))
}

/// The paths with those beneath a denied directory left out: the tmpfs over it
/// already hides them, and a mount beneath it would name a path that is no
/// longer there.
fn collapse(found: BTreeMap<PathBuf, bool>) -> Vec<(PathBuf, bool)> {
    let mut kept: Vec<(PathBuf, bool)> = Vec::new();
    for (path, is_dir) in found {
        let covered = kept
            .iter()
            .any(|(dir, dir_is_dir)| *dir_is_dir && path.starts_with(dir));
        if !covered {
            kept.push((path, is_dir));
        }
    }
    kept
}
