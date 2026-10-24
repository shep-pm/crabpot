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

use super::glob_walk::{self, KERNEL_MOUNTS};

pub(super) fn words(config: &Config) -> Result<Vec<OsString>, PathError> {
    Ok(collapse(located(config)?)
        .into_iter()
        .flat_map(|(path, is_dir)| mount(path, is_dir))
        .collect())
}

/// The located paths of `config`'s `denyRead`, each with whether it is a
/// directory, as [`locate`] finds them on disk.
pub(super) fn located(config: &Config) -> Result<BTreeMap<PathBuf, bool>, PathError> {
    let mut found = BTreeMap::new();
    for entry in config.filesystem.read_denies()? {
        for path in glob_walk::matches(&entry) {
            if let Some((located, is_dir)) = locate(path) {
                found.insert(located, is_dir);
            }
        }
    }
    Ok(found)
}

/// Where `path` is mounted over, and whether it is a directory; `None` when it
/// is not there. Links are resolved, so two spellings of one path mount once.
/// A path in a kernel mount keeps its spelling: `/proc/self` resolves to a host
/// pid the sandbox's own `/proc` does not hold.
pub(super) fn locate(path: PathBuf) -> Option<(PathBuf, bool)> {
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
pub(super) fn collapse(found: BTreeMap<PathBuf, bool>) -> Vec<(PathBuf, bool)> {
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

pub(super) fn mount(path: PathBuf, is_dir: bool) -> Vec<OsString> {
    if is_dir {
        vec!["--tmpfs".into(), path.into_os_string()]
    } else {
        vec!["--ro-bind".into(), "/dev/null".into(), path.into_os_string()]
    }
}
