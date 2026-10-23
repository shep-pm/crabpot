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

use super::glob_walk;

pub(super) fn words(config: &Config) -> Result<Vec<OsString>, PathError> {
    let mut found = BTreeMap::new();
    for entry in config.filesystem.read_denies()? {
        for path in glob_walk::matches(&entry) {
            if let Ok(real) = fs::canonicalize(path) {
                let is_dir = real.is_dir();
                found.insert(real, is_dir);
            }
        }
    }
    Ok(collapse(found)
        .into_iter()
        .flat_map(|(path, is_dir)| mount(path, is_dir))
        .collect())
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

fn mount(path: PathBuf, is_dir: bool) -> Vec<OsString> {
    if is_dir {
        vec!["--tmpfs".into(), path.into_os_string()]
    } else {
        vec!["--ro-bind".into(), "/dev/null".into(), path.into_os_string()]
    }
}
