//! What `filesystem.denyRead` hides: a directory is covered by an empty tmpfs
//! and a file is bound over from `/dev/null`.
//!
//! Upstream's `pushReadDenyDirMounts` and `readDenyEntries`. A mount follows
//! the root bind, which would otherwise cover it. A path that is not there is
//! skipped, since bwrap would have to create a mount point for it in the
//! read-only root.
//!
//! One path is denied whatever the settings say, because upstream's
//! `readDenyEntries` adds it to every read policy: see [`ALWAYS_DENIED`].

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;

use crabpot_core::PathError;
use crabpot_core::config::Config;
use crabpot_core::paths::PathBase;

use super::Draft;
use super::PlanError;
use super::glob_walk::{self, KERNEL_MOUNTS};

/// The directory upstream adds to every read policy, and crabpot always has a
/// read policy: `filesystem.disabled`, the one setting that would drop it, is
/// refused (ADR-0013). ssh refuses a config file whose owner or mode looks
/// wrong, and inside the sandbox every path sits over a bind and looks that way
/// (`Bad owner or permissions` under OrbStack).
pub(super) const ALWAYS_DENIED: [&str; 1] = ["/etc/ssh/ssh_config.d"];

/// One mount over a path: a mask of a denied one, or the bind of a host path
/// back over what a mask hid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Mount {
    /// Where it lands.
    pub(super) path: PathBuf,
    /// Whether the path is a directory.
    pub(super) is_dir: bool,
    /// A read-only bind of the host path, where `allowRead` opens it again.
    pub(super) reopened: bool,
}

impl Mount {
    /// A tmpfs over a denied directory, else `/dev/null` over a denied file.
    pub(super) fn mask(path: PathBuf, is_dir: bool) -> Self {
        Self {
            path,
            is_dir,
            reopened: false,
        }
    }

    /// The words that make the mount.
    pub(super) fn words(&self) -> Vec<OsString> {
        let path = self.path.clone().into_os_string();
        if self.reopened {
            vec!["--ro-bind".into(), path.clone(), path]
        } else if self.is_dir {
            vec!["--tmpfs".into(), path]
        } else {
            vec!["--ro-bind".into(), "/dev/null".into(), path]
        }
    }
}

pub(super) fn words(
    config: &Config,
    _base: &PathBase,
    draft: &mut Draft,
) -> Result<Vec<OsString>, PlanError> {
    let mounts = collapse(located(config)?)
        .into_iter()
        .map(|(path, is_dir)| Mount::mask(path, is_dir))
        .collect::<Vec<_>>();
    let words = mounts.iter().flat_map(Mount::words).collect();
    draft.protected.extend(
        mounts
            .iter()
            .filter_map(|mount| mount.path.to_str().map(str::to_owned)),
    );
    draft.read_mounts = mounts;
    Ok(words)
}

/// The located paths `denyRead` hides, each with whether it is a directory, as
/// [`locate`] finds them on disk: `config`'s entries, and [`ALWAYS_DENIED`].
pub(super) fn located(config: &Config) -> Result<BTreeMap<PathBuf, bool>, PathError> {
    let mut found = BTreeMap::new();
    for entry in config.filesystem.read_denies()? {
        for path in glob_walk::matches(&entry) {
            if let Some((located, is_dir)) = locate(path) {
                found.insert(located, is_dir);
            }
        }
    }
    for path in ALWAYS_DENIED {
        if let Some((located, is_dir)) = locate(PathBuf::from(path)) {
            found.insert(located, is_dir);
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
