//! What `filesystem.allowRead` re-opens inside what `denyRead` hides.
//!
//! Upstream's `reExposedBy` and `expandAllowReadGlob`: a read-only bind of the
//! host path follows the mount that hid it, since bwrap applies its mounts in
//! the order it reads them. A path no deny hides is already readable through
//! the root bind, so it adds no word.
//!
//! A bind re-opens its host directory whole, so the denials beneath it come
//! back after it, as macOS's `late_denies` does: a denied name as it was, and
//! the matches of a pattern that does not cover the reopening, which keep
//! their whole mask like a leaf glob. A pattern covering the reopening gives
//! way to it, carved out as macOS carves its region globs. The paths the plan
//! denies whatever the settings say are in this too, and no `allowRead` entry
//! is asked for them: see `remasked`.
//!
//! Two things the ordering and the flag settle:
//!
//! - Mounts come out shallowest first, so a late denial never covers a more
//!   specific allow: a denied directory beneath a reopening remounts before
//!   the bind of an allowed path beneath it, and a denial at a reopened path
//!   is what the allow names outright, so no late mount is written for it
//!   and the allow wins there.
//! - A reopened path that a writable bind of `allow_write` covers comes back
//!   with `--bind`, not `--ro-bind`, so a write grant survives the read deny
//!   it sits under, as it does on macOS.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use crabpot_core::PathError;
use crabpot_core::ResolvedPath;
use crabpot_core::config::Config;
use crabpot_core::paths::PathBase;

use super::allow_write;
use super::deny_read::{self, Mount, collapse, locate, located};
use super::glob_walk;
use super::{Draft, PlanError};

pub(super) fn words(
    config: &Config,
    base: &PathBase,
    draft: &mut Draft,
) -> Result<Vec<OsString>, PlanError> {
    let denies = config.filesystem.read_denies()?;
    let hidden = located(config)?;
    let writable = allow_write::bind_paths(base, config)?;
    let mut reopened = BTreeMap::new();
    for entry in config.filesystem.read_allows()? {
        for path in glob_walk::matches(&entry) {
            if entry.is_pattern() && is_symlink(&path) {
                continue;
            }
            if let Some((path, is_dir)) = locate(path)
                && hidden.keys().any(|deny| path.starts_with(deny))
            {
                reopened.insert(path, is_dir);
            }
        }
    }
    let open: BTreeSet<PathBuf> = reopened.keys().cloned().collect();
    let mut late = late_denies(&denies, &open)?;
    late.extend(remasked(&hidden, &open));
    let late = collapse(late);
    let mut mounts: Vec<(usize, Vec<OsString>, Mount)> = reopened
        .into_iter()
        .map(|(path, is_dir)| {
            let flag = if writable.iter().any(|bind| path.starts_with(bind)) {
                "--bind"
            } else {
                "--ro-bind"
            };
            (
                depth(&path),
                bind(flag, &path),
                Mount {
                    path,
                    is_dir,
                    reopened: true,
                },
            )
        })
        .chain(late.into_iter().map(|(path, is_dir)| {
            let mount = Mount::mask(path, is_dir);
            (depth(&mount.path), mount.words(), mount)
        }))
        .collect();
    // bwrap reads its mounts in order and a later one covers an earlier one,
    // so a mount is written after every mount of a directory above it. Two
    // mounts of the same depth hold neither of the other's path, so their
    // order asks nothing.
    mounts.sort_by_key(|(depth, _, _)| *depth);
    draft.protected.extend(
        mounts
            .iter()
            .filter(|(_, _, mount)| !mount.reopened)
            .filter_map(|(_, _, mount)| mount.path.to_str().map(str::to_owned)),
    );
    let words = mounts.iter().flat_map(|(_, words, _)| words.clone()).collect();
    draft.remounts = mounts.into_iter().map(|(_, _, mount)| mount).collect();
    Ok(words)
}

/// The number of names in `path`, which is how deep its mount sits under the
/// one it needs room in.
fn depth(path: &Path) -> usize {
    path.components().count()
}

/// The words binding `path` read-only, or writable under `flag`.
fn bind(flag: &str, path: &Path) -> Vec<OsString> {
    [
        OsString::from(flag),
        path.as_os_str().to_owned(),
        path.as_os_str().to_owned(),
    ]
    .into()
}

/// Whether `path` is itself a link. A glob authorizes the names it spells, and
/// a link planted in a matched directory would otherwise authorize its target
/// through [`locate`]'s resolving, reopening a denied path at its own place.
/// An allow that names a link is a name, not a match, and keeps its resolved
/// spelling.
fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|kind| kind.is_symlink())
}

/// The paths the plan denies whatever the settings say that a reopening has
/// brought back into view, to mount after the reopening that exposed them.
///
/// A reopening of a directory above one of them is a restore inside the mask
/// the plan made for that directory, which is where the denial was hidden: the
/// host's own path is bound back over it, and the denial is mounted again over
/// that. The exception is a reopening at the denial itself where the plan made
/// its mount on its own, with no denied directory above it: that reopening is
/// the restore inside the denial's own mount, which is what an allow naming a
/// denial outright comes to wherever the denial came from.
fn remasked(
    hidden: &BTreeMap<PathBuf, bool>,
    reopened: &BTreeSet<PathBuf>,
) -> BTreeMap<PathBuf, bool> {
    deny_read::mandatory()
        .into_iter()
        .filter(|(path, _)| reopened.iter().any(|open| path.starts_with(open)))
        .filter(|(path, _)| {
            !reopened.contains(path)
                || hidden
                    .iter()
                    .any(|(dir, is_dir)| *is_dir && *dir != *path && path.starts_with(dir))
        })
        .collect()
}

/// The denials a reopened directory would otherwise expose, to mount after
/// the reopening above them, and before any reopening beneath them.
///
/// - A denied name beneath a reopening, mounted as it was, unless the allow
///   names that denial outright: one at a reopened path is what the allow
///   asks for, and the allow wins there.
/// - The matches of a pattern beneath a reopening the pattern does not cover,
///   which beat the allow they land inside as a leaf glob does. A pattern
///   covering the reopening gives way to it, so what it matched beneath stays
///   open.
fn late_denies(
    denies: &[ResolvedPath],
    reopened: &BTreeSet<PathBuf>,
) -> Result<BTreeMap<PathBuf, bool>, PathError> {
    let mut late = BTreeMap::new();
    for entry in denies {
        let found = if entry.is_pattern() {
            glob_walk::matches(entry).into_iter().map(locate).collect()
        } else {
            vec![locate(PathBuf::from(entry.path()))]
        };
        for found in found.into_iter().flatten() {
            let (path, is_dir) = found;
            let under = reopened
                .iter()
                .any(|open| path != *open && path.starts_with(open));
            let named = reopened.contains(&path);
            let carved = entry.is_pattern()
                && reopened.iter().any(|open| {
                    path.starts_with(open)
                        && open.to_str().is_some_and(|open| entry.deny_covers(open))
                });
            if under && !named && !carved {
                late.insert(path, is_dir);
            }
        }
    }
    Ok(late)
}
