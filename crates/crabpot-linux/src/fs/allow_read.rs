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
//! way to it, carved out as macOS carves its region globs.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use crabpot_core::PathError;
use crabpot_core::ResolvedPath;
use crabpot_core::config::Config;

use super::deny_read::{collapse, locate, located, mount};
use super::glob_walk;

pub(super) fn words(config: &Config) -> Result<Vec<OsString>, PathError> {
    let denies = config.filesystem.read_denies()?;
    let hidden = located(config)?;
    let mut reopened = BTreeSet::new();
    for entry in config.filesystem.read_allows()? {
        for path in glob_walk::matches(&entry) {
            if entry.is_pattern() && is_symlink(&path) {
                continue;
            }
            if let Some((path, _is_dir)) = locate(path)
                && hidden.keys().any(|deny| path.starts_with(deny))
            {
                reopened.insert(path);
            }
        }
    }
    let mut words: Vec<OsString> = reopened
        .iter()
        .flat_map(|path| {
            let word = path.clone().into_os_string();
            ["--ro-bind".into(), word.clone(), word]
        })
        .collect();
    words.extend(late_denies(&denies, &reopened)?);
    Ok(words)
}

/// Whether `path` is itself a link. A glob authorizes the names it spells, and
/// a link planted in a matched directory would otherwise authorize its target
/// through [`locate`]'s resolving, reopening a denied path at its own place.
/// An allow that names a link is a name, not a match, and keeps its resolved
/// spelling.
fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|kind| kind.is_symlink())
}

/// The denials a reopened directory would otherwise expose, to mount after
/// its bind. A denial at the reopening itself is what the allow names, and
/// the allow wins there, as it does under seatbelt's last rule.
///
/// - A denied name beneath a reopening, mounted as it was.
/// - The matches of a pattern beneath a reopening the pattern does not cover,
///   which beat the allow they land inside as a leaf glob does. A pattern
///   covering the reopening gives way to it, so what it matched beneath stays
///   open.
fn late_denies(
    denies: &[ResolvedPath],
    reopened: &BTreeSet<PathBuf>,
) -> Result<Vec<OsString>, PathError> {
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
            let carved = entry.is_pattern()
                && reopened.iter().any(|open| {
                    path.starts_with(open) && open.to_str().is_some_and(|open| entry.deny_covers(open))
                });
            if under && !carved {
                late.insert(path, is_dir);
            }
        }
    }
    Ok(collapse(late)
        .into_iter()
        .flat_map(|(path, is_dir)| mount(path, is_dir))
        .collect())
}
