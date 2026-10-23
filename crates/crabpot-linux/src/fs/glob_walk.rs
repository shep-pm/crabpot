//! The paths on disk a resolved path entry matches.
//!
//! Upstream's `expandReadDenyGlobLinuxSteps` and `walkGlobPatternSteps`: bwrap
//! mounts over paths, not patterns, so a pattern is expanded by walking the
//! directory it is anchored at. A directory that matches is not walked, since
//! what is beneath it goes with it.

use std::fs;
use std::path::{Path, PathBuf};

use crabpot_core::ResolvedPath;

/// Mounts of the kernel, which bwrap makes afresh: a match there would be
/// covered by them, and walking `/proc` is slow and never settles.
const KERNEL_MOUNTS: [&str; 3] = ["/proc", "/sys", "/dev"];

/// The paths `entry` matches, or the path a name spells, whether or not it is
/// there. A directory that cannot be listed, or a name that is not UTF-8,
/// yields nothing.
pub(super) fn matches(entry: &ResolvedPath) -> Vec<PathBuf> {
    if !entry.is_pattern() {
        return vec![PathBuf::from(entry.path())];
    }
    let base = entry.base_dir();
    let tail = entry
        .path()
        .get(base.len()..)
        .unwrap_or_default()
        .trim_start_matches('/');
    // `*` and `?` stop at a separator, so without `**` the tail's depth is the
    // depth of every match.
    let depth = (!tail.contains("**")).then(|| tail.split('/').count());
    let mut found = Vec::new();
    walk(entry, Path::new(&base), depth, &mut found);
    found
}

fn walk(entry: &ResolvedPath, dir: &Path, depth: Option<usize>, found: &mut Vec<PathBuf>) {
    if depth == Some(0) {
        return;
    }
    let Ok(children) = fs::read_dir(dir) else {
        return;
    };
    for child in children.flatten() {
        let path = child.path();
        let Some(text) = path.to_str() else {
            continue;
        };
        if entry.allow_matches(text) {
            found.push(path);
        } else if child.file_type().is_ok_and(|kind| kind.is_dir())
            && !KERNEL_MOUNTS.contains(&text)
        {
            walk(entry, &path, depth.map(|left| left - 1), found);
        }
    }
}
