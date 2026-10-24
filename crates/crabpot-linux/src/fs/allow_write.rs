//! What a sandboxed command may write: each writable path bound back over the
//! read-only root.
//!
//! Upstream's write loop in `generateFilesystemArgs`, over the `allowOnly` of
//! its write config: the root is bound read-only, so a path is writable only
//! where bwrap binds it again with `--bind`. The paths are the default write
//! roots and `allowWrite` after them.
//!
//! Two things the macOS profile does not have to care about:
//!
//! - A glob is no path. bwrap binds one path, so a write glob is dropped
//!   (upstream's `stripWriteGlobs`), unless it is also the name of a path.
//! - `/dev` is bwrap's own fresh mount, which
//!   [`private_mounts`](super::private_mounts) mounts after this section, so
//!   the sandbox's stdio roots under it need no bind of their own. Binding one
//!   would reach through that mount to the host's device.
//!
//! The plan puts this section between the read-only root and the sandbox's own
//! mounts, which is the order upstream's `wrapCommandWithSandboxLinux` builds.
//! A bind follows the root so it can carve a writable path out of it, and the
//! private mounts follow the bind so that a grant of the whole root, or of
//! `/dev` or `/proc`, cannot put the host's filesystem, devices or processes
//! back over them.
//!
//! `denyWrite` comes after this section, and the mandatory write denies with it.
//! The ancestor pins go in before it, or after it under a grant of the whole
//! root (see [`pins`](super::pins)).

use std::ffi::OsString;

use crabpot_core::config::Config;
use crabpot_core::paths::{
    ListKind, PathBase, PathReading, contains_glob_chars, default_write_paths,
    is_symlink_outside_boundary, literal_readings, normalize_path_for_sandbox, real_path_of,
    remove_trailing_glob_suffix, split_path_entries,
};
use crabpot_core::PathError;

use super::Draft;

pub(super) fn words(config: &Config, draft: &mut Draft) -> Result<Vec<OsString>, PathError> {
    let base = PathBase::from_env();
    let binds = bind_paths(&base, config)?;
    let words = bind_words(&binds);
    // A bind of the whole root buries the pins spliced in beneath it, so they
    // follow the binds then.
    draft.pin_at = if binds.iter().any(|path| path == "/") {
        draft.offset + words.len()
    } else {
        draft.offset
    };
    draft.write_roots = binds;
    Ok(words)
}

/// The binds for `config`'s writable paths, read against `base`.
#[cfg(test)]
pub(super) fn words_with(config: &Config, base: &PathBase) -> Result<Vec<OsString>, PathError> {
    Ok(bind_words(&bind_paths(base, config)?))
}

fn bind_words(binds: &[String]) -> Vec<OsString> {
    binds
        .iter()
        .flat_map(|path| ["--bind", path, path].map(OsString::from))
        .collect()
}

/// Every path a bwrap invocation binds writable: the default write roots,
/// then `allowWrite` after them, in the one list upstream's `writeNamesOf`
/// makes.
pub(super) fn bind_paths(base: &PathBase, config: &Config) -> Result<Vec<String>, PathError> {
    let split = split_path_entries(&config.filesystem.allow_write);
    let mut paths = default_write_paths(base, config)?;
    paths.extend(strip_write_globs(base, &split.spelled, ListKind::Allow)?);
    paths.extend(split.marked.iter().map(|path| (*path).to_owned()));
    let mut binds = Vec::new();
    for path in paths {
        if let Some(bound) = bind_of(base, &path)? {
            binds.push(bound);
        }
    }
    Ok(binds)
}

/// A write list's spellings as paths.
///
/// A trailing `/**` says "the directory and all under it", which a bind of the
/// directory already does. What is still a pattern binds nothing: bwrap binds
/// paths, and a pattern is not one. A spelling that is also the name of a path
/// is kept as that name.
pub(super) fn strip_write_globs(
    base: &PathBase,
    spellings: &[&str],
    kind: ListKind,
) -> Result<Vec<String>, PathError> {
    let mut paths = Vec::new();
    for spelling in spellings {
        let stripped = remove_trailing_glob_suffix(spelling);
        if contains_glob_chars(&stripped) && !has_name_reading(base, &stripped, kind)? {
            continue;
        }
        paths.push(stripped);
    }
    Ok(paths)
}

/// Whether `spelling` is also the name of a directory or file, which is what a
/// bind needs.
fn has_name_reading(base: &PathBase, spelling: &str, kind: ListKind) -> Result<bool, PathError> {
    Ok(literal_readings(base, spelling, kind)?
        .iter()
        .any(|reading| matches!(reading, PathReading::Name { .. })))
}

/// The path to bind for `spelling`, and `None` for one bwrap is asked not to
/// make writable.
fn bind_of(base: &PathBase, spelling: &str) -> Result<Option<String>, PathError> {
    let path = normalize_path_for_sandbox(base, spelling, true)?;
    // An empty `HOME` makes `~` empty, and the empty spelling names no path:
    // `allowWrite: ["~"]` is not a grant of the whole filesystem.
    if path.is_empty() {
        return Ok(None);
    }
    // The `private_mounts` section's `--dev /dev` follows this one and holds
    // the sandbox's own stdio, writable on its own.
    if path.starts_with("/dev/") {
        return Ok(None);
    }
    // bwrap binds what is there. A path that is not, or that a link leads out
    // of its own tree, is not one it may make writable: the bind would follow
    // the link and open what the caller never named.
    let resolved = match real_path_of(base, &path) {
        Ok(resolved) => resolved,
        Err(_) => return Ok(None),
    };
    if resolved != path && is_symlink_outside_boundary(&path, &resolved) {
        return Ok(None);
    }
    Ok(Some(path))
}
