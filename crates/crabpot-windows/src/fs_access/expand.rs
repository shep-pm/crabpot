//! `expandWindowsFsPaths`: the lists of the settings as the concrete paths
//! `srt-win` is handed.

use core::fmt;

use crabpot_core::config::PathEntry;

use super::spelling::{
    contains_glob_chars, expand_env_references, has_env_references, is_absolute, is_unprobed,
    strip_extended_prefix, tilde_rest, win32_normalize, win32_resolve,
};
use super::walk::expand_glob;
use super::{Disk, Host, Ordered};

/// What a list is expanded for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// `allowRead` and `allowWrite`: a path that is not there is dropped, since
    /// a grant on nothing means nothing.
    Grant,
    /// `denyRead`, `denyWrite` and the credential files: a path that is not
    /// there is kept, and `srt-win` makes a placeholder for the deny to land
    /// on. A trailing separator in the entry marks a directory.
    Deny,
}

/// A path could not be made absolute because what it is read against is
/// missing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpandError {
    /// A path starts with `~` or holds `%USERPROFILE%`, `%HOMEDRIVE%` or
    /// `%HOMEPATH%`, and the host has no home directory.
    NoHomeDirectory,
    /// A path is relative, and the host has no working directory.
    NoWorkingDirectory,
}

impl fmt::Display for ExpandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoHomeDirectory => "a path needs the home directory and USERPROFILE is not set",
            Self::NoWorkingDirectory => "a path is relative and there is no working directory",
        })
    }
}

impl core::error::Error for ExpandError {}

/// The first character of a drive spelled in lower case, upper case, so `c:\`
/// and `C:\` are one spelling.
fn upper_drive(path: String) -> String {
    let mut chars = path.chars();
    match (chars.next(), chars.next()) {
        (Some(drive), Some(':')) if drive.is_ascii_lowercase() => {
            format!("{}{}", drive.to_ascii_uppercase(), &path[1..])
        }
        _ => path,
    }
}

impl<D: Disk> Host<D> {
    /// `p` as itself if that is how the disk resolves it: the same path once
    /// both are normalized. Upstream accepts a resolution on Windows no other
    /// way, since its boundary check splits on `/` and takes any other
    /// resolution for one that leaves the path's tree.
    fn resolved_if_same(&self, path: &str) -> Option<String> {
        match self.look(path) {
            super::Look::Resolved(real) if win32_normalize(path) == win32_normalize(&real) => {
                Some(real)
            }
            _ => None,
        }
    }

    /// `normalizePathForSandbox` on Windows: `%USERPROFILE%` and `~` expanded,
    /// the `\\?\` prefix gone, the drive letter upper case and a relative path
    /// made absolute. A glob keeps its pattern, and the directory before it is
    /// resolved. `literal` is a path that is never a pattern.
    fn normalize_for_sandbox(&self, pattern: &str, literal: bool) -> Result<String, ExpandError> {
        let mut path = pattern.to_owned();
        if has_env_references(&path) {
            path = expand_env_references(&path, self.home()?);
        }
        let path = upper_drive(strip_extended_prefix(&path));
        let is_glob = !literal && contains_glob_chars(&path);
        // A share or a device is never looked at: that is an SMB request, or a
        // connection to a pipe, with the real user's credentials.
        if is_unprobed(&path) && !is_glob {
            return Ok(win32_normalize(&path));
        }
        let normalized = if let Some(rest) = tilde_rest(&path) {
            format!("{}{rest}", self.home()?)
        } else if !is_absolute(&path) {
            win32_resolve(self.cwd()?, &path)
        } else {
            path
        };
        if !literal && contains_glob_chars(&normalized) {
            let before_glob = normalized.split(['*', '?']).next().unwrap_or_default();
            let base_len = before_glob.rfind(['\\', '/']).unwrap_or(0);
            if base_len > 0
                && let Some(real) = self.resolved_if_same(&normalized[..base_len])
            {
                return Ok(format!("{real}{}", &normalized[base_len..]));
            }
            return Ok(normalized);
        }
        Ok(self.resolved_if_same(&normalized).unwrap_or(normalized))
    }
}

/// Resolves a list of the settings to concrete paths. A pattern is expanded
/// now, by a walk of the disk that ignores case, and a path that appears
/// afterwards is not covered. A directory is accepted as it is: the ACE that
/// `srt-win` sets on it covers what is beneath.
///
/// A share (`\\server\share\…`) is passed through as spelled, in either mode,
/// and never looked at. A pattern on a share is walked. A literal entry that
/// holds `*` or `?` is skipped: no Win32 name has them.
///
/// # Errors
///
/// [`ExpandError`] when an entry needs a home or working directory the host
/// does not have.
pub fn expand_paths<D: Disk>(
    host: &Host<D>,
    entries: &[PathEntry],
    mode: Mode,
) -> Result<Vec<String>, ExpandError> {
    let mut out = Ordered::default();
    for entry in entries {
        let (raw, marked) = match entry {
            PathEntry::Spelled(raw) => (raw, false),
            PathEntry::Literal(raw) => (raw, true),
        };
        let norm = host.normalize_for_sandbox(raw, marked)?;
        if marked && contains_glob_chars(&norm) {
            continue;
        }
        let is_glob = !marked && contains_glob_chars(&norm);
        if is_unprobed(&norm) && !is_glob {
            out.insert(&norm);
            continue;
        }
        let candidates = if is_glob {
            expand_glob(host.disk(), &norm)
        } else {
            vec![norm]
        };
        for candidate in candidates {
            if host.disk().exists(&candidate) {
                out.insert(&candidate);
            } else if mode == Mode::Deny && !is_glob {
                // Normalizing a relative path dropped the separator that marks
                // a directory, so it goes back from the entry as written.
                let ends = |text: &str| text.ends_with(['\\', '/']);
                if ends(raw) && !ends(&candidate) {
                    out.insert(&format!("{candidate}\\"));
                } else {
                    out.insert(&candidate);
                }
            }
        }
    }
    Ok(out.into_vec())
}
