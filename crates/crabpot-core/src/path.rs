//! A filesystem path as upstream's `normalizePathForSandbox` makes it, for the
//! profiles and the mounts the platform crates build.
//!
//! A port of the POSIX half of `src/sandbox/sandbox-utils.ts` and of
//! `src/utils/real-path.ts`. The Windows branches are left out, and so is the
//! debug line upstream logs when a `..` survives.

mod lexical;
mod real_path;
#[cfg(all(test, unix))]
mod tests;

use core::fmt;
use std::env;
use std::ffi::OsString;

pub(crate) use lexical::{collapse_interior_spellings, is_absolute, is_strictly_under, resolve};
pub use lexical::{dirname, is_at_or_under};
pub(crate) use real_path::is_absence_error;
pub use real_path::real_path_of;

/// What a relative path and a leading `~` are read against.
#[derive(Clone, Debug)]
pub struct PathBase {
    home: Option<String>,
    cwd: Option<String>,
}

/// A path could not be read because the base it needs is missing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathError {
    /// The path starts with `~`, and `HOME` is not set to text.
    NoHomeDirectory,
    /// The path is relative, and the working directory is gone or is not text.
    NoWorkingDirectory,
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoHomeDirectory => "a path starts with `~` and HOME is not set",
            Self::NoWorkingDirectory => "a path is relative and there is no working directory",
        })
    }
}

impl core::error::Error for PathError {}

impl PathBase {
    /// The base of this process: `HOME`, and the working directory. An empty
    /// `HOME` is a home directory with no name, as it is to upstream. On Windows
    /// `USERPROFILE` stands in when `HOME` is not set.
    pub fn from_env() -> Self {
        let userprofile = if cfg!(windows) {
            env::var_os("USERPROFILE")
        } else {
            None
        };
        Self::new(
            home_from(env::var_os("HOME"), userprofile),
            env::current_dir()
                .ok()
                .and_then(|cwd| cwd.into_os_string().into_string().ok()),
        )
    }

    /// A base of the given home directory and working directory.
    pub fn new(home: Option<String>, cwd: Option<String>) -> Self {
        Self { home, cwd }
    }

    /// The home directory.
    ///
    /// # Errors
    ///
    /// [`PathError::NoHomeDirectory`] when `HOME` is not set to text.
    pub fn home(&self) -> Result<&str, PathError> {
        self.home.as_deref().ok_or(PathError::NoHomeDirectory)
    }

    pub(crate) fn cwd(&self) -> Result<&str, PathError> {
        self.cwd.as_deref().ok_or(PathError::NoWorkingDirectory)
    }
}

/// The home directory as text: `home`, or `userprofile` when there is no `home`.
fn home_from(home: Option<OsString>, userprofile: Option<OsString>) -> Option<String> {
    home.or(userprofile)
        .and_then(|home| home.into_string().ok())
}

/// Whether a path pattern holds a character a glob reads: `*`, `?`, `[` or `]`.
pub fn contains_glob_chars(path_pattern: &str) -> bool {
    path_pattern.contains(['*', '?', '[', ']'])
}

/// `path_pattern` without a trailing `/**`, which only says "the directory and
/// everything under it". Never empty: a pattern that was only that is `/`.
pub fn remove_trailing_glob_suffix(path_pattern: &str) -> String {
    let stripped = path_pattern.strip_suffix("/**").unwrap_or(path_pattern);
    if stripped.is_empty() { "/" } else { stripped }.to_owned()
}

/// Whether resolving the symlinks of `original` into `resolved` crosses out of
/// the path's own tree, which would widen the scope of a rule written for
/// `original`. `/tmp` and `/var` resolving beneath `/private` do not: macOS
/// spells them so.
pub fn is_symlink_outside_boundary(original: &str, resolved: &str) -> bool {
    let original = lexical::normalize(original);
    let resolved = lexical::normalize(resolved);
    if resolved == original {
        return false;
    }
    let is_system_link = original.starts_with("/tmp/") || original.starts_with("/var/");
    let canonical = if is_system_link {
        format!("/private{original}")
    } else {
        original.clone()
    };
    if is_system_link && resolved == canonical {
        return false;
    }
    if resolved == "/" {
        return true;
    }
    if resolved.split('/').filter(|part| !part.is_empty()).count() <= 1 {
        return true;
    }
    // The resolved path is an ancestor of the original: the link points at a
    // broader scope.
    if is_beneath(&original, &resolved) || (is_system_link && is_beneath(&canonical, &resolved)) {
        return true;
    }
    // What is left is inside the tree only if it is beneath the original, or
    // beneath its canonical form.
    !(is_beneath(&resolved, &original) || (is_system_link && is_beneath(&resolved, &canonical)))
}

/// `path` starts with `dir` and a `/`.
fn is_beneath(path: &str, dir: &str) -> bool {
    path.strip_prefix(dir)
        .is_some_and(|rest| rest.starts_with('/'))
}

/// `path` with a leading `~` or `~/` replaced by the home directory. `~user`
/// is a name like any other.
pub(crate) fn expand_tilde(base: &PathBase, path: &str) -> Result<String, PathError> {
    if path == "~" {
        return base.home().map(str::to_owned);
    }
    match path.strip_prefix('~') {
        Some(tail) if tail.starts_with('/') => Ok(format!("{}{tail}", base.home()?)),
        _ => Ok(path.to_owned()),
    }
}

/// The spellings that name `candidate`: as spelled, plus with every symlink
/// resolved when that differs. A path that cannot be resolved (dangling,
/// vanished) is named by its spelling alone.
pub(crate) fn path_spellings(base: &PathBase, candidate: &str) -> Vec<String> {
    match real_path_of(base, candidate) {
        Ok(resolved) if resolved != candidate => vec![candidate.to_owned(), resolved],
        _ => vec![candidate.to_owned()],
    }
}

/// The directory of a glob pattern with its symlinks resolved, and the rest of
/// the pattern behind it. None when there is no directory to resolve, it does
/// not resolve, or its link leads out of its tree.
fn resolve_glob_directory(base: &PathBase, pattern: &str) -> Option<String> {
    let static_prefix = pattern.split(['*', '?', '[', ']']).next()?;
    if static_prefix.is_empty() || static_prefix == "/" {
        return None;
    }
    let base_dir = match static_prefix.strip_suffix('/') {
        Some(dir) => dir,
        None => lexical::dirname(static_prefix),
    };
    let resolved = real_path_of(base, base_dir).ok()?;
    if is_symlink_outside_boundary(base_dir, &resolved) {
        return None;
    }
    Some(resolved + pattern.get(base_dir.len()..)?)
}

/// `path_pattern` made absolute, with its symlinks resolved.
///
/// - A leading `~` is the home directory, and a relative path is read against
///   the working directory.
/// - `//` and `/./` are folded in text. A `..` is left for the real path to
///   fold, and survives where there is none.
/// - A path that is there is its real path, unless a link took it out of its
///   own tree, when it keeps its spelling.
/// - A pattern keeps its wildcards and a trailing `/`. Only the directory
///   before the first one is resolved.
///
/// `literal` marks a path that names one file or directory rather than
/// matching several: one the library computed, one the caller marked literal,
/// or the name a pattern also is. Its `*`, `?` and `[` are characters of a
/// name, and the pattern reading is skipped.
///
/// # Errors
///
/// [`PathError`] when the path needs a home directory or a working directory
/// and has none.
pub fn normalize_path_for_sandbox(
    base: &PathBase,
    path_pattern: &str,
    literal: bool,
) -> Result<String, PathError> {
    let is_glob = |p: &str| !literal && contains_glob_chars(p);
    // A slash after a glob segment means something (`/x/*/` matches nothing),
    // and anywhere else it is only a spelling.
    let pattern = if path_pattern.ends_with('/') && !is_glob(path_pattern) {
        match path_pattern.trim_end_matches('/') {
            "" => "/",
            trimmed => trimmed,
        }
    } else {
        path_pattern
    };
    let mut normalized = expand_tilde(base, pattern)?;
    if normalized == pattern && !is_absolute(pattern) {
        normalized = lexical::resolve(base.cwd()?, pattern);
    }
    normalized = collapse_interior_spellings(&normalized);

    if is_glob(&normalized) {
        return Ok(resolve_glob_directory(base, &normalized).unwrap_or(normalized));
    }

    // The empty string is not the root: an empty `HOME` makes `~` empty, and
    // `allowWrite: ["~"]` must not become a grant of the whole filesystem.
    if !normalized.is_empty() {
        let without_dot = normalized.strip_suffix("/.").unwrap_or(&normalized);
        normalized = match without_dot.trim_end_matches('/') {
            "" => "/",
            trimmed => trimmed,
        }
        .to_owned();
    }
    if let Ok(resolved) = real_path_of(base, &normalized)
        && !is_symlink_outside_boundary(&normalized, &resolved)
    {
        normalized = resolved;
    }
    Ok(normalized)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn home_falls_back_to_userprofile_on_windows() {
        let home = Some(OsString::from("C:/Users/home"));
        let userprofile = Some(OsString::from("C:/Users/profile"));

        assert_eq!(
            home_from(None, userprofile.clone()).as_deref(),
            Some("C:/Users/profile")
        );
        assert_eq!(
            home_from(home, userprofile).as_deref(),
            Some("C:/Users/home")
        );
        assert_eq!(home_from(None, None), None);
    }
}
