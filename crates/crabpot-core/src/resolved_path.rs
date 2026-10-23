//! A path entry as a sandbox matches it, once it is made absolute and its
//! symlinks are resolved.
//!
//! A port of the entries `src/sandbox/macos-sandbox-utils.ts` builds from a
//! read list: `toPathEntry`, `toLiteralPathEntry`, `alsoReadAs`,
//! `callerEntries` and `inBothSpellings`, for a deny.

use crate::glob::{deny_glob_matches, deny_glob_regex, escape_regex_literal};
use crate::path::{
    PathBase, PathError, contains_glob_chars, is_at_or_under, normalize_path_for_sandbox,
    path_spellings,
};
use crate::path::{dirname, remove_trailing_glob_suffix};
use crate::path_entries::{ListKind, PathEntry, PathReading, literal_readings, split_path_entries};

/// Where a rule applies: one path and what is beneath it, or the paths a
/// pattern matches.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ResolvedPath {
    /// The name of one file or directory, whatever characters it holds.
    Name {
        /// The absolute path.
        path: String,
    },
    /// A glob pattern.
    Pattern {
        /// The absolute pattern.
        path: String,
        /// The leading directory of `path` that is a name on disk, and not
        /// pattern, since a directory may hold `[`, `*` or `?` in its own name.
        anchor: Option<String>,
    },
}

impl ResolvedPath {
    /// The path, or the pattern.
    #[must_use]
    pub fn path(&self) -> &str {
        match self {
            Self::Name { path } | Self::Pattern { path, .. } => path,
        }
    }

    /// The regular expression for a deny of this pattern, which covers
    /// everything beneath each match as `subpath` does for a name. `None` for
    /// a name.
    #[must_use]
    pub fn deny_regex(&self) -> Option<String> {
        let Self::Pattern { path, anchor } = self else {
            return None;
        };
        Some(match anchor {
            None => deny_glob_regex(path),
            Some(anchor) => {
                let tail = deny_glob_regex(path.get(anchor.len()..).unwrap_or_default());
                format!("^{}{}", escape_regex_literal(anchor), &tail[1..])
            }
        })
    }

    /// Whether a deny of this pattern matches `/` itself, which a `/*`-shaped
    /// pattern does.
    #[must_use]
    pub fn denies_root(&self) -> bool {
        let Self::Pattern { path, anchor } = self else {
            return false;
        };
        let anchor = anchor.as_deref().unwrap_or_default();
        "/".strip_prefix(anchor).is_some_and(|rest| {
            deny_glob_matches(path.get(anchor.len()..).unwrap_or_default(), rest)
        })
    }

    /// The directory that bounds where this can match: its anchor, the static
    /// prefix of a pattern, or the path itself for a name.
    fn base_dir(&self) -> String {
        match self {
            Self::Name { path } => path.clone(),
            Self::Pattern {
                anchor: Some(anchor),
                ..
            } => anchor.clone(),
            Self::Pattern { path, anchor: None } => {
                let static_prefix = path.split(['*', '?', '[', ']']).next().unwrap_or_default();
                match static_prefix {
                    "" | "/" => "/".to_owned(),
                    prefix => prefix
                        .strip_suffix('/')
                        .unwrap_or_else(|| dirname(prefix))
                        .to_owned(),
                }
            }
        }
    }
}

/// A spelling from the caller's list: its `*`, `?` and `[` are read as glob
/// syntax. The decision is made on the spelling as written, since making it
/// absolute can splice in a directory whose own name holds those characters.
fn spelled(base: &PathBase, spelling: &str) -> Result<ResolvedPath, PathError> {
    if contains_glob_chars(spelling) {
        Ok(ResolvedPath::Pattern {
            path: normalize_path_for_sandbox(base, spelling, false)?,
            anchor: None,
        })
    } else {
        named(base, spelling)
    }
}

/// A path that names one file or directory, whatever characters it holds.
fn named(base: &PathBase, path: &str) -> Result<ResolvedPath, PathError> {
    Ok(ResolvedPath::Name {
        path: normalize_path_for_sandbox(base, path, true)?,
    })
}

/// A deny entry in the spelling given and in the one with its links resolved.
/// The root is never a second spelling, nor is anything among the devices: a
/// rule on a name blanked with a link to `/dev/null` would be one on
/// `/dev/null` for every command.
fn in_both_spellings(base: &PathBase, entry: ResolvedPath) -> Vec<ResolvedPath> {
    let base_dir = entry.base_dir();
    let canonical = path_spellings(base, &base_dir)
        .into_iter()
        .nth(1)
        .unwrap_or_else(|| base_dir.clone());
    if canonical == base_dir || canonical == "/" || is_at_or_under(&canonical, "/dev") {
        return vec![entry];
    }
    let resolved = match &entry {
        ResolvedPath::Name { .. } => ResolvedPath::Name {
            path: canonical.clone(),
        },
        ResolvedPath::Pattern { path, .. } => ResolvedPath::Pattern {
            path: format!(
                "{canonical}{}",
                path.get(base_dir.len()..).unwrap_or_default()
            ),
            anchor: Some(canonical.clone()),
        },
    };
    vec![entry, resolved]
}

/// The entries of a deny list, in every reading each has: as written, as the
/// name it also is where a directory holds glob characters, and with its links
/// resolved. A trailing `/**` says only "and everything beneath", which a
/// deny does anyway, so it is dropped.
///
/// # Errors
///
/// [`PathError`] when an entry needs a home directory or a working directory
/// and has none.
pub(crate) fn deny_entries(
    base: &PathBase,
    entries: &[PathEntry],
) -> Result<Vec<ResolvedPath>, PathError> {
    let split = split_path_entries(entries);
    let mut stripped: Vec<String> = Vec::new();
    for spelling in split.spelled {
        let spelling = remove_trailing_glob_suffix(spelling);
        if !stripped.contains(&spelling) {
            stripped.push(spelling);
        }
    }

    let mut readings = Vec::new();
    for spelling in &stripped {
        readings.push(spelled(base, spelling)?);
    }
    for spelling in &stripped {
        for reading in literal_readings(base, spelling, ListKind::Deny)? {
            readings.push(match reading {
                PathReading::Name { path } => ResolvedPath::Name { path },
                PathReading::Pattern { path, anchor } => ResolvedPath::Pattern {
                    path,
                    anchor: Some(anchor),
                },
            });
        }
    }
    for path in split.marked {
        readings.push(named(base, path)?);
    }
    Ok(readings
        .into_iter()
        .flat_map(|entry| in_both_spellings(base, entry))
        .collect())
}
