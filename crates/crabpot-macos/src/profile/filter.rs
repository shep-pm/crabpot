//! The path filters of a rule, from the entries a config lists.
//!
//! Upstream's `callerEntries` and `pathFilter`. Seatbelt reads a
//! later rule over an earlier one, so every section that lists paths builds
//! its filters here and orders them itself.

use crabpot_core::PathError;
use crabpot_core::paths::{
    ListKind, PathBase, PathReading, contains_glob_chars, escape_regex_literal, glob_to_regex,
    literal_readings, normalize_path_for_sandbox,
};

use super::rule;

/// A path, or a pattern, as the profile spells it.
pub(super) enum Entry {
    /// The path and everything beneath it.
    Subpath(String),
    /// A pattern. `anchor` is a directory at its start that is a name on disk,
    /// whatever characters it holds, so only what follows it is pattern.
    Pattern {
        path: String,
        anchor: Option<String>,
    },
}

impl Entry {
    /// A spelling from a settings file: a pattern when its characters read as
    /// one, decided before any `~` or relative path is resolved, since the
    /// directory it resolves to may have glob characters in its name.
    fn spelled(base: &PathBase, spelling: &str) -> Result<Self, PathError> {
        if contains_glob_chars(spelling) {
            Ok(Self::Pattern {
                path: normalize_path_for_sandbox(base, spelling, false)?,
                anchor: None,
            })
        } else {
            normalize_path_for_sandbox(base, spelling, true).map(Self::Subpath)
        }
    }

    fn reading(reading: PathReading) -> Self {
        match reading {
            PathReading::Name { path } => Self::Subpath(path),
            PathReading::Pattern { path, anchor } => Self::Pattern {
                path,
                anchor: Some(anchor),
            },
        }
    }

    /// The path, or the pattern, as this entry spells it.
    pub(super) fn path(&self) -> &str {
        match self {
            Self::Subpath(path) | Self::Pattern { path, .. } => path,
        }
    }

    /// Whether this names one file or directory rather than a pattern.
    pub(super) fn is_pattern(&self) -> bool {
        matches!(self, Self::Pattern { .. })
    }

    /// The SBPL filter that matches this entry.
    pub(super) fn filter(&self) -> String {
        match self {
            Self::Subpath(path) => format!("(subpath {})", rule::string(path)),
            Self::Pattern { path, anchor: None } => {
                format!("(regex {})", rule::string(&glob_to_regex(path)))
            }
            Self::Pattern {
                path,
                anchor: Some(anchor),
            } => {
                let tail = glob_to_regex(path.get(anchor.len()..).unwrap_or_default());
                let regex = format!("^{}{}", escape_regex_literal(anchor), &tail[1..]);
                format!("(regex {})", rule::string(&regex))
            }
        }
    }
}

/// One of a config's lists as entries, in every reading each spelling has:
/// as written, as the path it also names where one exists, and the marked
/// paths as the names they are.
pub(super) fn caller_entries(
    base: &PathBase,
    kind: ListKind,
    spellings: &[String],
    literal_paths: &[String],
) -> Result<Vec<Entry>, PathError> {
    let mut entries = Vec::new();
    for spelling in spellings {
        entries.push(Entry::spelled(base, spelling)?);
    }
    for spelling in spellings {
        entries.extend(
            literal_readings(base, spelling, kind)?
                .into_iter()
                .map(Entry::reading),
        );
    }
    for path in literal_paths {
        entries.push(Entry::Subpath(normalize_path_for_sandbox(
            base, path, true,
        )?));
    }
    Ok(entries)
}
