//! The path filters of a rule, from the entries a config lists.
//!
//! Upstream's `callerEntries`, `pathFilter` and `renderRule`. Seatbelt reads a
//! later rule over an earlier one, so every section that lists paths builds
//! its filters here and orders them itself.

use crabpot_core::paths::{
    ListKind, PathBase, PathError, PathReading, contains_glob_chars, escape_regex_literal,
    glob_to_regex, literal_readings, normalize_path_for_sandbox,
};

/// What the profile is told to log a match as.
pub(super) const LOG_TAG: &str = "crabpot";

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

    /// The SBPL filter that matches this entry.
    pub(super) fn filter(&self) -> String {
        match self {
            Self::Subpath(path) => format!("(subpath {})", escape(path)),
            Self::Pattern { path, anchor: None } => {
                format!("(regex {})", escape(&glob_to_regex(path)))
            }
            Self::Pattern {
                path,
                anchor: Some(anchor),
            } => {
                let tail = glob_to_regex(path.get(anchor.len()..).unwrap_or_default());
                let regex = format!("^{}{}", escape_regex_literal(anchor), &tail[1..]);
                format!("(regex {})", escape(&regex))
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

/// A rule that applies `action` to each of `operations` for a path matching
/// one of `filters`, each once. Nothing for no filters: a rule with none
/// would match every path.
pub(super) fn render_rule(
    action: &str,
    operations: &[&str],
    filters: impl IntoIterator<Item = String>,
) -> String {
    let mut unique: Vec<String> = Vec::new();
    for filter in filters {
        if !unique.contains(&filter) {
            unique.push(filter);
        }
    }
    if unique.is_empty() {
        return String::new();
    }
    let mut rule = format!("({action} {}\n", operations.join(" "));
    for filter in unique {
        rule.push_str(&format!("  {filter}\n"));
    }
    rule.push_str(&format!("  (with message \"{LOG_TAG}\"))\n"));
    rule
}

/// A string as a profile reads it: JSON's escapes.
fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len() + 2);
    escaped.push('"');
    for c in text.chars() {
        match c {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\u{8}' => escaped.push_str("\\b"),
            '\u{c}' => escaped.push_str("\\f"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            c if c < ' ' => escaped.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => escaped.push(c),
        }
    }
    escaped.push('"');
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_string_is_escaped_as_json_escapes_it() {
        assert_eq!(escape("a\"b\\c\n\u{1}é"), "\"a\\\"b\\\\c\\n\\u0001é\"");
    }

    #[test]
    fn a_rule_without_filters_is_nothing() {
        assert_eq!(render_rule("allow", &["file-write*"], []), "");
    }
}
