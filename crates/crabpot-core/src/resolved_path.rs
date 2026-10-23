//! A path entry as a sandbox matches it, once it is made absolute and its
//! symlinks are resolved.
//!
//! A port of the entries `src/sandbox/macos-sandbox-utils.ts` builds from a
//! read list: `toPathEntry`, `toLiteralPathEntry`, `alsoReadAs`,
//! `callerEntries` and `inBothSpellings`, for a deny and for an allow.

use crate::glob::{deny_glob_matches, deny_glob_regex, escape_regex_literal, glob_to_regex};
use crate::path::{
    PathBase, PathError, contains_glob_chars, is_at_or_under, normalize_path_for_sandbox,
    path_spellings,
};
use crate::path::{dirname, is_strictly_under, remove_trailing_glob_suffix};
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
    /// The name of one file or directory, whatever characters it holds.
    #[must_use]
    pub fn named(path: impl Into<String>) -> Self {
        Self::Name { path: path.into() }
    }

    /// The paths `pattern` matches beneath `anchor`, which is a name on disk
    /// and not pattern, since a directory may hold `[`, `*` or `?` in its own
    /// name. `anchor` has no trailing `/`, except for the root itself.
    #[must_use]
    pub fn beneath(anchor: &str, pattern: &str) -> Self {
        let separator = if anchor.ends_with('/') { "" } else { "/" };
        Self::Pattern {
            path: format!("{anchor}{separator}{pattern}"),
            anchor: Some(anchor.to_owned()),
        }
    }

    /// The path, or the pattern.
    #[must_use]
    pub fn path(&self) -> &str {
        match self {
            Self::Name { path } | Self::Pattern { path, .. } => path,
        }
    }

    /// The regular expression for an allow of this pattern, which matches the
    /// paths it spells and not what is beneath them. `None` for a name.
    #[must_use]
    pub fn allow_regex(&self) -> Option<String> {
        self.regex(glob_to_regex)
    }

    /// The regular expression for a deny of this pattern, which covers
    /// everything beneath each match as `subpath` does for a name. `None` for
    /// a name.
    #[must_use]
    pub fn deny_regex(&self) -> Option<String> {
        self.regex(deny_glob_regex)
    }

    /// What `compile` makes of the tail of a pattern, behind its anchor taken as
    /// the name it is.
    fn regex(&self, compile: fn(&str) -> String) -> Option<String> {
        let Self::Pattern { path, anchor } = self else {
            return None;
        };
        Some(match anchor {
            None => compile(path),
            Some(anchor) => {
                let tail = compile(path.get(anchor.len()..).unwrap_or_default());
                format!("^{}{}", escape_regex_literal(anchor), &tail[1..])
            }
        })
    }

    /// Whether this is a pattern and not a name.
    #[must_use]
    pub fn is_pattern(&self) -> bool {
        matches!(self, Self::Pattern { .. })
    }

    /// Whether a deny of this pattern matches `sample`, which is how it is
    /// asked whether it covers the region a path points at. A name covers
    /// nothing here: `subpath` is told by [`ResolvedPath::is_strictly_under`].
    #[must_use]
    pub fn deny_covers(&self, sample: &str) -> bool {
        let Self::Pattern { path, anchor } = self else {
            return false;
        };
        let anchor = anchor.as_deref().unwrap_or_default();
        sample.strip_prefix(anchor).is_some_and(|rest| {
            deny_glob_matches(path.get(anchor.len()..).unwrap_or_default(), rest)
        })
    }

    /// Whether a deny of this pattern matches `/` itself, which a `/*`-shaped
    /// pattern does.
    #[must_use]
    pub fn denies_root(&self) -> bool {
        self.deny_covers("/")
    }

    /// A concrete path shaped like the ones this matches: each wildcard and set
    /// of a pattern is a literal `x`. A name, and the anchor of a pattern, are
    /// as they are.
    #[must_use]
    pub fn sample_path(&self) -> String {
        let Self::Pattern { path, anchor } = self else {
            return self.path().to_owned();
        };
        let anchor = anchor.as_deref().unwrap_or_default();
        let tail = path.get(anchor.len()..).unwrap_or_default();
        let mut sample = String::from(anchor);
        let mut rest = tail;
        while let Some(c) = rest.chars().next() {
            let width = match c {
                '*' | '?' => rest.find(|c| !matches!(c, '*' | '?')).unwrap_or(rest.len()),
                '[' => match rest.find(']') {
                    Some(close) => close + 1,
                    None => {
                        sample.push(c);
                        rest = &rest[1..];
                        continue;
                    }
                },
                _ => {
                    sample.push(c);
                    rest = &rest[c.len_utf8()..];
                    continue;
                }
            };
            sample.push('x');
            rest = &rest[width..];
        }
        sample
    }

    /// Whether the region this points at lies beneath `dir`, and not at it.
    #[must_use]
    pub fn is_strictly_under(&self, dir: &str) -> bool {
        is_strictly_under(&self.sample_path(), dir)
    }

    /// The directory that bounds where this can match: its anchor, the static
    /// prefix of a pattern, or the path itself for a name.
    #[must_use]
    pub fn base_dir(&self) -> String {
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

/// `path` with the links resolved: the whole path, or `None` when none is.
fn resolved(base: &PathBase, path: &str) -> String {
    path_spellings(base, path)
        .into_iter()
        .nth(1)
        .unwrap_or_else(|| path.to_owned())
}

/// Where the name `path` lives: its parent directories with their links
/// resolved, its last component as written. An allow of a link names the link,
/// and nothing it points at.
fn name_location(base: &PathBase, path: &str) -> String {
    if path == "/" {
        return path.to_owned();
    }
    let parent = resolved(base, dirname(path));
    let name = path.rsplit('/').next().unwrap_or_default();
    format!("{}/{name}", if parent == "/" { "" } else { &parent })
}

/// A read entry in the spelling given and in the one with its links resolved.
/// A deny is resolved to its end, and so is a pattern's directory. An allow
/// names a path, so its last component stays as written. The root is never a
/// second spelling, nor is anything among the devices: a rule on a name
/// blanked with a link to `/dev/null` would be one on `/dev/null` for every
/// command.
fn in_both_spellings(base: &PathBase, kind: ListKind, entry: ResolvedPath) -> Vec<ResolvedPath> {
    let base_dir = entry.base_dir();
    let canonical = if kind == ListKind::Deny || entry.is_pattern() {
        resolved(base, &base_dir)
    } else {
        name_location(base, &base_dir)
    };
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

/// The entries of a deny list, in every reading each has; see [`read_entries`].
///
/// # Errors
///
/// [`PathError`] when an entry needs a home directory or a working directory
/// and has none.
pub(crate) fn deny_entries(
    base: &PathBase,
    entries: &[PathEntry],
) -> Result<Vec<ResolvedPath>, PathError> {
    read_entries(base, entries, ListKind::Deny)
}

/// The entries of an allow list, in every reading each has; see
/// [`read_entries`].
///
/// # Errors
///
/// [`PathError`] when an entry needs a home directory or a working directory
/// and has none.
pub(crate) fn allow_entries(
    base: &PathBase,
    entries: &[PathEntry],
) -> Result<Vec<ResolvedPath>, PathError> {
    read_entries(base, entries, ListKind::Allow)
}

/// The entries of a read list, in every reading each has: as written, as the
/// name it also is where a directory holds glob characters (one `kind` takes),
/// and with its links resolved. A trailing `/**` says only "and everything
/// beneath", which both a deny and an allow do anyway, so it is dropped.
fn read_entries(
    base: &PathBase,
    entries: &[PathEntry],
    kind: ListKind,
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
        for reading in literal_readings(base, spelling, kind)? {
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
        .flat_map(|entry| in_both_spellings(base, kind, entry))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(path: &str, anchor: Option<&str>) -> ResolvedPath {
        ResolvedPath::Pattern {
            path: path.to_owned(),
            anchor: anchor.map(str::to_owned),
        }
    }

    #[test]
    fn a_sample_path_puts_an_x_for_each_wildcard_and_set() {
        for (path, anchor, sample) in [
            ("/a/**/*.key", None, "/a/x/x.key"),
            ("/a/b?c", None, "/a/bxc"),
            ("/a/[d]/e[f-h]", None, "/a/x/ex"),
            ("/a/*?*", None, "/a/x"),
            // A bracket with no end is text, and so is a `]` with no start.
            ("/a/[b", None, "/a/[b"),
            ("/a/b]", None, "/a/b]"),
            // The anchor is a name on disk.
            ("/a[1]/*", Some("/a[1]"), "/a[1]/x"),
        ] {
            assert_eq!(pattern(path, anchor).sample_path(), sample, "{path}");
        }
    }

    #[test]
    fn a_pattern_beneath_a_directory_keeps_the_directory_a_name() {
        let beneath = ResolvedPath::beneath("/a[1]", "**/.bashrc");

        assert_eq!(beneath, pattern("/a[1]/**/.bashrc", Some("/a[1]")));
        assert_eq!(
            beneath.deny_regex().as_deref(),
            Some(r"^/a\[1\]/(.*/)?\.bashrc(/.*)?$")
        );
        assert_eq!(beneath.base_dir(), "/a[1]");
    }

    #[test]
    fn a_pattern_beneath_the_root_has_one_separator() {
        let beneath = ResolvedPath::beneath("/", "**/.bashrc");
        assert_eq!(beneath.path(), "/**/.bashrc");
        assert!(beneath.deny_covers("/Users/x/.bashrc"));
    }

    #[test]
    fn a_named_path_is_a_name() {
        assert_eq!(
            ResolvedPath::named("/a[1]"),
            ResolvedPath::Name {
                path: "/a[1]".to_owned()
            }
        );
    }

    #[test]
    fn a_name_is_its_own_sample() {
        let name = ResolvedPath::Name {
            path: "/a/[b]".to_owned(),
        };

        assert_eq!(name.sample_path(), "/a/[b]");
    }

    #[test]
    fn a_deny_pattern_covers_what_it_matches_and_what_is_beneath() {
        let region = pattern("/h/**/*", None);
        let leaf = pattern("/h/**/*.key", None);
        let anchored = pattern("/a[1]/*", Some("/a[1]"));

        assert!(region.deny_covers("/h/proj"));
        assert!(region.deny_covers("/h/proj/deeper"));
        assert!(!leaf.deny_covers("/h/proj"));
        assert!(leaf.deny_covers("/h/proj/x.key/inside"));
        assert!(anchored.deny_covers("/a[1]/x"));
        assert!(!anchored.deny_covers("/a1/x"));
    }

    #[test]
    fn a_name_beneath_a_directory_is_strictly_under_it_and_not_at_it() {
        let name = ResolvedPath::Name {
            path: "/h/proj".to_owned(),
        };

        assert!(name.is_strictly_under("/h"));
        assert!(name.is_strictly_under("/"));
        assert!(!name.is_strictly_under("/h/proj"));
        assert!(!name.is_strictly_under("/h/pro"));
    }
}
