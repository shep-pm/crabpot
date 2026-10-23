//! How an entry of `denyRead`, `allowRead`, `allowWrite` or `denyWrite` is
//! read: as the pattern its characters spell, as the path they name, or both.
//!
//! A port of `src/sandbox/path-entries.ts`, without the Linux folds. An entry
//! with `*`, `?`, `[` or `]` is a pattern. A directory may hold those in its
//! own name (`[WIP] project`), so such an entry is also read as what it names
//! wherever the part that holds the characters exists on disk. A literal entry
//! is the name and nothing else.

#![cfg_attr(
    not(test),
    expect(dead_code, reason = "the seatbelt profile slice is the first consumer")
)]

#[cfg(all(test, unix))]
mod tests;

use std::fs;

use crate::path::{
    PathBase, PathError, collapse_interior_spellings, contains_glob_chars, expand_tilde,
    is_absence_error, is_absolute, normalize_path_for_sandbox, remove_trailing_glob_suffix,
    resolve,
};

/// An entry of a path list: a spelling, which is a pattern when it reads as
/// one, or a path that never is (`{ "path": ..., "literal": true }`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathEntry {
    /// A spelling.
    Spelled(String),
    /// The name of a path, whatever characters it holds.
    Literal(String),
}

/// The spellings and the literal paths of a list, apart.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SplitEntries<'a> {
    /// What may be a pattern.
    pub spelled: Vec<&'a str>,
    /// What is a name.
    pub marked: Vec<&'a str>,
}

/// Which way a list cuts. A deny takes every reading that may hold, since one
/// more can only deny more; an allow takes one only for a path that is there
/// exactly as spelled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListKind {
    /// `allowRead` and `allowWrite`.
    Allow,
    /// `denyRead` and `denyWrite`.
    Deny,
}

/// One reading of an entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathReading {
    /// The entry is the name of this path.
    Name {
        /// The path.
        path: String,
    },
    /// The entry is a pattern beneath `anchor`, a directory taken as the name
    /// it is.
    Pattern {
        /// `anchor` plus the tail, of which only the tail is pattern.
        path: String,
        /// The directory.
        anchor: String,
    },
}

/// The read lists with the names their spellings also are added.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadRules {
    /// `denyRead`, and the names its spellings also are.
    pub deny_read: Vec<PathEntry>,
    /// `allowRead`, and the names its spellings also are.
    pub allow_read: Option<Vec<PathEntry>>,
}

/// The literal paths of a read config. A list is `None` when it is empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LiteralReadLists {
    pub(crate) literal_deny_only: Option<Vec<String>>,
    pub(crate) literal_allow_within_deny: Option<Vec<String>>,
}

/// The literal paths of a write config. A list is `None` when it is empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LiteralWriteLists {
    pub(crate) literal_allow_only: Option<Vec<String>>,
    pub(crate) literal_deny_within_allow: Option<Vec<String>>,
}

/// The spellings and the literal paths of a list, apart.
pub fn split_path_entries(entries: &[PathEntry]) -> SplitEntries<'_> {
    let mut split = SplitEntries::default();
    for entry in entries {
        match entry {
            PathEntry::Spelled(spelling) => split.spelled.push(spelling),
            PathEntry::Literal(path) => split.marked.push(path),
        }
    }
    split
}

/// The spellings among the entries of a list: what may be a pattern.
pub(crate) fn spelled_of(entries: &[PathEntry]) -> Vec<&str> {
    split_path_entries(entries).spelled
}

/// The spelling made absolute as `normalize_path_for_sandbox` does for a
/// pattern: no symlink resolved, a trailing separator kept.
fn spelled_absolute(base: &PathBase, spelling: &str) -> Result<String, PathError> {
    let expanded = expand_tilde(base, spelling)?;
    let absolute = if expanded == spelling && !is_absolute(spelling) {
        resolve(base.cwd()?, spelling)
    } else {
        expanded
    };
    Ok(collapse_interior_spellings(&absolute))
}

/// Whether something may be at `p`, for a deny. A symbolic link counts,
/// dangling or not, and so does a path that cannot be looked at: otherwise a
/// command running as the same user could switch the deny off by making a
/// parent unsearchable, and undo that inside the next sandbox.
fn may_be_there(p: &str) -> bool {
    fs::symlink_metadata(p).map_or_else(|err| !is_absence_error(&err), |_| true)
}

/// Whether `p` is there and is not a symbolic link, for an allow. Whoever can
/// write the directory that holds `p` can plant a link of that name, and the
/// allow would open what it points at. What cannot be looked at is not there.
fn is_there_unlinked(p: &str) -> bool {
    fs::symlink_metadata(p).is_ok_and(|metadata| !metadata.is_symlink())
}

/// Whether a pattern can be walked beneath `p`, under the rule of `kind`.
fn is_directory_for(kind: ListKind, p: &str) -> bool {
    match kind {
        ListKind::Allow => fs::symlink_metadata(p).is_ok_and(|metadata| metadata.is_dir()),
        ListKind::Deny => {
            fs::metadata(p).map_or_else(|err| !is_absence_error(&err), |metadata| metadata.is_dir())
        }
    }
}

/// Whether no component after `from`, up to `to`, is a symbolic link or beyond
/// looking at. What is not there yet is neither.
fn rest_is_unlinked(from: usize, to: usize, prefix: &impl Fn(usize) -> String) -> bool {
    for i in from + 1..=to {
        match fs::symlink_metadata(prefix(i)) {
            Ok(metadata) if metadata.is_symlink() => return false,
            Ok(_) => {}
            Err(err) => return is_absence_error(&err),
        }
    }
    true
}

/// The readings a caller's spelling has beside the one its characters give it.
/// Empty for a spelling that is no pattern, and for a pattern none of whose
/// glob characters are part of a name on disk: that costs one `lstat`.
///
/// A trailing `/**` is set aside first. Of the components that hold glob
/// characters, the leading ones that exist on disk as spelled are names:
///
/// - When all of them exist, the entry is also the name it spells. What follows
///   the last of them need not exist.
/// - When a pattern follows an existing one, the entry is also that pattern
///   beneath the directory. There is one such reading per existing component,
///   the longest first, so creating or removing a directory adds or removes a
///   reading and never turns one into another.
///
/// A component exists for a deny as `may_be_there` has it. For an allow no
/// component from the first with glob characters on may be a symbolic link or
/// beyond looking at: a name to its end, a pattern up to its first pattern
/// component, from where the walk of an allow goes through no link.
///
/// # Errors
///
/// [`PathError`] when the spelling needs a home directory or a working
/// directory and has none.
pub fn literal_readings(
    base: &PathBase,
    spelling: &str,
    kind: ListKind,
) -> Result<Vec<PathReading>, PathError> {
    let stripped = remove_trailing_glob_suffix(spelling);
    if !contains_glob_chars(&stripped) {
        return Ok(Vec::new());
    }
    let spelled = spelled_absolute(base, &stripped)?;

    let parts: Vec<&str> = spelled.split('/').collect();
    let glob_at: Vec<usize> = parts
        .iter()
        .enumerate()
        .filter(|(_, part)| contains_glob_chars(part))
        .map(|(i, _)| i)
        .collect();
    let (Some(&first), Some(&last)) = (glob_at.first(), glob_at.last()) else {
        return Ok(Vec::new());
    };
    let prefix = |i: usize| -> String {
        match parts[..=i].join("/") {
            joined if joined.is_empty() => "/".to_owned(),
            joined => joined,
        }
    };

    let is_there = |p: &str| match kind {
        ListKind::Deny => may_be_there(p),
        ListKind::Allow => is_there_unlinked(p),
    };
    // The count of leading components found to be there, from the first with
    // glob characters on.
    let mut reached = first;
    while reached <= last && is_there(&prefix(reached)) {
        reached += 1;
    }
    if reached == first {
        return Ok(Vec::new());
    }
    let reach = reached - 1;

    let mut readings = Vec::new();
    if reach == last && (kind == ListKind::Deny || rest_is_unlinked(last, parts.len() - 1, &prefix))
    {
        readings.push(PathReading::Name {
            path: normalize_path_for_sandbox(base, &stripped, true)?,
        });
    }

    // The tail keeps a trailing separator, which makes a pattern match nothing
    // (`/x/*/`): stripped, an allow spelled so would match every child. The
    // `/**` set aside above goes back on, for the walk's directory form.
    let set_aside = if stripped == spelling { "" } else { "/**" };
    for n in (0..glob_at.len().saturating_sub(1)).rev() {
        let at = glob_at[n];
        if at > reach {
            continue;
        }
        // As far as the directory's own name goes on: up to the next component
        // with glob characters, or to where the disk ends.
        let next = glob_at[n + 1];
        let Some(end) = (at..=(next - 1).min(reach))
            .rev()
            .find(|&end| is_directory_for(kind, &prefix(end)))
        else {
            continue;
        };
        // The walk resolves what the tail spells before its first pattern
        // component: a link there would have an allow list what it points at.
        if kind == ListKind::Allow && !rest_is_unlinked(end, next - 1, &prefix) {
            continue;
        }
        let directory = prefix(end);
        let anchor = normalize_path_for_sandbox(base, &directory, true)?;
        let tail = spelled.get(directory.len()..).unwrap_or_default();
        readings.push(PathReading::Pattern {
            path: format!("{anchor}{tail}{set_aside}"),
            anchor,
        });
    }
    Ok(readings)
}

/// The read rules the default write paths are worked out from: the entries,
/// the credential denies, and the name each spelling also is, as a literal
/// path.
///
/// # Errors
///
/// [`PathError`] as [`literal_readings`] has it.
pub fn read_rules_of(
    base: &PathBase,
    deny_read: &[PathEntry],
    allow_read: Option<&[PathEntry]>,
    credential_denies: &[String],
) -> Result<ReadRules, PathError> {
    let with_names =
        |entries: Vec<PathEntry>, kind: ListKind| -> Result<Vec<PathEntry>, PathError> {
            let mut names = Vec::new();
            for spelling in spelled_of(&entries) {
                for reading in literal_readings(base, spelling, kind)? {
                    if let PathReading::Name { path } = reading {
                        names.push(PathEntry::Literal(path));
                    }
                }
            }
            let mut with_names = entries;
            with_names.extend(names);
            Ok(with_names)
        };
    let mut denies = deny_read.to_vec();
    denies.extend(credential_denies.iter().cloned().map(PathEntry::Spelled));
    Ok(ReadRules {
        deny_read: with_names(denies, ListKind::Deny)?,
        allow_read: allow_read
            .map(|entries| with_names(entries.to_vec(), ListKind::Allow))
            .transpose()?,
    })
}

fn non_empty(list: Vec<&str>) -> Option<Vec<String>> {
    (!list.is_empty()).then(|| list.into_iter().map(str::to_owned).collect())
}

/// The `literal...` lists of a read config: the literal entries of the two read
/// lists.
pub(crate) fn literal_read_lists(
    deny_read: &[PathEntry],
    allow_read: &[PathEntry],
) -> LiteralReadLists {
    LiteralReadLists {
        literal_deny_only: non_empty(split_path_entries(deny_read).marked),
        literal_allow_within_deny: non_empty(split_path_entries(allow_read).marked),
    }
}

/// The `literal...` lists of a write config; see [`literal_read_lists`].
pub(crate) fn literal_write_lists(
    allow_write: &[PathEntry],
    deny_write: &[PathEntry],
) -> LiteralWriteLists {
    LiteralWriteLists {
        literal_allow_only: non_empty(split_path_entries(allow_write).marked),
        literal_deny_within_allow: non_empty(split_path_entries(deny_write).marked),
    }
}

/// Every path a write config allows, whichever list it came in on. Whoever
/// asks "may the command write here" asks this, not `allow_only` alone: a path
/// the caller marked literal is in `literal_allow_only` and nowhere else.
pub(crate) fn write_roots_of(allow_only: &[String], literal_allow_only: &[String]) -> Vec<String> {
    [allow_only, literal_allow_only].concat()
}

/// The paths bound back over a read deny: the read allows and the write allows,
/// the literal ones among them. A deny glob's matches are collapsed against
/// these, and one left out loses the matches beneath it their mask.
pub(crate) fn re_exposed_by(
    expanded_allow_read: &[String],
    allow_read: &[PathEntry],
    allow_only: &[String],
    literal_allow_only: &[String],
) -> Vec<String> {
    let mut paths = expanded_allow_read.to_vec();
    paths.extend(
        split_path_entries(allow_read)
            .marked
            .into_iter()
            .map(str::to_owned),
    );
    paths.extend(write_roots_of(allow_only, literal_allow_only));
    paths
}
