//! Denied names folded into one regular expression for each set of same-shaped
//! folders.
//!
//! Upstream's `groupLiteralDenyPaths` and `literalDenyGroupFilters`. A `subpath`
//! filter spells the whole path, and `sandbox-exec` takes seconds to compile a
//! few thousand of them, so a folder with many children that each hold the
//! same denied names costs one regex that lists the children and one that
//! lists the names, in place of a filter for each pair.

use crabpot_core::ResolvedPath;
use crabpot_core::paths::{dirname, escape_regex_literal};

use super::rule;

/// `sandbox-exec` rejects a string literal longer than 1025 bytes, and the one
/// that does fails the whole profile. A regex here stays well under it.
const MAX_REGEX_BYTES: usize = 900;

/// Below this many folders one regex is no shorter than the filters it replaces.
const MIN_FOLDERS: usize = 4;

/// The folders of one directory that each hold the same denied names.
pub(super) struct Group {
    dir: String,
    folders: Vec<String>,
    names: Vec<String>,
}

/// What folding left: the groups, and the entries that stay filters of their own.
pub(super) struct Folded<'a> {
    pub(super) groups: Vec<Group>,
    pub(super) rest: Vec<&'a ResolvedPath>,
}

/// The filters of a [`Group`].
pub(super) struct GroupFilters {
    /// Each `<dir>/<folder>/<name>` and everything beneath it, as `subpath`
    /// would.
    pub(super) deny: Vec<String>,
    /// Each `<dir>/<folder>` itself, which a deny of its name would pin.
    pub(super) pins: Vec<String>,
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Bytes `fragment` takes inside a string literal of the profile.
fn literal_len(fragment: &str) -> usize {
    rule::string(fragment).len() - 2
}

impl Group {
    fn prefix(&self) -> String {
        format!("^{}/(", escape_regex_literal(&self.dir))
    }

    fn deny_tail(&self) -> String {
        let names: Vec<String> = self.names.iter().map(|n| escape_regex_literal(n)).collect();
        format!(")/({})(/.*)?$", names.join("|"))
    }

    /// `<dir>/<folder>/<name>` for each pair in the group.
    fn paths(&self) -> impl Iterator<Item = String> + '_ {
        self.folders.iter().flat_map(move |folder| {
            self.names
                .iter()
                .map(move |name| format!("{}/{folder}/{name}", self.dir))
        })
    }

    /// The filters, chunked so that no regex is longer than the profile takes.
    pub(super) fn filters(&self) -> GroupFilters {
        let (prefix, deny_tail) = (self.prefix(), self.deny_tail());
        let fixed = literal_len(&prefix) + literal_len(&deny_tail);
        let mut chunks: Vec<Vec<String>> = Vec::new();
        let mut chunk: Vec<String> = Vec::new();
        let mut chunk_len = 0;
        for folder in self.folders.iter().map(|f| escape_regex_literal(f)) {
            let len = literal_len(&folder) + usize::from(!chunk.is_empty());
            if !chunk.is_empty() && fixed + chunk_len + len > MAX_REGEX_BYTES {
                chunks.push(std::mem::take(&mut chunk));
                chunk_len = 0;
            }
            chunk.push(folder);
            chunk_len += if chunk.len() == 1 {
                literal_len(&chunk[0])
            } else {
                len
            };
        }
        chunks.push(chunk);
        let regexes = |tail: &str| {
            chunks
                .iter()
                .map(|folders| {
                    format!(
                        "(regex {})",
                        rule::string(&format!("{prefix}{}{tail}", folders.join("|")))
                    )
                })
                .collect()
        };
        GroupFilters {
            deny: regexes(&deny_tail),
            pins: regexes(")$"),
        }
    }

    /// The directory that holds the folders.
    pub(super) fn dir(&self) -> &str {
        &self.dir
    }
}

/// Folds the names in `entries` that fit a group of at least [`MIN_FOLDERS`]
/// folders. Patterns, names that do not fit a group, and folders too long for
/// one regex stay in `rest`, in order.
pub(super) fn fold(entries: &[ResolvedPath]) -> Folded<'_> {
    // Directory, then its folders, then the names denied in each, all in the
    // order first seen.
    let mut by_dir: Vec<(&str, Vec<(&str, Vec<&str>)>)> = Vec::new();
    for entry in entries.iter().filter(|entry| !entry.is_pattern()) {
        let path = entry.path();
        let parent = dirname(path);
        let dir = dirname(parent);
        if dir == parent || parent == path || dir == "/" {
            continue;
        }
        let at = by_dir
            .iter()
            .position(|(d, _)| *d == dir)
            .unwrap_or_else(|| {
                by_dir.push((dir, Vec::new()));
                by_dir.len() - 1
            });
        let folders = &mut by_dir[at].1;
        let folder = basename(parent);
        let at = folders
            .iter()
            .position(|(f, _)| *f == folder)
            .unwrap_or_else(|| {
                folders.push((folder, Vec::new()));
                folders.len() - 1
            });
        let name = basename(path);
        if !folders[at].1.contains(&name) {
            folders[at].1.push(name);
        }
    }

    let mut groups: Vec<Group> = Vec::new();
    for (dir, folders) in by_dir {
        let mut by_names: Vec<Group> = Vec::new();
        for (folder, mut names) in folders {
            names.sort_unstable();
            match by_names.iter_mut().find(|g| g.names == names) {
                Some(group) => group.folders.push(folder.to_owned()),
                None => by_names.push(Group {
                    dir: dir.to_owned(),
                    folders: vec![folder.to_owned()],
                    names: names.into_iter().map(str::to_owned).collect(),
                }),
            }
        }
        for mut group in by_names {
            let fixed = literal_len(&group.prefix()) + literal_len(&group.deny_tail());
            group.folders.retain(|folder| {
                fixed + literal_len(&escape_regex_literal(folder)) <= MAX_REGEX_BYTES
            });
            if group.folders.len() >= MIN_FOLDERS {
                groups.push(group);
            }
        }
    }

    let grouped: Vec<String> = groups.iter().flat_map(Group::paths).collect();
    let rest = entries
        .iter()
        .filter(|entry| !grouped.iter().any(|path| path == entry.path()))
        .collect();
    Folded { groups, rest }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(paths: &[&str]) -> Vec<ResolvedPath> {
        paths
            .iter()
            .map(|path| ResolvedPath::named(*path))
            .collect()
    }

    fn pkgs(folders: &[&str], names: &[&str]) -> Vec<ResolvedPath> {
        folders
            .iter()
            .flat_map(|folder| {
                names
                    .iter()
                    .map(move |name| format!("/w/pkgs/{folder}/{name}"))
            })
            .map(ResolvedPath::named)
            .collect()
    }

    #[test]
    fn four_folders_that_hold_the_same_names_fold_into_two_regexes() {
        // What upstream's `wrapCommandWithSandboxMacOS` at 0.0.81 renders for
        // these eight `denyWrite` paths, less the other names it denies.
        let entries = pkgs(&["p1", "p2", "p3", "p4"], &[".env", "key"]);

        let folded = fold(&entries);

        assert!(folded.rest.is_empty());
        let [group] = folded.groups.as_slice() else {
            panic!("one group");
        };
        assert_eq!(group.dir(), "/w/pkgs");
        let filters = group.filters();
        assert_eq!(
            filters.deny,
            [r#"(regex "^/w/pkgs/(p1|p2|p3|p4)/(\\.env|key)(/.*)?$")"#]
        );
        assert_eq!(filters.pins, [r#"(regex "^/w/pkgs/(p1|p2|p3|p4)$")"#]);
    }

    #[test]
    fn three_folders_stay_filters_of_their_own() {
        let entries = pkgs(&["p1", "p2", "p3"], &[".env"]);

        let folded = fold(&entries);

        assert!(folded.groups.is_empty());
        assert_eq!(folded.rest.len(), 3);
    }

    #[test]
    fn folders_that_hold_different_names_do_not_fold_together() {
        let mut entries = pkgs(&["p1", "p2"], &[".env"]);
        entries.extend(pkgs(&["p3", "p4"], &["key"]));

        assert!(fold(&entries).groups.is_empty());
    }

    #[test]
    fn a_pattern_and_a_shallow_name_are_never_folded() {
        let mut entries = names(&["/a/.env", "/b/.env", "/c/.env", "/d/.env"]);
        entries.push(ResolvedPath::beneath("/w", "**/.env"));

        let folded = fold(&entries);

        assert!(folded.groups.is_empty());
        assert_eq!(folded.rest.len(), 5);
    }

    #[test]
    fn a_long_list_of_folders_is_chunked_under_the_limit() {
        let folders: Vec<String> = (0..60)
            .map(|n| format!("folder-with-a-long-name-{n}"))
            .collect();
        let entries = pkgs(
            &folders.iter().map(String::as_str).collect::<Vec<_>>(),
            &[".env"],
        );

        let folded = fold(&entries);

        let [group] = folded.groups.as_slice() else {
            panic!("one group");
        };
        let filters = group.filters();
        assert!(filters.deny.len() > 1, "{:?}", filters.deny);
        assert_eq!(filters.deny.len(), filters.pins.len());
        for filter in filters.deny.iter().chain(&filters.pins) {
            assert!(
                filter.len() <= MAX_REGEX_BYTES + "(regex \"\")".len() + 8,
                "{filter}"
            );
        }
    }
}
