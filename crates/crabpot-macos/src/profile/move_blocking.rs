//! What stops `mv` from undoing a deny.
//!
//! A deny on a path says nothing about the directory that holds it: renamed,
//! the directory takes the path away from the rule, and a command reads or
//! writes it under the new name. So a denied path and every directory above it
//! may be neither unlinked (which a rename is) nor created, which also stops a
//! path that does not exist yet from being made a link to somewhere else.
//!
//! Upstream's `generateMoveBlockingRules`, `moveBlockingFilters` and
//! `getAncestorDirectories`. This section is the read half, for `denyRead`;
//! `deny_write` adds the write half with [`filters`].

use core::iter;

use crabpot_core::config::Config;
use crabpot_core::paths::dirname;
use crabpot_core::{PathError, ResolvedPath};

use super::rule;

/// The operations a rename or a link needs, which a deny of a path takes away.
const OPERATIONS: [&str; 2] = ["file-write-unlink", "file-write-create"];

/// The directories above `path`, nearest first, down to but not including the
/// root.
fn ancestors(path: &str) -> Vec<String> {
    let mut ancestors = Vec::new();
    let mut current = dirname(path);
    while current != "/" && current != "." {
        ancestors.push(current.to_owned());
        current = dirname(current);
    }
    ancestors
}

fn literal(path: &str) -> String {
    format!("(literal {})", rule::string(path))
}

/// The filters that pin `dir` and every directory above it.
pub(super) fn pin_directory(dir: &str) -> Vec<String> {
    iter::once(dir.to_owned())
        .chain(ancestors(dir))
        .map(|dir| literal(&dir))
        .collect()
}

/// The filters that pin `entries`: each denied path, the directory a pattern is
/// bounded by, and every directory above those. Duplicates are left for
/// [`rule::render`] to drop.
pub(super) fn filters<'a>(entries: impl IntoIterator<Item = &'a ResolvedPath>) -> Vec<String> {
    let mut filters = Vec::new();
    for entry in entries {
        filters.push(rule::deny_filter(entry));
        let base_dir = entry.base_dir();
        if entry.is_pattern() {
            if base_dir == "/" {
                continue;
            }
            filters.push(literal(&base_dir));
        }
        filters.extend(ancestors(&base_dir).iter().map(|dir| literal(dir)));
    }
    filters
}

/// The rule that denies the operations of a rename on `filters`.
pub(super) fn deny_rule(filters: &[String]) -> String {
    rule::render("deny", &OPERATIONS, filters)
}

pub(super) fn rules(config: &Config) -> Result<String, PathError> {
    Ok(deny_rule(&filters(&config.filesystem.read_denies()?)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(path: &str) -> ResolvedPath {
        ResolvedPath::named(path)
    }

    #[test]
    fn every_ancestor_of_a_denied_path_is_pinned() {
        assert_eq!(
            filters(&[name("/crabpot-nowhere/a/b/c")]),
            [
                r#"(subpath "/crabpot-nowhere/a/b/c")"#,
                r#"(literal "/crabpot-nowhere/a/b")"#,
                r#"(literal "/crabpot-nowhere/a")"#,
                r#"(literal "/crabpot-nowhere")"#,
            ]
        );
    }

    #[test]
    fn the_root_is_not_pinned_and_a_denied_root_has_no_ancestor() {
        assert_eq!(
            filters(&[name("/a"), name("/")]),
            [r#"(subpath "/a")"#, r#"(subpath "/")"#]
        );
    }

    #[test]
    fn a_pattern_pins_the_directory_it_is_bounded_by_and_the_ones_above() {
        let leaf = ResolvedPath::beneath("/crabpot-nowhere/work", "**/.env");

        assert_eq!(
            filters(&[leaf]),
            [
                r#"(regex "^/crabpot-nowhere/work/(.*/)?\\.env(/.*)?$")"#,
                r#"(literal "/crabpot-nowhere/work")"#,
                r#"(literal "/crabpot-nowhere")"#,
            ]
        );
    }

    #[test]
    fn a_pattern_from_the_root_pins_no_directory() {
        let config = Config::from_json(
            r#"{
                "network": {"allowedDomains": [], "deniedDomains": []},
                "filesystem": {"denyRead": ["/**/*.key"], "allowWrite": [], "denyWrite": []}
            }"#,
        )
        .unwrap();

        assert_eq!(
            rules(&config).unwrap(),
            r#"(deny file-write-unlink file-write-create
  (regex "^/(.*/)?[^/]*\\.key(/.*)?$")
  (with message "crabpot"))
"#
        );
    }

    #[test]
    fn denyread_pins_each_denied_path_like_upstream() {
        // What upstream's `wrapCommandWithSandboxMacOS` at 0.0.81 renders for
        // this `denyRead` as the `(deny file-write-unlink` rule that follows
        // the read section, with its log tag swapped for ours.
        let config = Config::from_json(
            r#"{
                "network": {"allowedDomains": [], "deniedDomains": []},
                "filesystem": {
                    "denyRead": ["/crabpot-nowhere/secrets/key"],
                    "allowWrite": [], "denyWrite": []
                }
            }"#,
        )
        .unwrap();

        assert_eq!(
            rules(&config).unwrap(),
            r#"(deny file-write-unlink file-write-create
  (subpath "/crabpot-nowhere/secrets/key")
  (literal "/crabpot-nowhere/secrets")
  (literal "/crabpot-nowhere")
  (with message "crabpot"))
"#
        );
    }

    #[test]
    fn nothing_denied_pins_nothing() {
        assert_eq!(deny_rule(&filters(&[])), "");
    }
}
