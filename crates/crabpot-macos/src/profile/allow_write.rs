//! What a sandboxed command may write: the default roots, then the config's
//! `allowWrite` after them.
//!
//! Upstream's `writeRootEntries` and the allow half of `generateWriteRules`.
//!
//! Nothing here denies upstream's mandatory paths (`.git/hooks`, `.git/config`,
//! shell rc files and the rest) inside an allowed root. That is issue #38, and
//! until it lands an `allowWrite` root is writable all the way down.

use crabpot_core::config::Config;
use crabpot_core::paths::{
    ListKind, PathBase, PathError, remove_trailing_glob_suffix, split_path_entries,
};

use super::filter::{Entry, caller_entries, render_rule};
use super::write_roots::default_write_paths;

pub(super) fn rules(config: &Config, base: &PathBase) -> Result<String, PathError> {
    let split = split_path_entries(&config.filesystem.allow_write);
    // A trailing `/**` says "the directory and all under it", which a subpath
    // already does. A glob that still is one is kept: only Linux drops it.
    let mut allow_only = default_write_paths(base, config)?;
    allow_only.extend(
        split
            .spelled
            .into_iter()
            .map(remove_trailing_glob_suffix),
    );
    let marked: Vec<String> = split.marked.into_iter().map(str::to_owned).collect();
    let roots = caller_entries(base, ListKind::Allow, &allow_only, &marked)?;
    Ok(format!(
        "\n; Writes\n{}",
        render_rule("allow", &["file-write*"], roots.iter().map(Entry::filter))
    ))
}

#[cfg(test)]
mod tests {
    use crabpot_core::config::{Config, PathEntry};
    use crabpot_core::paths::PathBase;

    use super::*;

    const HOME: &str = "/crabpot-test-home/me";

    fn base() -> PathBase {
        PathBase::new(Some(HOME.to_owned()), Some("/crabpot-test-work".to_owned()))
    }

    fn allowing(entries: Vec<PathEntry>) -> Config {
        let mut config = Config::default();
        config.filesystem.allow_write = entries;
        config
    }

    fn spelled(path: &str) -> PathEntry {
        PathEntry::Spelled(path.to_owned())
    }

    /// The filters of the one `(allow file-write*` rule, in order.
    fn filters(config: &Config) -> Vec<String> {
        let rules = rules(config, &base()).unwrap();
        let lines: Vec<&str> = rules.lines().collect();
        let start = lines
            .iter()
            .position(|line| *line == "(allow file-write*")
            .expect("an allow rule");
        lines[start + 1..]
            .iter()
            .take_while(|line| !line.starts_with("  (with message"))
            .map(|line| line.trim().to_owned())
            .collect()
    }

    #[test]
    fn allow_write_follows_the_defaults() {
        let filters = filters(&allowing(vec![
            spelled("/crabpot-test-work/project"),
            spelled("/crabpot-test-work/other"),
        ]));

        assert_eq!(filters[0], r#"(subpath "/dev/stdout")"#);
        let defaults_end = filters
            .iter()
            .position(|filter| filter == r#"(subpath "/crabpot-test-home/me/.claude/debug")"#)
            .expect("the last default root");
        assert_eq!(
            filters[defaults_end + 1..],
            [
                r#"(subpath "/crabpot-test-work/project")"#,
                r#"(subpath "/crabpot-test-work/other")"#,
            ]
        );
    }

    #[test]
    fn a_trailing_double_star_is_the_directory() {
        assert_eq!(
            filters(&allowing(vec![spelled("/crabpot-test-work/out/**")])).last(),
            Some(&r#"(subpath "/crabpot-test-work/out")"#.to_owned())
        );
    }

    #[test]
    fn a_glob_is_a_regular_expression() {
        assert_eq!(
            filters(&allowing(vec![spelled("/crabpot-test-work/*.log")])).last(),
            Some(&r#"(regex "^/crabpot-test-work/[^/]*\\.log$")"#.to_owned())
        );
    }

    #[test]
    fn a_glob_with_a_trailing_separator_matches_only_a_directory() {
        assert_eq!(
            filters(&allowing(vec![spelled("/crabpot-test-work/*/")])).last(),
            Some(&r#"(regex "^/crabpot-test-work/[^/]*/$")"#.to_owned())
        );
    }

    #[test]
    fn a_marked_path_is_a_name_whatever_it_holds() {
        let config = allowing(vec![PathEntry::Literal("/crabpot-test-work/a[1]".to_owned())]);

        assert_eq!(
            filters(&config).last(),
            Some(&r#"(subpath "/crabpot-test-work/a[1]")"#.to_owned())
        );
    }

    #[test]
    fn a_relative_path_and_a_tilde_are_resolved() {
        let filters = filters(&allowing(vec![spelled("out"), spelled("~/cache")]));

        assert_eq!(
            filters[filters.len() - 2..],
            [
                r#"(subpath "/crabpot-test-work/out")"#,
                r#"(subpath "/crabpot-test-home/me/cache")"#,
            ]
        );
    }
}
