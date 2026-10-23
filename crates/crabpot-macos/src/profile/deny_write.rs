//! What a sandboxed command may not write inside the paths `allowWrite` opened:
//! the paths `denyWrite` lists, the mandatory ones, and the directories above
//! them.
//!
//! Upstream's deny half of `generateWriteRules`. Seatbelt takes the last rule
//! that matches, so a deny follows the allow of the write section. A rename
//! needs `file-write-unlink`, which the deny of `file-write*` covers only for
//! the denied path itself, so a second rule pins the directories above it
//! (see `move_blocking`).

use crabpot_core::paths::PathBase;
use crabpot_core::config::Config;
use crabpot_core::{PathError, ResolvedPath};

use super::literal_groups::{self, Folded};
use super::{mandatory, move_blocking, rule};

pub(super) fn rules(config: &Config) -> Result<String, PathError> {
    let mut denies = config.filesystem.write_denies()?;
    denies.extend(mandatory::entries(
        &PathBase::from_env(),
        config.filesystem.allow_git_config.unwrap_or(false),
    )?);
    Ok(deny_rules(&denies))
}

/// The rules that deny writes to `denies` and the moves that would undo it.
fn deny_rules(denies: &[ResolvedPath]) -> String {
    let Folded { groups, rest } = literal_groups::fold(denies);
    let group_filters: Vec<_> = groups.iter().map(literal_groups::Group::filters).collect();

    let mut deny: Vec<String> = group_filters
        .iter()
        .flat_map(|filters| filters.deny.iter().cloned())
        .collect();
    deny.extend(rest.iter().map(|entry| rule::deny_filter(entry)));

    let mut pinned = move_blocking::filters(rest.iter().copied());
    for (group, filters) in groups.iter().zip(&group_filters) {
        pinned.extend(filters.deny.iter().chain(&filters.pins).cloned());
        pinned.extend(move_blocking::pin_directory(group.dir()));
    }

    rule::render("deny", &["file-write*"], &deny) + &move_blocking::deny_rule(&pinned)
}

#[cfg(test)]
mod tests {
    use crabpot_core::paths::PathBase;

    use super::super::render;
    use super::*;

    /// A config that allows `/crabpot-nowhere/work` and denies `deny_write`.
    fn denying(deny_write: &str) -> Config {
        Config::from_json(&format!(
            r#"{{
                "network": {{"allowedDomains": [], "deniedDomains": []}},
                "filesystem": {{
                    "denyRead": [],
                    "allowWrite": ["/crabpot-nowhere/work"],
                    "denyWrite": {deny_write}
                }}
            }}"#
        ))
        .unwrap()
    }

    #[test]
    fn a_deny_inside_an_allow_renders_after_it() {
        let profile = render(&denying(r#"["/crabpot-nowhere/work/.env"]"#), None, None).unwrap();

        let allow = profile.find(r#"  (subpath "/crabpot-nowhere/work")"#).unwrap();
        let deny = profile
            .find("(deny file-write*\n  (subpath \"/crabpot-nowhere/work/.env\")")
            .unwrap();
        assert!(allow < deny, "{profile}");
    }

    #[test]
    fn a_folder_a_glob_and_a_literal_render_one_rule_and_the_ones_above_them_are_pinned() {
        let config = denying(
            r#"["/crabpot-nowhere/work/secrets", "/crabpot-nowhere/work/**/*.key",
                {"path": "/crabpot-nowhere/work/a[b", "literal": true}]"#,
        );

        let rules = rules(&config).unwrap();

        assert!(
            rules.starts_with(
                r#"(deny file-write*
  (subpath "/crabpot-nowhere/work/secrets")
  (regex "^/crabpot-nowhere/work/(.*/)?[^/]*\\.key(/.*)?$")
  (subpath "/crabpot-nowhere/work/a[b")
"#
            ),
            "{rules}"
        );
        assert!(
            rules.contains(
                r#"(deny file-write-unlink file-write-create
  (subpath "/crabpot-nowhere/work/secrets")
  (literal "/crabpot-nowhere/work")
  (literal "/crabpot-nowhere")
  (regex "^/crabpot-nowhere/work/(.*/)?[^/]*\\.key(/.*)?$")
  (subpath "/crabpot-nowhere/work/a[b")
"#
            ),
            "{rules}"
        );
    }

    #[test]
    fn nothing_denied_still_denies_the_mandatory_paths() {
        let cwd = std::env::current_dir().unwrap().canonicalize().unwrap();
        let cwd = cwd.to_str().unwrap();

        let rules = rules(&denying("[]")).unwrap();

        assert!(
            rules.starts_with(&format!(
                "(deny file-write*\n  (subpath {:?})\n",
                format!("{cwd}/.gitconfig")
            )),
            "{rules}"
        );
    }

    #[test]
    fn the_mandatory_denies_render_upstreams_rules() {
        // What upstream's `wrapCommandWithSandboxMacOS` at 0.0.81 renders for a
        // `denyWrite` of nothing, as its two rules after the write allow, with
        // its log tag swapped for ours and its working directory for one no
        // machine has.
        let base = PathBase::new(None, Some("/crabpot-test-work".to_owned()));
        let denies = mandatory::entries(&base, false).unwrap();

        assert_eq!(
            deny_rules(&denies),
            include_str!("fixtures/mandatory-denies.txt")
        );
    }

    #[test]
    fn allow_git_config_leaves_git_config_writable() {
        let base = PathBase::new(None, Some("/crabpot-test-work".to_owned()));

        let denied = deny_rules(&mandatory::entries(&base, false).unwrap());
        let allowed = deny_rules(&mandatory::entries(&base, true).unwrap());

        assert!(denied.contains(".git/config"));
        assert!(!allowed.contains(".git/config"));
        assert!(allowed.contains(".git/hooks"));
    }
}
