//! What the read denies take back from the write roots.
//!
//! `move_blocking` pins every `denyRead` path against the two operations of a
//! rename, and then re-allows both for every write root so `rm` and a new file
//! work inside one. A denied name that lies inside a write root is left movable
//! by that, and a rename is a way to read: `mv work/.env work/x` leaves `work/x`
//! matching no read rule at all. This section, the last one in the profile,
//! denies unlink for those names and for the directories below a write root that
//! hold them. Create is left alone, so a new file named like a denied one is
//! still denied by name.
//!
//! Upstream's `generateReadDenyUnlinkRules`, for the denies that name a path.
//! The denies that are patterns, and the credential denies upstream emits
//! wherever they lie with nothing subtracted, are not ported yet: issue #81.

use crabpot_core::PathError;
use crabpot_core::config::Config;
use crabpot_core::paths::{PathBase, is_at_or_under};
use crabpot_core::ResolvedPath;

use super::allow_read::carve;
use super::allow_write::roots;
use super::filter::Entry;
use super::move_blocking::{ancestors, literal};
use super::rule;

/// Whether `path` lies beneath `root`, and not at it.
fn strictly_under(path: &str, root: &str) -> bool {
    path != root && is_at_or_under(path, root)
}

/// The write roots that name a path. Only a name can hold another name, and a
/// pattern's match is not one.
fn named_roots(write_roots: &[Entry]) -> Vec<&str> {
    write_roots
        .iter()
        .filter(|entry| !entry.is_pattern())
        .map(Entry::path)
        .collect()
}

/// The filters of the rule: each denied name inside a write root, less the
/// allows and write roots nested inside it, and each directory holding it that
/// is itself inside one.
fn filters(denies: &[ResolvedPath], allows: &[ResolvedPath], write_roots: &[Entry]) -> Vec<String> {
    let named = named_roots(write_roots);
    let inside_write_root = |path: &str| named.iter().any(|root| strictly_under(path, root));
    let mut filters = Vec::new();
    for deny in denies {
        if deny.is_pattern() || !inside_write_root(deny.path()) {
            continue;
        }
        let carve_outs: Vec<String> = allows
            .iter()
            .filter(|allow| !allow.is_pattern() && strictly_under(allow.path(), deny.path()))
            .map(rule::allow_filter)
            .chain(
                write_roots
                    .iter()
                    .filter(|root| !root.is_pattern() && strictly_under(root.path(), deny.path()))
                    .map(Entry::filter),
            )
            .collect();
        filters.push(carve(rule::deny_filter(deny), &carve_outs));
        filters.extend(
            ancestors(deny.path())
                .iter()
                .filter(|dir| inside_write_root(dir))
                .map(|dir| literal(dir)),
        );
    }
    filters
}

pub(super) fn rules(config: &Config) -> Result<String, PathError> {
    rules_with(config, &PathBase::from_env())
}

fn rules_with(config: &Config, base: &PathBase) -> Result<String, PathError> {
    let write_roots = roots(config, base)?;
    if write_roots.is_empty() {
        return Ok(String::new());
    }
    let filters = filters(
        &config.filesystem.read_denies()?,
        &config.filesystem.read_allows()?,
        &write_roots,
    );
    Ok(format!(
        "\n; Reads the write roots re-opened\n{}",
        rule::render("deny", &["file-write-unlink"], &filters)
    ))
}

#[cfg(test)]
mod tests {
    use super::super::render;
    use super::*;

    /// A config that allows `/crabpot-nowhere/work` and reads as `deny_read`
    /// and `allow_read`.
    fn reading(deny_read: &str, allow_read: &str, allow_write: &str) -> Config {
        Config::from_json(&format!(
            r#"{{
                "network": {{"allowedDomains": [], "deniedDomains": []}},
                "filesystem": {{
                    "denyRead": {deny_read}, "allowRead": {allow_read},
                    "allowWrite": {allow_write}, "denyWrite": []
                }}
            }}"#
        ))
        .unwrap()
    }

    fn base() -> PathBase {
        PathBase::new(
            Some("/crabpot-test-home/me".to_owned()),
            Some("/crabpot-test-work".to_owned()),
        )
    }

    fn rendered(deny_read: &str, allow_read: &str, allow_write: &str) -> String {
        let config = reading(deny_read, allow_read, allow_write);
        let write_roots = roots(&config, &base()).unwrap();
        rule::render(
            "deny",
            &["file-write-unlink"],
            &filters(
                &config.filesystem.read_denies().unwrap(),
                &config.filesystem.read_allows().unwrap(),
                &write_roots,
            ),
        )
    }

    /// A denied name inside a write root, and the directory that holds it, are
    /// both pinned again. What upstream's `wrapCommandWithSandboxMacOS` at 0.0.81
    /// renders as its last rule for this config, with its log tag swapped for
    /// ours.
    #[test]
    fn a_denied_name_inside_a_write_root_is_pinned_again() {
        assert_eq!(
            rendered(r#"["/crabpot-nowhere/secrets/key"]"#, "[]", r#"["/crabpot-nowhere"]"#),
            r#"(deny file-write-unlink
  (subpath "/crabpot-nowhere/secrets/key")
  (literal "/crabpot-nowhere/secrets")
  (with message "crabpot"))
"#
        );
    }

    /// A denied name outside every write root needs nothing: the pin in
    /// `move_blocking` still holds for it.
    #[test]
    fn a_denied_name_outside_a_write_root_is_left_alone() {
        assert_eq!(
            rendered(
                r#"["/crabpot-nowhere/secrets/key"]"#,
                "[]",
                r#"["/crabpot-nowhere/work"]"#
            ),
            ""
        );
    }

    /// An allow nested inside the denied name is subtracted from the pin, so
    /// what it opens stays movable. Upstream's rule for this config, with its
    /// log tag swapped for ours.
    #[test]
    fn an_allow_inside_the_denied_name_is_subtracted() {
        assert_eq!(
            rendered(
                r#"["/crabpot-nowhere/work/secrets"]"#,
                r#"["/crabpot-nowhere/work/secrets/open"]"#,
                r#"["/crabpot-nowhere/work"]"#
            ),
            r#"(deny file-write-unlink
  (require-all (subpath "/crabpot-nowhere/work/secrets") (require-not (subpath "/crabpot-nowhere/work/secrets/open")))
  (with message "crabpot"))
"#
        );
    }

    /// Nothing read-denied, nothing to take back.
    #[test]
    fn a_policy_with_no_read_denies_takes_back_nothing() {
        assert_eq!(rendered("[]", "[]", r#"["/crabpot-nowhere/work"]"#), "");
    }

    /// The section is the profile's last, which is where a rule that answers a
    /// re-allow has to be.
    #[test]
    fn the_rule_comes_last_in_the_profile() {
        let profile = render(
            &reading(r#"["/crabpot-nowhere/secrets/key"]"#, "[]", r#"["/crabpot-nowhere"]"#),
            None,
            None,
        )
        .unwrap();
        let pinned = profile
            .find("(deny file-write-unlink file-write-create\n  (subpath \"/crabpot-nowhere/secrets/key\")")
            .unwrap();
        let taken_back = profile
            .find("(deny file-write-unlink\n  (subpath \"/crabpot-nowhere/secrets/key\")")
            .unwrap();
        assert!(pinned < taken_back, "{profile}");
        assert!(
            taken_back > profile.find("; Writes").unwrap(),
            "the take back follows the write roots it answers: {profile}"
        );
    }
}
