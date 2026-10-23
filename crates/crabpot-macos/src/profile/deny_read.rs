//! What `filesystem.denyRead` hides from a sandboxed command.
//!
//! Seatbelt takes the last rule that matches, so a deny follows the
//! `(allow file-read*)` of the read section. The `allow_read` section follows
//! it, with the denies that must land after the allows.

use crabpot_core::PathError;
use crabpot_core::config::Config;

use super::rule;

pub(super) fn rules(config: &Config) -> Result<String, PathError> {
    let filters: Vec<String> = config
        .filesystem
        .read_denies()?
        .iter()
        .map(rule::deny_filter)
        .collect();
    Ok(rule::render("deny", &["file-read*"], &filters))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A config whose only setting is `denyRead`, which is `entries`.
    fn denying(entries: &str) -> Config {
        Config::from_json(&format!(
            r#"{{
                "network": {{"allowedDomains": [], "deniedDomains": []}},
                "filesystem": {{"denyRead": {entries}, "allowWrite": [], "denyWrite": []}}
            }}"#
        ))
        .unwrap()
    }

    #[test]
    fn a_folder_a_glob_and_a_literal_render_upstreams_rules() {
        // What upstream's `wrapCommandWithSandboxMacOS` at aceba124 renders for
        // this `denyRead` as its first `(deny file-read*` rule, with its log
        // tag swapped for ours. `/crabpot-nowhere` is a path no machine has, so
        // nothing is resolved.
        let config = denying(
            r#"["/crabpot-nowhere/secrets", "/crabpot-nowhere/**/*.key",
                {"path": "/crabpot-nowhere/a[b", "literal": true}]"#,
        );

        assert_eq!(
            rules(&config).unwrap(),
            r#"(deny file-read*
  (subpath "/crabpot-nowhere/secrets")
  (regex "^/crabpot-nowhere/(.*/)?[^/]*\\.key(/.*)?$")
  (subpath "/crabpot-nowhere/a[b")
  (with message "crabpot"))
"#
        );
    }

    #[test]
    fn a_folder_reached_through_a_link_is_denied_under_both_names() {
        let root = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("crabpot-deny-read-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("real/secrets")).unwrap();
        std::os::unix::fs::symlink("real", root.join("link")).unwrap();
        let root = root.to_str().unwrap();

        let rules = rules(&denying(&format!(r#"["{root}/link/secrets"]"#))).unwrap();

        std::fs::remove_dir_all(root).unwrap();
        assert_eq!(
            rules,
            format!(
                r#"(deny file-read*
  (subpath "{root}/link/secrets")
  (subpath "{root}/real/secrets")
  (with message "crabpot"))
"#
            )
        );
    }

    #[test]
    fn nothing_denied_renders_nothing() {
        assert_eq!(rules(&denying("[]")).unwrap(), "");
    }
}
