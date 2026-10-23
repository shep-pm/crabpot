//! What `filesystem.denyWrite` takes back from the paths `allowWrite` opened.
//!
//! Upstream's deny half of `generateWriteRules`, less the `file-write-unlink`
//! rules that stop a denied path or its ancestors being moved. Those are slice
//! 14 of #24, which reads `Filesystem::write_denies`. Until it lands, renaming
//! a directory above a denied path steps around the deny.
//!
//! Seatbelt takes the last rule that matches, so a deny follows the allow of
//! the write section.

use crabpot_core::PathError;
use crabpot_core::config::Config;

use super::rule;

pub(super) fn rules(config: &Config) -> Result<String, PathError> {
    let denies = config.filesystem.write_denies()?;
    let filters: Vec<String> = denies.iter().map(rule::deny_filter).collect();
    Ok(rule::render("deny", &["file-write*"], &filters))
}

#[cfg(test)]
mod tests {
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
        let profile = render(&denying(r#"["/crabpot-nowhere/work/.env"]"#), None).unwrap();

        let allow = profile.find(r#"  (subpath "/crabpot-nowhere/work")"#).unwrap();
        let deny = profile
            .find("(deny file-write*\n  (subpath \"/crabpot-nowhere/work/.env\")")
            .unwrap();
        assert!(allow < deny, "{profile}");
    }

    #[test]
    fn a_folder_a_glob_and_a_literal_render_one_rule() {
        let config = denying(
            r#"["/crabpot-nowhere/work/secrets", "/crabpot-nowhere/work/**/*.key",
                {"path": "/crabpot-nowhere/work/a[b", "literal": true}]"#,
        );

        assert_eq!(
            rules(&config).unwrap(),
            r#"(deny file-write*
  (subpath "/crabpot-nowhere/work/secrets")
  (regex "^/crabpot-nowhere/work/(.*/)?[^/]*\\.key(/.*)?$")
  (subpath "/crabpot-nowhere/work/a[b")
  (with message "crabpot"))
"#
        );
    }

    #[test]
    fn nothing_denied_renders_nothing() {
        assert_eq!(rules(&denying("[]")).unwrap(), "");
    }
}
