//! What `filesystem.denyRead` hides from a sandboxed command.
//!
//! Seatbelt takes the last rule that matches, so a deny follows the
//! `(allow file-read*)` of the read section.

use crabpot_core::config::Config;
use crabpot_core::{PathError, ResolvedPath};

use super::rule;

/// The filter that matches what a deny of `path` hides: a pattern's regular
/// expression, or a name and everything beneath it.
fn filter(path: &ResolvedPath) -> String {
    match path.deny_regex() {
        Some(regex) => format!("(regex {})", rule::string(&regex)),
        None => format!("(subpath {})", rule::string(path.path())),
    }
}

pub(super) fn rules(config: &Config) -> Result<String, PathError> {
    let denies = config.filesystem.read_denies()?;
    if denies.is_empty() {
        return Ok(String::new());
    }
    let filters: Vec<String> = denies.iter().map(filter).collect();
    let mut rules = rule::render("deny", &["file-read*"], &filters);

    // Each pattern again, after where the read allows go, since the last rule
    // that matches wins.
    let patterns: Vec<String> = denies
        .iter()
        .filter(|path| path.deny_regex().is_some())
        .map(filter)
        .collect();
    rules.push_str(&rule::render("deny", &["file-read*"], &patterns));

    // A deny of `/` itself, or a pattern that matches it, would stop dyld
    // before exec. The root alone is readable: it lists the names in it and
    // opens nothing beneath.
    if denies
        .iter()
        .any(|path| path.path() == "/" || path.denies_root())
    {
        rules.push_str(&format!(
            "(allow file-read* (literal {}))\n",
            rule::string("/")
        ));
    }

    // realpath() needs to stat each directory on the way to a path inside a
    // denied one. Metadata of a directory is not its listing nor its files.
    rules.push_str("(allow file-read-metadata\n  (vnode-type DIRECTORY))\n");
    Ok(rules)
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
        // this `denyRead` between its `; File read` and `; File write`, less
        // the `file-write-unlink` rule that blocks moves and with its log tag
        // swapped for ours. `/crabpot-nowhere` is a path no machine has, so
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
(deny file-read*
  (regex "^/crabpot-nowhere/(.*/)?[^/]*\\.key(/.*)?$")
  (with message "crabpot"))
(allow file-read-metadata
  (vnode-type DIRECTORY))
"#
        );
    }

    #[test]
    fn a_pattern_that_matches_the_root_leaves_the_root_readable() {
        let rules = rules(&denying(r#"["/*"]"#)).unwrap();

        assert_eq!(
            rules,
            r#"(deny file-read*
  (regex "^/[^/]*(/.*)?$")
  (with message "crabpot"))
(deny file-read*
  (regex "^/[^/]*(/.*)?$")
  (with message "crabpot"))
(allow file-read* (literal "/"))
(allow file-read-metadata
  (vnode-type DIRECTORY))
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
(allow file-read-metadata
  (vnode-type DIRECTORY))
"#
            )
        );
    }

    #[test]
    fn nothing_denied_renders_nothing() {
        assert_eq!(rules(&denying("[]")).unwrap(), "");
    }
}
