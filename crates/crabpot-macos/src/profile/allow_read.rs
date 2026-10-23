//! What `filesystem.allowRead` opens inside what `denyRead` hides, and the
//! denies that stay after it.
//!
//! Seatbelt takes the last rule that matches, so an allow follows the deny of
//! the `deny_read` section, and what the allow would open again follows it.

use crabpot_core::config::Config;
use crabpot_core::{PathError, ResolvedPath};

use super::rule;

/// `filter` narrowed to match nothing the `carve_outs` match.
fn carve(filter: String, carve_outs: &[String]) -> String {
    let mut unique: Vec<&String> = Vec::new();
    for carve_out in carve_outs {
        if !unique.contains(&carve_out) {
            unique.push(carve_out);
        }
    }
    if unique.is_empty() {
        return filter;
    }
    let nots: Vec<String> = unique
        .iter()
        .map(|carve_out| format!("(require-not {carve_out})"))
        .collect();
    format!("(require-all {filter} {})", nots.join(" "))
}

/// The denies that must land after the allows, which would otherwise open them
/// again, and whether one of them matches `/`:
///
/// - A name under a name that is allowed, as it was.
/// - Each pattern, less the allows it covers. A pattern shaped like a leaf
///   (`**/.env`) covers no folder an allow names and comes back whole, so it
///   beats the allow it lands inside. One shaped like a region (`~/**/*`)
///   covers its carve-outs and gives way to them.
///
/// None of them opens a path that is closed. A carve-out the pattern did not
/// need only gives back what the allow did, and one it missed leaves the deny
/// wider.
fn late_denies(denies: &[ResolvedPath], allows: &[ResolvedPath]) -> (Vec<String>, bool) {
    let mut filters = Vec::new();
    let mut covers_root = false;
    let allowed_names: Vec<&str> = allows
        .iter()
        .filter(|allow| !allow.is_pattern())
        .map(ResolvedPath::path)
        .collect();
    for deny in denies {
        if !deny.is_pattern() {
            if allowed_names.iter().any(|name| deny.is_strictly_under(name)) {
                filters.push(rule::deny_filter(deny));
            }
            continue;
        }
        covers_root |= deny.denies_root();
        let carve_outs: Vec<String> = allows
            .iter()
            .filter(|allow| deny.deny_covers(&allow.sample_path()))
            .map(rule::allow_filter)
            .collect();
        filters.push(carve(rule::deny_filter(deny), &carve_outs));
    }
    (filters, covers_root)
}

pub(super) fn rules(config: &Config) -> Result<String, PathError> {
    let denies = config.filesystem.read_denies()?;
    let allows = config.filesystem.read_allows()?;
    let filters: Vec<String> = allows.iter().map(rule::allow_filter).collect();
    let mut rules = rule::render("allow", &["file-read*"], &filters);
    if denies.is_empty() {
        return Ok(rules);
    }

    let (late, covers_root) = late_denies(&denies, &allows);
    rules.push_str(&rule::render("deny", &["file-read*"], &late));

    // A deny of `/` itself, or a pattern that matches it, would stop dyld
    // before exec. The root alone is readable: it lists the names in it and
    // opens nothing beneath.
    if covers_root || denies.iter().any(|path| path.path() == "/") {
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
    use super::super::deny_read;
    use super::*;

    /// A config whose read settings are `deny_read` and `allow_read`.
    fn reading(deny_read: &str, allow_read: &str) -> Config {
        Config::from_json(&format!(
            r#"{{
                "network": {{"allowedDomains": [], "deniedDomains": []}},
                "filesystem": {{
                    "denyRead": {deny_read}, "allowRead": {allow_read},
                    "allowWrite": [], "denyWrite": []
                }}
            }}"#
        ))
        .unwrap()
    }

    /// The read rules in the order they render.
    fn read_rules(config: &Config) -> String {
        deny_read::rules(config).unwrap() + &rules(config).unwrap()
    }

    #[test]
    fn an_allow_inside_a_deny_renders_upstreams_order() {
        // What upstream's `wrapCommandWithSandboxMacOS` at aceba124 renders for
        // this config between its `; File read` and `; File write`, less the
        // `file-write-unlink` rule that blocks moves and with its log tag
        // swapped for ours. `/crabpot-nowhere` is a path no machine has, so
        // nothing is resolved.
        let config = reading(
            r#"["/crabpot-nowhere/home", "/crabpot-nowhere/home/proj/secrets"]"#,
            r#"["/crabpot-nowhere/home/proj"]"#,
        );

        assert_eq!(
            read_rules(&config),
            r#"(deny file-read*
  (subpath "/crabpot-nowhere/home")
  (subpath "/crabpot-nowhere/home/proj/secrets")
  (with message "crabpot"))
(allow file-read*
  (subpath "/crabpot-nowhere/home/proj")
  (with message "crabpot"))
(deny file-read*
  (subpath "/crabpot-nowhere/home/proj/secrets")
  (with message "crabpot"))
(allow file-read-metadata
  (vnode-type DIRECTORY))
"#
        );
    }

    #[test]
    fn a_deny_glob_that_covers_the_allow_is_carved() {
        // A region glob covers the folder the allow names and gives way to it.
        // A leaf glob covers none and lands whole after the allow.
        let config = reading(
            r#"["/crabpot-nowhere/home/**/*", "/crabpot-nowhere/**/*.key"]"#,
            r#"["/crabpot-nowhere/home/proj"]"#,
        );

        assert_eq!(
            read_rules(&config),
            r#"(deny file-read*
  (regex "^/crabpot-nowhere/home/(.*/)?[^/]*(/.*)?$")
  (regex "^/crabpot-nowhere/(.*/)?[^/]*\\.key(/.*)?$")
  (with message "crabpot"))
(allow file-read*
  (subpath "/crabpot-nowhere/home/proj")
  (with message "crabpot"))
(deny file-read*
  (require-all (regex "^/crabpot-nowhere/home/(.*/)?[^/]*(/.*)?$") (require-not (subpath "/crabpot-nowhere/home/proj")))
  (regex "^/crabpot-nowhere/(.*/)?[^/]*\\.key(/.*)?$")
  (with message "crabpot"))
(allow file-read-metadata
  (vnode-type DIRECTORY))
"#
        );
    }

    #[test]
    fn an_allow_pattern_matches_the_paths_it_spells_and_not_what_is_beneath() {
        let config = reading(
            r#"["/crabpot-nowhere/secrets"]"#,
            r#"["/crabpot-nowhere/secrets/[d]", "/crabpot-nowhere/secrets/*.txt",
                {"path": "/crabpot-nowhere/secrets/a[b", "literal": true}]"#,
        );

        assert_eq!(
            read_rules(&config),
            r#"(deny file-read*
  (subpath "/crabpot-nowhere/secrets")
  (with message "crabpot"))
(allow file-read*
  (regex "^/crabpot-nowhere/secrets/[d]$")
  (regex "^/crabpot-nowhere/secrets/[^/]*\\.txt$")
  (subpath "/crabpot-nowhere/secrets/a[b")
  (with message "crabpot"))
(allow file-read-metadata
  (vnode-type DIRECTORY))
"#
        );
    }

    #[test]
    fn a_pattern_that_matches_the_root_leaves_the_root_readable() {
        let rules = read_rules(&reading(r#"["/*"]"#, "[]"));

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
    fn an_allow_reached_through_a_link_is_opened_under_both_names_and_a_link_under_its_own() {
        let root = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("crabpot-allow-read-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("real/secrets")).unwrap();
        std::fs::write(root.join("real/secrets/key"), "").unwrap();
        std::os::unix::fs::symlink("real", root.join("link")).unwrap();
        std::os::unix::fs::symlink("secrets/key", root.join("real/shortcut")).unwrap();
        let root = root.to_str().unwrap();

        let rules = rules(&reading(
            r#"["/crabpot-nowhere"]"#,
            &format!(r#"["{root}/link/secrets/key", "{root}/real/shortcut"]"#),
        ))
        .unwrap();

        std::fs::remove_dir_all(root).unwrap();
        assert_eq!(
            rules,
            format!(
                r#"(allow file-read*
  (subpath "{root}/link/secrets/key")
  (subpath "{root}/real/secrets/key")
  (subpath "{root}/real/shortcut")
  (with message "crabpot"))
(allow file-read-metadata
  (vnode-type DIRECTORY))
"#
            )
        );
    }

    #[test]
    fn nothing_denied_opens_what_is_allowed_and_nothing_else() {
        assert_eq!(rules(&reading("[]", "[]")).unwrap(), "");
        assert_eq!(
            rules(&reading("[]", r#"["/crabpot-nowhere/x"]"#)).unwrap(),
            r#"(allow file-read*
  (subpath "/crabpot-nowhere/x")
  (with message "crabpot"))
"#
        );
    }
}
