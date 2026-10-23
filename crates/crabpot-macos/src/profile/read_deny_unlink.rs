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
//! Upstream's `generateReadDenyUnlinkRules`. A glob deny is taken back when its
//! region meets a write root, and a name deny when it lies strictly below one.
//! A credential deny is taken back wherever it lies, with nothing subtracted.

use core::iter;

use crabpot_core::config::Config;
use crabpot_core::paths::{PathBase, is_at_or_under};
use crabpot_core::{PathError, ResolvedPath};

use super::allow_read::carve;
use super::allow_write::roots;
use super::filter::Entry;
use super::move_blocking::{ancestors, literal};
use super::rule;

/// Whether `path` lies beneath `root`, and not at it.
fn strictly_under(path: &str, root: &str) -> bool {
    path != root && is_at_or_under(path, root)
}

/// The write roots, told by what a deny has to ask of them.
struct WriteRoots<'a> {
    names: Vec<&'a str>,
    patterns: Vec<&'a ResolvedPath>,
}

impl<'a> WriteRoots<'a> {
    fn new(roots: &'a [ResolvedPath]) -> Self {
        let (patterns, names): (Vec<_>, Vec<_>) = roots.iter().partition(|root| root.is_pattern());
        Self {
            names: names.into_iter().map(ResolvedPath::path).collect(),
            patterns,
        }
    }

    /// Whether `dir` is a write root that names a path.
    fn names(&self, dir: &str) -> bool {
        self.names.contains(&dir)
    }

    /// Whether `path` lies beneath a write root, or is a directory one pattern
    /// matches.
    fn strictly_below(&self, path: &str) -> bool {
        self.names.iter().any(|root| strictly_under(path, root))
            || self.patterns.iter().any(|root| root.allow_matches(path))
    }

    /// Whether a pattern bounded by `base_dir` can match inside a write root.
    /// Any pattern root may, since where it reaches is not worked out.
    fn meets(&self, base_dir: &str) -> bool {
        !self.patterns.is_empty()
            || self.names.iter().any(|root| {
                base_dir == *root
                    || strictly_under(base_dir, root)
                    || strictly_under(root, base_dir)
            })
    }
}

/// The filters of the `exceptions` a deny gives way to.
fn carve_outs(
    exceptions: &[&ResolvedPath],
    covered: impl Fn(&ResolvedPath) -> bool,
) -> Vec<String> {
    exceptions
        .iter()
        .copied()
        .filter(|exception| covered(exception))
        .map(rule::allow_filter)
        .collect()
}

/// The filters of the rule: each deny a write root re-opened, less the allows
/// and write roots it covers, and each directory above it that is itself below
/// one. A credential deny is kept wherever it lies, with nothing subtracted and
/// a write root among its directories pinned with the rest.
fn filters(
    denies: &[ResolvedPath],
    credential_denies: &[ResolvedPath],
    allows: &[ResolvedPath],
    write_roots: &[ResolvedPath],
) -> Vec<String> {
    let roots = WriteRoots::new(write_roots);
    let marked = denies
        .iter()
        .map(|deny| (deny, false))
        .chain(credential_denies.iter().map(|deny| (deny, true)));
    let mut filters = Vec::new();
    for (deny, credential) in marked {
        let exceptions: Vec<&ResolvedPath> = if credential {
            Vec::new()
        } else {
            allows.iter().chain(write_roots).collect()
        };
        let directories: Vec<String> = if deny.is_pattern() {
            let base_dir = deny.base_dir();
            if !roots.meets(&base_dir) {
                continue;
            }
            let carve_outs = carve_outs(&exceptions, |exception| {
                deny.deny_covers(&exception.sample_path())
            });
            filters.push(carve(rule::deny_filter(deny), &carve_outs));
            if base_dir == "/" {
                Vec::new()
            } else {
                iter::once(base_dir.clone()).chain(ancestors(&base_dir)).collect()
            }
        } else {
            if !credential && !roots.strictly_below(deny.path()) {
                continue;
            }
            let carve_outs = carve_outs(&exceptions, |exception| {
                exception.is_strictly_under(deny.path())
            });
            filters.push(carve(rule::deny_filter(deny), &carve_outs));
            ancestors(deny.path())
        };
        filters.extend(
            directories
                .iter()
                .filter(|dir| roots.strictly_below(dir) || (credential && roots.names(dir)))
                .map(|dir| literal(dir)),
        );
    }
    filters
}

pub(super) fn rules(config: &Config) -> Result<String, PathError> {
    rules_with(config, &PathBase::from_env())
}

fn rules_with(config: &Config, base: &PathBase) -> Result<String, PathError> {
    let write_roots: Vec<ResolvedPath> = roots(config, base)?.iter().map(Entry::resolved).collect();
    if write_roots.is_empty() {
        return Ok(String::new());
    }
    // `credentials` is refused, so no deny is a credential deny.
    let filters = filters(
        &config.filesystem.read_denies()?,
        &[],
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
        let write_roots: Vec<ResolvedPath> = roots(&config, &base())
            .unwrap()
            .iter()
            .map(Entry::resolved)
            .collect();
        rule::render(
            "deny",
            &["file-write-unlink"],
            &filters(
                &config.filesystem.read_denies().unwrap(),
                &[],
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

    /// A glob deny inside a write root is pinned with a name deny there, and the
    /// directory a name deny sits in. The glob's own directory is the write root
    /// here, which the pin above already holds. What upstream's
    /// `wrapCommandWithSandboxMacOS` at 0.0.81 renders as its last rule for this
    /// config, with its log tag swapped for ours.
    #[test]
    fn a_glob_and_a_name_inside_a_write_root_are_pinned_again() {
        assert_eq!(
            rendered(
                r#"["/crabpot-nowhere/work/**/.env", "/crabpot-nowhere/work/secrets/key"]"#,
                "[]",
                r#"["/crabpot-nowhere/work"]"#
            ),
            r#"(deny file-write-unlink
  (regex "^/crabpot-nowhere/work/(.*/)?\\.env(/.*)?$")
  (subpath "/crabpot-nowhere/work/secrets/key")
  (literal "/crabpot-nowhere/work/secrets")
  (with message "crabpot"))
"#
        );
    }

    /// A glob that starts below the write root pins that directory too.
    #[test]
    fn a_glob_below_a_write_root_pins_the_directory_it_starts_from() {
        assert_eq!(
            rendered(
                r#"["/crabpot-nowhere/work/sub/**/.env"]"#,
                "[]",
                r#"["/crabpot-nowhere/work"]"#
            ),
            r#"(deny file-write-unlink
  (regex "^/crabpot-nowhere/work/sub/(.*/)?\\.env(/.*)?$")
  (literal "/crabpot-nowhere/work/sub")
  (with message "crabpot"))
"#
        );
    }

    /// A glob deny that covers an allow gives way to it. A write root the glob
    /// does not cover is not subtracted. Upstream's rule for this config, with
    /// its log tag swapped for ours.
    #[test]
    fn an_allow_the_glob_covers_is_subtracted() {
        assert_eq!(
            rendered(
                r#"["/crabpot-nowhere/work/**/*"]"#,
                r#"["/crabpot-nowhere/work/open"]"#,
                r#"["/crabpot-nowhere/work"]"#
            ),
            r#"(deny file-write-unlink
  (require-all (regex "^/crabpot-nowhere/work/(.*/)?[^/]*(/.*)?$") (require-not (subpath "/crabpot-nowhere/work/open")))
  (with message "crabpot"))
"#
        );
    }

    /// A write root nested inside a denied name is subtracted with the allows.
    /// Upstream's rule for this config, with its log tag swapped for ours.
    #[test]
    fn a_write_root_inside_the_denied_name_is_subtracted() {
        assert_eq!(
            rendered(
                r#"["/crabpot-nowhere/work/secrets"]"#,
                r#"["/crabpot-nowhere/work/secrets/open"]"#,
                r#"["/crabpot-nowhere/work", "/crabpot-nowhere/work/secrets/out"]"#
            ),
            r#"(deny file-write-unlink
  (require-all (subpath "/crabpot-nowhere/work/secrets") (require-not (subpath "/crabpot-nowhere/work/secrets/open")) (require-not (subpath "/crabpot-nowhere/work/secrets/out")))
  (with message "crabpot"))
"#
        );
    }

    /// A glob that starts from a directory above a write root meets it.
    /// Upstream's rule for this config, with its log tag swapped for ours.
    #[test]
    fn a_glob_that_starts_above_a_write_root_is_pinned_again() {
        assert_eq!(
            rendered(
                r#"["/crabpot-nowhere/**/.env"]"#,
                "[]",
                r#"["/crabpot-nowhere/work"]"#
            ),
            r#"(deny file-write-unlink
  (regex "^/crabpot-nowhere/(.*/)?\\.env(/.*)?$")
  (with message "crabpot"))
"#
        );
    }

    /// A glob that starts from a directory no write root meets needs nothing.
    #[test]
    fn a_glob_outside_every_write_root_is_left_alone() {
        assert_eq!(
            rendered(
                r#"["/crabpot-nowhere/other/**/.env"]"#,
                "[]",
                r#"["/crabpot-nowhere/work"]"#
            ),
            ""
        );
    }

    /// A pattern write root meets any glob. Upstream's rule for this config,
    /// with its log tag swapped for ours.
    #[test]
    fn a_pattern_write_root_meets_every_glob() {
        assert_eq!(
            rendered(
                r#"["/crabpot-nowhere/other/**/.env"]"#,
                "[]",
                r#"["/crabpot-nowhere/w*"]"#
            ),
            r#"(deny file-write-unlink
  (regex "^/crabpot-nowhere/other/(.*/)?\\.env(/.*)?$")
  (with message "crabpot"))
"#
        );
    }

    /// The credential denies as the config's own denies, to see what is done
    /// with them. Upstream's rule for the first two, with its log tag swapped
    /// for ours: nothing is subtracted from a credential deny, and a write
    /// root among its directories is pinned with the rest.
    #[test]
    fn a_credential_deny_is_kept_with_nothing_subtracted() {
        let write_roots = [
            ResolvedPath::named("/crabpot-nowhere/work"),
            ResolvedPath::named("/crabpot-nowhere/work/.aws/tmp"),
        ];
        let credential = [ResolvedPath::named("/crabpot-nowhere/work/.aws/credentials")];
        let allows = [ResolvedPath::named("/crabpot-nowhere/work/.aws/credentials/own")];

        assert_eq!(
            rule::render(
                "deny",
                &["file-write-unlink"],
                &filters(&[], &credential, &allows, &write_roots)
            ),
            r#"(deny file-write-unlink
  (subpath "/crabpot-nowhere/work/.aws/credentials")
  (literal "/crabpot-nowhere/work/.aws")
  (literal "/crabpot-nowhere/work")
  (with message "crabpot"))
"#
        );
    }

    /// A credential deny outside every write root is kept all the same, and
    /// pins no directory, none of them being below a write root.
    #[test]
    fn a_credential_deny_outside_every_write_root_is_kept() {
        let write_roots = [ResolvedPath::named("/crabpot-nowhere/work")];
        let credential = [ResolvedPath::named("/crabpot-nowhere/home/.aws/credentials")];

        assert_eq!(
            rule::render(
                "deny",
                &["file-write-unlink"],
                &filters(&[], &credential, &[], &write_roots)
            ),
            r#"(deny file-write-unlink
  (subpath "/crabpot-nowhere/home/.aws/credentials")
  (with message "crabpot"))
"#
        );
    }

    /// A credential glob is judged like any glob: one that meets no write root
    /// needs nothing. Only a credential name is kept wherever it lies. Upstream
    /// emits no trailing rule for this config.
    #[test]
    fn a_credential_glob_outside_every_write_root_is_left_alone() {
        let write_roots = [ResolvedPath::named("/crabpot-nowhere/work")];
        let credential = [ResolvedPath::pattern("/crabpot-nowhere/home/.aws/*", None)];

        assert_eq!(filters(&[], &credential, &[], &write_roots), Vec::<String>::new());
    }

    /// A new file named like a denied one is still refused by name, which only
    /// create could undo: the rule never names it.
    #[test]
    fn create_is_never_denied() {
        let profile = render(
            &reading(
                r#"["/crabpot-nowhere/work/**/.env"]"#,
                "[]",
                r#"["/crabpot-nowhere/work"]"#,
            ),
            None,
            None,
        )
        .unwrap();
        let taken_back = profile.split("; Reads the write roots re-opened").nth(1).unwrap();

        assert!(taken_back.contains("(deny file-write-unlink\n"), "{taken_back}");
        assert!(!taken_back.contains("file-write-create"), "{taken_back}");
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
