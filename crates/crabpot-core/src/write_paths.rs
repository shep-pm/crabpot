//! The roots every sandbox may write, before the config adds its own.
//!
//! Upstream's `getDefaultWritePaths` and `defaultWritePathsUnder`: the
//! sandbox's own devices and temporary folder, and two folders under the home
//! directory that its tools log to. Those two are left out when a `denyRead`
//! entry covers them, so an explicit read deny wins over a write nobody asked
//! for. Upstream also judges them against the credential denies, and
//! `credentials` is refused here, so there are none to judge by.
//!
//! Every platform starts from this list. The macOS profile allows it as
//! subpaths, and Linux binds each one that is there back over its read-only
//! root.

use crate::config::{Config, PathEntry};
use crate::glob::deny_glob_matches;
use crate::path::{
    PathBase, PathError, contains_glob_chars, is_at_or_under, normalize_path_for_sandbox,
    remove_trailing_glob_suffix,
};
use crate::path_entries::read_rules_of;

/// What the sandbox needs writable: the child's stdio and the `TMPDIR` it is
/// handed. Kept whatever is read-denied.
const OWN_ROOTS: [&str; 8] = [
    "/dev/stdout",
    "/dev/stderr",
    "/dev/null",
    "/dev/tty",
    "/dev/dtracehelper",
    "/dev/autofs_nowait",
    "/tmp/claude",
    "/private/tmp/claude",
];

/// Folders under the home directory made writable as a convenience.
const HOME_DIRS: [&str; 2] = [".npm/_logs", ".claude/debug"];

/// The default write roots under `config`'s read rules.
///
/// # Errors
///
/// [`PathError`] when the home directory is unknown, or a read entry needs a
/// working directory and there is none.
pub fn default_write_paths(base: &PathBase, config: &Config) -> Result<Vec<String>, PathError> {
    let home = base.home()?;
    let filesystem = &config.filesystem;
    let rules = read_rules_of(
        base,
        &filesystem.deny_read,
        filesystem.allow_read.as_deref(),
        &[],
    )?;
    let kept: Vec<&str> = if rules.deny_read.is_empty() {
        HOME_DIRS.to_vec()
    } else {
        homes_not_read_denied(
            base,
            home,
            &rules.deny_read,
            rules.allow_read.as_deref().unwrap_or_default(),
        )?
    };
    let mut roots: Vec<String> = OWN_ROOTS.iter().map(|root| (*root).to_owned()).collect();
    roots.extend(kept.into_iter().map(|dir| join(home, dir)));
    Ok(roots)
}

fn join(home: &str, dir: &str) -> String {
    if home.is_empty() {
        dir.to_owned()
    } else {
        format!("{}/{dir}", home.trim_end_matches('/'))
    }
}

/// A read rule, as far as it says what it covers.
enum Covers {
    /// The path and everything beneath it.
    Under(String),
    /// What a deny glob matches, and everything beneath each match.
    Matching(String),
}

impl Covers {
    /// A pattern is decided on what the caller wrote, before it is resolved:
    /// a resolved home directory may hold glob characters in its own name.
    fn of(base: &PathBase, entry: &PathEntry) -> Result<Self, PathError> {
        match entry {
            PathEntry::Literal(path) => {
                normalize_path_for_sandbox(base, path, true).map(Self::Under)
            }
            PathEntry::Spelled(spelling) => {
                let stripped = remove_trailing_glob_suffix(spelling);
                if contains_glob_chars(&stripped) {
                    normalize_path_for_sandbox(base, &stripped, false).map(Self::Matching)
                } else {
                    normalize_path_for_sandbox(base, &stripped, true).map(Self::Under)
                }
            }
        }
    }

    fn covers(&self, path: &str) -> bool {
        match self {
            Self::Under(rule) => is_at_or_under(path, rule),
            Self::Matching(pattern) => deny_glob_matches(pattern, path),
        }
    }
}

/// The [`HOME_DIRS`] no `deny_read` entry covers, or that an `allow_read` entry
/// beneath the covering deny reopens.
///
/// A folder is judged under both spellings of the home directory, since a
/// rule is compared as `normalize_path_for_sandbox` spells it and the folder
/// may not exist yet to be resolved.
fn homes_not_read_denied(
    base: &PathBase,
    home: &str,
    deny_read: &[PathEntry],
    allow_read: &[PathEntry],
) -> Result<Vec<&'static str>, PathError> {
    let mut homes = vec![home.to_owned()];
    let resolved = normalize_path_for_sandbox(base, home, true)?;
    if resolved != home {
        homes.push(resolved);
    }
    let denies = deny_read
        .iter()
        .map(|entry| Covers::of(base, entry))
        .collect::<Result<Vec<_>, _>>()?;
    let mut reopened = Vec::new();
    for entry in allow_read {
        let path = match entry {
            PathEntry::Literal(path) => path.clone(),
            PathEntry::Spelled(spelling) => {
                let stripped = remove_trailing_glob_suffix(spelling);
                if contains_glob_chars(&stripped) {
                    continue;
                }
                stripped
            }
        };
        reopened.push(normalize_path_for_sandbox(base, &path, true)?);
    }
    Ok(HOME_DIRS
        .into_iter()
        .filter(|dir| {
            let spellings: Vec<String> = homes.iter().map(|home| join(home, dir)).collect();
            !denies.iter().any(|deny| {
                spellings.iter().any(|s| deny.covers(s))
                    && !reopened.iter().any(|allow| {
                        deny.covers(allow) && spellings.iter().any(|s| is_at_or_under(s, allow))
                    })
            })
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use crate::config::{Config, PathEntry};
    use crate::path::PathBase;

    use super::*;

    /// A home directory that is not there, so no link rewrites it.
    const HOME: &str = "/crabpot-test-home/me";

    fn base() -> PathBase {
        PathBase::new(Some(HOME.to_owned()), Some("/crabpot-test-work".to_owned()))
    }

    fn denying(entries: &[&str]) -> Config {
        let mut config = Config::default();
        config.filesystem.deny_read = entries
            .iter()
            .map(|entry| PathEntry::Spelled((*entry).to_owned()))
            .collect();
        config
    }

    #[test]
    fn the_default_roots_are_upstreams_eight_plus_two_home_dirs() {
        assert_eq!(
            default_write_paths(&base(), &Config::default()).unwrap(),
            [
                "/dev/stdout",
                "/dev/stderr",
                "/dev/null",
                "/dev/tty",
                "/dev/dtracehelper",
                "/dev/autofs_nowait",
                "/tmp/claude",
                "/private/tmp/claude",
                "/crabpot-test-home/me/.npm/_logs",
                "/crabpot-test-home/me/.claude/debug",
            ]
        );
    }

    #[test]
    fn a_home_dir_under_a_read_deny_is_dropped() {
        let roots =
            default_write_paths(&base(), &denying(&["/crabpot-test-home/me/.claude"])).unwrap();

        assert_eq!(roots.len(), 9);
        assert!(!roots.contains(&"/crabpot-test-home/me/.claude/debug".to_owned()));
        assert!(roots.contains(&"/crabpot-test-home/me/.npm/_logs".to_owned()));
    }

    fn home_dirs(config: &Config) -> Vec<String> {
        default_write_paths(&base(), config).unwrap()[8..].to_vec()
    }

    #[test]
    fn a_deny_above_the_home_dir_drops_both() {
        assert!(home_dirs(&denying(&["/crabpot-test-home"])).is_empty());
        assert!(home_dirs(&denying(&["~"])).is_empty());
    }

    #[test]
    fn a_deny_elsewhere_drops_nothing() {
        assert_eq!(
            home_dirs(&denying(&["/crabpot-test-home/me/.claudex", "/secret"])).len(),
            2
        );
    }

    #[test]
    fn a_deny_glob_drops_what_it_matches() {
        assert_eq!(
            home_dirs(&denying(&["/crabpot-test-home/*/.npm"])),
            ["/crabpot-test-home/me/.claude/debug"]
        );
        assert_eq!(
            home_dirs(&denying(&["/**/.claude/**"])),
            ["/crabpot-test-home/me/.npm/_logs"]
        );
    }

    #[test]
    fn an_allow_read_inside_the_deny_keeps_the_dir() {
        let mut config = denying(&["/crabpot-test-home/me/.claude"]);
        config.filesystem.allow_read = Some(vec![PathEntry::Spelled(
            "/crabpot-test-home/me/.claude/debug".to_owned(),
        )]);

        assert_eq!(home_dirs(&config).len(), 2);
    }

    #[test]
    fn an_allow_read_reopens_only_a_dir_it_is_at_or_above() {
        let allowing = |allow: &str| {
            let mut config = denying(&["/crabpot-test-home"]);
            config.filesystem.allow_read = Some(vec![PathEntry::Spelled(allow.to_owned())]);
            home_dirs(&config)
        };

        assert_eq!(
            allowing("/crabpot-test-home/me/.claude"),
            ["/crabpot-test-home/me/.claude/debug"]
        );
        assert!(allowing("/crabpot-test-home/me/.claude/debug/sub").is_empty());
        assert!(allowing("/elsewhere").is_empty());
    }

    #[test]
    fn an_allow_read_glob_reopens_nothing() {
        let mut config = denying(&["/crabpot-test-home/me/.claude"]);
        config.filesystem.allow_read = Some(vec![PathEntry::Spelled(
            "/crabpot-test-home/me/.claude/*".to_owned(),
        )]);

        assert_eq!(home_dirs(&config), ["/crabpot-test-home/me/.npm/_logs"]);
    }

    #[test]
    fn an_unknown_home_directory_is_an_error() {
        let base = PathBase::new(None, None);

        assert_eq!(
            default_write_paths(&base, &Config::default()),
            Err(PathError::NoHomeDirectory)
        );
    }
}
