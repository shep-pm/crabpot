//! The folders under the home directory a command may write without asking,
//! less those a read deny hides.
//!
//! A port of `getDefaultWritePaths` and `homeDirsNotReadDenied` in
//! `src/sandbox/sandbox-utils.ts`. An explicit `denyRead` wins over the
//! implicit write allow, and an `allowRead` beneath the deny gives the folder
//! back, since the caller has already made it readable.

use crate::glob::deny_glob_matches;
use crate::path::{
    PathBase, PathError, contains_glob_chars, is_at_or_under, normalize,
    normalize_path_for_sandbox, remove_trailing_glob_suffix,
};
use crate::path_entries::PathEntry;

/// Relative to the home directory.
const FOLDERS: &[&str] = &[".npm/_logs", ".claude/debug"];

/// `home` and `rel` joined as `path.join` joins them.
fn join(home: &str, rel: &str) -> String {
    let joined = if home.is_empty() {
        rel.to_owned()
    } else {
        format!("{home}/{rel}")
    };
    normalize(&joined)
}

/// What a read rule covers: a name and everything beneath it, or what a
/// pattern matches and everything beneath that.
enum Covers {
    Name(String),
    Pattern(String),
}

impl Covers {
    fn holds(&self, path: &str) -> bool {
        match self {
            Self::Name(name) => is_at_or_under(path, name),
            Self::Pattern(pattern) => deny_glob_matches(pattern, path),
        }
    }
}

/// What `entry` covers. Pattern or name is decided on what the caller wrote,
/// before the spelling is resolved: resolving splices in a working directory
/// or a home directory that may carry glob characters in its own name.
fn covers(base: &PathBase, entry: &PathEntry) -> Result<Covers, PathError> {
    Ok(match entry {
        PathEntry::Literal(path) => Covers::Name(normalize_path_for_sandbox(base, path, true)?),
        PathEntry::Spelled(spelling) => {
            let stripped = remove_trailing_glob_suffix(spelling);
            if contains_glob_chars(&stripped) {
                Covers::Pattern(normalize_path_for_sandbox(base, &stripped, false)?)
            } else {
                Covers::Name(normalize_path_for_sandbox(base, &stripped, true)?)
            }
        }
    })
}

/// The paths an `allowRead` entry opens as a name. A pattern opens none, since
/// what it matches is not known until the command runs.
fn reopened(base: &PathBase, allow_read: &[PathEntry]) -> Result<Vec<String>, PathError> {
    let mut names = Vec::new();
    for entry in allow_read {
        let name = match entry {
            PathEntry::Literal(path) => path.clone(),
            PathEntry::Spelled(spelling) => {
                let stripped = remove_trailing_glob_suffix(spelling);
                if contains_glob_chars(&stripped) {
                    continue;
                }
                stripped
            }
        };
        names.push(normalize_path_for_sandbox(base, &name, true)?);
    }
    Ok(names)
}

/// The folders no entry of `deny_read` covers, or that an entry of
/// `allow_read` beneath the covering deny opens again, as paths under the home
/// directory of `base`.
///
/// # Errors
///
/// [`PathError`] when the home directory is not set, or an entry needs a
/// working directory and there is none.
pub(crate) fn kept(
    base: &PathBase,
    deny_read: &[PathEntry],
    allow_read: &[PathEntry],
) -> Result<Vec<String>, PathError> {
    let home = base.home()?;
    // A folder may not exist yet, so its second spelling is built from the
    // home directory, which does.
    let mut homes = vec![home.to_owned()];
    let resolved = normalize_path_for_sandbox(base, home, true)?;
    if resolved != home {
        homes.push(resolved);
    }
    let denies = deny_read
        .iter()
        .map(|entry| covers(base, entry))
        .collect::<Result<Vec<_>, _>>()?;
    let reopened = reopened(base, allow_read)?;

    Ok(FOLDERS
        .iter()
        .filter(|rel| {
            let spellings: Vec<String> = homes.iter().map(|home| join(home, rel)).collect();
            !denies.iter().any(|deny| {
                spellings.iter().any(|s| deny.holds(s))
                    && !reopened.iter().any(|allow| {
                        deny.holds(allow) && spellings.iter().any(|s| is_at_or_under(s, allow))
                    })
            })
        })
        .map(|rel| join(home, rel))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(spellings: &[&str]) -> Vec<PathEntry> {
        spellings
            .iter()
            .map(|spelling| PathEntry::Spelled((*spelling).to_owned()))
            .collect()
    }

    const BOTH: &[&str] = &["/crabpot-home/.npm/_logs", "/crabpot-home/.claude/debug"];
    const NPM: &[&str] = &["/crabpot-home/.npm/_logs"];
    const CLAUDE: &[&str] = &["/crabpot-home/.claude/debug"];

    fn kept_of(deny_read: &[PathEntry], allow_read: &[PathEntry]) -> Vec<String> {
        let base = PathBase::new(Some("/crabpot-home".to_owned()), Some("/work".to_owned()));
        kept(&base, deny_read, allow_read).unwrap()
    }

    #[test]
    fn a_folder_under_a_read_deny_is_dropped_and_one_an_allow_reopens_returns() {
        // What `getDefaultWritePaths` returns at aceba124 for the same rules,
        // with `/crabpot-home` as HOME. It is a path no machine has, so nothing
        // is resolved.
        let home = &["/crabpot-home"];
        for (deny, allow, expected) in [
            (&["/elsewhere"][..], &[][..], BOTH),
            (&["~"], &[], &[]),
            (&["/crabpot-home/.npm"], &[], CLAUDE),
            (&["/crabpot-home/.claude/debug"], &[], NPM),
            (home, &[], &[]),
            (home, &["/crabpot-home/.claude/debug"], CLAUDE),
            (home, &["/crabpot-home/.claude"], CLAUDE),
            (home, &["/crabpot-home/.claude/debug/sub"], &[]),
            (home, &["/crabpot-home/.claude/*"], &[]),
            (home, &["/elsewhere"], &[]),
            (&["/crabpot-home/.*"], &[], &[]),
            (&["/crabpot-home/.c*"], &[], NPM),
            (&["/crabpot-home/**/_logs"], &[], CLAUDE),
            (&["/crabpot-home/.npm/**"], &[], CLAUDE),
            (
                &["/crabpot-home/.claude", "/crabpot-home/.npm"],
                &["/crabpot-home/.claude/debug"],
                CLAUDE,
            ),
        ] {
            assert_eq!(
                kept_of(&entries(deny), &entries(allow)),
                expected,
                "deny {deny:?} allow {allow:?}"
            );
        }
    }

    #[test]
    fn a_marked_entry_is_a_name_whatever_it_holds() {
        let marked = |path: &str| PathEntry::Literal(path.to_owned());

        assert_eq!(
            kept_of(&[marked("/crabpot-home")], &[]),
            <[&str; 0]>::default()
        );
        assert_eq!(
            kept_of(
                &entries(&["/crabpot-home"]),
                &[marked("/crabpot-home/.claude/debug")]
            ),
            CLAUDE
        );
        assert_eq!(kept_of(&[marked("/crabpot-home/.[nc]*")], &[]), BOTH);
    }

    #[test]
    fn with_no_deny_every_folder_is_kept() {
        assert_eq!(kept_of(&[], &entries(&["/crabpot-home"])), BOTH);
    }

    #[test]
    fn no_home_directory_is_an_error() {
        let base = PathBase::new(None, Some("/work".to_owned()));

        assert_eq!(kept(&base, &[], &[]), Err(PathError::NoHomeDirectory));
    }
}
