//! The write denies that are always on, inside the working directory.
//!
//! Upstream's `macGetMandatoryDenyEntries`, with the lists of
//! `src/sandbox/sandbox-utils.ts`. They stand wherever `allowWrite` opens the
//! working directory, since a command that can write a shell rc file or a git
//! hook runs code outside the sandbox the next time one is read.

use crabpot_core::paths::{PathBase, normalize_path_for_sandbox};
use crabpot_core::{PathError, ResolvedPath};

/// Files that run or configure a program outside the sandbox.
const DANGEROUS_FILES: [&str; 9] = [
    ".gitconfig",
    ".gitmodules",
    ".bashrc",
    ".bash_profile",
    ".zshrc",
    ".zprofile",
    ".profile",
    ".ripgreprc",
    ".mcp.json",
];

/// Directories whose contents do the same. `.git` is not one: a command must
/// write it to use git, so only `.git/hooks` and `.git/config` are denied.
const DANGEROUS_DIRECTORIES: [&str; 4] = [".vscode", ".idea", ".claude/commands", ".claude/agents"];

/// Each mandatory deny twice: the path in the working directory, and the same
/// name anywhere beneath it. The working directory is a name on disk, so the
/// first is a name and the second keeps it as the anchor of its pattern.
///
/// # Errors
///
/// [`PathError`] when there is no working directory.
pub(super) fn entries(
    base: &PathBase,
    allow_git_config: bool,
) -> Result<Vec<ResolvedPath>, PathError> {
    let cwd = normalize_path_for_sandbox(base, ".", true)?;
    let mut entries = Vec::new();
    let mut deny = |name: &str, beneath: String| -> Result<(), PathError> {
        let path = normalize_path_for_sandbox(base, &format!("{cwd}/{name}"), true)?;
        entries.push(ResolvedPath::named(path));
        entries.push(ResolvedPath::beneath(&cwd, &beneath));
        Ok(())
    };
    for file in DANGEROUS_FILES {
        deny(file, format!("**/{file}"))?;
    }
    for directory in DANGEROUS_DIRECTORIES {
        deny(directory, format!("**/{directory}/**"))?;
    }
    deny(".git/hooks", "**/.git/hooks/**".to_owned())?;
    if !allow_git_config {
        deny(".git/config", "**/.git/config".to_owned())?;
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> PathBase {
        PathBase::new(
            Some("/crabpot-test-home".to_owned()),
            Some("/crabpot-test-work".to_owned()),
        )
    }

    #[test]
    fn there_are_30_entries_and_28_with_allow_git_config() {
        assert_eq!(entries(&base(), false).unwrap().len(), 30);
        assert_eq!(entries(&base(), true).unwrap().len(), 28);
    }

    #[test]
    fn from_the_root_the_patterns_still_cover_a_nested_repo() {
        let root = PathBase::new(Some("/crabpot-test-home".to_owned()), Some("/".to_owned()));
        let entries = entries(&root, false).unwrap();
        assert!(entries.contains(&ResolvedPath::named("/.bashrc")));
        let covers = |sample: &str| entries.iter().any(|entry| entry.deny_covers(sample));
        assert!(covers("/Users/x/proj/.git/hooks/pre-commit"));
        assert!(covers("/Users/x/proj/.bashrc"));
        assert!(covers("/Users/x/proj/.git/config"));
        assert!(!covers("/Users/x/proj/.git/HEAD"));
    }
}
