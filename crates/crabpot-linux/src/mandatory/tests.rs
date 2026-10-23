use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

use super::*;

#[path = "../../tests/support/mod.rs"]
mod support;

use support::Tree;

/// Deep enough for every name of the fixture tree except the chain's.
const DEEP: usize = 6;

/// The fixture tree's deny paths at the default depth, relative to its root
/// and sorted.
fn denied(test: &str, max_depth: usize) -> Vec<String> {
    let tree = Tree::fixture(test);
    relative(&tree, mandatory_deny_paths(tree.root(), max_depth, false))
}

fn relative(tree: &Tree, paths: Vec<PathBuf>) -> Vec<String> {
    let mut paths: Vec<String> = paths
        .iter()
        .map(|path| {
            path.strip_prefix(tree.root())
                .expect("beneath the root")
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    paths.sort();
    paths
}

fn lists(denied: &[String], expected: &[&str]) {
    for path in expected {
        assert!(denied.iter().any(|d| d == path), "{path} in {denied:#?}");
    }
}

fn omits(denied: &[String], unexpected: &[&str]) {
    for path in unexpected {
        assert!(!denied.iter().any(|d| d == path), "{path} in {denied:#?}");
    }
}

#[test]
fn case_variants_are_listed() {
    let denied = denied("case-variants", DEEP);
    lists(
        &denied,
        &[
            "case/file/.BashRC",
            "case/vscode/.VSCODE",
            "case/idea/.Idea",
            "case/commands/.Claude/COMMANDS",
            "case/agents/.CLAUDE/agents",
            // The directory keeps its case, and hooks is hooks.
            "case/hooks/.Git/HOOKS",
            "case/head/.GIT/hooks",
            "case/config/.git/CONFIG",
        ],
    );
}

#[test]
fn hidden_files_are_listed() {
    let tree = Tree::fixture("hidden");
    let listed: Vec<String> = scan(tree.root(), 4, false, SCAN_TIME_LIMIT)
        .unwrap()
        .listed
        .iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect();
    lists(
        &listed,
        &[
            ".bashrc",
            ".bash_profile",
            ".gitconfig",
            ".gitmodules",
            ".zshrc",
            ".zprofile",
            ".profile",
            ".ripgreprc",
            ".mcp.json",
            "repo/.git/HEAD",
            "repo/.git/config",
            "repo/.git/hooks/pre-commit",
            "repo/.git/hooks/sub/post-merge",
        ],
    );
    omits(
        &listed,
        &[
            "readme.md",
            "repo/src/main.rs",
            "repo/.git/objects/pack/pack-1",
            "worktree/.claude/settings.json",
        ],
    );

    let denied = relative(&tree, mandatory_deny_paths(tree.root(), 3, false));
    lists(&denied, &["repo/.git/hooks", "repo/.git/config"]);
    omits(
        &denied,
        &[
            "repo/.git/HEAD",
            "repo/.git/objects",
            "repo/src",
            "worktree/.git",
            "worktree/.claude",
        ],
    );
}

#[test]
fn a_gitignore_does_not_hide_a_file() {
    let denied = denied("gitignore", DEEP);
    lists(&denied, &["ignored/.bashrc", "ignored/.vscode"]);
}

#[test]
fn node_modules_is_skipped() {
    let denied = denied("node-modules", DEEP);
    omits(
        &denied,
        &[
            "node_modules/pkg/.bashrc",
            "node_modules/.vscode",
            "packages/node_modules/.vscode",
            "packages/node_modules/pkg/.git/hooks",
        ],
    );
    // The glob upstream passes is case-sensitive.
    lists(&denied, &["other/Node_Modules/.vscode"]);
}

/// `rg` takes every `--iglob` after every `-g`, and the last glob wins.
#[test]
fn a_file_directly_in_node_modules_is_still_listed_as_rg_lists_it() {
    let denied = denied("node-modules-direct", DEEP);
    lists(
        &denied,
        &[
            "node_modules/.bashrc",
            "node_modules/.zshrc/.profile",
            ".vscode",
        ],
    );
}

#[test]
fn a_symlinked_directory_is_not_followed() {
    let denied = denied("symlinks", DEEP);
    lists(&denied, &["real/.bashrc", "real/.vscode"]);
    omits(
        &denied,
        &[
            "linked/.bashrc",
            "linked/.vscode",
            "sub/.vscode",
            "sub/.zprofile",
            "dangling/.profile",
        ],
    );
}

#[test]
fn a_dangerous_name_that_is_a_directory_lists_only_what_is_beneath_it() {
    let denied = denied("directory-names", DEEP);
    omits(&denied, &["dirs/.zshrc", "dirs/.bashrc", "dirs/.vscode"]);
}

/// With a depth of 3, a file lies down to the third level, and a dangerous
/// directory or the hooks and config of a repository to the second. At 5, the
/// same two levels further down.
#[test]
fn the_depth_boundary_matches_upstream() {
    let denied = denied("depth", 3);
    lists(
        &denied,
        &[
            "chain/.bashrc",
            "chain/.vscode",
            "chain/.git/hooks",
            "chain/c1/.bashrc",
        ],
    );
    omits(
        &denied,
        &[
            "chain/c1/.vscode",
            "chain/c1/.git/hooks",
            "chain/c1/.git/config",
            "chain/c1/c2/.bashrc",
            "chain/c1/c2/c3/c4/.bashrc",
            "chain/c1/c2/c3/c4/c5/.mcp.json",
        ],
    );

    let deeper = self::denied("depth-deeper", 5);
    lists(
        &deeper,
        &[
            "chain/c1/c2/c3/.bashrc",
            "chain/c1/c2/.vscode",
            "chain/c1/c2/.git/hooks",
            "chain/c1/c2/.git/config",
        ],
    );
    omits(
        &deeper,
        &[
            "chain/c1/c2/c3/c4/.bashrc",
            "chain/c1/c2/c3/.vscode",
            "chain/c1/c2/c3/.git/hooks",
            "chain/c1/c2/c3/c4/c5/.mcp.json",
        ],
    );
}

#[test]
fn a_depth_of_zero_denies_nothing_below_the_working_directory() {
    let tree = Tree::fixture("depth-zero");
    let paths = mandatory_deny_paths(tree.root(), 0, false);
    assert_eq!(paths, cwd_deny_paths(tree.root(), false));
}

#[test]
fn the_working_directory_denies_the_same_names_as_the_macos_profile_does() {
    let tree = Tree::empty("cwd-names");
    tree.dir(".git");
    let paths = relative(&tree, cwd_deny_paths(tree.root(), false));
    assert_eq!(paths.len(), 9 + 4 + 2);
    lists(
        &paths,
        &[".bashrc", ".claude/commands", ".git/hooks", ".git/config"],
    );
    omits(&paths, &[".git"]);
    let paths = relative(&tree, cwd_deny_paths(tree.root(), true));
    omits(&paths, &[".git/config"]);
}

#[test]
fn a_dot_git_file_is_denied_and_an_absent_one_is_not() {
    let tree = Tree::empty("dot-git-file");
    assert!(!relative(&tree, cwd_deny_paths(tree.root(), false)).contains(&".git".to_owned()));
    tree.file(".git", "gitdir: /elsewhere");
    let paths = relative(&tree, cwd_deny_paths(tree.root(), false));
    lists(&paths, &[".git"]);
    omits(&paths, &[".git/hooks", ".git/config"]);
}

/// Whether this user reads a directory of mode 0, as root does: there is
/// nothing to see, so the test has nothing to show.
fn reads_anything(dir: &Path) -> bool {
    fs::read_dir(dir).is_ok()
}

#[test]
fn an_unreadable_directory_is_denied_whole() {
    let tree = Tree::empty("unreadable");
    tree.file("open/.bashrc", "");
    tree.file("shut/inner/.bashrc", "");
    let shut = tree.root().join("shut");
    fs::set_permissions(&shut, fs::Permissions::from_mode(0o000)).unwrap();
    if reads_anything(&shut) {
        return;
    }
    let paths = relative(&tree, mandatory_deny_paths(tree.root(), 3, false));
    lists(&paths, &["open/.bashrc", "shut"]);
    omits(&paths, &["shut/inner/.bashrc"]);

    // Past the depth, it is not looked at at all.
    let paths = relative(&tree, mandatory_deny_paths(tree.root(), 0, false));
    omits(&paths, &["shut"]);
}

#[test]
fn a_directory_that_cannot_be_searched_is_stood_in_for_by_the_one_above_it() {
    let tree = Tree::empty("unsearchable");
    tree.file("shut/inner/.bashrc", "");
    let shut = tree.root().join("shut");
    // Listed but not entered.
    fs::set_permissions(&shut, fs::Permissions::from_mode(0o444)).unwrap();
    if fs::metadata(shut.join("inner")).is_ok() {
        return;
    }
    let paths = relative(&tree, mandatory_deny_paths(tree.root(), 3, false));
    lists(&paths, &["shut"]);
}

#[test]
fn a_walk_past_the_time_limit_is_an_error() {
    let tree = Tree::fixture("time-limit");
    let limit = Duration::ZERO;
    let Err(timed_out) = scan(tree.root(), 3, false, limit) else {
        panic!("a walk with no time ended");
    };
    assert_eq!(timed_out.limit, limit);
    assert!(timed_out.found.listed.is_empty());
    assert!(timed_out.to_string().contains("ran past"));
    // And in a generous one the same walk ends.
    assert!(scan(tree.root(), 3, false, Duration::from_secs(60)).is_ok());
}
