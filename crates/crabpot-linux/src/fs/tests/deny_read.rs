//! What `denyRead` mounts over, and the order those mounts land in.

use super::{at, denied_words};
use crate::support::Tree;

#[test]
fn a_denied_directory_becomes_a_tmpfs() {
    let tree = Tree::empty("fs-deny-directory");
    tree.dir("secrets");
    tree.file("secrets/key", "");
    let secrets = at(&tree, "secrets");

    assert_eq!(denied_words(&[&secrets]), ["--tmpfs", &secrets]);
}

#[test]
fn a_denied_file_is_bound_from_dev_null() {
    let tree = Tree::empty("fs-deny-file");
    tree.file("key", "");
    let key = at(&tree, "key");

    assert_eq!(denied_words(&[&key]), ["--ro-bind", "/dev/null", &key]);
}

#[test]
fn a_missing_denied_path_is_skipped() {
    let tree = Tree::empty("fs-deny-missing");

    assert_eq!(denied_words(&[&at(&tree, "nowhere")]), Vec::<String>::new());
}

#[test]
fn what_is_beneath_a_denied_directory_is_left_to_its_tmpfs() {
    let tree = Tree::empty("fs-deny-nested");
    tree.dir("secrets");
    tree.file("secrets/deeper/key", "");
    let secrets = at(&tree, "secrets");
    let key = at(&tree, "secrets/deeper/key");

    assert_eq!(denied_words(&[&key, &secrets]), ["--tmpfs", &secrets]);
}

#[test]
fn a_glob_expands_to_the_paths_on_disk() {
    let tree = Tree::empty("fs-deny-glob");
    tree.file("top.key", "");
    tree.file("a/b/y.key", "");
    tree.file("a/notes.txt", "");
    let nested = at(&tree, "a/b/y.key");
    let top = at(&tree, "top.key");
    let pattern = at(&tree, "**/*.key");

    assert_eq!(
        denied_words(&[&pattern]),
        [
            "--ro-bind",
            "/dev/null",
            &nested,
            "--ro-bind",
            "/dev/null",
            &top
        ]
    );
}

#[test]
fn a_glob_that_matches_nothing_adds_no_word() {
    let tree = Tree::empty("fs-deny-no-match");
    tree.file("a/notes.txt", "");
    let pattern = at(&tree, "**/*.key");

    assert_eq!(denied_words(&[&pattern]), Vec::<String>::new());
}

#[cfg(target_os = "linux")]
#[test]
fn a_path_in_the_kernels_proc_keeps_its_spelling() {
    assert_eq!(
        denied_words(&["/proc/self/environ"]),
        ["--ro-bind", "/dev/null", "/proc/self/environ"]
    );
}
