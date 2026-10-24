//! What `allowRead` opens back over a read mask.

use super::{allowed_words, allowed_words_with, at, bound_back_at, mount_at, plan, reading};
use crate::support::Tree;

#[test]
fn an_allowed_path_is_bound_back_over_a_tmpfs() {
    let tree = Tree::empty("fs-allow-back");
    tree.dir("secrets");
    tree.file("secrets/ok.txt", "");
    let secrets = at(&tree, "secrets");
    let ok = at(&tree, "secrets/ok.txt");

    let words = plan(&tree, &reading(&[&secrets], &[&ok]));
    let tmpfs = mount_at(&words, "--tmpfs", &secrets);
    let bind = bound_back_at(&words, &ok);

    assert!(tmpfs < bind, "{words:#?}");
}

#[test]
fn an_allowed_path_outside_a_denial_adds_no_word() {
    let tree = Tree::empty("fs-allow-outside");
    tree.dir("secrets");
    tree.dir("open");
    let secrets = at(&tree, "secrets");
    let open = at(&tree, "open");

    assert_eq!(allowed_words(&[&secrets], &[&open]), Vec::<String>::new());
}

#[test]
fn an_allow_glob_expands_on_disk() {
    let tree = Tree::empty("fs-allow-glob");
    tree.dir("secrets");
    tree.file("secrets/a.txt", "");
    tree.file("secrets/b.log", "");
    let secrets = at(&tree, "secrets");
    let txt = at(&tree, "secrets/a.txt");
    let pattern = at(&tree, "secrets/*.txt");

    assert_eq!(
        allowed_words(&[&secrets], &[&pattern]),
        ["--ro-bind", &txt, &txt]
    );
}

#[test]
fn a_nested_deny_stays_hidden_under_a_reopened_directory() {
    let tree = Tree::empty("fs-allow-nested-deny");
    tree.dir("secrets");
    tree.dir("secrets/shared");
    tree.file("secrets/shared/key", "");
    let secrets = at(&tree, "secrets");
    let shared = at(&tree, "secrets/shared");
    let key = at(&tree, "secrets/shared/key");

    assert_eq!(
        allowed_words(&[&secrets, &key], &[&shared]),
        [
            "--ro-bind",
            &shared,
            &shared,
            "--ro-bind",
            "/dev/null",
            &key,
        ]
    );
}

#[test]
fn a_deny_glob_covering_a_reopened_directory_gives_way() {
    let tree = Tree::empty("fs-allow-late-carve");
    tree.dir("secrets");
    tree.dir("secrets/shared");
    tree.file("secrets/shared/a", "");
    tree.file("secrets/key", "");
    let secrets = at(&tree, "secrets");
    let shared = at(&tree, "secrets/shared");
    let region = at(&tree, "secrets/**/*");

    assert_eq!(
        allowed_words(&[&secrets, &region], &[&shared]),
        ["--ro-bind", &shared, &shared]
    );
}

#[test]
fn a_deny_glob_not_covering_a_reopened_directory_stays_masked() {
    let tree = Tree::empty("fs-allow-late-leaf");
    tree.dir("secrets");
    tree.dir("secrets/shared");
    tree.file("secrets/shared/deeper.key", "");
    tree.file("secrets/key", "");
    let secrets = at(&tree, "secrets");
    let shared = at(&tree, "secrets/shared");
    let leaf = at(&tree, "secrets/shared/deeper.key");
    let pattern = at(&tree, "secrets/**/*.key");

    assert_eq!(
        allowed_words(&[&secrets, &pattern], &[&shared]),
        [
            "--ro-bind",
            &shared,
            &shared,
            "--ro-bind",
            "/dev/null",
            &leaf,
        ]
    );
}

#[test]
fn an_allow_named_under_its_own_denial_wins() {
    let tree = Tree::empty("fs-allow-named-deny");
    tree.dir("secrets");
    tree.dir("secrets/shared");
    tree.file("secrets/shared/key", "");
    let secrets = at(&tree, "secrets");
    let shared = at(&tree, "secrets/shared");
    let key = at(&tree, "secrets/shared/key");

    assert_eq!(
        allowed_words(&[&secrets, &key], &[&shared, &key]),
        ["--ro-bind", &shared, &shared, "--ro-bind", &key, &key]
    );
}

#[test]
fn a_denied_directory_under_a_reopening_masks_around_a_deeper_allow() {
    let tree = Tree::empty("fs-allow-deeper");
    tree.dir("secrets");
    tree.dir("secrets/a/b/c");
    tree.file("secrets/a/b/other", "");
    let secrets = at(&tree, "secrets");
    let a = at(&tree, "secrets/a");
    let b = at(&tree, "secrets/a/b");
    let c = at(&tree, "secrets/a/b/c");

    assert_eq!(
        allowed_words(&[&secrets, &b], &[&a, &c]),
        ["--ro-bind", &a, &a, "--tmpfs", &b, "--ro-bind", &c, &c,]
    );
}

#[test]
fn an_allow_under_a_write_bind_comes_back_writable() {
    let tree = Tree::empty("fs-allow-write-back");
    tree.dir("work/secrets");
    tree.file("work/secrets/out", "");
    let work = at(&tree, "work");
    let secrets = at(&tree, "work/secrets");
    let out = at(&tree, "work/secrets/out");

    assert_eq!(
        allowed_words_with(&[&secrets], &[&out], &[&work]),
        ["--bind", &out, &out]
    );
}

/// A link planted in an allow glob's directory is no match the glob
/// authorized: resolving it would reopen its target at the target's own
/// place, beneath the denial that hides it.
#[test]
fn a_symlink_match_of_an_allow_glob_reopens_nothing() {
    let tree = Tree::empty("fs-allow-glob-link");
    tree.dir("secrets");
    tree.file("secrets/key", "");
    tree.link("../secrets/key", "public/key.txt");
    let secrets = at(&tree, "secrets");
    let pattern = at(&tree, "public/*.txt");

    assert_eq!(
        allowed_words(&[&secrets], &[&pattern]),
        Vec::<String>::new()
    );
}

/// The bind back of an allowed path is covered by the sandbox's own mounts,
/// which are the plan's last words.
#[test]
fn an_allow_bind_precedes_the_private_mounts() {
    let tree = Tree::empty("fs-allow-order");
    tree.dir("secrets");
    tree.file("secrets/ok.txt", "");
    let secrets = at(&tree, "secrets");
    let ok = at(&tree, "secrets/ok.txt");

    let words = plan(&tree, &reading(&[&secrets], &[&ok]));
    let bind = bound_back_at(&words, &ok);
    for (flag, dest) in [("--dev", "/dev"), ("--proc", "/proc")] {
        let mount = mount_at(&words, flag, dest);
        assert!(bind < mount, "{flag} {dest} follows the bind: {words:#?}");
    }
}
