//! What `denyWrite` binds read-only, and the read mounts a deny bind shows
//! through.

use super::{at, bind_at, denying_writes, last_write_bind, mount_at, plan};
use crate::support::Tree;
use crabpot_core::config::PathEntry;

/// A denied file is bound over itself read-only, and a later write bind does
/// not undo it: the bind comes after every write bind in the plan.
#[test]
fn deny_write_words_come_after_every_write_bind() {
    let tree = Tree::empty("fs-deny-write-order");
    tree.file("work/.env", "x");
    tree.dir("other");
    let (work, env, other) = (
        at(&tree, "work"),
        at(&tree, "work/.env"),
        at(&tree, "other"),
    );

    let words = plan(&tree, &denying_writes(&[&work, &other], &[&env]));

    let deny = mount_at(&words, "--ro-bind", &env);
    assert!(last_write_bind(&words) < deny, "{words:#?}");
    assert!(
        deny < mount_at(&words, "--dev", "/dev"),
        "the sandbox's own mounts stay last: {words:#?}"
    );
}

#[test]
fn a_denied_file_is_bound_read_only() {
    let tree = Tree::empty("fs-deny-write-file");
    tree.file("work/.env", "x");
    let (work, env) = (at(&tree, "work"), at(&tree, "work/.env"));

    let words = plan(&tree, &denying_writes(&[&work], &[&env]));

    let at = words
        .windows(3)
        .position(|triple| triple == ["--ro-bind", &env, &env]);
    assert!(at.is_some(), "{words:#?}");
}

/// A denied path outside every write root is read-only already, so it adds no
/// bind.
#[test]
fn a_deny_outside_the_write_roots_adds_nothing() {
    let tree = Tree::empty("fs-deny-write-outside");
    tree.file("work/seed", "x");
    tree.file("elsewhere/.env", "x");
    let (work, env) = (at(&tree, "work"), at(&tree, "elsewhere/.env"));

    let words = plan(&tree, &denying_writes(&[&work], &[&env]));

    assert!(
        !words
            .windows(3)
            .any(|triple| triple == ["--ro-bind", &env, &env]),
        "{words:#?}"
    );
}

/// A write glob is dropped, as it is for `allowWrite`: upstream binds paths on
/// Linux and a pattern is none.
#[test]
fn a_deny_glob_is_dropped() {
    let tree = Tree::empty("fs-deny-write-glob");
    tree.file("work/top.key", "x");
    let (work, pattern) = (at(&tree, "work"), at(&tree, "work/**/*.key"));
    let key = at(&tree, "work/top.key");

    let words = plan(&tree, &denying_writes(&[&work], &[&pattern]));

    assert!(
        !words
            .windows(3)
            .any(|triple| triple == ["--ro-bind", &key, &key]),
        "{words:#?}"
    );
}

/// A deny bind over a directory shows what a read tmpfs hid beneath it, so the
/// tmpfs is made again after it.
#[test]
fn a_read_mount_beneath_a_denied_directory_is_made_again() {
    let tree = Tree::empty("fs-deny-write-reapply");
    tree.file("work/dir/secret/key", "x");
    let (work, dir, secret) = (
        at(&tree, "work"),
        at(&tree, "work/dir"),
        at(&tree, "work/dir/secret"),
    );
    let mut config = denying_writes(&[&work], &[&dir]);
    config.filesystem.deny_read = vec![PathEntry::Spelled(secret.clone())];

    let words = plan(&tree, &config);

    let deny = mount_at(&words, "--ro-bind", &dir);
    let again = words
        .windows(2)
        .rposition(|pair| pair == ["--tmpfs", &secret]);
    assert!(again.is_some_and(|at| deny < at), "{words:#?}");
}

/// A deny bind over a directory shows the host's contents again, so a path
/// `allowRead` opened in a tmpfs beneath it is hidden and opened again.
#[test]
fn a_reopened_path_beneath_a_denied_directory_is_made_again() {
    let tree = Tree::empty("fs-deny-write-reopen");
    tree.file("work/dir/secret/public/key", "x");
    let (work, dir, secret, public) = (
        at(&tree, "work"),
        at(&tree, "work/dir"),
        at(&tree, "work/dir/secret"),
        at(&tree, "work/dir/secret/public"),
    );
    let mut config = denying_writes(&[&work], &[&dir]);
    config.filesystem.deny_read = vec![PathEntry::Spelled(secret.clone())];
    config.filesystem.allow_read = Some(vec![PathEntry::Spelled(public.clone())]);

    let words = plan(&tree, &config);

    let deny = mount_at(&words, "--ro-bind", &dir);
    let hidden = words
        .windows(2)
        .rposition(|pair| pair == ["--tmpfs", &secret])
        .expect("the tmpfs is made again");
    let reopened = words
        .windows(3)
        .rposition(|triple| triple == ["--ro-bind", &public, &public])
        .expect("the path is opened again");
    assert!(deny < hidden && hidden < reopened, "{words:#?}");
}

/// A deny of a directory under a read tmpfs makes no bind of its own, but a
/// path `allowRead` opened inside it came back writable, so it is bound
/// read-only after.
#[test]
fn a_reopened_path_under_a_hidden_deny_is_bound_read_only() {
    let tree = Tree::empty("fs-deny-write-hidden");
    tree.file("work/secret/pub/key", "x");
    let (work, secret, public) = (
        at(&tree, "work"),
        at(&tree, "work/secret"),
        at(&tree, "work/secret/pub"),
    );
    let mut config = denying_writes(&[&work], &[&secret]);
    config.filesystem.deny_read = vec![PathEntry::Spelled(secret.clone())];
    config.filesystem.allow_read = Some(vec![PathEntry::Spelled(public.clone())]);

    let words = plan(&tree, &config);

    let writable = bind_at(&words, &public);
    let read_only = words
        .windows(3)
        .rposition(|triple| triple == ["--ro-bind", &public, &public])
        .expect("the path is bound read-only");
    assert!(writable < read_only, "{words:#?}");
}
