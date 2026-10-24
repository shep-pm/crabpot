//! The ancestor pins that keep a protected path from being renamed away.

use super::{at, bind_at, denying, denying_writes, mount_at, plan};
use crate::support::Tree;
use crabpot_core::config::PathEntry;

/// The directories between a protected path and the write root are bound over
/// themselves, so the kernel refuses to rename them. The write root is its own
/// mount, and gets no pin. The pins sit beneath the write binds, shallowest
/// first, so one on top of a write root cannot make it read-only.
#[test]
fn an_ancestor_of_a_protected_path_is_pinned() {
    let tree = Tree::empty("fs-deny-write-pins");
    tree.file("work/a/b/.env", "x");
    tree.file("work/a/sibling/seed", "x");
    let (work, a, b) = (
        at(&tree, "work"),
        at(&tree, "work/a"),
        at(&tree, "work/a/b"),
    );
    let env = at(&tree, "work/a/b/.env");

    let words = plan(&tree, &denying_writes(&[&work], &[&env]));

    let pin_a = mount_at(&words, "--ro-bind", &a);
    let pin_b = mount_at(&words, "--ro-bind", &b);
    assert!(pin_a < pin_b, "shallowest first: {words:#?}");
    assert!(
        pin_b < bind_at(&words, &work),
        "beneath the write binds: {words:#?}"
    );
    assert!(
        !words
            .windows(3)
            .any(|triple| triple == ["--ro-bind", &work, &work]),
        "a write root is a mount already: {words:#?}"
    );
    assert!(
        !words.iter().any(|word| word.ends_with("/sibling")),
        "a sibling is nobody's ancestor: {words:#?}"
    );
}

/// A read mask is protected in the same way: renaming the directory that holds
/// it would leave the file readable under its new name.
#[test]
fn an_ancestor_of_a_read_mask_is_pinned() {
    let tree = Tree::empty("fs-deny-read-pins");
    tree.file("secrets/key", "x");
    let (root, secrets, key) = (
        at(&tree, ""),
        at(&tree, "secrets"),
        at(&tree, "secrets/key"),
    );
    let mut config = denying(&[&key]);
    config.filesystem.allow_write = vec![PathEntry::Spelled(root.trim_end_matches('/').to_owned())];

    let words = plan(&tree, &config);

    mount_at(&words, "--ro-bind", &secrets);
}

/// Under a write root of `/` the pins would be buried by its bind, so they
/// follow it, and the top-level directory they stop below is bound writable
/// over them.
#[test]
fn a_root_write_bind_gets_its_pins_after_it_and_a_cover() {
    let tree = Tree::empty("fs-deny-write-root");
    tree.file("work/a/.env", "x");
    let env = at(&tree, "work/a/.env");
    let top = format!("/{}", env.split('/').nth(1).expect("an absolute path"));
    let words = plan(&tree, &denying_writes(&["/"], &[&env]));

    let root = bind_at(&words, "/");
    let pin = mount_at(&words, "--ro-bind", &at(&tree, "work/a"));
    let cover = bind_at(&words, &top);
    assert!(root < pin && pin < cover, "{words:#?}");
}
