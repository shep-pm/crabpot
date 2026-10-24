//! The paths the plan binds writable, and what is no path to bind: a glob, or a
//! link that leaves its own tree.

use super::{
    allowing, at, base, bind_at, bound, holds, holds_no_name_below, mount_at, plan, words,
};
use crate::support::Tree;
use crabpot_core::config::Config;
use crabpot_core::paths::{contains_glob_chars, normalize_path_for_sandbox};
use std::path::Path;

#[test]
fn an_allowed_path_is_bound_writable() {
    let tree = Tree::empty("fs-allow-write");
    tree.dir("work");
    let work = at(&tree, "work");

    let binds = bound(&words(&allowing(&[&work]), &base(&tree)));

    assert!(holds(&binds, &work), "{binds:#?}");
}

/// bwrap applies its mounts in the order it reads them, so a bind carves a
/// path out of the read-only root only when it follows it.
#[test]
fn a_bind_follows_the_read_only_root() {
    let tree = Tree::empty("fs-allow-write-order");
    tree.dir("work");
    let work = at(&tree, "work");

    let words = plan(&tree, &allowing(&[&work]));
    let root = words
        .windows(3)
        .position(|triple| triple == ["--ro-bind", "/", "/"])
        .expect("the read-only root");
    let bind = bind_at(&words, &work);

    assert!(root < bind, "{words:#?}");
}

/// The plan's last words are the sandbox's own mounts, as they are in
/// upstream's `wrapCommandWithSandboxLinux`. A grant of the whole root binds
/// the host's filesystem over the read-only one, which is what the caller
/// asked for, and still leaves the sandbox its own `/dev` and its own procfs.
#[test]
fn a_bind_of_the_whole_root_leaves_the_private_mounts_last() {
    let tree = Tree::empty("fs-allow-write-root");
    let words = plan(&tree, &allowing(&["/"]));

    let bind = bind_at(&words, "/");
    for (flag, dest) in [("--dev", "/dev"), ("--proc", "/proc")] {
        let mount = mount_at(&words, flag, dest);
        assert!(bind < mount, "{flag} {dest} follows the bind: {words:#?}");
    }
}

/// The sandbox's own trees stay its own whatever a config asks for. A grant on
/// one of them is bound, and the mount that makes the tree the sandbox's own
/// follows it, so the host's processes and devices never become the sandbox's.
/// A tree that is not there at all, which `/proc` is on macOS, binds nothing
/// and needs no covering.
#[test]
fn a_grant_on_a_private_mount_is_covered_by_it() {
    let tree = Tree::empty("fs-private-mount-cover");
    let words = plan(&tree, &allowing(&["/dev", "/proc"]));

    let dev_bind = bind_at(&words, "/dev");
    for (flag, dest) in [("--dev", "/dev"), ("--proc", "/proc")] {
        let mount = mount_at(&words, flag, dest);
        assert!(
            dev_bind < mount,
            "{flag} {dest} follows the bind: {words:#?}"
        );
    }
}

#[test]
fn a_write_glob_is_dropped() {
    let tree = Tree::empty("fs-write-glob");
    tree.file("logs/a.log", "x");
    tree.dir("out");
    let logs = at(&tree, "logs");
    let out = at(&tree, "out");

    let binds = bound(&words(
        &allowing(&[&format!("{logs}/*.log"), &format!("{out}/**")]),
        &base(&tree),
    ));

    // A trailing `/**` is the directory itself, which a bind of it covers.
    assert!(holds(&binds, &out), "{binds:#?}");
    assert!(holds_no_name_below(&binds, "/logs"), "{binds:#?}");
    assert!(
        !binds.iter().any(|bound| contains_glob_chars(bound)),
        "{binds:#?}"
    );
}

/// A spelling that is a pattern and also the name of a directory that is there
/// is bound as that name, which is the one reading bwrap can use.
#[test]
fn a_glob_that_is_a_name_is_bound() {
    let tree = Tree::empty("fs-write-name");
    tree.dir("out/a[b");
    let name = at(&tree, "out/a[b");

    let binds = bound(&words(&allowing(&[&name]), &base(&tree)));

    assert!(holds(&binds, &name), "{binds:#?}");
}

#[test]
fn the_default_write_paths_are_bound() {
    let tree = Tree::empty("fs-default-write");
    tree.dir("home/.npm/_logs");
    tree.dir("home/.claude/debug");
    let base = base(&tree);

    let binds = bound(&words(&Config::default(), &base));

    assert!(holds(&binds, &at(&tree, "home/.npm/_logs")), "{binds:#?}");
    assert!(
        holds(&binds, &at(&tree, "home/.claude/debug")),
        "{binds:#?}"
    );
    // The sandbox's own stdio sits under the `--dev /dev` mount, which bwrap
    // makes read-write on its own.
    assert!(
        !binds.iter().any(|bound| bound.starts_with("/dev/")),
        "{binds:#?}"
    );
    // `/tmp/claude` is bound where the host has it, under the name it resolves
    // to. A host with no `/tmp/claude` binds nothing for it.
    let tmp_claude = normalize_path_for_sandbox(&base, "/tmp/claude", true).expect("absolute");
    if Path::new(&tmp_claude).exists() {
        assert!(holds(&binds, &tmp_claude), "{binds:#?}");
    }
}

#[test]
fn a_missing_write_path_is_skipped() {
    let tree = Tree::empty("fs-write-missing");
    tree.dir("work");
    let work = at(&tree, "work");

    let binds = bound(&words(
        &allowing(&[&work, &at(&tree, "nowhere"), &at(&tree, "work/inner")]),
        &base(&tree),
    ));

    assert!(holds(&binds, &work), "{binds:#?}");
    assert!(holds_no_name_below(&binds, "/nowhere"), "{binds:#?}");
    assert!(holds_no_name_below(&binds, "/inner"), "{binds:#?}");
}

/// A link is no path bwrap may make writable: a bind follows it, and what
/// becomes writable is what the link leads to, which the caller never named. So
/// a link whose target is not beneath its own spelling is dropped, as upstream's
/// write loop drops it. The fixture tree's `rootlink` is a link to the root.
#[test]
fn a_link_out_of_its_tree_is_not_bound() {
    let tree = Tree::fixture("fs-write-link-out");

    let binds = bound(&words(&allowing(&[&at(&tree, "rootlink")]), &base(&tree)));

    assert!(holds_no_name_below(&binds, "/rootlink"), "{binds:#?}");
    assert!(!holds(&binds, "/"), "{binds:#?}");
}

/// The check is strict: the fixture tree's `linked` leads to a directory beside
/// it, which is outside its own tree too, and is dropped like a link that
/// leaves the filesystem.
#[test]
fn a_link_to_a_sibling_directory_is_not_bound() {
    let tree = Tree::fixture("fs-write-link-sibling");

    let binds = bound(&words(&allowing(&[&at(&tree, "linked")]), &base(&tree)));

    assert!(holds_no_name_below(&binds, "/linked"), "{binds:#?}");
    assert!(holds_no_name_below(&binds, "/real"), "{binds:#?}");
}
