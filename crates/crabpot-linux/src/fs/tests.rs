use std::path::Path;

use crabpot_core::config::{Config, PathEntry};
use crabpot_core::paths::{PathBase, contains_glob_chars, normalize_path_for_sandbox};

use super::Plan;
use super::allow_write::words_with;
use crate::support::Tree;

/// A tree's path, as a config would spell it.
fn at(tree: &Tree, path: &str) -> String {
    tree.root().join(path).to_string_lossy().into_owned()
}

/// What a relative path and a `~` are read against: a home directory and a
/// working directory inside the tree.
fn base(tree: &Tree) -> PathBase {
    PathBase::new(Some(at(tree, "home")), Some(at(tree, "cwd")))
}

fn allowing(entries: &[&str]) -> Config {
    let mut config = Config::default();
    config.filesystem.allow_write = entries
        .iter()
        .map(|entry| PathEntry::Spelled((*entry).to_owned()))
        .collect();
    config
}

/// The section's words, as text.
fn words(config: &Config, base: &PathBase) -> Vec<String> {
    words_with(config, base)
        .expect("the config resolves")
        .iter()
        .map(|word| word.to_string_lossy().into_owned())
        .collect()
}

/// The paths the words bind writable, in order.
fn bound(words: &[String]) -> Vec<String> {
    words
        .windows(3)
        .filter(|triple| triple[0] == "--bind" && triple[1] == triple[2])
        .map(|triple| triple[1].clone())
        .collect()
}

/// Whether `binds` holds `path` bound writable.
fn holds(binds: &[String], path: &str) -> bool {
    binds.iter().any(|bound| *bound == path)
}

/// Whether `binds` holds nothing that ends at `name`.
fn holds_no_name_below(binds: &[String], name: &str) -> bool {
    !binds.iter().any(|bound| bound.ends_with(name))
}

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

    let words = Plan::build(&allowing(&[&work]))
        .expect("the config resolves")
        .words()
        .iter()
        .map(|word| word.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let root = words
        .windows(3)
        .position(|triple| triple == ["--ro-bind", "/", "/"])
        .expect("the read-only root");
    let bind = words
        .windows(3)
        .position(|triple| triple[0] == "--bind" && triple[1] == work)
        .expect("the bind of the allowed path");

    assert!(root < bind, "{words:#?}");
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
