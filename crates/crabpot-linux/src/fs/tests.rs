use std::path::Path;

use crabpot_core::config::{Config, PathEntry};
use crabpot_core::paths::{PathBase, contains_glob_chars, normalize_path_for_sandbox};

use super::Plan;
use super::allow_read;
use super::allow_write::words_with;
use super::deny_read;
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

/// A config whose only path entries are `denyRead` spellings.
fn denying(entries: &[&str]) -> Config {
    let list = entries
        .iter()
        .map(|entry| format!("\"{entry}\""))
        .collect::<Vec<_>>()
        .join(",");
    Config::from_json(&format!(
        r#"{{
            "network": {{"allowedDomains": [], "deniedDomains": []}},
            "filesystem": {{"denyRead": [{list}], "allowWrite": [], "denyWrite": []}}
        }}"#
    ))
    .expect("a config")
}

/// A config whose read settings are `denyRead` and `allowRead`.
fn reading(deny: &[&str], allow: &[&str]) -> Config {
    reading_with(deny, allow, &[])
}

/// A config whose read settings are `denyRead` and `allowRead`, and whose
/// `allowWrite` is `write`.
fn reading_with(deny: &[&str], allow: &[&str], write: &[&str]) -> Config {
    let list = |entries: &[&str]| {
        entries
            .iter()
            .map(|entry| format!("\"{entry}\""))
            .collect::<Vec<_>>()
            .join(",")
    };
    Config::from_json(&format!(
        r#"{{
            "network": {{"allowedDomains": [], "deniedDomains": []}},
            "filesystem": {{
                "denyRead": [{}], "allowRead": [{}],
                "allowWrite": [{}], "denyWrite": []
            }}
        }}"#,
        list(deny),
        list(allow),
        list(write)
    ))
    .expect("a config")
}

/// The section's words, as text.
fn words(config: &Config, base: &PathBase) -> Vec<String> {
    words_with(config, base)
        .expect("the config resolves")
        .iter()
        .map(|word| word.to_string_lossy().into_owned())
        .collect()
}

/// The mounts `allowRead` adds to what a config allowing nothing adds.
fn allowed_words(deny: &[&str], allow: &[&str]) -> Vec<String> {
    allowed_words_with(deny, allow, &[])
}

/// The mounts `allowRead` adds, with `allowWrite` set to `write`.
fn allowed_words_with(deny: &[&str], allow: &[&str], write: &[&str]) -> Vec<String> {
    allow_read::words(&reading_with(deny, allow, write))
        .expect("a config")
        .iter()
        .map(|word| word.to_string_lossy().into_owned())
        .collect()
}

/// Where the plan binds `path` back read-only over what hid it.
fn bound_back_at(words: &[String], path: &str) -> usize {
    words
        .windows(3)
        .position(|triple| triple == ["--ro-bind", path, path])
        .unwrap_or_else(|| panic!("--ro-bind {path} {path} is not in the plan: {words:#?}"))
}

/// A whole plan's words, as text: every mount `bwrap` is asked to make, in the
/// order it reads them.
fn plan(config: &Config) -> Vec<String> {
    Plan::build(config)
        .expect("the config resolves")
        .words()
        .iter()
        .map(|word| word.to_string_lossy().into_owned())
        .collect()
}

/// The mounts `denyRead` adds to what a config denying nothing adds.
fn denied_words(entries: &[&str]) -> Vec<String> {
    let nothing = deny_read::words(&denying(&[])).expect("a config").len();
    deny_read::words(&denying(entries))
        .expect("a config")
        .iter()
        .skip(nothing)
        .map(|word| word.to_string_lossy().into_owned())
        .collect()
}

/// Where the plan mounts `dest` as `flag` asks.
fn mount_at(words: &[String], flag: &str, dest: &str) -> usize {
    words
        .windows(2)
        .position(|pair| pair == [flag, dest])
        .unwrap_or_else(|| panic!("{flag} {dest} is not in the plan: {words:#?}"))
}

/// Where the plan binds `path` writable.
fn bind_at(words: &[String], path: &str) -> usize {
    words
        .windows(3)
        .position(|triple| triple == ["--bind", path, path])
        .unwrap_or_else(|| panic!("--bind {path} {path} is not in the plan: {words:#?}"))
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

    let words = plan(&allowing(&[&work]));
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
    let words = plan(&allowing(&["/"]));

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
    let words = plan(&allowing(&["/dev", "/proc"]));

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

#[test]
fn an_allowed_path_is_bound_back_over_a_tmpfs() {
    let tree = Tree::empty("fs-allow-back");
    tree.dir("secrets");
    tree.file("secrets/ok.txt", "");
    let secrets = at(&tree, "secrets");
    let ok = at(&tree, "secrets/ok.txt");

    let words = plan(&reading(&[&secrets], &[&ok]));
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

    let words = plan(&reading(&[&secrets], &[&ok]));
    let bind = bound_back_at(&words, &ok);
    for (flag, dest) in [("--dev", "/dev"), ("--proc", "/proc")] {
        let mount = mount_at(&words, flag, dest);
        assert!(bind < mount, "{flag} {dest} follows the bind: {words:#?}");
    }
}
