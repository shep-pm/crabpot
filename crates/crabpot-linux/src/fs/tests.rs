use std::path::Path;

use crabpot_core::config::{Config, PathEntry};
use crabpot_core::paths::{PathBase, contains_glob_chars, normalize_path_for_sandbox};

use super::Draft;
use super::Plan;
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

/// The section's words, as text.
fn words(config: &Config, base: &PathBase) -> Vec<String> {
    words_with(config, base)
        .expect("the config resolves")
        .iter()
        .map(|word| word.to_string_lossy().into_owned())
        .collect()
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
    let nothing = deny_read::words(&denying(&[]), &mut Draft::default())
        .expect("a config")
        .len();
    deny_read::words(&denying(entries), &mut Draft::default())
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

/// A config that allows `allow` and denies `deny`, in the order a settings
/// file spells them.
fn denying_writes(allow: &[&str], deny: &[&str]) -> Config {
    let quoted = |entries: &[&str]| {
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
                "denyRead": [],
                "allowWrite": [{}],
                "denyWrite": [{}]
            }}
        }}"#,
        quoted(allow),
        quoted(deny)
    ))
    .expect("a config")
}

/// The last place a write bind is made in `words`.
fn last_write_bind(words: &[String]) -> usize {
    words
        .windows(3)
        .rposition(|triple| triple[0] == "--bind" && triple[1] == triple[2])
        .expect("a write bind")
}

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

    let words = plan(&denying_writes(&[&work, &other], &[&env]));

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

    let words = plan(&denying_writes(&[&work], &[&env]));

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

    let words = plan(&denying_writes(&[&work], &[&env]));

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

    let words = plan(&denying_writes(&[&work], &[&pattern]));

    assert!(
        !words
            .windows(3)
            .any(|triple| triple == ["--ro-bind", &key, &key]),
        "{words:#?}"
    );
}

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

    let words = plan(&denying_writes(&[&work], &[&env]));

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

    let words = plan(&config);

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
    let words = plan(&denying_writes(&["/"], &[&env]));

    let root = bind_at(&words, "/");
    let pin = mount_at(&words, "--ro-bind", &at(&tree, "work/a"));
    let cover = bind_at(&words, &top);
    assert!(root < pin && pin < cover, "{words:#?}");
}

/// A path that is not there is bound at its first missing component, and that
/// component is made on the host by bwrap, so the plan is to remove it.
#[test]
fn an_absent_path_gets_a_host_mount_point() {
    let tree = Tree::empty("fs-deny-write-absent");
    tree.dir("work/.git");
    let (work, hooks) = (at(&tree, "work"), at(&tree, "work/.git/hooks"));
    let mount_point = tree.root().join("work/.git/hooks");

    let plan = Plan::build(&denying_writes(&[&work], &[&hooks])).expect("the config resolves");

    let words: Vec<_> = plan.words().iter().map(|w| w.to_string_lossy()).collect();
    let at = words
        .windows(3)
        .position(|triple| triple == ["--ro-bind", "/dev/null", &*mount_point.to_string_lossy()]);
    assert!(at.is_some(), "{words:#?}");
    assert_eq!(plan.mount_points(), [mount_point]);
}

/// A component with a deny beneath it is an empty directory, which stays
/// traversable, and a deny of the component itself shares the mount point.
#[test]
fn a_component_with_a_deny_beneath_it_is_an_empty_directory() {
    let tree = Tree::empty("fs-deny-write-component");
    tree.dir("work");
    let (work, claude, commands) = (
        at(&tree, "work"),
        at(&tree, "work/.claude"),
        at(&tree, "work/.claude/commands"),
    );

    let plan = Plan::build(&denying_writes(&[&work], &[&claude, &commands])).expect("a plan");

    let words: Vec<_> = plan.words().iter().map(|w| w.to_string_lossy()).collect();
    let at = words
        .windows(3)
        .position(|triple| triple[0] == "--ro-bind" && triple[2] == claude)
        .expect("a bind at the first missing component");
    assert_ne!(words[at + 1], "/dev/null", "{words:#?}");
    assert_eq!(
        words.iter().filter(|word| **word == claude).count(),
        // The bind's dest and the empty directory's own read-only bind are not
        // this path; the pin of the source is under the temp directory.
        1,
        "{words:#?}"
    );
    assert_eq!(plan.mount_points(), [std::path::PathBuf::from(&claude)]);
}

/// bwrap leaves its mount points behind, so a plan removes the ones it is
/// still holding when it drops. Anything that has been written to is not the
/// empty file bwrap made, and stays.
#[test]
fn mount_points_are_removed_when_the_sandbox_drops() {
    let tree = Tree::empty("fs-deny-write-drop");
    tree.dir("work");
    let (work, made, written) = (
        at(&tree, "work"),
        tree.root().join("work/made"),
        tree.root().join("work/written"),
    );
    let plan = Plan::build(&denying_writes(
        &[&work],
        &[&made.to_string_lossy(), &written.to_string_lossy()],
    ))
    .expect("a plan");
    // What bwrap does when it runs.
    std::fs::write(&made, "").expect("a mount point");
    std::fs::write(&written, "kept").expect("a file");

    drop(plan);

    assert!(!made.exists());
    assert!(written.exists());
}

/// A mount point goes when the last plan holding it drops: removing it under a
/// bwrap that is still running detaches that one's bind.
#[test]
fn a_mount_point_outlives_the_first_of_two_sandboxes_to_drop() {
    let tree = Tree::empty("fs-deny-write-shared");
    tree.dir("work");
    let (work, made) = (at(&tree, "work"), tree.root().join("work/made"));
    let config = denying_writes(&[&work], &[&made.to_string_lossy()]);
    let first = Plan::build(&config).expect("a plan");
    let second = Plan::build(&config).expect("a plan");
    std::fs::write(&made, "").expect("a mount point");

    drop(first);
    assert!(made.exists());
    drop(second);
    assert!(!made.exists());
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

    let words = plan(&config);

    let deny = mount_at(&words, "--ro-bind", &dir);
    let again = words
        .windows(2)
        .rposition(|pair| pair == ["--tmpfs", &secret]);
    assert!(again.is_some_and(|at| deny < at), "{words:#?}");
}
