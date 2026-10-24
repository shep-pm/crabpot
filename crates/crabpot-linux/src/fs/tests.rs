use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use crabpot_core::PathError;
use crabpot_core::config::{Config, PathEntry};
use crabpot_core::paths::{PathBase, contains_glob_chars, normalize_path_for_sandbox};

use super::Draft;
use super::Plan;
use super::PlanError;
use super::allow_read;
use super::allow_write;
use super::deny_read;
use crate::support::Tree;

/// The name [`build`] makes the plan's working directory under, which is where
/// the mandatory denies the plan walks for land.
const CWD: &str = "cwd";

/// A tree's path, as a config would spell it.
fn at(tree: &Tree, path: &str) -> String {
    tree.root().join(path).to_string_lossy().into_owned()
}

/// What a relative path and a `~` are read against: a home directory and a
/// working directory inside the tree.
fn base(tree: &Tree) -> PathBase {
    PathBase::new(Some(at(tree, "home")), Some(at(tree, CWD)))
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
    allow_write::words(config, base, &mut Draft::default())
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
    allow_read::words(
        &reading_with(deny, allow, write),
        &PathBase::from_env(),
        &mut Draft::default(),
    )
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

/// The plan for `config`, read against the tree: a `~` against `tree/home`, a
/// relative entry against `tree/cwd`, and the mandatory denies walked for that
/// same directory. A plan of this process's own base would walk the directory
/// the test runner started in, which is no tree of the test's.
fn build(tree: &Tree, config: &Config) -> Plan {
    tree.dir(CWD);
    Plan::build_with(config, &base(tree)).expect("a plan")
}

/// A whole plan's words, as text: every mount `bwrap` is asked to make, in the
/// order it reads them.
fn plan(tree: &Tree, config: &Config) -> Vec<String> {
    build(tree, config)
        .words()
        .iter()
        .map(|word| word.to_string_lossy().into_owned())
        .collect()
}

/// The mounts a `denyRead` section's words make: each flag with the paths it
/// takes.
fn read_denies_of(words: &[String]) -> Vec<Vec<String>> {
    let mut mounts = Vec::new();
    let mut at = 0;
    while at < words.len() {
        let taken = match words[at].as_str() {
            "--tmpfs" => 2,
            "--ro-bind" | "--bind" => 3,
            word => panic!("{word} is no mount: {words:#?}"),
        };
        mounts.push(words[at..at + taken].to_vec());
        at += taken;
    }
    mounts
}

/// The mounts `denyRead` adds to what a config denying nothing adds. The paths
/// every sandbox denies on its own are in both, so they cancel out.
fn denied_words(entries: &[&str]) -> Vec<String> {
    let words = |entries: &[&str]| {
        deny_read::words(
            &denying(entries),
            &PathBase::from_env(),
            &mut Draft::default(),
        )
        .expect("a config")
        .iter()
        .map(|word| word.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
    };
    let own = read_denies_of(&words(&[]));
    read_denies_of(&words(entries))
        .into_iter()
        .filter(|mount| !own.contains(mount))
        .flatten()
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

/// A path that is not there is bound at its first missing component, and that
/// component is made on the host by bwrap, so the plan is to remove it.
#[test]
fn an_absent_path_gets_a_host_mount_point() {
    let tree = Tree::empty("fs-deny-write-absent");
    tree.dir("work/.git");
    let (work, hooks) = (at(&tree, "work"), at(&tree, "work/.git/hooks"));
    let mount_point = tree.root().join("work/.git/hooks");

    let plan = build(&tree, &denying_writes(&[&work], &[&hooks]));

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

    let plan = build(&tree, &denying_writes(&[&work], &[&claude, &commands]));

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
    let plan = build(
        &tree,
        &denying_writes(
            &[&work],
            &[&made.to_string_lossy(), &written.to_string_lossy()],
        ),
    );
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
    let first = build(&tree, &config);
    let second = build(&tree, &config);
    std::fs::write(&made, "").expect("a mount point");

    drop(first);
    assert!(made.exists());
    drop(second);
    assert!(!made.exists());
}

/// A plan built after bwrap made the first one's mount point finds the path
/// there, and holds it all the same.
#[test]
fn a_mount_point_that_exists_is_held_by_the_next_sandbox() {
    let tree = Tree::empty("fs-deny-write-existing");
    tree.dir("work");
    let (work, made) = (at(&tree, "work"), tree.root().join("work/made"));
    let config = denying_writes(&[&work], &[&made.to_string_lossy()]);
    let first = build(&tree, &config);
    std::fs::write(&made, "").expect("a mount point");
    let second = build(&tree, &config);

    drop(first);
    assert!(made.exists());
    assert_eq!(second.mount_points(), std::slice::from_ref(&made));
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

/// A mount point another sandbox holds as a directory above this one's is held
/// as well, or it is left behind with the second's inside it.
#[test]
fn a_mount_point_above_the_next_sandboxs_is_held_by_it() {
    let tree = Tree::empty("fs-deny-write-above");
    tree.dir("work");
    let (work, commands) = (at(&tree, "work"), at(&tree, "work/.claude/commands"));
    let claude = tree.root().join("work/.claude");
    let config = denying_writes(&[&work], &[&commands]);
    let first = build(&tree, &config);
    std::fs::create_dir(&claude).expect("a mount point");
    let second = build(&tree, &config);
    std::fs::create_dir(claude.join("commands")).expect("a mount point");

    drop(first);
    assert!(claude.exists());
    drop(second);
    assert!(!claude.exists());
}

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

/// The list the walk found below the working directory goes through the same
/// deny loop as the settings' own `denyWrite`: each path it names is bound
/// read-only, the directories carrying those paths are pinned so they cannot be
/// renamed away, and a name the walk never saw stays writable.
#[test]
fn the_walker_list_is_denied_for_write() {
    let tree = Tree::empty("fs-mandatory-walker");
    for name in [
        "repo/.git/hooks/pre-commit",
        "repo/.git/config",
        "repo/.git/HEAD",
        "tool/.bashrc",
        "notes.txt",
    ] {
        tree.file(&format!("cwd/{name}"), "x");
    }
    let work = at(&tree, "cwd");

    let words = plan(&tree, &denying_writes(&[&work], &[]));

    for name in ["repo/.git/hooks", "repo/.git/config", "tool/.bashrc"] {
        mount_at(&words, "--ro-bind", &at(&tree, &format!("cwd/{name}")));
    }
    for name in ["repo", "repo/.git", "tool"] {
        mount_at(&words, "--ro-bind", &at(&tree, &format!("cwd/{name}")));
    }
    let notes = at(&tree, "cwd/notes.txt");
    assert!(
        !words
            .windows(3)
            .any(|triple| triple == ["--ro-bind", &notes, &notes]),
        "a plain file the walk listed nothing under is nobody's deny: {words:#?}"
    );
}

/// Upstream's `readDenyEntries` adds `/etc/ssh/ssh_config.d` to every read
/// policy, and crabpot always has a read policy: `filesystem.disabled`, the one
/// setting that would drop it, is refused (ADR-0013). ssh refuses a config file
/// whose owner or mode looks wrong, and inside the sandbox every path sits over
/// a bind and looks that way. A host with no such directory mounts nothing over
/// it, as it mounts nothing over any deny of a path that is not there.
#[test]
fn ssh_config_d_is_always_hidden() {
    let tree = Tree::empty("fs-ssh-config-d");
    tree.dir("work");
    let work = at(&tree, "work");
    const SSH: &str = "/etc/ssh/ssh_config.d";
    let config = |deny: &[&str]| {
        let mut config = denying_writes(&[&work], &[]);
        config.filesystem.deny_read = deny
            .iter()
            .map(|entry| PathEntry::Spelled((*entry).to_owned()))
            .collect();
        config
    };

    // A settings file that denies nothing hides it as one naming it outright
    // does, and the mount is the read deny's own: a tmpfs over the directory.
    assert_eq!(plan(&tree, &config(&[])), plan(&tree, &config(&[SSH])));
    if let Some((located, is_dir)) = deny_read::locate(PathBuf::from(SSH)) {
        assert!(is_dir, "{SSH} is a directory wherever it is");
        mount_at(
            &plan(&tree, &config(&[])),
            "--tmpfs",
            &located.to_string_lossy(),
        );
    }
}

/// A deny the plan cannot spell is a deny it cannot mount, and a walk with no
/// directory to walk gives the plan no deny at all. Both are an error: the words
/// are what `exec` takes, and a plan that dropped a deny, or never went looking
/// for one, would run the command with the path open.
#[test]
fn a_walk_error_is_an_error_not_an_open_door() {
    let tree = Tree::empty("fs-mandatory-walk-error");
    tree.dir("cwd");
    tree.dir("work");

    let no_cwd = PathBase::new(Some(at(&tree, "home")), None);
    let Err(error) = Plan::build_with(&denying_writes(&[&at(&tree, "work")], &[]), &no_cwd) else {
        panic!("a plan with no working directory to walk built anyway");
    };
    assert_eq!(error, PlanError::Path(PathError::NoWorkingDirectory));

    // A directory name that is not text, holding a dangerous file: the deny is
    // the file, and it is the name above it that the plan cannot spell. A
    // filesystem that will not hold such a name is not this plan's business.
    let Some(holder) = unspellable_holder(&tree) else {
        return;
    };
    std::fs::write(holder.join(".bashrc"), "x").expect("a file");
    let base = PathBase::new(Some(at(&tree, "home")), Some(at(&tree, CWD)));
    let Err(error) = Plan::build_with(&denying_writes(&[&at(&tree, CWD)], &[]), &base) else {
        panic!("a plan that dropped the deny it cannot name built anyway");
    };
    assert!(matches!(error, PlanError::Unspellable { .. }), "{error}");
}

/// A directory under the tree's working directory whose name is not text, or
/// `None` where the filesystem will not hold one.
fn unspellable_holder(tree: &Tree) -> Option<PathBuf> {
    let odd = OsString::from_vec(b"odd-\xff".to_vec());
    let holder = tree.root().join(CWD).join(&odd);
    std::fs::create_dir_all(&holder).ok().map(|()| holder)
}
