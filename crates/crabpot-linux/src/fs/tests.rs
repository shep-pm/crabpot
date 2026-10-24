//! The plan's cases, and the helpers every one of them uses.
//!
//! Every case builds a plan for a config over one `Tree` and reads the words
//! back, so the helpers that make a tree, a config, and a plan are here, and
//! each file under this one holds the cases for one part of the plan: a section
//! of `super`, or the pins and mount points that come out of them. The cases
//! here are the ones about the plan as a whole: what a walk of the working
//! directory adds to it, what it hides whatever the settings say, and what it
//! refuses to be.
//!
//! A file under this one is named for the part it covers, so it shares the name
//! of a section module. The helpers here reach a section by full path
//! (`crate::fs::deny_read`) rather than by importing it, which a name of this
//! module's own would hide.

use super::{Draft, Plan, PlanError};
use crate::support::Tree;
use crabpot_core::PathError;
use crabpot_core::config::{Config, PathEntry};
use crabpot_core::paths::PathBase;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

mod allow_read;
mod allow_write;
mod deny_read;
mod deny_write;
mod mount_points;
mod pins;

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
    crate::fs::allow_write::words(config, base, &mut Draft::default())
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
    crate::fs::allow_read::words(
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
        crate::fs::deny_read::words(
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
    if let Some((located, is_dir)) = crate::fs::deny_read::locate(PathBuf::from(SSH)) {
        assert!(is_dir, "{SSH} is a directory wherever it is");
        mount_at(
            &plan(&tree, &config(&[])),
            "--tmpfs",
            &located.to_string_lossy(),
        );
    }
}

/// The always-hidden directory stays hidden when `allowRead` re-opens a
/// directory above it, or re-opens it outright under a denied ancestor: the
/// reopening is a restore inside the mask the plan made for the directory above
/// the denial, and the denial is mounted again over it. A reopening at the
/// denial itself, where the plan made that denial's mount on its own, is the
/// exception, and the host's own directory comes back.
#[test]
fn ssh_config_d_stays_hidden_under_a_reopening() {
    const SSH: &str = "/etc/ssh/ssh_config.d";
    const SSH_PARENT: &str = "/etc/ssh";
    let Some((denial, true)) = crate::fs::deny_read::locate(PathBuf::from(SSH)) else {
        return; // This host has no such directory, so it has nothing to hide.
    };
    let denial = denial.to_string_lossy().into_owned();
    let reopened = crate::fs::deny_read::locate(PathBuf::from(SSH_PARENT))
        .map(|(path, _)| path.to_string_lossy().into_owned())
        .expect("/etc/ssh is there wherever /etc/ssh/ssh_config.d is");

    let tree = Tree::empty("fs-ssh-config-d-reopening");
    tree.dir("work");
    let work = at(&tree, "work");
    let plan_of = |deny: &[&str], allow: &[&str]| plan(&tree, &reading_with(deny, allow, &[&work]));
    let masked_last = |words: &[String]| {
        words
            .windows(2)
            .rposition(|pair| pair == ["--tmpfs", denial.as_str()])
            .unwrap_or_else(|| panic!("no --tmpfs {denial} in the plan: {words:#?}"))
    };

    // A reopening of the directory above it: the mask follows the bind that
    // brought the host's directory back.
    let words = plan_of(&["/etc"], &[SSH_PARENT]);
    let reopened_at = bound_back_at(&words, &reopened);
    let masked = masked_last(&words);
    assert!(
        reopened_at < masked,
        "a reopening of {SSH_PARENT} left {SSH} the host's own: {words:#?}"
    );

    // The same reopening, naming the denial outright under a denied ancestor.
    let words = plan_of(&["/etc"], &[SSH]);
    let reopened_at = bound_back_at(&words, &denial);
    let masked = masked_last(&words);
    assert!(
        reopened_at < masked,
        "an allow of {SSH} under a denied {SSH_PARENT} dropped the denial: {words:#?}"
    );

    // Nothing above it denied: the reopening is the restore inside the denial's
    // own mount, and the host's directory comes back read-only.
    let words = plan_of(&[], &[SSH]);
    let reopened_at = bound_back_at(&words, &denial);
    let masked = masked_last(&words);
    assert!(
        masked < reopened_at,
        "{SSH} was masked after the allow that names it: {words:#?}"
    );
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
