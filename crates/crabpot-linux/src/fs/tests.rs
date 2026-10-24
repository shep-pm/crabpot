use std::fs;
use std::path::PathBuf;

use super::*;

/// A tree under the temp directory, removed when it drops.
struct Tree {
    root: PathBuf,
}

impl Tree {
    fn new(test: &str) -> Self {
        let temp = fs::canonicalize(std::env::temp_dir()).expect("the temp directory is there");
        let root = temp.join(format!("crabpot-linux-fs-{test}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("a root");
        Self { root }
    }

    fn dir(&self, path: &str) -> String {
        fs::create_dir_all(self.root.join(path)).expect("a directory");
        self.at(path)
    }

    fn file(&self, path: &str) -> String {
        let at = self.root.join(path);
        fs::create_dir_all(at.parent().expect("a file has a parent")).expect("a parent");
        fs::write(at, "").expect("a file");
        self.at(path)
    }

    #[cfg(unix)]
    fn link(&self, target: &str, path: &str) -> String {
        let at = self.root.join(path);
        fs::create_dir_all(at.parent().expect("a link has a parent")).expect("a parent");
        std::os::unix::fs::symlink(self.at(target), &at).expect("a link");
        self.at(path)
    }

    fn at(&self, path: &str) -> String {
        self.root
            .join(path)
            .to_str()
            .expect("a UTF-8 root")
            .to_owned()
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// A config whose read settings are `denyRead` and `allowRead`.
fn reading(deny: &[&str], allow: &[&str]) -> Config {
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
                "allowWrite": [], "denyWrite": []
            }}
        }}"#,
        list(deny),
        list(allow)
    ))
    .expect("a config")
}

fn words_of(config: &Config) -> Vec<String> {
    Plan::build(config)
        .expect("the config resolves")
        .words()
        .iter()
        .map(|word| word.to_string_lossy().into_owned())
        .collect()
}

/// The words `denyRead` and `allowRead` add to what a config denying nothing
/// has.
fn read_words(deny: &[&str], allow: &[&str]) -> Vec<String> {
    let nothing = words_of(&reading(&[], &[])).len();
    words_of(&reading(deny, allow)).split_off(nothing)
}

/// The words `denyRead` adds to what a config denying nothing has.
fn denied_words(entries: &[&str]) -> Vec<String> {
    read_words(entries, &[])
}

#[test]
fn a_denied_directory_becomes_a_tmpfs() {
    let tree = Tree::new("directory");
    let secrets = tree.dir("secrets");
    tree.file("secrets/key");

    assert_eq!(denied_words(&[&secrets]), ["--tmpfs", &secrets]);
}

#[test]
fn a_denied_file_is_bound_from_dev_null() {
    let tree = Tree::new("file");
    let key = tree.file("key");

    assert_eq!(denied_words(&[&key]), ["--ro-bind", "/dev/null", &key]);
}

#[test]
fn a_missing_denied_path_is_skipped() {
    let tree = Tree::new("missing");

    assert_eq!(denied_words(&[&tree.at("nowhere")]), Vec::<String>::new());
}

#[test]
fn what_is_beneath_a_denied_directory_is_left_to_its_tmpfs() {
    let tree = Tree::new("nested");
    let secrets = tree.dir("secrets");
    let key = tree.file("secrets/deeper/key");

    assert_eq!(denied_words(&[&key, &secrets]), ["--tmpfs", &secrets]);
}

#[test]
fn a_glob_expands_to_the_paths_on_disk() {
    let tree = Tree::new("glob");
    let top = tree.file("top.key");
    let nested = tree.file("a/b/y.key");
    tree.file("a/notes.txt");
    let pattern = tree.at("**/*.key");

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
    let tree = Tree::new("no-match");
    tree.file("a/notes.txt");
    let pattern = tree.at("**/*.key");

    assert_eq!(denied_words(&[&pattern]), Vec::<String>::new());
}

#[test]
fn an_allowed_path_is_bound_back_over_a_tmpfs() {
    let tree = Tree::new("allow-back");
    let secrets = tree.dir("secrets");
    let ok = tree.file("secrets/ok.txt");

    assert_eq!(
        read_words(&[&secrets], &[&ok]),
        ["--tmpfs", &secrets, "--ro-bind", &ok, &ok]
    );
}

#[test]
fn an_allowed_path_outside_a_denial_adds_no_word() {
    let tree = Tree::new("allow-outside");
    let secrets = tree.dir("secrets");
    let open = tree.dir("open");

    assert_eq!(read_words(&[&secrets], &[&open]), ["--tmpfs", &secrets]);
}

#[test]
fn an_allow_glob_expands_on_disk() {
    let tree = Tree::new("allow-glob");
    let secrets = tree.dir("secrets");
    let txt = tree.file("secrets/a.txt");
    tree.file("secrets/b.log");
    let pattern = tree.at("secrets/*.txt");

    assert_eq!(
        read_words(&[&secrets], &[&pattern]),
        ["--tmpfs", &secrets, "--ro-bind", &txt, &txt]
    );
}

#[test]
fn a_nested_deny_stays_hidden_under_a_reopened_directory() {
    let tree = Tree::new("nested-deny-back");
    let secrets = tree.dir("secrets");
    let shared = tree.dir("secrets/shared");
    let key = tree.file("secrets/shared/key");

    assert_eq!(
        read_words(&[&secrets, &key], &[&shared]),
        [
            "--tmpfs",
            &secrets,
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
    let tree = Tree::new("late-carve");
    let secrets = tree.dir("secrets");
    let shared = tree.dir("secrets/shared");
    tree.file("secrets/shared/a");
    tree.file("secrets/key");
    let region = tree.at("secrets/**/*");

    assert_eq!(
        read_words(&[&secrets, &region], &[&shared]),
        ["--tmpfs", &secrets, "--ro-bind", &shared, &shared]
    );
}

#[test]
fn a_deny_glob_not_covering_a_reopened_directory_stays_masked() {
    let tree = Tree::new("late-leaf");
    let secrets = tree.dir("secrets");
    let shared = tree.dir("secrets/shared");
    let leaf = tree.file("secrets/shared/deeper.key");
    tree.file("secrets/key");
    let pattern = tree.at("secrets/**/*.key");

    assert_eq!(
        read_words(&[&secrets, &pattern], &[&shared]),
        [
            "--tmpfs",
            &secrets,
            "--ro-bind",
            &shared,
            &shared,
            "--ro-bind",
            "/dev/null",
            &leaf,
        ]
    );
}

#[cfg(unix)]
#[test]
fn a_symlink_match_of_an_allow_glob_reopens_nothing() {
    let tree = Tree::new("allow-glob-link");
    let secrets = tree.dir("secrets");
    tree.file("secrets/key");
    tree.link("secrets/key", "public/key.txt");
    let pattern = tree.at("public/*.txt");

    assert_eq!(read_words(&[&secrets], &[&pattern]), ["--tmpfs", &secrets]);
}

#[cfg(target_os = "linux")]
#[test]
fn a_path_in_the_kernels_proc_keeps_its_spelling() {
    assert_eq!(
        denied_words(&["/proc/self/environ"]),
        ["--ro-bind", "/dev/null", "/proc/self/environ"]
    );
}
