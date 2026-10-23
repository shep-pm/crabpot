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

fn words_of(config: &Config) -> Vec<String> {
    Plan::build(config)
        .expect("the config resolves")
        .words()
        .iter()
        .map(|word| word.to_string_lossy().into_owned())
        .collect()
}

/// The words `denyRead` adds to what a config denying nothing has.
fn denied_words(entries: &[&str]) -> Vec<String> {
    let nothing = words_of(&denying(&[])).len();
    words_of(&denying(entries)).split_off(nothing)
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
