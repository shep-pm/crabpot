//! The fixture tree, built on disk for the test that holds it.

use std::{
    env, fs,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
};

const TREE: &str = include_str!("../fixtures/tree.txt");

/// A directory under the temp directory, removed when it drops.
#[derive(Debug)]
pub struct Tree {
    root: PathBuf,
}

impl Tree {
    /// An empty directory of its own, named for the test that holds it. Its
    /// path has no symbolic link in it, as the walk expects of a working
    /// directory.
    pub fn empty(test: &str) -> Self {
        let temp = fs::canonicalize(env::temp_dir()).expect("the temp directory is there");
        let root = temp.join(format!("crabpot-linux-{test}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("a root");
        Self { root }
    }

    /// The fixture tree of `tests/fixtures/tree.txt`.
    pub fn fixture(test: &str) -> Self {
        let tree = Self::empty(test);
        for line in TREE
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            if let Some((path, target)) = line.split_once(" -> ") {
                tree.link(target, path);
            } else if let Some((path, text)) = line.split_once(" = ") {
                tree.file(path, text);
            } else if let Some(path) = line.strip_suffix('/') {
                tree.dir(path);
            } else {
                tree.file(line, "");
            }
        }
        tree
    }

    /// The root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// A directory, and the ones above it.
    pub fn dir(&self, path: &str) {
        fs::create_dir_all(self.root.join(path)).expect("a directory");
    }

    /// A file, and the directories above it.
    pub fn file(&self, path: &str, text: &str) {
        let at = self.root.join(path);
        fs::create_dir_all(at.parent().expect("a file has a parent")).expect("a parent");
        fs::write(at, text).expect("a file");
    }

    /// A symbolic link at `path` to `target`, with the directories above it.
    pub fn link(&self, target: &str, path: &str) {
        let at = self.root.join(path);
        fs::create_dir_all(at.parent().expect("a link has a parent")).expect("a parent");
        symlink(target, at).expect("a symbolic link");
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        // A test that made a directory unreadable must not leave it so.
        restore_modes(&self.root);
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn restore_modes(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o755));
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            restore_modes(&entry.path());
        }
    }
}
