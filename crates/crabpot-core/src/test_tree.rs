//! The directory tree the path tests run on, laid out as upstream's tables were
//! generated on it. Spellings in a table write `{root}` for its root.

use std::{env, fs, os::unix::fs::symlink, path::Path};

use crate::path::PathBase;

/// A tree under the temp directory, removed when it drops. `home` is the home
/// directory of its [`PathBase`], and `cwd` the working directory.
///
/// ```text
/// real/file.txt         real/sub/a[b/inner.txt    a[b/file
/// link -> real          up -> .                   across -> real/sub
/// rootlink -> /         dangling -> missing       loop -> loop
/// dang[1] -> missing    real/sub/lnk[1] -> a[b
/// cwd/inside/           cwd/a[b/                  cwd/rel -> ../real
/// home/.cfg             home/.aws/
/// ```
#[derive(Debug)]
pub(crate) struct Tree {
    root: String,
}

impl Tree {
    /// A tree of its own, named for the test that holds it.
    pub(crate) fn new(test: &str) -> Self {
        let temp = fs::canonicalize(env::temp_dir()).expect("the temp directory is there");
        let root = temp.join(format!("crabpot-core-{test}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let file = |path: &str| {
            let at = root.join(path);
            fs::create_dir_all(at.parent().expect("a file has a parent")).expect("a parent");
            fs::write(at, "").expect("a file");
        };
        let dir = |path: &str| fs::create_dir_all(root.join(path)).expect("a directory");
        let link = |target: &str, path: &str| {
            symlink(target, root.join(path)).expect("a symbolic link");
        };
        file("real/file.txt");
        file("real/sub/a[b/inner.txt");
        file("a[b/file");
        file("home/.cfg");
        dir("cwd/inside");
        dir("cwd/a[b");
        dir("home/.aws");
        link("real", "link");
        link(".", "up");
        link("real/sub", "across");
        link("/", "rootlink");
        link("missing", "dangling");
        link("loop", "loop");
        link("../real", "cwd/rel");
        link("a[b", "real/sub/lnk[1]");
        link("missing", "dang[1]");
        Self {
            root: root.into_os_string().into_string().expect("a UTF-8 root"),
        }
    }

    /// What a relative path and `~` are read against.
    pub(crate) fn base(&self) -> PathBase {
        PathBase::new(
            Some(format!("{}/home", self.root)),
            Some(format!("{}/cwd", self.root)),
        )
    }

    /// `spelling` with the tree's root where it writes `{root}`.
    pub(crate) fn spell(&self, spelling: &str) -> String {
        spelling.replace("{root}", &self.root)
    }

    /// `path` with `{root}` where it holds the tree's root.
    pub(crate) fn unspell(&self, path: &str) -> String {
        path.replace(&self.root, "{root}")
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(Path::new(&self.root));
    }
}
