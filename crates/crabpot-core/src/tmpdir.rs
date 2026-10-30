//! The folder a sandboxed command's `TMPDIR` names, made before the command
//! runs.
//!
//! Upstream leaves making it to the host. Only the last folder is made: a
//! missing parent is a host that has not set the sandbox up.

use core::fmt;
use std::fs::{self, DirBuilder, Metadata};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};

use nix::unistd::geteuid;

/// The folder cannot be used as a temp folder.
// `#[non_exhaustive]`: a library error enum, and a check on the folder may be
// added without a new major version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TmpdirError {
    /// The path is relative, or starts with `~`, which the child and the
    /// grant would each read against a different base.
    NotAbsolute,
    /// The folder is missing and so is its parent.
    MissingParent,
    /// The path is a symbolic link, whatever it points at.
    Link,
    /// The path is there and is not a folder.
    NotADirectory,
    /// The folder belongs to a user other than the one running this process.
    OtherOwner,
    /// The folder could not be looked at or made, for the reason given.
    Io(io::ErrorKind),
}

impl fmt::Display for TmpdirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAbsolute => f.write_str("the temp folder is not an absolute path"),
            Self::MissingParent => f.write_str("the temp folder's parent is missing"),
            Self::Link => f.write_str("the temp folder is a symbolic link"),
            Self::NotADirectory => f.write_str("the temp folder is not a folder"),
            Self::OtherOwner => f.write_str("the temp folder belongs to another user"),
            Self::Io(kind) => write!(f, "cannot use the temp folder: {kind}"),
        }
    }
}

impl core::error::Error for TmpdirError {}

/// Who named the folder a command's `TMPDIR` is set to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// The host set `CLAUDE_CODE_TMPDIR` or `CLAUDE_TMPDIR`.
    Host,
    /// Neither is set, so the folder is the default `/tmp/claude`.
    Default,
}

/// Makes `path` when it is missing, owner-only (mode 0700).
///
/// A folder that is there and belongs to this user is kept as it is, mode
/// included. The default folder of another user is kept too, as upstream does:
/// the command may not write it, and a shared host can still run.
///
/// # Errors
///
/// [`TmpdirError::NotAbsolute`] when the path is relative,
/// [`TmpdirError::MissingParent`] when the folder and its parent are both
/// missing, [`TmpdirError::Link`] when the path is a link,
/// [`TmpdirError::NotADirectory`] when it is a file, [`TmpdirError::OtherOwner`]
/// when another user owns a folder `origin` says the host named, and [`TmpdirError::Io`] for any other
/// failure.
pub fn prepare(path: &Path, origin: Origin) -> Result<(), TmpdirError> {
    // A trailing `/` or `/.` makes the kernel follow a final link, which
    // `symlink_metadata` would otherwise report as one.
    if !path.is_absolute() {
        return Err(TmpdirError::NotAbsolute);
    }
    let path: PathBuf = path.components().collect();
    let path = path.as_path();
    match fs::symlink_metadata(path) {
        Ok(found) => check(&found, origin),
        Err(error) if error.kind() == io::ErrorKind::NotFound => make(path, origin),
        Err(error) => Err(TmpdirError::Io(error.kind())),
    }
}

/// Makes the last folder of `path`, and looks at what is there instead when a
/// racing process made it first.
fn make(path: &Path, origin: Origin) -> Result<(), TmpdirError> {
    match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => Ok(()),
        Err(error) => match error.kind() {
            io::ErrorKind::NotFound => Err(TmpdirError::MissingParent),
            io::ErrorKind::AlreadyExists => fs::symlink_metadata(path)
                .map_err(|error| TmpdirError::Io(error.kind()))
                .and_then(|found| check(&found, origin)),
            kind => Err(TmpdirError::Io(kind)),
        },
    }
}

/// Whether what is at the path is a folder this user owns, or a default folder
/// of any owner.
fn check(found: &Metadata, origin: Origin) -> Result<(), TmpdirError> {
    if found.file_type().is_symlink() {
        Err(TmpdirError::Link)
    } else if !found.is_dir() {
        Err(TmpdirError::NotADirectory)
    } else if origin == Origin::Host && found.uid() != geteuid().as_raw() {
        Err(TmpdirError::OtherOwner)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;

    use super::*;

    /// A folder of its own under the temp folder, removed when it drops.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(test: &str) -> Self {
            let root = std::env::temp_dir()
                .join(format!("crabpot-core-tmpdir-{test}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).unwrap();
            Self(root)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn a_missing_folder_is_made_owner_only() {
        let scratch = Scratch::new("made");
        let folder = scratch.0.join("claude");

        assert_eq!(prepare(&folder, Origin::Host), Ok(()));

        assert!(folder.is_dir());
        assert_eq!(mode(&folder), 0o700);
    }

    #[test]
    fn an_existing_folder_this_user_owns_is_kept() {
        let scratch = Scratch::new("kept");
        let folder = scratch.0.join("claude");
        fs::create_dir(&folder).unwrap();
        fs::set_permissions(&folder, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(folder.join("left-by-the-host"), "").unwrap();

        assert_eq!(prepare(&folder, Origin::Host), Ok(()));

        assert_eq!(mode(&folder), 0o755);
        assert!(folder.join("left-by-the-host").exists());
    }

    #[test]
    fn a_missing_parent_is_refused() {
        let scratch = Scratch::new("parent");
        let parent = scratch.0.join("absent");

        assert_eq!(
            prepare(&parent.join("claude"), Origin::Host),
            Err(TmpdirError::MissingParent)
        );

        assert!(!parent.exists());
    }

    #[test]
    fn a_link_is_refused() {
        let scratch = Scratch::new("link");
        let target = scratch.0.join("target");
        fs::create_dir(&target).unwrap();
        let link = scratch.0.join("claude");
        symlink(&target, &link).unwrap();

        assert_eq!(prepare(&link, Origin::Host), Err(TmpdirError::Link));
    }

    #[test]
    fn a_link_with_a_trailing_slash_is_refused() {
        let scratch = Scratch::new("link-slash");
        let target = scratch.0.join("target");
        fs::create_dir(&target).unwrap();
        let link = scratch.0.join("claude");
        symlink(&target, &link).unwrap();

        assert_eq!(
            prepare(&scratch.0.join("claude/"), Origin::Host),
            Err(TmpdirError::Link)
        );
        assert_eq!(
            prepare(&scratch.0.join("claude/."), Origin::Host),
            Err(TmpdirError::Link)
        );
    }

    #[test]
    fn a_file_is_refused() {
        let scratch = Scratch::new("file");
        let file = scratch.0.join("claude");
        fs::write(&file, "").unwrap();

        assert_eq!(
            prepare(&file, Origin::Host),
            Err(TmpdirError::NotADirectory)
        );
    }

    #[test]
    fn a_folder_another_user_owns_is_refused() {
        if geteuid().is_root() {
            return;
        }

        assert_eq!(
            prepare(Path::new("/"), Origin::Host),
            Err(TmpdirError::OtherOwner)
        );
    }

    #[test]
    fn a_relative_tmpdir_is_refused() {
        for relative in ["claude", "./claude", "~/claude", ""] {
            assert_eq!(
                prepare(Path::new(relative), Origin::Host),
                Err(TmpdirError::NotAbsolute),
                "{relative}"
            );
        }
        assert!(!Path::new("claude").exists());
    }

    #[test]
    fn the_default_folder_another_user_owns_is_accepted() {
        if geteuid().is_root() {
            return;
        }

        assert_eq!(prepare(Path::new("/"), Origin::Default), Ok(()));
    }

    #[test]
    fn the_default_folder_is_refused_as_a_link() {
        let scratch = Scratch::new("default-link");
        let target = scratch.0.join("target");
        fs::create_dir(&target).unwrap();
        let link = scratch.0.join("claude");
        symlink(&target, &link).unwrap();

        assert_eq!(prepare(&link, Origin::Default), Err(TmpdirError::Link));
    }
}
