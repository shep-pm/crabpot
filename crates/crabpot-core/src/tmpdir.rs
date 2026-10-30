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
            Self::MissingParent => f.write_str("the temp folder's parent is missing"),
            Self::Link => f.write_str("the temp folder is a symbolic link"),
            Self::NotADirectory => f.write_str("the temp folder is not a folder"),
            Self::OtherOwner => f.write_str("the temp folder belongs to another user"),
            Self::Io(kind) => write!(f, "cannot use the temp folder: {kind}"),
        }
    }
}

impl core::error::Error for TmpdirError {}

/// Makes `path` when it is missing, owner-only (mode 0700).
///
/// A folder that is there and belongs to this user is kept as it is, mode
/// included.
///
/// # Errors
///
/// [`TmpdirError::MissingParent`] when the folder and its parent are both
/// missing, [`TmpdirError::Link`] when the path is a link,
/// [`TmpdirError::NotADirectory`] when it is a file, [`TmpdirError::OtherOwner`]
/// when another user owns the folder, and [`TmpdirError::Io`] for any other
/// failure.
pub fn prepare(path: &Path) -> Result<(), TmpdirError> {
    // A trailing `/` or `/.` makes the kernel follow a final link, which
    // `symlink_metadata` would otherwise report as one.
    let path: PathBuf = path.components().collect();
    let path = path.as_path();
    match fs::symlink_metadata(path) {
        Ok(found) => check(&found),
        Err(error) if error.kind() == io::ErrorKind::NotFound => make(path),
        Err(error) => Err(TmpdirError::Io(error.kind())),
    }
}

/// Makes the last folder of `path`, and looks at what is there instead when a
/// racing process made it first.
fn make(path: &Path) -> Result<(), TmpdirError> {
    match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => Ok(()),
        Err(error) => match error.kind() {
            io::ErrorKind::NotFound => Err(TmpdirError::MissingParent),
            io::ErrorKind::AlreadyExists => fs::symlink_metadata(path)
                .map_err(|error| TmpdirError::Io(error.kind()))
                .and_then(|found| check(&found)),
            kind => Err(TmpdirError::Io(kind)),
        },
    }
}

/// Whether what is at the path is a folder this user owns.
fn check(found: &Metadata) -> Result<(), TmpdirError> {
    if found.file_type().is_symlink() {
        Err(TmpdirError::Link)
    } else if !found.is_dir() {
        Err(TmpdirError::NotADirectory)
    } else if found.uid() != geteuid().as_raw() {
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

        assert_eq!(prepare(&folder), Ok(()));

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

        assert_eq!(prepare(&folder), Ok(()));

        assert_eq!(mode(&folder), 0o755);
        assert!(folder.join("left-by-the-host").exists());
    }

    #[test]
    fn a_missing_parent_is_refused() {
        let scratch = Scratch::new("parent");
        let parent = scratch.0.join("absent");

        assert_eq!(
            prepare(&parent.join("claude")),
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

        assert_eq!(prepare(&link), Err(TmpdirError::Link));
    }

    #[test]
    fn a_link_with_a_trailing_slash_is_refused() {
        let scratch = Scratch::new("link-slash");
        let target = scratch.0.join("target");
        fs::create_dir(&target).unwrap();
        let link = scratch.0.join("claude");
        symlink(&target, &link).unwrap();

        assert_eq!(prepare(&scratch.0.join("claude/")), Err(TmpdirError::Link));
        assert_eq!(prepare(&scratch.0.join("claude/.")), Err(TmpdirError::Link));
    }

    #[test]
    fn a_file_is_refused() {
        let scratch = Scratch::new("file");
        let file = scratch.0.join("claude");
        fs::write(&file, "").unwrap();

        assert_eq!(prepare(&file), Err(TmpdirError::NotADirectory));
    }

    #[test]
    fn a_folder_another_user_owns_is_refused() {
        if geteuid().is_root() {
            return;
        }

        assert_eq!(prepare(Path::new("/")), Err(TmpdirError::OtherOwner));
    }
}
