//! The host paths bwrap makes for a plan's denies, and their removal.
//!
//! Upstream's `bwrapMountPoints`, `cleanupBwrapMountPoints` and
//! `ensureEmptyMountSourceDir`. A deny on a path that is not there is a bind
//! over it, and bwrap makes the file or directory to bind on first, in the
//! host's own tree. Those stay after bwrap exits, so the plan that asked for
//! them takes them away when it drops, where they are still the empty file or
//! directory bwrap made.
//!
//! A mount point is shared by every sandbox of the process that asked for it:
//! removing it while another bwrap runs detaches that one's bind, and its deny
//! stops applying. So it goes only when the last plan holding it drops.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};

/// How many plans of this process hold each mount point.
static HELD: Mutex<BTreeMap<PathBuf, usize>> = Mutex::new(BTreeMap::new());

/// Names the empty directories of this process apart.
static EMPTY_DIRECTORIES: AtomicUsize = AtomicUsize::new(0);

/// The mount points one plan asked bwrap for.
#[derive(Debug, Default)]
pub struct MountPoints {
    paths: Vec<PathBuf>,
    empty_source: Option<PathBuf>,
}

impl MountPoints {
    /// The paths bwrap is to make.
    #[must_use]
    pub fn paths(&self) -> &[PathBuf] {
        &self.paths
    }

    /// Holds `path` for as long as this value lives. Held once, however often
    /// it is asked for.
    pub(super) fn hold(&mut self, path: PathBuf) {
        if self.paths.contains(&path) {
            return;
        }
        *HELD
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(path.clone())
            .or_default() += 1;
        self.paths.push(path);
    }

    /// The empty directory a directory mount point is bound from, made on first
    /// use. It is private to this plan, and the plan pins it read-only inside
    /// the sandbox.
    ///
    /// # Errors
    ///
    /// [`io::Error`] when the directory cannot be made.
    pub(super) fn empty_source(&mut self) -> io::Result<&Path> {
        match &mut self.empty_source {
            Some(path) => Ok(path.as_path()),
            slot => Ok(slot.insert(make_empty_directory()?).as_path()),
        }
    }
}

impl Drop for MountPoints {
    fn drop(&mut self) {
        let mut held = HELD.lock().unwrap_or_else(PoisonError::into_inner);
        // Deepest first: a directory goes only when it is empty.
        let mut paths = core::mem::take(&mut self.paths);
        paths.sort_by_key(|path| core::cmp::Reverse(path.components().count()));
        for path in paths {
            let last = match held.get_mut(&path) {
                Some(count) if *count > 1 => {
                    *count -= 1;
                    false
                }
                _ => {
                    held.remove(&path);
                    true
                }
            };
            if last {
                remove_if_empty(&path);
            }
        }
        if let Some(source) = self.empty_source.take() {
            remove_if_empty(&source);
        }
    }
}

/// Removes `path` when it is still the empty file or directory bwrap made.
/// Anything else is somebody's, and is left. A link is never followed.
fn remove_if_empty(path: &Path) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    // Only a failure to remove is possible here, and it leaves what is there.
    let _ = if metadata.is_file() && metadata.len() == 0 {
        fs::remove_file(path)
    } else if metadata.is_dir() {
        fs::remove_dir(path)
    } else {
        Ok(())
    };
}

fn make_empty_directory() -> io::Result<PathBuf> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    loop {
        let path = std::env::temp_dir().join(format!(
            "crabpot-empty-{}-{}",
            std::process::id(),
            EMPTY_DIRECTORIES.fetch_add(1, Ordering::Relaxed)
        ));
        match builder.create(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
}
