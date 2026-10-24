//! Which paths a Windows sandbox grants and denies, from the settings' lists.
//!
//! `srt-win` grants and denies by resolved path, so the lists are expanded and
//! ranked the way upstream does it: `expandWindowsFsPaths`,
//! `rankWindowsFsAccess`, `windowsGrantsBeneathDenies` and
//! `windowsProfileExclusionConflicts` of `src/sandbox/windows-sandbox-utils.ts`,
//! with the path rules of `src/sandbox/sandbox-utils.ts` they stand on.
//!
//! The result is one [`Access`], the shape `srt-win acl grant --persistent`
//! reads from stdin. Nothing here calls `srt-win`.
//!
//! The rules read text, and the disk through [`Disk`], so they compile and run
//! on every host. [`StdDisk`] is the disk of the host the process runs on.

mod disk;
mod exclusions;
mod expand;
#[cfg(test)]
mod fake;
mod rank;
mod spelling;
#[cfg(test)]
mod tests;
mod walk;

use std::env;

use serde::Serialize;

pub use disk::{Disk, DiskError, Entry, Kind, StdDisk};
pub use exclusions::{
    Conflict, ConflictOptions, ExclusionKind, ProfileGrant, Relation, profile_exclusion_conflicts,
};
pub use expand::{ExpandError, Mode, expand_paths};
pub use rank::{Held, Lists, Settings, access, grants_beneath_denies, rank};

use spelling::{is_unprobed, key_of, strip_extended_prefix};

/// What `srt-win` is handed: resolved paths to grant to the sandbox user and
/// to deny it. Serializes as `{"read":…,"write":…,"denyRead":…,"denyWrite":…}`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Access {
    /// Paths granted read and execute.
    pub read: Vec<String>,
    /// Paths granted modify, without deleting children.
    pub write: Vec<String>,
    /// Paths the sandbox user may not read.
    pub deny_read: Vec<String>,
    /// Paths the sandbox user may not write.
    pub deny_write: Vec<String>,
}

/// What a path is read against: the home directory, the working directory and
/// the disk.
#[derive(Clone, Debug)]
pub struct Host<D> {
    home: Option<String>,
    cwd: Option<String>,
    disk: D,
}

impl Host<StdDisk> {
    /// This process: `USERPROFILE`, which is what node's `os.homedir` reads on
    /// Windows, its working directory, and the disk of this host.
    pub fn from_process() -> Self {
        Self::new(
            env::var("USERPROFILE").ok().as_deref(),
            env::current_dir()
                .ok()
                .and_then(|cwd| cwd.into_os_string().into_string().ok())
                .as_deref(),
            StdDisk,
        )
    }
}

impl<D: Disk> Host<D> {
    /// A host with the given home directory, working directory and disk. Each
    /// is `None` when the host has none, which only a path that needs it
    /// notices.
    pub fn new(home: Option<&str>, cwd: Option<&str>, disk: D) -> Self {
        Self {
            home: home.map(str::to_owned),
            cwd: cwd.map(str::to_owned),
            disk,
        }
    }

    /// The disk the host reads.
    pub fn disk(&self) -> &D {
        &self.disk
    }

    fn home(&self) -> Result<&str, ExpandError> {
        self.home.as_deref().ok_or(ExpandError::NoHomeDirectory)
    }

    fn cwd(&self) -> Result<&str, ExpandError> {
        self.cwd.as_deref().ok_or(ExpandError::NoWorkingDirectory)
    }

    /// `resolveWindowsPath`: the one look at a path on disk that comparisons
    /// are made from.
    fn look(&self, path: &str) -> Look {
        if is_unprobed(path) {
            return Look::Unprobed;
        }
        match self.disk.real_path(path) {
            Ok(real) => Look::Resolved(strip_extended_prefix(&real)),
            Err(DiskError::Absent) => Look::Absent,
            Err(DiskError::Other(code)) => Look::Error(code),
        }
    }

    /// `windowsPathKey`: `path` for comparison with another, with links,
    /// junctions, 8.3 names and the case on disk resolved.
    fn key(&self, path: &str) -> String {
        key_from_look(path, &self.look(path))
    }
}

/// What the one look at a path on disk found.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Look {
    /// The object it names, with links, 8.3 names and case resolved.
    Resolved(String),
    /// Nothing is there, or a parent is not a directory.
    Absent,
    /// Not looked at: a share or a device.
    Unprobed,
    /// Looking failed for another reason; holds the reason.
    Error(String),
}

/// `windowsPathKeyOf`: [`Host::key`] from a look already taken.
fn key_from_look(path: &str, look: &Look) -> String {
    match look {
        Look::Resolved(real) => key_of(real),
        _ => key_of(path),
    }
}

/// An insertion-ordered set of paths, spelled as they came.
#[derive(Default)]
struct Ordered {
    seen: std::collections::HashSet<String>,
    items: Vec<String>,
}

impl Ordered {
    fn insert(&mut self, item: &str) {
        if self.seen.insert(item.to_owned()) {
            self.items.push(item.to_owned());
        }
    }

    fn extend<'a>(&mut self, items: impl IntoIterator<Item = &'a str>) {
        for item in items {
            self.insert(item);
        }
    }

    fn into_vec(self) -> Vec<String> {
        self.items
    }
}
