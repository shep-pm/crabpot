//! A Windows volume in memory, for tests that run on any host.

use std::cell::Cell;
use std::collections::BTreeMap;

use super::{Disk, DiskError, Entry, Kind};

struct Node {
    /// The path as the disk spells it, `\` separated.
    spelled: String,
    kind: Kind,
    /// Where a link points, as a path to resolve.
    target: Option<String>,
}

/// Paths are matched without regard to case and to the separator, as NTFS and
/// the Win32 API do. `real_path` answers in the `\\?\` form Windows gives.
#[derive(Default)]
pub(super) struct FakeDisk {
    nodes: BTreeMap<String, Node>,
    probes: Cell<usize>,
    unreadable: Vec<String>,
}

fn key(path: &str) -> String {
    path.replace('/', "\\")
        .trim_end_matches('\\')
        .to_lowercase()
}

fn parent_of(path: &str) -> Option<&str> {
    path.rsplit_once('\\').map(|(parent, _)| parent)
}

impl FakeDisk {
    fn add(&mut self, path: &str, kind: Kind, target: Option<&str>) {
        let spelled = path.replace('/', "\\");
        let spelled = spelled.trim_end_matches('\\');
        if let Some(parent) = parent_of(spelled)
            && !parent.ends_with(':')
            && !self.nodes.contains_key(&key(parent))
        {
            self.add(parent, Kind::Dir, None);
        }
        self.nodes.insert(
            key(spelled),
            Node {
                spelled: spelled.to_owned(),
                kind,
                target: target.map(str::to_owned),
            },
        );
    }

    pub(super) fn dir(mut self, path: &str) -> Self {
        self.add(path, Kind::Dir, None);
        self
    }

    pub(super) fn file(mut self, path: &str) -> Self {
        self.add(path, Kind::File, None);
        self
    }

    /// A symlink, junction or 8.3 alias at `path` for `target`.
    pub(super) fn link(mut self, path: &str, target: &str) -> Self {
        self.add(path, Kind::Link, Some(target));
        self
    }

    /// A directory that exists and cannot be listed or resolved.
    pub(super) fn unreadable(mut self, path: &str) -> Self {
        self.add(path, Kind::Dir, None);
        self.unreadable.push(key(path));
        self
    }

    /// How many times the disk was asked anything.
    pub(super) fn probes(&self) -> usize {
        self.probes.get()
    }

    fn resolve(&self, path: &str) -> Result<String, DiskError> {
        let path = path.replace('/', "\\");
        let mut parts = path.trim_end_matches('\\').split('\\');
        let mut real = parts.next().unwrap_or_default().to_uppercase();
        for part in parts.filter(|part| !part.is_empty()) {
            let at = format!("{real}\\{part}");
            if self.unreadable.contains(&key(&at)) {
                return Err(DiskError::Other("PermissionDenied".to_owned()));
            }
            let node = self.nodes.get(&key(&at)).ok_or(DiskError::Absent)?;
            real = match &node.target {
                Some(target) => self.resolve(target)?,
                None => node.spelled.clone(),
            };
        }
        Ok(real)
    }
}

impl Disk for FakeDisk {
    fn real_path(&self, path: &str) -> Result<String, DiskError> {
        self.probes.set(self.probes.get() + 1);
        self.resolve(path).map(|real| format!(r"\\?\{real}"))
    }

    fn exists(&self, path: &str) -> bool {
        self.probes.set(self.probes.get() + 1);
        !matches!(self.resolve(path), Err(DiskError::Absent))
    }

    fn lstat(&self, path: &str) -> Result<Kind, DiskError> {
        self.probes.set(self.probes.get() + 1);
        let path = path.replace('/', "\\");
        let parent = parent_of(&path).map_or(Ok(String::new()), |parent| self.resolve(parent))?;
        let name = path.rsplit('\\').next().unwrap_or_default();
        self.nodes
            .get(&key(&format!("{parent}\\{name}")))
            .map(|node| node.kind)
            .ok_or(DiskError::Absent)
    }

    fn read_dir(&self, path: &str) -> Result<Vec<Entry>, DiskError> {
        self.probes.set(self.probes.get() + 1);
        let dir = self.resolve(path)?;
        if self
            .nodes
            .get(&key(&dir))
            .is_some_and(|n| n.kind != Kind::Dir)
        {
            return Err(DiskError::Absent);
        }
        Ok(self
            .nodes
            .values()
            .filter(|node| parent_of(&node.spelled).is_some_and(|p| key(p) == key(&dir)))
            .map(|node| Entry {
                name: node
                    .spelled
                    .rsplit('\\')
                    .next()
                    .unwrap_or_default()
                    .to_owned(),
                kind: node.kind,
            })
            .collect())
    }
}
