//! What `filesystem.denyWrite` takes back from the write binds: each denied
//! path bound over itself read-only, after every other mount that could undo it.
//!
//! The deny loop of upstream's `generateFilesystemArgs`. A deny is only worth
//! a bind where a write root covers the path, or lies beneath it: everywhere
//! else the root bind already holds it read-only. A path that is not there is
//! covered at its first missing component, by `/dev/null` or by an empty
//! directory, so the command cannot make it. bwrap makes that mount point on
//! the host, and the plan takes it away when it drops
//! ([`MountPoints`](super::MountPoints)).
//!
//! The binds come after `denyRead`'s, since a read mount over an ancestor
//! would otherwise wipe them. That puts them over a read mount of their own,
//! though: a deny bind of a directory that holds a read-denied path shows the
//! real contents again, so the read mount is made again after it. A deny
//! already under a read mount's tmpfs is left out, since a bind of the host's
//! path there would show what the tmpfs hides.
//!
//! A glob is no path: as in `allowWrite`, a write glob is dropped unless it is
//! also the name of a path.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::path::Path;

use crabpot_core::PathError;
use crabpot_core::config::Config;
use crabpot_core::paths::{
    ListKind, PathBase, dirname, is_at_or_under, normalize_path_for_sandbox, real_path_of,
    split_path_entries,
};

use super::allow_write::strip_write_globs;
use super::deny_read::Mount;
use super::{Draft, MountPoints};

pub(super) fn words(config: &Config, draft: &mut Draft) -> Result<Vec<OsString>, PathError> {
    let base = PathBase::from_env();
    let split = split_path_entries(&config.filesystem.deny_write);
    let mut spellings = strip_write_globs(&base, &split.spelled, ListKind::Deny)?;
    spellings.extend(split.marked.iter().map(|path| (*path).to_owned()));
    let mut raw = Vec::new();
    for spelling in &spellings {
        raw.push(normalize_path_for_sandbox(&base, spelling, true)?);
    }

    let mut plan = Plan {
        base: &base,
        roots: &draft.write_roots,
        mounts: &draft.read_mounts,
        mount_points: &mut draft.mount_points,
        seen: BTreeSet::new(),
        decided: BTreeSet::new(),
        ancestors: BTreeSet::new(),
        read_only_dirs: Vec::new(),
        binds: Vec::new(),
        empty_source: None,
    };
    plan.decide(&raw);
    let empty_source = plan.empty_source.clone();
    let (words, protected) = plan.emit();
    draft.protected.extend(protected);
    let mut words = words;
    if let Some(source) = empty_source {
        // The source of an empty directory is never writable inside the
        // sandbox: a write to it would land on the denied path it is bound to.
        // It follows the other mounts, to cover any write bind that holds it.
        words.extend(["--ro-bind", &source, &source].map(OsString::from));
    }
    Ok(words)
}

/// One bind to make: `source` over `dest`.
struct Bind {
    source: String,
    dest: String,
}

struct Plan<'a> {
    base: &'a PathBase,
    roots: &'a [String],
    mounts: &'a [Mount],
    mount_points: &'a mut MountPoints,
    /// Paths a deny has been made for, so two spellings of one make one bind.
    seen: BTreeSet<String>,
    /// The destinations of the mount points decided so far.
    decided: BTreeSet<String>,
    /// Every directory a deny path lies beneath, there or not.
    ancestors: BTreeSet<String>,
    /// Existing denied directories that are bound read-only: whatever lies
    /// strictly beneath one is unwritable, and bwrap could not make a mount
    /// point in it.
    read_only_dirs: Vec<String>,
    binds: Vec<Bind>,
    empty_source: Option<String>,
}

impl Plan<'_> {
    fn decide(&mut self, raw: &[String]) {
        let resolved: Vec<(&String, Option<String>)> = raw
            .iter()
            .filter(|path| !path.starts_with("/dev/"))
            .map(|path| (path, resolve_deny_path(self.base, path)))
            .collect();
        // The directories the loop below binds read-only, found before any
        // decision about a missing path so the order of the list does not matter.
        for path in resolved.iter().filter_map(|(_, path)| path.as_deref()) {
            let mut above = dirname(path);
            while above != "/" {
                self.ancestors.insert(above.to_owned());
                above = dirname(above);
            }
            if self.symlink_in_path(path).is_none()
                && fs::metadata(path).is_ok_and(|metadata| metadata.is_dir())
                && self.meets_write_root(path)
            {
                self.read_only_dirs.push(path.to_owned());
            }
        }
        for (raw, path) in resolved {
            let Some(path) = path else {
                // Where a write would land cannot be told: the link on the way is
                // masked, and bwrap refuses to start. Dropping the deny would run
                // the command with the path open.
                if let Some(link) = self.symlink_in_path(raw) {
                    self.mask_link(link);
                }
                continue;
            };
            if path.starts_with("/dev/") || !self.seen.insert(path.clone()) {
                continue;
            }
            // The path was resolved, but the tree may have changed since.
            if let Some(link) = self.symlink_in_path(&path) {
                self.mask_link(link);
                continue;
            }
            self.mount_points.hold_if_held(&path);
            if self.decided_over(&path).is_some() || !Path::new(&path).exists() {
                self.placeholder(&path);
            } else if self.meets_write_root(&path) && !self.under_read_only_dir(&path) {
                self.binds.push(Bind {
                    source: path.clone(),
                    dest: path,
                });
            }
        }
    }

    /// `/dev/null` over a symlink, which keeps it from being replaced.
    fn mask_link(&mut self, link: String) {
        if self.seen.insert(link.clone()) {
            self.binds.push(Bind {
                source: "/dev/null".to_owned(),
                dest: link,
            });
        }
    }

    /// The first component of `path` that is a symlink inside a write root.
    fn symlink_in_path(&self, path: &str) -> Option<String> {
        let mut current = String::new();
        for part in path.split('/').filter(|part| !part.is_empty()) {
            current = format!("{current}/{part}");
            let metadata = fs::symlink_metadata(&current).ok()?;
            if metadata.is_symlink() && self.within_write_root(&current) {
                return Some(current);
            }
        }
        None
    }

    fn within_write_root(&self, path: &str) -> bool {
        self.roots.iter().any(|root| is_at_or_under(path, root))
    }

    /// Whether a bind of `path` matters: a write root covers it, or lies beneath
    /// it and has its bind covered by the deny's.
    fn meets_write_root(&self, path: &str) -> bool {
        self.within_write_root(path)
            || self
                .roots
                .iter()
                .any(|root| strictly_under(root, path))
    }

    fn under_read_only_dir(&self, path: &str) -> bool {
        self.read_only_dirs
            .iter()
            .any(|dir| strictly_under(path, dir))
    }

    /// Whether a write root outside every read-only denied directory covers
    /// `path`. Any other is read-only already.
    fn within_writable_root(&self, path: &str) -> bool {
        self.roots.iter().any(|root| {
            is_at_or_under(path, root)
                && !self
                    .read_only_dirs
                    .iter()
                    .any(|dir| strictly_under(root, dir))
        })
    }

    fn decided_over(&self, path: &str) -> Option<&String> {
        self.decided
            .iter()
            .find(|decided| is_at_or_under(path, decided))
    }

    /// The mount point an absent deny path adds to the plan, if it adds one.
    ///
    /// Left out only where the command cannot make the path either; on any doubt
    /// it stays, and at worst bwrap cannot make its mount point and nothing
    /// starts, which loses no deny.
    fn placeholder(&mut self, absent: &str) {
        if self.decided_over(absent).is_some() {
            return;
        }
        if !self.within_writable_root(absent) || self.under_read_only_dir(absent) {
            return;
        }
        // Nothing can be made under a file (a worktree's `.git` is one), for as
        // long as it is there. So the file is bound over itself, where the command
        // may write the directory that holds it.
        if let Some(file) = file_on_the_way(dirname(absent)) {
            if self.seen.contains(&file) || !self.within_writable_root(dirname(&file)) {
                return;
            }
            self.seen.insert(file.clone());
            self.decided.insert(file.clone());
            self.binds.push(Bind {
                source: file.clone(),
                dest: file,
            });
            return;
        }
        let dest = first_missing_component(absent);
        self.decided.insert(dest.clone());
        // A component with a deny beneath it is an empty directory, which stays
        // traversable. As a file it would break tools that expect a directory.
        let source = if self.ancestors.contains(&dest) {
            self.empty_directory()
        } else {
            None
        };
        self.mount_points.hold(dest.clone().into());
        self.binds.push(Bind {
            source: source.unwrap_or_else(|| "/dev/null".to_owned()),
            dest,
        });
    }

    /// The empty directory a directory mount point is bound from. `None` when it
    /// cannot be made, and the mount point is `/dev/null` then, which denies as
    /// well.
    fn empty_directory(&mut self) -> Option<String> {
        let source = self.mount_points.empty_source().ok()?.to_str()?.to_owned();
        self.empty_source = Some(source.clone());
        Some(source)
    }

    /// The binds in the order they are made, and the paths they land on.
    fn emit(self) -> (Vec<OsString>, Vec<String>) {
        let mut words = Vec::new();
        let mut protected = Vec::new();
        let mut emitted: Vec<&str> = Vec::new();
        for Bind { source, dest } in &self.binds {
            // The deny lands where a mask or a tmpfs of `denyRead` already sits.
            protected.push(dest.clone());
            let hidden = self
                .mounts
                .iter()
                .any(|mount| path_of(mount).is_some_and(|path| mount.is_dir && is_at_or_under(dest, path)));
            let masked = self
                .mounts
                .iter()
                .any(|mount| !mount.is_dir && path_of(mount) == Some(dest));
            if hidden || masked {
                continue;
            }
            words.extend(["--ro-bind", source, dest].map(OsString::from));
            emitted.push(dest);
        }
        // A bind over a directory shows what the read mounts hid beneath it, so
        // they are made again over it: the directories first, as they were.
        for is_dir in [true, false] {
            for mount in self.mounts.iter().filter(|mount| mount.is_dir == is_dir) {
                if path_of(mount)
                    .is_some_and(|path| emitted.iter().any(|dest| strictly_under(path, dest)))
                {
                    words.extend(mount.words());
                }
            }
        }
        (words, protected)
    }
}

fn path_of(mount: &Mount) -> Option<&str> {
    mount.path.to_str()
}

fn strictly_under(path: &str, dir: &str) -> bool {
    path != dir && is_at_or_under(path, dir)
}

/// Where a write to `raw` lands: its symlinks resolved, as far as the path is
/// there. What is missing is joined on as written. `None` when that cannot be
/// told: a link that leads nowhere is the first missing name, so whoever makes
/// its target decides where the write goes.
fn resolve_deny_path(base: &PathBase, raw: &str) -> Option<String> {
    if let Ok(real) = real_path_of(base, raw) {
        return Some(real);
    }
    let mut ancestor = raw;
    let mut missing: Vec<&str> = Vec::new();
    let real = loop {
        let parent = dirname(ancestor);
        if parent == ancestor {
            return None;
        }
        missing.insert(0, ancestor.rsplit('/').next().unwrap_or(ancestor));
        ancestor = parent;
        if let Ok(real) = real_path_of(base, ancestor) {
            break real;
        }
    };
    let first = format!("{}/{}", real.trim_end_matches('/'), missing.first()?);
    if fs::symlink_metadata(&first).is_ok_and(|metadata| metadata.is_symlink()) {
        return None;
    }
    Some(format!("{}/{}", real.trim_end_matches('/'), missing.join("/")))
}

/// The first existing component of `path` that is not a directory.
fn file_on_the_way(path: &str) -> Option<String> {
    let mut current = String::new();
    for part in path.split('/').filter(|part| !part.is_empty()) {
        current = format!("{current}/{part}");
        match fs::metadata(&current) {
            Ok(metadata) if !metadata.is_dir() => return Some(current),
            Ok(_) => {}
            Err(_) => return None,
        }
    }
    None
}

/// The first component of `path` that is not there.
fn first_missing_component(path: &str) -> String {
    let mut current = String::new();
    for part in path.split('/').filter(|part| !part.is_empty()) {
        current = format!("{current}/{part}");
        if !Path::new(&current).exists() {
            return current;
        }
    }
    path.to_owned()
}
