//! The self-binds that keep a protected path from being moved away.
//!
//! Upstream's `ancestorPinArgs`. A deny bind, a read mask or a read tmpfs sits
//! on one path, and the directories between it and the write root that covers
//! it carry no mount, so `rename(2)` on one moves the mount along with it and
//! the path can be made again unprotected (`mv .git aside; mkdir .git`). A
//! directory that is a mount point the kernel refuses to rename or remove, so
//! each of them is bound over itself, read-only and shallowest first.
//!
//! The write root itself needs no pin: its bind is already a mount point. The
//! pins are spliced in beneath the write binds, so that a pin on top of a
//! write root cannot make it read-only.
//!
//! A write root of `/` buries them: its own bind is one of the mounts above
//! the pins. The pins then follow the binds and take every ancestor, the other
//! write roots included, down to but not including the top-level directory
//! `D` on the chain. A writable bind of `D` over itself, the cover, buries them
//! again: lookups enter the cover and meet no pin, so no filesystem boundary
//! lands inside `D`, while the kernel's rename and remove checks scan the
//! mounts by dentry and still find one. `/proc`, `/dev` and `/sys` are bwrap's
//! own, and are never covered.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::io;

use crabpot_core::paths::{dirname, is_at_or_under};

use super::Draft;

const KERNEL_TOP_LEVEL_DIRS: [&str; 3] = ["/proc", "/dev", "/sys"];

/// The pin words for the paths `draft` says are protected.
pub(super) fn words(draft: &Draft) -> Vec<OsString> {
    let roots = &draft.write_roots;
    let root_is_write_root = roots.iter().any(|root| root == "/");
    let within_write_root = |dir: &str| roots.iter().any(|root| is_at_or_under(dir, root));
    let mut pins: Vec<&str> = Vec::new();
    let mut covers = BTreeSet::new();
    // A directory's chain is the same from whichever seed reaches it.
    let mut visited = BTreeSet::new();
    for seed in &draft.protected {
        if root_is_write_root
            && KERNEL_TOP_LEVEL_DIRS
                .iter()
                .any(|dir| is_at_or_under(seed, dir))
        {
            continue;
        }
        let mut dir = dirname(seed);
        while dir != "/" && !visited.contains(dir) && within_write_root(dir) {
            visited.insert(dir);
            if root_is_write_root {
                if dirname(dir) == "/" {
                    covers.insert(dir);
                    dir = dirname(dir);
                    continue;
                }
            } else if roots.iter().any(|root| root == dir) {
                dir = dirname(dir);
                continue;
            }
            // A directory that is not there cannot be bound or renamed. One that
            // cannot be looked at is pinned all the same.
            let absent = matches!(
                fs::metadata(dir).map_err(|error| error.kind()),
                Err(io::ErrorKind::NotFound | io::ErrorKind::NotADirectory)
            );
            if !absent {
                pins.push(dir);
            }
            dir = dirname(dir);
        }
    }
    pins.sort_by_key(|dir| dir.split('/').count());
    pins.iter()
        .flat_map(|dir| ["--ro-bind", dir, dir])
        .chain(covers.iter().flat_map(|dir| ["--bind", dir, dir]))
        .map(OsString::from)
        .collect()
}
