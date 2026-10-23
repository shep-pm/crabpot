//! `expandGlobPattern` for Windows: a pattern as the paths on disk it matches,
//! without regard to case.

use crabpot_core::paths::glob_matches;

use super::{Disk, Kind, Ordered};

/// The paths on disk that `pattern` matches. A link or junction is a match in
/// its own right and is not walked into. A directory that cannot be listed
/// yields nothing. A pattern that ends in a separator matches directories only.
///
/// The pattern is read twice, the way upstream does for a directory with `[`
/// in its name: with `[` and `]` as a character class from the first of them,
/// and as the name they are in every directory before the first `*` or `?`.
pub(super) fn expand_glob<D: Disk>(disk: &D, pattern: &str) -> Vec<String> {
    let pattern = pattern.replace('\\', "/");
    let mut found = Ordered::default();
    let class_base = base_dir(&pattern, &['*', '?', '[', ']']);
    let name_base = base_dir(&pattern, &['*', '?']);
    let bases = if class_base == name_base {
        vec![class_base]
    } else {
        vec![class_base, name_base]
    };
    for base in bases {
        // A pattern whose first component is a wildcard starts at no
        // directory, and a walk of the root would list every volume.
        if base.is_empty() || base == "/" {
            continue;
        }
        let tail = pattern[base.len()..].trim_start_matches('/');
        walk(disk, base, tail, &mut found);
    }
    found.into_vec()
}

/// The directory a walk of `pattern` starts from: the text before its first
/// character of `glob`, without the last component when that is not a
/// directory of its own.
fn base_dir<'a>(pattern: &'a str, glob: &[char]) -> &'a str {
    let prefix = pattern.split(glob).next().unwrap_or_default();
    if let Some(dir) = prefix.strip_suffix('/') {
        return dir;
    }
    prefix.rfind('/').map_or("", |at| &prefix[..at])
}

fn walk<D: Disk>(disk: &D, base: &str, tail: &str, found: &mut Ordered) {
    // A separator at the end asks for a directory, and no entry's name has one.
    let directories_only = tail.ends_with('/');
    let tail = tail.trim_end_matches('/').to_lowercase();
    // `*` and `?` stop at a separator, so without `**` the tail's depth is the
    // depth of every match.
    let depth = (!tail.contains("**")).then(|| tail.split('/').count());
    let root = native_dir(base);
    let mut pending = vec![(root, String::new(), 1_usize)];
    while let Some((dir, relative, level)) = pending.pop() {
        let Ok(mut entries) = disk.read_dir(&dir) else {
            continue;
        };
        entries.sort_by_cached_key(|entry| entry.name.to_lowercase());
        for entry in entries {
            let below = if relative.is_empty() {
                entry.name.clone()
            } else {
                format!("{relative}/{}", entry.name)
            };
            let path = format!("{}\\{}", dir.trim_end_matches('\\'), entry.name);
            let wanted = !directories_only || entry.kind == Kind::Dir;
            if wanted && glob_matches(&tail, &below.to_lowercase()) {
                found.insert(&path);
            }
            if entry.kind == Kind::Dir && depth.is_none_or(|most| level < most) {
                pending.push((path, below, level + 1));
            }
        }
    }
}

/// A directory in the spelling the disk is asked in: `\` separated, and a bare
/// drive with its root, since `C:` alone names the drive's working directory.
fn native_dir(base: &str) -> String {
    let dir = base.replace('/', "\\");
    if dir.ends_with(':') {
        format!("{dir}\\")
    } else {
        dir
    }
}
