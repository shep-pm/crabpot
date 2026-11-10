//! What `network.allowUnixSockets` leaves shut on Linux: every Unix socket the
//! command could dial that the list does not open.
//!
//! With no list the `unix` filter refuses `socket(AF_UNIX)` outright, so there
//! is nothing to mount. A list opens `AF_UNIX` to the command, and seccomp
//! cannot see the path a socket dials, so the filter alone would open every
//! socket the command can read. Reading a socket file is what dialing it asks
//! for, and a read-only bind does not stop that, so the plan mounts `/dev/null`
//! over each socket the list leaves out. That is the mask
//! [`deny_read`](super::deny_read) gives a denied file, and a dial of a masked
//! path is answered `ECONNREFUSED`, which is what a dial of a socket nobody
//! listens on is answered anyway.
//!
//! The sockets to mask are the ones the kernel lists in `/proc/net/unix` when
//! the plan is built. Three things follow from that, and none of them is a way
//! in:
//!
//! - A socket the host binds after the sandbox starts is not in the listing and
//!   stays dialable. The list holds the sockets the host held, and does not
//!   keep the host from making another.
//! - One inode bound at two paths is masked only where the kernel recorded it.
//!   A hard link to a socket is a second door the listing does not name.
//! - An abstract socket has no path to mount over. The sandbox's own network
//!   namespace already keeps it out of reach, which is why upstream's Linux
//!   filter never masked one either.
//!
//! The section masks every socket it names or none of them: a listing that
//! cannot be read, or that names more sockets than [`MAX_MASKS`], leaves
//! `AF_UNIX` refused, which is what a host with no list gets today. Masking
//! some of them and opening the call would be the wider door.
//!
//! A listed path opens that socket and every socket beneath it, as the macOS
//! profile's `subpath` rule does. An entry is read against the plan's own base,
//! the same reading `Network::unix_socket_paths` gives the macOS profile: `~`
//! against `HOME`, a relative spelling against the working directory, and the
//! empty string as that directory. A listed path the plan has already hidden
//! stays hidden: `denyRead` and `allowRead` come before this section, and a
//! mount of this one beneath a mask of theirs has no mount point to land on,
//! since bwrap cannot make one in the read-only root.
//!
//! The masks are not added to the plan's `protected` paths, so no ancestor of
//! one is pinned read-only: a listed socket in a writable directory stays
//! bindable there, as it is on macOS. Moving a masked socket's directory moves
//! the mask with it, and what the command makes in its place is a socket of its
//! own, never the host's.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crabpot_core::config::Config;
use crabpot_core::paths::{
    PathBase, is_at_or_under, normalize_path_for_sandbox,
};

use super::Draft;
use super::PlanError;
use super::deny_read::Mount;

#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use super::glob_walk::KERNEL_MOUNTS;


/// The kernel's own list of the Unix sockets it holds.
#[cfg(target_os = "linux")]
const LISTING: &str = "/proc/net/unix";

/// The most sockets one plan masks. Each costs bwrap three words, and a whole
/// invocation is capped at 9 000 of them, which the plan shares with its other
/// mounts, its pins, the helper and proxy binds and the command. Half of that
/// cap is left to the masks.
const MAX_MASKS: usize = 1_500;

/// The mask words for the sockets `config`'s list does not open.
///
/// Sets [`Draft::unix_sockets_open`] when it has them, which is when the `unix`
/// filter may leave `AF_UNIX` to the command. The flag is set only when every
/// socket is named: a host whose `/proc/net/unix` cannot be read, or which
/// holds more sockets than [`MAX_MASKS`], masks none and keeps refusing
/// `AF_UNIX`, which is what the list does on such a host today.
pub(super) fn words(
    config: &Config,
    base: &PathBase,
    draft: &mut Draft,
) -> Result<Vec<OsString>, PlanError> {
    let opened = config
        .network
        .allow_unix_sockets
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|entry| normalize_path_for_sandbox(base, entry, false))
        .collect::<Result<Vec<_>, _>>()?;
    if opened.is_empty() {
        return Ok(Vec::new());
    }
    let Some(bound) = bound() else {
        return Ok(Vec::new());
    };
    let hidden: Vec<Mount> = draft
        .read_mounts
        .iter()
        .chain(&draft.remounts)
        .cloned()
        .collect();
    let shut: Vec<&PathBuf> = bound
        .iter()
        .filter(|socket| {
            !opened.iter().any(|entry| opens(entry, socket))
                && !under_a_read_mount(socket, &hidden)
        })
        .collect();
    if shut.len() > MAX_MASKS {
        // The plan cannot name every socket it would have to mask, and an open
        // `AF_UNIX` with some of them left unmasked is a wider door than the
        // refusal the filter gives with no list. The list is ignored here, as
        // it is when the listing cannot be read.
        return Ok(Vec::new());
    }
    draft.unix_sockets_open = true;
    Ok(shut.iter().flat_map(|socket| mask_of(socket)).collect())
}

/// The sockets `/proc/net/unix` lists, each canonical and each still a socket,
/// sorted so one host renders one plan. `None` when the listing is not there to
/// read.
#[cfg(target_os = "linux")]
pub(super) fn bound() -> Option<Vec<PathBuf>> {
    let listing = fs::read(LISTING).ok()?;
    let mut bound = BTreeSet::new();
    for name in names(&listing)? {
        if let Some(socket) = maskable(&name) {
            bound.insert(socket);
        }
    }
    Some(bound.into_iter().collect())
}

/// There is no `/proc/net/unix` to read, and no bwrap plan to mask for.
#[cfg(not(target_os = "linux"))]
pub(super) fn bound() -> Option<Vec<PathBuf>> {
    None
}

/// Where `path` is a socket this plan can mount over: not under a mount bwrap
/// makes afresh, and there as a socket once its links are resolved. A link on
/// the way is resolved away, so what is left to mount over is a plain path bwrap
/// finds in its own tree.
#[cfg(target_os = "linux")]
fn maskable(path: &Path) -> Option<PathBuf> {
    if under_kernel_mount(path) {
        return None;
    }
    let socket = fs::canonicalize(path).ok()?;
    if under_kernel_mount(&socket) {
        return None;
    }
    use std::os::unix::fs::FileTypeExt;
    fs::metadata(&socket)
        .ok()
        .is_some_and(|kind| kind.file_type().is_socket())
        .then_some(socket)
}

/// Whether `path` is at or under one of the mounts bwrap replaces with its own.
#[cfg(target_os = "linux")]
fn under_kernel_mount(path: &Path) -> bool {
    KERNEL_MOUNTS.iter().any(|mount| path.starts_with(mount))
}

/// The path of every pathname socket in a `/proc/net/unix` listing: what
/// follows the seven fixed fields of a line, which a name may hold spaces in.
/// The listing is read as bytes, since a path is bytes, so one name that is no
/// text costs no more than the socket it names.
///
/// `None` for a line whose name is neither a pathname nor an abstract one,
/// which is a listing this parser no longer reads. Masking none of it would
/// leave every socket dialable, so none of it is read at all.
#[cfg(target_os = "linux")]
fn names(listing: &[u8]) -> Option<Vec<PathBuf>> {
    use std::os::unix::ffi::OsStringExt;

    let mut named = Vec::new();
    for line in listing.split(|byte| *byte == b'\n').skip(1) {
        if line.is_empty() {
            continue;
        }
        let mut fields = line
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|field| !field.is_empty());
        for _ in 0..7 {
            fields.next()?;
        }
        let mut path: Vec<u8> = Vec::new();
        for field in fields {
            if !path.is_empty() {
                path.push(b' ');
            }
            path.extend_from_slice(field);
        }
        // An unnamed socket prints no name, an abstract one prints one with
        // `@` first, and a pathname one prints its path. The sandbox's own
        // network namespace keeps the abstract ones out of reach.
        match path.first() {
            None | Some(b'@') => {}
            Some(b'/') => named.push(PathBuf::from(OsString::from_vec(path))),
            Some(_) => return None,
        }
    }
    Some(named)
}

/// The words that mount `/dev/null` over `socket`.
fn mask_of(socket: &Path) -> [OsString; 3] {
    [
        OsString::from("--ro-bind"),
        OsString::from("/dev/null"),
        socket.as_os_str().to_owned(),
    ]
}

/// Whether `entry` opens `socket`: it is the socket, or a directory holding it.
/// The comparison is by component, so `/run/sock` opens no socket of
/// `/run/socket`.
fn opens(entry: &str, socket: &Path) -> bool {
    socket.to_str().is_some_and(|socket| is_at_or_under(socket, entry))
}

/// Whether the last of the read sections' mounts to cover `socket` hides it. A
/// socket beneath a tmpfs, or at a `/dev/null` mask, is out of reach already,
/// and has no file here to mount on.
fn under_a_read_mount(socket: &Path, mounts: &[Mount]) -> bool {
    mounts
        .iter()
        .rfind(|mount| {
            if mount.is_dir {
                socket.starts_with(&mount.path)
            } else {
                mount.path == socket
            }
        })
        .is_some_and(|mount| !mount.reopened)
}
