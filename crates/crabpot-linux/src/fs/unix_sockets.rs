//! What `network.allowUnixSockets` leaves shut on Linux: every Unix socket the
//! command could dial that the list does not open.
//!
//! With no list the `unix` filter refuses `socket(AF_UNIX)` outright, so there
//! is nothing to mount. A list opens `AF_UNIX` to the command, and seccomp
//! cannot see the path a socket dials, so the filter alone would open every
//! socket the command can read. Reading a socket file is what dialing it asks
//! for, and a read-only bind does not stop that, so the plan mounts `/dev/null`
//! over each socket the list leaves out. That is the mask
//! [`deny_read`](super::deny_read) gives a denied file.
//!
//! The sockets to mask are the ones the kernel lists in `/proc/net/unix`, read
//! for each command the sandbox wraps, so a socket the host bound after the
//! sandbox started is named by the next command's masks. The listing shows the
//! sockets of the reader's network namespace alone, and a pathname socket is
//! found by its inode, so one bound in another namespace is dialable all the
//! same. The section therefore reads the listing of every network namespace a
//! process it may inspect holds, once each. Four kinds of socket the masks do not
//! cover are known, and the docs of the section name them so none is a surprise:
//!
//! - A socket the host binds while a command runs is not in that command's
//!   listing and stays dialable by it. The list holds the sockets the host
//!   held, and does not keep the host from making another.
//! - One inode bound at two paths is masked only where the kernel recorded it.
//!   A hard link to a socket is a second door the listing does not name.
//! - A socket bound to a relative path is named in the listing as the binder
//!   spelled it, and the directory it is relative to is the binder's working
//!   directory, which the listing does not hold. It has no path to mount over,
//!   so it stays dialable where its file can be reached.
//! - An abstract socket has no path to mount over. The sandbox's own network
//!   namespace already keeps it out of reach, which is why upstream's Linux
//!   filter never masked one either.
//!
//! A socket in a namespace that only processes this one may not inspect hold,
//! such as another user's container, is not listed, and is dialable where its
//! path is visible and its permissions allow it. So is one whose path the
//! container's own mount namespace spells differently from this one's.
//!
//! A socket that is unlinked between the listing and bwrap's mount has no path
//! left to mount over, and bwrap cannot make one in the read-only root, so that
//! launch fails closed with the helper never started. The window is the time
//! from reading the listing to bwrap's mounts, and a host that churns sockets in
//! it, as other sandboxes starting and stopping do with their proxy sockets, can
//! meet it now and then. The `crabpot` wrapper makes a launch that failed so
//! again, up to twice, with the masks made afresh, since no part of the command
//! has run; the caller of the library's `Sandbox::command` spawns its own and
//! sees the failure as bwrap's exit status.
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
//! A dial of a masked path is answered `ECONNREFUSED` on Linux, which is what
//! `connect(2)` answers for a path that is no socket (unix(7)): the harness
//! counts it as a refusal (`harness/src/probe/unix.rs`).
//!
//! The masks are not added to the plan's `protected` paths, so no ancestor of
//! one is pinned read-only: a listed socket in a writable directory stays
//! bindable there, as it is on macOS. Moving a masked socket's directory moves
//! the mask with it, and what the command makes in its place is a socket of its
//! own, never the host's.
//!
//! The proxy's own mux socket is held out of the mask, through
//! [`Draft::own_sockets`]. The plan binds it after its words, and bwrap reads a
//! bind's source through the mounts it made before it: a mask over that path
//! would hand the bind `/dev/null` for a source, and the relays in the sandbox
//! would have no proxy to reach.
//!
//! [`Draft::own_sockets`]: super::Draft

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

/// What a command's masks are made from, kept so each command the sandbox wraps
/// is masked against the sockets the host holds then.
#[derive(Debug, Clone)]
pub struct Masks {
    /// The entries of the list, read against the plan's base.
    opened: Vec<String>,
    /// What the read sections mounted, which hides a socket already.
    hidden: Vec<Mount>,
    /// The sockets the plan binds itself.
    own: Vec<PathBuf>,
    /// Where the section's words start in the words [`Masks::refresh`] is
    /// given: the plan's own, until [`Masks::after`] moves it past a prefix.
    at: usize,
    /// How many words the section made when the plan was built.
    len: usize,
}

impl Masks {
    /// These masks for words that start with `prefix` more words than the
    /// plan's own, as `bwrap` itself does in [`wrap::words`]. [`Masks::refresh`]
    /// cuts at a place it counts from the first word it is given, so it needs
    /// the place to be counted from there.
    ///
    /// [`wrap::words`]: crate::wrap::words
    #[must_use]
    pub fn after(mut self, prefix: usize) -> Self {
        self.at += prefix;
        self
    }

    /// `words`, the ones these masks were placed for, with the section's words
    /// made again for the sockets the host holds now, and whether the `unix`
    /// filter may leave `socket(AF_UNIX)` to the command: false when the listing
    /// cannot be read or holds more sockets than `MAX_MASKS`, which masks none
    /// of them.
    ///
    /// Those are the plan's words as [`Plan::words`] gives them, or the words of
    /// [`wrap::words`] once [`Masks::after`] has moved the place past `bwrap`
    /// itself. Given words the masks were not placed for, it cuts a mount in two.
    ///
    /// [`Plan::words`]: super::Plan::words
    /// [`wrap::words`]: crate::wrap::words
    #[must_use]
    pub fn refresh(&self, words: &[OsString]) -> (Vec<OsString>, bool) {
        self.refresh_from(words, bound())
    }

    /// [`Masks::refresh`] against `bound`, the sockets the host holds.
    pub(crate) fn refresh_from(
        &self,
        words: &[OsString],
        bound: Option<Vec<PathBuf>>,
    ) -> (Vec<OsString>, bool) {
        let end = (self.at + self.len).min(words.len());
        let at = self.at.min(end);
        let mut fresh = words[..at].to_vec();
        let open = match self.masks_from(bound) {
            Some(masks) => {
                fresh.extend(masks);
                true
            }
            None => false,
        };
        fresh.extend_from_slice(&words[end..]);
        (fresh, open)
    }

    /// Moves the section's place for `pinned` words spliced in at `pin_at`,
    /// which `Plan::build_with` does once every section has run.
    pub(super) fn shift_for_pins(&mut self, pin_at: usize, pinned: usize) {
        if pin_at <= self.at {
            self.at += pinned;
        }
    }

    /// The mask words for the sockets the list leaves out, or `None` when none
    /// can be made: the listing cannot be read, or the plan cannot name every
    /// socket it would have to mask, and an open `AF_UNIX` with some of them
    /// left unmasked is a wider door than the refusal the filter gives with no
    /// list.
    fn masks_from(&self, bound: Option<Vec<PathBuf>>) -> Option<Vec<OsString>> {
        let bound = bound?;
        let shut: Vec<&PathBuf> = bound
            .iter()
            .filter(|socket| {
                !self.opened.iter().any(|entry| opens(entry, socket))
                    && !under_a_read_mount(socket, &self.hidden)
                    && !held_by_the_plan(socket, &self.own)
            })
            .collect();
        if shut.len() > MAX_MASKS {
            return None;
        }
        Some(shut.iter().flat_map(|socket| mask_of(socket)).collect())
    }
}

/// The mask words for the sockets `config`'s list does not open.
///
/// Sets [`Draft::unix_sockets_open`] when it has them, which is when the `unix`
/// filter may leave `AF_UNIX` to the command, and leaves the pieces a later
/// command's masks are made from in [`Draft::unix_masks`].
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
    let mut masks = Masks {
        opened,
        hidden: draft
            .read_mounts
            .iter()
            .chain(&draft.remounts)
            .cloned()
            .collect(),
        own: draft.own_sockets.clone(),
        at: draft.offset,
        len: 0,
    };
    let made = masks.masks_from(bound());
    draft.unix_sockets_open = made.is_some();
    let made = made.unwrap_or_default();
    masks.len = made.len();
    draft.unix_masks = Some(masks);
    Ok(made)
}

/// The sockets every network namespace this process can inspect lists, each
/// canonical and each still a socket, sorted so one host renders one plan.
/// `None` when this process's own listing is not there to read, or one is a
/// listing this parser no longer understands.
#[cfg(target_os = "linux")]
pub(super) fn bound() -> Option<Vec<PathBuf>> {
    let mut bound = BTreeSet::new();
    for listing in listings()? {
        for name in names(&listing)? {
            if let Some(socket) = maskable(&name) {
                bound.insert(socket);
            }
        }
    }
    Some(bound.into_iter().collect())
}

/// There is no `/proc/net/unix` to read, and no bwrap plan to mask for.
#[cfg(not(target_os = "linux"))]
pub(super) fn bound() -> Option<Vec<PathBuf>> {
    None
}

/// The kernel's socket listing of this process's network namespace, then that
/// of every other one a process this one may inspect holds, once each. A
/// pathname socket is found by its inode, so a command can dial one bound in a
/// namespace this process is not in, and `/proc/net/unix` lists only the
/// reader's own. A process that is gone or cannot be inspected is skipped.
#[cfg(target_os = "linux")]
fn listings() -> Option<Vec<Vec<u8>>> {
    let mut listings = vec![fs::read(LISTING).ok()?];
    let mut seen: BTreeSet<PathBuf> = fs::read_link("/proc/self/ns/net").into_iter().collect();
    for process in fs::read_dir("/proc").ok()?.flatten() {
        let name = process.file_name();
        if !name.as_encoded_bytes().iter().all(u8::is_ascii_digit) {
            continue;
        }
        let Ok(namespace) = fs::read_link(process.path().join("ns/net")) else {
            continue;
        };
        if !seen.insert(namespace) {
            continue;
        }
        if let Ok(listing) = fs::read(process.path().join("net/unix")) {
            listings.push(listing);
        }
    }
    Some(listings)
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
/// follows the seven fixed fields of a line and the one space after them, kept
/// byte for byte, since a name may hold runs of spaces and any other byte but a
/// newline. The listing is read as bytes, since a path is bytes, so one name
/// that is no text costs no more than the socket it names.
///
/// A name that starts with neither `/` nor `@` is a relative path, which a
/// process bound as it spelled it. The kernel prints it as given, and the
/// directory it is relative to is the binder's working directory at the time,
/// which the listing does not hold. The socket is skipped: there is no path to
/// mount over. Any process of the host can make one, so one may not cost the
/// whole listing.
///
/// `None` for a line that has fewer than seven fields, which is a listing this
/// parser no longer reads, or a name holding a newline, which spills onto a line
/// of its own. Masking none of it would leave every socket dialable, so none of
/// it is read at all.
#[cfg(any(target_os = "linux", all(test, unix)))]
pub(super) fn names(listing: &[u8]) -> Option<Vec<PathBuf>> {
    use std::os::unix::ffi::OsStringExt;

    let mut named = Vec::new();
    for line in listing.split(|byte| *byte == b'\n').skip(1) {
        if line.is_empty() {
            continue;
        }
        let mut end = 0;
        for _ in 0..7 {
            while line.get(end).is_some_and(u8::is_ascii_whitespace) {
                end += 1;
            }
            let start = end;
            while line.get(end).is_some_and(|byte| !byte.is_ascii_whitespace()) {
                end += 1;
            }
            if end == start {
                return None;
            }
        }
        let path = line.get(end + 1..).unwrap_or_default();
        // An unnamed socket prints no name, an abstract one prints one with
        // `@` first, and a pathname one prints its path. The sandbox's own
        // network namespace keeps the abstract ones out of reach.
        match path.first() {
            None | Some(b'@') => {}
            Some(b'/') => named.push(PathBuf::from(OsString::from_vec(path.to_vec()))),
            // A relative name has no path to mount over.
            Some(_) => {}
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

/// Whether `socket` is one the plan binds itself, which no mask may cover. Both
/// sides are read canonical: the kernel's listing names what it resolved, and a
/// bind names what the process was handed.
fn held_by_the_plan(socket: &Path, held: &[PathBuf]) -> bool {
    held.iter().any(|bind| canonical(bind) == *socket)
}

/// `path` with its links resolved, or itself when they cannot be.
fn canonical(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
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
