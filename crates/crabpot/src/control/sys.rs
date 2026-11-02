//! The calls on the control descriptor that std and nix have no safe form of.
//!
//! This is the crate's one module of FFI (IR-22).

#![allow(unsafe_code)]

use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

/// The lowest number a copy may take, above the descriptors a launcher hands
/// down (3) and the ones the Linux wrapper keeps for itself (7 to 9).
const COPY_ABOVE: libc::c_int = 10;

/// Whether `fd` is an open descriptor of this process.
pub(super) fn check_open(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fcntl` with `F_GETFD` takes a descriptor number, and returns its
    // flags or -1. It reads no memory and changes nothing.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Moves the descriptor `fd` to a close-on-exec copy that is returned, and
/// leaves `/dev/null` open under `fd` in its place, so a command started from
/// here sees nothing of what the host writes. The number is replaced for the
/// whole process, so the caller must own it and hold no `OwnedFd` or `File` for it.
pub(super) fn take(fd: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: `fcntl` with `F_DUPFD_CLOEXEC` takes a descriptor number and an
    // int, and returns a new descriptor or -1. It reads no memory.
    let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, COPY_ABOVE) };
    if copy < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fcntl` returned a fresh descriptor that nothing else owns.
    let copy = unsafe { OwnedFd::from_raw_fd(copy) };
    // `fd` is open, so the file cannot be given its number.
    let null = File::options().read(true).write(true).open("/dev/null")?;
    // SAFETY: `dup2` takes two descriptor numbers and reads no memory. `null` is
    // open, and `fd` is open and replaced.
    if unsafe { libc::dup2(null.as_raw_fd(), fd) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(copy)
}

/// What `poll` found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Ready {
    /// A read of `input` would not block: it has bytes, is at its end, or failed.
    pub(super) input: bool,
    /// The write end of `wake` is closed.
    pub(super) woken: bool,
}

/// Waits until `input` can be read or `wake` is closed, or only looks when
/// `block` is false.
pub(super) fn poll(input: BorrowedFd<'_>, wake: BorrowedFd<'_>, block: bool) -> io::Result<Ready> {
    let mut fds = [
        libc::pollfd {
            fd: input.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: wake.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let timeout = if block { -1 } else { 0 };
    loop {
        // SAFETY: `fds` is two initialized `pollfd`s that live through the call,
        // and the count passed is its length.
        let found = unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout) };
        if found >= 0 {
            return Ok(Ready {
                input: fds[0].revents != 0,
                woken: fds[1].revents != 0,
            });
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}
