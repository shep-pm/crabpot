//! The args file the long form of a bwrap invocation reads its flags from.
//!
//! A port of `openBwrapArgsProfile` from upstream's
//! `src/sandbox/linux-sandbox-utils.ts`. The file is `O_TMPFILE`, so it is
//! never named in the directory it is opened in: there is nothing for another
//! process to substitute or read between the wrap and the run, and the file is
//! gone once the descriptor the caller holds closes.
//!
//! The child reaches the words by path and not by inheritance: the path names
//! this process's own descriptor, `/proc/<pid>/fd/<n>`, which is a fresh
//! read-only description of the same inode at offset 0. The descriptor is
//! therefore close-on-exec, and no child is left holding it. Opening the path
//! here, before the child runs, is upstream's own check and is kept: a host
//! whose `/proc` will not take the open fails the wrap, where the caller is
//! told, rather than a redirection that runs no command.
//!
//! This is the crate's one module of FFI (IR-22).

#![allow(unsafe_code)]

use std::ffi::{CString, OsString};
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// The words the file holds, and the descriptor that holds them open.
pub(crate) struct ArgsFile {
    /// The descriptor the caller keeps open for as long as its child runs.
    /// Closing it is what deletes the file.
    pub(crate) fd: OwnedFd,
    /// Where the child opens the file from: this process's own descriptor,
    /// which stays open while the child runs.
    pub(crate) path: PathBuf,
}

/// Open an args file in `dir` holding `flags` as words terminated each by a
/// NUL byte, which is how bwrap splits an args file.
pub(crate) fn open(dir: &Path, flags: &[OsString]) -> io::Result<ArgsFile> {
    let dir = CString::new(dir.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "the args directory holds a NUL byte",
        )
    })?;

    // SAFETY: `dir` is a `CString`, so its pointer is a valid NUL-terminated
    // path for the whole call. `O_TMPFILE` takes a mode, and `0o600` is one
    // only the file's owner can read and write. `O_TMPFILE` is the asm-generic
    // value with the `O_DIRECTORY` it is defined to carry, so a kernel or
    // filesystem that does not know it fails the open on the directory instead
    // of creating a named file.
    let raw = unsafe {
        libc::open(
            dir.as_ptr(),
            libc::O_RDWR | libc::O_TMPFILE | libc::O_DIRECTORY | libc::O_CLOEXEC,
            0o600_u32,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call above returned a descriptor this code owns, and nothing
    // else takes it.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    let mut words: Vec<u8> = Vec::new();
    for word in flags {
        words.extend_from_slice(word.as_bytes());
        words.push(0);
    }

    let mut file = File::from(fd);
    file.write_all(&words)?;
    let fd = OwnedFd::from(file);

    // Read-only from here: this process is done writing it.
    // SAFETY: `fd` is a descriptor this code owns, and `fchmod` takes no
    // pointer at all: the descriptor and a mode value.
    let readonly = unsafe { libc::fchmod(fd.as_raw_fd(), 0o400) };
    if readonly < 0 {
        return Err(io::Error::last_os_error());
    }

    let path = PathBuf::from(format!(
        "/proc/{}/fd/{}",
        std::process::id(),
        fd.as_raw_fd()
    ));
    // The child opens this path. Fail here, where the caller is told why,
    // rather than in a redirection that runs no command. The probe closes with
    // the statement.
    File::open(&path)?;

    Ok(ArgsFile { fd, path })
}
