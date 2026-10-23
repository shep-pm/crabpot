//! The args file the long form of a bwrap invocation reads its words from.
//!
//! A port of `openBwrapArgsProfile` from upstream's
//! `src/sandbox/linux-sandbox-utils.ts`. The file is `O_TMPFILE`, so it has no
//! name in the directory it is opened in: nothing can race with the name or
//! read the words through it, and it is gone once the last descriptor to it
//! closes. That descriptor is the caller's, and the child reaches the words
//! through it: the file is opened without `O_CLOEXEC`, so `exec` hands it to
//! the shell, which moves it onto the fd `bwrap` reads.
//!
//! This is the crate's one module of FFI (IR-22).

#![allow(unsafe_code)]

use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::argv::SEPARATOR;

/// The words the file holds, and the descriptor that holds them open.
pub(crate) struct ArgsFile {
    /// The descriptor the caller keeps open for as long as its child runs.
    /// Closing it is what deletes the file.
    pub(crate) fd: OwnedFd,
    /// Where the child opens the file from: this very descriptor, which the
    /// `exec` handed to the child.
    pub(crate) path: PathBuf,
}

/// Open an args file in `dir` holding `flags`, the `--` that ends them, and
/// `command`, as entries terminated each by a NUL byte.
pub(crate) fn open(dir: &Path, flags: &[OsString], command: &[OsString]) -> io::Result<ArgsFile> {
    let dir = CString::new(dir.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "the args directory holds a NUL byte",
        )
    })?;

    // SAFETY: `dir` is a `CString`, so its pointer is a valid NUL-terminated
    // path for the whole call. `O_TMPFILE` takes a mode, and `0o600` is one
    // only the file's owner can read and write. The descriptor is left without
    // `O_CLOEXEC` on purpose: the args-file form hands the file to its child
    // through it, and `O_DIRECTORY` is what `O_TMPFILE` asks for so the path
    // must be a directory.
    let raw = unsafe {
        libc::open(
            dir.as_ptr(),
            libc::O_RDWR | libc::O_TMPFILE | libc::O_DIRECTORY,
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
    for word in flags
        .iter()
        .map(|word| word.as_os_str())
        .chain(std::iter::once(OsStr::new(SEPARATOR)))
        .chain(command.iter().map(|word| word.as_os_str()))
    {
        words.extend_from_slice(word.as_bytes());
        words.push(0);
    }

    let mut file = File::from(fd);
    file.write_all(&words)?;
    let fd = OwnedFd::from(file);
    let path = PathBuf::from(format!("/proc/self/fd/{}", fd.as_raw_fd()));

    Ok(ArgsFile { fd, path })
}
