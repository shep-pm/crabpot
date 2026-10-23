//! Unix socket paths as upstream's Node binds and dials them: the
//! `sockaddr_un` is sized to the path, so a path past the 104 bytes of macOS's
//! `sun_path` is taken wherever the kernel takes it (ADR-0003). Neither std nor
//! nix builds one that long, so this is the crate's one module of FFI
//! (IR-22).

#![allow(unsafe_code)]

use core::fmt;
use core::mem::offset_of;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use std::os::unix::ffi::OsStrExt;

/// The backlog std listens with.
const BACKLOG: libc::c_int = 128;

/// The most a `sockaddr_un` may measure. macOS holds its length in the `u8`
/// `sun_len`, and a Linux kernel takes no more than the struct.
#[cfg(target_vendor = "apple")]
const MAX_ADDRESS: usize = u8::MAX as usize;
#[cfg(not(target_vendor = "apple"))]
const MAX_ADDRESS: usize = size_of::<libc::sockaddr_un>();

/// Where `sun_path` starts in a `sockaddr_un`.
const PATH_AT: usize = offset_of!(libc::sockaddr_un, sun_path);

/// The longest path a `sockaddr_un` carries, with the terminator after it.
const MAX_PATH: usize = MAX_ADDRESS - PATH_AT - 1;

/// Why a path cannot be a socket's address.
#[derive(Debug)]
pub(crate) enum PathError {
    /// The path is longer than the most the platform's `sockaddr_un` carries.
    TooLong {
        /// The path asked for.
        path: PathBuf,
    },
    /// The path holds a NUL byte, which ends it in a `sockaddr_un`.
    Nul {
        /// The path asked for.
        path: PathBuf,
    },
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { path } => write!(
                f,
                "the socket path {} is {} bytes, and this platform takes {MAX_PATH} at most",
                path.display(),
                path.as_os_str().len(),
            ),
            Self::Nul { path } => write!(f, "the socket path {} holds a NUL byte", path.display()),
        }
    }
}

impl core::error::Error for PathError {}

impl From<PathError> for io::Error {
    fn from(error: PathError) -> Self {
        Self::new(io::ErrorKind::InvalidInput, error)
    }
}

/// A `sockaddr_un` of the length its path needs.
#[repr(C, align(8))]
struct Address {
    bytes: [u8; MAX_ADDRESS],
    len: libc::socklen_t,
}

impl Address {
    fn new(path: &Path) -> Result<Self, PathError> {
        let name = path.as_os_str().as_bytes();
        if name.len() > MAX_PATH {
            return Err(PathError::TooLong { path: path.into() });
        }
        if name.contains(&0) {
            return Err(PathError::Nul { path: path.into() });
        }
        let len = PATH_AT + name.len() + 1;
        let mut bytes = [0u8; MAX_ADDRESS];
        // `len` is at most `MAX_ADDRESS`, which fits the `u8` macOS holds it in.
        #[cfg(target_vendor = "apple")]
        {
            bytes[0] = len as u8;
            bytes[1] = libc::AF_UNIX as u8;
        }
        #[cfg(not(target_vendor = "apple"))]
        bytes[..PATH_AT].copy_from_slice(&(libc::AF_UNIX as libc::sa_family_t).to_ne_bytes());
        bytes[PATH_AT..PATH_AT + name.len()].copy_from_slice(name);
        Ok(Self {
            bytes,
            len: len as libc::socklen_t,
        })
    }

    fn as_ptr(&self) -> *const libc::sockaddr {
        self.bytes.as_ptr().cast()
    }
}

/// A stream socket that is close-on-exec and non-blocking, so the sandboxed
/// child inherits no descriptor of it.
fn socket() -> io::Result<OwnedFd> {
    // SAFETY: `socket` reads nothing from this process's memory.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a descriptor `socket` just returned, and nothing else
    // owns it.
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: `fcntl` with these commands takes only the descriptor and an int.
    let flags = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: as above.
    let status = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) };
    if status < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(socket)
}

/// Binds and listens on a Unix socket at `path`. The listener is non-blocking.
///
/// # Errors
///
/// An [`io::Error`] of kind `InvalidInput`, holding a [`PathError`], for a path
/// longer than the platform takes or one with a NUL in it, and otherwise the
/// error of whichever syscall failed.
pub(crate) fn bind(path: &Path) -> io::Result<UnixListener> {
    let address = Address::new(path)?;
    let socket = socket()?;
    // SAFETY: `address` holds `len` initialised bytes of a `sockaddr_un`, and
    // `socket` is an open descriptor.
    let bound = unsafe { libc::bind(socket.as_raw_fd(), address.as_ptr(), address.len) };
    if bound < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `socket` is an open, bound descriptor.
    let listening = unsafe { libc::listen(socket.as_raw_fd(), BACKLOG) };
    if listening < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(UnixListener::from(socket))
}

/// Dials the Unix socket at `path`.
///
/// # Errors
///
/// As [`bind`].
pub(crate) async fn connect(path: &Path) -> io::Result<tokio::net::UnixStream> {
    let address = Address::new(path)?;
    let socket = socket()?;
    // SAFETY: as in `bind`.
    let dialed = unsafe { libc::connect(socket.as_raw_fd(), address.as_ptr(), address.len) };
    if dialed < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(error);
        }
    }
    let stream = tokio::net::UnixStream::from_std(std::os::unix::net::UnixStream::from(socket))?;
    stream.writable().await?;
    match stream.take_error()? {
        Some(error) => Err(error),
        None => Ok(stream),
    }
}

#[cfg(test)]
mod tests;
