//! A path as the kernel resolves it, and the errors that say nothing is there.

use std::{fs, io};

use super::{PathBase, lexical};

/// `p` with every symbolic link on the way to it resolved. A `.`, `..` or `//`
/// in `p` itself, and a `/` at its end, is folded in text before anything is
/// looked at: `link/..` is the directory that holds the link. In a link's
/// target they are read as the kernel reads them.
///
/// # Errors
///
/// Whatever the kernel says of the first component that fails to resolve. A
/// real path that is not UTF-8 is [`io::ErrorKind::InvalidData`]: the string
/// made of its bytes would name another file, or none.
pub(crate) fn real_path_of(base: &PathBase, p: &str) -> io::Result<String> {
    let cwd = if lexical::is_absolute(p) {
        ""
    } else {
        base.cwd().map_err(io::Error::other)?
    };
    fs::canonicalize(lexical::resolve(cwd, p))?
        .into_os_string()
        .into_string()
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the real path is not valid UTF-8",
            )
        })
}

/// `ELOOP` where this platform's number is known. `std` has no stable name for
/// it.
const ELOOP: Option<i32> = if cfg!(target_os = "macos") {
    Some(62)
} else if cfg!(all(
    target_os = "linux",
    not(any(
        target_arch = "mips",
        target_arch = "mips64",
        target_arch = "sparc64",
        target_arch = "powerpc"
    ))
)) {
    Some(40)
} else {
    None
};

/// Whether `err` means the name resolves to no file: it is missing, or the path
/// cannot name one at all. An error that means a file is there but could not be
/// looked at (`EACCES`, `EPERM`, `EIO`, anything unrecognised) is not one.
///
/// A platform whose `ELOOP` is not known here reads a link loop as a file that
/// could not be looked at, which is the side a deny and an allow both err on.
pub(crate) fn is_absence_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory | io::ErrorKind::InvalidFilename
    ) || ELOOP.is_some_and(|eloop| err.raw_os_error() == Some(eloop))
}
