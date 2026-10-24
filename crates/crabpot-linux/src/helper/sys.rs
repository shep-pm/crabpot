//! The helper's two calls that nix has no safe form of.
//!
//! This is one of the crate's two modules of FFI (IR-22); the other opens the
//! args file.

#![allow(unsafe_code)]

use nix::errno::Errno;
use nix::unistd::{self, ForkResult};

/// Splits this process in two, as `fork(2)` does.
pub(super) fn fork() -> Result<ForkResult, Errno> {
    // SAFETY: `fork` is unsafe because a child of a multithreaded process may
    // meet a lock another thread held. The helper is entered first thing in
    // `main` (`run_from_args`), before the host starts a thread, and starts
    // none itself, so there is no other thread to hold one.
    unsafe { unistd::fork() }
}

/// Empties this process's ambient capability set, which a command would
/// inherit across `exec` as permitted and effective.
pub(super) fn clear_ambient_capabilities() -> Result<(), Errno> {
    // SAFETY: `PR_CAP_AMBIENT_CLEAR_ALL` takes no pointer and no descriptor,
    // and the three arguments after it must be zero. `prctl` reads its
    // arguments as `unsigned long`, so each is passed as one.
    let result = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    Errno::result(result).map(drop)
}
