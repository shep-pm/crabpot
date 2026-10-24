//! Probes of the kernel calls a Linux sandbox's seccomp filters refuse: a
//! socket by family, `io_uring_setup` and `unshare` of a user namespace.
//!
//! A filter answers `EPERM`, so that is the refusal. Any other error says
//! nothing of the sandbox, such as `ENOSYS` from a kernel without io_uring, and
//! is an [`Error::Io`].
//!
//! This is the harness's one module of FFI (IR-22): nix has no form of
//! `io_uring_setup`.

#![allow(unsafe_code)]

use std::os::fd::{FromRawFd, OwnedFd, RawFd};

use nix::errno::Errno;
use nix::sched::{CloneFlags, unshare};
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socket as make_socket};

use super::{Error, Outcome};

/// What a refused call answers.
const REFUSED: Errno = Errno::EPERM;

/// `sizeof(struct io_uring_params)`, in the 8-byte words it is aligned to.
const IO_URING_PARAMS_WORDS: usize = 15;

fn judged(result: Result<(), Errno>) -> Outcome {
    match result {
        Ok(()) => Ok(true),
        Err(errno) if errno == REFUSED => Ok(false),
        Err(errno) => Err(Error::Io(errno.into())),
    }
}

/// Makes a stream socket of the family `name` spells: `unix` or `vsock`.
pub(super) fn socket(name: &str) -> Outcome {
    let family = match name {
        "unix" => AddressFamily::Unix,
        "vsock" => AddressFamily::Vsock,
        _ => return Err(Error::Usage),
    };
    judged(make_socket(family, SockType::Stream, SockFlag::empty(), None).map(drop))
}

/// Asks the kernel for a ring of one entry.
pub(super) fn io_uring_setup() -> Outcome {
    let mut params = [0u64; IO_URING_PARAMS_WORDS];
    // SAFETY: `io_uring_setup(entries, params)` reads and writes only the
    // `io_uring_params` struct `params` points to, which is the 120 bytes of
    // zeroes it asks for, aligned to 8 and alive for the call.
    let ring = unsafe {
        libc::syscall(
            libc::SYS_io_uring_setup,
            1 as libc::c_uint,
            params.as_mut_ptr(),
        )
    };
    if ring < 0 {
        return judged(Err(Errno::last()));
    }
    // SAFETY: a non-negative result is a descriptor the call made and nothing
    // else holds, so the `OwnedFd` is its only owner and closes it.
    drop(unsafe { OwnedFd::from_raw_fd(ring as RawFd) });
    Ok(true)
}

/// Makes a user namespace of the probe's own, which a process may do only if
/// the sandbox lets it.
pub(super) fn unshare_user() -> Outcome {
    judged(unshare(CloneFlags::CLONE_NEWUSER))
}

#[cfg(test)]
mod tests {
    use nix::errno::Errno;

    use super::*;

    #[test]
    fn a_call_that_works_is_allowed_and_one_answered_eperm_is_refused() {
        assert!(matches!(judged(Ok(())), Ok(true)));
        assert!(matches!(judged(Err(Errno::EPERM)), Ok(false)));
    }

    #[test]
    fn any_other_errno_is_no_answer() {
        // A kernel without the call, or a family it has no module for, says
        // nothing of the sandbox.
        for errno in [Errno::ENOSYS, Errno::EAFNOSUPPORT, Errno::ENOSPC] {
            assert!(matches!(judged(Err(errno)), Err(Error::Io(_))), "{errno}");
        }
    }

    #[test]
    fn a_unix_socket_is_made_where_nothing_refuses_it() {
        assert!(matches!(socket("unix"), Ok(true)));
    }

    #[test]
    fn a_socket_of_a_family_the_probe_does_not_know_is_a_usage_error() {
        assert!(matches!(socket("inet"), Err(Error::Usage)));
    }
}
