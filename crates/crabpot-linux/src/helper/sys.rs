//! The helper's calls that nix has no safe form of.
//!
//! This is one of the crate's two modules of FFI (IR-22); the other opens the
//! args file.

#![allow(unsafe_code)]

use core::ffi::c_int;
use core::sync::atomic::{AtomicI32, Ordering};

use nix::errno::Errno;
use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, kill, sigaction};
use nix::unistd::{self, ForkResult, Pid};

/// The process the installed handler passes a signal to, or 0 for none.
static FORWARD_TO: AtomicI32 = AtomicI32::new(0);

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

extern "C" fn forward(number: c_int) {
    let target = FORWARD_TO.load(Ordering::Relaxed);
    if let Ok(signal) = Signal::try_from(number) {
        // Nothing to do if the target is gone: the caller is about to see it end.
        let _ = kill(Pid::from_raw(target), signal);
    }
}

/// Passes each of `signals`, when this process gets it, on to `child`.
pub(super) fn forward_signals(child: Pid, signals: &[Signal]) -> Result<(), Errno> {
    FORWARD_TO.store(child.as_raw(), Ordering::Relaxed);
    let action = SigAction::new(
        SigHandler::Handler(forward),
        SaFlags::empty(),
        SigSet::all(),
    );
    for &signal in signals {
        // SAFETY: `forward` only loads an atomic and calls `kill`, which is
        // async-signal-safe, so it is sound to run in the middle of any other
        // code. The target is stored before the first handler is installed.
        unsafe { sigaction(signal, &action) }?;
    }
    Ok(())
}

/// Puts each of `signals` back to its default action, for a process that
/// inherited [`forward_signals`]'s handler and has no target to pass to.
pub(super) fn restore_default_signals(signals: &[Signal]) -> Result<(), Errno> {
    let action = SigAction::new(SigHandler::SigDfl, SaFlags::empty(), SigSet::empty());
    for &signal in signals {
        // SAFETY: `SigDfl` installs no handler, so no code runs in a signal
        // context.
        unsafe { sigaction(signal, &action) }?;
    }
    Ok(())
}
