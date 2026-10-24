//! The helper as PID 1 of a PID and mount namespace of its own.
//!
//! A port of the namespace half of upstream's `apply-seccomp.c`. A process the
//! command starts cannot see or signal one outside the namespace, and its
//! `/proc` lists only the sandbox's. No filter is installed here yet.
//!
//! Three processes take part. The helper that bwrap runs unshares the
//! namespaces and waits, outside them. Its child is PID 1 inside: it prepares
//! the namespace, forks the command, and reaps every orphan left to it until
//! the command ends. The command's own process is the third. A relay forked
//! first (see [`super::relay`]) is a fourth, outside the namespaces.

use core::fmt;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::Path;

use nix::errno::Errno;
use nix::mount::{MsFlags, mount};
use nix::sched::{CloneFlags, unshare};
use nix::sys::prctl;
use nix::sys::signal::{SigSet, Signal};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, getgid, getuid};

use super::exec::{ExecError, exec};
use super::relay;
use super::sys;

/// Where the sandbox's `max_user_namespaces` limit is written.
const MAX_USER_NAMESPACES: &str = "/proc/sys/user/max_user_namespaces";

/// The signals a helper passes on to what it runs: the ones a host ends a
/// command with.
const FORWARDED: [Signal; 4] = [
    Signal::SIGINT,
    Signal::SIGTERM,
    Signal::SIGHUP,
    Signal::SIGQUIT,
];

/// Runs the command `argv` names as a child of a new PID 1. With a `relay` it
/// first forks the relay that forwards the sandbox's proxy ports to that Unix
/// socket, and waits for it to listen.
///
/// It returns in two cases. `Ok` carries the status the calling process ends
/// with: the command's, or 128 and the signal number when a signal ended it.
/// `Err` is the process that was to replace itself with the command, which
/// could not.
///
/// # Errors
///
/// A [`InitError`] names the step that failed, or says the command could not
/// be started.
pub fn init(relay: Option<&Path>, argv: &[OsString]) -> Result<i32, InitError> {
    if argv.is_empty() {
        return Err(InitError::NoCommand);
    }
    if let Some(socket) = relay {
        relay::start(socket)?;
    }
    let own_user_namespace = enter_namespaces()?;
    // No other process of the user's may read or trace the helper before its
    // children take over, whatever the namespaces hold.
    set_dumpable()?;
    match fork_forwarding()? {
        ForkResult::Parent { child } => Ok(reap_until(child)),
        ForkResult::Child => namespace_init(argv, own_user_namespace),
    }
}

/// Unshares the PID and mount namespaces. A process without `CAP_SYS_ADMIN` is
/// refused, so it makes a user namespace first, where it has the capability,
/// and maps its own ids to themselves. It returns whether it made one.
fn enter_namespaces() -> Result<bool, InitError> {
    let flags = CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWNS;
    if unshare(flags).is_ok() {
        return Ok(false);
    }
    // The ids are read before the unshare: in the new namespace they are
    // unmapped until the maps below are written.
    let (uid, gid) = (getuid(), getgid());
    unshare(flags | CloneFlags::CLONE_NEWUSER)
        .map_err(|reason| InitError::step(Step::Unshare, reason))?;
    // `gid_map` is refused to a process that may still call `setgroups`.
    write_proc("/proc/self/setgroups", "deny")?;
    write_proc("/proc/self/uid_map", &format!("{uid} {uid} 1"))?;
    write_proc("/proc/self/gid_map", &format!("{gid} {gid} 1"))?;
    Ok(true)
}

fn write_proc(path: &'static str, contents: &str) -> Result<(), InitError> {
    fs::write(path, contents).map_err(|error| InitError::Map {
        path,
        reason: error.kind(),
    })
}

fn set_dumpable() -> Result<(), InitError> {
    prctl::set_dumpable(false).map_err(|reason| InitError::step(Step::Dumpable, reason))
}

/// PID 1 of the namespace: makes it the command's, then runs the command.
/// `own_user_namespace` is whether the namespace's user namespace is one this
/// helper made.
fn namespace_init(argv: &[OsString], own_user_namespace: bool) -> Result<i32, InitError> {
    set_dumpable()?;
    // Mounts made here must not reach the namespace this one was copied from.
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(|reason| InitError::step(Step::PrivateMounts, reason))?;
    // The `/proc` the process inherited lists the pids of the namespace it was
    // copied from.
    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .map_err(|reason| InitError::step(Step::Proc, reason))?;
    // Best effort: the command cannot make a user namespace to regain
    // capabilities in. The limit belongs to the user namespace it is written
    // in, so it is written only in one this helper made, and never in the
    // host's. A kernel without the sysctl has nothing to limit.
    if own_user_namespace {
        let _ = fs::write(MAX_USER_NAMESPACES, "0");
    }
    sys::clear_ambient_capabilities()
        .map_err(|reason| InitError::step(Step::AmbientCapabilities, reason))?;
    match fork_forwarding()? {
        ForkResult::Parent { child } => Ok(reap_until(child)),
        ForkResult::Child => {
            // The mask would outlive the `exec`.
            unblock_forwarded()?;
            Err(InitError::Exec(exec(argv)))
        }
    }
}

/// Forks, and has the parent pass the signals in [`FORWARDED`] on to the
/// child, so the command answers a SIGINT or SIGTERM sent to the helper
/// itself.
///
/// The signals are blocked across the fork so none arrives before the parent
/// forwards it. The parent unblocks them once its handlers are installed. The
/// child keeps them blocked, pending rather than dropped, until it has handlers
/// of its own or is about to run the command, and then calls
/// [`unblock_forwarded`]: a namespace's init drops a signal from outside it
/// that it has no handler for.
fn fork_forwarding() -> Result<ForkResult, InitError> {
    let signals = |reason| InitError::step(Step::Signals, reason);
    forwarded_set().thread_block().map_err(signals)?;
    let forked = sys::fork().map_err(|reason| InitError::step(Step::Fork, reason))?;
    if let ForkResult::Parent { child } = forked {
        sys::forward_signals(child, &FORWARDED).map_err(signals)?;
        unblock_forwarded()?;
    }
    Ok(forked)
}

fn forwarded_set() -> SigSet {
    let mut set = SigSet::empty();
    for signal in FORWARDED {
        set.add(signal);
    }
    set
}

fn unblock_forwarded() -> Result<(), InitError> {
    forwarded_set()
        .thread_unblock()
        .map_err(|reason| InitError::step(Step::Signals, reason))
}

/// Waits for every child, whichever it is, until `target` has ended, and
/// returns the status it ended with. A child that is not `target` is an
/// orphan reparented to this process, which reaps it so it is not a zombie.
fn reap_until(target: Pid) -> i32 {
    loop {
        match waitpid(None, None) {
            Ok(WaitStatus::Exited(pid, code)) if pid == target => return code,
            Ok(WaitStatus::Signaled(pid, signal, _)) if pid == target => {
                return 128 + signal as i32;
            }
            Ok(_) | Err(Errno::EINTR) => {}
            // No child is left, so `target` was never there to be waited for.
            Err(_) => return 1,
        }
    }
}

/// A step the helper takes before it runs the command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Unsharing the PID and mount namespaces, with a user namespace.
    Unshare,
    /// Making the process not dumpable.
    Dumpable,
    /// Splitting into the inner init and the command.
    Fork,
    /// Making the mounts private to the new namespace.
    PrivateMounts,
    /// Mounting a `/proc` of the new namespace.
    Proc,
    /// Clearing the ambient capabilities.
    AmbientCapabilities,
    /// Blocking or forwarding the signals that end the command.
    Signals,
    /// Making the channel the relay reports on.
    Relay,
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unshare => "unshare the PID and mount namespaces",
            Self::Dumpable => "make the process not dumpable",
            Self::Fork => "fork",
            Self::PrivateMounts => "make the mounts private",
            Self::Proc => "mount /proc",
            Self::AmbientCapabilities => "clear the ambient capabilities",
            Self::Signals => "forward signals",
            Self::Relay => "open the relay's channel",
        })
    }
}

/// Why the command did not run in a namespace of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitError {
    /// There was no program to run.
    NoCommand,
    /// A step failed with an error number.
    Step {
        /// What the helper was doing.
        step: Step,
        /// The error number the call returned.
        reason: Errno,
    },
    /// A user namespace's id map could not be written.
    Map {
        /// The `/proc/self` file that was written.
        path: &'static str,
        /// How writing it failed.
        reason: io::ErrorKind,
    },
    /// The relay for the sandbox's proxy ports did not start: it could not
    /// listen, or ended first.
    Relay(String),
    /// The command could not be started in the namespace.
    Exec(ExecError),
}

impl InitError {
    pub(super) fn step(step: Step, reason: Errno) -> Self {
        Self::Step { step, reason }
    }
}

impl fmt::Display for InitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCommand => write!(f, "no command specified"),
            Self::Step { step, reason } => write!(f, "cannot {step}: {reason}"),
            Self::Map { path, reason } => write!(f, "cannot write {path}: {reason}"),
            Self::Relay(reason) => write!(f, "cannot start the relay: {reason}"),
            Self::Exec(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl core::error::Error for InitError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_command_is_refused_before_any_namespace_is_made() {
        assert_eq!(init(None, &[]), Err(InitError::NoCommand));
    }

    #[test]
    fn a_failed_step_is_named_with_its_error() {
        let error = InitError::step(Step::Proc, Errno::EPERM);

        assert_eq!(
            error.to_string(),
            "cannot mount /proc: EPERM: Operation not permitted"
        );
    }

    #[test]
    fn a_relay_that_did_not_start_says_why() {
        let error = InitError::Relay("cannot listen on port 3128: address in use".to_owned());

        assert_eq!(
            error.to_string(),
            "cannot start the relay: cannot listen on port 3128: address in use"
        );
    }

    #[test]
    fn a_failed_map_names_its_file() {
        let error = InitError::Map {
            path: "/proc/self/uid_map",
            reason: io::ErrorKind::PermissionDenied,
        };

        assert_eq!(
            error.to_string(),
            "cannot write /proc/self/uid_map: permission denied"
        );
    }
}
