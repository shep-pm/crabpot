//! The harness's reach into the operating system's process calls, through the
//! same `nix` crate `crabpot-core` reaches its own with.

use std::io;

use nix::sys::signal::Signal;
use nix::sys::signal::killpg;
use nix::unistd::Pid;

/// `SIGTERM`, the signal a host sends to end a process it started.
pub const TERM: Signal = Signal::SIGTERM;

/// Sends `signal` to every process in the group `pgid` leads, which is what
/// `kill -TERM -<pgid>` does from a shell.
///
/// `pgid` names the group a probe child leads: each is started with
/// `process_group(0)`, which makes the child's own pid the group's.
///
/// # Errors
///
/// The kernel's [`io::Error`]: `EPERM` when the sandbox will not let the signal
/// through, `ESRCH` when no such group runs.
pub fn signal_group(pgid: u32, signal: Signal) -> Result<(), io::Error> {
    let Ok(pgid) = i32::try_from(pgid) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the process group is not one a signal can name",
        ));
    };
    killpg(Pid::from_raw(pgid), signal).map_err(io::Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::process::Command;

    #[test]
    fn a_group_started_here_takes_the_signal() {
        let mut child = Command::new("/bin/sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .unwrap();
        let group = child.id();

        signal_group(group, TERM).unwrap();
        let ended = child.wait().unwrap();

        assert_eq!(ended.signal(), Some(TERM as i32), "the group took nothing");
    }

    #[test]
    fn a_group_no_signal_can_name_is_an_error_and_not_a_refusal() {
        // A pid no group leads. The answer says nothing about what a sandbox
        // would have allowed, so it is not the probe's `REFUSED`.
        let error = signal_group(u32::MAX, TERM).unwrap_err();
        assert_ne!(error.kind(), io::ErrorKind::PermissionDenied);
    }
}
