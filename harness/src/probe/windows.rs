//! The Windows form of the probes that name a process, a process group and a
//! Unix socket.
//!
//! Windows has no process groups. `srt-win` holds each sandboxed command in a
//! job object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`
//! (`crates/crabpot-windows/srt-win/src/job.rs`), which ends the command and
//! every process the command started as soon as the command ends, and
//! `crates/crabpot/src/windows/` never touches it. `signal-group` measures that
//! containment in its place: that the command is held in a job that ends its
//! members when it closes, and so is a child the command starts inside the
//! sandbox.
//!
//! `ps` names a process with `tasklist`, and `bind-unix` with the `AF_UNIX`
//! family Windows 10 and later carries, which `std` has no form of: see
//! [`crate::win32`]. What `tasklist` answers is read in [`super::tasklist`],
//! which holds no Windows call and so is testable on any host.

use std::io::ErrorKind;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use super::tasklist::{TASKLIST, names_the_pid};
use super::{Error, Outcome, judge, socket_path_too_long};

/// The mode a probe child runs: this same binary, asleep for the seconds it is
/// given. Windows has no `/bin/sleep`, and the child has to be a program the
/// sandbox is already running. No probe kind spells it, so no case holds it.
const HOLD: &str = "--hold";

/// How long the probe's child lives on its own, in seconds. Long enough that
/// the probe ends it and never races it.
const CHILD_LIFE: &str = "30";

/// The exit code of a process ended by `TerminateProcess`, which is what
/// `Child::kill` calls.
const KILLED: i32 = 1;

/// A child the sandbox will not let the command start, or a `tasklist` it will
/// not let the command run, is the sandbox refusing the action. It answers
/// `EPERM`, or the error of a program it will not open at all.
const START_REFUSED: &[ErrorKind] = &[ErrorKind::PermissionDenied, ErrorKind::NotFound];

/// A socket the sandbox will not let the command bind answers `WSAEACCES`,
/// which is a refusal of the action and not of the path.
const BIND_REFUSED: &[ErrorKind] = &[ErrorKind::PermissionDenied];

/// Binds a Unix socket at `path`, which is how a command takes a path the
/// profile lists for it. Nothing denies a Unix socket on Windows, so what a
/// refusal there can only come from is the sandbox itself.
pub(super) fn bind_unix(path: &str) -> Outcome {
    if socket_path_too_long(path) {
        return Ok(false);
    }
    judge(
        crate::win32::Listener::bind(Path::new(path)).map(drop),
        BIND_REFUSED,
    )
}

/// Sleeps for the seconds `secs` names, which is how a probe child holds on
/// until the probe ends it.
pub(super) fn hold(secs: &str) -> Outcome {
    let secs: u64 = secs.parse().map_err(|_| Error::Usage)?;
    std::thread::sleep(std::time::Duration::from_secs(secs));
    Ok(true)
}

/// Starts this same binary as a child that holds on, inside the sandbox.
fn start_child() -> Result<Child, Error> {
    Command::new(std::env::current_exe().map_err(Error::Io)?)
        .arg(HOLD)
        .arg(CHILD_LIFE)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(Error::Io)
}

/// Starts a child inside the sandbox and asks whether the sandbox ends a
/// command's whole tree, which is what Windows has in place of the group a host
/// signals, and then ends the child.
///
/// Allowed when the command is held in a job that ends every process it holds as
/// soon as the job closes, the child the command started is held in a job too,
/// and the child ended when the probe ended it. Refused when the sandbox will not
/// let the command start a child at all, or holds the command in no job.
///
/// Held in a job is not the containment on its own. A command can be held in a
/// job whoever started it put its host in, and a job that leaves its members
/// running when it closes ends no tree, so the probe reads the job's limits for
/// `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, the flag `srt-win` sets. A process holds
/// no handle of the job it is in, so the probe cannot name the sandbox's job and
/// tell it from an inherited one: `a_probe_outside_a_sandbox_is_not_held_in_a_kill_on_close_job`
/// holds that the host running the harness is no such job, which is what makes
/// the answer mean the sandbox.
///
/// A job holds every child of a process it holds unless that process may break
/// away, and `srt-win` gives the command a job that may not, so a child held in a
/// job is held in the job that ends the command too.
pub(super) fn signal_group() -> Outcome {
    let mut child = match start_child() {
        Ok(child) => child,
        Err(Error::Io(error)) if START_REFUSED.contains(&error.kind()) => return Ok(false),
        Err(error) => return Err(error),
    };
    let held = crate::win32::this_process_is_held().map_err(Error::Io)?
        && crate::win32::child_is_held(&child).map_err(Error::Io)?;
    let containment = held && crate::win32::this_job_kills_on_close().map_err(Error::Io)?;
    // End the child the way the platform ends a process on its own, which is
    // the only ending a process can ask for here: the job that ends the whole
    // tree belongs to the sandbox, and the command holds no handle to it.
    child.kill().map_err(Error::Io)?;
    let ended = child.wait().map_err(Error::Io)?;
    Ok(containment && ended.code() == Some(KILLED))
}

/// Asks `tasklist` whether a process runs, which is how a host tells whether a
/// session it attached to still holds.
///
/// The process it asks for is the probe's own, which is the one process the
/// probe knows runs: the question the case asks is whether a sandboxed command
/// can name a process at all.
///
/// Allowed when `tasklist` names it. Refused when `tasklist` cannot run at all,
/// which is the sandbox refusing the action, as macOS answers `EPERM` to `ps`.
pub(super) fn ps() -> Outcome {
    let pid = std::process::id();
    let filter = format!("PID eq {pid}");
    let asked = Command::new(TASKLIST)
        .args(["/FI", &filter, "/FO", "CSV", "/NH"])
        .output();
    match asked {
        Ok(output) => Ok(names_the_pid(&output.stdout, pid)),
        Err(error) if START_REFUSED.contains(&error.kind()) => Ok(false),
        Err(error) => Err(Error::Io(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Outside a sandbox the probe has no containment to report. A host that
    /// holds its own children in a kill-on-close job, a CI agent's or a
    /// terminal's, would have the probe report containment for a command no
    /// sandbox holds at all, which is the case passing for the regression it
    /// exists to catch.
    #[test]
    fn a_probe_outside_a_sandbox_is_not_held_in_a_kill_on_close_job() {
        let held = crate::win32::this_process_is_held().unwrap();
        assert!(!(held && crate::win32::this_job_kills_on_close().unwrap()));
    }

    /// `--hold` is what the probe's child runs as, and it ends on its own after
    /// the seconds it is given.
    #[test]
    fn a_hold_of_no_seconds_ends_at_once() {
        assert_eq!(probe(&[HOLD, "0"]), crate::probe::ALLOWED);
    }

    /// Runs the probe's action for `args` and returns its code.
    fn probe(args: &[&str]) -> u8 {
        let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
        crate::probe::run(&args, None, None, None)
    }
}
