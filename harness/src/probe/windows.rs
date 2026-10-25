//! The Windows form of the probes that name a process, a process group and a
//! Unix socket.
//!
//! Windows has no process groups. `srt-win` holds each sandboxed command in a
//! job object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`
//! (`crates/crabpot-windows/srt-win/src/job.rs`), which ends the command and
//! every process the command started as soon as the command ends, and
//! `crates/crabpot/src/windows/` never touches it. `signal-group` measures that
//! containment in its place: that the command is held in a job, and so is a
//! child the command starts inside the sandbox.
//!
//! `ps` names a process with `tasklist`, and `bind-unix` with the `AF_UNIX`
//! family Windows 10 and later carries, which `std` has no form of: see
//! [`crate::win32`].

use std::io::ErrorKind;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use super::{Error, Outcome, judge, socket_path_too_long};

/// The program that names a process and how it runs, which a host asks when it
/// decides whether a session it attached to still holds.
const TASKLIST: &str = "tasklist";

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

/// Starts a child inside the sandbox and asks whether the sandbox holds it the
/// way it holds the command, which is how the platform ends a command's whole
/// tree, and then ends the child.
///
/// Allowed when the command and the child it started are both held in a job,
/// and the child ended when the probe ended it. Refused when the sandbox will
/// not let the command start a child at all, or leaves one it started outside
/// the containment that ends the command.
///
/// A job holds every child of a process it holds unless that process may break
/// away, and `srt-win` gives the command a job that may not, so a child held in
/// some job is held in the job that ends the command too.
pub(super) fn signal_group() -> Outcome {
    let mut child = match start_child() {
        Ok(child) => child,
        Err(Error::Io(error)) if START_REFUSED.contains(&error.kind()) => return Ok(false),
        Err(error) => return Err(error),
    };
    let held = crate::win32::this_process_is_held().map_err(Error::Io)?
        && crate::win32::child_is_held(&child).map_err(Error::Io)?;
    // End the child the way the platform ends a process on its own, which is
    // the only ending a process can ask for here: the job that ends the whole
    // tree belongs to the sandbox, and the command holds no handle to it.
    child.kill().map_err(Error::Io)?;
    let ended = child.wait().map_err(Error::Io)?;
    Ok(held && ended.code() == Some(KILLED))
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

/// Whether `tasklist`'s output names `pid`.
///
/// `/FO CSV /NH` gives one line per process with every field quoted, and the pid
/// is the second of them: `"probe.exe","1234","Console","1","3,072 K"`. A quoted
/// pid between two commas is what no other column can spell: the memory column
/// ends in ` K"`, and the session number carries no quotes. Where nothing
/// matches its filter, `tasklist` prints `INFO: No tasks are running which match
/// the specified criteria.`, which names no pid.
fn names_the_pid(stdout: &[u8], pid: u32) -> bool {
    let needle = format!(",\"{pid}\",");
    stdout
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The line `tasklist` gives for a match, with a memory column that holds a
    /// comma of its own, and the line it gives for none.
    #[test]
    fn tasklist_output_names_the_pid_and_no_other_number_in_it() {
        let line = b"\"probe.exe\",\"1234\",\"Console\",\"1\",\"3,072 K\"\r\n";
        assert!(names_the_pid(line, 1234));
        assert!(!names_the_pid(line, 3072));
        assert!(!names_the_pid(line, 1));
        assert!(!names_the_pid(
            b"INFO: No tasks are running which match the specified criteria.\r\n",
            1234
        ));
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
