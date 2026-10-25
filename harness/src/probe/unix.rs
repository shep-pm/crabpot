//! The Unix form of the probes that name a socket, a process group and a
//! process: a Unix socket at a path, a signal to a whole process group, and
//! `ps`.
//!
//! Each has a Windows form of its own, which measures what the platform has in
//! place of the group, the `ps` call and the socket: see [`super::windows`].

use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, Stdio};

use crate::signal;

use super::{Error, Outcome, judge, socket_path_too_long};

/// A socket the sandbox will not let the command use answers `EPERM`, which is
/// what a refused `bind` or `connect` on `AF_UNIX` gives back.
const UNIX_BIND_REFUSED: &[io::ErrorKind] = &[io::ErrorKind::PermissionDenied];

/// A dial of a socket file nobody is listening on is answered, and an answer is
/// not a refusal.
const UNIX_CONNECT_REFUSED: &[io::ErrorKind] = &[
    io::ErrorKind::PermissionDenied,
    io::ErrorKind::ConnectionRefused,
];

/// Binds a Unix socket at `path`, which is how a command takes a path the
/// profile lists for it.
pub(super) fn bind_unix(path: &str) -> Outcome {
    if socket_path_too_long(path) {
        return Ok(false);
    }
    judge(UnixListener::bind(path).map(drop), UNIX_BIND_REFUSED)
}

/// Dials the Unix socket at `path`, which is how a command reaches a socket
/// the profile lists for it.
pub(super) fn connect_unix(path: &str) -> Outcome {
    if socket_path_too_long(path) {
        return Ok(false);
    }
    judge(UnixStream::connect(path).map(drop), UNIX_CONNECT_REFUSED)
}

/// The program the probe starts as the member of the group it means to signal.
pub(super) const SLEEP: &str = "/bin/sleep";

/// The program that names a process and how it runs, which a host asks when it
/// decides whether a session it attached to still holds.
const PS: &str = "/bin/ps";

/// How long the probe's child lives on its own, in seconds. A sandbox that
/// refuses both the group signal and the signal to the child alone still leaves
/// nothing behind once this runs out.
const CHILD_LIFE: &str = "5";

/// Starts `sleep` as the leader of a process group of its own, which is how a
/// host leads a group it means to signal: the child's pid is the group's.
fn start_group() -> Result<Child, Error> {
    Command::new(SLEEP)
        .arg(CHILD_LIFE)
        .process_group(0)
        .stdin(Stdio::null())
        .spawn()
        .map_err(Error::Io)
}

/// Signals the process group the probe started, and asks whether it took the
/// signal.
///
/// Allowed when the group died by it, refused when the sandbox would not let a
/// group signal through, which is what a host meets when it ends a call it
/// started inside a worker.
pub(super) fn signal_group() -> Outcome {
    let mut child = start_group()?;
    let group = child.id();
    match signal::signal_group(group, signal::TERM) {
        Ok(()) => {
            let ended = child.wait().map_err(Error::Io)?;
            Ok(ended.signal() == Some(signal::TERM as i32))
        }
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            // The group is out of reach. End the child on its own so the run
            // leaves nothing behind, and report what the group signal answered.
            let _ = child.kill();
            let _ = child.wait();
            Ok(false)
        }
        Err(error) => Err(Error::Io(error)),
    }
}

/// Asks `ps` whether a process runs, which is how a host tells whether a
/// session it attached to still holds.
///
/// Allowed when `ps` names the process. Refused when `ps` cannot run at all or
/// runs and names nothing: macOS answers `EPERM` to a sandboxed command that
/// tries to run it, which is the sandbox refusing the action and not the probe
/// failing to run.
pub(super) fn ps() -> Outcome {
    let mut child = start_group()?;
    let asked = ps_names(child.id());
    // Whatever `ps` answered, end the child the probe started.
    let _ = child.kill();
    let _ = child.wait();
    asked
}

/// Asks `ps` whether the harness's own process runs, which it does not from
/// inside a pid namespace of the sandbox's own: `ps` lists the sandbox's pids
/// and no others.
///
/// Allowed when `ps` names the process, which is the sandbox showing what runs
/// outside it. Refused when it does not.
pub(super) fn ps_outside(harness_pid: Option<&str>) -> Outcome {
    let pid = harness_pid
        .and_then(|pid| pid.parse().ok())
        .ok_or_else(|| Error::BadHarnessPid(harness_pid.map(str::to_owned)))?;
    ps_names(pid)
}

/// Whether `ps` names the process `pid`.
fn ps_names(pid: u32) -> Outcome {
    let asked = Command::new(PS)
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output();
    match asked {
        Ok(output) => {
            Ok(output.status.success()
                && output.stdout.iter().any(|byte| !byte.is_ascii_whitespace()))
        }
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => Ok(false),
        Err(error) => Err(Error::Io(error)),
    }
}
