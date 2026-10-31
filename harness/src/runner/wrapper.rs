//! What running a wrapper reported: the status it ended with, and the code its
//! probe said it exited with, which is there only if the probe ran.

use std::process::{Command, Stdio};

use crate::case::Env;
use crate::probe;

use super::Error;

/// What a wrapper did: the status it exited with, and the code its probe
/// reported, which is there only if the probe ran.
struct Wrapped {
    status: i32,
    reported: Option<u8>,
}

/// Gives `command` the harness's own pid in [`probe::HARNESS_PID`], which the
/// `ps-outside` probe looks for from inside the sandbox.
pub(super) fn export_harness_pid(command: &mut Command) {
    command.env(probe::HARNESS_PID, std::process::id().to_string());
}

/// Gives `command` the host environment the case sets.
pub(super) fn export_env(command: &mut Command, env: &Env) {
    command.envs(env);
}

/// Runs the wrapper to its end. Its stderr is inherited, so a failing run
/// leaves its diagnostics in the log; it is never compared.
fn wrapped(mut command: Command, runner: &'static str) -> Result<Wrapped, Error> {
    let output = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .map_err(Error::Io)?;
    let status = output.status.code().ok_or(Error::Signalled(runner))?;
    let reported = String::from_utf8_lossy(&output.stdout)
        .lines()
        .rev()
        .find_map(|line| line.strip_prefix(probe::REPORT)?.parse::<u8>().ok());
    Ok(Wrapped { status, reported })
}

/// Runs the wrapper to its end and returns the code its probe reported, which
/// must be the wrapper's exit status.
pub(super) fn exit_code(command: Command, runner: &'static str) -> Result<u8, Error> {
    let Wrapped { status, reported } = wrapped(command, runner)?;
    match reported {
        Some(code) if i32::from(code) == status => Ok(code),
        _ => Err(Error::Unreported { runner, status }),
    }
}

/// Runs the wrapper to its end and says whether it exited with `refused`
/// without its probe reporting anything.
pub(super) fn refusal(command: Command, runner: &'static str, refused: i32) -> Result<bool, Error> {
    match wrapped(command, runner)? {
        Wrapped {
            reported: Some(_), ..
        } => Ok(false),
        Wrapped { status, .. } if status == refused => Ok(true),
        Wrapped { status, .. } => Err(Error::Unreported { runner, status }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn a_wrapper_command_carries_the_environment_the_case_sets() {
        let mut command = Command::new("probe");
        export_env(
            &mut command,
            &Env::from([("CLAUDE_CODE_TMPDIR".to_owned(), "/r/fresh".to_owned())]),
        );
        let exported = command
            .get_envs()
            .find(|(name, _)| *name == OsStr::new("CLAUDE_CODE_TMPDIR"))
            .and_then(|(_, value)| value);
        assert_eq!(exported, Some(OsStr::new("/r/fresh")));
    }

    #[test]
    fn a_wrapper_command_carries_the_harness_pid() {
        let mut command = Command::new("probe");
        export_harness_pid(&mut command);
        let pid = std::process::id().to_string();
        let exported = command
            .get_envs()
            .find(|(name, _)| *name == OsStr::new(probe::HARNESS_PID))
            .and_then(|(_, value)| value);
        assert_eq!(exported, Some(OsStr::new(&pid)));
    }
}
