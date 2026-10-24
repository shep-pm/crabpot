//! The Windows host's view of the sandbox before a command runs: its status
//! and the refusals that follow from it.

#[cfg(windows)]
mod ffi;
pub(crate) mod install;
mod status;

#[cfg(windows)]
use std::process::Command;

pub use status::{
    LoopbackMode, ProfileState, SetupVersion, UserState, WindowsStatus, refusal_for_exit,
};

use crate::StartError;

/// Reads what the install says about the sandbox, by running this binary
/// again as srt-win (`--srt-win`) for `user status`, `wfp status` and `profile
/// status`. None of them needs elevation.
///
/// A machine with no install is an `Ok` status whose
/// [`user`](WindowsStatus::user) is [`UserState::NotProvisioned`]: the
/// refusals are [`WindowsStatus::refusal`]'s, and [`windows_preflight`] makes
/// them. A host must call [`run_from_args`](crate::run_from_args) first thing
/// in `main`, or its own `main` runs in place of srt-win.
///
/// # Errors
///
/// [`StartError::UnsupportedPlatform`] off Windows,
/// [`StartError::CurrentExe`] when the path of this binary is unknown,
/// [`StartError::NotProvisioned`] or [`StartError::SeclogonDisabled`] when a
/// query exits 15 or 18, and [`StartError::StatusFailed`] when a query does
/// not run, fails otherwise, or prints what cannot be read.
pub fn windows_status() -> Result<WindowsStatus, StartError> {
    status::read(run_srt_win)
}

/// Checks what [`windows_status`] reads, and the session this process runs in,
/// against what a command needs, and returns the status when all of it holds.
///
/// # Errors
///
/// Every error of [`windows_status`], then [`StartError::SessionZero`] for the
/// services' session, and [`WindowsStatus::refusal`]'s.
pub fn windows_preflight() -> Result<WindowsStatus, StartError> {
    refuse_session_zero(current_session()?)?;
    let status = windows_status()?;
    match status.refusal() {
        Some(error) => Err(error),
        None => Ok(status),
    }
}

impl WindowsStatus {
    /// The error that stops a command from running under this status, if any:
    /// [`StartError::NotProvisioned`] for an install that is missing or of
    /// another setup version, [`StartError::SeclogonDisabled`], then
    /// [`StartError::NotDesktopSession`].
    #[must_use]
    pub fn refusal(&self) -> Option<StartError> {
        if self.user == UserState::NotProvisioned {
            Some(StartError::NotProvisioned)
        } else if !self.seclogon_runs {
            Some(StartError::SeclogonDisabled)
        } else if !self.in_desktop_session {
            Some(StartError::NotDesktopSession)
        } else {
            None
        }
    }
}

/// Refuses session 0, the services' session, by name.
fn refuse_session_zero(session: u32) -> Result<(), StartError> {
    if session == 0 {
        Err(StartError::SessionZero)
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn current_session() -> Result<u32, StartError> {
    ffi::session_of(std::process::id()).ok_or(StartError::StatusFailed {
        command: "ProcessIdToSessionId",
        code: None,
    })
}

#[cfg(not(windows))]
fn current_session() -> Result<u32, StartError> {
    Err(StartError::UnsupportedPlatform)
}

/// Runs this binary as `srt-win <command>` and returns what it printed.
#[cfg(windows)]
fn run_srt_win(command: &'static str) -> Result<String, StartError> {
    let failed = |code| StartError::StatusFailed { command, code };
    let exe = std::env::current_exe().map_err(|e| StartError::CurrentExe(e.kind()))?;
    let output = Command::new(exe)
        .arg(crabpot_windows::SRT_WIN_DISPATCH_ARG1)
        .args(command.split(' '))
        .output()
        .map_err(|_| failed(None))?;
    if output.status.success() {
        return String::from_utf8(output.stdout).map_err(|_| failed(None));
    }
    let code = output.status.code();
    Err(code.and_then(refusal_for_exit).unwrap_or(failed(code)))
}

#[cfg(not(windows))]
fn run_srt_win(command: &'static str) -> Result<String, StartError> {
    let _ = command;
    Err(StartError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status() -> WindowsStatus {
        WindowsStatus {
            user: UserState::Provisioned,
            setup_version: SetupVersion {
                installed: Some(3),
                expected: 3,
            },
            loopback: LoopbackMode::Closed,
            proxy_ports: None,
            profile: ProfileState::Current,
            seclogon_runs: true,
            in_desktop_session: true,
        }
    }

    #[test]
    fn session_zero_is_refused_by_name() {
        assert_eq!(refuse_session_zero(0), Err(StartError::SessionZero));
        assert_eq!(refuse_session_zero(1), Ok(()));
    }

    #[test]
    fn a_ready_status_has_no_refusal() {
        assert_eq!(status().refusal(), None);
    }

    #[test]
    fn each_missing_piece_has_its_own_refusal() {
        let cases = [
            (
                WindowsStatus {
                    user: UserState::NotProvisioned,
                    ..status()
                },
                StartError::NotProvisioned,
            ),
            (
                WindowsStatus {
                    seclogon_runs: false,
                    ..status()
                },
                StartError::SeclogonDisabled,
            ),
            (
                WindowsStatus {
                    in_desktop_session: false,
                    ..status()
                },
                StartError::NotDesktopSession,
            ),
        ];
        for (status, error) in cases {
            assert_eq!(status.refusal(), Some(error));
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn off_windows_there_is_no_status() {
        assert_eq!(windows_status(), Err(StartError::UnsupportedPlatform));
        assert_eq!(windows_preflight(), Err(StartError::UnsupportedPlatform));
    }
}
