//! The Windows host's view of the sandbox before a command runs: its status
//! and the refusals that follow from it.

// The session's pieces are built and tested on every host, and used on Windows.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) mod command;
#[cfg(windows)]
mod ffi;
#[cfg_attr(not(windows), allow(dead_code))]
mod held;
pub(crate) mod install;
#[cfg_attr(not(windows), allow(dead_code))]
mod plan;
#[cfg_attr(not(windows), allow(dead_code))]
mod runner;
#[cfg_attr(not(windows), allow(dead_code))]
mod srt;
#[cfg_attr(not(windows), allow(dead_code))]
mod start;
mod status;
#[cfg_attr(not(windows), allow(dead_code))]
mod wfp;

#[cfg(windows)]
use std::process::Command;
#[cfg(windows)]
use std::sync::Arc;

use crabpot_core::config::Config;

#[cfg(windows)]
pub(crate) use start::Session;
pub use status::{
    LoopbackMode, ProfileExclusions, ProfileState, SetupVersion, UserState, WindowsStatus,
    refusal_for_exit,
};

use crate::StartError;

/// Reads what the install says about the sandbox, by running this binary
/// again as srt-win (`--srt-win`) for `user status`, `wfp status` and `profile
/// status`, under the default WFP sublayer. None of them needs elevation.
///
/// [`windows_status_for`] reads the status of the install a
/// [`Config`]'s `windows` settings name.
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
    windows_status_for(&Config::default())
}

/// [`windows_status`] for the install `config`'s `windows.sublayerGuid` names,
/// as upstream's status call reads it.
///
/// # Errors
///
/// Those of [`windows_status`].
pub fn windows_status_for(config: &Config) -> Result<WindowsStatus, StartError> {
    status::read(config.windows.sublayer_guid.as_deref(), run_srt_win)
}

/// Checks what [`windows_status`] reads, and the session this process runs in,
/// against what a command needs, and returns the status when all of it holds.
///
/// # Errors
///
/// Every error of [`windows_status`], then [`StartError::SessionZero`] for the
/// services' session, and [`WindowsStatus::refusal`]'s.
pub fn windows_preflight() -> Result<WindowsStatus, StartError> {
    windows_preflight_for(&Config::default())
}

/// [`windows_preflight`] for the install `config`'s `windows.sublayerGuid`
/// names.
///
/// # Errors
///
/// Those of [`windows_preflight`].
pub fn windows_preflight_for(config: &Config) -> Result<WindowsStatus, StartError> {
    refuse_session_zero(current_session()?)?;
    let status = windows_status_for(config)?;
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
        stderr: String::new(),
    })
}

#[cfg(not(windows))]
fn current_session() -> Result<u32, StartError> {
    Err(StartError::UnsupportedPlatform)
}

/// The sandbox users the fence has been verified for in this process.
#[cfg(windows)]
static VERIFIED: start::Verified = start::Verified::new();

/// Starts a Windows session for `config`: the status checks, then
/// [`start::start_with`] through this binary run again as srt-win.
///
/// # Errors
///
/// Those of [`windows_preflight`] and [`start::start_with`], and
/// [`StartError::CurrentExe`] when the path of this binary is unknown.
#[cfg(windows)]
pub(crate) fn start_session(config: &Config) -> Result<Session, StartError> {
    let status = windows_preflight_for(config)?;
    let exe = std::env::current_exe().map_err(|e| StartError::CurrentExe(e.kind()))?;
    start::start_with(
        start::Host {
            srt: Arc::new(srt::Process),
            holder: std::process::id(),
            runner: runner::Runner::of(exe, Some(&status)),
        },
        &VERIFIED,
        &status,
        config,
    )
}

/// Runs this binary as `srt-win <command>` and returns what it printed.
#[cfg(windows)]
fn run_srt_win(command: &'static str, extra: &[&str]) -> Result<String, StartError> {
    let failed = |code, stderr: &[u8]| StartError::StatusFailed {
        command,
        code,
        stderr: String::from_utf8_lossy(stderr).trim().to_owned(),
    };
    let exe = std::env::current_exe().map_err(|e| StartError::CurrentExe(e.kind()))?;
    let output = Command::new(exe)
        .arg(crabpot_windows::SRT_WIN_DISPATCH_ARG1)
        .args(command.split(' '))
        .args(extra)
        .output()
        .map_err(|_| failed(None, &[]))?;
    if output.status.success() {
        return String::from_utf8(output.stdout).map_err(|_| failed(None, &output.stderr));
    }
    let code = output.status.code();
    Err(code
        .and_then(refusal_for_exit)
        .unwrap_or_else(|| failed(code, &output.stderr)))
}

#[cfg(not(windows))]
fn run_srt_win(command: &'static str, extra: &[&str]) -> Result<String, StartError> {
    let _ = (command, extra);
    Err(StartError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status() -> WindowsStatus {
        WindowsStatus {
            user: UserState::Provisioned,
            sandbox_sid: Some("S-1-5-21-1".to_owned()),
            sandbox_group_sid: Some("S-1-5-21-9".to_owned()),
            real_user_sid: Some("S-1-5-21-2".to_owned()),
            session_user_sid: Some("S-1-5-21-2".to_owned()),
            setup_version: SetupVersion {
                installed: Some(3),
                expected: 3,
            },
            loopback: LoopbackMode::Closed,
            proxy_ports: None,
            profile: ProfileState::Current,
            profile_exclusions: ProfileExclusions::default(),
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
