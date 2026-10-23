//! One sandbox: the profile a command runs under, and the wrapping of a
//! command into it (ADR-0010).

use core::fmt;
use std::process::Command;

use crabpot_core::config::Config;
#[cfg(target_os = "macos")]
use crabpot_macos::env::Facts;

/// A sandbox started from a [`Config`]. Wrap each command that is to run in it
/// with [`Sandbox::command`], and drop it when they have all ended, since the
/// proxies a later release adds stop with it.
#[derive(Debug)]
pub struct Sandbox {
    #[cfg(target_os = "macos")]
    profile: String,
    #[cfg(target_os = "macos")]
    facts: Facts,
}

impl Sandbox {
    /// Starts a sandbox that applies `config`.
    ///
    /// # Errors
    ///
    /// [`StartError::UnsupportedPlatform`] off macOS, where nothing
    /// confines a command yet.
    pub fn start(config: &Config) -> Result<Self, StartError> {
        #[cfg(target_os = "macos")]
        {
            Ok(Self {
                profile: crabpot_macos::profile::render(config),
                // No config crabpot accepts yet lets a command reach loopback:
                // allowLocalBinding is refused, and no proxy port is open.
                facts: Facts::from_process(false),
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = config;
            Err(StartError::UnsupportedPlatform)
        }
    }

    /// Wraps `command` into one that runs it inside this sandbox, to spawn in
    /// its place.
    ///
    /// The wrapped command keeps `command`'s program, arguments, working
    /// directory and environment changes, and gains the sandbox's own
    /// environment over them. It does not keep its standard streams, which a
    /// [`Command`] cannot be asked for, nor an
    /// [`env_clear`](Command::env_clear).
    ///
    /// # Errors
    ///
    /// [`WrapError::Missing`] when the machine has no `sandbox-exec`, and
    /// [`WrapError::UnsupportedPlatform`] off macOS.
    pub fn command(&self, command: &Command) -> Result<Command, WrapError> {
        #[cfg(target_os = "macos")]
        {
            use std::ffi::OsString;
            use std::path::Path;

            use crabpot_macos::argv::{SANDBOX_EXEC, sandbox_exec};

            if !Path::new(SANDBOX_EXEC).exists() {
                return Err(WrapError::Missing);
            }
            let mut wrapped = Command::new(SANDBOX_EXEC);
            wrapped.args(sandbox_exec(
                &self.profile,
                command.get_program(),
                command.get_args().map(OsString::from),
            ));
            if let Some(dir) = command.get_current_dir() {
                wrapped.current_dir(dir);
            }
            for (key, value) in command.get_envs() {
                match value {
                    Some(value) => wrapped.env(key, value),
                    None => wrapped.env_remove(key),
                };
            }
            for (key, value) in crabpot_macos::env::vars(&self.facts) {
                wrapped.env(key, value);
            }
            Ok(wrapped)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = command;
            Err(WrapError::UnsupportedPlatform)
        }
    }
}

/// Why a sandbox did not start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// A platform or a proxy that fails to start adds a variant without breaking a
// caller's `match`.
#[non_exhaustive]
pub enum StartError {
    /// The platform has no sandbox yet: only macOS has one.
    UnsupportedPlatform,
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => write!(f, "only macOS has a sandbox yet"),
        }
    }
}

impl core::error::Error for StartError {}

/// Why a command was not wrapped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// A sandbox that can refuse a command for a new reason adds a variant without
// breaking a caller's `match`.
#[non_exhaustive]
pub enum WrapError {
    /// There is no `/usr/bin/sandbox-exec` to run the command under.
    Missing,
    /// The platform has no sandbox yet: only macOS has one.
    UnsupportedPlatform,
}

impl fmt::Display for WrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => write!(f, "/usr/bin/sandbox-exec is missing"),
            Self::UnsupportedPlatform => write!(f, "only macOS has a sandbox yet"),
        }
    }
}

impl core::error::Error for WrapError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn a_command_runs_and_is_refused_a_write() {
        let sandbox = Sandbox::start(&Config::default()).unwrap();

        let mut echo = Command::new("echo");
        echo.arg("hello");
        let output = sandbox.command(&echo).unwrap().output().unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(output.stdout, b"hello\n");

        let target = std::env::temp_dir().join(format!("crabpot-refused-{}", std::process::id()));
        let mut write = Command::new("sh");
        write.arg("-c").arg("echo x > \"$0\"").arg(&target);
        let status = sandbox.command(&write).unwrap().status().unwrap();
        assert!(!status.success(), "the write went through");
        assert!(!target.exists(), "the refused write left a file");
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn a_sandbox_does_not_start_off_macos() {
        assert_eq!(
            Sandbox::start(&Config::default()).unwrap_err(),
            StartError::UnsupportedPlatform
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn command_carries_the_env() {
        let sandbox = Sandbox::start(&Config::default()).unwrap();

        let mut probe = Command::new("sh");
        probe
            .arg("-c")
            .arg(r#"printf '%s\n' "$SANDBOX_RUNTIME" "$TMPDIR" "$CALLER""#);
        probe.env("CALLER", "kept");
        probe.env("TMPDIR", "/caller/tmp");

        let output = sandbox.command(&probe).unwrap().output().unwrap();
        assert!(output.status.success(), "{output:?}");
        let text = String::from_utf8(output.stdout).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "1", "SANDBOX_RUNTIME");
        assert_ne!(lines[1], "/caller/tmp", "the sandbox's TMPDIR wins");
        assert_eq!(lines[2], "kept", "the caller's own variable survives");
    }
}
