//! One sandbox: the profile a command runs under, and the wrapping of a
//! command into it (ADR-0010).

use core::fmt;
use std::io;
use std::process::Command;

use crabpot_core::PathError;
use crabpot_core::config::Config;
#[cfg(target_os = "macos")]
use crabpot_core::proxy::{Proxy, username_for};
#[cfg(target_os = "macos")]
use crabpot_macos::env::Facts;

/// A sandbox started from a [`Config`]. Wrap each command that is to run in it
/// with [`Sandbox::command`], and drop it when they have all ended, since the
/// proxy stops with it.
#[derive(Debug)]
pub struct Sandbox {
    #[cfg(target_os = "macos")]
    profile: String,
    #[cfg(target_os = "macos")]
    facts: Facts,
    #[cfg(target_os = "macos")]
    proxy: Proxy,
}

impl Sandbox {
    /// Starts a sandbox that applies `config`.
    ///
    /// # Errors
    ///
    /// [`StartError::UnsupportedPlatform`] off macOS, where nothing
    /// confines a command yet, [`StartError::UnresolvedPath`] when a path
    /// in `config` cannot be made absolute, and [`StartError::Proxy`] when the
    /// proxy that carries its network cannot start.
    pub fn start(config: &Config) -> Result<Self, StartError> {
        #[cfg(target_os = "macos")]
        {
            let proxy = Proxy::start(
                &config.network.allowed_domains,
                &config.network.denied_domains,
                // A settings file that leaves the key out reads as not strict, as it
                // does upstream.
                config.network.strict_allowlist.unwrap_or(false),
            )
            .map_err(|e| StartError::Proxy(e.kind()))?;
            Ok(Self {
                profile: crabpot_macos::profile::render(
                    config,
                    Some(proxy.port()),
                    Some(proxy.socks_port()),
                )
                .map_err(StartError::UnresolvedPath)?,
                // The proxy listens on `127.0.0.1`, so the child reaches
                // loopback through it.
                facts: Facts::from_process(true),
                proxy,
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
    /// environment: a name the sandbox owns is set over the caller's, a name
    /// the caller owns is left to it, and the variables that point its clients
    /// at the proxy are set over them. It does not keep its standard
    /// streams, which a [`Command`] cannot be asked for, nor an
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
            for (key, value) in crabpot_macos::env::vars(&self.facts.for_command(command)) {
                wrapped.env(key, value);
            }
            let line = core::iter::once(command.get_program())
                .chain(command.get_args())
                .map(|word| word.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ");
            let username = username_for(&line);
            let token = self.proxy.token();
            for (name, value) in crabpot_macos::env::http::vars(self.proxy.port(), &username, token)
                .into_iter()
                .chain(crabpot_macos::env::socks::vars(
                    self.proxy.socks_port(),
                    &username,
                    token,
                    // The HTTP proxy is always there, so ssh goes through it.
                    true,
                ))
            {
                wrapped.env(name, value);
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
    /// A path in the settings starts with `~` and `HOME` is not set, or is
    /// relative and there is no working directory. A rule written for it would
    /// be dropped.
    UnresolvedPath(PathError),
    /// The proxy could not start: no token, no port, or no thread to run on.
    Proxy(io::ErrorKind),
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => write!(f, "only macOS has a sandbox yet"),
            Self::UnresolvedPath(error) => write!(f, "{error}"),
            Self::Proxy(kind) => write!(f, "cannot start the proxy: {kind}"),
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

    #[cfg(target_os = "macos")]
    #[test]
    fn a_wrapped_command_is_pointed_at_the_proxy() {
        let sandbox = Sandbox::start(&Config::default()).unwrap();
        let wrapped = sandbox.command(&Command::new("true")).unwrap();

        let proxy = wrapped
            .get_envs()
            .find(|(name, _)| *name == "HTTPS_PROXY")
            .and_then(|(_, value)| value)
            .expect("HTTPS_PROXY is set")
            .to_string_lossy();
        assert!(
            proxy.ends_with(&format!("@localhost:{}", sandbox.proxy.port())),
            "{proxy}"
        );
        assert!(proxy.starts_with("http://srt.dHJ1ZQ%3D%3D:"), "{proxy}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_wrapped_command_is_pointed_at_the_socks_proxy() {
        let sandbox = Sandbox::start(&Config::default()).unwrap();
        let wrapped = sandbox.command(&Command::new("true")).unwrap();

        let ftp = wrapped
            .get_envs()
            .find(|(name, _)| *name == "FTP_PROXY")
            .and_then(|(_, value)| value)
            .expect("FTP_PROXY is set")
            .to_string_lossy();
        assert!(ftp.starts_with("socks5h://srt.dHJ1ZQ%3D%3D:"), "{ftp}");
        assert!(
            ftp.ends_with(&format!("@localhost:{}", sandbox.proxy.socks_port())),
            "{ftp}"
        );
        assert_ne!(sandbox.proxy.socks_port(), sandbox.proxy.port());
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
            .arg(r#"printf '%s\n' "$SANDBOX_RUNTIME" "$TMPDIR" "$CALLER" "$JAVA_TOOL_OPTIONS""#);
        probe.env("CALLER", "kept");
        probe.env("TMPDIR", "/caller/tmp");
        probe.env("JAVA_TOOL_OPTIONS", "-Xmx2g");

        let output = sandbox.command(&probe).unwrap().output().unwrap();
        assert!(output.status.success(), "{output:?}");
        let text = String::from_utf8(output.stdout).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "1", "SANDBOX_RUNTIME");
        assert_ne!(lines[1], "/caller/tmp", "the sandbox's TMPDIR wins");
        assert_eq!(lines[2], "kept", "the caller's own variable survives");
        assert_eq!(
            lines[3], "-Xmx2g -Djava.net.preferIPv4Stack=true",
            "the flag joins the caller's own value, since the proxy is on loopback"
        );
    }
}
