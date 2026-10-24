//! One sandbox: the profile or the bwrap words a command runs under, and the
//! wrapping of a command into it (ADR-0010).

use core::fmt;
use std::io;
use std::process::Command;
#[cfg(target_os = "linux")]
use std::{
    ffi::OsString,
    os::fd::OwnedFd,
    path::PathBuf,
    sync::{Mutex, PoisonError},
};

use crabpot_core::PathError;
use crabpot_core::config::Config;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use crabpot_core::proxy::Proxy;
#[cfg(target_os = "macos")]
use crabpot_core::proxy::username_for;
#[cfg(target_os = "macos")]
use crabpot_macos::env::Facts;

#[cfg(target_os = "linux")]
use crate::args::{HELPER_FLAG, HelperMode};

/// A sandbox started from a [`Config`]. Wrap each command that is to run in it
/// with [`Sandbox::command`], and drop it when they have all ended, since the
/// proxy stops with it.
#[derive(Debug)]
pub struct Sandbox {
    #[cfg(target_os = "macos")]
    profile: String,
    /// The bwrap words, `bwrap` first, that each command's own words follow.
    #[cfg(target_os = "linux")]
    words: Vec<OsString>,
    /// The host paths bwrap makes for the words' denies, which go when the
    /// sandbox drops.
    #[cfg(target_os = "linux")]
    #[expect(dead_code, reason = "held to be removed on drop")]
    mount_points: crabpot_linux::fs::MountPoints,
    /// This binary, which bwrap runs as the helper in front of each command.
    #[cfg(target_os = "linux")]
    helper: PathBuf,
    /// The args files of the commands wrapped so far, each held open for as
    /// long as the command may run, which is until the sandbox drops.
    #[cfg(target_os = "linux")]
    args_files: Mutex<Vec<OwnedFd>>,
    #[cfg(target_os = "macos")]
    facts: Facts,
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[cfg_attr(
        target_os = "linux",
        expect(dead_code, reason = "held to keep the proxy running")
    )]
    proxy: Proxy,
}

impl Sandbox {
    /// Starts a sandbox that applies `config`.
    ///
    /// # Errors
    ///
    /// [`StartError::UnsupportedPlatform`] off macOS and Linux, where nothing
    /// confines a command yet, [`StartError::UnresolvedPath`] when a path
    /// in `config` cannot be made absolute, and [`StartError::Proxy`] when the
    /// proxy that carries its network cannot start. On Linux the bwrap checks
    /// run first: [`StartError::Missing`] when there is no executable `bwrap`
    /// on `PATH`, and [`StartError::Uid0WithoutSetfcap`] for uid 0 without
    /// `CAP_SETFCAP`, and [`StartError::CurrentExe`] when the path of this
    /// binary is unknown. A `bwrap` older than 0.5.0 is a warning on stderr.
    pub fn start(config: &Config) -> Result<Self, StartError> {
        #[cfg(target_os = "linux")]
        let bwrap = crabpot_linux::deps::check_here()?;
        #[cfg(target_os = "linux")]
        let helper = std::env::current_exe().map_err(|e| StartError::CurrentExe(e.kind()))?;
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            let proxy = Proxy::start(
                &config.network.allowed_domains,
                &config.network.denied_domains,
                config
                    .network
                    .denied_resolved_addresses
                    .as_deref()
                    .unwrap_or_default(),
                // A settings file that leaves the key out reads as not strict, as it
                // does upstream.
                config.network.strict_allowlist.unwrap_or(false),
                config.network.mitm_proxy.as_ref(),
            )
            .map_err(|e| StartError::Proxy(e.kind()))?;
            #[cfg(target_os = "macos")]
            {
                let proxy_port = proxy.port();
                Ok(Self {
                    profile: crabpot_macos::profile::render(
                        config,
                        Some(proxy_port),
                        Some(proxy.socks_port()),
                    )
                    .map_err(StartError::UnresolvedPath)?,
                    // The proxy listens on `127.0.0.1`, and `allowLocalBinding`
                    // opens every loopback port, so either one is enough for the
                    // child to reach loopback.
                    facts: Facts::for_sandbox(config, Some(proxy_port)),
                    proxy,
                })
            }
            #[cfg(target_os = "linux")]
            {
                let wrapped = crabpot_linux::wrap::words(
                    &bwrap,
                    config,
                    &helper,
                    crabpot_linux::deps::is_root_with_setfcap_here(),
                )
                .map_err(StartError::UnresolvedPath)?;
                Ok(Self {
                    words: wrapped.words,
                    mount_points: wrapped.mount_points,
                    helper,
                    args_files: Mutex::new(Vec::new()),
                    proxy,
                })
            }
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = config;
            Err(StartError::UnsupportedPlatform)
        }
    }

    /// Wraps `command` into one that runs it inside this sandbox, to spawn in
    /// its place.
    ///
    /// On Linux, bwrap runs this binary again inside the sandbox as the helper,
    /// and the helper runs `command`. A host must call
    /// [`run_from_args`](crate::run_from_args) first thing in `main`, or its
    /// own `main` runs inside the sandbox in place of the command.
    ///
    /// The wrapped command keeps `command`'s program, arguments, working
    /// directory and environment changes. It does not keep its standard
    /// streams, which a [`Command`] cannot be asked for, nor an
    /// [`env_clear`](Command::env_clear).
    ///
    /// On macOS it gains the sandbox's own environment: a name the sandbox owns
    /// is set over the caller's, a name the caller owns is left to it, and the
    /// variables that point its clients at the proxy are set over them. On
    /// Linux the sandbox sets none yet.
    ///
    /// # Errors
    ///
    /// [`WrapError::Missing`] when the machine has no `sandbox-exec`,
    /// [`WrapError::Bwrap`] when the command cannot be put in a bwrap line, and
    /// [`WrapError::UnsupportedPlatform`] off macOS and Linux.
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
            carry_over(command, &mut wrapped);
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
            let http = crabpot_macos::env::http::vars(self.proxy.port(), &username, token);
            let socks = crabpot_macos::env::socks::vars(self.proxy.socks_port(), &username, token);
            let ssh = crabpot_macos::env::ssh::vars(
                self.proxy.port(),
                self.proxy.socks_port(),
                &username,
                token,
            );
            for (name, value) in http.into_iter().chain(socks).chain(ssh) {
                wrapped.env(name, value);
            }
            Ok(wrapped)
        }
        #[cfg(target_os = "linux")]
        {
            let mut words = vec![
                self.helper.clone().into_os_string(),
                OsString::from(HELPER_FLAG),
                OsString::from(HelperMode::Init.word()),
                command.get_program().to_owned(),
            ];
            words.extend(command.get_args().map(OsString::from));
            let rendered = crabpot_linux::argv::render(&self.words, &words, &std::env::temp_dir())
                .map_err(|e| WrapError::Bwrap(e.to_string()))?;
            let mut wrapped = rendered.command;
            carry_over(command, &mut wrapped);
            if let Some(args_file) = rendered.args_file {
                self.args_files
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(args_file);
            }
            Ok(wrapped)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = command;
            Err(WrapError::UnsupportedPlatform)
        }
    }
}

/// Gives `wrapped` the working directory and the environment changes `command`
/// asks for.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn carry_over(command: &Command, wrapped: &mut Command) {
    if let Some(dir) = command.get_current_dir() {
        wrapped.current_dir(dir);
    }
    for (key, value) in command.get_envs() {
        match value {
            Some(value) => wrapped.env(key, value),
            None => wrapped.env_remove(key),
        };
    }
}

/// Why a sandbox did not start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// A platform or a proxy that fails to start adds a variant without breaking a
// caller's `match`.
#[non_exhaustive]
pub enum StartError {
    /// The platform has no sandbox yet: only macOS and Linux have one.
    UnsupportedPlatform,
    /// A path in the settings starts with `~` and `HOME` is not set, or is
    /// relative and there is no working directory. A rule written for it would
    /// be dropped.
    UnresolvedPath(PathError),
    /// The proxy could not start: no token, no port, or no thread to run on.
    Proxy(io::ErrorKind),
    /// `tool` is not on `PATH`, or is there but not executable.
    Missing {
        /// The program's name.
        tool: &'static str,
    },
    /// The process is uid 0 without `CAP_SETFCAP`, and bwrap cannot make a
    /// user namespace.
    Uid0WithoutSetfcap,
    /// The path of this binary is unknown, and bwrap needs it to run the
    /// helper.
    CurrentExe(io::ErrorKind),
}

#[cfg(target_os = "linux")]
impl From<crabpot_linux::deps::DepsError> for StartError {
    fn from(error: crabpot_linux::deps::DepsError) -> Self {
        use crabpot_linux::deps::DepsError;

        match error {
            DepsError::Missing { tool } => Self::Missing { tool },
            DepsError::Uid0WithoutSetfcap => Self::Uid0WithoutSetfcap,
            // `DepsError` is `non_exhaustive`: a check this build does not
            // know of is a missing dependency it cannot name.
            _ => Self::Missing { tool: "bwrap" },
        }
    }
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => write!(f, "only macOS and Linux have a sandbox yet"),
            Self::UnresolvedPath(error) => write!(f, "{error}"),
            Self::Proxy(kind) => write!(f, "cannot start the proxy: {kind}"),
            Self::Missing { tool } => write!(f, "{tool} is missing or not executable"),
            Self::Uid0WithoutSetfcap => write!(
                f,
                "running as uid 0 without CAP_SETFCAP, so bwrap cannot make a user namespace"
            ),
            Self::CurrentExe(kind) => write!(f, "cannot find this binary: {kind}"),
        }
    }
}

impl core::error::Error for StartError {}

/// Why a command was not wrapped.
#[derive(Debug, Clone, PartialEq, Eq)]
// A sandbox that can refuse a command for a new reason adds a variant without
// breaking a caller's `match`.
#[non_exhaustive]
pub enum WrapError {
    /// There is no `/usr/bin/sandbox-exec` to run the command under.
    Missing,
    /// The command cannot be put in a bwrap line: it has too many words or
    /// bytes, a word holds a NUL byte, or the file the flags move to when the
    /// line is long could not be opened.
    Bwrap(String),
    /// The platform has no sandbox yet: only macOS and Linux have one.
    UnsupportedPlatform,
}

impl fmt::Display for WrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => write!(f, "/usr/bin/sandbox-exec is missing"),
            Self::Bwrap(reason) => write!(f, "cannot build the bwrap command: {reason}"),
            Self::UnsupportedPlatform => write!(f, "only macOS and Linux have a sandbox yet"),
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
        assert_eq!(
            sandbox.proxy.socks_port(),
            sandbox.proxy.port(),
            "one port serves both protocols"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_command_is_wrapped_in_bwrap() {
        let sandbox = match Sandbox::start(&Config::default()) {
            Ok(sandbox) => sandbox,
            // The machine has no bwrap to wrap a command in.
            Err(StartError::Missing { .. } | StartError::Uid0WithoutSetfcap) => return,
            Err(error) => panic!("{error}"),
        };
        let mut echo = Command::new("echo");
        echo.arg("hello").env("CALLER", "kept").current_dir("/");

        let wrapped = sandbox.command(&echo).unwrap();

        assert!(wrapped.get_program().to_string_lossy().ends_with("bwrap"));
        let args: Vec<_> = wrapped
            .get_args()
            .map(|arg| arg.to_string_lossy())
            .collect();
        assert_eq!(args[..3], ["--ro-bind", "/", "/"]);
        let helper = std::env::current_exe().unwrap();
        let helper = helper.to_string_lossy();
        assert_eq!(
            args[args.len() - 6..],
            ["--", &*helper, "--crabpot-helper", "init", "echo", "hello"][..]
        );
        assert_eq!(wrapped.get_current_dir(), Some(std::path::Path::new("/")));
        assert!(wrapped.get_envs().any(|(name, value)| {
            name == "CALLER" && value.is_some_and(|value| value == "kept")
        }));
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    #[test]
    fn a_sandbox_does_not_start_on_windows() {
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
