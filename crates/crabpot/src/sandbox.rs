//! One sandbox: the profile or the bwrap words a command runs under, and the
//! wrapping of a command into it (ADR-0010).

use core::fmt;
use std::io;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
#[cfg(target_os = "linux")]
use std::{
    ffi::OsString,
    os::fd::OwnedFd,
    sync::{Mutex, PoisonError},
};

use crabpot_core::PathError;
use crabpot_core::config::Config;
use crabpot_core::proxy::PortRange;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use crabpot_core::proxy::Proxy;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use crabpot_core::proxy::username_for;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use crabpot_core::tmpdir::{Origin, TmpdirError};
#[cfg(target_os = "linux")]
use crabpot_linux::env::Facts;
#[cfg(target_os = "linux")]
use crabpot_linux::info::Info;
#[cfg(target_os = "linux")]
use crabpot_linux::net::env::HostPorts;
#[cfg(target_os = "macos")]
use crabpot_macos::env::Facts;

#[cfg(target_os = "linux")]
use crate::args::{HELPER_FLAG, HelperMode, RELAY_FLAG};
use crate::windows::ProfileState;

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
    /// The grants and the proxy of the Windows session, which its commands run
    /// through srt-win under.
    #[cfg(windows)]
    session: crate::windows::Session,
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    facts: Facts,
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    proxy: Proxy,
}

impl Sandbox {
    /// Starts a sandbox that applies `config`.
    ///
    /// # Errors
    ///
    /// [`StartError::UnsupportedPlatform`] off macOS, Linux and Windows, where
    /// nothing confines a command yet, [`StartError::UnresolvedPath`] when a path
    /// in `config` cannot be made absolute, and [`StartError::Proxy`] when the
    /// proxy that carries its network cannot start. On macOS and Linux the
    /// sandbox first makes the folder it sets `TMPDIR` to (`CLAUDE_CODE_TMPDIR`,
    /// then `CLAUDE_TMPDIR`, then `/tmp/claude`) when it is missing, owner-only,
    /// and lets the command write there. [`StartError::Tmpdir`] when that path
    /// is relative or holds a `..`, its parent is missing, it is a link or a
    /// file, or another user owns it. A `/tmp/claude` that another user owns is
    /// used as it is, when the host names no folder. On Linux the bwrap checks
    /// run first: [`StartError::Missing`] when there is no executable `bwrap`
    /// on `PATH`, and [`StartError::Uid0WithoutSetfcap`] for uid 0 without
    /// `CAP_SETFCAP`, and [`StartError::CurrentExe`] when the path of this
    /// binary is unknown. A `bwrap` older than 0.5.0 is a warning on stderr.
    /// [`StartError::UnspellableDeny`] names a mandatory write deny the plan
    /// cannot spell, which is a Linux answer too. On Windows the status checks
    /// of [`windows_preflight_for`](crate::windows_preflight_for) run first, then
    /// [`StartError::ProfileGrantOutdated`] for a profile grant that is neither
    /// none nor current, [`StartError::LoopbackMismatch`] for a session whose
    /// `network.allowLocalBinding` is not the install's loopback mode,
    /// [`StartError::ProfileConflicts`] when a grant meets what the profile
    /// read grant keeps out of reach, [`StartError::RunnerUnreadable`] when the
    /// sandbox user cannot read this binary and so cannot run it as its runner,
    /// [`StartError::GrantBlocked`],
    /// [`StartError::ProfileBusy`] or [`StartError::GrantFailed`] when the
    /// session's grants and denies cannot be made,
    /// [`StartError::FenceInactive`] or [`StartError::FenceUnverified`] when the
    /// firewall fence is not shown to be active, and
    /// [`StartError::ProxyRangeFull`] or [`StartError::ProxyRangeRefused`]
    /// when the proxy has no port of its range to listen on. The grants are
    /// held until the sandbox drops, which revokes them.
    pub fn start(config: &Config) -> Result<Self, StartError> {
        #[cfg(target_os = "linux")]
        let bwrap = crabpot_linux::deps::check_here()?;
        #[cfg(target_os = "linux")]
        let helper = std::env::current_exe().map_err(|e| StartError::CurrentExe(e.kind()))?;
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            // The folder is made before the profile or the bwrap words are
            // rendered, since they resolve and bind it only once it exists.
            let (tmpdir, host_named) = crabpot_core::env::base::tmpdir_named(
                std::env::var_os("CLAUDE_CODE_TMPDIR").as_deref(),
                std::env::var_os("CLAUDE_TMPDIR").as_deref(),
            );
            let origin = if host_named {
                Origin::Host
            } else {
                Origin::Default
            };
            crabpot_core::tmpdir::prepare(Path::new(&tmpdir), origin)?;
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
                    proxy.mux_socket(),
                    crabpot_linux::deps::is_root_with_setfcap_here(),
                )
                .map_err(StartError::from_plan)?;
                Ok(Self {
                    words: wrapped.words,
                    mount_points: wrapped.mount_points,
                    helper,
                    args_files: Mutex::new(Vec::new()),
                    facts: Facts::for_sandbox(config),
                    proxy,
                })
            }
        }
        #[cfg(windows)]
        {
            crate::windows::start_session(config).map(|session| Self { session })
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
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
    /// On Windows, this binary runs again as `srt-win exec` in front of the
    /// command, which it launches as the sandbox user in two hops. A program
    /// that resolves to a `.exe` or `.com` file runs as itself, with its
    /// arguments as given. Any other program, such as a batch file or a
    /// `cmd.exe` builtin, runs through `cmd.exe /d /s /c` as one line, a word
    /// `cmd.exe` would act on in quotes. A host
    /// must call [`run_from_args`](crate::run_from_args) first thing in `main`
    /// for that too.
    ///
    /// On macOS it gains the sandbox's own environment: a name the sandbox owns
    /// is set over the caller's, a name the caller owns is left to it, and the
    /// variables that point its clients at the proxy are set over them. On
    /// Linux it gains the sandbox's own `SANDBOX_RUNTIME` and `TMPDIR`, and the
    /// variables that point its clients at the relay and its ssh at the
    /// `connect` mode, set over the caller's.
    ///
    /// # Errors
    ///
    /// [`WrapError::Missing`] when the machine has no `sandbox-exec`,
    /// [`WrapError::Bwrap`] when the command cannot be put in a bwrap line,
    /// [`WrapError::Cmd`] when it runs through `cmd.exe` and a word of it
    /// cannot be put on the line,
    /// and [`WrapError::UnsupportedPlatform`] off macOS, Linux and Windows.
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
            let username = username_for(&command_line(command));
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
            self.linux_command(command, false)
        }
        #[cfg(windows)]
        {
            self.session.command(command)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
        {
            let _ = command;
            Err(WrapError::UnsupportedPlatform)
        }
    }
}

#[cfg(target_os = "linux")]
impl Sandbox {
    /// [`Sandbox::command`], and with it what bwrap reports of the sandbox,
    /// which tells the launcher which process to signal in place of bwrap
    /// itself. The command is given the descriptor the report goes to, so it
    /// is spawned from the returned [`Command`] and not from one a plain
    /// [`Sandbox::command`] gave.
    pub(crate) fn command_reporting(
        &self,
        command: &Command,
    ) -> Result<(Command, Info), WrapError> {
        let mut wrapped = self.linux_command(command, true)?;
        let info = crabpot_linux::info::attach(&mut wrapped)
            .map_err(|e| WrapError::Bwrap(e.to_string()))?;
        Ok((wrapped, info))
    }

    fn linux_command(&self, command: &Command, report: bool) -> Result<Command, WrapError> {
        let mut words = vec![
            self.helper.clone().into_os_string(),
            OsString::from(HELPER_FLAG),
            OsString::from(HelperMode::Init.word()),
            OsString::from(RELAY_FLAG),
            self.proxy.mux_socket().as_os_str().to_owned(),
            command.get_program().to_owned(),
        ];
        words.extend(command.get_args().map(OsString::from));
        let mut bwrap_words = self.words.clone();
        if report {
            bwrap_words.splice(1..1, crabpot_linux::wrap::info_words());
        }
        let rendered = crabpot_linux::argv::render(&bwrap_words, &words, &std::env::temp_dir())
            .map_err(|e| WrapError::Bwrap(e.to_string()))?;
        let mut wrapped = rendered.command;
        carry_over(command, &mut wrapped);
        for (name, value) in crabpot_linux::env::vars(&self.facts.for_command(command)) {
            wrapped.env(name, value);
        }
        // On the command's environment, not in bwrap's words: its argv is
        // readable from `/proc` by every process of the user, and the token
        // is the proxy's credential.
        let username = username_for(&command_line(command));
        let host = HostPorts {
            http: self.proxy.port(),
            socks: self.proxy.socks_port(),
        };
        let ssh = crabpot_linux::net::ssh::vars(&self.helper, &username, self.proxy.token());
        for (name, value) in crabpot_linux::net::env::vars(host, &username, self.proxy.token())
            .into_iter()
            .map(|(name, value)| (name, OsString::from(value)))
            .chain(ssh)
        {
            wrapped.env(name, value);
        }
        if let Some(args_file) = rendered.args_file {
            self.args_files
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(args_file);
        }
        Ok(wrapped)
    }
}

/// The words of `command` joined by spaces, which the proxy's username is made
/// from.
pub(crate) fn command_line(command: &Command) -> String {
    core::iter::once(command.get_program())
        .chain(command.get_args())
        .map(|word| word.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ")
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

/// A path a Windows session asks to grant, and the exclusion of the profile
/// read grant it meets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileConflict {
    /// The path, as the settings resolved it.
    pub path: String,
    /// The exclusion, as the profile grant recorded it.
    pub exclusion: String,
    /// Whether the session asked to write the path, and not only read it.
    pub write: bool,
}

impl fmt::Display for ProfileConflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let access = if self.write { "write" } else { "read" };
        write!(f, "{} ({access}) meets {}", self.path, self.exclusion)
    }
}

/// Why a sandbox did not start.
#[derive(Debug, Clone, PartialEq, Eq)]
// A platform or a proxy that fails to start adds a variant without breaking a
// caller's `match`. `UnspellableDeny` carries a path, which is why this one is
// `Clone` and not `Copy`.
#[non_exhaustive]
pub enum StartError {
    /// The platform has no sandbox yet: only macOS, Linux and Windows have one.
    UnsupportedPlatform,
    /// A path in the settings starts with `~` and `HOME` is not set, or is
    /// relative and there is no working directory. A rule written for it would
    /// be dropped.
    UnresolvedPath(PathError),
    /// The proxy could not start for any other reason: no token, no port, or
    /// no thread to run on.
    Proxy(io::ErrorKind),
    /// Windows: every loopback port of the proxy port range is taken, so the
    /// proxy has no port to listen on. Each sandbox takes two ports there.
    ProxyRangeFull {
        /// The range's first port.
        first: u16,
        /// The range's last port.
        last: u16,
    },
    /// Windows: the proxy port range the install reports or the settings name
    /// starts at port 0, ends before it starts, or holds more than
    /// [`PortRange::MAX_WIDTH`] ports, so the proxy has no range to bind in.
    ProxyRangeRefused {
        /// The range's first port, as the install or the settings name it.
        first: u16,
        /// The range's last port, as the install or the settings name it.
        last: u16,
    },
    /// `tool` is not on `PATH`, or is there but not executable.
    Missing {
        /// The program's name.
        tool: &'static str,
    },
    /// The process is uid 0 without `CAP_SETFCAP`, and bwrap cannot make a
    /// user namespace.
    Uid0WithoutSetfcap,
    /// The path of this binary is unknown, and bwrap needs it to run the
    /// helper, or srt-win needs it to run this binary again.
    CurrentExe(io::ErrorKind),
    /// Windows: the sandbox user is not provisioned, or its install has a setup
    /// version other than this build's. srt-win exits 15 for either, and the
    /// repair for both is to run the install again.
    NotProvisioned,
    /// Windows: the Secondary Logon service is disabled or missing, and every
    /// launch as the sandbox user goes through it. srt-win exits 18.
    SeclogonDisabled,
    /// Windows: this process runs in session 0, the services' session, and the
    /// sandbox runs from the signed-in user's desktop session only.
    SessionZero,
    /// Windows: this process is in a session, but not as the user who owns it,
    /// so the install's grants were not made for it.
    NotDesktopSession,
    /// Windows: the sandbox user cannot read this binary, which it has to run
    /// as the runner. The profile read grant `windows-install` makes, or a
    /// binary in a folder every user can read, is the repair. A binary moved in
    /// from another folder (`cargo install` does) keeps its old access list and
    /// lacks the grant's inherited entry, which `icacls <this binary> /reset`
    /// restores.
    RunnerUnreadable,
    /// Windows: `command`, one of the srt-win queries a status is read from,
    /// did not run, exited with `code`, or printed what this build cannot read
    /// (`code` is `None` for the first and the last).
    StatusFailed {
        /// The query, such as `user status`.
        command: &'static str,
        /// Its exit code, when it ran to one.
        code: Option<i32>,
        /// What it printed on stderr, trimmed, and empty when it did not run or
        /// printed nothing.
        stderr: String,
    },
    /// Windows: the recorded read grant on the user profile cannot be used, since
    /// it is `state` and not none or current. Bringing it up to date, or
    /// forgetting it, is the install's to do, and a session does neither.
    ProfileGrantOutdated {
        /// What `profile status` reports.
        state: ProfileState,
    },
    /// Windows: the `acl grant` call that applies the session's grants and denies
    /// exited with `code` (`None` when it did not run, or a signal ended it).
    GrantFailed {
        /// Its exit code, when it ran to one.
        code: Option<i32>,
        /// What it printed on stderr, trimmed, and empty when it did not run or
        /// printed nothing.
        stderr: String,
    },
    /// Windows: srt-win exited 24 for the `acl grant` call, which holds it off.
    /// Nothing was granted or denied, and the call can be made again.
    GrantBlocked,
    /// Windows: srt-win exited 25 for the `acl grant` call, because a
    /// `profile grant` or `profile forget` holds the lock the call needs.
    /// Nothing was granted or denied, and the call can be made again once that
    /// operation is done.
    ProfileBusy,
    /// Windows: the session asks to grant paths that the profile read grant
    /// keeps out of reach, each named with the exclusion it meets. Nothing was
    /// granted or denied.
    ProfileConflicts(Vec<ProfileConflict>),
    /// Windows: `network.allowLocalBinding` is not the loopback mode the install
    /// made, which the install fixes and a session cannot change. The repair is
    /// the install again with `--allow-loopback` for a session that opens
    /// loopback, or without it for one that keeps it closed. srt-win answers the
    /// difference with exit 19.
    LoopbackMismatch,
    /// Windows: a direct outbound connect the fence must refuse was not
    /// refused, so the fence is not active and the install has to be run
    /// again.
    FenceInactive {
        /// The attempts that got through, as `wfp verify` names them.
        detail: String,
    },
    /// Windows: `wfp verify` ran, but its answer does not show the fence is
    /// active: it failed, printed what cannot be read, or did not report the
    /// plain attempt as blocked.
    FenceUnverified {
        /// What `wfp verify` exited with and printed.
        detail: String,
    },
    /// macOS and Linux: the folder `TMPDIR` names cannot be used as the temp
    /// folder, so there is nowhere for the command to write its temp files.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    Tmpdir(TmpdirError),
    /// A write deny the sandbox must apply in its own working directory is a
    /// path its words cannot name, so there is no mount for it and no command
    /// runs. Linux only, where the mandatory denies come from a walk.
    UnspellableDeny {
        /// The path the walk found, as the filesystem holds it.
        path: PathBuf,
    },
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
impl From<TmpdirError> for StartError {
    fn from(error: TmpdirError) -> Self {
        Self::Tmpdir(error)
    }
}

#[cfg(target_os = "linux")]
impl StartError {
    /// The reason a bwrap plan was not built, as a [`StartError`].
    fn from_plan(error: crabpot_linux::fs::PlanError) -> Self {
        match error {
            crabpot_linux::fs::PlanError::Path(error) => Self::UnresolvedPath(error),
            crabpot_linux::fs::PlanError::Unspellable { path } => Self::UnspellableDeny { path },
        }
    }
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

/// Appends `: <stderr>` to an error message, when srt-win printed any.
fn write_stderr(f: &mut fmt::Formatter<'_>, stderr: &str) -> fmt::Result {
    if stderr.is_empty() {
        Ok(())
    } else {
        write!(f, ": {stderr}")
    }
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                write!(f, "only macOS, Linux and Windows have a sandbox yet")
            }
            Self::UnresolvedPath(error) => write!(f, "{error}"),
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            Self::Tmpdir(error) => write!(f, "{error}"),
            Self::Proxy(kind) => write!(f, "cannot start the proxy: {kind}"),
            Self::ProxyRangeFull { first, last } => write!(
                f,
                "no free loopback port in the proxy port range {first}-{last}: each sandbox \
                 takes two, so widen it with --proxy-port-range or stop a sandbox"
            ),
            Self::ProxyRangeRefused { first, last } => write!(
                f,
                "the proxy port range {first}-{last} is no range the proxy can bind in: it \
                 must start above port 0, end at or after its first port, and hold at most \
                 {} ports",
                PortRange::MAX_WIDTH
            ),
            Self::Missing { tool } => write!(f, "{tool} is missing or not executable"),
            Self::Uid0WithoutSetfcap => write!(
                f,
                "running as uid 0 without CAP_SETFCAP, so bwrap cannot make a user namespace"
            ),
            Self::CurrentExe(kind) => write!(f, "cannot find this binary: {kind}"),
            Self::NotProvisioned => write!(
                f,
                "the sandbox user is not provisioned, or its setup version is not this build's; run the install again"
            ),
            Self::SeclogonDisabled => write!(
                f,
                "the Secondary Logon service is disabled or missing, and the sandbox user cannot be launched without it"
            ),
            Self::SessionZero => write!(
                f,
                "this process is in session 0, and the sandbox runs from the desktop session only"
            ),
            Self::NotDesktopSession => write!(
                f,
                "this process is not running as the user who owns its session, so the sandbox's grants do not apply to it"
            ),
            Self::RunnerUnreadable => {
                write!(
                    f,
                    "the sandbox user cannot read this binary, which it runs as the runner; \
                     run `crabpot windows-install` to make the profile read grant, or keep \
                     crabpot in a folder every user can read; a binary moved in from another \
                     folder keeps its old access list, and `icacls <this binary> /reset` \
                     re-applies the folder's inherited entries"
                )
            }
            Self::StatusFailed {
                command,
                code: Some(code),
                stderr,
            } => {
                write!(f, "`srt-win {command}` exited {code}")?;
                write_stderr(f, stderr)
            }
            Self::StatusFailed {
                command,
                code: None,
                stderr,
            } => {
                write!(
                    f,
                    "`srt-win {command}` did not run, or printed what cannot be read"
                )?;
                write_stderr(f, stderr)
            }
            Self::ProfileGrantOutdated { state } => write!(
                f,
                "the recorded read grant on the user profile cannot be used ({state:?}); bring it up to date with the install, or forget it"
            ),
            Self::GrantFailed {
                code: Some(code),
                stderr,
            } => {
                write!(f, "`srt-win acl grant` exited {code}")?;
                write_stderr(f, stderr)
            }
            Self::GrantFailed { code: None, stderr } => {
                write!(f, "`srt-win acl grant` did not run")?;
                write_stderr(f, stderr)
            }
            Self::GrantBlocked => write!(
                f,
                "`srt-win acl grant` was held off (exit 24), and changed nothing"
            ),
            Self::ProfileBusy => write!(
                f,
                "`srt-win acl grant` was held off by a profile grant or forget in progress, and changed nothing"
            ),
            Self::ProfileConflicts(conflicts) => {
                write!(
                    f,
                    "the profile read grant keeps these out of a session's grants:"
                )?;
                for conflict in conflicts {
                    write!(f, " {conflict};")?;
                }
                Ok(())
            }
            Self::LoopbackMismatch => write!(
                f,
                "network.allowLocalBinding is not the install's loopback mode, which the install fixes; run `crabpot windows-install --allow-loopback --force` to open loopback, or `crabpot windows-install --force` to keep it closed"
            ),
            Self::FenceInactive { detail } => write!(
                f,
                "the firewall fence is not active ({detail}); run the install again"
            ),
            Self::FenceUnverified { detail } => {
                write!(f, "the firewall fence could not be verified: {detail}")
            }
            Self::UnspellableDeny { path } => write!(
                f,
                "a mandatory write deny is a path the sandbox cannot name: {}",
                path.display()
            ),
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
    /// Windows: the command runs through `cmd.exe`, because its program is not
    /// a `.exe` or `.com` file, and a word of it has a double quote, a percent
    /// sign or a line break, which `cmd.exe` would act on instead of passing on.
    /// Also when the environment it carries makes the srt-win command line
    /// longer than Windows spawns.
    Cmd(String),
    /// The platform has no sandbox yet: only macOS, Linux and Windows have one.
    UnsupportedPlatform,
}

impl fmt::Display for WrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => write!(f, "/usr/bin/sandbox-exec is missing"),
            Self::Bwrap(reason) => write!(f, "cannot build the bwrap command: {reason}"),
            Self::Cmd(reason) => write!(f, "cannot build the cmd.exe line: {reason}"),
            Self::UnsupportedPlatform => {
                write!(f, "only macOS, Linux and Windows have a sandbox yet")
            }
        }
    }
}

impl core::error::Error for WrapError {}

#[cfg(test)]
mod tests {
    #[cfg(not(windows))]
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
        let socket = sandbox.proxy.mux_socket().to_string_lossy();
        assert_eq!(
            args[args.len() - 8..],
            [
                "--",
                &*helper,
                "--crabpot-helper",
                "init",
                "--relay",
                &*socket,
                "echo",
                "hello"
            ][..]
        );
        assert!(
            args.windows(3)
                .any(|run| run == ["--bind", &*socket, &*socket]),
            "the proxy's socket is bound into the sandbox: {args:?}"
        );
        assert!(
            args.iter().any(|arg| arg == "--unshare-net"),
            "the network stays unshared: {args:?}"
        );
        assert_eq!(wrapped.get_current_dir(), Some(std::path::Path::new("/")));
        assert!(wrapped.get_envs().any(|(name, value)| {
            name == "CALLER" && value.is_some_and(|value| value == "kept")
        }));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_wrapped_command_gains_the_sandbox_environment() {
        let sandbox = match Sandbox::start(&Config::default()) {
            Ok(sandbox) => sandbox,
            // The machine has no bwrap to wrap a command in.
            Err(StartError::Missing { .. } | StartError::Uid0WithoutSetfcap) => return,
            Err(error) => panic!("{error}"),
        };
        let mut echo = Command::new("echo");
        echo.arg("hello").env("TMPDIR", "/caller/tmp");

        let wrapped = sandbox.command(&echo).unwrap();
        let last = |name: &str| {
            wrapped
                .get_envs()
                .filter(|(key, _)| *key == name)
                .last()
                .and_then(|(_, value)| value)
                .map(|value| value.to_string_lossy().into_owned())
        };

        assert_eq!(last("SANDBOX_RUNTIME").as_deref(), Some("1"));
        let tmpdir = last("TMPDIR");
        assert!(tmpdir.is_some(), "the sandbox sets TMPDIR: {tmpdir:?}");
        assert_ne!(
            tmpdir.as_deref(),
            Some("/caller/tmp"),
            "the sandbox's TMPDIR is set over the caller's: {tmpdir:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_wrapped_command_is_pointed_at_the_relays_and_the_token_stays_out_of_argv() {
        let sandbox = match Sandbox::start(&Config::default()) {
            Ok(sandbox) => sandbox,
            // The machine has no bwrap to wrap a command in.
            Err(StartError::Missing { .. } | StartError::Uid0WithoutSetfcap) => return,
            Err(error) => panic!("{error}"),
        };

        let wrapped = sandbox.command(&Command::new("true")).unwrap();
        let env = |name: &str| {
            wrapped
                .get_envs()
                .find(|(key, _)| *key == name)
                .and_then(|(_, value)| value)
                .map(|value| value.to_string_lossy().into_owned())
                .unwrap_or_else(|| panic!("{name} is not set"))
        };

        let token = sandbox.proxy.token();
        assert!(env("HTTPS_PROXY").ends_with("@localhost:3128"));
        assert!(env("HTTPS_PROXY").contains(token));
        assert!(env("FTP_PROXY").ends_with("@localhost:1080"));
        assert_eq!(
            env("CLAUDE_CODE_HOST_HTTP_PROXY_PORT"),
            sandbox.proxy.port().to_string()
        );

        let helper = std::env::current_exe().unwrap();
        let ssh = env("GIT_SSH_COMMAND");
        assert!(
            ssh.contains("--crabpot-helper connect 3128") && ssh.contains("SRT_SSH_PROXY_BINARY"),
            "git's ssh is told to ask this binary for the tunnel: {ssh}"
        );
        assert_eq!(
            env(crabpot_linux::net::ssh::BINARY_VARIABLE),
            helper.to_string_lossy().into_owned(),
            "the binary the command expands, on the environment and not in a word \
             git's shell reads"
        );
        assert!(
            !ssh.contains(token),
            "the credential is not in a command line: {ssh}"
        );
        assert!(
            !env("SRT_SSH_PROXY_CREDENTIAL").is_empty(),
            "the credential rides in a variable of its own"
        );

        assert!(
            wrapped
                .get_args()
                .all(|arg| !arg.to_string_lossy().contains(token)),
            "bwrap's argv is readable from /proc: {wrapped:?}"
        );
    }

    #[test]
    fn runner_unreadable_names_the_reset_for_a_moved_binary() {
        let said = super::StartError::RunnerUnreadable.to_string();

        assert!(said.contains("icacls"), "{said}");
        assert!(said.contains("/reset"), "{said}");
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    #[test]
    fn a_sandbox_does_not_start_on_another_platform() {
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
