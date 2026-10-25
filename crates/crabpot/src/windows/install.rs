//! `windows-install` and `windows-uninstall`: the one-time, elevated setup of
//! the sandbox user, the WFP fence and the grants.
//!
//! Both run this binary again as srt-win (`--srt-win`), which asks for
//! elevation itself and does the work. The install is upstream's: the same
//! user, the same sublayer and the same setup version, so an install by either
//! tool satisfies the other.

use core::fmt;
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;

#[cfg(windows)]
use super::ProfileState;

/// What `windows-install` passes on to `srt-win install`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct InstallOptions {
    /// `--sublayer-guid`: the WFP sublayer, when it is not the default.
    pub(crate) sublayer_guid: Option<OsString>,
    /// `--proxy-port-range LOW-HIGH`: the loopback ports left open for the proxy.
    pub(crate) proxy_port_range: Option<OsString>,
    /// `--allow-loopback`: every loopback port open, not the proxy's alone.
    pub(crate) allow_loopback: bool,
    /// `--sandbox-user`: the account's name, when it is not the default.
    pub(crate) sandbox_user: Option<OsString>,
    /// `--force`: replace an install that differs.
    pub(crate) force: bool,
    /// `--profile-exclude <path>`: a path inside the profile the read grant
    /// keeps out, on top of the list srt-win owns. Repeatable, and passed to
    /// `profile grant` as `--exclude`.
    pub(crate) profile_exclude: Vec<OsString>,
    /// `--skip-profile-grant`: make no profile read grant at all.
    pub(crate) skip_profile_grant: bool,
}

/// What `windows-uninstall` passes on to `srt-win uninstall` and `srt-win wfp
/// uninstall`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct UninstallOptions {
    /// `--sublayer-guid`: the WFP sublayer, when it is not the default.
    pub(crate) sublayer_guid: Option<OsString>,
    /// `--keep-user`: leave the account, its credential and the setup marker.
    pub(crate) keep_user: bool,
}

/// Why an install or uninstall did not finish.
// Each platform constructs some of these and not the rest.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InstallError {
    /// The command is for Windows.
    NotWindows,
    /// The path of this binary is unknown, and srt-win needs it to run it again.
    CurrentExe(io::ErrorKind),
    /// The sandbox user cannot read this binary, so seclogon would refuse to
    /// launch it as the runner with a misleading message.
    RunnerUnreadable(PathBuf),
    /// srt-win could not be started.
    NotRun(io::ErrorKind),
    /// srt-win's `command` exited with `code`, or was ended with none.
    Exited {
        command: &'static str,
        code: Option<i32>,
    },
}

impl fmt::Display for InstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotWindows => write!(f, "this command is for Windows"),
            Self::CurrentExe(kind) => write!(f, "cannot find this binary: {kind}"),
            Self::RunnerUnreadable(path) => write!(
                f,
                "the sandbox user cannot read {}, which it runs as the runner; run \
                 windows-install to make the profile read grant, or move crabpot to a folder \
                 every user can read, such as one under Program Files",
                path.display()
            ),
            Self::NotRun(kind) => write!(f, "cannot run srt-win: {kind}"),
            Self::Exited {
                command: "install",
                code: Some(10),
            } => write!(f, "the elevation prompt was cancelled"),
            Self::Exited {
                command: "install",
                code: Some(12),
            } => write!(f, "the WFP filters could not be installed"),
            Self::Exited {
                command: "install",
                code: Some(13),
            } => write!(
                f,
                "an install with another port range, loopback mode or sandbox user is \
                 there; pass --force to replace it"
            ),
            Self::Exited {
                command: "install",
                code: Some(14),
            } => write!(f, "the sandbox user could not be provisioned"),
            Self::Exited {
                command,
                code: Some(code),
            } => write!(f, "`srt-win {command}` exited {code}"),
            Self::Exited {
                command,
                code: None,
            } => write!(f, "`srt-win {command}` was ended before it exited"),
        }
    }
}

impl core::error::Error for InstallError {}

/// What an install or an uninstall needs from the machine.
pub(crate) trait Host {
    /// Whether the sandbox user can read this binary, which it runs as the
    /// runner: [`InstallError::RunnerUnreadable`] when it cannot.
    fn check_runner(&self) -> Result<(), InstallError>;
    /// The session this process runs in, `None` when the machine does not say.
    fn session(&self) -> Option<u32>;
    /// Runs this binary as `srt-win <args>`, to the end, and returns its exit
    /// code.
    fn run_srt_win(&mut self, args: &[OsString]) -> Result<Option<i32>, InstallError>;
}

/// The arguments of `srt-win install` for `options`.
pub(crate) fn install_args(options: &InstallOptions) -> Vec<OsString> {
    let mut args = vec![OsString::from("install")];
    if let Some(guid) = &options.sublayer_guid {
        args.extend([OsString::from("--sublayer-guid"), guid.clone()]);
    }
    if let Some(range) = &options.proxy_port_range {
        args.extend([OsString::from("--proxy-port-range"), range.clone()]);
    }
    if options.allow_loopback {
        args.push("--allow-loopback".into());
    }
    if let Some(user) = &options.sandbox_user {
        args.extend([OsString::from("--sandbox-user"), user.clone()]);
    }
    if options.force {
        args.push("--force".into());
    }
    args
}

/// The arguments of `srt-win profile grant` for `options`: the exclusions
/// `--profile-exclude` names, on top of the list srt-win owns.
fn grant_args(options: &InstallOptions) -> Vec<OsString> {
    let mut args = vec![OsString::from("profile"), OsString::from("grant")];
    for path in &options.profile_exclude {
        args.extend([OsString::from("--exclude"), path.clone()]);
    }
    args
}

/// Why `windows-install` makes no profile read grant, when it makes none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GrantSkip {
    /// `--skip-profile-grant` was given.
    Flag,
    /// This process runs in session 0, the services' session, whose account
    /// runs no sandbox command that could read the profile a grant here opens.
    SessionZero,
}

impl fmt::Display for GrantSkip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Flag => write!(f, "--skip-profile-grant"),
            Self::SessionZero => write!(
                f,
                "this process is in session 0, and its account runs no sandbox command \
                 that could read the profile a grant here would open"
            ),
        }
    }
}

/// Why no profile read grant is made for `options`, if anything. A session the
/// machine does not name is not session 0, and grants.
fn grant_skip_reason(options: &InstallOptions, session: Option<u32>) -> Option<GrantSkip> {
    if options.skip_profile_grant {
        Some(GrantSkip::Flag)
    } else if session == Some(0) {
        Some(GrantSkip::SessionZero)
    } else {
        None
    }
}

/// What `windows-install` prints once the grant is in place: what it opens, and
/// what it keeps shut.
fn grant_notice() -> &'static str {
    "the profile read grant is in place: a sandbox command can read your profile, except \
     the credential stores srt-win keeps out and what --profile-exclude names; a new \
     top-level item of the profile stays unreadable until the grant runs again"
}

/// Installs the sandbox, makes the profile read grant unless a skip reason
/// holds, and then checks that the sandbox user can read this binary, which is
/// what it runs as the runner. The check comes last because the grant is often
/// what makes a runner under the profile readable.
pub(crate) fn install(host: &mut impl Host, options: &InstallOptions) -> Result<(), InstallError> {
    run(host, "install", &install_args(options))?;
    match grant_skip_reason(options, host.session()) {
        None => {
            run(host, "profile grant", &grant_args(options))?;
            eprintln!("crabpot: {}", grant_notice());
        }
        Some(skip) => eprintln!("crabpot: no profile read grant: {skip}"),
    }
    host.check_runner()
}

/// Removes the sandbox: `srt-win uninstall`, then `wfp uninstall` last. The
/// second does not run when the first fails, since the filters are what fence
/// a sandbox user that is still there.
pub(crate) fn uninstall(
    host: &mut impl Host,
    options: &UninstallOptions,
) -> Result<(), InstallError> {
    let guid = |args: &mut Vec<OsString>| {
        if let Some(guid) = &options.sublayer_guid {
            args.extend([OsString::from("--sublayer-guid"), guid.clone()]);
        }
    };
    let mut user = vec![OsString::from("uninstall")];
    guid(&mut user);
    if options.keep_user {
        user.push("--keep-user".into());
    }
    let mut fence = vec![OsString::from("wfp"), OsString::from("uninstall")];
    guid(&mut fence);
    run(host, "uninstall", &user)?;
    run(host, "wfp uninstall", &fence)
}

/// Runs `srt-win <args>` and turns any exit but 0 into an error naming
/// `command`.
fn run(host: &mut impl Host, command: &'static str, args: &[OsString]) -> Result<(), InstallError> {
    match host.run_srt_win(args)? {
        Some(0) => Ok(()),
        code => Err(InstallError::Exited { command, code }),
    }
}

/// The machine this process runs on.
pub(crate) struct Machine;

#[cfg(windows)]
impl Host for Machine {
    fn check_runner(&self) -> Result<(), InstallError> {
        let exe = current_exe()?;
        // Only a grant that is in place opens the profile.
        let granted = super::windows_status().is_ok_and(|s| s.profile == ProfileState::Current);
        if super::runner::Runner::of(exe.clone(), granted).readable() {
            Ok(())
        } else {
            Err(InstallError::RunnerUnreadable(exe))
        }
    }

    fn session(&self) -> Option<u32> {
        super::ffi::session_of(std::process::id())
    }

    fn run_srt_win(&mut self, args: &[OsString]) -> Result<Option<i32>, InstallError> {
        let status = std::process::Command::new(current_exe()?)
            .arg(crabpot_windows::SRT_WIN_DISPATCH_ARG1)
            .args(args)
            .status()
            .map_err(|e| InstallError::NotRun(e.kind()))?;
        Ok(status.code())
    }
}

#[cfg(not(windows))]
impl Host for Machine {
    fn check_runner(&self) -> Result<(), InstallError> {
        Err(InstallError::NotWindows)
    }

    fn session(&self) -> Option<u32> {
        None
    }

    fn run_srt_win(&mut self, args: &[OsString]) -> Result<Option<i32>, InstallError> {
        let _ = args;
        Err(InstallError::NotWindows)
    }
}

/// This binary's path with links resolved, which is the form the profile's is
/// compared in.
#[cfg(windows)]
fn current_exe() -> Result<PathBuf, InstallError> {
    let exe = std::env::current_exe().map_err(|e| InstallError::CurrentExe(e.kind()))?;
    Ok(std::fs::canonicalize(&exe).unwrap_or(exe))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A machine that records what srt-win is asked to do and answers with
    /// `exit`.
    struct Fake {
        readable: bool,
        session: Option<u32>,
        exit: Vec<Option<i32>>,
        ran: Vec<Vec<String>>,
    }

    impl Fake {
        fn new() -> Self {
            Self {
                readable: true,
                session: Some(1),
                exit: Vec::new(),
                ran: Vec::new(),
            }
        }
    }

    impl Host for Fake {
        fn check_runner(&self) -> Result<(), InstallError> {
            if self.readable {
                Ok(())
            } else {
                Err(InstallError::RunnerUnreadable("crabpot.exe".into()))
            }
        }

        fn session(&self) -> Option<u32> {
            self.session
        }

        fn run_srt_win(&mut self, args: &[OsString]) -> Result<Option<i32>, InstallError> {
            self.ran.push(
                args.iter()
                    .map(|arg| arg.to_string_lossy().into_owned())
                    .collect(),
            );
            Ok(if self.exit.is_empty() {
                Some(0)
            } else {
                self.exit.remove(0)
            })
        }
    }

    fn strs(args: &[OsString]) -> Vec<&str> {
        args.iter().map(|arg| arg.to_str().unwrap()).collect()
    }

    #[test]
    fn install_args_pass_through_upstreams_flags() {
        assert_eq!(strs(&install_args(&InstallOptions::default())), ["install"]);

        let all = InstallOptions {
            sublayer_guid: Some("{0F4B1C2D-0000-4000-8000-000000000001}".into()),
            proxy_port_range: Some("61000-61009".into()),
            allow_loopback: true,
            sandbox_user: Some("ci-sandbox".into()),
            force: true,
            // The two grant flags belong to `profile grant`, not to `install`.
            profile_exclude: Vec::new(),
            skip_profile_grant: false,
        };
        assert_eq!(
            strs(&install_args(&all)),
            [
                "install",
                "--sublayer-guid",
                "{0F4B1C2D-0000-4000-8000-000000000001}",
                "--proxy-port-range",
                "61000-61009",
                "--allow-loopback",
                "--sandbox-user",
                "ci-sandbox",
                "--force",
            ]
        );
    }

    #[test]
    fn install_makes_the_profile_grant_after_the_install() {
        let mut host = Fake::new();

        install(&mut host, &InstallOptions::default()).unwrap();

        assert_eq!(host.ran, [vec!["install"], vec!["profile", "grant"]]);
    }

    #[test]
    fn skip_profile_grant_makes_no_grant() {
        let mut host = Fake::new();
        let options = InstallOptions {
            skip_profile_grant: true,
            ..InstallOptions::default()
        };

        install(&mut host, &options).unwrap();

        assert_eq!(host.ran, [vec!["install"]]);
    }

    #[test]
    fn session_zero_makes_no_grant() {
        let mut host = Fake::new();
        host.session = Some(0);

        install(&mut host, &InstallOptions::default()).unwrap();

        assert_eq!(host.ran, [vec!["install"]]);
    }

    #[test]
    fn profile_exclude_passes_through_as_exclude() {
        let mut host = Fake::new();
        let options = InstallOptions {
            profile_exclude: vec![r"C:\Users\me\.aws".into(), ".ssh".into()],
            ..InstallOptions::default()
        };

        install(&mut host, &options).unwrap();

        assert_eq!(
            host.ran,
            [
                vec!["install"],
                vec![
                    "profile",
                    "grant",
                    "--exclude",
                    r"C:\Users\me\.aws",
                    "--exclude",
                    ".ssh"
                ],
            ]
        );
    }

    #[test]
    fn an_unreadable_runner_is_refused_after_the_grant_that_could_open_it() {
        let mut host = Fake::new();
        host.readable = false;

        let error = install(&mut host, &InstallOptions::default()).unwrap_err();

        assert_eq!(error, InstallError::RunnerUnreadable("crabpot.exe".into()));
        assert_eq!(
            host.ran,
            [vec!["install"], vec!["profile", "grant"]],
            "the install and the grant both ran first: the grant is what makes a runner under the profile readable"
        );
    }

    #[test]
    fn uninstall_runs_wfp_uninstall_last() {
        let mut host = Fake::new();
        let options = UninstallOptions {
            sublayer_guid: Some("{0F4B1C2D-0000-4000-8000-000000000001}".into()),
            keep_user: true,
        };

        uninstall(&mut host, &options).unwrap();

        let guid = "{0F4B1C2D-0000-4000-8000-000000000001}";
        assert_eq!(
            host.ran,
            [
                vec!["uninstall", "--sublayer-guid", guid, "--keep-user"],
                vec!["wfp", "uninstall", "--sublayer-guid", guid],
            ]
        );
    }
}
