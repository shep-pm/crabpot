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
use std::path::{Path, PathBuf};

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
    /// `user status` named no account for this process, so no profile read
    /// grant can be decided for it.
    StatusUnreadable,
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
            Self::StatusUnreadable => write!(
                f,
                "cannot read which account and session this install ran as, so no profile \
                 read grant is decided",
            ),
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
    /// The account this install ran as, and the owner of the session it ran in,
    /// which decide whether a profile read grant is made for it.
    fn grant_ids(&self) -> Result<GrantIds, InstallError>;
    /// The profile directory a grant here would open, `None` when the machine
    /// does not name one.
    fn profile_dir(&self) -> Option<PathBuf>;
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

/// LocalSystem, LocalService, NetworkService: accounts no one runs sessions as.
const WINDOWS_SERVICE_ACCOUNT_SIDS: [&str; 3] = ["S-1-5-18", "S-1-5-19", "S-1-5-20"];

/// Who an install is asked to grant for: the account that ran it, and the owner
/// of the session it ran in. What `user status` reports as `real_user_sid` and
/// `session_user_sid`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GrantIds {
    pub(crate) real_user_sid: String,
    pub(crate) session_user_sid: Option<String>,
}

/// What every skip reason but the flag's tells the person at the keyboard to do
/// instead.
const GRANT_HOW: &str = "run the install, or `crabpot --srt-win profile grant`, as the user \
                         whose sessions are to read their profile";

/// Why an install leaves the profile read grant unapplied: asked to skip, a
/// service account, or not running as the owner of the interactive session,
/// whose profile it would open instead. Upstream's four reasons, in upstream's
/// order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GrantSkip {
    /// `--skip-profile-grant` was given.
    Flag,
    /// The install ran as LocalSystem, LocalService or NetworkService.
    ServiceAccount { real_user_sid: String },
    /// The owner of the session the install ran in could not be read.
    SessionOwnerUnknown { real_user_sid: String },
    /// The install ran in a session that belongs to another account.
    SessionOwnerDiffers {
        real_user_sid: String,
        session_user_sid: String,
    },
}

impl fmt::Display for GrantSkip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Flag => write!(f, "--skip-profile-grant was set"),
            Self::ServiceAccount { real_user_sid } => write!(
                f,
                "the install ran as the service account {real_user_sid}, which runs no \
                 sessions; {GRANT_HOW}"
            ),
            Self::SessionOwnerUnknown { real_user_sid } => write!(
                f,
                "the owner of the session this install ran in could not be determined, so \
                 it is not known whose profile {real_user_sid} is; {GRANT_HOW}"
            ),
            Self::SessionOwnerDiffers {
                real_user_sid,
                session_user_sid,
            } => write!(
                f,
                "the install ran as {real_user_sid} in a session that belongs to \
                 {session_user_sid}; granting would open the installing account's profile, \
                 not the session owner's; {GRANT_HOW}"
            ),
        }
    }
}

/// Why no profile read grant is made for `options` run as `ids`, if anything.
/// SIDs are compared without case, as upstream compares them.
fn grant_skip_reason(options: &InstallOptions, ids: &GrantIds) -> Option<GrantSkip> {
    if options.skip_profile_grant {
        return Some(GrantSkip::Flag);
    }
    if WINDOWS_SERVICE_ACCOUNT_SIDS.contains(&ids.real_user_sid.as_str()) {
        return Some(GrantSkip::ServiceAccount {
            real_user_sid: ids.real_user_sid.clone(),
        });
    }
    let Some(session_user_sid) = &ids.session_user_sid else {
        return Some(GrantSkip::SessionOwnerUnknown {
            real_user_sid: ids.real_user_sid.clone(),
        });
    };
    if !session_user_sid.eq_ignore_ascii_case(&ids.real_user_sid) {
        return Some(GrantSkip::SessionOwnerDiffers {
            real_user_sid: ids.real_user_sid.clone(),
            session_user_sid: session_user_sid.clone(),
        });
    }
    None
}

/// What the profile read grant is about to do, in one line, for the person at
/// the keyboard. `profile_dir` is the profile it opens, `None` when the machine
/// does not name one.
fn grant_notice(profile_dir: Option<&Path>) -> String {
    let dir = match profile_dir {
        Some(dir) => dir.display().to_string(),
        None => "your profile".to_owned(),
    };
    format!(
        "Making {dir} readable to sandboxed commands on this machine, except the excluded \
         credential stores (SSH and GPG keys, cloud and browser sign-ins, password managers, \
         registry hives). Readable files include package-manager configuration that can hold \
         feed tokens: .npmrc, pip.ini, NuGet.Config, Maven settings.xml, gradle.properties, \
         .gitconfig. Skip with --skip-profile-grant; undo with `crabpot --srt-win profile \
         forget`."
    )
}

/// Installs the sandbox, makes the profile read grant unless one of the skip
/// reasons holds, and then checks that the sandbox user can read this binary,
/// which is what it runs as the runner. The check comes last because the grant
/// is often what makes a runner under the profile readable.
pub(crate) fn install(host: &mut impl Host, options: &InstallOptions) -> Result<(), InstallError> {
    run(host, "install", &install_args(options))?;
    let ids = host.grant_ids()?;
    match grant_skip_reason(options, &ids) {
        None => {
            eprintln!("crabpot: {}", grant_notice(host.profile_dir().as_deref()));
            run(host, "profile grant", &grant_args(options))?
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
        // The status is what names the grant, the account and the group. A
        // machine that cannot read it names none of the three, and the check is
        // left with the well-known groups alone.
        let status = super::windows_status().ok();
        if super::runner::Runner::of(exe.clone(), status.as_ref()).readable() {
            Ok(())
        } else {
            Err(InstallError::RunnerUnreadable(exe))
        }
    }

    fn grant_ids(&self) -> Result<GrantIds, InstallError> {
        let status = super::windows_status().map_err(|_| InstallError::StatusUnreadable)?;
        let Some(real_user_sid) = status.real_user_sid else {
            return Err(InstallError::StatusUnreadable);
        };
        Ok(GrantIds {
            real_user_sid,
            session_user_sid: status.session_user_sid,
        })
    }

    fn profile_dir(&self) -> Option<PathBuf> {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
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

    fn grant_ids(&self) -> Result<GrantIds, InstallError> {
        Err(InstallError::NotWindows)
    }

    fn profile_dir(&self) -> Option<PathBuf> {
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
        ids: GrantIds,
        profile_dir: Option<PathBuf>,
        exit: Vec<Option<i32>>,
        ran: Vec<Vec<String>>,
    }

    impl Fake {
        fn new() -> Self {
            Self {
                readable: true,
                // An install that ran as the owner of its own session: the case
                // that grants.
                ids: GrantIds {
                    real_user_sid: "S-1-5-21-1-2-3-1001".to_owned(),
                    session_user_sid: Some("S-1-5-21-1-2-3-1001".to_owned()),
                },
                profile_dir: Some(r"C:\Users\me".into()),
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

        fn grant_ids(&self) -> Result<GrantIds, InstallError> {
            Ok(self.ids.clone())
        }

        fn profile_dir(&self) -> Option<PathBuf> {
            self.profile_dir.clone()
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

    /// A service account runs no sessions, so a grant it made would open the
    /// profile of an account no one signs in as.
    #[test]
    fn a_service_account_install_makes_no_grant() {
        let mut host = Fake::new();
        host.ids.real_user_sid = "S-1-5-19".to_owned();

        install(&mut host, &InstallOptions::default()).unwrap();

        assert_eq!(host.ran, [vec!["install"]]);
    }

    #[test]
    fn an_install_whose_session_owner_is_unknown_makes_no_grant() {
        let mut host = Fake::new();
        host.ids.session_user_sid = None;

        install(&mut host, &InstallOptions::default()).unwrap();

        assert_eq!(host.ran, [vec!["install"]]);
    }

    /// Granting here would open the installing account's profile, which is not
    /// the one the sessions in that session read.
    #[test]
    fn an_install_in_another_accounts_session_makes_no_grant() {
        let mut host = Fake::new();
        host.ids.session_user_sid = Some("S-1-5-21-1-2-3-1002".to_owned());

        install(&mut host, &InstallOptions::default()).unwrap();

        assert_eq!(host.ran, [vec!["install"]]);
    }

    #[test]
    fn the_two_sids_are_compared_without_case() {
        let mut host = Fake::new();
        host.ids.session_user_sid = Some("s-1-5-21-1-2-3-1001".to_owned());

        install(&mut host, &InstallOptions::default()).unwrap();

        assert_eq!(host.ran, [vec!["install"], vec!["profile", "grant"]]);
    }

    /// Every reason names the account it turned on and what to run instead.
    #[test]
    fn each_skip_reason_names_the_account_and_the_repair() {
        let ids = GrantIds {
            real_user_sid: "S-1-5-19".to_owned(),
            session_user_sid: Some("S-1-5-21-1-2-3-1001".to_owned()),
        };
        let reasons = [
            grant_skip_reason(
                &InstallOptions {
                    skip_profile_grant: true,
                    ..InstallOptions::default()
                },
                &ids,
            )
            .unwrap(),
            grant_skip_reason(&InstallOptions::default(), &ids).unwrap(),
            grant_skip_reason(
                &InstallOptions::default(),
                &GrantIds {
                    real_user_sid: "S-1-5-21-1-2-3-1001".to_owned(),
                    session_user_sid: None,
                },
            )
            .unwrap(),
            grant_skip_reason(
                &InstallOptions::default(),
                &GrantIds {
                    real_user_sid: "S-1-5-21-1-2-3-1001".to_owned(),
                    session_user_sid: Some("S-1-5-21-1-2-3-1002".to_owned()),
                },
            )
            .unwrap(),
        ];
        let said: Vec<String> = reasons.iter().map(|reason| reason.to_string()).collect();

        assert_eq!(said[0], "--skip-profile-grant was set");
        assert!(said[1].starts_with("the install ran as the service account S-1-5-19"));
        assert!(said[2].starts_with("the owner of the session this install ran in could not be"));
        assert!(said[2].contains("whose profile S-1-5-21-1-2-3-1001 is"));
        assert!(said[3].starts_with("the install ran as S-1-5-21-1-2-3-1001 in a session"));
        assert!(said[3].contains("belongs to S-1-5-21-1-2-3-1002"));
        for reason in &said[1..] {
            assert!(reason.ends_with("as the user whose sessions are to read their profile"));
        }
    }

    /// The notice is what the grant is about to do, in the words upstream puts
    /// in front of the person at the keyboard.
    #[test]
    fn the_notice_names_the_profile_and_the_way_back_out() {
        let notice = grant_notice(Some(Path::new(r"C:\Users\me")));

        assert!(notice.starts_with(r"Making C:\Users\me readable to sandboxed commands"));
        assert!(notice.contains("SSH and GPG keys, cloud and browser sign-ins"));
        assert!(notice.contains(".npmrc, pip.ini, NuGet.Config"));
        assert!(notice.contains("Skip with --skip-profile-grant"));
        assert!(notice.contains("undo with `crabpot --srt-win profile forget`"));
        assert!(
            grant_notice(None).starts_with("Making your profile readable to sandboxed commands"),
            "a machine that names no profile still says what is opened"
        );
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
