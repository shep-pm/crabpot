//! What a Windows sandbox asks srt-win to grant and deny, from a [`Config`].
//!
//! A plan is built by sections, each a file in the `plan` folder with a
//! `contribute` function, and registered by naming it in the `sections!` call.
//! A section adds to the lists the one `acl grant --persistent` call reads from
//! standard input. Each section ranks only the lists it owns, so the lists it
//! does not read are empty. The lists are then held against the profile read
//! grant in [`profile`].

use crabpot_core::PathError;
use crabpot_core::config::Config;
use crabpot_windows::fs_access::{Access, Disk, ExpandError, Host, Settings, access};

use super::srt::{Call, Srt};
use super::status::ProfileExclusions;
use crate::StartError;

mod profile;

/// Declares each section's module and lists them in the order they run.
macro_rules! sections {
    ($($name:ident),* $(,)?) => {
        $(mod $name;)*

        fn contribute<D: Disk>(
            config: &Config,
            host: &Host<D>,
            access: &mut Access,
        ) -> Result<(), StartError> {
            $($name::contribute(config, host, access)?;)*
            Ok(())
        }
    };
}

sections!(write, read, deny_read, deny_write);

/// What srt-win exits with when it holds the call off and nothing changed.
const EXIT_GRANT_BLOCKED: i32 = 24;

/// What srt-win exits with when a profile grant or forget holds the init lock
/// and nothing changed.
const EXIT_PROFILE_BUSY: i32 = 25;

/// Settings that list nothing, for a section to fill in the lists it owns.
const NO_PATHS: Settings<'static> = Settings {
    allow_read: &[],
    allow_write: &[],
    deny_read: &[],
    deny_write: &[],
    credential_deny: &[],
    masked_files: &[],
};

/// `settings` expanded and ranked on `host`.
fn ranked<D: Disk>(host: &Host<D>, settings: &Settings<'_>) -> Result<Access, StartError> {
    access(host, settings).map_err(|error| {
        StartError::UnresolvedPath(match error {
            ExpandError::NoHomeDirectory => PathError::NoHomeDirectory,
            ExpandError::NoWorkingDirectory => PathError::NoWorkingDirectory,
        })
    })
}

/// Adds the paths of `items` that `list` does not hold, so two sections that
/// reach the same path leave it once.
fn add_new(list: &mut Vec<String>, items: Vec<String>) {
    for item in items {
        if !list.contains(&item) {
            list.push(item);
        }
    }
}

/// The grants and denies one sandbox applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Plan {
    access: Access,
}

impl Plan {
    /// The plan `config` comes to on this host, beside the profile read grant
    /// `profile` records.
    ///
    /// # Errors
    ///
    /// [`StartError::UnresolvedPath`] when a path needs a home or working
    /// directory the host does not have, and [`StartError::ProfileConflicts`]
    /// when a grant meets what `profile` keeps out of reach.
    pub(crate) fn build(config: &Config, profile: &ProfileExclusions) -> Result<Self, StartError> {
        Self::build_on(config, &Host::from_process(), profile)
    }

    /// The plan `config` comes to on `host`.
    fn build_on<D: Disk>(
        config: &Config,
        host: &Host<D>,
        profile: &ProfileExclusions,
    ) -> Result<Self, StartError> {
        let mut access = Access::default();
        contribute(config, host, &mut access)?;
        profile::check(host, &access, profile)?;
        Ok(Self { access })
    }

    /// The roots the sandbox user may write, which every command is told.
    pub(crate) fn write_roots(&self) -> &[String] {
        &self.access.write
    }

    /// The `acl grant --persistent` call that applies the plan to the sandbox
    /// user `sid`, for the session of process `holder`. It is made whatever the
    /// lists hold, since it also records the process as a session.
    pub(crate) fn grant(&self, sid: &str, holder: u32) -> Call {
        let mut call = Call::new([
            "acl",
            "grant",
            "--holder-pid",
            &holder.to_string(),
            "--sandbox-user-sid",
            sid,
            "--persistent",
        ]);
        call.stdin = Some(serde_json::to_string(&self.access).expect("lists of strings serialize"));
        call
    }

    /// Makes the [`grant`](Self::grant) call through `srt`.
    ///
    /// # Errors
    ///
    /// [`StartError::GrantBlocked`] when srt-win exits 24,
    /// [`StartError::ProfileBusy`] when it exits 25, and
    /// [`StartError::GrantFailed`] for any other exit, or a call that did not
    /// run.
    pub(crate) fn apply(&self, srt: &dyn Srt, sid: &str, holder: u32) -> Result<(), StartError> {
        match srt.run(&self.grant(sid, holder)) {
            Ok(output) if output.succeeded() => Ok(()),
            Ok(output) => Err(match output.code {
                Some(EXIT_GRANT_BLOCKED) => StartError::GrantBlocked,
                Some(EXIT_PROFILE_BUSY) => StartError::ProfileBusy,
                code => StartError::GrantFailed {
                    code,
                    stderr: output.stderr.trim().to_owned(),
                },
            }),
            Err(_) => Err(StartError::GrantFailed {
                code: None,
                stderr: String::new(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::path::Path;
    use std::process::Command;

    use crabpot_core::config::{Filesystem, PathEntry};
    use crabpot_windows::fs_access::{DiskError, Entry, Kind};

    use super::super::command::{Params, wrap};
    use super::super::srt::{
        Output,
        fake::{Fake, exit, fail},
    };
    use super::*;
    use crate::ProfileConflict;

    /// A volume where only the listed directories exist, spelled as given.
    struct Volume(&'static [&'static str]);

    impl Disk for Volume {
        fn real_path(&self, path: &str) -> Result<String, DiskError> {
            self.0
                .iter()
                .find(|dir| dir.eq_ignore_ascii_case(path))
                .map(|dir| (*dir).to_owned())
                .ok_or(DiskError::Absent)
        }

        fn exists(&self, path: &str) -> bool {
            self.real_path(path).is_ok()
        }

        fn lstat(&self, path: &str) -> Result<Kind, DiskError> {
            self.real_path(path).map(|_| Kind::Dir)
        }

        fn read_dir(&self, _: &str) -> Result<Vec<Entry>, DiskError> {
            Ok(Vec::new())
        }
    }

    fn plan_for(allow_write: &[&str], dirs: &'static [&'static str]) -> Plan {
        plan_with(dirs, |filesystem| {
            filesystem.allow_write = entries(allow_write);
        })
    }

    fn plan_denying(
        allow_write: &[&str],
        deny_write: &[&str],
        dirs: &'static [&'static str],
    ) -> Plan {
        plan_with(dirs, |filesystem| {
            filesystem.allow_write = entries(allow_write);
            filesystem.deny_write = entries(deny_write);
        })
    }

    fn entries(paths: &[&str]) -> Vec<PathEntry> {
        paths
            .iter()
            .map(|path| PathEntry::Spelled((*path).to_owned()))
            .collect()
    }

    fn plan_with(dirs: &'static [&'static str], set: impl FnOnce(&mut Filesystem)) -> Plan {
        let mut config = Config::default();
        set(&mut config.filesystem);
        Plan::build_on(&config, &host(dirs), &ProfileExclusions::default()).unwrap()
    }

    fn host(dirs: &'static [&'static str]) -> Host<Volume> {
        Host::new(Some(r"C:\Users\me"), Some(r"C:\work"), Volume(dirs))
    }

    fn stdin(plan: &Plan) -> String {
        plan.grant("S-1-5-21-7", 4242).stdin.unwrap()
    }

    const DIRS: &[&str] = &[r"C:\work", r"D:\scratch"];

    #[test]
    fn an_empty_plan_still_makes_one_grant_call() {
        let plan = Plan::build(&Config::default(), &ProfileExclusions::default()).unwrap();

        let call = plan.grant("S-1-5-21-7", 4242);

        assert_eq!(
            call.args,
            [
                "acl",
                "grant",
                "--holder-pid",
                "4242",
                "--sandbox-user-sid",
                "S-1-5-21-7",
                "--persistent"
            ]
        );
        assert_eq!(
            call.stdin.as_deref(),
            Some(r#"{"read":[],"write":[],"denyRead":[],"denyWrite":[]}"#)
        );
        assert!(plan.write_roots().is_empty());
    }

    #[test]
    fn allow_write_roots_become_write_grants() {
        let plan = plan_for(&[r"C:\work", r"D:\scratch", r"E:\absent"], DIRS);

        let call = plan.grant("S-1-5-21-7", 4242);

        assert_eq!(
            call.stdin.as_deref(),
            Some(r#"{"read":[],"write":["C:\\work","D:\\scratch"],"denyRead":[],"denyWrite":[]}"#)
        );
        assert_eq!(plan.write_roots(), [r"C:\work", r"D:\scratch"]);
    }

    #[test]
    fn each_write_root_gets_a_write_root_flag() {
        let plan = plan_for(&[r"C:\work", r"D:\scratch"], DIRS);
        let params = Params {
            exe: Path::new(r"C:\crabpot\crabpot.exe"),
            held_by: 4242,
            write_roots: plan.write_roots(),
            git_safe_directories: &[],
            allow_loopback: false,
            proxy_port: 60080,
            token: "tok",
        };

        let wrapped = wrap(&params, &Command::new("echo")).unwrap();

        let args: Vec<_> = wrapped
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        let flags: Vec<_> = args
            .windows(2)
            .filter(|pair| pair[0] == "--write-root")
            .map(|pair| pair[1].as_str())
            .collect();
        assert_eq!(flags, [r"C:\work", r"D:\scratch"]);
    }

    #[test]
    fn a_write_root_at_or_under_a_deny_write_is_not_granted() {
        let plan = plan_denying(
            &[r"C:\work", r"C:\work\out", r"D:\scratch"],
            &[r"C:\work"],
            &[r"C:\work", r"C:\work\out", r"D:\scratch"],
        );

        assert_eq!(plan.write_roots(), [r"D:\scratch"]);
    }

    #[test]
    fn deny_read_reaches_the_grant_stdin() {
        let plan = plan_with(DIRS, |filesystem| {
            filesystem.deny_read = entries(&[r"C:\work\secrets", r"~\.ssh"]);
        });

        assert_eq!(
            stdin(&plan),
            r#"{"read":[],"write":[],"denyRead":["C:\\work\\secrets","C:\\Users\\me\\.ssh"],"denyWrite":[]}"#
        );
    }

    #[test]
    fn deny_write_downgrades_an_allow_write_to_read() {
        let plan = plan_denying(
            &[r"C:\work", r"D:\scratch"],
            &[r"D:\scratch"],
            &[r"C:\work", r"D:\scratch"],
        );

        assert_eq!(
            stdin(&plan),
            r#"{"read":["D:\\scratch"],"write":["C:\\work"],"denyRead":[],"denyWrite":["D:\\scratch"]}"#
        );
        assert_eq!(plan.write_roots(), [r"C:\work"]);
    }

    const SSH_DIRS: &[&str] = &[r"C:\work", r"C:\work\.ssh\config"];

    fn deny_read_plan(
        deny_read: &[&str],
        allow_read: &[&str],
        credential_deny: &[&str],
        dirs: &'static [&'static str],
    ) -> Plan {
        let mut config = Config::default();
        config.filesystem.deny_read = entries(deny_read);
        config.filesystem.allow_read = Some(entries(allow_read));
        let mut access = Access::default();
        deny_read::contribute_with_credentials(
            &config,
            &host(dirs),
            &entries(credential_deny),
            &mut access,
        )
        .unwrap();
        Plan { access }
    }

    #[test]
    fn an_allow_read_beneath_a_deny_read_is_granted_again() {
        let plan = deny_read_plan(&[r"C:\work"], &[r"C:\work\.ssh\config"], &[], SSH_DIRS);

        assert_eq!(
            stdin(&plan),
            r#"{"read":["C:\\work\\.ssh\\config"],"write":[],"denyRead":["C:\\work"],"denyWrite":[]}"#
        );
    }

    #[test]
    fn a_credential_deny_drops_the_grants_beneath_it() {
        let plan = deny_read_plan(
            &[r"C:\work"],
            &[r"C:\work\.ssh\config"],
            &[r"C:\work\.ssh"],
            SSH_DIRS,
        );

        assert_eq!(
            stdin(&plan),
            r#"{"read":[],"write":[],"denyRead":["C:\\work","C:\\work\\.ssh"],"denyWrite":[]}"#
        );
    }

    #[test]
    fn allow_read_reaches_the_grant_stdin() {
        let plan = plan_with(DIRS, |filesystem| {
            filesystem.allow_read = Some(entries(&[r"D:\scratch", r"E:\absent"]));
        });

        assert_eq!(
            stdin(&plan),
            r#"{"read":["D:\\scratch"],"write":[],"denyRead":[],"denyWrite":[]}"#
        );
    }

    #[test]
    fn an_allow_read_beneath_a_deny_read_is_granted_once() {
        let plan = deny_read_plan(&[r"C:\work"], &[r"C:\work\.ssh\config"], &[], SSH_DIRS);

        let mut config = Config::default();
        config.filesystem.deny_read = entries(&[r"C:\work"]);
        config.filesystem.allow_read = Some(entries(&[r"C:\work\.ssh\config"]));
        let both = Plan::build_on(&config, &host(SSH_DIRS), &ProfileExclusions::default()).unwrap();

        assert_eq!(stdin(&both), stdin(&plan));
    }

    fn profile(exclusions: &[&str], ungranted_only: &[&str]) -> ProfileExclusions {
        ProfileExclusions {
            exclusions: exclusions.iter().map(|path| (*path).to_owned()).collect(),
            ungranted_only: ungranted_only
                .iter()
                .map(|path| (*path).to_owned())
                .collect(),
        }
    }

    fn build_beside(
        profile: &ProfileExclusions,
        dirs: &'static [&'static str],
        set: impl FnOnce(&mut Filesystem),
    ) -> Result<Plan, StartError> {
        let mut config = Config::default();
        set(&mut config.filesystem);
        Plan::build_on(&config, &host(dirs), profile)
    }

    const PROFILE_DIRS: &[&str] = &[r"C:\Users\me", r"C:\Users\me\.ssh", r"C:\work"];

    #[test]
    fn a_profile_conflict_is_a_typed_error() {
        let recorded = profile(&[r"C:\Users\me\.ssh"], &[]);

        let error = build_beside(&recorded, PROFILE_DIRS, |filesystem| {
            filesystem.allow_read = Some(entries(&[r"C:\Users\me", r"C:\work"]));
            filesystem.allow_write = entries(&[r"C:\Users\me\.ssh"]);
        })
        .unwrap_err();

        assert_eq!(
            error,
            StartError::ProfileConflicts(vec![
                ProfileConflict {
                    path: r"C:\Users\me".to_owned(),
                    exclusion: r"C:\Users\me\.ssh".to_owned(),
                    write: false,
                },
                ProfileConflict {
                    path: r"C:\Users\me\.ssh".to_owned(),
                    exclusion: r"C:\Users\me\.ssh".to_owned(),
                    write: true,
                },
            ])
        );
    }

    #[test]
    fn grants_clear_of_the_profile_exclusions_are_no_conflict() {
        let recorded = profile(&[r"C:\Users\me\.ssh"], &[]);

        let plan = build_beside(&recorded, PROFILE_DIRS, |filesystem| {
            filesystem.allow_read = Some(entries(&[r"C:\work"]));
        });

        assert!(plan.is_ok());
    }

    #[test]
    fn a_failed_grant_carries_what_srt_win_printed() {
        let (srt, _) = Fake::answering(|_| fail(1, "deny refused: x\n"));
        let plan = Plan::build(&Config::default(), &ProfileExclusions::default()).unwrap();

        let error = plan.apply(&srt, "S-1-5-21-7", 4242).unwrap_err();

        assert_eq!(
            error,
            StartError::GrantFailed {
                code: Some(1),
                stderr: "deny refused: x".to_owned()
            }
        );
        assert!(error.to_string().ends_with("exited 1: deny refused: x"));
    }

    #[test]
    fn a_failed_grant_that_printed_nothing_keeps_its_message() {
        let (srt, _) = Fake::answering(|_| fail(1, " \n"));
        let plan = Plan::build(&Config::default(), &ProfileExclusions::default()).unwrap();

        let error = plan.apply(&srt, "S-1-5-21-7", 4242).unwrap_err();

        assert_eq!(error.to_string(), "`srt-win acl grant` exited 1");
    }

    #[test]
    fn a_grant_call_that_did_not_run_carries_no_stderr() {
        #[derive(Debug)]
        struct Broken;
        impl Srt for Broken {
            fn run(&self, _: &Call) -> io::Result<Output> {
                Err(io::Error::other("no srt-win"))
            }
        }
        let plan = Plan::build(&Config::default(), &ProfileExclusions::default()).unwrap();

        let error = plan.apply(&Broken, "S-1-5-21-7", 4242).unwrap_err();

        assert_eq!(
            error,
            StartError::GrantFailed {
                code: None,
                stderr: String::new()
            }
        );
        assert_eq!(error.to_string(), "`srt-win acl grant` did not run");
    }

    #[test]
    fn exit_25_maps_to_the_profile_busy_error() {
        let (srt, _) = Fake::answering(|_| exit(25, ""));
        let plan = Plan::build(&Config::default(), &ProfileExclusions::default()).unwrap();

        let error = plan.apply(&srt, "S-1-5-21-7", 4242).unwrap_err();

        assert_eq!(error, StartError::ProfileBusy);
    }

    #[test]
    fn exit_24_maps_to_the_grant_blocked_error() {
        let (srt, _) = Fake::answering(|_| exit(24, ""));
        let plan = Plan::build(&Config::default(), &ProfileExclusions::default()).unwrap();

        let error = plan.apply(&srt, "S-1-5-21-7", 4242).unwrap_err();

        assert_eq!(error, StartError::GrantBlocked);
    }
}
