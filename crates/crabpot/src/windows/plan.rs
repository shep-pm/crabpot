//! What a Windows sandbox asks srt-win to grant and deny, from a [`Config`].
//!
//! A plan is built by sections, each a file in the `plan` folder with a
//! `contribute` function, and registered by naming it in the `sections!` call.
//! A section adds to the lists the one `acl grant --persistent` call reads from
//! standard input. Each section ranks only the lists it owns, so the lists it
//! does not read are empty: the read grants are not here yet.

use crabpot_core::PathError;
use crabpot_core::config::Config;
use crabpot_windows::fs_access::{Access, Disk, ExpandError, Host, Settings, access};

use super::srt::{Call, Srt};
use crate::StartError;

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

sections!(write, deny_read, deny_write);

/// What srt-win exits with when something holds a grant off and nothing
/// changed: 25 when a profile grant or forget holds the init lock, which is how
/// `acl grant` meets it, and 24, which `profile grant` gives for a running
/// session and the issue names for this call as well.
const EXIT_GRANT_BLOCKED: [i32; 2] = [24, 25];

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
    /// The plan `config` comes to on this host.
    ///
    /// # Errors
    ///
    /// [`StartError::UnresolvedPath`] when a path needs a home or working
    /// directory the host does not have.
    pub(crate) fn build(config: &Config) -> Result<Self, StartError> {
        Self::build_on(config, &Host::from_process())
    }

    /// The plan `config` comes to on `host`.
    fn build_on<D: Disk>(config: &Config, host: &Host<D>) -> Result<Self, StartError> {
        let mut access = Access::default();
        contribute(config, host, &mut access)?;
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
    /// [`StartError::GrantBlocked`] when srt-win exits 24 or 25, and
    /// [`StartError::GrantFailed`] for any other exit, or a call that did not
    /// run.
    pub(crate) fn apply(&self, srt: &dyn Srt, sid: &str, holder: u32) -> Result<(), StartError> {
        match srt.run(&self.grant(sid, holder)) {
            Ok(output) if output.succeeded() => Ok(()),
            Ok(output)
                if output
                    .code
                    .is_some_and(|code| EXIT_GRANT_BLOCKED.contains(&code)) =>
            {
                Err(StartError::GrantBlocked)
            }
            Ok(output) => Err(StartError::GrantFailed { code: output.code }),
            Err(_) => Err(StartError::GrantFailed { code: None }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::process::Command;

    use crabpot_core::config::{Filesystem, PathEntry};
    use crabpot_windows::fs_access::{DiskError, Entry, Kind};

    use super::super::command::{Params, wrap};
    use super::super::srt::fake::{Fake, exit};
    use super::*;

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
        Plan::build_on(&config, &host(dirs)).unwrap()
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
        let plan = Plan::build(&Config::default()).unwrap();

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
    fn exit_24_maps_to_the_grant_blocked_error() {
        let (srt, _) = Fake::answering(|_| exit(24, ""));
        let plan = Plan::build(&Config::default()).unwrap();

        let error = plan.apply(&srt, "S-1-5-21-7", 4242).unwrap_err();

        assert_eq!(error, StartError::GrantBlocked);
    }

    #[test]
    fn exit_25_maps_to_the_grant_blocked_error() {
        let (srt, _) = Fake::answering(|_| exit(25, ""));
        let plan = Plan::build(&Config::default()).unwrap();

        let error = plan.apply(&srt, "S-1-5-21-7", 4242).unwrap_err();

        assert_eq!(error, StartError::GrantBlocked);
    }
}
