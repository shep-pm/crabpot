//! What a Windows sandbox asks srt-win to grant and deny, from a [`Config`].
//!
//! A plan is built by sections, each a file in the `plan` folder with a
//! `contribute` function, and registered by naming it in the `sections!` call.
//! A section adds to the lists the one `acl grant --persistent` call reads from
//! standard input. Only `write` exists so far, so the other lists are empty.

use crabpot_core::config::Config;
use crabpot_windows::fs_access::{Access, Disk, Host};

use super::srt::Call;
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

sections!(write);

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
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::process::Command;

    use crabpot_core::config::PathEntry;
    use crabpot_windows::fs_access::{DiskError, Entry, Kind};

    use super::super::command::{Params, wrap};
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
        plan_denying(allow_write, &[], dirs)
    }

    fn plan_denying(
        allow_write: &[&str],
        deny_write: &[&str],
        dirs: &'static [&'static str],
    ) -> Plan {
        let entries = |paths: &[&str]| -> Vec<PathEntry> {
            paths
                .iter()
                .map(|path| PathEntry::Spelled((*path).to_owned()))
                .collect()
        };
        let mut config = Config::default();
        config.filesystem.allow_write = entries(allow_write);
        config.filesystem.deny_write = entries(deny_write);
        let host = Host::new(Some(r"C:\Users\me"), Some(r"C:\work"), Volume(dirs));
        Plan::build_on(&config, &host).unwrap()
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
}
