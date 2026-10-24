//! What a Windows sandbox asks srt-win to grant and deny, from a [`Config`].
//!
//! A plan is built by sections, each a file in the `plan` folder with a
//! `contribute` function, and registered by naming it in the `sections!` call.
//! A section adds to the lists the one `acl grant --persistent` call reads from
//! standard input. None exists yet, so every list is empty.

use crabpot_core::config::Config;
use crabpot_windows::fs_access::Access;

use super::srt::Call;
use crate::StartError;

/// Declares each section's module and lists them in the order they run.
macro_rules! sections {
    ($($name:ident),* $(,)?) => {
        $(mod $name;)*

        const SECTIONS: &[fn(&Config, &mut Access) -> Result<(), StartError>] =
            &[$($name::contribute),*];
    };
}

sections!();

/// The grants and denies one sandbox applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Plan {
    access: Access,
}

impl Plan {
    /// The plan `config` comes to.
    pub(crate) fn build(config: &Config) -> Result<Self, StartError> {
        let mut access = Access::default();
        for section in SECTIONS {
            section(config, &mut access)?;
        }
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
    use super::*;

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
}
