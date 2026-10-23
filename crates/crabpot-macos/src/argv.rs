//! The `sandbox-exec` command line that runs a program under a profile.

use std::ffi::{OsStr, OsString};

/// Where macOS keeps `sandbox-exec`. A path and not a lookup, so a `PATH`
/// entry cannot stand in for it.
pub const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// The arguments `sandbox-exec` takes to run `program` with `args` under
/// `profile`. The program is exec'd by `sandbox-exec` itself, with no shell
/// between.
#[must_use]
pub fn sandbox_exec(
    profile: &str,
    program: &OsStr,
    args: impl IntoIterator<Item = OsString>,
) -> Vec<OsString> {
    let mut argv = vec![
        OsString::from("-p"),
        OsString::from(profile),
        program.to_owned(),
    ];
    argv.extend(args);
    argv
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_argv_is_sandbox_exec_p_profile_then_the_program() {
        let argv = sandbox_exec(
            "(version 1)",
            OsStr::new("echo"),
            ["hello".into(), "a b".into()],
        );

        assert_eq!(
            argv,
            ["-p", "(version 1)", "echo", "hello", "a b"].map(OsString::from)
        );
    }
}
