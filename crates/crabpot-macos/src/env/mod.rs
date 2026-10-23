//! The environment a sandboxed command starts with.
//!
//! A part is a file in this folder with a `vars` function, and it is
//! registered by naming it in the `parts!` call. The parts apply in that
//! order, and after whatever the command carried in, so a later part wins
//! over an earlier one and over the host.

use std::ffi::OsString;

/// Declares each part's module and lists them in the order they apply.
macro_rules! parts {
    ($($name:ident),* $(,)?) => {
        $(mod $name;)*

        const PARTS: &[fn(&Facts) -> Vec<(OsString, OsString)>] = &[$($name::vars),*];
    };
}

parts!(base, java);

/// What the parts are built from: what the sandbox lets the command reach,
/// and the names it inherits from the host.
#[derive(Debug)]
pub struct Facts {
    /// Whether the sandbox lets the command reach loopback at all.
    pub loopback_reachable: bool,
    /// `CLAUDE_CODE_TMPDIR`, as the host carries it.
    pub claude_code_tmpdir: Option<OsString>,
    /// `CLAUDE_TMPDIR`, as the host carries it.
    pub claude_tmpdir: Option<OsString>,
    /// `JAVA_TOOL_OPTIONS`, as the host carries it.
    pub java_tool_options: Option<OsString>,
}

impl Facts {
    /// Reads the inherited names from this process's environment, which is
    /// the environment a wrapped command inherits from too.
    pub fn from_process(loopback_reachable: bool) -> Self {
        use std::env;

        Self {
            loopback_reachable,
            claude_code_tmpdir: env::var_os("CLAUDE_CODE_TMPDIR"),
            claude_tmpdir: env::var_os("CLAUDE_TMPDIR"),
            java_tool_options: env::var_os("JAVA_TOOL_OPTIONS"),
        }
    }
}

/// The variables to set on a wrapped command, in the order to set them in.
#[must_use]
pub fn vars(facts: &Facts) -> Vec<(OsString, OsString)> {
    let mut vars = Vec::new();
    for part in PARTS {
        vars.extend(part(facts));
    }
    vars
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(claude_code_tmpdir: Option<&str>, claude_tmpdir: Option<&str>) -> Facts {
        Facts {
            loopback_reachable: false,
            claude_code_tmpdir: claude_code_tmpdir.map(OsString::from),
            claude_tmpdir: claude_tmpdir.map(OsString::from),
            java_tool_options: None,
        }
    }

    fn tmpdir(facts: &Facts) -> Option<OsString> {
        vars(facts)
            .into_iter()
            .find(|(name, _)| name == "TMPDIR")
            .map(|(_, value)| value)
    }

    #[test]
    fn sandbox_runtime_and_tmpdir_are_set() {
        assert_eq!(
            vars(&facts(None, None)),
            vec![
                (OsString::from("SANDBOX_RUNTIME"), OsString::from("1")),
                (OsString::from("TMPDIR"), OsString::from("/tmp/claude")),
            ],
        );
    }

    #[test]
    fn tmpdir_prefers_claude_code_tmpdir_then_claude_tmpdir() {
        assert_eq!(
            tmpdir(&facts(Some("/tmp/code"), Some("/tmp/legacy"))),
            Some(OsString::from("/tmp/code")),
        );
        assert_eq!(
            tmpdir(&facts(None, Some("/tmp/legacy"))),
            Some(OsString::from("/tmp/legacy")),
        );
        assert_eq!(
            tmpdir(&facts(Some(""), Some("/tmp/legacy"))),
            Some(OsString::from("/tmp/legacy")),
            "an empty name is no answer, as upstream's `||` reads it",
        );
    }
}
