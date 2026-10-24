//! The environment a sandboxed command is given on Linux.
//!
//! The base part is the platform-independent one
//! ([`crabpot_core::env::base`]), and the names it sets are the sandbox's own:
//! they are set over whatever the command carried, since the sandbox is what
//! makes the folder `TMPDIR` names writable.

use std::env;
use std::ffi::OsString;

/// What the environment is built from: the names the command inherits from the
/// host.
#[derive(Debug, Clone)]
pub struct Facts {
    /// `CLAUDE_CODE_TMPDIR`, as the host carries it.
    pub claude_code_tmpdir: Option<OsString>,
    /// `CLAUDE_TMPDIR`, as the host carries it.
    pub claude_tmpdir: Option<OsString>,
}

impl Facts {
    /// The facts of a sandbox started by this process. The inherited names come
    /// from this process's environment, which is the environment a wrapped
    /// command inherits from too.
    #[must_use]
    pub fn for_sandbox() -> Self {
        Self {
            claude_code_tmpdir: env::var_os("CLAUDE_CODE_TMPDIR"),
            claude_tmpdir: env::var_os("CLAUDE_TMPDIR"),
        }
    }
}

/// The variables to set on a wrapped command, in the order to set them in.
#[must_use]
pub fn vars(facts: &Facts) -> Vec<(OsString, OsString)> {
    crabpot_core::env::base::vars(
        facts.claude_code_tmpdir.as_deref(),
        facts.claude_tmpdir.as_deref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(claude_code_tmpdir: Option<&str>, claude_tmpdir: Option<&str>) -> Facts {
        Facts {
            claude_code_tmpdir: claude_code_tmpdir.map(OsString::from),
            claude_tmpdir: claude_tmpdir.map(OsString::from),
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
    }

    #[test]
    fn an_empty_name_is_no_answer() {
        assert_eq!(
            tmpdir(&facts(Some(""), Some("/tmp/legacy"))),
            Some(OsString::from("/tmp/legacy")),
            "an empty name is no answer, as upstream's `||` reads it",
        );
        assert_eq!(
            tmpdir(&facts(Some("/tmp/code"), Some(""))),
            Some(OsString::from("/tmp/code")),
            "the empty name is skipped, not chosen",
        );
        assert_eq!(
            tmpdir(&facts(Some(""), Some(""))),
            Some(OsString::from("/tmp/claude")),
            "two empty names are no answer either",
        );
    }
}
