//! The part of the environment every sandboxed command gets, whatever the
//! config says.
//!
//! Upstream's `generateProxyEnvVars` in `src/sandbox/sandbox-utils.ts`, which
//! runs on macOS and on Linux alike. The temp folder is one of the paths a
//! filesystem policy always allows writing to
//! ([`crate::paths::default_write_paths`]), so a command that writes temp
//! files lands where the sandbox lets it.

use std::ffi::{OsStr, OsString};

/// Where a command's temp files go when the host names no folder of its own.
pub(crate) const DEFAULT_TMPDIR: &str = "/tmp/claude";

/// The names the sandbox owns: the marker a tool reads to tell it runs inside
/// the sandbox, and the temp folder it writes to.
///
/// `claude_code_tmpdir` and `claude_tmpdir` are what the host carries under
/// `CLAUDE_CODE_TMPDIR` and `CLAUDE_TMPDIR`.
#[must_use]
pub fn vars(
    claude_code_tmpdir: Option<&OsStr>,
    claude_tmpdir: Option<&OsStr>,
) -> Vec<(OsString, OsString)> {
    vec![
        (OsString::from("SANDBOX_RUNTIME"), OsString::from("1")),
        (
            OsString::from("TMPDIR"),
            tmpdir(claude_code_tmpdir, claude_tmpdir),
        ),
    ]
}

/// The host's own temp folder, under the name it uses now and the one it used
/// before, or `/tmp/claude`. A name that carries nothing is no answer.
///
/// The folder `TMPDIR` is set to, and the one the sandbox makes and may write.
#[must_use]
pub fn tmpdir(claude_code_tmpdir: Option<&OsStr>, claude_tmpdir: Option<&OsStr>) -> OsString {
    tmpdir_named(claude_code_tmpdir, claude_tmpdir).0
}

/// [`tmpdir`], and whether the host named it, as opposed to the default.
#[must_use]
pub fn tmpdir_named(
    claude_code_tmpdir: Option<&OsStr>,
    claude_tmpdir: Option<&OsStr>,
) -> (OsString, bool) {
    match named(claude_code_tmpdir).or_else(|| named(claude_tmpdir)) {
        Some(name) => (name.to_owned(), true),
        None => (OsString::from(DEFAULT_TMPDIR), false),
    }
}

/// The name, when it carries something.
fn named(value: Option<&OsStr>) -> Option<&OsStr> {
    value.filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chosen(code: Option<&str>, old: Option<&str>) -> (OsString, bool) {
        tmpdir_named(code.map(OsStr::new), old.map(OsStr::new))
    }

    #[test]
    fn the_default_folder_is_no_host_name() {
        let default = (OsString::from("/tmp/claude"), false);

        assert_eq!(chosen(None, None), default);
        assert_eq!(chosen(Some(""), Some("")), default);
    }

    #[test]
    fn claude_code_tmpdir_wins_over_claude_tmpdir() {
        assert_eq!(chosen(Some("/a"), Some("/b")), (OsString::from("/a"), true));
        assert_eq!(chosen(None, Some("/b")), (OsString::from("/b"), true));
        assert_eq!(chosen(Some(""), Some("/b")), (OsString::from("/b"), true));
    }

    #[test]
    fn tmpdir_is_the_folder_of_tmpdir_named() {
        assert_eq!(tmpdir(Some(OsStr::new("/a")), None), OsString::from("/a"));
    }
}
