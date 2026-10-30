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
    named(claude_code_tmpdir)
        .or_else(|| named(claude_tmpdir))
        .map_or_else(|| OsString::from(DEFAULT_TMPDIR), OsString::from)
}

/// Whether the host names a temp folder of its own, so [`tmpdir`] is not the
/// default.
#[must_use]
pub fn tmpdir_is_host_named(
    claude_code_tmpdir: Option<&OsStr>,
    claude_tmpdir: Option<&OsStr>,
) -> bool {
    named(claude_code_tmpdir)
        .or_else(|| named(claude_tmpdir))
        .is_some()
}

/// The name, when it carries something.
fn named(value: Option<&OsStr>) -> Option<&OsStr> {
    value.filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_folder_is_no_host_name() {
        let empty = OsStr::new("");

        assert!(!tmpdir_is_host_named(None, None));
        assert!(!tmpdir_is_host_named(Some(empty), Some(empty)));
        assert!(tmpdir_is_host_named(Some(OsStr::new("/a")), None));
        assert!(tmpdir_is_host_named(None, Some(OsStr::new("/b"))));
    }
}
