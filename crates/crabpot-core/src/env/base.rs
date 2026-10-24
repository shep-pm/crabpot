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
const DEFAULT_TMPDIR: &str = "/tmp/claude";

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
/// before. A name that carries nothing is no answer.
fn tmpdir(claude_code_tmpdir: Option<&OsStr>, claude_tmpdir: Option<&OsStr>) -> OsString {
    named(claude_code_tmpdir)
        .or_else(|| named(claude_tmpdir))
        .map_or_else(|| OsString::from(DEFAULT_TMPDIR), OsString::from)
}

/// The name, when it carries something.
fn named(value: Option<&OsStr>) -> Option<&OsStr> {
    value.filter(|value| !value.is_empty())
}
