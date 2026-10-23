//! The part of the environment every sandboxed command gets, whatever the
//! config says.
//!
//! `src/sandbox/sandbox-utils.ts` `generateProxyEnvVars`. The temp folder is
//! one of the paths a filesystem policy always allows writing to, so a command
//! that writes temp files lands where the profile lets it.

use std::ffi::OsString;

use super::Facts;

/// Where a command's temp files go when the host names no folder of its own.
const DEFAULT_TMPDIR: &str = "/tmp/claude";

pub(super) fn vars(facts: &Facts) -> Vec<(OsString, OsString)> {
    vec![
        (OsString::from("SANDBOX_RUNTIME"), OsString::from("1")),
        (OsString::from("TMPDIR"), tmpdir(facts)),
    ]
}

/// The host's own temp folder, under the name it uses now and the one it used
/// before. A name that carries nothing is no answer.
fn tmpdir(facts: &Facts) -> OsString {
    facts
        .claude_code_tmpdir
        .as_ref()
        .filter(|value| !value.is_empty())
        .or_else(|| facts.claude_tmpdir.as_ref().filter(|value| !value.is_empty()))
        .cloned()
        .unwrap_or_else(|| OsString::from(DEFAULT_TMPDIR))
}
