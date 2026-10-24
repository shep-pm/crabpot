//! The part of the environment every sandboxed command gets, whatever the
//! config says.
//!
//! Built by [`crabpot_core::env::base`], which the Linux command environment
//! is built from too.

use std::ffi::OsString;

use super::Facts;

pub(super) fn vars(facts: &Facts) -> Vec<(OsString, OsString)> {
    crabpot_core::env::base::vars(
        facts.claude_code_tmpdir.as_deref(),
        facts.claude_tmpdir.as_deref(),
    )
}
