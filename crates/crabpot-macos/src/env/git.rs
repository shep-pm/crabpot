//! The part of the environment that tells git which directories are safe,
//! built by [`crabpot_core::env::git`].
//!
//! Emitted only for a config that names directories, as upstream's
//! `buildPosixGitSafeDirEnv` is called only for a non-empty list.

use std::ffi::OsString;

use super::Facts;

/// The name a command carries its git config count in, and the name this part
/// amends rather than owns.
pub(super) const GIT_CONFIG_COUNT: &str = "GIT_CONFIG_COUNT";

pub(super) fn vars(facts: &Facts) -> Vec<(OsString, OsString)> {
    if facts.git_safe_directories.is_empty() {
        return Vec::new();
    }
    let carried = facts
        .git_config_count
        .as_deref()
        .map(|count| count.to_string_lossy());
    crabpot_core::env::git::safe_directory_vars(&facts.git_safe_directories, carried.as_deref())
        .into_iter()
        .map(|(name, value)| (OsString::from(name), OsString::from(value)))
        .collect()
}
