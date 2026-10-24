//! The write denies that are always on in and below the working directory.
//!
//! Upstream calls `linuxGetMandatoryDenyPaths` from its deny loop, beside the
//! entries `denyWrite` names, and the loop denies both alike. This section makes
//! no mount of its own for the same reason: it walks the tree and hands the list
//! to [`deny_write`](super::deny_write), which puts it after the settings' own
//! and denies every path in it the way it denies one the settings name.
//!
//! The walk is [`mandatory`](crate::mandatory), at upstream's depth and time
//! limit. A walk that runs out of time counts for what it had found by then, as
//! upstream's does when it kills `rg`: what it had not come to is not denied.
//!
//! A deny the plan cannot spell is another matter. The words are what `exec`
//! takes, and a name that is not text has no mount to write, so a plan that
//! dropped it would run the command with that path open. It is an error, and
//! there is no plan.

use std::ffi::OsString;
#[cfg(unix)]
use std::path::Path;

use crabpot_core::config::Config;
#[cfg(unix)]
use crabpot_core::paths::normalize_path_for_sandbox;
use crabpot_core::paths::PathBase;

#[cfg(unix)]
use crate::mandatory::{DEFAULT_MANDATORY_DENY_SEARCH_DEPTH, mandatory_deny_paths};

use super::{Draft, PlanError};

pub(super) fn words(
    config: &Config,
    base: &PathBase,
    draft: &mut Draft,
) -> Result<Vec<OsString>, PlanError> {
    draft.mandatory_denies = deny_paths(config, base)?;
    Ok(Vec::new())
}

/// Every path the working directory denies writes to, as `deny_write` wants
/// them: absolute, and spelled as text.
///
/// # Errors
///
/// [`PlanError::Unspellable`] when the walk finds a path that is not text, and
/// [`PlanError::Path`] when `base` has no working directory to walk.
#[cfg(unix)]
fn deny_paths(config: &Config, base: &PathBase) -> Result<Vec<String>, PlanError> {
    // The working directory as upstream's `process.cwd()` is: a real path,
    // which is what the walk asks for. Without one there is no tree to walk,
    // and a plan with no mandatory denies is one that lets the command write
    // whatever it finds.
    let cwd = normalize_path_for_sandbox(base, ".", true)?;
    let found = mandatory_deny_paths(
        Path::new(&cwd),
        DEFAULT_MANDATORY_DENY_SEARCH_DEPTH,
        config.filesystem.allow_git_config.unwrap_or(false),
    );
    let mut denies = Vec::new();
    for path in found {
        let Some(spelling) = path.to_str() else {
            return Err(PlanError::Unspellable { path });
        };
        denies.push(spelling.to_owned());
    }
    Ok(denies)
}

/// There is no tree to walk off Unix: [`mandatory`](crate::mandatory) is gated
/// with the bwrap plan it feeds, and this crate builds off Unix only for the
/// cross-target gates, where no plan here is ever handed to a sandbox.
#[cfg(not(unix))]
fn deny_paths(_config: &Config, _base: &PathBase) -> Result<Vec<String>, PlanError> {
    Ok(Vec::new())
}
