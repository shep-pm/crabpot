//! `allowRead`: the paths the sandbox user may read outside the profile grant.
//!
//! The profile read grant covers the user profile and what the install lists,
//! so a read anywhere else needs an `allowRead` path. A path beneath a
//! `denyRead` is granted again by [`deny_read`](super::deny_read), which asks
//! for that same grant, so the plan holds it once.

use crabpot_core::config::Config;
use crabpot_windows::fs_access::{Access, Disk, Host, Settings};

use super::{NO_PATHS, add_new, ranked};
use crate::StartError;

/// Adds the paths `allowRead` names to the read grants.
pub(super) fn contribute<D: Disk>(
    config: &Config,
    host: &Host<D>,
    access: &mut Access,
) -> Result<(), StartError> {
    let settings = Settings {
        allow_read: config.filesystem.allow_read.as_deref().unwrap_or_default(),
        ..NO_PATHS
    };
    add_new(&mut access.read, ranked(host, &settings)?.read);
    Ok(())
}
