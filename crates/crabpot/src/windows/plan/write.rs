//! `allowWrite`: the roots the sandbox user may write.
//!
//! Windows has no default write paths. Upstream's `computeWindowsFsAccessSet`
//! grants what `allowWrite` names and nothing else, less what `denyWrite`
//! covers: a root at or under a write deny is not a write root.
//!
//! The denies themselves, and the read grant such a root falls back to, belong
//! to the sections that own those lists.

use crabpot_core::config::Config;
use crabpot_windows::fs_access::{Access, Disk, Host, Settings};

use super::{NO_PATHS, ranked};
use crate::StartError;

/// Adds the roots `allowWrite` names, ranked under `denyWrite`, to the write
/// grants.
pub(super) fn contribute<D: Disk>(
    config: &Config,
    host: &Host<D>,
    access: &mut Access,
) -> Result<(), StartError> {
    let filesystem = &config.filesystem;
    let settings = Settings {
        allow_write: &filesystem.allow_write,
        deny_write: &filesystem.deny_write,
        ..NO_PATHS
    };
    access.write.extend(ranked(host, &settings)?.write);
    Ok(())
}
