//! `denyWrite`: the paths the sandbox user may not write.
//!
//! A write deny beats an `allowWrite` grant at or beneath it, as on the other
//! platforms, and that grant falls back to a read grant, since the sandbox
//! user may still read what it may no longer write. The write section leaves
//! such a root out of the write grants, and this one grants it read.

use crabpot_core::config::Config;
use crabpot_windows::fs_access::{Access, Disk, Host, Settings};

use super::{NO_PATHS, add_new, ranked};
use crate::StartError;

/// Adds the `denyWrite` paths to the write denies, and the `allowWrite` roots
/// at or beneath one to the read grants.
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
    let ranked = ranked(host, &settings)?;
    add_new(&mut access.deny_write, ranked.deny_write);
    add_new(&mut access.read, ranked.read);
    Ok(())
}
