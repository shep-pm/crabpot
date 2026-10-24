//! `allowWrite`: the roots the sandbox user may write.
//!
//! Windows has no default write paths. Upstream's `computeWindowsFsAccessSet`
//! grants what `allowWrite` names and nothing else.

use crabpot_core::config::Config;
use crabpot_core::PathError;
use crabpot_windows::fs_access::{Access, Disk, ExpandError, Host, Mode, expand_paths};

use crate::StartError;

/// Adds the roots `allowWrite` names to the write grants.
pub(super) fn contribute<D: Disk>(
    config: &Config,
    host: &Host<D>,
    access: &mut Access,
) -> Result<(), StartError> {
    let roots = expand_paths(host, &config.filesystem.allow_write, Mode::Grant).map_err(
        |error| {
            StartError::UnresolvedPath(match error {
                ExpandError::NoHomeDirectory => PathError::NoHomeDirectory,
                ExpandError::NoWorkingDirectory => PathError::NoWorkingDirectory,
            })
        },
    )?;
    access.write.extend(roots);
    Ok(())
}
