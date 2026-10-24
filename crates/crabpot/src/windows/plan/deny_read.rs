//! `denyRead`: the paths the sandbox user may not read.
//!
//! A deny beats a grant above it and loses to one beneath it, as on the other
//! platforms. `denyReadExcept` is `allowRead`: a path of it beneath a deny is
//! granted again, which `srt-win` lets win since the ACE set further down is
//! the one that counts. A credential deny drops the `allowRead` paths beneath
//! it, so those are not granted again.
//!
//! The rest of `allowRead` belongs to the section that owns it.

use crabpot_core::config::{Config, PathEntry};
use crabpot_windows::fs_access::{Access, Disk, Host, Settings, grants_beneath_denies};

use super::{NO_PATHS, add_new, ranked};
use crate::StartError;

/// Adds the `denyRead` paths to the read denies, and the `allowRead` paths
/// beneath one to the read grants.
pub(super) fn contribute<D: Disk>(
    config: &Config,
    host: &Host<D>,
    access: &mut Access,
) -> Result<(), StartError> {
    // `credentials` is refused, so no file is a credential file yet.
    contribute_with_credentials(config, host, &[], access)
}

/// [`contribute`] with the credential files `credential_deny` names, which are
/// read denies that outrank every grant.
pub(super) fn contribute_with_credentials<D: Disk>(
    config: &Config,
    host: &Host<D>,
    credential_deny: &[PathEntry],
    access: &mut Access,
) -> Result<(), StartError> {
    let filesystem = &config.filesystem;
    let settings = Settings {
        allow_read: filesystem.allow_read.as_deref().unwrap_or_default(),
        deny_read: &filesystem.deny_read,
        credential_deny,
        ..NO_PATHS
    };
    let ranked = ranked(host, &settings)?;
    let regranted = grants_beneath_denies(host, &ranked.read, &ranked.deny_read);
    add_new(&mut access.deny_read, ranked.deny_read);
    add_new(&mut access.read, regranted);
    Ok(())
}
