//! The folders between a read deny and a grant beneath it.
//!
//! A read deny is inherited by every folder beneath it, so the folders above a
//! grant keep it and the sandbox user cannot read their attributes. A program
//! that checks each component of a path fails there. Upstream's macOS profile
//! allows `file-read-metadata` on every directory for this reason, and these
//! folders get the same, with no listing and no reading beside the grant.
//!
//! This section reads the lists the sections before it filled, so it is named
//! last.

use crabpot_core::config::Config;
use crabpot_windows::fs_access::{Access, Disk, Host, folders_above_grants_in_denies};

use super::add_new;
use crate::StartError;

/// Adds the folders above a read or write grant and beneath a read deny to the
/// metadata list.
pub(super) fn contribute<D: Disk>(
    _config: &Config,
    host: &Host<D>,
    access: &mut Access,
) -> Result<(), StartError> {
    let grants: Vec<String> = access
        .read
        .iter()
        .chain(&access.write)
        .cloned()
        .collect();
    let folders = folders_above_grants_in_denies(host, &grants, &access.deny_read);
    add_new(&mut access.metadata, folders);
    Ok(())
}
