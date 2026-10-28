//! The profile read grant against the session's grants.
//!
//! While a profile read grant is recorded, `srt-win acl grant` refuses any path
//! that is a protected exclusion of it, lies inside or above one, or is or lies
//! above a directory it leaves ungranted, and grants nothing. The same check
//! runs here first, on the plan's own lists, so the refusal names the paths.
//! With no grant recorded the exclusions are empty and nothing conflicts.

use crabpot_windows::fs_access::{Access, Disk, Host};

use super::super::status::ProfileExclusions;
use crate::StartError;

/// Whether no path of `access` that is granted meets `profile`.
///
/// # Errors
///
/// [`StartError::ProfileConflicts`] with each read and write grant that does,
/// reads first.
pub(super) fn check<D: Disk>(
    host: &Host<D>,
    access: &Access,
    profile: &ProfileExclusions,
) -> Result<(), StartError> {
    let mut found = profile.conflicts_on(host, &access.read, false);
    found.extend(profile.conflicts_on(host, &access.write, true));
    if found.is_empty() {
        Ok(())
    } else {
        Err(StartError::ProfileConflicts(found))
    }
}
