//! The profile read grant against the session's grants.
//!
//! While a profile read grant is recorded, `srt-win acl grant` refuses any path
//! that is a protected exclusion of it, lies inside or above one, or is or lies
//! above a directory it leaves ungranted, and grants nothing. The same check
//! runs here first, on the plan's own lists, so the refusal names the paths.
//! With no grant recorded the exclusions are empty and nothing conflicts.

use crabpot_windows::fs_access::{
    Access, ConflictOptions, Disk, Host, ProfileGrant, profile_exclusion_conflicts,
};

use super::super::status::ProfileExclusions;
use crate::{ProfileConflict, StartError};

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
    let grant = ProfileGrant {
        exclusions: &profile.exclusions,
        ungranted_only: &profile.ungranted_only,
    };
    let mut found = Vec::new();
    for (paths, write) in [(&access.read, false), (&access.write, true)] {
        let options = ConflictOptions {
            write,
            ..ConflictOptions::default()
        };
        found.extend(
            profile_exclusion_conflicts(host, paths, &grant, &options)
                .into_iter()
                .map(|conflict| ProfileConflict {
                    path: conflict.path,
                    exclusion: conflict.exclusion,
                    write,
                }),
        );
    }
    if found.is_empty() {
        Ok(())
    } else {
        Err(StartError::ProfileConflicts(found))
    }
}
