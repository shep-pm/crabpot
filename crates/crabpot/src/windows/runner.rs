//! The runner: this binary, which the sandbox user has to be able to read,
//! since every sandboxed command is launched as that user running it. A binary
//! under the user's profile (`cargo install` puts one there, and kelpie's binary
//! lives there) is readable only once the profile read grant is in place, and
//! seclogon answers the failure with a message about the service instead of
//! about the binary.

use std::path::PathBuf;

/// What decides whether the sandbox user can read this binary.
#[derive(Debug)]
pub(crate) struct Runner {
    /// This binary.
    pub(crate) exe: PathBuf,
    /// The profile a current profile read grant opens to the sandbox user,
    /// `None` when no such grant is in place.
    pub(crate) granted_profile: Option<PathBuf>,
    /// Whether a group the sandbox user is in can read `exe`. `None` for a
    /// check the machine could not make, which refuses nothing.
    pub(crate) groups_can_read: Option<bool>,
}

impl Runner {
    /// The facts for `exe` on this machine, where `grant_is_current` says
    /// whether a profile read grant is in place.
    #[cfg(windows)]
    pub(crate) fn of(exe: PathBuf, grant_is_current: bool) -> Self {
        Self {
            granted_profile: granted_profile(grant_is_current),
            groups_can_read: super::ffi::groups_can_read(&exe),
            exe,
        }
    }

    /// Whether the sandbox user can read `exe`: a group it is in can, or `exe`
    /// is under `granted_profile`, the profile a current read grant opens to it.
    pub(crate) fn readable(&self) -> bool {
        self.groups_can_read.unwrap_or(true)
            || self
                .granted_profile
                .as_deref()
                .is_some_and(|profile| self.exe.starts_with(profile))
    }
}

/// The profile a current profile read grant opens to the sandbox user, with
/// links resolved, which is the form the grant recorded its path in. `None`
/// when no grant is in place, or the machine names no profile.
#[cfg(windows)]
fn granted_profile(grant_is_current: bool) -> Option<PathBuf> {
    std::env::var_os("USERPROFILE")
        .filter(|_| grant_is_current)
        .and_then(|p| std::fs::canonicalize(p).ok())
}
