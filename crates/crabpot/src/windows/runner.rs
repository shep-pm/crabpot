//! The runner: this binary, which the sandbox user has to be able to read,
//! since every sandboxed command is launched as that user running it. A binary
//! under the user's profile (`cargo install` puts one there, and kelpie's binary
//! lives there) is readable only once the profile read grant is in place, and
//! seclogon answers the failure with a message about the service instead of
//! about the binary.

use std::path::PathBuf;

#[cfg(windows)]
use super::status::WindowsStatus;

/// What decides whether the sandbox user can read this binary.
#[derive(Debug)]
pub(crate) struct Runner {
    /// This binary.
    pub(crate) exe: PathBuf,
    /// Whether the file's own access list names the sandbox account, the group it
    /// is in, or a group of its token as able to read and execute it. `None` for
    /// a check the machine could not make, which refuses nothing.
    pub(crate) dacl_allows: Option<bool>,
}

impl Runner {
    /// The facts for `exe` on this machine. `status` is what the install says
    /// about the sandbox, or `None` when it could not be read, which names no
    /// account and no group.
    #[cfg(windows)]
    pub(crate) fn of(exe: PathBuf, status: Option<&WindowsStatus>) -> Self {
        let sids = status.map_or_else(Vec::new, |status| status.sandbox_sids());
        Self {
            dacl_allows: crabpot_windows::sandbox_can_read(&exe, &sids),
            exe,
        }
    }

    /// Whether the sandbox user can read `exe`, by `exe`'s own access list.
    ///
    /// The profile read grant puts an inheritable entry on each folder it
    /// reaches, so a file's list is the record of what the grant opened. Being
    /// under the profile is not that record: the grant denies its protected
    /// exclusions, writes nothing in its ungranted-only temporary directory, and
    /// reaches no top-level item made after it ran. A file moved into a granted
    /// folder keeps the list it had and inherits nothing from it.
    pub(crate) fn readable(&self) -> bool {
        self.dacl_allows.unwrap_or(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A runner under the profile, where a crabpot sits unreadable until the
    /// grant reaches it. `dacl_allows` is what the access-list check answered
    /// for it, which srt-win's `logon` tests pin for each shape of list.
    fn runner(dacl_allows: Option<bool>) -> Runner {
        Runner {
            exe: PathBuf::from(r"C:\Users\runneradmin\.cargo\bin\crabpot.exe"),
            dacl_allows,
        }
    }

    #[test]
    fn a_file_the_check_read_as_granted_is_readable() {
        assert!(runner(Some(true)).readable());
    }

    /// An exclusion of the grant, its temporary directory, and a top-level item
    /// made after the grant ran are each under the profile and each carry no
    /// entry for the sandbox.
    #[test]
    fn a_file_the_check_read_as_denied_is_not_readable() {
        assert!(!runner(Some(false)).readable());
    }

    #[test]
    fn a_check_the_machine_could_not_make_refuses_nothing() {
        assert!(runner(None).readable());
    }
}
