//! The runner: this binary, which the sandbox user has to be able to read,
//! since every sandboxed command is launched as that user running it. A binary
//! under the user's profile (`cargo install` puts one there, and kelpie's binary
//! lives there) is readable only once the profile read grant is in place, and
//! seclogon answers the failure with a message about the service instead of
//! about the binary.

use std::path::{Path, PathBuf};

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
                .is_some_and(|profile| under(profile, &self.exe))
    }
}

/// Whether `exe` is `profile` itself or below it.
///
/// The two are compared as text, and not with [`Path::starts_with`], which
/// cannot answer this: on Windows it reads the `C:` of `C:\Users\me` as one
/// kind of prefix and the `C:` of `\\?\C:\Users\me` as another, and the two are
/// never equal. `granted_profile` always has the `\\?\` form, because
/// [`granted_profile`] canonicalizes it, and `exe` never does, because
/// [`std::env::current_exe`] does not, so a comparison through
/// [`Path::starts_with`] holds for nothing on a Windows host.
fn under(profile: &Path, exe: &Path) -> bool {
    let profile = comparable(profile);
    let exe = comparable(exe);
    exe.len() > profile.len()
        && exe.starts_with(&profile)
        // The next character is a separator, so `exe` is below `profile` and not
        // in a folder merely named for it.
        && exe.as_bytes()[profile.len()] == b'\\'
}

/// `path` in the one form every path of it takes: the verbatim prefix
/// `std::fs::canonicalize` adds is dropped (`\\?\UNC\server\share` becomes
/// `\\server\share`), `/` is read as `\`, repeated separators collapse, and case
/// is dropped, which is how Windows names a path.
fn comparable(path: &Path) -> String {
    let raw = path.to_string_lossy().replace('/', "\\");
    let raw = match raw.strip_prefix(r"\\?\UNC\") {
        Some(server) => format!(r"\\{server}"),
        None => raw.strip_prefix(r"\\?\").unwrap_or(&raw).to_owned(),
    };
    let mut out = String::with_capacity(raw.len());
    for part in raw.split('\\').filter(|part| !part.is_empty()) {
        if !out.is_empty() {
            out.push('\\');
        }
        out.push_str(&part.to_lowercase());
    }
    out
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A runner under the profile, as the machine names the two: `granted_profile`
    /// comes from `std::fs::canonicalize`, which gives it a `\\?\` prefix, and
    /// `exe` comes from `std::env::current_exe`, which gives it none.
    fn under_the_profile(exe: &str) -> Runner {
        Runner {
            exe: PathBuf::from(exe),
            granted_profile: Some(PathBuf::from(r"\\?\C:\Users\runneradmin")),
            groups_can_read: Some(false),
        }
    }

    /// The profile read grant's ACE is for the sandbox group, not for Users,
    /// Authenticated Users or Everyone, so `groups_can_read` is false for a
    /// granted file and the profile is what answers for it.
    #[test]
    fn a_runner_under_the_granted_profile_is_readable() {
        assert!(under_the_profile(r"C:\Users\runneradmin\crabpot.exe").readable());
        assert!(
            under_the_profile(r"C:\Users\runneradmin\crabpot-under-profile\crabpot.exe").readable()
        );
        assert!(under_the_profile(r"C:\Users\runneradmin\.cargo\bin\crabpot.exe").readable());
    }

    /// Windows names a path without case, and `canonicalize` answers with the
    /// case the folder is recorded in.
    #[test]
    fn the_two_paths_are_compared_without_case() {
        assert!(under_the_profile(r"C:\Users\RunnerAdmin\crabpot.exe").readable());
    }

    /// A folder named for the profile is not the profile: a sibling of the
    /// granted folder stays unreadable.
    #[test]
    fn a_runner_in_a_sibling_of_the_granted_profile_is_not_readable() {
        assert!(!under_the_profile(r"C:\Users\runneradmin2\crabpot.exe").readable());
        assert!(!under_the_profile(r"C:\Users\other\crabpot.exe").readable());
    }

    /// A profile named as a plain path, and one named as a share, answer the
    /// same way as the canonical form.
    #[test]
    fn a_profile_named_without_the_verbatim_prefix_answers_the_same() {
        let mut runner = under_the_profile(r"C:\Users\runneradmin\crabpot.exe");
        runner.granted_profile = Some(PathBuf::from(r"C:\Users\runneradmin"));
        assert!(runner.readable());

        let mut share = under_the_profile(r"\\server\share\runneradmin\crabpot.exe");
        share.granted_profile = Some(PathBuf::from(r"\\?\UNC\server\share\runneradmin"));
        assert!(share.readable());
    }
}
