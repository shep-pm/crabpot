//! Which of the wrapper's own variables the command it runs keeps on Windows.

use std::ffi::OsString;

/// The names the sandbox user's profile owns, which stay the sandbox user's.
const PROFILE: [&str; 17] = [
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "HOMEDRIVE",
    "HOMEPATH",
    "HOMESHARE",
    "TEMP",
    "TMP",
    "USERNAME",
    "USERDOMAIN",
    "USERDOMAIN_ROAMINGPROFILE",
    "LOGONSERVER",
    "ONEDRIVE",
    "ONEDRIVECONSUMER",
    "ONEDRIVECOMMERCIAL",
    "SESSIONNAME",
    "CLIENTNAME",
];

/// The pairs of `host` the command keeps: all but the profile's names, which
/// Windows reads without case. A name that starts with `=` is a drive's
/// working directory, kept by the process and not set by it.
pub(crate) fn carried(
    host: impl IntoIterator<Item = (OsString, OsString)>,
) -> Vec<(OsString, OsString)> {
    host.into_iter()
        .filter(|(name, _)| {
            let name = name.to_string_lossy();
            !name.starts_with('=')
                && !PROFILE
                    .iter()
                    .any(|owned| owned.eq_ignore_ascii_case(&name))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(list: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        list.iter().map(|(n, v)| (n.into(), v.into())).collect()
    }

    #[test]
    fn a_hosts_variable_is_carried() {
        let host = pairs(&[("CLAUDE_CODE_OAUTH_TOKEN", "secret"), ("PATH", "C:\\bin")]);
        assert_eq!(carried(host.clone()), host);
    }

    #[test]
    fn a_name_the_profile_owns_is_not_carried_whatever_its_case() {
        let host = pairs(&[
            ("UserProfile", "C:\\Users\\me"),
            ("temp", "C:\\t"),
            ("KEPT", "1"),
        ]);
        assert_eq!(carried(host), pairs(&[("KEPT", "1")]));
    }

    #[test]
    fn a_drive_working_directory_entry_is_not_carried() {
        let host = pairs(&[("=C:", "C:\\work"), ("KEPT", "1")]);
        assert_eq!(carried(host), pairs(&[("KEPT", "1")]));
    }
}
