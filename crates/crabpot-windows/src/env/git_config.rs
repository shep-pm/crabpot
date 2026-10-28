//! The `GIT_CONFIG_*` variables a sandboxed command's git reads: the
//! directories it is told are safe ([`crabpot_core::env::git`]), and the TLS
//! knobs. A port of `buildGitConfigEnv` (`src/sandbox/sandbox-utils.ts`) with
//! the choices `wrapCommandWithSandboxWindows` makes on Windows.

use crabpot_core::env::git;

/// The `GIT_CONFIG_KEY_n` / `GIT_CONFIG_VALUE_n` pairs and their
/// `GIT_CONFIG_COUNT`, for these safe directories.
///
/// `carried_count` is the `GIT_CONFIG_COUNT` the command brings, which the
/// numbering continues from. `schannel_ca` asks for the schannel knobs that
/// make git read the proxy's trust bundle. git always gets its OpenSSL
/// backend: schannel cannot acquire credentials under the write-restricted
/// token.
#[must_use]
pub(super) fn vars(
    safe_dirs: &[String],
    carried_count: Option<&str>,
    schannel_ca: bool,
) -> Vec<(String, String)> {
    let schannel: &[(&str, &str)] = if schannel_ca {
        &[
            ("http.schannelUseSSLCAInfo", "true"),
            ("http.schannelCheckRevoke", "false"),
        ]
    } else {
        &[]
    };
    let openssl = [("http.sslBackend", "openssl")];
    let knobs: Vec<(&str, &str)> = schannel.iter().chain(&openssl).copied().collect();
    git::config_vars(safe_dirs, &knobs, carried_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dirs(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    fn values(vars: &[(String, String)]) -> Vec<String> {
        vars.iter()
            .filter(|(name, _)| name.starts_with("GIT_CONFIG_VALUE_"))
            .map(|(_, value)| value.clone())
            .collect()
    }

    #[test]
    fn a_directory_gets_itself_and_its_glob() {
        let vars = vars(&dirs(&[r"C:\Users\me\repo"]), None, false);
        assert_eq!(
            values(&vars),
            ["C:/Users/me/repo", "C:/Users/me/repo/*", "openssl"]
        );
    }

    #[test]
    fn the_schannel_knobs_come_with_a_trust_bundle() {
        let vars = vars(&dirs(&[r"C:\repo"]), None, true);
        assert_eq!(
            values(&vars),
            ["C:/repo", "C:/repo/*", "true", "false", "openssl",],
            "schannelUseSSLCAInfo then schannelCheckRevoke, then the backend"
        );
    }

    #[test]
    fn the_knobs_continue_the_carried_numbering() {
        let vars = vars(&[], Some("2"), false);
        assert_eq!(
            vars,
            [
                ("GIT_CONFIG_KEY_2".to_owned(), "http.sslBackend".to_owned()),
                ("GIT_CONFIG_VALUE_2".to_owned(), "openssl".to_owned()),
                ("GIT_CONFIG_COUNT".to_owned(), "3".to_owned()),
            ]
        );
    }

    #[test]
    fn a_carried_count_of_zero_opts_out_of_the_knobs_too() {
        assert_eq!(vars(&dirs(&[r"C:\repo"]), Some("0"), true), []);
    }
}
