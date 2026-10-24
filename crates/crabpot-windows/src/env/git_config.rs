//! The `GIT_CONFIG_*` variables a sandboxed command's git reads: the
//! directories it is told are safe, and the TLS knobs. A port of
//! `buildGitConfigEnv` (`src/sandbox/sandbox-utils.ts`) with the choices
//! `wrapCommandWithSandboxWindows` makes on Windows.

use std::collections::HashSet;

/// Past this many safe directories, one `*` stands for all of them instead
/// of each with its own glob. Upstream's `SAFE_DIRECTORY_WILDCARD_THRESHOLD`.
const SAFE_DIRECTORY_WILDCARD_THRESHOLD: usize = 8;

/// The `GIT_CONFIG_KEY_n` / `GIT_CONFIG_VALUE_n` pairs and their
/// `GIT_CONFIG_COUNT`, for these safe directories.
///
/// `schannel_ca` asks for the schannel knobs that make git read the proxy's
/// trust bundle. git always gets its OpenSSL backend: schannel cannot
/// acquire credentials under the write-restricted token.
#[must_use]
pub(super) fn vars(safe_dirs: &[String], schannel_ca: bool) -> Vec<(String, String)> {
    let dirs = normalized_dirs(safe_dirs);
    let mut entries: Vec<(String, String)> = Vec::new();
    if dirs.len() > SAFE_DIRECTORY_WILDCARD_THRESHOLD {
        emit(&mut entries, "safe.directory", "*");
    } else {
        // git matches safe.directory against the repo top-level exactly, so
        // each directory carries its `<dir>/*` glob (git ≥2.46) beside it.
        for dir in &dirs {
            emit(&mut entries, "safe.directory", dir);
            let glob = if dir.ends_with('/') {
                format!("{dir}*")
            } else {
                format!("{dir}/*")
            };
            emit(&mut entries, "safe.directory", &glob);
        }
    }
    if schannel_ca {
        emit(&mut entries, "http.schannelUseSSLCAInfo", "true");
        emit(&mut entries, "http.schannelCheckRevoke", "false");
    }
    emit(&mut entries, "http.sslBackend", "openssl");
    let count = entries.len() / 2;
    entries.push(("GIT_CONFIG_COUNT".to_owned(), count.to_string()));
    entries
}

/// The safe directories as git wants them: forward slashes, no trailing
/// slash, empty names dropped, duplicates dropped, first spelling kept.
fn normalized_dirs(safe_dirs: &[String]) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for dir in safe_dirs {
        if dir.is_empty() {
            continue;
        }
        let dir = normalize(dir);
        if seen.insert(dir.clone()) {
            out.push(dir);
        }
    }
    out
}

/// One directory as git wants it.
fn normalize(dir: &str) -> String {
    let slashed = dir.replace('\\', "/");
    let trimmed = slashed.trim_end_matches('/');
    // `C:` alone is drive-relative-cwd, which git wants as `C:/`, and the
    // POSIX root must stay `/`. Neither keeps its stripped form.
    if trimmed.is_empty() || is_drive_letter(trimmed) {
        return format!("{trimmed}/");
    }
    trimmed.to_owned()
}

/// Whether the directory is a bare drive letter and colon.
fn is_drive_letter(dir: &str) -> bool {
    let [letter, b':'] = dir.as_bytes() else {
        return false;
    };
    letter.is_ascii_alphabetic()
}

/// One `GIT_CONFIG_KEY_n` / `GIT_CONFIG_VALUE_n` pair, numbered by the pairs
/// already emitted.
fn emit(entries: &mut Vec<(String, String)>, key: &str, value: &str) {
    let n = entries.len() / 2;
    entries.push((format!("GIT_CONFIG_KEY_{n}"), key.to_owned()));
    entries.push((format!("GIT_CONFIG_VALUE_{n}"), value.to_owned()));
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
        let vars = vars(&dirs(&[r"C:\Users\me\repo"]), false);
        assert_eq!(
            values(&vars),
            ["C:/Users/me/repo", "C:/Users/me/repo/*", "openssl"]
        );
    }

    #[test]
    fn a_root_keeps_its_trailing_slash_and_its_glob_has_only_one() {
        let vars = vars(&dirs(&["C:", "/"]), false);
        assert_eq!(
            values(&vars),
            ["C:/", "C:/*", "/", "/*", "openssl"],
            "git's own forms: `C:` alone is drive-relative-cwd, and a root's glob adds no second slash"
        );
    }

    #[test]
    fn duplicates_and_empty_names_are_dropped() {
        let vars = vars(&dirs(&[r"C:\repo", r"C:\repo\", "", r"C:\repo"]), false);
        assert_eq!(values(&vars), ["C:/repo", "C:/repo/*", "openssl"]);
    }

    #[test]
    fn past_the_threshold_one_wildcard_stands_for_all() {
        let many: Vec<String> = (0..=SAFE_DIRECTORY_WILDCARD_THRESHOLD)
            .map(|n| format!(r"C:\repo{n}"))
            .collect();
        let vars = vars(&many, false);
        assert_eq!(values(&vars), ["*", "openssl"]);
        assert_eq!(
            vars.iter()
                .find(|(name, _)| name == "GIT_CONFIG_COUNT")
                .map(|(_, value)| value.as_str()),
            Some("2")
        );
    }

    #[test]
    fn the_schannel_knobs_come_with_a_trust_bundle() {
        let vars = vars(&dirs(&[r"C:\repo"]), true);
        assert_eq!(
            values(&vars),
            ["C:/repo", "C:/repo/*", "true", "false", "openssl",],
            "schannelUseSSLCAInfo then schannelCheckRevoke, then the backend"
        );
    }
}
