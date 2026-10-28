//! The `GIT_CONFIG_*` variables that tell git which directories are safe: a
//! port of `buildGitConfigEnv` (`src/sandbox/sandbox-utils.ts`).
//!
//! Inside the sandbox the working tree is owned by another user than the
//! command runs as, so git refuses it as a dubious owner without a
//! `safe.directory`. Numbering continues from the `GIT_CONFIG_COUNT` the
//! command already carries, so its own entries are kept.

use std::collections::HashSet;

/// Past this many safe directories, one `*` stands for all of them instead
/// of each with its own glob. Upstream's `SAFE_DIRECTORY_WILDCARD_THRESHOLD`.
const SAFE_DIRECTORY_WILDCARD_THRESHOLD: usize = 8;

/// The `GIT_CONFIG_KEY_n` / `GIT_CONFIG_VALUE_n` pairs that make `dirs` safe,
/// and the `GIT_CONFIG_COUNT` that includes them.
///
/// `base_count` is the `GIT_CONFIG_COUNT` the command carries, as text. The
/// first pair is numbered by it, and an explicit `0` opts out of environment
/// git config, so nothing is emitted. Nothing is emitted either when `dirs`
/// names no directory.
#[must_use]
pub fn safe_directory_vars(dirs: &[String], base_count: Option<&str>) -> Vec<(String, String)> {
    config_vars(dirs, &[], base_count)
}

/// [`safe_directory_vars`] with `extra` config pairs after the directories,
/// each a git config key and its value.
#[must_use]
pub fn config_vars(
    dirs: &[String],
    extra: &[(&str, &str)],
    base_count: Option<&str>,
) -> Vec<(String, String)> {
    if base_count == Some("0") {
        return Vec::new();
    }
    let start = base_count.map_or(0, count_from);
    let mut config: Vec<(String, String)> = Vec::new();
    let dirs = normalized_dirs(dirs);
    if dirs.len() > SAFE_DIRECTORY_WILDCARD_THRESHOLD {
        config.push(("safe.directory".to_owned(), "*".to_owned()));
    } else {
        // git matches safe.directory against the repo top-level exactly, so
        // each directory carries its `<dir>/*` glob (git ≥2.46) beside it.
        for dir in &dirs {
            config.push(("safe.directory".to_owned(), dir.clone()));
            let glob = if dir.ends_with('/') {
                format!("{dir}*")
            } else {
                format!("{dir}/*")
            };
            config.push(("safe.directory".to_owned(), glob));
        }
    }
    config.extend(
        extra
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned())),
    );
    if config.is_empty() {
        return Vec::new();
    }
    let mut vars = Vec::with_capacity(config.len() * 2 + 1);
    for (n, (key, value)) in (start..).zip(config) {
        vars.push((format!("GIT_CONFIG_KEY_{n}"), key));
        vars.push((format!("GIT_CONFIG_VALUE_{n}"), value));
    }
    let total = start + vars.len() / 2;
    vars.push(("GIT_CONFIG_COUNT".to_owned(), total.to_string()));
    vars
}

/// The number a carried `GIT_CONFIG_COUNT` starts the numbering at: its
/// leading digits, as JavaScript's `parseInt` reads them, or 0 when it has
/// none.
fn count_from(carried: &str) -> usize {
    let text = carried.trim_start();
    let text = text.strip_prefix('+').unwrap_or(text);
    let digits = text
        .find(|c: char| !c.is_ascii_digit())
        .map_or(text, |end| &text[..end]);
    digits.parse().unwrap_or(0)
}

/// The safe directories as git wants them: forward slashes, no trailing
/// slash, empty names dropped, duplicates dropped, first spelling kept.
fn normalized_dirs(dirs: &[String]) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for dir in dirs {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn dirs(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    fn pairs(vars: &[(String, String)]) -> Vec<(&str, &str)> {
        vars.iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect()
    }

    #[test]
    fn a_directory_gets_itself_and_its_glob() {
        let vars = safe_directory_vars(&dirs(&[r"C:\Users\me\repo"]), None);
        assert_eq!(
            pairs(&vars),
            [
                ("GIT_CONFIG_KEY_0", "safe.directory"),
                ("GIT_CONFIG_VALUE_0", "C:/Users/me/repo"),
                ("GIT_CONFIG_KEY_1", "safe.directory"),
                ("GIT_CONFIG_VALUE_1", "C:/Users/me/repo/*"),
                ("GIT_CONFIG_COUNT", "2"),
            ]
        );
    }

    #[test]
    fn a_root_keeps_its_trailing_slash_and_its_glob_has_only_one() {
        let vars = safe_directory_vars(&dirs(&["C:", "/"]), None);
        let values: Vec<&str> = pairs(&vars)
            .into_iter()
            .filter(|(name, _)| name.starts_with("GIT_CONFIG_VALUE_"))
            .map(|(_, value)| value)
            .collect();
        assert_eq!(
            values,
            ["C:/", "C:/*", "/", "/*"],
            "git's own forms: `C:` alone is drive-relative-cwd, and a root's glob adds no second slash"
        );
    }

    #[test]
    fn duplicates_and_empty_names_are_dropped() {
        let vars = safe_directory_vars(&dirs(&[r"C:\repo", r"C:\repo\", "", r"C:\repo"]), None);
        assert_eq!(pairs(&vars).last(), Some(&("GIT_CONFIG_COUNT", "2")));
    }

    #[test]
    fn past_the_threshold_one_wildcard_stands_for_all() {
        let many: Vec<String> = (0..=SAFE_DIRECTORY_WILDCARD_THRESHOLD)
            .map(|n| format!("/repo{n}"))
            .collect();
        assert_eq!(
            pairs(&safe_directory_vars(&many, None)),
            [
                ("GIT_CONFIG_KEY_0", "safe.directory"),
                ("GIT_CONFIG_VALUE_0", "*"),
                ("GIT_CONFIG_COUNT", "1"),
            ]
        );
    }

    #[test]
    fn numbering_continues_from_the_carried_count() {
        let vars = safe_directory_vars(&dirs(&["/a", "/b"]), Some("2"));
        assert_eq!(
            pairs(&vars),
            [
                ("GIT_CONFIG_KEY_2", "safe.directory"),
                ("GIT_CONFIG_VALUE_2", "/a"),
                ("GIT_CONFIG_KEY_3", "safe.directory"),
                ("GIT_CONFIG_VALUE_3", "/a/*"),
                ("GIT_CONFIG_KEY_4", "safe.directory"),
                ("GIT_CONFIG_VALUE_4", "/b"),
                ("GIT_CONFIG_KEY_5", "safe.directory"),
                ("GIT_CONFIG_VALUE_5", "/b/*"),
                ("GIT_CONFIG_COUNT", "6"),
            ]
        );
    }

    #[test]
    fn a_carried_count_of_zero_emits_nothing() {
        assert_eq!(safe_directory_vars(&dirs(&["/a"]), Some("0")), []);
        assert_eq!(config_vars(&dirs(&["/a"]), &[("k", "v")], Some("0")), []);
    }

    #[test]
    fn a_carried_count_that_is_no_number_starts_at_zero() {
        for carried in ["", "x", "-3", " "] {
            let vars = safe_directory_vars(&dirs(&["/a"]), Some(carried));
            assert_eq!(pairs(&vars)[0].0, "GIT_CONFIG_KEY_0", "{carried:?}");
        }
        let vars = safe_directory_vars(&dirs(&["/a"]), Some("3x"));
        assert_eq!(
            pairs(&vars)[0].0,
            "GIT_CONFIG_KEY_3",
            "the leading digits, as parseInt reads them"
        );
    }

    #[test]
    fn nothing_to_say_emits_nothing() {
        assert_eq!(safe_directory_vars(&[], Some("2")), []);
        assert_eq!(safe_directory_vars(&dirs(&[""]), None), []);
    }

    #[test]
    fn extra_pairs_follow_the_directories() {
        let vars = config_vars(&dirs(&["/a"]), &[("http.sslBackend", "openssl")], Some("1"));
        assert_eq!(
            pairs(&vars)[4..],
            [
                ("GIT_CONFIG_KEY_3", "http.sslBackend"),
                ("GIT_CONFIG_VALUE_3", "openssl"),
                ("GIT_CONFIG_COUNT", "4"),
            ]
        );
    }
}
