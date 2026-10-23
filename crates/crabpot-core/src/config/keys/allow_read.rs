//! `filesystem.allowRead`: paths a command may read inside a denied one.

use serde::Deserializer;

use super::super::Filesystem;
use super::super::leaf::path_list;
use crate::home_write_dirs;
use crate::path::{PathBase, PathError};
use crate::path_entries::PathEntry;
use crate::resolved_path::{ResolvedPath, allow_entries};

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<PathEntry>>, D::Error> {
    path_list(deserializer).map(Some)
}

impl Filesystem {
    /// What `allowRead` re-opens inside what `denyRead` hides, as the sandbox
    /// matches it: each entry made absolute against `HOME` and the working
    /// directory, in every reading it has.
    ///
    /// # Errors
    ///
    /// [`PathError`] when an entry starts with `~` and `HOME` is not set, or is
    /// relative and there is no working directory.
    pub fn read_allows(&self) -> Result<Vec<ResolvedPath>, PathError> {
        allow_entries(
            &PathBase::from_env(),
            self.allow_read.as_deref().unwrap_or_default(),
        )
    }

    /// The folders under the home directory a command may write without
    /// asking (`~/.npm/_logs`, `~/.claude/debug`), less those `denyRead`
    /// hides. An `allowRead` entry beneath the deny that covers one gives it
    /// back. The caller adds what is left to its write allows.
    ///
    /// # Errors
    ///
    /// [`PathError`] when `HOME` is not set, or an entry is relative and there
    /// is no working directory.
    pub fn convenience_write_dirs(&self) -> Result<Vec<String>, PathError> {
        home_write_dirs::kept(
            &PathBase::from_env(),
            &self.deny_read,
            self.allow_read.as_deref().unwrap_or_default(),
        )
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::config::{Config, ConfigError};
    use crate::path_entries::PathEntry;

    fn load(allow_read: &serde_json::Value) -> Result<Config, ConfigError> {
        Config::from_json(
            &json!({
                "network": {"allowedDomains": [], "deniedDomains": []},
                "filesystem": {
                    "denyRead": [], "allowRead": allow_read, "allowWrite": [], "denyWrite": []
                }
            })
            .to_string(),
        )
    }

    #[test]
    fn an_empty_entry_is_refused() {
        let Err(ConfigError::Invalid { key, .. }) = load(&json!(["/a", ""])) else {
            panic!("an empty entry was not refused as invalid");
        };

        assert_eq!(key, "filesystem.allowRead.1");
    }

    #[test]
    fn each_refusal_names_its_key_path() {
        for (entries, key) in [
            (json!([{"path": "/a"}]), "filesystem.allowRead.0"),
            (
                json!(["/a", {"path": "/b", "literal": true, "extra": 1}]),
                "filesystem.allowRead.1",
            ),
            (json!("/a"), "filesystem.allowRead"),
            (json!(null), "filesystem.allowRead"),
        ] {
            let Err(ConfigError::Invalid { key: named, .. }) = load(&entries) else {
                panic!("{entries} was not refused as invalid");
            };
            assert_eq!(named, key, "{entries}");
        }
    }

    #[test]
    fn a_trailing_separator_on_a_glob_is_not_refused() {
        let config = load(&json!(["/x/*/", {"path": "/c[1]", "literal": true}])).unwrap();

        assert_eq!(
            config.filesystem.allow_read,
            Some(vec![
                PathEntry::Spelled("/x/*/".to_owned()),
                PathEntry::Literal("/c[1]".to_owned()),
            ])
        );
    }
}
