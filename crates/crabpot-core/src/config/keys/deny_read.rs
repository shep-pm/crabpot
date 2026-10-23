//! `filesystem.denyRead`: paths a command may not read. Required, and a
//! pattern with a trailing separator is refused.

use serde::Deserializer;

use super::super::Filesystem;
use super::super::leaf::deny_list;
use crate::path::{PathBase, PathError};
use crate::path_entries::PathEntry;
use crate::resolved_path::{ResolvedPath, deny_entries};

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<PathEntry>, D::Error> {
    deny_list(deserializer)
}

impl Filesystem {
    /// What `denyRead` hides, as the sandbox matches it: each entry made
    /// absolute against `HOME` and the working directory, in every reading it
    /// has.
    ///
    /// # Errors
    ///
    /// [`PathError`] when an entry starts with `~` and `HOME` is not set, or is
    /// relative and there is no working directory.
    pub fn read_denies(&self) -> Result<Vec<ResolvedPath>, PathError> {
        deny_entries(&PathBase::from_env(), &self.deny_read)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::config::{Config, ConfigError};
    use crate::path_entries::PathEntry;

    fn load(deny_read: &serde_json::Value) -> Result<Config, ConfigError> {
        Config::from_json(
            &json!({
                "network": {"allowedDomains": [], "deniedDomains": []},
                "filesystem": {"denyRead": deny_read, "allowWrite": [], "denyWrite": []}
            })
            .to_string(),
        )
    }

    #[test]
    fn each_refusal_names_its_key_path() {
        for (entries, key) in [
            (json!(["/a", ""]), "filesystem.denyRead.1"),
            (json!([{"path": "/a"}]), "filesystem.denyRead.0"),
            (
                json!(["/a", {"path": "/b", "literal": true, "extra": 1}]),
                "filesystem.denyRead.1",
            ),
            (json!(["/ok", "/x/*/"]), "filesystem.denyRead.1"),
            (json!("/a"), "filesystem.denyRead"),
        ] {
            let Err(ConfigError::Invalid { key: named, .. }) = load(&entries) else {
                panic!("{entries} was not refused as invalid");
            };
            assert_eq!(named, key, "{entries}");
        }
    }

    #[test]
    fn what_it_denies_loads_as_entries() {
        let config = load(&json!(["/a/b", {"path": "/c[1]", "literal": true}])).unwrap();

        assert_eq!(
            config.filesystem.deny_read,
            [
                PathEntry::Spelled("/a/b".to_owned()),
                PathEntry::Literal("/c[1]".to_owned()),
            ]
        );
    }
}
