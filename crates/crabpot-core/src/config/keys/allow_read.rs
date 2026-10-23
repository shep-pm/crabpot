//! `filesystem.allowRead`: paths a command may read inside a denied one.

use serde::Deserializer;

use super::super::leaf::path_list;
use crate::path_entries::PathEntry;

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<PathEntry>>, D::Error> {
    path_list(deserializer).map(Some)
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
