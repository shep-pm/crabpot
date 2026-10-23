//! `filesystem.allowWrite`: paths a command may write. Required. Unlike a
//! deny list it takes a pattern with a trailing separator, which matches
//! nothing and so allows nothing.

use serde::Deserializer;

use super::super::leaf::path_list;
use crate::path_entries::PathEntry;

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<PathEntry>, D::Error> {
    path_list(deserializer)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::config::{Config, ConfigError};

    fn load(allow_write: &serde_json::Value) -> Result<Config, ConfigError> {
        Config::from_json(
            &json!({
                "network": {"allowedDomains": [], "deniedDomains": []},
                "filesystem": {"denyRead": [], "allowWrite": allow_write, "denyWrite": []}
            })
            .to_string(),
        )
    }

    #[test]
    fn an_empty_entry_is_refused() {
        assert_eq!(
            load(&json!(["/work", ""])),
            Err(ConfigError::Invalid {
                key: "filesystem.allowWrite.1".to_owned(),
                reason: "path cannot be empty".to_owned(),
            })
        );
    }

    #[test]
    fn a_path_is_read() {
        let config = load(&json!(["/work", {"path": "/a[1]", "literal": true}])).unwrap();

        assert_eq!(
            config.filesystem.allow_write,
            [
                crate::config::PathEntry::Spelled("/work".to_owned()),
                crate::config::PathEntry::Literal("/a[1]".to_owned()),
            ]
        );
    }

    #[test]
    fn a_glob_with_a_trailing_separator_is_accepted() {
        assert!(load(&json!(["/work/*/"])).is_ok());
    }
}
