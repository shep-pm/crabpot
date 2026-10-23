//! `filesystem.denyWrite`: paths a command may not write, which beat
//! `allowWrite`. Required, and a pattern with a trailing separator is refused.

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
    /// What `denyWrite` takes back from `allowWrite`, as the sandbox matches
    /// it: each entry made absolute against `HOME` and the working directory,
    /// in every reading it has.
    ///
    /// # Errors
    ///
    /// [`PathError`] when an entry starts with `~` and `HOME` is not set, or is
    /// relative and there is no working directory.
    pub fn write_denies(&self) -> Result<Vec<ResolvedPath>, PathError> {
        deny_entries(&PathBase::from_env(), &self.deny_write)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::config::{Config, ConfigError};

    fn load(deny_write: &serde_json::Value) -> Result<Config, ConfigError> {
        Config::from_json(
            &json!({
                "network": {"allowedDomains": [], "deniedDomains": []},
                "filesystem": {"denyRead": [], "allowWrite": [], "denyWrite": deny_write}
            })
            .to_string(),
        )
    }

    #[test]
    fn a_trailing_separator_glob_is_refused_but_a_marked_literal_is_not() {
        let Err(ConfigError::Invalid { key, .. }) = load(&json!(["/ok", "/x/*/"])) else {
            panic!("a deny glob ending in a separator was not refused");
        };
        assert_eq!(key, "filesystem.denyWrite.1");

        assert!(load(&json!([{"path": "/x/*/", "literal": true}])).is_ok());
    }
}
