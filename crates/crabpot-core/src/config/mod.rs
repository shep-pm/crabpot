//! The settings a sandbox starts from.
//!
//! A stub. It accepts the shape of upstream's default config, whose lists are
//! all empty, and refuses a list that asks for something, since this slice
//! applies none of them. It reads no other key, so a key upstream knows and
//! this stub does not is dropped without notice. The real schema replaces it
//! and closes that gap (ADR-0004, ADR-0013).

use core::fmt;

use serde::Deserialize;

/// The settings one sandbox runs under.
///
/// Today there is nothing to set, so every `Config` is the default one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Config {}

impl Config {
    /// Reads a settings file's text.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] when `json` is not a settings object, and
    /// [`ConfigError::Unsupported`] when a list asks for something.
    pub fn from_json(json: &str) -> Result<Self, ConfigError> {
        let raw: Raw = serde_json::from_str(json).map_err(|e| ConfigError::Invalid {
            reason: e.to_string(),
        })?;
        let lists = [
            ("network.allowedDomains", &raw.network.allowed_domains),
            ("network.deniedDomains", &raw.network.denied_domains),
            ("filesystem.denyRead", &raw.filesystem.deny_read),
            ("filesystem.allowRead", &raw.filesystem.allow_read),
            ("filesystem.allowWrite", &raw.filesystem.allow_write),
            ("filesystem.denyWrite", &raw.filesystem.deny_write),
        ];
        match lists.iter().find(|(_, list)| !list.is_empty()) {
            Some((key, _)) => Err(ConfigError::Unsupported { key }),
            None => Ok(Self {}),
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct Raw {
    network: RawNetwork,
    filesystem: RawFilesystem,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct RawNetwork {
    allowed_domains: Vec<String>,
    denied_domains: Vec<String>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct RawFilesystem {
    deny_read: Vec<String>,
    allow_read: Vec<String>,
    allow_write: Vec<String>,
    deny_write: Vec<String>,
}

/// Why a settings file was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
// A key crabpot learns to honour, or a failure of the reader, adds a variant
// without breaking a caller's `match`.
#[non_exhaustive]
pub enum ConfigError {
    /// The text is not JSON, or a key holds a value of the wrong type.
    Invalid {
        /// The parser's own account of what is wrong.
        reason: String,
    },
    /// A key asks for something crabpot does not apply yet. Running anyway
    /// would drop the rule.
    Unsupported {
        /// The dotted path of the key, as written in a settings file.
        key: &'static str,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid { reason } => write!(f, "invalid settings: {reason}"),
            Self::Unsupported { key } => {
                write!(f, "settings key `{key}` is not supported yet")
            }
        }
    }
}

impl core::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_config_shape_loads() {
        let json = r#"{
            "network": {"allowedDomains": [], "deniedDomains": []},
            "filesystem": {"denyRead": [], "allowRead": [], "allowWrite": [], "denyWrite": []}
        }"#;

        assert_eq!(Config::from_json(json), Ok(Config::default()));
    }

    #[test]
    fn a_list_that_asks_for_something_is_refused() {
        let json = r#"{"network": {"allowedDomains": ["example.com"]}}"#;

        assert_eq!(
            Config::from_json(json),
            Err(ConfigError::Unsupported {
                key: "network.allowedDomains"
            })
        );
    }

    #[test]
    fn text_that_is_not_settings_is_invalid() {
        assert!(matches!(
            Config::from_json("[1]"),
            Err(ConfigError::Invalid { .. })
        ));
    }
}
