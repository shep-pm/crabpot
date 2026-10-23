//! The settings a sandbox starts from.
//!
//! A stub. It reads no key, and refuses every key crabpot cannot honour yet
//! that asks for something, so a rule is never dropped without an error
//! (ADR-0013). A key upstream does not know is dropped, as upstream drops it.
//! The real schema replaces it (ADR-0004).

use core::fmt;

use serde_json::Value;

/// The keys upstream applies and this stub does not, as dotted paths. The
/// lists are here too, since nothing applies them yet.
const UNSUPPORTED: &[&str] = &[
    "network.allowedDomains",
    "network.deniedDomains",
    "network.allowUnixSockets",
    "network.allowAllUnixSockets",
    "network.allowLocalBinding",
    "network.httpProxyPort",
    "network.socksProxyPort",
    "network.parentProxy",
    "network.tlsTerminate",
    "network.denyMachLookup",
    "filesystem.denyRead",
    "filesystem.allowRead",
    "filesystem.allowWrite",
    "filesystem.denyWrite",
    "filesystem.allowGitConfig",
    "credentials",
    "allowPty",
    "enableWeakerNestedSandbox",
    "enableWeakerNetworkIsolation",
];

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
    /// [`ConfigError::Unsupported`] when a key asks for something crabpot
    /// does not apply yet. A key asks for something when its value is a
    /// non-empty list, string or object, a number, or `true`.
    pub fn from_json(json: &str) -> Result<Self, ConfigError> {
        let settings: Value = serde_json::from_str(json).map_err(|e| ConfigError::Invalid {
            reason: e.to_string(),
        })?;
        if !settings.is_object() {
            return Err(ConfigError::Invalid {
                reason: "settings are not an object".to_owned(),
            });
        }
        for key in UNSUPPORTED {
            let value = key
                .split('.')
                .try_fold(&settings, |value, part| value.get(part));
            if value.is_some_and(asks) {
                return Err(ConfigError::Unsupported { key });
            }
        }
        Ok(Self {})
    }
}

fn asks(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(set) => *set,
        Value::Number(_) => true,
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(fields) => !fields.is_empty(),
    }
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
    fn a_known_key_that_is_not_a_list_is_refused_too() {
        for (json, key) in [
            (r#"{"credentials": {"files": ["~/.aws"]}}"#, "credentials"),
            (
                r#"{"network": {"denyMachLookup": ["com.apple.x"]}}"#,
                "network.denyMachLookup",
            ),
            (
                r#"{"network": {"tlsTerminate": true}}"#,
                "network.tlsTerminate",
            ),
        ] {
            assert_eq!(
                Config::from_json(json),
                Err(ConfigError::Unsupported { key })
            );
        }
    }

    #[test]
    fn a_key_that_asks_for_nothing_loads() {
        let json = r#"{"credentials": {}, "network": {"tlsTerminate": false}, "other": 1}"#;

        assert_eq!(Config::from_json(json), Ok(Config::default()));
    }

    #[test]
    fn text_that_is_not_settings_is_invalid() {
        assert!(matches!(
            Config::from_json("[1]"),
            Err(ConfigError::Invalid { .. })
        ));
    }
}
