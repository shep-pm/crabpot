//! `network.strictAllowlist`: whether `allowedDomains` is policy the proxy may
//! not widen. Upstream's schema has it as an optional boolean, and crabpot
//! reads it as one.
//!
//! It decides nothing about what crabpot's proxy lets through. Upstream consults
//! a per-command allow list and an ask callback only when the key is off
//! (`src/sandbox/sandbox-manager.ts:532-566`), and crabpot has neither
//! (issue #7), so a host off `allowedDomains` is refused whether the key is
//! `true` or `false`. `proxy::filter` holds the flag and says so.

use serde::Deserializer;

use super::super::leaf::present;

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<bool>, D::Error> {
    present(deserializer)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::config::{Config, ConfigError};

    fn load(strict: &serde_json::Value) -> Result<Config, ConfigError> {
        Config::from_json(
            &json!({
                "network": {
                    "allowedDomains": ["example.com"],
                    "deniedDomains": [],
                    "strictAllowlist": strict
                },
                "filesystem": {"denyRead": [], "allowWrite": [], "denyWrite": []}
            })
            .to_string(),
        )
    }

    #[test]
    fn both_settings_load() {
        assert_eq!(
            load(&json!(true)).unwrap().network.strict_allowlist,
            Some(true)
        );
        assert_eq!(
            load(&json!(false)).unwrap().network.strict_allowlist,
            Some(false)
        );
        assert_eq!(
            Config::from_json(
                &json!({
                    "network": {"allowedDomains": [], "deniedDomains": []},
                    "filesystem": {"denyRead": [], "allowWrite": [], "denyWrite": []}
                })
                .to_string(),
            )
            .unwrap()
            .network
            .strict_allowlist,
            None
        );
    }

    #[test]
    fn a_value_that_is_not_a_boolean_is_refused_with_its_key_path() {
        for strict in [json!("true"), json!(0), json!(null), json!({})] {
            match load(&strict) {
                Err(ConfigError::Invalid { key, .. }) => {
                    assert_eq!(key, "network.strictAllowlist", "{strict}");
                }
                other => panic!("{strict}: expected Invalid, got {other:?}"),
            }
        }
    }
}
