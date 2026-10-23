//! `enableWeakerNetworkIsolation`: lets a command look up
//! `com.apple.trustd.agent`, which Go programs need to verify certificates.

use serde::{Deserialize, Deserializer};
use serde_json::Value;

/// What upstream's schema puts on the key: a boolean, and `null` is not one.
const EXPECTED: &str = "expected a boolean";

/// The key as upstream writes it, `None` when it is left out.
pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<bool>, D::Error> {
    match Value::deserialize(deserializer)? {
        Value::Bool(set) => Ok(Some(set)),
        _ => Err(serde::de::Error::custom(EXPECTED)),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::config::{Config, ConfigError};

    /// The keys upstream's schema requires, with this key set to `value`.
    fn settings(value: &Value) -> String {
        json!({
            "enableWeakerNetworkIsolation": value,
            "network": {"allowedDomains": [], "deniedDomains": []},
            "filesystem": {"denyRead": [], "allowWrite": [], "denyWrite": []},
        })
        .to_string()
    }

    #[test]
    fn a_string_is_refused() {
        const KEY: &str = "enableWeakerNetworkIsolation";

        for value in [
            json!("yes"),
            json!(""),
            json!(null),
            json!(1),
            json!([true]),
        ] {
            assert_eq!(
                Config::from_json(&settings(&value)),
                Err(ConfigError::Invalid {
                    key: KEY.to_owned(),
                    reason: EXPECTED.to_owned(),
                }),
                "{value}"
            );
        }
    }
}
