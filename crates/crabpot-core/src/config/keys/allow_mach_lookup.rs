//! `network.allowMachLookup`: Mach service names a command may look up. A
//! `*` is only allowed as the last character.

use serde::Deserializer;

use super::super::leaf::parsed_list;

fn service(name: &str) -> Result<String, &'static str> {
    let prefix = name.strip_suffix('*').unwrap_or(name);
    if prefix.contains('*') {
        Err(
            "wildcards are only allowed as a single trailing \"*\" (e.g., \"com.example.*\" \
             or \"*\" for all services)",
        )
    } else {
        Ok(name.to_owned())
    }
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<String>>, D::Error> {
    parsed_list(deserializer, service).map(Some)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use crate::config::{Config, ConfigError};

    /// Upstream's message for a `*` that is not the single last character
    /// (`src/sandbox/sandbox-config.ts:751`).
    const NOT_TRAILING: &str = "wildcards are only allowed as a single trailing \"*\" (e.g., \"com.example.*\" or \"*\" for all services)";

    /// A settings file that sets only what upstream's schema requires, with
    /// `allowMachLookup` set to `names`.
    fn settings(names: Value) -> String {
        json!({
            "network": {"allowedDomains": [], "deniedDomains": [], "allowMachLookup": names},
            "filesystem": {"denyRead": [], "allowRead": [], "allowWrite": [], "denyWrite": []},
        })
        .to_string()
    }

    #[test]
    fn a_wildcard_in_the_middle_is_refused() {
        for names in [
            json!(["com.*.x"]),
            json!(["*example.com"]),
            json!(["a.b*c*"]),
        ] {
            assert_eq!(
                Config::from_json(&settings(names.clone())),
                Err(ConfigError::Invalid {
                    key: "network.allowMachLookup.0".to_owned(),
                    reason: NOT_TRAILING.to_owned(),
                }),
                "{names}"
            );
        }
    }

    #[test]
    fn a_lone_star_is_accepted() {
        let config = Config::from_json(&settings(json!(["*"]))).unwrap();

        assert_eq!(config.network.allow_mach_lookup, Some(vec!["*".to_owned()]));
    }
}
