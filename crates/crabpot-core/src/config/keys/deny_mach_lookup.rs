//! `network.denyMachLookup`: Mach service names a command may not look up,
//! such as the keychain's. A key of crabpot's own (ADR-0003, ADR-0011), so
//! upstream's schema says nothing about it. A name is checked as
//! `allowMachLookup`'s is.

pub(crate) use super::allow_mach_lookup::deserialize;

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use crate::config::{Config, ConfigError};

    /// A settings file that sets only what upstream's schema requires, with
    /// `key` of `network` set to `names`.
    fn settings(key: &str, names: Value) -> String {
        json!({
            "network": {"allowedDomains": [], "deniedDomains": [], key: names},
            "filesystem": {"denyRead": [], "allowWrite": [], "denyWrite": []},
        })
        .to_string()
    }

    /// What loading `names` as `key` comes to, with the key's own name left
    /// out of the error so the two keys can be compared.
    fn loaded(key: &str, names: &Value) -> Result<Option<Vec<String>>, (String, String)> {
        match Config::from_json(&settings(key, names.clone())) {
            Ok(config) => Ok(if key == "denyMachLookup" {
                config.network.deny_mach_lookup
            } else {
                config.network.allow_mach_lookup
            }),
            Err(ConfigError::Invalid { key: at, reason }) => {
                Err((at.replace(key, "<key>"), reason))
            }
            Err(other) => panic!("{key} {names}: {other}"),
        }
    }

    #[test]
    fn the_wildcard_rule_matches_allow_mach_lookups() {
        for names in [
            json!(["com.*.x"]),
            json!(["*example.com"]),
            json!(["a.b*c*"]),
            json!(["com.apple.ok", "com.*.x"]),
            json!(["*"]),
            json!(["com.example.*"]),
            json!([]),
            json!(["com.apple.securityd.xpc", "com.apple.SecurityServer"]),
        ] {
            assert_eq!(
                loaded("denyMachLookup", &names),
                loaded("allowMachLookup", &names),
                "{names}"
            );
        }
    }

    #[test]
    fn a_wildcard_in_the_middle_is_refused_naming_its_entry() {
        assert_eq!(
            Config::from_json(&settings(
                "denyMachLookup",
                json!(["com.apple.ok", "com.*.x"])
            )),
            Err(ConfigError::Invalid {
                key: "network.denyMachLookup.1".to_owned(),
                reason: "wildcards are only allowed as a single trailing \"*\" (e.g., \
                         \"com.example.*\" or \"*\" for all services)"
                    .to_owned(),
            })
        );
    }

    #[test]
    fn the_names_are_read_into_the_config_in_order() {
        let config = Config::from_json(&settings(
            "denyMachLookup",
            json!(["com.apple.securityd.xpc", "com.apple.SecurityServer"]),
        ))
        .unwrap();

        assert_eq!(
            config.network.deny_mach_lookup,
            Some(vec![
                "com.apple.securityd.xpc".to_owned(),
                "com.apple.SecurityServer".to_owned(),
            ])
        );
    }
}
