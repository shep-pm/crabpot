//! `network.allowedDomains`: the hosts a command may reach, each with an
//! optional `:port`. Required, and a bare `*` is refused.

use serde::Deserializer;

use super::super::leaf::parsed_list;
use crate::domain::DomainEntry;

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<DomainEntry>, D::Error> {
    parsed_list(deserializer, DomainEntry::parse_allowed)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::config::{Config, ConfigError};

    fn load(domains: &serde_json::Value) -> Result<Config, ConfigError> {
        Config::from_json(
            &json!({
                "network": {"allowedDomains": domains, "deniedDomains": []},
                "filesystem": {"denyRead": [], "allowWrite": [], "denyWrite": []}
            })
            .to_string(),
        )
    }

    #[test]
    fn a_bad_entry_is_refused_with_its_key_path() {
        for (domains, key) in [
            (json!(["*"]), "network.allowedDomains.0"),
            (json!(["example.com", "*.com"]), "network.allowedDomains.1"),
            (json!(["https://example.com"]), "network.allowedDomains.0"),
            (json!(["::1"]), "network.allowedDomains.0"),
        ] {
            match load(&domains) {
                Err(ConfigError::Invalid { key: got, .. }) => assert_eq!(got, key, "{domains}"),
                other => panic!("{domains}: expected Invalid, got {other:?}"),
            }
        }
    }

    #[test]
    fn the_entries_are_kept_as_written() {
        let config = load(&json!(["example.com", "*.example.org:8443"])).unwrap();

        let entries: Vec<&str> = config
            .network
            .allowed_domains
            .iter()
            .map(|entry| entry.as_str())
            .collect();
        assert_eq!(entries, ["example.com", "*.example.org:8443"]);
    }
}
