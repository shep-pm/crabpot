//! `network.deniedDomains`: hosts a command may not reach, which beat
//! `allowedDomains`. Required, and a bare `*` or `*:port` is allowed.

use serde::Deserializer;

use super::super::leaf::parsed_list;
use crate::domain::DomainEntry;

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<DomainEntry>, D::Error> {
    parsed_list(deserializer, DomainEntry::parse_denied)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::config::{Config, ConfigError};

    fn load(domains: &serde_json::Value) -> Result<Config, ConfigError> {
        Config::from_json(
            &json!({
                "network": {"allowedDomains": [], "deniedDomains": domains},
                "filesystem": {"denyRead": [], "allowWrite": [], "denyWrite": []}
            })
            .to_string(),
        )
    }

    #[test]
    fn a_bad_entry_is_refused_with_its_key_path() {
        for (domains, key) in [
            (json!(["*.com"]), "network.deniedDomains.0"),
            (
                json!(["example.com", "https://example.com"]),
                "network.deniedDomains.1",
            ),
            (json!(["2001:db8::1:443"]), "network.deniedDomains.0"),
            (json!([""]), "network.deniedDomains.0"),
            (json!("example.com"), "network.deniedDomains"),
        ] {
            match load(&domains) {
                Err(ConfigError::Invalid { key: got, .. }) => assert_eq!(got, key, "{domains}"),
                other => panic!("{domains}: expected Invalid, got {other:?}"),
            }
        }
    }

    #[test]
    fn the_entries_are_kept_as_written() {
        let config = load(&json!(["*", "*:22", "*.example.org:8443", "[::1]:443"])).unwrap();

        let entries: Vec<&str> = config
            .network
            .denied_domains
            .iter()
            .map(|entry| entry.as_str())
            .collect();
        assert_eq!(entries, ["*", "*:22", "*.example.org:8443", "[::1]:443"]);
    }
}
