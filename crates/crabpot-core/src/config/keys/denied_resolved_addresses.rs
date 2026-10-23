//! `network.deniedResolvedAddresses`: IP addresses and CIDR ranges an allowed
//! name may not resolve to.

use serde::Deserializer;

use super::super::leaf::parsed_list;
use crate::address::AddressRange;

fn parse(entry: &str) -> Result<AddressRange, &'static str> {
    AddressRange::parse(entry).map_err(|_| {
        "invalid IP address or CIDR range. Use an IPv4/IPv6 literal or CIDR, e.g. \
         \"10.0.0.0/8\", \"192.168.1.10\", \"fc00::/7\" (IPv6 unbracketed)"
    })
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<AddressRange>>, D::Error> {
    parsed_list(deserializer, parse).map(Some)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::config::{Config, ConfigError};

    fn load(addresses: &serde_json::Value) -> Result<Config, ConfigError> {
        Config::from_json(
            &json!({
                "network": {
                    "allowedDomains": [],
                    "deniedDomains": [],
                    "deniedResolvedAddresses": addresses
                },
                "filesystem": {"denyRead": [], "allowWrite": [], "denyWrite": []}
            })
            .to_string(),
        )
    }

    #[test]
    fn a_bad_cidr_is_refused_with_its_key_path() {
        for (addresses, key) in [
            (json!(["10.0.0.0/33"]), "network.deniedResolvedAddresses.0"),
            (
                json!(["10.0.0.0/8", "fc00::/129"]),
                "network.deniedResolvedAddresses.1",
            ),
            (json!(["[::1]"]), "network.deniedResolvedAddresses.0"),
            (
                json!(["::ffff:10.0.0.0/95"]),
                "network.deniedResolvedAddresses.0",
            ),
            (json!(["example.com"]), "network.deniedResolvedAddresses.0"),
            (json!("10.0.0.0/8"), "network.deniedResolvedAddresses"),
        ] {
            match load(&addresses) {
                Err(ConfigError::Invalid { key: got, .. }) => {
                    assert_eq!(got, key, "{addresses}");
                }
                other => panic!("{addresses}: expected Invalid, got {other:?}"),
            }
        }
    }

    #[test]
    fn the_ranges_are_read_in_the_form_rules_keep() {
        let config = load(&json!(["10.0.0.0/8", "::ffff:10.0.0.0/104", "fe80::1%en0"])).unwrap();

        let ranges: Vec<(String, u8)> = config
            .network
            .denied_resolved_addresses
            .unwrap()
            .iter()
            .map(|range| (range.address.to_string(), range.prefix))
            .collect();
        assert_eq!(
            ranges,
            [
                ("10.0.0.0".to_owned(), 8),
                ("10.0.0.0".to_owned(), 8),
                ("fe80::1".to_owned(), 128),
            ]
        );
    }
}
