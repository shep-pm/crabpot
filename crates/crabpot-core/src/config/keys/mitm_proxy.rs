//! `network.mitmProxy`: domains routed through an upstream proxy over a Unix
//! socket. Both parts are required, and `domains` holds at least one.

use serde::{Deserialize, Deserializer};

use super::super::leaf::{non_empty, parsed, parsed_list};
use crate::domain::DomainPattern;

pub(crate) const PATH: &str = "network.mitmProxy";

/// The Unix socket of an upstream proxy, and the domains sent to it.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct MitmProxy {
    /// The Unix socket path of the proxy.
    #[serde(deserialize_with = "socket_path")]
    pub socket_path: String,
    /// The domains routed through it.
    #[serde(deserialize_with = "domains")]
    pub domains: Vec<DomainPattern>,
}

fn socket_path<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    parsed(deserializer, non_empty)
}

fn domains<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<DomainPattern>, D::Error> {
    let domains = parsed_list(deserializer, DomainPattern::parse)?;
    if domains.is_empty() {
        return Err(serde::de::Error::custom(
            "must contain at least 1 element(s)",
        ));
    }
    Ok(domains)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use crate::config::{Config, ConfigError};

    /// A settings file whose only optional `network` key is `mitmProxy`.
    fn load(mitm: &Value) -> Result<Config, ConfigError> {
        Config::from_json(
            &json!({
                "network": {"allowedDomains": [], "deniedDomains": [], "mitmProxy": mitm},
                "filesystem": {"denyRead": [], "allowWrite": [], "denyWrite": []}
            })
            .to_string(),
        )
    }

    #[test]
    fn the_socket_and_its_domains_are_kept() {
        let config = load(&json!(
            {"socketPath": "/run/mitm.sock", "domains": ["example.com", "*.internal.org"]}
        ))
        .unwrap();

        let mitm = config.network.mitm_proxy.expect("mitmProxy is read");
        assert_eq!(mitm.socket_path, "/run/mitm.sock");
        let domains: Vec<&str> = mitm
            .domains
            .iter()
            .map(|pattern| pattern.as_str())
            .collect();
        assert_eq!(domains, ["example.com", "*.internal.org"]);
    }

    #[test]
    fn empty_domains_and_empty_socket_path_are_refused() {
        for (mitm, key) in [
            (
                json!({"socketPath": "/m", "domains": []}),
                "network.mitmProxy.domains",
            ),
            (
                json!({"socketPath": "", "domains": ["a.com"]}),
                "network.mitmProxy.socketPath",
            ),
            (json!({"socketPath": "/m"}), "network.mitmProxy.domains"),
            (
                json!({"socketPath": "/m", "domains": ["https://a.com"]}),
                "network.mitmProxy.domains.0",
            ),
        ] {
            match load(&mitm) {
                Err(ConfigError::Invalid { key: got, .. }) => assert_eq!(got, key, "{mitm}"),
                other => panic!("{mitm}: expected Invalid, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_socket_path_of_any_text_loads() {
        // A path that names nothing is a refused tunnel per request, not a load error.
        let config = load(&json!({"socketPath": "/no/such/socket", "domains": ["a.com"]})).unwrap();

        assert!(config.network.mitm_proxy.is_some());
    }
}
