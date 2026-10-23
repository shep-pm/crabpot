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
