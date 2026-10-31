//! `network.publish`: local addresses and ports a command may listen on

use std::net::SocketAddr;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer};

#[cfg(not(target_os = "macos"))]
pub(crate) const PATH: &str = "network.publish";

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<SocketAddr>>, D::Error> {
    let entries = Vec::<String>::deserialize(deserializer)?;
    let mut addresses = Vec::new();
    for entry in entries {
        let address = entry
            .parse::<SocketAddr>()
            .ok()
            .filter(|address| address.port() != 0)
            .ok_or_else(|| {
                D::Error::custom(format_args!(
                    "invalid entry \"{entry}\": expected an IP literal and port from 1 to 65535"
                ))
            })?;
        if addresses.contains(&address) {
            return Err(D::Error::custom(format_args!("duplicate entry \"{entry}\"")));
        }
        addresses.push(address);
    }
    Ok(Some(addresses))
}
