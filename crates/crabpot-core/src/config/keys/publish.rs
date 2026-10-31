//! `network.publish`: local addresses and ports a command may listen on

use std::net::SocketAddr;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer};

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<SocketAddr>>, D::Error> {
    let entries = Vec::<String>::deserialize(deserializer)?;
    entries
        .iter()
        .map(|entry| {
            entry.parse::<SocketAddr>().map_err(|_| {
                D::Error::custom(format_args!(
                    "invalid entry \"{entry}\": expected an IP literal and port"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}
