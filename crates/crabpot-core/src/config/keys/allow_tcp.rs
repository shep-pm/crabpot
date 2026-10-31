//! `network.allowTcp`: hosts and ports a command may dial directly

use std::net::SocketAddr;
use std::num::NonZeroU16;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer};

pub(crate) const PATH: &str = "network.allowTcp";

/// A DNS name or IP literal with a nonzero TCP port
// Wire format: changing the host:port spelling is a breaking change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpDestination {
    host: String,
    port: NonZeroU16,
}

impl TcpDestination {
    /// The DNS name in lowercase, or the IP literal without brackets
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The TCP port, from 1 to 65535
    pub fn port(&self) -> u16 {
        self.port.get()
    }

    fn parse(entry: &str) -> Option<Self> {
        if let Ok(address) = entry.parse::<SocketAddr>() {
            return Some(Self {
                host: address.ip().to_string(),
                port: NonZeroU16::new(address.port())?,
            });
        }
        let (host, port) = entry.rsplit_once(':')?;
        if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let host = host.strip_suffix('.').unwrap_or(host);
        let valid_host = !host.is_empty()
            && host.len() <= 253
            && host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            });
        if !valid_host {
            return None;
        }
        Some(Self {
            host: host.to_ascii_lowercase(),
            port: NonZeroU16::new(port.parse().ok()?)?,
        })
    }
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<TcpDestination>>, D::Error> {
    let entries = Vec::<String>::deserialize(deserializer)?;
    let mut destinations = Vec::new();
    for entry in entries {
        let destination = TcpDestination::parse(&entry).ok_or_else(|| {
            D::Error::custom(format_args!(
                "invalid entry \"{entry}\": expected a DNS name or IP literal and port from 1 to 65535"
            ))
        })?;
        if destinations.contains(&destination) {
            return Err(D::Error::custom(format_args!(
                "duplicate entry \"{entry}\""
            )));
        }
        destinations.push(destination);
    }
    Ok(Some(destinations))
}
