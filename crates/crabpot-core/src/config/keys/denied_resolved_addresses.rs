//! `network.deniedResolvedAddresses`: IP addresses and CIDR ranges an allowed
//! name may not resolve to.

use core::net::IpAddr;

use serde::Deserializer;

use super::super::leaf::parsed_list;

pub(crate) const PATH: &str = "network.deniedResolvedAddresses";

/// An IP literal or a CIDR range, in the form rules are kept in: an IPv4-mapped
/// IPv6 range is the IPv4 range it stands for, and a zone id is dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressRange {
    /// The address, or the network's base address as written.
    pub address: IpAddr,
    /// How many leading bits of `address` the range fixes.
    pub prefix: u8,
}

impl AddressRange {
    fn parse(entry: &str) -> Result<Self, &'static str> {
        const INVALID: &str = "invalid IP address or CIDR range. Use an IPv4/IPv6 literal or \
            CIDR, e.g. \"10.0.0.0/8\", \"192.168.1.10\", \"fc00::/7\" (IPv6 unbracketed)";
        let (address, prefix) = match entry.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (entry, None),
        };
        let address = address.split_once('%').map_or(address, |(bare, _)| bare);
        let address: IpAddr = address.parse().map_err(|_| INVALID)?;
        let max: u8 = if address.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => max,
            Some(digits)
                if (1..=3).contains(&digits.len())
                    && digits.bytes().all(|b| b.is_ascii_digit()) =>
            {
                digits
                    .parse()
                    .ok()
                    .filter(|prefix| *prefix <= max)
                    .ok_or(INVALID)?
            }
            Some(_) => return Err(INVALID),
        };
        if let IpAddr::V6(v6) = address
            && let Some(v4) = v6.to_ipv4_mapped()
        {
            return match prefix.checked_sub(96) {
                Some(prefix) => Ok(Self {
                    address: IpAddr::V4(v4),
                    prefix,
                }),
                None => Err(INVALID),
            };
        }
        Ok(Self { address, prefix })
    }
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<AddressRange>>, D::Error> {
    parsed_list(deserializer, AddressRange::parse).map(Some)
}
