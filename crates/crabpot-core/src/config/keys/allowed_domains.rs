//! `network.allowedDomains`: the hosts a command may reach, each with an
//! optional `:port`. Required, and a bare `*` is refused.

use serde::Deserializer;

use super::super::leaf::parsed_list;
use crate::domain::DomainEntry;

pub(crate) const PATH: &str = "network.allowedDomains";

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<DomainEntry>, D::Error> {
    parsed_list(deserializer, DomainEntry::parse_allowed)
}
