//! `network.deniedDomains`: hosts a command may not reach, which beat
//! `allowedDomains`. Required, and a bare `*` or `*:port` is allowed.

use serde::Deserializer;

use super::super::leaf::parsed_list;
use crate::domain::DomainEntry;

pub(crate) const PATH: &str = "network.deniedDomains";

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<DomainEntry>, D::Error> {
    parsed_list(deserializer, DomainEntry::parse_denied)
}
