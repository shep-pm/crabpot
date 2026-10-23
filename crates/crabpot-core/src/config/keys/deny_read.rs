//! `filesystem.denyRead`: paths a command may not read. Required, and a
//! pattern with a trailing separator is refused.

use serde::Deserializer;

use super::super::leaf::deny_list;
use crate::path_entries::PathEntry;

pub(crate) const PATH: &str = "filesystem.denyRead";

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<PathEntry>, D::Error> {
    deny_list(deserializer)
}
