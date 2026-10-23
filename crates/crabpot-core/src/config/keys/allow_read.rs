//! `filesystem.allowRead`: paths a command may read inside a denied one.

use serde::Deserializer;

use super::super::leaf::path_list;
use crate::path_entries::PathEntry;

pub(crate) const PATH: &str = "filesystem.allowRead";

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<PathEntry>>, D::Error> {
    path_list(deserializer).map(Some)
}
