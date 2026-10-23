//! `filesystem.allowWrite`: paths a command may write. Required.

use serde::Deserializer;

use super::super::leaf::path_list;
use crate::path_entries::PathEntry;

pub(crate) const PATH: &str = "filesystem.allowWrite";

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<PathEntry>, D::Error> {
    path_list(deserializer)
}
