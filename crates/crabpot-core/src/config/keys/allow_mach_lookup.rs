//! `network.allowMachLookup`: Mach service names a command may look up. A
//! `*` is only allowed as the last character.

use serde::Deserializer;

use super::super::leaf::parsed_list;

pub(crate) const PATH: &str = "network.allowMachLookup";

fn service(name: &str) -> Result<String, &'static str> {
    let prefix = name.strip_suffix('*').unwrap_or(name);
    if prefix.contains('*') {
        Err(
            "wildcards are only allowed as a single trailing \"*\" (e.g., \"com.example.*\" \
             or \"*\" for all services)",
        )
    } else {
        Ok(name.to_owned())
    }
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<String>>, D::Error> {
    parsed_list(deserializer, service).map(Some)
}
