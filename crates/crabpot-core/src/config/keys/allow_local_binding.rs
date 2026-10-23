//! `network.allowLocalBinding`: whether a command may bind, accept on and dial
//! any local port. A boolean, and unset is upstream's `false`.

use serde::Deserializer;

use super::super::Network;
use super::super::leaf::present;

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<bool>, D::Error> {
    present(deserializer)
}

impl Network {
    /// `allowLocalBinding`: whether the command may bind and accept on any
    /// local port and dial any loopback port. Unset is upstream's `false`.
    #[must_use]
    pub fn allows_local_binding(&self) -> bool {
        self.allow_local_binding.unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::config::Config;

    /// A settings file that sets only what upstream requires, plus
    /// `allowLocalBinding` when `allow_local_binding` is given.
    fn settings(allow_local_binding: Option<bool>) -> String {
        let mut network = json!({"allowedDomains": [], "deniedDomains": []});
        if let Some(value) = allow_local_binding {
            network
                .as_object_mut()
                .unwrap()
                .insert("allowLocalBinding".to_owned(), json!(value));
        }
        json!({
            "network": network,
            "filesystem": {"denyRead": [], "allowWrite": [], "denyWrite": []}
        })
        .to_string()
    }

    #[test]
    fn a_true_is_read_and_an_unset_is_upstreams_false() {
        for (text, allowed) in [(Some(true), true), (Some(false), false), (None, false)] {
            let config = Config::from_json(&settings(text)).unwrap();
            assert_eq!(
                config.network.allows_local_binding(),
                allowed,
                "{text:?}: {config:?}"
            );
        }
    }
}
