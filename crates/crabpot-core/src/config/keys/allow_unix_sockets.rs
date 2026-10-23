//! `network.allowUnixSockets`: the Unix socket paths a command may use.
//! Upstream takes every string, an empty one included.

use serde::Deserializer;

use super::super::leaf::present;
use super::super::Network;
use crate::path::{PathBase, PathError, normalize_path_for_sandbox};

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<String>>, D::Error> {
    present(deserializer)
}

impl Network {
    /// What `allowUnixSockets` names, as the sandbox matches it: each entry
    /// made absolute against `HOME` and the working directory, in the reading
    /// a path pattern has.
    ///
    /// # Errors
    ///
    /// [`PathError`] when an entry starts with `~` and `HOME` is not set, or is
    /// relative and there is no working directory.
    pub fn unix_socket_paths(&self) -> Result<Vec<String>, PathError> {
        let base = PathBase::from_env();
        self.allow_unix_sockets
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|entry| normalize_path_for_sandbox(&base, entry, false))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::config::Config;

    fn load(allow_unix_sockets: &serde_json::Value) -> Result<Config, String> {
        Config::from_json(
            &json!({
                "network": {
                    "allowedDomains": [], "deniedDomains": [],
                    "allowUnixSockets": allow_unix_sockets
                },
                "filesystem": {"denyRead": [], "allowWrite": [], "denyWrite": []}
            })
            .to_string(),
        )
        .map_err(|e| format!("{e}"))
    }

    #[test]
    fn a_list_of_socket_paths_loads() {
        let config = load(&json!(["/crabpot-nowhere/socks", "/crabpot-nowhere/live.sock"]));

        assert_eq!(
            config.unwrap().network.allow_unix_sockets,
            Some(vec![
                "/crabpot-nowhere/socks".to_owned(),
                "/crabpot-nowhere/live.sock".to_owned(),
            ])
        );
    }

    #[test]
    fn an_empty_entry_loads() {
        assert_eq!(
            load(&json!([""])).unwrap().network.allow_unix_sockets,
            Some(vec![String::new()])
        );
    }

    #[test]
    fn an_entry_that_is_not_a_string_is_refused() {
        for entries in [json!({"path": "/a"}), json!([{"path": "/a", "literal": true}])] {
            let reason = load(&entries).unwrap_err();

            assert!(reason.contains("allowUnixSockets"), "{entries}: {reason}");
        }
    }
}
