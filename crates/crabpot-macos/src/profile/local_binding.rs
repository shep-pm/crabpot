//! `network.allowLocalBinding` and `network.publish`: local ports a command
//! may bind and accept on, and loopback ports it may dial
//!
//! Upstream's `allowLocalBinding` half of `generateSandboxProfile`
//! (`src/sandbox/macos-sandbox-utils.ts`), with its reasons kept.
//!
//! bind and inbound take `(local ip "*:*")` rather than `localhost:*` because a
//! modern runtime (Java and the like) opens an IPv6 dual-stack socket, and a
//! bind of such a socket to `127.0.0.1` is what the kernel holds as
//! `::ffff:127.0.0.1`, which Seatbelt's `localhost` filter does not match.
//! Seatbelt takes only `localhost` or `*` as the host token of an ip filter, so
//! `*:*` is the only spelling that admits the IPv4-mapped form. bind and
//! inbound are local operations with no remote endpoint, so wildcarding them
//! grants no egress.
//!
//! outbound stays `(remote ip "localhost:*")`, so the egress allowlist holds
//! with the key on (upstream's #225 and #88). A `(local ip ...)` filter on
//! `network-outbound` is read against the source address, which for a socket
//! not yet bound is `INADDR_ANY` (`0.0.0.0` or `::`) at `connect()` time, and
//! Seatbelt's `localhost` matches the any-address, so any host token there
//! admits every outbound connect. `(remote ip "localhost:*")` matches a connect
//! to `127.0.0.1` and `::1` but not to `::ffff:127.0.0.1`, which is why the
//! java part forces the IPv4 stack (see [`crate::env::java`]).

use crabpot_core::PathError;
use crabpot_core::config::Config;

pub(super) fn rules(config: &Config) -> Result<String, PathError> {
    if config.network.allows_local_binding() {
        return Ok(RULES.to_owned());
    }
    let mut rules = String::new();
    for address in config.network.publish.iter().flatten() {
        let port = address.port();
        rules.push_str(&format!(
            "(allow network-bind (local ip \"*:{port}\"))\n\
             (allow network-inbound (local ip \"*:{port}\"))\n"
        ));
    }
    Ok(rules)
}

/// The three rules the key adds, with the header of its own group.
const RULES: &str = "\n; Local binding\n\
    (allow network-bind (local ip \"*:*\"))\n\
    (allow network-inbound (local ip \"*:*\"))\n\
    (allow network-outbound (remote ip \"localhost:*\"))\n";

#[cfg(test)]
mod tests {
    use crabpot_core::config::Config;

    use super::super::render;

    /// A config whose only network setting beyond the empty allowlist is
    /// `allowLocalBinding` and `publish`.
    fn config(allow_local_binding: bool, publish: &str) -> Config {
        Config::from_json(&format!(
            r#"{{
                "network": {{
                    "allowedDomains": [],
                    "deniedDomains": [],
                    "allowLocalBinding": {allow_local_binding},
                    "publish": {publish}
                }},
                "filesystem": {{"denyRead": [], "allowWrite": [], "denyWrite": []}}
            }}"#
        ))
        .unwrap()
    }

    /// The network rules a profile admits, in the order it holds them.
    fn admitted(profile: &str) -> Vec<&str> {
        profile
            .lines()
            .filter(|line| line.starts_with("(allow network"))
            .collect()
    }

    #[test]
    fn true_renders_the_three_rules_and_false_none() {
        let profile = render(&config(true, "[]"), None, None).unwrap();

        assert_eq!(
            admitted(&profile),
            [
                r#"(allow network-bind (local ip "*:*"))"#,
                r#"(allow network-inbound (local ip "*:*"))"#,
                r#"(allow network-outbound (remote ip "localhost:*"))"#,
            ],
            "{profile}"
        );

        for config in [config(false, "[]"), Config::default()] {
            let profile = render(&config, None, None).unwrap();
            assert!(admitted(&profile).is_empty(), "{profile}");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn published_ports_allow_binding_and_inbound_without_outbound() {
        let config = config(false, r#"["127.0.0.1:8001", "[::]:3600"]"#);
        let profile = render(&config, None, None).unwrap();

        assert_eq!(
            admitted(&profile),
            [
                r#"(allow network-bind (local ip "*:8001"))"#,
                r#"(allow network-inbound (local ip "*:8001"))"#,
                r#"(allow network-bind (local ip "*:3600"))"#,
                r#"(allow network-inbound (local ip "*:3600"))"#,
            ],
            "{profile}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn local_binding_already_covers_published_ports() {
        let profile = render(&config(true, r#"["0.0.0.0:8001"]"#), None, None).unwrap();

        assert_eq!(
            admitted(&profile),
            [
                r#"(allow network-bind (local ip "*:*"))"#,
                r#"(allow network-inbound (local ip "*:*"))"#,
                r#"(allow network-outbound (remote ip "localhost:*"))"#,
            ],
            "{profile}"
        );
    }
}
