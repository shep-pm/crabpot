//! The part of the environment a JVM in the sandbox needs.
//!
//! `src/sandbox/java-proxy-agent.ts` `buildJavaToolOptions`, without the
//! agent jar ADR-0008 leaves to upstream.

use std::ffi::{OsStr, OsString};

use super::Facts;

/// The name a JVM reads, and the name a part amends rather than owns.
pub(super) const JAVA_TOOL_OPTIONS: &str = "JAVA_TOOL_OPTIONS";

/// Seatbelt's `(remote ip "localhost:N")` matches `127.0.0.1` and `::1` but
/// not `::ffff:127.0.0.1`, and a modern JVM dials loopback in that form
/// unless it is forced onto the IPv4 stack. The flag goes on whenever the
/// profile lets the command reach loopback: the proxy's own port, or
/// `allowLocalBinding`'s `localhost:*` (see [`crate::profile::local_binding`]).
const PREFER_IPV4: &str = "-Djava.net.preferIPv4Stack=true";

pub(super) fn vars(facts: &Facts) -> Vec<(OsString, OsString)> {
    java_tool_options(facts)
        .map(|value| vec![(OsString::from(JAVA_TOOL_OPTIONS), value)])
        .unwrap_or_default()
}

/// The flag joined onto the value the command starts with. Nothing is set
/// when the command needs nothing added to its own value, so a value the
/// caller set or removed on the command stays the caller's.
fn java_tool_options(facts: &Facts) -> Option<OsString> {
    if !facts.loopback_reachable {
        return None;
    }
    let mut value = facts.java_tool_options.clone().unwrap_or_default();
    if carries(&value, PREFER_IPV4) {
        return None;
    }
    if !value.is_empty() {
        value.push(" ");
    }
    value.push(PREFER_IPV4);
    Some(value)
}

/// The flag is looked for in the whole value, as upstream's `includes` does.
/// A flag is ASCII, so reading the value lossily can neither hide one nor
/// invent one.
fn carries(value: &OsStr, flag: &str) -> bool {
    value.to_string_lossy().contains(flag)
}

#[cfg(test)]
mod tests {
    use crabpot_core::config::Config;

    use super::*;

    /// A config whose only network setting beyond the empty allowlist is
    /// `allowLocalBinding` set to `allow_local_binding`.
    fn config(allow_local_binding: bool) -> Config {
        Config::from_json(&format!(
            r#"{{
                "network": {{
                    "allowedDomains": [],
                    "deniedDomains": [],
                    "allowLocalBinding": {allow_local_binding}
                }},
                "filesystem": {{"denyRead": [], "allowWrite": [], "denyWrite": []}}
            }}"#
        ))
        .unwrap()
    }

    /// The facts of a sandbox that runs `config` with no proxy of its own, and
    /// with nothing inherited for the java part to compose against.
    fn facts_for(config: &Config) -> Facts {
        Facts {
            java_tool_options: None,
            ..Facts::for_sandbox(config, None)
        }
    }

    #[test]
    fn allow_local_binding_sets_the_ipv4_flag() {
        let facts = facts_for(&config(true));
        assert!(facts.loopback_reachable, "the key opens every loopback port");
        assert_eq!(
            vars(&facts),
            vec![(
                OsString::from(JAVA_TOOL_OPTIONS),
                OsString::from("-Djava.net.preferIPv4Stack=true"),
            )],
        );

        let facts = facts_for(&config(false));
        assert!(
            !facts.loopback_reachable,
            "no key and no proxy port leaves loopback unreachable"
        );
        assert!(vars(&facts).is_empty(), "nothing to add to JAVA_TOOL_OPTIONS");
    }

    fn facts(loopback_reachable: bool, inherited: Option<&str>) -> Facts {
        Facts {
            loopback_reachable,
            claude_code_tmpdir: None,
            claude_tmpdir: None,
            java_tool_options: inherited.map(OsString::from),
            git_safe_directories: Vec::new(),
            git_config_count: None,
        }
    }

    #[test]
    fn the_flag_joins_an_inherited_value_and_is_absent_when_loopback_is_not_reachable() {
        assert_eq!(
            vars(&facts(true, Some("-Xmx256m"))),
            vec![(
                OsString::from("JAVA_TOOL_OPTIONS"),
                OsString::from("-Xmx256m -Djava.net.preferIPv4Stack=true"),
            )],
        );
        assert!(
            vars(&facts(false, Some("-Xmx256m"))).is_empty(),
            "a value the command carries is left to the command"
        );
        assert!(
            vars(&facts(false, None)).is_empty(),
            "nothing to carry and no flag to add sets no variable"
        );
    }

    #[test]
    fn the_flag_is_the_whole_value_when_nothing_is_inherited() {
        assert_eq!(
            vars(&facts(true, None)),
            vec![(
                OsString::from("JAVA_TOOL_OPTIONS"),
                OsString::from("-Djava.net.preferIPv4Stack=true"),
            )],
        );
    }

    #[test]
    fn the_flag_is_left_to_a_value_that_already_carries_it() {
        assert!(
            vars(&facts(true, Some("-Djava.net.preferIPv4Stack=true -Xmx256m"))).is_empty(),
            "the command's own value already has the flag"
        );
    }
}
