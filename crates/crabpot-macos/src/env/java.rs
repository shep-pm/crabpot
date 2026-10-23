//! The part of the environment a JVM in the sandbox needs.
//!
//! `src/sandbox/java-proxy-agent.ts` `buildJavaToolOptions`, without the
//! agent jar ADR-0008 leaves to upstream.

use std::ffi::{OsStr, OsString};

use super::Facts;

/// Seatbelt's `(remote ip "localhost:N")` matches `127.0.0.1` and `::1` but
/// not `::ffff:127.0.0.1`, and a modern JVM dials loopback in that form
/// unless it is forced onto the IPv4 stack.
const PREFER_IPV4: &str = "-Djava.net.preferIPv4Stack=true";

pub(super) fn vars(facts: &Facts) -> Vec<(OsString, OsString)> {
    java_tool_options(facts)
        .map(|value| vec![(OsString::from("JAVA_TOOL_OPTIONS"), value)])
        .unwrap_or_default()
}

/// The host's value with the flag joined on, or nothing when there is no
/// value to carry and no flag to add.
fn java_tool_options(facts: &Facts) -> Option<OsString> {
    let inherited = facts.java_tool_options.clone().unwrap_or_default();
    let mut value = inherited.clone();
    if facts.loopback_reachable && !carries(&inherited, PREFER_IPV4) {
        if !value.is_empty() {
            value.push(" ");
        }
        value.push(PREFER_IPV4);
    }
    (!value.is_empty()).then_some(value)
}

/// The flag is looked for in the whole value, as upstream's `includes` does.
/// A flag is ASCII, so reading the value lossily can neither hide one nor
/// invent one.
fn carries(value: &OsStr, flag: &str) -> bool {
    value.to_string_lossy().contains(flag)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(loopback_reachable: bool, inherited: Option<&str>) -> Facts {
        Facts {
            loopback_reachable,
            claude_code_tmpdir: None,
            claude_tmpdir: None,
            java_tool_options: inherited.map(OsString::from),
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
        assert_eq!(
            vars(&facts(false, Some("-Xmx256m"))),
            vec![(
                OsString::from("JAVA_TOOL_OPTIONS"),
                OsString::from("-Xmx256m"),
            )],
            "the inherited value stays, with no flag on it"
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
    fn the_flag_is_not_added_twice() {
        assert_eq!(
            vars(&facts(true, Some("-Djava.net.preferIPv4Stack=true -Xmx256m"))),
            vec![(
                OsString::from("JAVA_TOOL_OPTIONS"),
                OsString::from("-Djava.net.preferIPv4Stack=true -Xmx256m"),
            )],
        );
    }
}
