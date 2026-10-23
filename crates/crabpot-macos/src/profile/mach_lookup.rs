//! The Mach services a config adds to the ones every profile already allows.
//!
//! A name is a service, or a name with a trailing `*` for every service under
//! it, which becomes a prefix rule. A lone `*` is the prefix rule of the empty
//! prefix, which is every service.

use crabpot_core::config::Config;

pub(super) fn rules(config: &Config) -> String {
    let names = config
        .network
        .allow_mach_lookup
        .as_deref()
        .unwrap_or_default();
    if names.is_empty() {
        return String::new();
    }

    let mut rules = String::from("\n; Mach lookups\n");
    for name in names {
        let (rule, service) = match name.strip_suffix('*') {
            Some(prefix) => ("global-name-prefix", prefix),
            None => ("global-name", name.as_str()),
        };
        rules.push_str(&format!(
            "(allow mach-lookup ({rule} {}))\n",
            quoted(service)
        ));
    }
    rules
}

/// `text` as a seatbelt string, quoted the way upstream's `escapePath` quotes
/// a name: as a JSON string.
fn quoted(text: &str) -> String {
    serde_json::Value::from(text).to_string()
}

#[cfg(test)]
mod tests {
    use crabpot_core::config::Config;

    use super::*;

    /// A config whose `allowMachLookup` is `names`.
    fn allowing(names: &[&str]) -> Config {
        let mut config = Config::default();
        config.network.allow_mach_lookup =
            Some(names.iter().map(|name| (*name).to_owned()).collect());
        config
    }

    #[test]
    fn a_trailing_star_becomes_a_prefix_rule() {
        assert_eq!(
            rules(&allowing(&["com.example.*", "com.apple.foo", "*"])),
            "\n; Mach lookups\n\
             (allow mach-lookup (global-name-prefix \"com.example.\"))\n\
             (allow mach-lookup (global-name \"com.apple.foo\"))\n\
             (allow mach-lookup (global-name-prefix \"\"))\n"
        );
    }

    #[test]
    fn a_name_is_quoted_as_a_json_string() {
        assert_eq!(
            rules(&allowing(&[r#"com.example."weird""#, r"com.example\back"])),
            "\n; Mach lookups\n\
             (allow mach-lookup (global-name \"com.example.\\\"weird\\\"\"))\n\
             (allow mach-lookup (global-name \"com.example\\\\back\"))\n"
        );
    }

    #[test]
    fn a_config_that_asks_for_no_lookup_adds_no_rule() {
        assert_eq!(rules(&Config::default()), "");
        assert_eq!(rules(&allowing(&[])), "");
    }
}
