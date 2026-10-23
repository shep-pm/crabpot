//! `enableWeakerNetworkIsolation`: the one Mach lookup a Go program needs to
//! verify a TLS certificate. It relaxes no file or network rule.

use crabpot_core::config::Config;

pub(super) fn rules(config: &Config) -> String {
    if config.enable_weaker_network_isolation == Some(true) {
        TRUSTD.to_owned()
    } else {
        String::new()
    }
}

/// The service `trustd` answers certificate questions on, which Go's
/// `crypto/x509` asks and the base profile's list does not hold.
const TRUSTD: &str = concat!(
    "\n; Weaker network isolation: the trustd lookup a Go program needs\n",
    "(allow mach-lookup (global-name \"com.apple.trustd.agent\"))\n",
);

#[cfg(test)]
mod tests {
    use crabpot_core::config::Config;

    use super::super::render;

    /// The whole profile for a settings file that sets
    /// `enableWeakerNetworkIsolation` to `weaker`, or leaves it out for `None`.
    fn profile(weaker: Option<bool>) -> String {
        let key = match weaker {
            Some(set) => format!("\"enableWeakerNetworkIsolation\": {set},"),
            None => String::new(),
        };
        let settings = format!(
            r#"{{{key}
                "network": {{"allowedDomains": [], "deniedDomains": []}},
                "filesystem": {{"denyRead": [], "allowWrite": [], "denyWrite": []}}
            }}"#
        );
        let config = Config::from_json(&settings).unwrap_or_else(|e| panic!("{settings}: {e}"));

        render(&config)
    }

    #[test]
    fn true_adds_the_trustd_rule_and_false_adds_nothing() {
        const TRUSTD: &str = "(allow mach-lookup (global-name \"com.apple.trustd.agent\"))";
        let default = profile(None);

        assert!(profile(Some(true)).contains(TRUSTD));
        assert!(!default.contains("trustd"), "{default}");
        assert_eq!(profile(Some(false)), default);
    }
}
