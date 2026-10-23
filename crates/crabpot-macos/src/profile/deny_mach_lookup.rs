//! The Mach services a config takes away, which `network.denyMachLookup` names.
//!
//! A deny is the last rule of the profile, so it wins over the base profile's
//! allows and over `allowMachLookup`, a lone `*` included. A name is written as
//! `allowMachLookup`'s is: a trailing `*` makes it a prefix rule.

use crabpot_core::PathError;
use crabpot_core::config::Config;

use super::mach_lookup::section;

pub(super) fn rules(config: &Config) -> Result<String, PathError> {
    let names = config
        .network
        .deny_mach_lookup
        .as_deref()
        .unwrap_or_default();
    Ok(section("Denied Mach lookups", "deny", names))
}

#[cfg(test)]
mod tests {
    use crabpot_core::config::Config;

    use super::super::render;

    const KEYCHAIN: [&str; 2] = ["com.apple.securityd.xpc", "com.apple.SecurityServer"];

    /// `names` as a JSON list.
    fn list(names: &[&str]) -> String {
        let quoted: Vec<String> = names.iter().map(|name| format!("\"{name}\"")).collect();
        format!("[{}]", quoted.join(", "))
    }

    /// The whole profile for a settings file that allows `allow` and denies
    /// `deny`, with the proxy's ports so its rules are there to come before.
    fn profile(allow: &[&str], deny: Option<&[&str]>) -> String {
        let deny = deny.map_or_else(String::new, |deny| {
            format!(r#""denyMachLookup": {},"#, list(deny))
        });
        let settings = format!(
            r#"{{
                "network": {{
                    {deny}
                    "allowedDomains": [], "deniedDomains": [],
                    "allowMachLookup": {}
                }},
                "filesystem": {{"denyRead": [], "allowWrite": [], "denyWrite": []}}
            }}"#,
            list(allow)
        );
        let config = Config::from_json(&settings).unwrap_or_else(|e| panic!("{settings}: {e}"));

        render(&config, Some(51234), Some(51235)).unwrap()
    }

    #[test]
    fn the_denies_come_last_and_beat_allow_mach_lookup_star() {
        let profile = profile(&["*"], Some(&[KEYCHAIN[0], KEYCHAIN[1], "com.example.*"]));

        assert!(
            profile.ends_with(
                "\n; Denied Mach lookups\n\
                 (deny mach-lookup (global-name \"com.apple.securityd.xpc\"))\n\
                 (deny mach-lookup (global-name \"com.apple.SecurityServer\"))\n\
                 (deny mach-lookup (global-name-prefix \"com.example.\"))\n"
            ),
            "{profile}"
        );
        let last_allow = profile.rfind("(allow mach-lookup").unwrap();
        let first_deny = profile.find("(deny mach-lookup").unwrap();
        assert!(last_allow < first_deny, "{profile}");
        assert!(
            profile.contains("(allow mach-lookup (global-name-prefix \"\"))"),
            "the wildcard allow is still in the profile for the denies to beat"
        );
    }

    #[test]
    fn left_out_or_empty_the_profile_is_the_one_without_the_key() {
        let without = profile(&[], None);

        assert!(!without.contains("(deny mach-lookup"), "{without}");
        assert_eq!(profile(&[], Some(&[])), without);
    }
}
