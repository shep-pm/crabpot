//! The seatbelt profile for one [`Config`] and the proxy it reaches the network through.
//!
//! A profile is a list of sections, in order, since a later rule wins over an
//! earlier one. A section is a file in this folder with a `rules` function,
//! and it is registered by naming it in the `sections!` call.

use crabpot_core::config::Config;

/// What the sections render from.
struct Inputs<'a> {
    #[expect(dead_code, reason = "no section reads the config's rules yet")]
    config: &'a Config,
    /// The loopback port of the proxy, when there is one.
    proxy_port: Option<u16>,
}

/// Declares each section's module and lists them in the order they render.
macro_rules! sections {
    ($($name:ident),* $(,)?) => {
        $(mod $name;)*

        const SECTIONS: &[fn(&Inputs) -> String] = &[$($name::rules),*];
    };
}

sections!(base, read, write, proxy);

/// Renders the profile `sandbox-exec -p` takes. A command under it reaches
/// the network only through the proxy on `proxy_port`, if there is one.
#[must_use]
pub fn render(config: &Config, proxy_port: Option<u16>) -> String {
    let inputs = Inputs { config, proxy_port };
    let mut profile = String::from("(version 1)\n");
    for rules in SECTIONS {
        profile.push_str(&rules(&inputs));
    }
    profile
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_profile_denies_network_and_write() {
        let profile = render(&Config::default(), None);

        assert!(profile.starts_with("(version 1)\n(deny default"));
        assert!(profile.contains("(allow file-read*)"));
        assert!(
            !profile.contains("(allow network"),
            "a default profile allows no network"
        );
        let writes: Vec<&str> = profile
            .lines()
            .filter(|line| line.starts_with("(allow file-write*"))
            .collect();
        assert!(!writes.is_empty(), "the standard devices stay writable");
        assert!(
            writes.iter().all(|line| line.contains("(literal \"/dev/")),
            "a default profile allows no write but to a device: {writes:?}"
        );
    }
}
