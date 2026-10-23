//! The seatbelt profile for one [`Config`] and the proxy it reaches the network through.
//!
//! A profile is a list of sections, in order, since a later rule wins over an
//! earlier one. A section is a file in this folder with a `rules` function,
//! and it is registered by naming it in the `sections!` call.

use crabpot_core::PathError;
use crabpot_core::config::Config;

mod filter;
mod proxy;
mod rule;
mod write_roots;

/// Declares each section's module and lists them in the order they render.
macro_rules! sections {
    ($($name:ident),* $(,)?) => {
        $(mod $name;)*

        const SECTIONS: &[fn(&Config) -> Result<String, PathError>] = &[$($name::rules),*];
    };
}

sections!(
    base,
    mach_lookup,
    read,
    deny_read,
    allow_read,
    allow_write,
    deny_write,
    unix_sockets
);

/// Renders the profile `sandbox-exec` takes. A command under it reaches the
/// network only through the proxy on `proxy_port`, if there is one, and only
/// the Unix sockets `allowUnixSockets` names.
///
/// # Errors
///
/// [`PathError`] when a path in `config` starts with `~` and `HOME` is not set,
/// or is relative and there is no working directory. A rule written for it
/// would be dropped, so there is no profile.
pub fn render(config: &Config, proxy_port: Option<u16>) -> Result<String, PathError> {
    let mut profile = String::from(
        "(version 1)
",
    );
    for rules in SECTIONS {
        profile.push_str(&rules(config)?);
    }
    profile.push_str(&proxy::rules(proxy_port));
    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_profile_denies_network_and_write() {
        let profile = render(&Config::default(), None).unwrap();

        assert!(profile.starts_with("(version 1)\n(deny default"));
        assert!(profile.contains("(allow file-read*)"));
        assert!(
            !profile.contains("(allow network"),
            "a default profile allows no network"
        );
        let filters: Vec<&str> = profile
            .lines()
            .skip_while(|line| *line != "(allow file-write*")
            .skip(1)
            .take_while(|line| !line.starts_with("  (with message"))
            .collect();
        assert!(!filters.is_empty(), "the default roots stay writable");
        for filter in filters {
            assert!(
                [
                    r#"  (subpath "/dev/"#,
                    r#"  (subpath "/tmp/claude""#,
                    r#"  (subpath "/private/tmp/claude""#,
                    r#"/.npm/_logs")"#,
                    r#"/.claude/debug")"#,
                ]
                .iter()
                .any(|allowed| filter.starts_with(allowed) || filter.ends_with(allowed)),
                "a default profile allows no write but to the default roots: {filter}"
            );
        }
    }
}
