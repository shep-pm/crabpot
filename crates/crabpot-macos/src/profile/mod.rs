//! The seatbelt profile for one [`Config`].
//!
//! A profile is a list of sections, in order, since a later rule wins over an
//! earlier one. A section is a file in this folder with a `rules` function,
//! and it is registered by naming it in the `sections!` call.

use crabpot_core::PathError;
use crabpot_core::config::Config;

mod rule;

/// Declares each section's module and lists them in the order they render.
macro_rules! sections {
    ($($name:ident),* $(,)?) => {
        $(mod $name;)*

        const SECTIONS: &[fn(&Config) -> Result<String, PathError>] = &[$($name::rules),*];
    };
}

sections!(base, read, deny_read, write);

/// Renders the profile `sandbox-exec -p` takes.
///
/// # Errors
///
/// [`PathError`] when a path in `config` starts with `~` and `HOME` is not set,
/// or is relative and there is no working directory. A rule written for it
/// would be dropped, so there is no profile.
pub fn render(config: &Config) -> Result<String, PathError> {
    let mut profile = String::from("(version 1)\n");
    for rules in SECTIONS {
        profile.push_str(&rules(config)?);
    }
    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_profile_denies_network_and_write() {
        let profile = render(&Config::default()).unwrap();

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
