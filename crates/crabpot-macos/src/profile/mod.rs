//! The seatbelt profile for one [`Config`].
//!
//! A profile is a list of sections, in order, since a later rule wins over an
//! earlier one. A section is a file in this folder with a `rules` function,
//! and it is registered by naming it in the `sections!` call.

use crabpot_core::config::Config;
use crabpot_core::paths::{PathBase, PathError};

/// Declares each section's module and lists them in the order they render.
macro_rules! sections {
    ($($name:ident),* $(,)?) => {
        $(mod $name;)*

        const SECTIONS: &[fn(&Config, &PathBase) -> Result<String, PathError>] =
            &[$($name::rules),*];
    };
}

sections!(base, read, allow_write);

mod filter;
mod write_roots;

/// Renders the profile `sandbox-exec -p` takes, with `HOME` and the working
/// directory of this process as what `~` and a relative path mean.
///
/// # Errors
///
/// [`PathError`] when the config or the defaults need a home directory or a
/// working directory and there is none.
pub fn render(config: &Config) -> Result<String, PathError> {
    render_with(config, &PathBase::from_env())
}

fn render_with(config: &Config, base: &PathBase) -> Result<String, PathError> {
    let mut profile = String::from("(version 1)\n");
    for rules in SECTIONS {
        profile.push_str(&rules(config, base)?);
    }
    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> PathBase {
        PathBase::new(
            Some("/crabpot-test-home/me".to_owned()),
            Some("/crabpot-test-work".to_owned()),
        )
    }

    #[test]
    fn the_default_profile_denies_network_and_write() {
        let profile = render_with(&Config::default(), &base()).unwrap();

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
                    r#"  (subpath "/crabpot-test-home/me/."#,
                ]
                .iter()
                .any(|allowed| filter.starts_with(allowed)),
                "a default profile allows no write but to the default roots: {filter}"
            );
        }
    }
}
