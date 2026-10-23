//! The filesystem part of a bwrap invocation: the words that build the
//! sandbox's mounts and namespaces for one [`Config`].
//!
//! A plan is a list of sections, in order, since bwrap applies its mounts in the
//! order it reads them and a later one covers an earlier one. A section is a
//! file in this folder with a `words` function, and it is registered by naming
//! it in the `sections!` call.

use std::ffi::OsString;

use crabpot_core::PathError;
use crabpot_core::config::Config;

mod glob_walk;

/// Declares each section's module and lists them in the order they render.
macro_rules! sections {
    ($($name:ident),* $(,)?) => {
        $(mod $name;)*

        const SECTIONS: &[fn(&Config) -> Result<Vec<OsString>, PathError>] = &[$($name::words),*];
    };
}

sections!(base, deny_read, allow_read);

/// The words a config's filesystem policy comes to, in the order bwrap reads
/// them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    words: Vec<OsString>,
}

impl Plan {
    /// Builds the plan for `config`.
    ///
    /// # Errors
    ///
    /// [`PathError`] when a path in `config` starts with `~` and `HOME` is not
    /// set, or is relative and there is no working directory. A mount written for
    /// it would be dropped, so there is no plan.
    pub fn build(config: &Config) -> Result<Self, PathError> {
        let mut words = Vec::new();
        for section in SECTIONS {
            words.extend(section(config)?);
        }
        Ok(Self { words })
    }

    /// The words, to follow `bwrap` itself.
    #[must_use]
    pub fn words(&self) -> &[OsString] {
        &self.words
    }
}

#[cfg(test)]
mod tests;
