//! The filesystem part of a bwrap invocation: the words that build the
//! sandbox's mounts and namespaces for one [`Config`].
//!
//! A plan is a list of sections, in order, since bwrap applies its mounts in
//! the order it reads them and a later one covers an earlier one. A section is
//! a file in this folder with a `words` function, and it is registered by
//! naming it in the `sections!` call. The sandbox's own mounts are the last
//! section, and any section that binds a path belongs before them.
//!
//! A section hands what a later one needs through the `Draft` it is given.
//! The ancestor pins are the one part that is no section: they are spliced
//! into the words once every section has said which paths it protects (see the
//! `pins` module).

use std::ffi::OsString;

use std::path::PathBuf;

use crabpot_core::PathError;
use crabpot_core::config::Config;

mod glob_walk;
mod mount_points;
mod pins;

pub use mount_points::MountPoints;

/// Declares each section's module and lists them in the order they render.
macro_rules! sections {
    ($($name:ident),* $(,)?) => {
        $(mod $name;)*

        const SECTIONS: &[fn(&Config, &mut Draft) -> Result<Vec<OsString>, PathError>] =
            &[$($name::words),*];
    };
}

sections!(base, allow_write, deny_read, deny_write, private_mounts);

/// What the sections of one plan tell each other.
#[derive(Debug, Default)]
struct Draft {
    /// Where the section being built starts in the plan's words.
    offset: usize,
    /// Where the ancestor pins are spliced in: set by `allow_write`.
    pin_at: usize,
    /// The paths bound writable, canonical and without a trailing slash.
    write_roots: Vec<String>,
    /// What `denyRead` mounts over, set by `deny_read`.
    read_mounts: Vec<deny_read::Mount>,
    /// The paths whose protection the pins keep from being moved away: where a
    /// deny bind or a read mount lands.
    protected: Vec<String>,
    /// The host paths bwrap makes as mount points for the plan.
    mount_points: MountPoints,
}

/// The fixture tree the cases build their paths on needs `symlink`, so the
/// cases sit with the unix tests.
#[cfg(all(test, unix))]
mod tests;

/// The words a config's filesystem policy comes to, in the order bwrap reads
/// them.
///
/// Dropping the plan removes the mount points bwrap made on the host for it,
/// so keep it for as long as a command may run under its words.
#[derive(Debug)]
pub struct Plan {
    words: Vec<OsString>,
    mount_points: MountPoints,
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
        let mut draft = Draft::default();
        for section in SECTIONS {
            draft.offset = words.len();
            words.extend(section(config, &mut draft)?);
        }
        let pins = pins::words(&draft);
        words.splice(draft.pin_at..draft.pin_at, pins);
        Ok(Self {
            words,
            mount_points: draft.mount_points,
        })
    }

    /// The words, to follow `bwrap` itself.
    #[must_use]
    pub fn words(&self) -> &[OsString] {
        &self.words
    }

    /// The host paths bwrap makes as mount points for the plan's denies, which
    /// the plan removes when it drops.
    #[must_use]
    pub fn mount_points(&self) -> &[PathBuf] {
        self.mount_points.paths()
    }

    /// Hands the mount points over, so they outlive the plan's words and are
    /// removed when the returned value drops.
    #[must_use]
    pub fn into_parts(self) -> (Vec<OsString>, MountPoints) {
        (self.words, self.mount_points)
    }
}
