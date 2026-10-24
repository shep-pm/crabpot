//! The sandbox's own mounts: a fresh `/dev`, its own pid namespace, and a
//! fresh `/proc`.
//!
//! Upstream's `wrapCommandWithSandboxLinux` adds these after every filesystem
//! argument it has built, with the comment "IMPORTANT: These must come AFTER
//! filesystem binds for nested bwrap to work". bwrap applies its mounts in the
//! order it reads them, so last is what keeps them the sandbox's own: a write
//! bind of the whole root, or of `/dev` or `/proc`, is covered by the mount
//! here instead of covering it. A config that names one of them gets the
//! sandbox's tree, never the host's processes or devices behind it.
//!
//! `/proc` follows `--unshare-pid`, since a proc mount of the host's pid
//! namespace is refused from a user namespace.

use std::ffi::OsString;

use crabpot_core::config::Config;
use crabpot_core::paths::PathBase;

use super::{Draft, PlanError};

pub(super) fn words(
    _config: &Config,
    _base: &PathBase,
    _draft: &mut Draft,
) -> Result<Vec<OsString>, PlanError> {
    Ok([
        "--dev",
        "/dev",
        "--unshare-pid",
        "--proc",
        "/proc",
    ]
    .map(OsString::from)
    .into())
}
