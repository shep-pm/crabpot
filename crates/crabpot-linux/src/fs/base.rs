//! What every sandbox has: the root read-only, no network, a fresh `/dev` and
//! `/proc`, and no process outliving its parent.
//!
//! Upstream's `generateFilesystemArgs` binds the root read-only first, and
//! `wrapCommandWithSandboxLinux` adds the namespaces and the two mounts. The
//! mounts follow the root bind, which would otherwise cover them.

use std::ffi::OsString;

use crabpot_core::PathError;
use crabpot_core::config::Config;

pub(super) fn words(_config: &Config) -> Result<Vec<OsString>, PathError> {
    Ok([
        "--ro-bind",
        "/",
        "/",
        "--unshare-net",
        "--die-with-parent",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
    ]
    .map(OsString::from)
    .into())
}
