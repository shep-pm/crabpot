//! What every sandbox has: the root read-only, no network, its own session and
//! process ids, a fresh `/dev` and `/proc`, and no process outliving its parent.
//!
//! Upstream's `generateFilesystemArgs` binds the root read-only first, and
//! `wrapCommandWithSandboxLinux` adds the namespaces and the two mounts. The
//! mounts follow the root bind, which would otherwise cover them, and `/proc`
//! follows `--unshare-pid`, since a proc mount of the host's pid namespace is
//! refused from a user namespace. `--new-session` takes the command off the
//! caller's terminal, which it could otherwise push keystrokes into.

use std::ffi::OsString;

use crabpot_core::PathError;
use crabpot_core::config::Config;

pub(super) fn words(_config: &Config) -> Result<Vec<OsString>, PathError> {
    Ok([
        "--ro-bind",
        "/",
        "/",
        "--new-session",
        "--unshare-net",
        "--die-with-parent",
        "--dev",
        "/dev",
        "--unshare-pid",
        "--proc",
        "/proc",
    ]
    .map(OsString::from)
    .into())
}
