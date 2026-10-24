//! What every sandbox starts with: the root read-only, no network, its own
//! session, and no process outliving its parent.
//!
//! Upstream's `generateFilesystemArgs` binds the root read-only first, and
//! `wrapCommandWithSandboxLinux` adds the namespaces around it. The fresh
//! `/dev` and `/proc` are not here: they are the plan's last section,
//! [`private_mounts`](super::private_mounts). bwrap applies its mounts in the
//! order it reads them, and a write bind must not be able to cover them.
//! `--new-session` takes the command off the caller's terminal, which it could
//! otherwise push keystrokes into.

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
    ]
    .map(OsString::from)
    .into())
}
