//! Native Rust sandbox runtime for AI agents, rewritten from Anthropic's sandbox-runtime.

mod args;
mod run;
mod sandbox;
mod windows;

#[cfg(all(test, windows))]
mod test;

pub use crabpot_core::config::{Config, ConfigError};
pub use run::{run_args, run_from_args};
pub use sandbox::{ProfileConflict, Sandbox, StartError, WrapError};
pub use windows::{
    LoopbackMode, PROFILE_READ_ENV_VARS, ProfileExclusions, ProfileState, SetupVersion, UserState,
    WindowsStatus, refusal_for_exit, windows_preflight, windows_preflight_for, windows_status,
    windows_status_for,
};
