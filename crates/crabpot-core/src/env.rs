//! The environment every sandboxed command gains, whatever the config says.
//!
//! The parts here are the ones macOS and Linux agree on. Each platform crate
//! puts them into its own command environment, beside the parts only that
//! platform has.

pub mod base;
pub mod git;
pub mod http;
pub mod socks;
