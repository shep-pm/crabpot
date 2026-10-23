//! The platform-independent half of crabpot: config, globs, path entries and proxies.

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "slice 25 wires the address rules into the proxy")
)]
mod address;
pub mod config;
mod domain;
mod glob;
mod path;
mod path_entries;
pub mod paths;
pub mod proxy;
mod resolved_path;
#[cfg(all(test, unix))]
mod test_tree;

pub use path::PathError;
pub use resolved_path::ResolvedPath;
