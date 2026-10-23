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
pub mod proxy;
#[cfg(all(test, unix))]
mod test_tree;
