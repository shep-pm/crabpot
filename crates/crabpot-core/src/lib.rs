//! The platform-independent half of crabpot: config, globs, path entries and proxies.

pub mod config;
mod domain;
mod glob;
mod path;
mod path_entries;
#[cfg(all(test, unix))]
mod test_tree;
