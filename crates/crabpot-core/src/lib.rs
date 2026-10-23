//! The platform-independent half of crabpot: config, globs, path entries and proxies.

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
