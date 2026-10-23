//! The platform-independent half of crabpot: config, globs, path entries and proxies.

mod glob;
mod path;
mod path_entries;
#[cfg(all(test, unix))]
mod test_tree;
