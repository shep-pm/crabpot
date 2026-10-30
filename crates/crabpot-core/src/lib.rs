//! The platform-independent half of crabpot: config, globs, path entries and proxies.

mod address;
pub mod config;
pub mod dangerous;
mod domain;
pub mod env;
mod glob;
mod path;
mod path_entries;
pub mod paths;
pub mod proxy;
mod resolved_path;
#[cfg(all(test, unix))]
mod test_tree;
#[cfg(unix)]
pub mod tmpdir;
#[cfg(unix)]
mod unix_socket;
mod write_paths;
// The crate's Windows FFI, which is the one module allowed unsafe code there.
#[cfg(windows)]
#[allow(unsafe_code)]
mod win32;

pub use path::PathError;
pub use resolved_path::ResolvedPath;
