//! The path and glob rules the platform crates build their profiles from.
//!
//! Public so `crabpot-macos` can reach them (ADR-0012). Nothing else should
//! depend on this module: it follows what a platform crate needs.

pub use crate::glob::{deny_glob_matches, deny_glob_regex, escape_regex_literal, glob_to_regex};
pub use crate::path::{
    PathBase, contains_glob_chars, dirname, is_at_or_under, normalize_path_for_sandbox,
    remove_trailing_glob_suffix,
};
pub use crate::path_entries::{
    ListKind, PathReading, ReadRules, SplitEntries, literal_readings, read_rules_of,
    split_path_entries,
};
