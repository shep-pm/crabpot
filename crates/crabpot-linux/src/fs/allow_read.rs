//! What `filesystem.allowRead` re-opens inside what `denyRead` hides.
//!
//! Upstream's `reExposedBy` and `expandAllowReadGlob`: a read-only bind of the
//! host path follows the mount that hid it, since bwrap applies its mounts in
//! the order it reads them. A path no deny hides is already readable through
//! the root bind, so it adds no word.

use std::collections::BTreeSet;
use std::ffi::OsString;

use crabpot_core::PathError;
use crabpot_core::config::Config;

use super::deny_read::{locate, located};
use super::glob_walk;

pub(super) fn words(config: &Config) -> Result<Vec<OsString>, PathError> {
    let hidden = located(config)?;
    let mut reopened = BTreeSet::new();
    for entry in config.filesystem.read_allows()? {
        for path in glob_walk::matches(&entry) {
            if let Some((path, _is_dir)) = locate(path)
                && hidden.keys().any(|deny| path.starts_with(deny))
            {
                reopened.insert(path);
            }
        }
    }
    Ok(reopened
        .into_iter()
        .flat_map(|path| {
            let word = path.into_os_string();
            ["--ro-bind".into(), word.clone(), word]
        })
        .collect())
}
