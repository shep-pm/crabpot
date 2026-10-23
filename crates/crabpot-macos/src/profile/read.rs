//! What a sandboxed command may read.

use crabpot_core::config::Config;
use crabpot_core::paths::{PathBase, PathError};

pub(super) fn rules(_config: &Config, _base: &PathBase) -> Result<String, PathError> {
    Ok("\n; Reads\n(allow file-read*)\n".to_owned())
}
