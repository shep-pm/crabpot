//! What a sandboxed command may read.

use crabpot_core::PathError;
use crabpot_core::config::Config;

pub(super) fn rules(_config: &Config) -> Result<String, PathError> {
    Ok("\n; Reads\n(allow file-read*)\n".to_owned())
}
