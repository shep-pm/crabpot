//! What a sandboxed command may read.

use crabpot_core::config::Config;

pub(super) fn rules(_config: &Config) -> String {
    "\n; Reads\n(allow file-read*)\n".to_owned()
}
