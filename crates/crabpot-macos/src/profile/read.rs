//! What a sandboxed command may read.

use super::Inputs;

pub(super) fn rules(_inputs: &Inputs) -> String {
    "\n; Reads\n(allow file-read*)\n".to_owned()
}
