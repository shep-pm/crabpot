//! What a sandboxed command may write.

use super::Inputs;

/// The devices every command writes to. Nothing else is writable until a
/// config names a write root.
const DEVICES: &[&str] = &[
    "/dev/stdout",
    "/dev/stderr",
    "/dev/null",
    "/dev/tty",
    "/dev/dtracehelper",
    "/dev/autofs_nowait",
];

pub(super) fn rules(_inputs: &Inputs) -> String {
    let mut rules = String::from("\n; Writes\n");
    for device in DEVICES {
        rules.push_str(&format!("(allow file-write* (literal \"{device}\"))\n"));
    }
    rules
}
