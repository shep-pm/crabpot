//! What a sandboxed command may write.

use crabpot_core::PathError;
use crabpot_core::config::Config;

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

pub(super) fn rules(_config: &Config) -> Result<String, PathError> {
    let mut rules = String::from("\n; Writes\n");
    for device in DEVICES {
        rules.push_str(&format!("(allow file-write* (literal \"{device}\"))\n"));
    }
    Ok(rules)
}
