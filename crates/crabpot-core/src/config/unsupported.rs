//! The keys upstream applies and crabpot does not yet, which are refused when
//! they ask for something (ADR-0013).
//!
//! A key asks for something when its value is `true`, a number, a non-empty
//! string or list, or an object, so the empty lists upstream requires still
//! load. A key that is not an object where it should be is wrong, and the
//! typed read has refused it before this runs.
//!
//! The list is upstream's schema at aceba124 (`src/sandbox/sandbox-config.ts`)
//! less what upstream applies nowhere on macOS. Each key leaves it when it is
//! built, and none is left at parity.

use serde_json::Value;

use super::error::ConfigError;
use super::keys::{
    allow_local_binding, allow_mach_lookup, allow_read, allow_unix_sockets, allow_write,
    allowed_domains, denied_domains, denied_resolved_addresses, deny_mach_lookup, deny_read,
    deny_write, enable_weaker_network_isolation, mitm_proxy,
};

/// Dotted paths, in the order they are checked.
pub(super) const PATHS: &[&str] = &[
    // The kelpie keys, each refused until its slice builds it.
    allowed_domains::PATH,
    denied_domains::PATH,
    allow_unix_sockets::PATH,
    allow_mach_lookup::PATH,
    deny_mach_lookup::PATH,
    allow_local_binding::PATH,
    enable_weaker_network_isolation::PATH,
    denied_resolved_addresses::PATH,
    mitm_proxy::PATH,
    deny_read::PATH,
    allow_read::PATH,
    allow_write::PATH,
    deny_write::PATH,
    // Upstream's other keys that act on macOS, with what each does.
    // Lets a command use every Unix socket.
    "network.allowAllUnixSockets",
    // Replace the HTTP and SOCKS proxy upstream would start.
    "network.httpProxyPort",
    "network.socksProxyPort",
    // The reason the proxy gives for refusing a denied domain.
    "network.deniedDomainReasons",
    // Proxy behaviour: headers dropped from responses, tunnels it cannot see
    // into, and a Host header that must name the host dialed.
    "network.stripResponseHeaders",
    "network.refuseOpaqueTunnels",
    "network.requireHostMatch",
    // The proxy terminates TLS, and any object turns it on.
    "network.tlsTerminate",
    // The proxy dials through another proxy.
    "network.parentProxy",
    // Drops every filesystem rule and the mandatory write denies.
    "filesystem.disabled",
    // Lets a command write `.git/config`.
    "filesystem.allowGitConfig",
    // Files and variables masked or denied, and the proxy that swaps them.
    "credentials",
    // Violations the sandbox log reports that are left out.
    "ignoreViolations",
    // Lets a command use pseudo-terminals.
    "allowPty",
    // Lets a command send Apple Events and open other applications.
    "allowAppleEvents",
    // The JVM agent that points Java at the proxy, which ADR-0008 leaves to
    // upstream's own jar.
    "javaAgentJarPath",
    // Directories git is told are safe through `GIT_CONFIG_*`.
    "git.safeDirectories",
];

/// Refuses `settings` when a key in [`PATHS`] asks for something.
pub(super) fn refuse(settings: &Value) -> Result<(), ConfigError> {
    for &key in PATHS {
        if key
            .split('.')
            .try_fold(settings, |at, part| at.get(part))
            .is_some_and(asks)
        {
            return Err(ConfigError::Unsupported { key });
        }
    }
    Ok(())
}

fn asks(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(set) => *set,
        Value::Number(_) | Value::Object(_) => true,
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
    }
}
