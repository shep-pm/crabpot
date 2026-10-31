//! The keys crabpot does not yet honour, which are refused when
//! they ask for something (ADR-0013).
//!
//! A key asks for something when its value is `true`, a number, a non-empty
//! string or list, or an object, so the empty lists upstream requires still
//! load. A key of the wrong type is invalid, as upstream's schema has it, and
//! [`check_shapes`] refuses it first, so a `false` where an object belongs is
//! never read as asking for nothing.
//!
//! The list covers upstream's schema at aceba124 (`src/sandbox/sandbox-config.ts`)
//! and crabpot-only keys. Each key leaves it on a platform when it is built.
//!
//! On Linux [`LINUX_PATHS`] joins it: the keys that tune the bwrap and seccomp
//! path upstream runs there, and crabpot's own does not read. On Windows
//! [`WINDOWS_IGNORED`] leaves it: the keys upstream's Windows path never reads.

use serde_json::Value;

use super::error::ConfigError;
#[cfg(not(target_os = "linux"))]
use super::keys::allow_tcp;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
use super::keys::publish;

/// Dotted paths, in the order they are checked.
pub(super) const PATHS: &[&str] = &[
    // Seatbelt cannot restrict a direct grant to the requested host.
    #[cfg(not(target_os = "linux"))]
    allow_tcp::PATH,
    // Local port publication is implemented by the macOS profile and the Linux
    // launcher's relay.
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    publish::PATH,
    // Upstream's keys that act on macOS, with what each does.
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
];

/// The keys of [`PATHS`] that upstream's Windows path never reads: the macOS
/// profile and the JVM agent are the only places they act. They are accepted and
/// ignored on Windows, and refused everywhere else.
///
/// `network.allowAllUnixSockets` is not here. Upstream ignores it on Windows
/// too, but ADR-0013 keeps it refused on every platform, so a config that lifts
/// the rule on macOS or Linux does not load on Windows with the rule unlifted.
pub(super) const WINDOWS_IGNORED: &[&str] = &["allowPty", "allowAppleEvents", "javaAgentJarPath"];

/// The keys of [`PATHS`] this build accepts and ignores.
pub(super) const fn ignored_here() -> &'static [&'static str] {
    if cfg!(windows) { WINDOWS_IGNORED } else { &[] }
}

/// Dotted paths only Linux refuses, since upstream applies each there and
/// ignores it on macOS.
///
/// `socatPath` and `ripgrep` are not here: crabpot runs neither tool
/// (ADR-0014), so a path to one asks for nothing.
#[cfg(target_os = "linux")]
pub(super) const LINUX_PATHS: &[&str] = &[
    // The bwrap binary to run.
    "bwrapPath",
    // The seccomp filter and helper to apply.
    "seccomp",
    // How deep the mandatory deny walk looks.
    "mandatoryDenySearchDepth",
    // Gives up the sandbox's own isolation so it can run inside a container.
    "enableWeakerNestedSandbox",
    // Lets the command create user namespaces.
    "allowNestedUserNamespaces",
];
#[cfg(not(target_os = "linux"))]
pub(super) const LINUX_PATHS: &[&str] = &[];

/// What type upstream's schema gives a key in [`PATHS`] that the typed read
/// does not cover.
#[derive(Clone, Copy)]
enum Shape {
    Bool,
    Number,
    Object,
    #[cfg(target_os = "linux")]
    String,
    Strings,
}

impl Shape {
    fn holds(self, value: &Value) -> bool {
        match self {
            Self::Bool => value.is_boolean(),
            Self::Number => value.is_number(),
            Self::Object => value.is_object(),
            #[cfg(target_os = "linux")]
            Self::String => value.is_string(),
            Self::Strings => value
                .as_array()
                .is_some_and(|items| items.iter().all(Value::is_string)),
        }
    }

    fn expected(self) -> &'static str {
        match self {
            Self::Bool => "expected a boolean",
            Self::Number => "expected a number",
            Self::Object => "expected an object",
            #[cfg(target_os = "linux")]
            Self::String => "expected a string",
            Self::Strings => "expected an array of strings",
        }
    }
}

/// The keys of [`PATHS`] whose type is checked here, a group before its keys.
const SHAPES: &[(&str, Shape)] = &[
    ("network.allowAllUnixSockets", Shape::Bool),
    ("network.httpProxyPort", Shape::Number),
    ("network.socksProxyPort", Shape::Number),
    ("network.stripResponseHeaders", Shape::Strings),
    ("network.refuseOpaqueTunnels", Shape::Bool),
    ("network.requireHostMatch", Shape::Bool),
    ("network.tlsTerminate", Shape::Object),
    ("network.parentProxy", Shape::Object),
    ("filesystem.disabled", Shape::Bool),
    ("credentials", Shape::Object),
    ("ignoreViolations", Shape::Object),
    ("allowPty", Shape::Bool),
    ("allowAppleEvents", Shape::Bool),
    ("git", Shape::Object),
    ("git.safeDirectories", Shape::Strings),
];

/// The keys of [`LINUX_PATHS`] whose type is checked here.
#[cfg(target_os = "linux")]
const LINUX_SHAPES: &[(&str, Shape)] = &[
    ("bwrapPath", Shape::String),
    ("seccomp", Shape::Object),
    ("mandatoryDenySearchDepth", Shape::Number),
    ("enableWeakerNestedSandbox", Shape::Bool),
    ("allowNestedUserNamespaces", Shape::Bool),
];
#[cfg(not(target_os = "linux"))]
const LINUX_SHAPES: &[(&str, Shape)] = &[];

/// Refuses `settings` when a key in [`SHAPES`] is there with the wrong type,
/// `null` included, since upstream's optional keys do not take it.
pub(super) fn check_shapes(settings: &Value) -> Result<(), ConfigError> {
    for &(key, shape) in SHAPES.iter().chain(LINUX_SHAPES) {
        if let Some(value) = key.split('.').try_fold(settings, |at, part| at.get(part))
            && !shape.holds(value)
        {
            return Err(ConfigError::Invalid {
                key: key.to_owned(),
                reason: shape.expected().to_owned(),
            });
        }
    }
    Ok(())
}

/// Refuses `settings` when a key in [`PATHS`], or on Linux in [`LINUX_PATHS`],
/// asks for something, and the key is not one this build ignores.
pub(super) fn refuse(settings: &Value) -> Result<(), ConfigError> {
    refuse_ignoring(settings, ignored_here())
}

/// [`refuse`], with the keys in `ignored` accepted whatever they ask.
pub(super) fn refuse_ignoring(settings: &Value, ignored: &[&str]) -> Result<(), ConfigError> {
    for &key in PATHS.iter().chain(LINUX_PATHS) {
        if !ignored.contains(&key)
            && key
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
