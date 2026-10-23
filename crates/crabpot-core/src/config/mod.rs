//! The settings a sandbox starts from: upstream's settings schema (ADR-0004).
//!
//! A key upstream does not know is dropped, as upstream drops it. A key
//! upstream knows and crabpot does not yet apply is refused when it asks for
//! something, so a rule is never dropped without an error (ADR-0013). A key
//! upstream accepts and ignores on macOS is accepted and ignored.

mod error;
mod keys;
mod leaf;
mod unsupported;

#[cfg(test)]
mod tests;

use std::fs;
use std::io;
use std::path::Path;

use serde::{Deserialize, Deserializer};
use serde_json::Value;

pub use self::error::ConfigError;
pub use self::keys::denied_resolved_addresses::AddressRange;
pub use self::keys::mitm_proxy::MitmProxy;
pub use crate::domain::{DomainEntry, DomainParseError, DomainPattern};
pub use crate::path_entries::PathEntry;

use self::keys::{
    allow_mach_lookup, allow_read, allow_write, allowed_domains, denied_domains,
    denied_resolved_addresses, deny_read, deny_write, mitm_proxy,
};
use self::leaf::present;

/// The settings one sandbox runs under.
///
/// Deserializing one refuses what [`Config::from_json`] refuses.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", remote = "Self")]
#[non_exhaustive]
pub struct Config {
    /// What a command may reach.
    pub network: Network,
    /// What a command may read and write.
    pub filesystem: Filesystem,
    /// `enableWeakerNetworkIsolation`, which is not read yet.
    #[serde(default, deserialize_with = "present")]
    pub enable_weaker_network_isolation: Option<bool>,
}

/// `network`: what a command may reach.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Network {
    /// `allowedDomains`, which is not read yet.
    #[serde(deserialize_with = "allowed_domains::deserialize")]
    pub allowed_domains: Vec<DomainEntry>,
    /// `deniedDomains`, which is not read yet.
    #[serde(deserialize_with = "denied_domains::deserialize")]
    pub denied_domains: Vec<DomainEntry>,
    /// `strictAllowlist`: accepted, and nothing the settings file can reach reads it.
    #[serde(default, deserialize_with = "present")]
    pub strict_allowlist: Option<bool>,
    /// `deniedResolvedAddresses`, which is not read yet.
    #[serde(default, deserialize_with = "denied_resolved_addresses::deserialize")]
    pub denied_resolved_addresses: Option<Vec<AddressRange>>,
    /// `allowUnixSockets`, which is not read yet.
    #[serde(default, deserialize_with = "present")]
    pub allow_unix_sockets: Option<Vec<String>>,
    /// `allowLocalBinding`, which is not read yet.
    #[serde(default, deserialize_with = "present")]
    pub allow_local_binding: Option<bool>,
    /// `allowMachLookup`, which is not read yet.
    #[serde(default, deserialize_with = "allow_mach_lookup::deserialize")]
    pub allow_mach_lookup: Option<Vec<String>>,
    /// `denyMachLookup`, which is not read yet.
    #[serde(default, deserialize_with = "present")]
    pub deny_mach_lookup: Option<Vec<String>>,
    /// `mitmProxy`, which is not read yet.
    #[serde(default, deserialize_with = "present")]
    pub mitm_proxy: Option<MitmProxy>,
}

/// `filesystem`: what a command may read and write.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Filesystem {
    /// `denyRead`, which is not read yet.
    #[serde(deserialize_with = "deny_read::deserialize")]
    pub deny_read: Vec<PathEntry>,
    /// `allowRead`, which is not read yet.
    #[serde(default, deserialize_with = "allow_read::deserialize")]
    pub allow_read: Option<Vec<PathEntry>>,
    /// `allowWrite`: paths a command may write, beside the default write roots.
    #[serde(deserialize_with = "allow_write::deserialize")]
    pub allow_write: Vec<PathEntry>,
    /// `denyWrite`, which is not read yet.
    #[serde(deserialize_with = "deny_write::deserialize")]
    pub deny_write: Vec<PathEntry>,
}

impl Config {
    /// Reads a settings file's text.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Invalid`] when `json` is not a settings object, a
    /// required key is missing, or a value is wrong in the way upstream's
    /// schema refuses, and [`ConfigError::Unsupported`] when a key asks for
    /// something crabpot does not apply yet.
    pub fn from_json(json: &str) -> Result<Self, ConfigError> {
        let settings = serde_json::from_str(json).map_err(|e| ConfigError::Invalid {
            key: String::new(),
            reason: format!("not valid JSON: {e}"),
        })?;
        Self::from_value(&settings)
    }

    /// Reads the settings file at `path`.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Missing`] when there is no file, [`ConfigError::Empty`]
    /// when it holds only whitespace, [`ConfigError::Unreadable`] when it
    /// cannot be read, and what [`Config::from_json`] returns for its text.
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        match fs::read_to_string(path) {
            Ok(text) if text.trim().is_empty() => Err(ConfigError::Empty),
            Ok(text) => Self::from_json(&text),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Err(ConfigError::Missing),
            Err(e) => Err(ConfigError::Unreadable {
                reason: e.to_string(),
            }),
        }
    }

    fn from_value(settings: &Value) -> Result<Self, ConfigError> {
        require_objects(settings)?;
        let Shape(config) = serde_path_to_error::deserialize(settings).map_err(|e| invalid(&e))?;
        unsupported::check_shapes(settings)?;
        unsupported::refuse(settings)?;
        Ok(config)
    }
}

/// The groups of keys, which serde would otherwise read from a list, field by
/// field in order.
fn require_objects(settings: &Value) -> Result<(), ConfigError> {
    for key in ["", "network", "filesystem", mitm_proxy::PATH] {
        let value = key
            .split('.')
            .filter(|part| !part.is_empty())
            .try_fold(settings, |at, part| at.get(part));
        if value.is_some_and(|value| !value.is_object()) {
            return Err(ConfigError::Invalid {
                key: key.to_owned(),
                reason: "expected an object".to_owned(),
            });
        }
    }
    Ok(())
}

/// The key path and the reason of a failed read, with a missing key named in
/// the path as upstream's does.
fn invalid(error: &serde_path_to_error::Error<serde_json::Error>) -> ConfigError {
    use serde_path_to_error::Segment;

    let mut key: Vec<String> = error
        .path()
        .iter()
        .map(|segment| match segment {
            Segment::Seq { index } => index.to_string(),
            Segment::Map { key } | Segment::Enum { variant: key } => key.clone(),
            Segment::Unknown => "?".to_owned(),
        })
        .collect();
    let message = error.inner().to_string();
    let reason = match message.strip_prefix("missing field `") {
        Some(rest) => {
            let (field, _) = rest.split_once('`').unwrap_or((rest, ""));
            key.push(field.to_owned());
            "required".to_owned()
        }
        None => message,
    };
    ConfigError::Invalid {
        key: key.join("."),
        reason,
    }
}

/// A [`Config`] read by its fields alone, which tracks the path of a wrong key.
struct Shape(Config);

impl<'de> Deserialize<'de> for Shape {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // The derive's own function, since the trait's runs `from_value`.
        Config::deserialize(deserializer).map(Self)
    }
}

impl<'de> Deserialize<'de> for Config {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let settings = Value::deserialize(deserializer)?;
        Self::from_value(&settings).map_err(serde::de::Error::custom)
    }
}
