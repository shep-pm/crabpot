//! Why a settings file was refused.

use core::fmt;

/// Why a settings file was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
// A key crabpot learns to honour, or a failure of the reader, adds a variant
// without breaking a caller's `match`.
#[non_exhaustive]
pub enum ConfigError {
    /// The text is not JSON, or the value at `key` is wrong: missing, of the
    /// wrong type, or refused by the setting's validation rules.
    Invalid {
        /// The dotted path of the key, such as `network.allowedDomains.0`,
        /// which is empty when the text as a whole is wrong.
        key: String,
        /// What is wrong with it.
        reason: String,
    },
    /// A key asks for something crabpot does not apply on this platform yet.
    /// Running anyway would drop the rule.
    Unsupported {
        /// The dotted path of the key, as written in a settings file.
        key: &'static str,
    },
    /// There is no file.
    Missing,
    /// The file holds nothing but whitespace.
    Empty,
    /// The file is there and cannot be read.
    Unreadable {
        /// The operating system's account of why.
        reason: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid { key, reason } if key.is_empty() => {
                write!(f, "invalid settings: {reason}")
            }
            Self::Invalid { key, reason } => write!(f, "invalid settings: {key}: {reason}"),
            Self::Unsupported { key } => {
                write!(f, "settings key `{key}` is not supported yet")
            }
            Self::Missing => f.write_str("does not exist"),
            Self::Empty => f.write_str("is empty: delete it, or put settings in it"),
            Self::Unreadable { reason } => write!(f, "cannot be read: {reason}"),
        }
    }
}

impl core::error::Error for ConfigError {}
