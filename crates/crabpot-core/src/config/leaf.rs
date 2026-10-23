//! What the key modules share to read a leaf of upstream's schema.

use core::fmt;

use serde::de::{DeserializeSeed, Error as _, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

use crate::path::{contains_glob_chars, is_absolute};
use crate::path_entries::PathEntry;

/// A key that may be left out but not set to `null`, as upstream's `.optional()`.
pub(super) fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// A string read by `parse`.
pub(super) fn parsed<'de, D, T, E>(
    deserializer: D,
    parse: fn(&str) -> Result<T, E>,
) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    E: fmt::Display,
{
    let text = String::deserialize(deserializer)?;
    parse(&text).map_err(D::Error::custom)
}

/// A list of strings, each one read by `parse`. The index of a bad entry is
/// part of the error's key path.
pub(super) fn parsed_list<'de, D, T, E>(
    deserializer: D,
    parse: fn(&str) -> Result<T, E>,
) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    E: fmt::Display,
{
    struct Each<T, E>(fn(&str) -> Result<T, E>);

    impl<'de, T, E: fmt::Display> DeserializeSeed<'de> for Each<T, E> {
        type Value = T;

        fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<T, D::Error> {
            parsed(deserializer, self.0)
        }
    }

    struct List<T, E>(fn(&str) -> Result<T, E>);

    impl<'de, T, E: fmt::Display> Visitor<'de> for List<T, E> {
        type Value = Vec<T>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a list of strings")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<T>, A::Error> {
            let mut entries = Vec::new();
            while let Some(entry) = seq.next_element_seed(Each(self.0))? {
                entries.push(entry);
            }
            Ok(entries)
        }
    }

    deserializer.deserialize_seq(List(parse))
}

/// A string that is not empty.
pub(super) fn non_empty(text: &str) -> Result<String, &'static str> {
    if text.is_empty() {
        Err("must not be empty")
    } else {
        Ok(text.to_owned())
    }
}

const PATH_ENTRY_EXPECTED: &str = "a path, or { \"path\": \"<path>\", \"literal\": true }";

/// What an entry of a path list is written as, before its parts are checked.
#[derive(Deserialize)]
#[serde(
    untagged,
    expecting = "a path, or { \"path\": \"<path>\", \"literal\": true }"
)]
enum Written {
    Spelled(String),
    Marked(Marked),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Marked {
    path: String,
    literal: bool,
}

impl<'de> Deserialize<'de> for PathEntry {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match Written::deserialize(deserializer)? {
            Written::Spelled(spelling) if spelling.is_empty() => {
                Err(D::Error::custom("path cannot be empty"))
            }
            Written::Spelled(spelling) => Ok(Self::Spelled(spelling)),
            Written::Marked(Marked {
                path,
                literal: true,
            }) if !path.is_empty() => Ok(Self::Literal(path)),
            Written::Marked(_) => Err(D::Error::custom(format_args!(
                "expected {PATH_ENTRY_EXPECTED}"
            ))),
        }
    }
}

/// A list of path entries.
pub(super) fn path_list<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<PathEntry>, D::Error> {
    Vec::deserialize(deserializer)
}

/// A path entry of a deny list: one a trailing separator leaves matching
/// nothing is refused, since a deny that matches nothing fails open.
struct DenyEntry(PathEntry);

impl<'de> Deserialize<'de> for DenyEntry {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let entry = PathEntry::deserialize(deserializer)?;
        if let PathEntry::Spelled(spelling) = &entry
            && spelling.ends_with('/')
            && contains_glob_chars(spelling)
            && (is_absolute(spelling) || spelling.starts_with('~'))
        {
            let trimmed = spelling.trim_end_matches('/');
            return Err(D::Error::custom(format_args!(
                "deny glob \"{spelling}\" ends in a separator, so as a pattern it can match no \
                 path. Write \"{trimmed}\", which is also read as the path of that name where \
                 it exists, or add a \"**\" segment to match at any depth"
            )));
        }
        Ok(Self(entry))
    }
}

/// A list of path entries for `denyRead` or `denyWrite`.
pub(super) fn deny_list<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<PathEntry>, D::Error> {
    let entries: Vec<DenyEntry> = Vec::deserialize(deserializer)?;
    Ok(entries.into_iter().map(|DenyEntry(entry)| entry).collect())
}
