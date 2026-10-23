//! A case: the files, settings and probes one differential run is made of.

use std::path::PathBuf;

use serde_json::Value;

/// One action to run inside the sandbox, as the `probe` binary spells it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    /// Open the path for reading.
    Read(String),
    /// Open the path for writing, creating it.
    Write(String),
    /// Connect to the host and port.
    Connect {
        /// The host to dial.
        host: String,
        /// The port to dial.
        port: u16,
        /// The proxy to ask for the connection, if not the HTTP proxy.
        via: Option<Via>,
    },
    /// Bind a loopback socket.
    Bind,
}

/// A proxy other than the HTTP one that a `connect` probe goes through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    /// The SOCKS5 proxy.
    Socks5,
}

/// A case file, with `$ROOT` expanded.
#[derive(Debug, Clone, PartialEq)]
pub struct Case {
    /// Files to create before the probes run, with their contents.
    pub files: Vec<(PathBuf, String)>,
    /// The settings file, in upstream's schema. A string is the file's text
    /// as written, so a case can hold a file that is not JSON or is empty,
    /// and `null` is no file.
    pub settings: Value,
    /// Whether both runners refuse the settings: each wrapper exits 1 before
    /// the probe runs.
    pub refused: bool,
    /// The probes, in order.
    pub probes: Vec<Probe>,
}

/// Why a case file is not a case.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The text is not JSON.
    Json(String),
    /// A field is missing or is not the kind of value it should be.
    Shape(String),
    /// A probe's `kind` is not `read`, `write`, `connect` or `bind`.
    UnknownProbe(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Json(reason) => write!(f, "the case is not JSON: {reason}"),
            Self::Shape(what) => write!(f, "the case has {what}"),
            Self::UnknownProbe(kind) => write!(f, "the case has an unknown probe kind {kind:?}"),
        }
    }
}

impl core::error::Error for Error {}

impl Case {
    /// Reads a case file's text, replacing `$ROOT` with `root` wherever it
    /// appears in a string or a key. A file's path that stays relative is under `root`.
    ///
    /// # Errors
    ///
    /// [`Error::Json`] when `text` is not JSON, [`Error::Shape`] when `files`,
    /// `settings` or `probes` is missing or has the wrong type, as is a `refused`
    /// that is not a boolean, and
    /// [`Error::UnknownProbe`] when a probe's `kind` is not one this harness knows.
    pub fn parse(text: &str, root: &str) -> Result<Self, Error> {
        let parsed: Value = serde_json::from_str(text).map_err(|e| Error::Json(e.to_string()))?;
        let Value::Object(mut case) = expand(parsed, root) else {
            return Err(Error::Shape("a top level that is not an object".to_owned()));
        };
        let mut take = |field: &str| {
            case.remove(field)
                .ok_or_else(|| Error::Shape(format!("no `{field}`")))
        };
        let files = match take("files")? {
            Value::Object(files) => files
                .into_iter()
                .map(|(path, contents)| match contents {
                    Value::String(contents) => {
                        Ok((std::path::Path::new(root).join(path), contents))
                    }
                    _ => Err(Error::Shape(format!(
                        "a file {path:?} whose contents are not a string"
                    ))),
                })
                .collect::<Result<_, _>>()?,
            _ => return Err(Error::Shape("a `files` that is not an object".to_owned())),
        };
        let settings = take("settings")?;
        let refused = match take("refused") {
            Err(_) => false,
            Ok(Value::Bool(refused)) => refused,
            Ok(_) => return Err(Error::Shape("a `refused` that is not a boolean".to_owned())),
        };
        let probes = match take("probes")? {
            Value::Array(probes) => probes
                .iter()
                .map(Probe::from_value)
                .collect::<Result<_, _>>()?,
            _ => return Err(Error::Shape("a `probes` that is not an array".to_owned())),
        };
        Ok(Self {
            files,
            settings,
            refused,
            probes,
        })
    }
}

/// `value` with `$ROOT` replaced in every string and key.
fn expand(value: Value, root: &str) -> Value {
    match value {
        Value::String(text) => Value::String(text.replace("$ROOT", root)),
        Value::Array(items) => {
            Value::Array(items.into_iter().map(|item| expand(item, root)).collect())
        }
        Value::Object(members) => Value::Object(
            members
                .into_iter()
                .map(|(key, member)| (key.replace("$ROOT", root), expand(member, root)))
                .collect(),
        ),
        other => other,
    }
}

impl Probe {
    /// The words after `probe` that run this probe.
    pub fn args(&self) -> Vec<String> {
        match self {
            Self::Read(path) => vec!["read".to_owned(), path.clone()],
            Self::Write(path) => vec!["write".to_owned(), path.clone()],
            Self::Connect { host, port, via } => {
                let mut args = vec!["connect".to_owned(), host.clone(), port.to_string()];
                if let Some(Via::Socks5) = via {
                    args.extend(["--via".to_owned(), "socks5".to_owned()]);
                }
                args
            }
            Self::Bind => vec!["bind".to_owned()],
        }
    }

    fn from_value(value: &Value) -> Result<Self, Error> {
        let field = |name: &str| value.get(name);
        let text = |name: &str| {
            field(name)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| Error::Shape(format!("a probe without a string `{name}`")))
        };
        let kind = text("kind")?;
        match kind.as_str() {
            "read" => Ok(Self::Read(text("path")?)),
            "write" => Ok(Self::Write(text("path")?)),
            "connect" => Ok(Self::Connect {
                host: text("host")?,
                port: field("port")
                    .and_then(Value::as_u64)
                    .and_then(|port| u16::try_from(port).ok())
                    .ok_or_else(|| {
                        Error::Shape("a probe without a `port` that fits 16 bits".to_owned())
                    })?,
                via: match field("via") {
                    None => None,
                    Some(Value::String(via)) if via == "socks5" => Some(Via::Socks5),
                    Some(_) => {
                        return Err(Error::Shape(
                            "a probe with a `via` that is not \"socks5\"".to_owned(),
                        ));
                    }
                },
            }),
            "bind" => Ok(Self::Bind),
            _ => Err(Error::UnknownProbe(kind)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_case_file_parses_and_expands_root() {
        let text = r#"{
            "files": {"$ROOT/in": "hello"},
            "settings": {"filesystem": {"allowWrite": ["$ROOT/out"]}},
            "probes": [
                {"kind": "read", "path": "$ROOT/in"},
                {"kind": "write", "path": "$ROOT/out"},
                {"kind": "connect", "host": "example.com", "port": 443},
                {"kind": "connect", "host": "example.com", "port": 443, "via": "socks5"},
                {"kind": "bind"}
            ]
        }"#;
        let case = Case::parse(text, "/r").unwrap();
        assert_eq!(case.files, [(PathBuf::from("/r/in"), "hello".to_owned())]);
        assert_eq!(
            case.settings,
            json!({"filesystem": {"allowWrite": ["/r/out"]}})
        );
        assert_eq!(
            case.probes,
            [
                Probe::Read("/r/in".to_owned()),
                Probe::Write("/r/out".to_owned()),
                Probe::Connect {
                    host: "example.com".to_owned(),
                    port: 443,
                    via: None,
                },
                Probe::Connect {
                    host: "example.com".to_owned(),
                    port: 443,
                    via: Some(Via::Socks5),
                },
                Probe::Bind,
            ]
        );
    }

    #[test]
    fn a_case_may_say_its_settings_are_refused() {
        let text = |refused: &str| {
            format!(r#"{{"files": {{}}, "settings": "", "refused": {refused}, "probes": []}}"#)
        };

        let case = Case::parse(&text("true"), "/r").unwrap();
        assert!(case.refused);
        assert_eq!(case.settings, json!(""));
        assert!(
            !Case::parse(r#"{"files": {}, "settings": {}, "probes": []}"#, "/r")
                .unwrap()
                .refused
        );
        assert!(matches!(
            Case::parse(&text("1"), "/r"),
            Err(Error::Shape(_))
        ));
    }

    #[test]
    fn an_unknown_probe_kind_is_a_harness_error() {
        let text = r#"{"files": {}, "settings": {}, "probes": [{"kind": "ping"}]}"#;
        assert_eq!(
            Case::parse(text, "/r"),
            Err(Error::UnknownProbe("ping".to_owned()))
        );
    }

    #[test]
    fn every_case_file_in_the_folder_parses() {
        let folder = concat!(env!("CARGO_MANIFEST_DIR"), "/cases");
        let mut parsed = 0;
        for entry in std::fs::read_dir(folder).unwrap() {
            let path = entry.unwrap().path();
            let text = std::fs::read_to_string(&path).unwrap();
            if let Err(error) = Case::parse(&text, "/r") {
                panic!("{}: {error}", path.display());
            }
            parsed += 1;
        }
        assert!(parsed >= 4, "only {parsed} case files found");
    }
}
