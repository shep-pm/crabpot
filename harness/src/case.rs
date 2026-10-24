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
    /// Rename `from` to `to`.
    Rename {
        /// The path to move.
        from: String,
        /// The path to move it to.
        to: String,
    },
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
    /// Bind a Unix socket at the path. A relative one names a place under the
    /// case root, which is where each wrapper runs.
    BindUnix(String),
    /// Dial the Unix socket at the path, named as `BindUnix` names it. The
    /// harness serves it, so a case must not hold a file at that path itself.
    ConnectUnix(String),
    /// Bind a loopback listener, dial it and accept the dial.
    Loopback,
    /// Signal the process group a child the probe started leads.
    SignalGroup,
    /// Ask `ps` whether a process runs.
    Ps,
    /// Make a stream socket of the family. Linux only.
    Socket(Family),
    /// Call `io_uring_setup`. Linux only.
    IoUringSetup,
    /// Make a user namespace with `unshare`. Linux only.
    UnshareUser,
    /// Ask `ps` for the harness's own process, which a sandbox with a pid
    /// namespace of its own does not hold.
    PsOutside,
    /// Pass the program an argument that holds a backslash, and report whether
    /// it arrived as written. Upstream's Windows runner wraps such an argument
    /// in single quotes, so `upstream` is the code it is known to give, which
    /// crabpot must not.
    BackslashArgument {
        /// The argument, which holds a backslash.
        value: String,
        /// The code upstream's runner gives, recorded as the difference.
        upstream: u8,
    },
}

impl Probe {
    /// The code upstream is known to give where crabpot differs on purpose.
    pub fn upstream_exit(&self) -> Option<u8> {
        match self {
            Self::BackslashArgument { upstream, .. } => Some(*upstream),
            _ => None,
        }
    }
}

/// The address family of a `socket` probe: the two a Linux sandbox refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// `AF_UNIX`.
    Unix,
    /// `AF_VSOCK`.
    Vsock,
}

impl Family {
    /// The word the `probe` binary and a case's `family` spell it with.
    fn word(self) -> &'static str {
        match self {
            Self::Unix => "unix",
            Self::Vsock => "vsock",
        }
    }
}

/// A proxy other than the HTTP one that a `connect` probe goes through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    /// The SOCKS5 proxy.
    Socks5,
}

/// A platform a case can mean something on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// macOS, whose sandbox is `sandbox-exec`.
    MacOs,
    /// Linux, whose sandbox is `bubblewrap`.
    Linux,
    /// Windows, whose sandbox is `srt-win`.
    Windows,
}

impl Platform {
    /// The platform named `name`, the word a case uses for it in its
    /// `platforms`, or `None` for a name this harness does not run.
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "macos" => Some(Self::MacOs),
            "linux" => Some(Self::Linux),
            "windows" => Some(Self::Windows),
            _ => None,
        }
    }

    /// The platform this harness runs on: macOS, Windows, or Linux for every
    /// other target.
    pub fn current() -> Self {
        if cfg!(target_os = "macos") {
            Self::MacOs
        } else if cfg!(windows) {
            Self::Windows
        } else {
            Self::Linux
        }
    }
}

/// A peer the harness serves while a case's probes run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Serve {
    /// The Unix socket to listen on.
    pub unix_socket: String,
    /// The status line to answer its `CONNECT` with.
    pub status: String,
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
    /// A socket the harness serves for the probes to reach.
    pub serve: Option<Serve>,
    /// The probes, in order.
    pub probes: Vec<Probe>,
    /// The platforms the case means something on. A case names one only when
    /// it means nothing elsewhere, as a `denyMachLookup` case does. An empty
    /// list means every platform.
    pub platforms: Vec<Platform>,
}

/// Why a case file is not a case.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The text is not JSON.
    Json(String),
    /// A field is missing or is not the kind of value it should be.
    Shape(String),
    /// A probe's `kind` is not one of the kinds in [`Probe`].
    UnknownProbe(String),
    /// A `platforms` entry names a platform this harness does not run.
    UnknownPlatform(String),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Json(reason) => write!(f, "the case is not JSON: {reason}"),
            Self::Shape(what) => write!(f, "the case has {what}"),
            Self::UnknownProbe(kind) => write!(f, "the case has an unknown probe kind {kind:?}"),
            Self::UnknownPlatform(name) => {
                write!(
                    f,
                    "the case names the platform {name:?}, which it cannot run on"
                )
            }
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
    /// `settings`, `serve` or `probes` is missing or has the wrong type, as is a `refused`
    /// that is not a boolean, and
    /// [`Error::UnknownProbe`] when a probe's `kind` is not one this harness knows,
    /// and [`Error::UnknownPlatform`] when a `platforms` entry names a platform
    /// this harness does not run on.
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
        let serve = match take("serve") {
            Err(_) => None,
            Ok(Value::Object(members)) => {
                let field = |name: &str| {
                    members
                        .get(name)
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                        .ok_or_else(|| Error::Shape(format!("a `serve` without a string `{name}`")))
                };
                Some(Serve {
                    unix_socket: field("unixSocket")?,
                    status: field("status")?,
                })
            }
            Ok(_) => return Err(Error::Shape("a `serve` that is not an object".to_owned())),
        };
        let platforms = match take("platforms") {
            Err(_) => Vec::new(),
            Ok(Value::Array(names)) => names
                .iter()
                .map(Platform::from_value)
                .collect::<Result<_, _>>()?,
            _ => {
                return Err(Error::Shape(
                    "a `platforms` that is not an array".to_owned(),
                ));
            }
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
            serve,
            probes,
            platforms,
        })
    }

    /// Whether the case means `platform`. One that names no platform means
    /// every platform.
    pub fn runs_on(&self, platform: Platform) -> bool {
        self.platforms.is_empty() || self.platforms.contains(&platform)
    }

    /// Whether the settings set `network.allowLocalBinding`, which on Windows is
    /// a property of the installed filters and not of a session: upstream
    /// refuses a session whose setting is not the one the install was made with.
    pub fn allows_loopback(&self) -> bool {
        self.settings["network"]["allowLocalBinding"] == Value::Bool(true)
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
            Self::Rename { from, to } => vec!["rename".to_owned(), from.clone(), to.clone()],
            Self::Connect { host, port, via } => {
                let mut args = vec!["connect".to_owned(), host.clone(), port.to_string()];
                if let Some(Via::Socks5) = via {
                    args.extend(["--via".to_owned(), "socks5".to_owned()]);
                }
                args
            }
            Self::Bind => vec!["bind".to_owned()],
            Self::BindUnix(path) => vec!["bind-unix".to_owned(), path.clone()],
            Self::ConnectUnix(path) => vec!["connect-unix".to_owned(), path.clone()],
            Self::Loopback => vec!["loopback".to_owned()],
            Self::SignalGroup => vec!["signal-group".to_owned()],
            Self::Ps => vec!["ps".to_owned()],
            Self::Socket(family) => vec!["socket".to_owned(), family.word().to_owned()],
            Self::IoUringSetup => vec!["io-uring-setup".to_owned()],
            Self::UnshareUser => vec!["unshare-user".to_owned()],
            Self::PsOutside => vec!["ps-outside".to_owned()],
            Self::BackslashArgument { value, .. } => {
                vec![
                    "backslash-argument".to_owned(),
                    value.clone(),
                    crate::probe::argument::encode(value),
                ]
            }
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
            "rename" => Ok(Self::Rename {
                from: text("from")?,
                to: text("to")?,
            }),
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
            "bind-unix" => Ok(Self::BindUnix(text("path")?)),
            "connect-unix" => Ok(Self::ConnectUnix(text("path")?)),
            "loopback" => Ok(Self::Loopback),
            "signal-group" => Ok(Self::SignalGroup),
            "ps" => Ok(Self::Ps),
            "socket" => match text("family")?.as_str() {
                "unix" => Ok(Self::Socket(Family::Unix)),
                "vsock" => Ok(Self::Socket(Family::Vsock)),
                _ => Err(Error::Shape(
                    "a probe with a `family` that is not \"unix\" or \"vsock\"".to_owned(),
                )),
            },
            "io-uring-setup" => Ok(Self::IoUringSetup),
            "unshare-user" => Ok(Self::UnshareUser),
            "ps-outside" => Ok(Self::PsOutside),
            "backslash-argument" => Ok(Self::BackslashArgument {
                value: text("value")?,
                upstream: field("upstream")
                    .and_then(Value::as_u64)
                    .and_then(|code| u8::try_from(code).ok())
                    .ok_or_else(|| {
                        Error::Shape("a probe without an `upstream` that fits 8 bits".to_owned())
                    })?,
            }),
            _ => Err(Error::UnknownProbe(kind)),
        }
    }
}

impl Platform {
    fn from_value(value: &Value) -> Result<Self, Error> {
        let name = value
            .as_str()
            .ok_or_else(|| Error::Shape("a `platforms` entry that is not a string".to_owned()))?;
        Self::from_name(name).ok_or_else(|| Error::UnknownPlatform(name.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::Path;

    #[test]
    fn a_case_file_parses_and_expands_root() {
        let text = r#"{
            "files": {"$ROOT/in": "hello"},
            "settings": {"filesystem": {"allowWrite": ["$ROOT/out"]}},
            "probes": [
                {"kind": "read", "path": "$ROOT/in"},
                {"kind": "write", "path": "$ROOT/out"},
                {"kind": "rename", "from": "$ROOT/in", "to": "$ROOT/moved"},
                {"kind": "connect", "host": "example.com", "port": 443},
                {"kind": "connect", "host": "example.com", "port": 443, "via": "socks5"},
                {"kind": "bind"},
                {"kind": "bind-unix", "path": "$ROOT/socks/a.sock"},
                {"kind": "connect-unix", "path": "$ROOT/socks/live.sock"},
                {"kind": "loopback"},
                {"kind": "signal-group"},
                {"kind": "ps"}
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
                Probe::Rename {
                    from: "/r/in".to_owned(),
                    to: "/r/moved".to_owned()
                },
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
                Probe::BindUnix("/r/socks/a.sock".to_owned()),
                Probe::ConnectUnix("/r/socks/live.sock".to_owned()),
                Probe::Loopback,
                Probe::SignalGroup,
                Probe::Ps,
            ]
        );
    }

    #[test]
    fn the_kernel_probes_parse_and_spell_their_words() {
        let text = r#"{
            "files": {},
            "settings": {},
            "probes": [
                {"kind": "socket", "family": "unix"},
                {"kind": "socket", "family": "vsock"},
                {"kind": "io-uring-setup"},
                {"kind": "unshare-user"},
                {"kind": "ps-outside"}
            ]
        }"#;
        let case = Case::parse(text, "/r").unwrap();
        assert_eq!(
            case.probes,
            [
                Probe::Socket(Family::Unix),
                Probe::Socket(Family::Vsock),
                Probe::IoUringSetup,
                Probe::UnshareUser,
                Probe::PsOutside,
            ]
        );
        let words: Vec<Vec<String>> = case.probes.iter().map(Probe::args).collect();
        assert_eq!(
            words,
            [
                ["socket", "unix"].as_slice(),
                ["socket", "vsock"].as_slice(),
                ["io-uring-setup"].as_slice(),
                ["unshare-user"].as_slice(),
                ["ps-outside"].as_slice(),
            ]
        );
    }

    #[test]
    fn a_socket_probe_needs_a_family_the_probe_knows() {
        for probe in [
            r#"{"kind": "socket"}"#,
            r#"{"kind": "socket", "family": "inet"}"#,
        ] {
            let text = format!(r#"{{"files": {{}}, "settings": {{}}, "probes": [{probe}]}}"#);
            assert!(
                matches!(Case::parse(&text, "/r"), Err(Error::Shape(_))),
                "{probe}"
            );
        }
    }

    /// A socket probe may name its socket against the case root instead, which
    /// is where each wrapper runs and where the harness serves it.
    #[test]
    fn a_socket_probe_named_against_the_case_root_stays_relative() {
        let text = r#"{
            "files": {},
            "settings": {},
            "probes": [
                {"kind": "bind-unix", "path": "socks/a.sock"},
                {"kind": "connect-unix", "path": "socks/live.sock"}
            ]
        }"#;
        let case = Case::parse(text, "/r").unwrap();
        assert_eq!(
            case.probes,
            [
                Probe::BindUnix("socks/a.sock".to_owned()),
                Probe::ConnectUnix("socks/live.sock".to_owned()),
            ]
        );
    }

    /// A backslash-argument probe records the code upstream gives, which is
    /// the difference the case pins.
    #[test]
    fn a_backslash_argument_probe_records_the_code_upstream_gives() {
        let text = r#"{
            "files": {},
            "settings": {},
            "probes": [{"kind": "backslash-argument", "value": "C:\\work", "upstream": 1}]
        }"#;
        let case = Case::parse(text, "/r").unwrap();
        let [probe] = case.probes.as_slice() else {
            panic!("one probe: {:?}", case.probes);
        };

        assert_eq!(
            *probe,
            Probe::BackslashArgument {
                value: r"C:\work".to_owned(),
                upstream: 1,
            }
        );
        assert_eq!(
            probe.args(),
            ["backslash-argument", r"C:\work", "433a5c776f726b"]
        );
        assert_eq!(probe.upstream_exit(), Some(1));
        assert_eq!(Probe::Bind.upstream_exit(), None);
    }

    #[test]
    fn a_backslash_argument_probe_needs_a_value_and_a_code_upstream_gives() {
        for probe in [
            r#"{"kind": "backslash-argument", "upstream": 1}"#,
            r#"{"kind": "backslash-argument", "value": "C:\\work"}"#,
            r#"{"kind": "backslash-argument", "value": "C:\\work", "upstream": 256}"#,
        ] {
            let text = format!(r#"{{"files": {{}}, "settings": {{}}, "probes": [{probe}]}}"#);
            assert!(
                matches!(Case::parse(&text, "/r"), Err(Error::Shape(_))),
                "{probe}"
            );
        }
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
    fn a_case_may_serve_a_unix_socket() {
        let text = r#"{
            "files": {},
            "settings": {},
            "serve": {"unixSocket": "$ROOT/mitm.sock", "status": "403 Forbidden"},
            "probes": []
        }"#;
        let case = Case::parse(text, "/r").unwrap();

        assert_eq!(
            case.serve,
            Some(Serve {
                unix_socket: "/r/mitm.sock".to_owned(),
                status: "403 Forbidden".to_owned(),
            })
        );
        let case = Case::parse(r#"{"files": {}, "settings": {}, "probes": []}"#, "/r").unwrap();
        assert_eq!(case.serve, None);
        for text in [
            r#"{"files": {}, "settings": {}, "serve": [], "probes": []}"#,
            r#"{"files": {}, "settings": {}, "serve": {}, "probes": []}"#,
            r#"{"files": {}, "settings": {}, "serve": {"unixSocket": 1}, "probes": []}"#,
        ] {
            assert!(
                matches!(Case::parse(text, "/r"), Err(Error::Shape(_))),
                "{text}"
            );
        }
    }

    #[test]
    fn a_case_without_platforms_runs_everywhere() {
        let case = Case::parse(r#"{"files": {}, "settings": {}, "probes": []}"#, "/r").unwrap();
        assert!(case.platforms.is_empty());
        assert!(case.runs_on(Platform::MacOs));
        assert!(case.runs_on(Platform::Linux));
    }

    #[test]
    fn a_case_allows_loopback_only_when_its_settings_say_true() {
        let with = |network: &str| {
            Case::parse(
                &format!(
                    r#"{{"files": {{}}, "settings": {{"network": {network}}}, "probes": []}}"#
                ),
                "/r",
            )
            .unwrap()
        };

        assert!(with(r#"{"allowLocalBinding": true}"#).allows_loopback());
        assert!(!with(r#"{"allowLocalBinding": false}"#).allows_loopback());
        assert!(!with("{}").allows_loopback());
        let text = Case::parse(
            r#"{"files": {}, "settings": "not json", "probes": []}"#,
            "/r",
        );
        assert!(!text.unwrap().allows_loopback());
    }

    #[test]
    fn a_case_runs_only_on_the_platforms_it_names() {
        let named = |platforms: &str| {
            Case::parse(
                &format!(
                    r#"{{"files": {{}}, "settings": {{}}, "platforms": {platforms}, "probes": []}}"#
                ),
                "/r",
            )
        };

        let case = named(r#"["macos"]"#).unwrap();
        assert_eq!(case.platforms, [Platform::MacOs]);
        assert!(case.runs_on(Platform::MacOs));
        assert!(!case.runs_on(Platform::Linux));

        let case = named(r#"["linux", "macos"]"#).unwrap();
        assert_eq!(case.platforms, [Platform::Linux, Platform::MacOs]);
        assert!(case.runs_on(Platform::MacOs));
        assert!(case.runs_on(Platform::Linux));

        assert_eq!(
            named(r#"["plan9"]"#),
            Err(Error::UnknownPlatform("plan9".to_owned()))
        );
        for platforms in [r#""macos""#, "[1]", r#"["macos", 2]"#] {
            assert!(
                matches!(named(platforms), Err(Error::Shape(_))),
                "{platforms}"
            );
        }
    }

    #[test]
    fn a_case_that_names_other_platforms_is_skipped_on_windows() {
        let named = |platforms: &str| {
            Case::parse(
                &format!(
                    r#"{{"files": {{}}, "settings": {{}}, "platforms": {platforms}, "probes": []}}"#
                ),
                "/r",
            )
            .unwrap()
        };

        let unix_only = named(r#"["macos", "linux"]"#);
        assert!(!unix_only.runs_on(Platform::Windows));
        assert!(unix_only.runs_on(Platform::MacOs));

        let windows = named(r#"["windows"]"#);
        assert_eq!(windows.platforms, [Platform::Windows]);
        assert!(windows.runs_on(Platform::Windows));
        assert!(!windows.runs_on(Platform::Linux));

        let everywhere = named("[]");
        assert!(everywhere.runs_on(Platform::Windows));
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

    #[test]
    fn every_write_and_rename_in_a_case_file_has_a_folder_to_land_in() {
        let folder = concat!(env!("CARGO_MANIFEST_DIR"), "/cases");
        for entry in std::fs::read_dir(folder).unwrap() {
            let path = entry.unwrap().path();
            let text = std::fs::read_to_string(&path).unwrap();
            let case = Case::parse(&text, "/r").unwrap();
            let mut folders = std::collections::HashSet::new();
            let mut sources = std::collections::HashSet::new();
            for (file, _) in &case.files {
                sources.insert(file.clone());
                for ancestor in file.ancestors().skip(1) {
                    folders.insert(ancestor.to_owned());
                    sources.insert(ancestor.to_owned());
                }
            }
            // A probe cannot tell a missing folder from a refusal, so one
            // that lands in a folder the case never made exits 2.
            let lands = |target: &str| match Path::new(target).parent() {
                Some(parent) => {
                    !target.starts_with("/r/")
                        || folders.contains(parent)
                        || parent == Path::new("/r")
                }
                None => true,
            };
            for probe in &case.probes {
                match probe {
                    Probe::Write(target) => {
                        assert!(lands(target), "{}: no folder for {target}", path.display())
                    }
                    Probe::Rename { from, to } => {
                        assert!(
                            !from.starts_with("/r/") || sources.contains(Path::new(from)),
                            "{}: nothing to move at {from}",
                            path.display()
                        );
                        assert!(lands(to), "{}: no folder for {to}", path.display());
                    }
                    Probe::BindUnix(target) | Probe::ConnectUnix(target) => {
                        assert!(lands(target), "{}: no folder for {target}", path.display())
                    }
                    Probe::Read(_) | Probe::Connect { .. } | Probe::Bind | Probe::Loopback => {}
                    Probe::SignalGroup | Probe::Ps => {}
                    Probe::Socket(_)
                    | Probe::IoUringSetup
                    | Probe::UnshareUser
                    | Probe::PsOutside
                    | Probe::BackslashArgument { .. } => {}
                }
            }
        }
    }
}
