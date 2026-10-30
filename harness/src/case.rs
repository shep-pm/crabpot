//! A case: the files, settings and probes one differential run is made of.

use std::collections::BTreeMap;
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
    /// in single quotes, so its case records the code upstream is known to
    /// give, which crabpot must not.
    BackslashArgument {
        /// The argument, which holds a backslash.
        value: String,
    },
}

/// The host environment a case's wrappers run under, names to values.
pub type Env = BTreeMap<String, String>;

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

/// Where the harness listens for a case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// The Unix socket at the path.
    UnixSocket(String),
    /// The Windows named pipe of the name, which is `\\.\pipe\` and a word.
    NamedPipe(String),
}

/// A peer the harness serves while a case's probes run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Serve {
    /// What to listen on.
    pub endpoint: Endpoint,
    /// The status line to answer its `CONNECT` with.
    pub status: String,
}

/// A case file, with `$ROOT` expanded.
#[derive(Clone, PartialEq)]
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
    /// The host environment both wrappers run under, set beside `HOME`.
    pub env: Env,
    /// The probes, in order.
    pub probes: Vec<Probe>,
    /// The code upstream is known to give each probe, where crabpot differs on
    /// purpose, in the order of `probes`. A probe past the end has none.
    pub upstream: Vec<Option<u8>>,
    /// The platforms the case means something on. A case names one only when
    /// it means nothing elsewhere, as a `denyMachLookup` case does. An empty
    /// list means every platform.
    pub platforms: Vec<Platform>,
}

/// The names of a case's `env` with every value hidden, which is how a case
/// prints: the values are the host's environment and may carry a secret.
struct Redacted<'a>(&'a Env);

impl core::fmt::Debug for Redacted<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_map()
            .entries(self.0.keys().map(|name| (name, "<redacted>")))
            .finish()
    }
}

impl core::fmt::Debug for Case {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Case")
            .field("files", &self.files)
            .field("settings", &self.settings)
            .field("refused", &self.refused)
            .field("serve", &self.serve)
            .field("env", &Redacted(&self.env))
            .field("probes", &self.probes)
            .field("upstream", &self.upstream)
            .field("platforms", &self.platforms)
            .finish()
    }
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
    /// appears in a string or a key, and `$PIPE` with the name of a Windows
    /// named pipe that is `root`'s own. A file's path that stays relative is under `root`.
    ///
    /// # Errors
    ///
    /// [`Error::Json`] when `text` is not JSON, [`Error::Shape`] when `files`,
    /// `settings`, `serve` or `probes` is missing or has the wrong type, as is a `refused`
    /// that is not a boolean, an `env` that is not an object of strings, or a
    /// probe's `upstream` that does not fit 8 bits, and
    /// [`Error::UnknownProbe`] when a probe's `kind` is not one this harness knows,
    /// and [`Error::UnknownPlatform`] when a `platforms` entry names a platform
    /// this harness does not run on.
    pub fn parse(text: &str, root: &str) -> Result<Self, Error> {
        let parsed: Value = serde_json::from_str(text).map_err(|e| Error::Json(e.to_string()))?;
        let Value::Object(mut case) = expand(parsed, root, &pipe_for(root)) else {
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
                let endpoint = match (field("unixSocket"), field("namedPipe")) {
                    (Ok(path), Err(_)) => Endpoint::UnixSocket(path),
                    (Err(_), Ok(name)) => Endpoint::NamedPipe(name),
                    _ => {
                        return Err(Error::Shape(
                            "a `serve` without exactly one of `unixSocket` and `namedPipe`"
                                .to_owned(),
                        ));
                    }
                };
                Some(Serve {
                    endpoint,
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
        let env = match take("env") {
            Err(_) => Env::new(),
            Ok(Value::Object(members)) => members
                .into_iter()
                .map(|(name, value)| match value {
                    Value::String(value) => Ok((name, value)),
                    _ => Err(Error::Shape(format!(
                        "an `env` whose {name:?} is not a string"
                    ))),
                })
                .collect::<Result<_, _>>()?,
            Ok(_) => return Err(Error::Shape("an `env` that is not an object".to_owned())),
        };
        let Value::Array(listed) = take("probes")? else {
            return Err(Error::Shape("a `probes` that is not an array".to_owned()));
        };
        let probes = listed
            .iter()
            .map(Probe::from_value)
            .collect::<Result<_, _>>()?;
        let upstream = listed
            .iter()
            .map(upstream_exit_of)
            .collect::<Result<_, _>>()?;
        Ok(Self {
            files,
            settings,
            refused,
            serve,
            env,
            probes,
            upstream,
            platforms,
        })
    }

    /// The code upstream is known to give the probe at `index` where crabpot
    /// differs on purpose, if its case records one.
    pub fn upstream_exit(&self, index: usize) -> Option<u8> {
        self.upstream.get(index).copied().flatten()
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

/// The `upstream` a probe's object records, which any kind of probe may carry.
fn upstream_exit_of(probe: &Value) -> Result<Option<u8>, Error> {
    probe
        .get("upstream")
        .map(|code| {
            code.as_u64()
                .and_then(|code| u8::try_from(code).ok())
                .ok_or_else(|| {
                    Error::Shape("a probe with an `upstream` that does not fit 8 bits".to_owned())
                })
        })
        .transpose()
}

/// The named pipe a case may serve, which is named for its root's folder so
/// that no two cases share one.
fn pipe_for(root: &str) -> String {
    let folder = root.rsplit(['/', '\\']).next().unwrap_or(root);
    format!(r"\\.\pipe\crabpot-harness-{folder}")
}

/// `value` with `$ROOT` and `$PIPE` replaced in every string and key.
fn expand(value: Value, root: &str, pipe: &str) -> Value {
    let spell = |text: &str| text.replace("$ROOT", root).replace("$PIPE", pipe);
    match value {
        Value::String(text) => Value::String(spell(&text)),
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|item| expand(item, root, pipe))
                .collect(),
        ),
        Value::Object(members) => Value::Object(
            members
                .into_iter()
                .map(|(key, member)| (spell(&key), expand(member, root, pipe)))
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
mod tests;
