//! The crabpot command line: upstream's `-s/--settings`, `-c`, `-d` and `--`,
//! then a program and its arguments.

use core::fmt;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// What the command line asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Args {
    /// The settings file, when `-s` names one.
    pub(crate) settings: Option<PathBuf>,
    /// Whether `-d` was given.
    pub(crate) debug: bool,
    /// What to run.
    pub(crate) command: Invocation,
}

/// How the sandboxed command is named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Invocation {
    /// A program and its arguments, exec'd with no shell.
    Argv(Vec<OsString>),
    /// A line for `bash -c`.
    Shell(OsString),
}

/// The hidden first argument that makes the binary the helper inside bwrap
/// (ADR-0014). It is followed by a [`HelperMode`], then the mode's own arguments.
pub(crate) const HELPER_FLAG: &str = "--crabpot-helper";

/// Which of the helper's jobs a re-entry asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HelperMode {
    /// Runs the command, as PID 1 of the sandbox.
    Init,
    /// Relays a TCP port to the proxy's Unix socket.
    Relay,
    /// Connects standard input and output to the proxy, through the relay port
    /// inside the sandbox. This is ssh's `ProxyCommand` hop.
    Connect,
}

impl HelperMode {
    /// The word that names the mode on the command line.
    pub(crate) const fn word(self) -> &'static str {
        match self {
            Self::Init => "init",
            Self::Relay => "relay",
            Self::Connect => "connect",
        }
    }
}

/// A re-entry as the helper: its mode and the mode's own arguments, which are
/// not read as options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Helper {
    pub(crate) mode: HelperMode,
    pub(crate) args: Vec<OsString>,
}

/// Why the command line was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ArgsError {
    /// An option that takes a value was last.
    MissingValue(&'static str),
    /// An option before the command that crabpot does not know.
    UnknownOption(OsString),
    /// Upstream has it and crabpot does not yet.
    Unsupported(&'static str),
    /// No `-c`, and nothing to run.
    NoCommand,
    /// `--crabpot-helper` was followed by a word that names no mode.
    UnknownHelperMode(OsString),
}

impl fmt::Display for ArgsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingValue(option) => write!(f, "{option} needs a value"),
            Self::UnknownOption(option) => {
                write!(f, "unknown option {option:?}, put `--` before the command")
            }
            Self::Unsupported(what) => write!(f, "{what} is not supported yet"),
            Self::NoCommand => write!(f, "no command specified"),
            Self::UnknownHelperMode(mode) => write!(f, "unknown helper mode {mode:?}"),
        }
    }
}

impl core::error::Error for ArgsError {}

/// Reads the arguments after the program's name as a helper re-entry. `None`
/// when the first one is not `--crabpot-helper`: it is recognised there and
/// nowhere else, so the arguments of a command the host runs are never read.
pub(crate) fn parse_helper(
    args: impl IntoIterator<Item = OsString>,
) -> Option<Result<Helper, ArgsError>> {
    let mut args = args.into_iter();
    if args.next()? != HELPER_FLAG {
        return None;
    }
    let mode = match args.next() {
        None => return Some(Err(ArgsError::MissingValue(HELPER_FLAG))),
        Some(word) => match word.to_str() {
            Some("init") => HelperMode::Init,
            Some("relay") => HelperMode::Relay,
            Some("connect") => HelperMode::Connect,
            _ => return Some(Err(ArgsError::UnknownHelperMode(word))),
        },
    };
    Some(Ok(Helper {
        mode,
        args: args.collect(),
    }))
}

/// The flag that gives `init` the proxy's Unix socket to relay the sandbox's
/// proxy ports to. The sandbox always puts it before the command, and a direct
/// `init` leaves it out to run a command with no relay.
pub(crate) const RELAY_FLAG: &str = "--relay";

/// Splits `init`'s arguments into the relay's socket, when they start with
/// [`RELAY_FLAG`] and a path, and the command that follows.
pub(crate) fn split_relay(args: &[OsString]) -> (Option<&Path>, &[OsString]) {
    match args {
        [flag, socket, command @ ..] if flag == RELAY_FLAG => (Some(Path::new(socket)), command),
        _ => (None, args),
    }
}

/// Reads the arguments after the program's name. The first one that is not an
/// option begins the command, and everything from there is the command's own.
/// A `-c` line runs instead of any program named beside it, as upstream's does.
pub(crate) fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Args, ArgsError> {
    let mut args = args.into_iter();
    let mut settings: Option<PathBuf> = None;
    let mut debug = false;
    let mut shell = None;
    let mut argv = Vec::new();
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("-d" | "--debug") => debug = true,
            Some("-s" | "--settings") => {
                settings = Some(args.next().ok_or(ArgsError::MissingValue("-s"))?.into());
            }
            Some("-c") => shell = Some(args.next().ok_or(ArgsError::MissingValue("-c"))?),
            Some("--control-fd") => return Err(ArgsError::Unsupported("--control-fd")),
            Some("proxy") => return Err(ArgsError::Unsupported("proxy")),
            Some("--") => {
                argv.extend(args.by_ref());
            }
            Some(option) if option.starts_with("--settings=") => {
                settings = Some(option["--settings=".len()..].into());
            }
            Some(option) if option.starts_with("--control-fd=") => {
                return Err(ArgsError::Unsupported("--control-fd"));
            }
            Some(option) if option.starts_with('-') => {
                return Err(ArgsError::UnknownOption(arg));
            }
            _ => {
                argv.push(arg);
                argv.extend(args.by_ref());
            }
        }
    }
    let command = match shell {
        Some(line) => Invocation::Shell(line),
        None if argv.is_empty() => return Err(ArgsError::NoCommand),
        None => Invocation::Argv(argv),
    };
    Ok(Args {
        // Upstream tests the option for truthiness, so `-s ""` names no file.
        settings: settings.filter(|path| !path.as_os_str().is_empty()),
        debug,
        command,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_strs(args: &[&str]) -> Result<Args, ArgsError> {
        parse(args.iter().map(OsString::from))
    }

    fn argv(args: &[&str]) -> Invocation {
        Invocation::Argv(args.iter().map(OsString::from).collect())
    }

    #[test]
    fn the_parser_reads_settings_c_d_and_dash_dash() {
        assert_eq!(
            parse_strs(&["-s", "a.json", "-d", "--", "ls", "-la"]),
            Ok(Args {
                settings: Some("a.json".into()),
                debug: true,
                command: argv(&["ls", "-la"]),
            })
        );
        assert_eq!(
            parse_strs(&["--settings=b.json", "--debug", "-c", "echo hi | cat"]),
            Ok(Args {
                settings: Some("b.json".into()),
                debug: true,
                command: Invocation::Shell("echo hi | cat".into()),
            })
        );
        assert_eq!(
            parse_strs(&["--settings", "c.json", "ls", "-d"]),
            Ok(Args {
                settings: Some("c.json".into()),
                debug: false,
                command: argv(&["ls", "-d"]),
            }),
            "an option after the program is the program's"
        );
        assert_eq!(
            parse_strs(&["--", "-d"]).map(|args| args.command),
            Ok(argv(&["-d"])),
            "`--` lets a program's name look like an option"
        );
    }

    #[test]
    fn an_empty_settings_path_names_no_file() {
        assert_eq!(
            parse_strs(&["-s", "", "ls"]).map(|args| args.settings),
            Ok(None)
        );
        assert_eq!(
            parse_strs(&["--settings=", "ls"]).map(|args| args.settings),
            Ok(None)
        );
    }

    #[test]
    fn a_command_line_that_cannot_run_is_refused() {
        assert_eq!(parse_strs(&[]), Err(ArgsError::NoCommand));
        assert_eq!(parse_strs(&["-d"]), Err(ArgsError::NoCommand));
        assert_eq!(parse_strs(&["-s"]), Err(ArgsError::MissingValue("-s")));
        assert_eq!(
            parse_strs(&["--nope", "ls"]),
            Err(ArgsError::UnknownOption("--nope".into()))
        );
        assert_eq!(
            parse_strs(&["--control-fd", "3", "ls"]),
            Err(ArgsError::Unsupported("--control-fd"))
        );
        assert_eq!(
            parse_strs(&["proxy", "start"]),
            Err(ArgsError::Unsupported("proxy"))
        );
    }

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn the_helper_argument_is_recognised_only_first() {
        assert_eq!(
            parse_helper(os(&["--crabpot-helper", "init", "sh", "-c", "exit 3"])),
            Some(Ok(Helper {
                mode: HelperMode::Init,
                args: os(&["sh", "-c", "exit 3"]),
            }))
        );
        for (mode, name) in [
            (HelperMode::Relay, "relay"),
            (HelperMode::Connect, "connect"),
        ] {
            assert_eq!(
                parse_helper(os(&["--crabpot-helper", name])),
                Some(Ok(Helper { mode, args: vec![] }))
            );
        }
        assert_eq!(parse_helper(os(&["ls", "--crabpot-helper", "init"])), None);
        assert_eq!(
            parse_helper(os(&["--crabpot", "--crabpot-helper", "init"])),
            None,
            "the sandboxed command's own arguments are its own"
        );
        assert_eq!(parse_helper(os(&[])), None);
    }

    #[test]
    fn init_takes_the_relay_socket_before_the_command() {
        let args = os(&["--relay", "/tmp/p.sock", "--relay", "x"]);
        assert_eq!(
            split_relay(&args),
            (Some(Path::new("/tmp/p.sock")), &args[2..]),
            "only the first is the helper's"
        );

        let args = os(&["sh", "-c", "exit 3"]);
        assert_eq!(split_relay(&args), (None, &args[..]));

        let args = os(&["--relay"]);
        assert_eq!(
            split_relay(&args),
            (None, &args[..]),
            "a flag with no socket is a command's name"
        );
    }

    /// The Linux half spells the re-entry into the `connect` mode for ssh's
    /// `ProxyCommand`, and this is the reader of it: the two spellings are one.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_connect_mode_is_spelled_as_the_parser_reads_it() {
        assert_eq!(
            crabpot_linux::net::ssh::CONNECT_REENTRY,
            format!("{HELPER_FLAG} {}", HelperMode::Connect.word())
        );
    }

    #[test]
    fn an_unknown_helper_mode_is_refused() {
        assert_eq!(
            parse_helper(os(&["--crabpot-helper", "nope"])),
            Some(Err(ArgsError::UnknownHelperMode("nope".into())))
        );
        assert_eq!(
            parse_helper(os(&["--crabpot-helper"])),
            Some(Err(ArgsError::MissingValue("--crabpot-helper")))
        );
    }
}
