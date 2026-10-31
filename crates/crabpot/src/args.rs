//! The crabpot command line: upstream's `-s/--settings`, `-c`, `-d` and `--`,
//! then a program and its arguments.

use core::fmt;
use std::ffi::OsString;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use crate::windows::install::{InstallOptions, UninstallOptions};

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

/// The hidden first argument that makes the binary srt-win (see `run_from_args`).
pub(crate) const SRT_WIN_FLAG: &str = "--srt-win";

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

/// A subcommand that sets the Windows sandbox up or takes it down, in place of
/// running a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Subcommand {
    /// `windows-install`.
    WindowsInstall(InstallOptions),
    /// `windows-uninstall`.
    WindowsUninstall(UninstallOptions),
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
    /// `--loopback` was followed by something other than an IP address.
    InvalidLoopback(OsString),
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
            Self::InvalidLoopback(address) => write!(f, "invalid loopback address {address:?}"),
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

/// Reads the arguments after the program's name as `windows-install` or
/// `windows-uninstall`. `None` when the first one is neither: the names are
/// recognised there and nowhere else, so a program of that name still runs
/// after `--`.
pub(crate) fn parse_subcommand(
    args: impl IntoIterator<Item = OsString>,
) -> Option<Result<Subcommand, ArgsError>> {
    let mut args = args.into_iter();
    let first = args.next()?;
    match first.to_str()? {
        "windows-install" => Some(parse_install(args).map(Subcommand::WindowsInstall)),
        "windows-uninstall" => Some(parse_uninstall(args).map(Subcommand::WindowsUninstall)),
        _ => None,
    }
}

fn parse_install(mut args: impl Iterator<Item = OsString>) -> Result<InstallOptions, ArgsError> {
    let mut options = InstallOptions::default();
    while let Some(arg) = args.next() {
        match flag(&arg, &mut args)? {
            ("--allow-loopback", None) => options.allow_loopback = true,
            ("--force", None) => options.force = true,
            ("--sublayer-guid", Some(value)) => options.sublayer_guid = Some(value),
            ("--proxy-port-range", Some(value)) => options.proxy_port_range = Some(value),
            ("--sandbox-user", Some(value)) => options.sandbox_user = Some(value),
            ("--profile-exclude", Some(value)) => options.profile_exclude.push(value),
            ("--skip-profile-grant", None) => options.skip_profile_grant = true,
            _ => return Err(ArgsError::UnknownOption(arg)),
        }
    }
    Ok(options)
}

fn parse_uninstall(
    mut args: impl Iterator<Item = OsString>,
) -> Result<UninstallOptions, ArgsError> {
    let mut options = UninstallOptions::default();
    while let Some(arg) = args.next() {
        match flag(&arg, &mut args)? {
            ("--keep-user", None) => options.keep_user = true,
            ("--sublayer-guid", Some(value)) => options.sublayer_guid = Some(value),
            _ => return Err(ArgsError::UnknownOption(arg)),
        }
    }
    Ok(options)
}

/// Splits `arg` into an option's name and its value. A value comes from
/// `--name=value`, or from the next argument for the options that take one.
fn flag<'a>(
    arg: &'a OsString,
    rest: &mut impl Iterator<Item = OsString>,
) -> Result<(&'a str, Option<OsString>), ArgsError> {
    const TAKES_VALUE: [&str; 4] = [
        "--sublayer-guid",
        "--proxy-port-range",
        "--sandbox-user",
        "--profile-exclude",
    ];
    let text = arg
        .to_str()
        .ok_or_else(|| ArgsError::UnknownOption(arg.clone()))?;
    if let Some((name, value)) = text.split_once('=')
        && TAKES_VALUE.contains(&name)
    {
        return Ok((name, Some(value.into())));
    }
    match TAKES_VALUE.into_iter().find(|name| *name == text) {
        Some(name) => Ok((
            name,
            Some(rest.next().ok_or(ArgsError::MissingValue(name))?),
        )),
        None => Ok((text, None)),
    }
}

/// The flag that gives `init` the proxy's Unix socket to relay the sandbox's
/// proxy ports to. The sandbox always puts it before the command, and a direct
/// `init` leaves it out to run a command with no relay.
pub(crate) const RELAY_FLAG: &str = "--relay";

/// The flag that adds an IP address to the sandbox's loopback.
pub(crate) const LOOPBACK_FLAG: &str = "--loopback";

/// Asks the helper to acknowledge startup through its inherited descriptor.
pub(crate) const REPORT_STARTED_FLAG: &str = "--report-started";

/// The helper's options and the command's untouched arguments.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Init<'a> {
    pub(crate) report_started: bool,
    pub(crate) relay: Option<&'a Path>,
    pub(crate) loopback: Vec<IpAddr>,
    pub(crate) command: &'a [OsString],
}

/// Reads helper options until the command or `--` begins its arguments.
pub(crate) fn parse_init(mut args: &[OsString]) -> Result<Init<'_>, ArgsError> {
    let mut report_started = false;
    let mut relay = None;
    let mut loopback = Vec::new();
    while let Some(arg) = args.first() {
        let flag = match arg.to_str() {
            Some(REPORT_STARTED_FLAG) => {
                report_started = true;
                args = &args[1..];
                continue;
            }
            Some(RELAY_FLAG) => RELAY_FLAG,
            Some(LOOPBACK_FLAG) => LOOPBACK_FLAG,
            Some("--") => {
                args = &args[1..];
                break;
            }
            _ => break,
        };
        let value = args.get(1).ok_or(ArgsError::MissingValue(flag))?;
        if flag == RELAY_FLAG {
            relay = Some(Path::new(value));
        } else {
            loopback.push(
                value
                    .to_str()
                    .and_then(|value| value.parse().ok())
                    .ok_or_else(|| ArgsError::InvalidLoopback(value.clone()))?,
            );
        }
        args = &args[2..];
    }
    Ok(Init {
        report_started,
        relay,
        loopback,
        command: args,
    })
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
    fn windows_install_reads_upstreams_flags() {
        assert_eq!(
            parse_subcommand(os(&["windows-install"])),
            Some(Ok(Subcommand::WindowsInstall(InstallOptions::default())))
        );
        assert_eq!(
            parse_subcommand(os(&[
                "windows-install",
                "--allow-loopback",
                "--proxy-port-range",
                "61000-61009",
                "--sandbox-user=ci",
                "--sublayer-guid",
                "{G}",
                "--force",
            ])),
            Some(Ok(Subcommand::WindowsInstall(InstallOptions {
                sublayer_guid: Some("{G}".into()),
                proxy_port_range: Some("61000-61009".into()),
                allow_loopback: true,
                sandbox_user: Some("ci".into()),
                force: true,
                ..InstallOptions::default()
            })))
        );
    }

    #[test]
    fn windows_install_reads_the_profile_grant_flags() {
        assert_eq!(
            parse_subcommand(os(&[
                "windows-install",
                "--profile-exclude",
                r"C:\Users\me\.aws",
                "--profile-exclude=.ssh",
                "--skip-profile-grant",
            ])),
            Some(Ok(Subcommand::WindowsInstall(InstallOptions {
                profile_exclude: vec![r"C:\Users\me\.aws".into(), ".ssh".into()],
                skip_profile_grant: true,
                ..InstallOptions::default()
            })))
        );
        assert_eq!(
            parse_subcommand(os(&["windows-install", "--profile-exclude"])),
            Some(Err(ArgsError::MissingValue("--profile-exclude")))
        );
    }

    #[test]
    fn init_reads_repeated_loopback_addresses_before_the_command() {
        let args = os(&[
            "--loopback",
            "10.9.9.9",
            "--loopback",
            "fd00::5",
            "sh",
            "--loopback",
        ]);
        let init = parse_init(&args).unwrap();

        assert_eq!(init.relay, None);
        assert_eq!(
            init.loopback,
            [
                "10.9.9.9".parse::<std::net::IpAddr>().unwrap(),
                "fd00::5".parse().unwrap()
            ]
        );
        assert_eq!(init.command, &args[4..]);
    }

    #[test]
    fn init_reads_loopback_addresses_on_either_side_of_the_relay() {
        let args = os(&[
            "--loopback",
            "10.0.0.5",
            "--relay",
            "proxy.sock",
            "--loopback",
            "::5",
            "echo",
            "ok",
        ]);
        let init = parse_init(&args).unwrap();

        assert_eq!(init.relay, Some(Path::new("proxy.sock")));
        assert_eq!(
            init.loopback,
            [
                "10.0.0.5".parse::<IpAddr>().unwrap(),
                "::5".parse().unwrap()
            ]
        );
        assert_eq!(init.command, &args[6..]);
    }

    #[test]
    fn init_refuses_a_malformed_or_missing_loopback_address() {
        for address in ["10.9.9.999", "10.9.9.9/32", "localhost", ""] {
            assert_eq!(
                parse_init(&os(&["--loopback", address, "sh"])),
                Err(ArgsError::InvalidLoopback(address.into()))
            );
        }
        assert_eq!(
            parse_init(&os(&["--loopback"])),
            Err(ArgsError::MissingValue(LOOPBACK_FLAG))
        );
    }

    #[test]
    fn init_takes_the_relay_socket_before_the_command() {
        let args = os(&["--relay", "/tmp/p.sock", "--", "--relay", "x"]);
        let init = parse_init(&args).unwrap();
        assert_eq!(
            (init.relay, init.command),
            (Some(Path::new("/tmp/p.sock")), &args[3..])
        );

        let args = os(&["sh", "-c", "exit 3"]);
        let init = parse_init(&args).unwrap();
        assert_eq!((init.relay, init.command), (None, &args[..]));
        assert!(init.loopback.is_empty());

        let args = os(&["--relay"]);
        assert_eq!(parse_init(&args), Err(ArgsError::MissingValue(RELAY_FLAG)));
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
    fn windows_uninstall_reads_its_flags() {
        assert_eq!(
            parse_subcommand(os(&[
                "windows-uninstall",
                "--keep-user",
                "--sublayer-guid=G"
            ])),
            Some(Ok(Subcommand::WindowsUninstall(UninstallOptions {
                sublayer_guid: Some("G".into()),
                keep_user: true,
            })))
        );
    }

    #[test]
    fn a_windows_subcommand_refuses_what_it_does_not_know() {
        assert_eq!(
            parse_subcommand(os(&["windows-install", "--keep-user"])),
            Some(Err(ArgsError::UnknownOption("--keep-user".into())))
        );
        assert_eq!(
            parse_subcommand(os(&["windows-uninstall", "--allow-loopback"])),
            Some(Err(ArgsError::UnknownOption("--allow-loopback".into())))
        );
        assert_eq!(
            parse_subcommand(os(&["windows-install", "--sandbox-user"])),
            Some(Err(ArgsError::MissingValue("--sandbox-user")))
        );
        assert_eq!(
            parse_subcommand(os(&["windows-install", "--allow-loopback=yes"])),
            Some(Err(ArgsError::UnknownOption("--allow-loopback=yes".into())))
        );
    }

    #[test]
    fn a_subcommand_is_recognised_only_first() {
        assert_eq!(parse_subcommand(os(&["--", "windows-install"])), None);
        assert_eq!(parse_subcommand(os(&["ls", "windows-install"])), None);
        assert_eq!(parse_subcommand(os(&[])), None);
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
