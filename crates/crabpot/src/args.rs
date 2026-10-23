//! The crabpot command line: upstream's `-s/--settings`, `-c`, `-d` and `--`,
//! then a program and its arguments.

use core::fmt;
use std::ffi::OsString;
use std::path::PathBuf;

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
        }
    }
}

impl core::error::Error for ArgsError {}

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
}
