//! The last step of the helper: replacing it with the command.

use core::fmt;
use std::ffi::OsString;
use std::io;
use std::os::unix::process::CommandExt;
use std::process::Command;

/// Replaces this process with the command `argv` names: its program, searched
/// for on `PATH`, then its arguments, none of them read as options.
///
/// It returns only when the command could not be started.
pub fn exec(argv: &[OsString]) -> ExecError {
    let Some((program, args)) = argv.split_first() else {
        return ExecError::NoCommand;
    };
    let error = Command::new(program).args(args).exec();
    ExecError::Spawn {
        program: program.clone(),
        reason: error.kind(),
    }
}

/// Why the command did not replace the helper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecError {
    /// There was no program to run.
    NoCommand,
    /// The program could not be started: it is not found, not executable, or
    /// the process may not run it.
    Spawn {
        /// The program that was named.
        program: OsString,
        /// How starting it failed.
        reason: io::ErrorKind,
    },
}

impl fmt::Display for ExecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCommand => write!(f, "no command specified"),
            Self::Spawn { program, reason } => {
                write!(f, "cannot run {program:?}: {reason}")
            }
        }
    }
}

impl core::error::Error for ExecError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(words: &[&str]) -> Vec<OsString> {
        words.iter().map(OsString::from).collect()
    }

    #[test]
    fn no_command_is_refused() {
        assert_eq!(exec(&[]), ExecError::NoCommand);
    }

    #[test]
    fn a_program_that_is_not_there_is_named_in_the_error() {
        let error = exec(&argv(&["/no/such/program", "arg"]));

        assert_eq!(
            error,
            ExecError::Spawn {
                program: "/no/such/program".into(),
                reason: io::ErrorKind::NotFound,
            }
        );
        assert_eq!(
            error.to_string(),
            r#"cannot run "/no/such/program": entity not found"#
        );
    }
}
