//! The `bwrap` command line that runs a command inside a sandbox.
//!
//! A port of `renderBwrapInvocation` from upstream's
//! `src/sandbox/linux-sandbox-utils.ts`. The words that build the sandbox and
//! the command that runs inside it are passed to `bwrap` as `exec` arguments,
//! which a long policy can overflow. When they do, the words move to a file
//! `bwrap` reads with `--args`, and only the short line that opens that file
//! is passed as arguments.

use core::fmt;
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(target_os = "linux")]
mod file;

/// Where Linux keeps `bwrap`. A path and not a lookup, so a `PATH` entry
/// cannot stand in for it. A host that keeps `bwrap` elsewhere sets
/// `bwrapPath`, and the caller puts that path first in the words.
pub const BWRAP: &str = "/usr/bin/bwrap";

/// The most words one bwrap invocation may carry: the `bwrap` to run, its
/// flags, the `--` that ends them, and the command.
///
/// Past it a policy is a mistake rather than a sandbox, and upstream refuses
/// it instead of handing `bwrap` a line no `exec` takes.
pub const BWRAP_MAX_ARGS: usize = 9_000;

/// The longest one word an `exec` call takes. Linux's `MAX_ARG_STRLEN` is 32
/// pages of 4 KiB, and the NUL that ends the word is one of them.
///
/// The args file lifts this limit off the flags `bwrap` reads from it, and off
/// none of the words `bwrap` hands to `exec` when it runs the command: a
/// command word past it is refused in either form.
pub const MAX_ARG_STRLEN: usize = 32 * 4096 - 1;

/// The fd `bwrap` reads its `--args` words from, and the fd the args-file
/// form hands it.
pub const BWRAP_ARGS_FD: u32 = 9;

/// The most bytes one `exec` call takes for its words and its environment
/// together.
///
/// Linux quarters the stack limit for it, and 128 KiB is the least a host is
/// configured with. crabpot takes the args-file form rather than trust a
/// bigger `getconf ARG_MAX`, so a policy that fits here is refused by no
/// `exec`.
const ARG_MAX_BYTES: usize = 128 * 1024;

/// Bytes held back out of [`ARG_MAX_BYTES`] for what the direct line carries
/// beside its words: the caller's environment, and the `/bin/sh -c` line the
/// args-file form needs in its place.
const ARG_HEADROOM_BYTES: usize = 4096;

/// Where the args-file form finds the shell that opens the args file.
#[cfg(target_os = "linux")]
const SH: &str = "/bin/sh";

/// The word that ends the flags and starts the command.
pub(crate) const SEPARATOR: &str = "--";

/// The shell line the args-file form runs in place of `bwrap`: it opens the
/// args file as [`BWRAP_ARGS_FD`], drops it from the words, and execs the
/// rest. `$0` is `bwrap`'s own path, and `$1` the args file.
#[cfg(target_os = "linux")]
fn args_wrapper() -> String {
    format!("exec {BWRAP_ARGS_FD}<\"$1\" && shift && exec \"$@\"")
}

/// A bwrap invocation ready to spawn.
#[derive(Debug)]
pub struct Rendered {
    /// The command to spawn: `bwrap` with the words as its arguments, or
    /// `/bin/sh` with the words in the args file.
    pub command: Command,
    /// The args file's descriptor, which the caller keeps open for as long as
    /// `command` runs. `None` when the words went to `bwrap` directly.
    ///
    /// It is not close-on-exec, since the shell `command` runs reads the words
    /// through it. The caller closes it once `command` has started, so it is
    /// left in no other child of this process.
    pub args_file: Option<OwnedFd>,
}

/// Render `words`, the words of one bwrap invocation with `bwrap` itself
/// first, running `command` inside the sandbox.
///
/// `words` is never empty: its first word names the `bwrap` to run, which a
/// host that keeps it elsewhere sets from `bwrapPath`.
///
/// `args_dir` is the directory the args file is opened in when the words are
/// too long to pass as `exec` arguments.
pub fn render(
    words: &[OsString],
    command: &[OsString],
    args_dir: &Path,
) -> Result<Rendered, ArgvError> {
    debug_assert!(!words.is_empty(), "a bwrap invocation names bwrap");

    let total = words.len() + 1 + command.len();
    if total > BWRAP_MAX_ARGS {
        return Err(ArgvError::TooManyArguments { words: total });
    }

    for word in words.iter().chain(command) {
        if holds_nul(word) {
            return Err(ArgvError::NulInPath { word: word.clone() });
        }
    }

    if let Some(longest) = command
        .iter()
        .map(|word| word.len())
        .filter(|bytes| *bytes > MAX_ARG_STRLEN)
        .max()
    {
        return Err(ArgvError::CommandTooLong { bytes: longest });
    }

    let bytes = words
        .iter()
        .chain(command)
        .map(|word| word.len() + 1)
        .sum::<usize>()
        + SEPARATOR.len()
        + 1;

    if bytes + ARG_HEADROOM_BYTES <= ARG_MAX_BYTES {
        let mut bwrap = Command::new(&words[0]);
        bwrap.args(&words[1..]);
        bwrap.arg(SEPARATOR);
        bwrap.args(command);
        return Ok(Rendered {
            command: bwrap,
            args_file: None,
        });
    }

    render_through_args_file(words, command, args_dir)
}

/// Render the invocation with its words in an args file, which is the form a
/// policy too long for one `exec` line takes.
#[cfg(target_os = "linux")]
fn render_through_args_file(
    words: &[OsString],
    command: &[OsString],
    args_dir: &Path,
) -> Result<Rendered, ArgvError> {
    let file = file::open(args_dir, &words[1..], command).map_err(|error| {
        ArgvError::ArgsFileUnavailable {
            dir: args_dir.to_path_buf(),
            reason: error.kind(),
        }
    })?;

    let mut sh = Command::new(SH);
    sh.arg("-c")
        .arg(args_wrapper())
        .arg(&words[0])
        .arg(&file.path)
        .arg(&words[0])
        .arg("--args")
        .arg(BWRAP_ARGS_FD.to_string());

    Ok(Rendered {
        command: sh,
        args_file: Some(file.fd),
    })
}

/// The args-file form is Linux's: it is `bwrap` that overflows, and only Linux
/// opens an args file.
#[cfg(not(target_os = "linux"))]
fn render_through_args_file(
    _words: &[OsString],
    _command: &[OsString],
    args_dir: &Path,
) -> Result<Rendered, ArgvError> {
    Err(ArgvError::ArgsFileUnavailable {
        dir: args_dir.to_path_buf(),
        reason: io::ErrorKind::Unsupported,
    })
}

/// Why a bwrap invocation cannot be rendered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArgvError {
    /// The invocation carries more words than [`BWRAP_MAX_ARGS`].
    TooManyArguments {
        /// How many words it carries.
        words: usize,
    },
    /// A word holds a NUL byte, which ends it in an `exec` argument and in
    /// the args file.
    NulInPath {
        /// The word that holds one.
        word: OsString,
    },
    /// The command carries a word longer than [`MAX_ARG_STRLEN`], which no
    /// form of the invocation can hand to `exec`.
    CommandTooLong {
        /// How long the word is.
        bytes: usize,
    },
    /// The args file the words had to move to could not be opened.
    ArgsFileUnavailable {
        /// The directory it was opened in.
        dir: PathBuf,
        /// How opening it failed.
        reason: io::ErrorKind,
    },
}

impl fmt::Display for ArgvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyArguments { words } => write!(
                f,
                "the bwrap invocation carries {words} words, and {BWRAP_MAX_ARGS} is the most it takes"
            ),
            Self::NulInPath { word } => write!(
                f,
                "the bwrap word {} holds a NUL byte",
                word.to_string_lossy()
            ),
            Self::CommandTooLong { bytes } => write!(
                f,
                "the command carries a word of {bytes} bytes, and an `exec` argument is {MAX_ARG_STRLEN} at most"
            ),
            Self::ArgsFileUnavailable { dir, reason } => write!(
                f,
                "the bwrap args file could not be opened in {}: {reason:?}",
                dir.display()
            ),
        }
    }
}

impl core::error::Error for ArgvError {}

/// Whether `word` holds a NUL byte, which ends it wherever it is passed.
#[cfg(unix)]
fn holds_nul(word: &OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt;

    word.as_bytes().contains(&0)
}

/// Whether `word` holds a NUL byte, which ends it wherever it is passed.
#[cfg(not(unix))]
fn holds_nul(word: &OsStr) -> bool {
    word.encode_wide().any(|unit| unit == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words() -> Vec<OsString> {
        vec![
            OsString::from(BWRAP),
            OsString::from("--ro-bind"),
            OsString::from("/"),
            OsString::from("/"),
            OsString::from("--dev"),
            OsString::from("/dev"),
        ]
    }

    fn command() -> Vec<OsString> {
        vec![OsString::from("echo"), OsString::from("hello world")]
    }

    #[test]
    fn more_than_9000_words_is_refused() {
        let mut words = vec![OsString::from(BWRAP)];
        words.extend((0..BWRAP_MAX_ARGS - 1).map(|n| OsString::from(format!("--ro-bind-try{n}"))));

        let error = render(&words, &command(), Path::new("/tmp"))
            .expect_err("9000 flags over bwrap is refused");
        assert_eq!(
            error,
            ArgvError::TooManyArguments {
                words: BWRAP_MAX_ARGS + 3
            }
        );
    }

    /// A command long enough that its words no longer fit one `exec` line.
    #[cfg(target_os = "linux")]
    fn long_command() -> Vec<OsString> {
        (0..1_200)
            .map(|n| OsString::from(format!("--input-{n}-{}", "x".repeat(100))))
            .collect()
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn a_long_command_moves_the_words_to_the_args_file() {
        use std::os::fd::AsRawFd;

        let rendered = render(&words(), &long_command(), &std::env::temp_dir())
            .expect("the words fit the args file");
        let fd = rendered
            .args_file
            .expect("a line past 128 KiB moves the words to the args file");

        assert_eq!(rendered.command.get_program(), OsStr::new(SH));
        assert_eq!(
            rendered.command.get_args().collect::<Vec<_>>(),
            [
                "-c",
                "exec 9<\"$1\" && shift && exec \"$@\"",
                BWRAP,
                &format!("/proc/self/fd/{}", fd.as_raw_fd()),
                BWRAP,
                "--args",
                "9",
            ]
            .map(OsString::from)
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn an_unavailable_args_file_is_an_error() {
        let dir = Path::new("/crabpot-has-no-args-directory-here");

        let error = render(&words(), &long_command(), dir)
            .expect_err("with no args file there is no way to run this");
        assert_eq!(
            error,
            ArgvError::ArgsFileUnavailable {
                dir: dir.to_path_buf(),
                reason: std::io::ErrorKind::NotFound,
            }
        );
    }

    #[test]
    fn a_command_past_the_string_limit_is_refused() {
        let long = vec![OsString::from("x".repeat(MAX_ARG_STRLEN + 1))];

        let error = render(&words(), &long, Path::new("/tmp"))
            .expect_err("the args file reaches none of the words bwrap execs");
        assert_eq!(
            error,
            ArgvError::CommandTooLong {
                bytes: MAX_ARG_STRLEN + 1
            }
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_word_with_a_nul_is_refused() {
        use std::os::unix::ffi::OsStringExt;

        let mut words = words();
        words[2] = OsString::from_vec(b"/\0home".to_vec());

        let error = render(&words, &command(), Path::new("/tmp"))
            .expect_err("a NUL byte ends the word it sits in");
        assert_eq!(
            error,
            ArgvError::NulInPath {
                word: OsString::from_vec(b"/\0home".to_vec())
            }
        );
    }

    #[test]
    fn a_short_argv_is_passed_directly() {
        let rendered = render(&words(), &command(), Path::new("/tmp")).expect("renders");

        assert!(rendered.args_file.is_none());
        assert_eq!(rendered.command.get_program(), OsStr::new(BWRAP));
        assert_eq!(
            rendered.command.get_args().collect::<Vec<_>>(),
            [
                "--ro-bind",
                "/",
                "/",
                "--dev",
                "/dev",
                "--",
                "echo",
                "hello world"
            ]
            .map(OsString::from)
        );
    }
}
