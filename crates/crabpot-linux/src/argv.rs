//! The `bwrap` command line that runs a command inside a sandbox.
//!
//! A port of `renderBwrapInvocation` from upstream's
//! `src/sandbox/linux-sandbox-utils.ts`. The flags that build the sandbox and
//! the command that runs inside it are passed to `bwrap` as `exec` arguments,
//! which a long policy can overflow. When they do, the flags move to a file
//! `bwrap` reads with `--args` at the position they had, and the command stays
//! on the line.
//!
//! Every word stays a `Command` argument. Upstream builds its line as one
//! quoted shell string, which is the argument the kernel caps: crabpot builds
//! no shell string, and caps the whole line against the same figure.

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

/// The most words bwrap parses: the flags, the `--` that ends them, and the
/// command. The `bwrap` that parses them is not one of them.
///
/// Past it a policy is a mistake rather than a sandbox, and upstream refuses it
/// instead of handing bwrap a line no `exec` takes.
pub const BWRAP_MAX_ARGS: usize = 9_000;

/// The bytes a command may carry: Linux's `MAX_ARG_STRLEN`, 32 pages of 4 KiB,
/// less the NUL that ends a word.
///
/// Upstream caps its whole quoted line at this figure, which is the one `exec`
/// argument it sends. crabpot builds no such argument, so it caps the two
/// things the figure is really about: the whole direct line, and the command,
/// which stays on the line in either form. A command past it is refused here
/// rather than handed to an `exec` that answers E2BIG.
///
/// Upstream reads the page size from `/proc/self/auxv` and so takes 2 MiB on a
/// 64 KiB-page host. crabpot takes the 4 KiB floor, which only moves a profile
/// to the args file sooner than it had to.
///
/// The args file lifts this figure off the flags `bwrap` reads from it, and off
/// none of the words `bwrap` hands to `exec` when it runs the command.
pub const MAX_ARG_STRLEN: usize = 32 * 4096 - 1;

/// The fd `bwrap` reads its `--args` words from, and the fd the args-file form
/// hands it.
///
/// One digit, because the shell dash is `/bin/sh` to many hosts rejects a
/// redirection to a multi-digit fd. High, because a caller hands the command
/// low fds of its own.
pub const BWRAP_ARGS_FD: u32 = 9;

/// Room left below [`MAX_ARG_STRLEN`] when deciding whether the flags stay on
/// the line: the caller's environment shares the `exec` budget with its words.
const ARG_HEADROOM_BYTES: usize = 4096;

/// Where the args-file form finds the shell that opens the args file.
const SH: &str = "/bin/sh";

/// The word that ends the flags and starts the command.
const SEPARATOR: &str = "--";

/// The name the args-file shell gives itself: `$0`, which `shift` drops. A
/// name and not a path, since nothing runs it.
const ARGS_LABEL: &str = "crabpot-args";

/// The shell line the args-file form runs in place of `bwrap`: it opens the
/// args file as [`BWRAP_ARGS_FD`], drops it from the words, and execs the
/// rest. `$0` is [`ARGS_LABEL`], and `$1` the args file.
fn args_wrapper() -> String {
    format!("exec {BWRAP_ARGS_FD}<\"$1\" && shift && exec \"$@\"")
}

/// An args file: where a child opens the words from, and the descriptor that
/// holds them open. Closing the descriptor is what deletes the file.
struct ArgsFile {
    // This process's own descriptor entry, which a child opens read-only.
    path: PathBuf,
    // The descriptor the caller keeps open for as long as its child runs.
    fd: OwnedFd,
}

/// A bwrap invocation ready to spawn.
#[derive(Debug)]
pub struct Rendered {
    /// The command to spawn: `bwrap` with the flags and the command as its
    /// arguments, or `/bin/sh` with the flags in the args file.
    pub command: Command,
    /// The args file's descriptor, which the caller keeps open for as long as
    /// `command` runs. `None` when the words went to `bwrap` directly.
    ///
    /// It is close-on-exec: `command`'s own shell reaches the file through the
    /// path this process's `/proc` entry gives it, and holds no descriptor of
    /// its own. The caller closes this one once `command` has finished, which
    /// is what deletes the file.
    pub args_file: Option<OwnedFd>,
}

/// Render `words`, the words of one bwrap invocation with `bwrap` itself
/// first, running `command` inside the sandbox.
///
/// `words` is never empty: its first word names the `bwrap` to run, which a
/// host that keeps it elsewhere sets from `bwrapPath`.
///
/// `args_dir` is the directory the args file is opened in when the line the
/// words make is too long for one `exec` argument.
///
/// The command's own bytes are capped at [`MAX_ARG_STRLEN`] in either form,
/// since the command stays on the line in both.
pub fn render(
    words: &[OsString],
    command: &[OsString],
    args_dir: &Path,
) -> Result<Rendered, ArgvError> {
    debug_assert!(!words.is_empty(), "a bwrap invocation names bwrap");

    // What bwrap counts, which is every word of the line but the binary.
    let total = (words.len() - 1) + 1 + command.len();
    if total > BWRAP_MAX_ARGS {
        return Err(ArgvError::TooManyArguments { words: total });
    }

    for word in words.iter().chain(command) {
        if holds_nul(word) {
            return Err(ArgvError::NulInPath { word: word.clone() });
        }
    }

    // The command stays on the line in either form, so its own bytes are
    // capped. Checking them one word at a time is not enough: 20 words of
    // 120_000 bytes each fit every word limit and overflow the exec call that
    // has to take them.
    let command_bytes = command.iter().map(|word| word.len() + 1).sum::<usize>();
    if command_bytes > MAX_ARG_STRLEN {
        return Err(ArgvError::CommandTooLong {
            bytes: command_bytes,
        });
    }

    let inline_bytes = words.iter().map(|word| word.len() + 1).sum::<usize>()
        + SEPARATOR.len()
        + 1
        + command_bytes;

    if inline_bytes + ARG_HEADROOM_BYTES <= MAX_ARG_STRLEN {
        let mut bwrap = Command::new(&words[0]);
        bwrap.args(&words[1..]);
        bwrap.arg(SEPARATOR);
        bwrap.args(command);
        return Ok(Rendered {
            command: bwrap,
            args_file: None,
        });
    }

    render_through_args_file(words, command, args_dir, total)
}

/// Render the invocation with its flags in an args file, which is the form a
/// policy too long for one `exec` line takes. The command stays on the line.
fn render_through_args_file(
    words: &[OsString],
    command: &[OsString],
    args_dir: &Path,
    total: usize,
) -> Result<Rendered, ArgvError> {
    // `--args <fd>` are two more words for bwrap to parse.
    if total + 2 > BWRAP_MAX_ARGS {
        return Err(ArgvError::TooManyArguments { words: total + 2 });
    }

    let file =
        open_args_file(args_dir, &words[1..]).map_err(|error| ArgvError::ArgsFileUnavailable {
            dir: args_dir.to_path_buf(),
            reason: error.kind(),
        })?;

    Ok(Rendered {
        command: args_file_argv(&file.path, words, command),
        args_file: Some(file.fd),
    })
}

/// The `/bin/sh` line that stands in for bwrap when its flags are in an args
/// file: it opens the file at `path` as [`BWRAP_ARGS_FD`], drops that path from
/// the words, and execs bwrap with `--args <fd>` where the flags were. The
/// command and the `--` that starts it stay on the line.
fn args_file_argv(path: &Path, words: &[OsString], command: &[OsString]) -> Command {
    debug_assert!(!words.is_empty(), "a bwrap invocation names bwrap");

    let mut sh = Command::new(SH);
    sh.arg("-c")
        .arg(args_wrapper())
        .arg(ARGS_LABEL)
        .arg(path)
        .arg(&words[0])
        .arg("--args")
        .arg(BWRAP_ARGS_FD.to_string())
        .arg(SEPARATOR)
        .args(command);
    sh
}

/// Open the args file. Only Linux has one: it is bwrap that overflows, and
/// `O_TMPFILE` is Linux's.
#[cfg(target_os = "linux")]
fn open_args_file(dir: &Path, flags: &[OsString]) -> io::Result<ArgsFile> {
    file::open(dir, flags)
}

/// There is no args file to open off Linux, and the caller is told so.
#[cfg(not(target_os = "linux"))]
fn open_args_file(_dir: &Path, _flags: &[OsString]) -> io::Result<ArgsFile> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "only Linux opens a bwrap args file",
    ))
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
    /// The command carries more bytes than [`MAX_ARG_STRLEN`], which no form
    /// of the invocation can hand to `exec`.
    CommandTooLong {
        /// How many bytes its words and the NUL that ends each one take.
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
                "the command carries {bytes} bytes, and {MAX_ARG_STRLEN} is the most an `exec` line takes here"
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
fn holds_nul(word: &OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt;

    word.as_bytes().contains(&0)
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
                words: BWRAP_MAX_ARGS + 2
            }
        );
    }

    /// A command long enough that the line no longer fits one `exec` argument,
    /// and short enough that the command on its own still fits. Its 1150 words
    /// of 110 bytes are 127_650 of the 131_071 a command may carry, and the
    /// flags put the whole line past the 126_975 that stays on the line.
    fn long_command() -> Vec<OsString> {
        (0..1_150)
            .map(|n| OsString::from(format!("{n:0<110}")))
            .collect()
    }

    /// Where this process's own descriptor `fd` can be opened again.
    #[cfg(target_os = "linux")]
    fn proc_fd(fd: &std::os::fd::OwnedFd) -> String {
        use std::os::fd::AsRawFd;

        format!("/proc/{}/fd/{}", std::process::id(), fd.as_raw_fd())
    }

    /// The words that follow the args file's path on the line that replaces
    /// bwrap: the flags are gone, and the command is all of it.
    #[test]
    fn the_args_file_line_splices_the_flags_and_keeps_the_command() {
        let long = long_command();
        let sh = args_file_argv(Path::new("/proc/4242/fd/9"), &words(), &long);
        assert_eq!(sh.get_program(), OsStr::new(SH));

        let head = [
            "-c",
            "exec 9<\"$1\" && shift && exec \"$@\"",
            "crabpot-args",
            "/proc/4242/fd/9",
            BWRAP,
            "--args",
            "9",
            "--",
        ]
        .map(OsStr::new);

        let args = sh.get_args().collect::<Vec<_>>();
        assert_eq!(&args[..head.len()], &head[..]);
        let tail = long.iter().map(OsString::as_os_str).collect::<Vec<_>>();
        assert_eq!(&args[head.len()..], &tail[..]);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn a_long_command_moves_the_words_to_the_args_file() {
        use std::os::unix::ffi::OsStrExt;

        let command = long_command();
        let rendered =
            render(&words(), &command, &std::env::temp_dir()).expect("the words fit the args file");
        let fd = rendered
            .args_file
            .expect("a line past the string limit moves the words to the args file");

        assert_eq!(rendered.command.get_program(), OsStr::new(SH));

        let path = proc_fd(&fd);
        let head = [
            "-c",
            "exec 9<\"$1\" && shift && exec \"$@\"",
            "crabpot-args",
            path.as_str(),
            BWRAP,
            "--args",
            "9",
            "--",
        ]
        .map(OsStr::new);

        let args = rendered.command.get_args().collect::<Vec<_>>();
        assert_eq!(&args[..head.len()], &head[..]);
        let tail = command.iter().map(OsString::as_os_str).collect::<Vec<_>>();
        assert_eq!(&args[head.len()..], &tail[..]);

        // The flags are in the file the line points at, and the command is not.
        let args_file = std::fs::read(&path).expect("the args file the line points at");
        let mut words_in_file = words();
        words_in_file.remove(0);
        let mut expected_words: Vec<u8> = Vec::new();
        for word in &words_in_file {
            expected_words.extend_from_slice(word.as_bytes());
            expected_words.push(0);
        }
        assert_eq!(args_file, expected_words);
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn an_args_file_is_refused_where_no_bwrap_overflows() {
        let dir = std::env::temp_dir();

        let error = render(&words(), &long_command(), &dir)
            .expect_err("only Linux opens an args file, so a line that needs one is refused");
        assert_eq!(
            error,
            ArgvError::ArgsFileUnavailable {
                dir,
                reason: std::io::ErrorKind::Unsupported,
            }
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
                bytes: MAX_ARG_STRLEN + 2
            }
        );
    }

    #[test]
    fn many_words_past_the_string_limit_together_are_refused() {
        // Each word is short enough for one `exec` argument on its own, and
        // together they are more than any `exec` call takes.
        let long = (0..20)
            .map(|_| OsString::from("x".repeat(120_000)))
            .collect::<Vec<_>>();

        let error = render(&words(), &long, Path::new("/tmp"))
            .expect_err("20 words of 120_000 bytes overflow the exec line");
        assert_eq!(
            error,
            ArgvError::CommandTooLong {
                bytes: 20 * (120_000 + 1)
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
