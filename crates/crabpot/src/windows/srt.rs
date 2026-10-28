//! The calls a session makes to srt-win, and the seam they are made through.

use core::fmt;
use std::io;
#[cfg(windows)]
use std::io::Write;
#[cfg(windows)]
use std::process::{Command, Stdio};

/// One srt-win call: its arguments after `srt-win`, and what it reads from
/// standard input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Call {
    pub(crate) args: Vec<String>,
    pub(crate) stdin: Option<String>,
}

impl Call {
    /// A call that reads nothing.
    pub(crate) fn new<S: Into<String>>(args: impl IntoIterator<Item = S>) -> Self {
        Self {
            args: args.into_iter().map(Into::into).collect(),
            stdin: None,
        }
    }
}

/// What a call printed and how it ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Output {
    /// The exit code, or `None` when a signal ended it.
    pub(crate) code: Option<i32>,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

impl Output {
    pub(crate) fn succeeded(&self) -> bool {
        self.code == Some(0)
    }
}

/// Where a session's calls go: srt-win, or a stand-in in a test.
pub(crate) trait Srt: fmt::Debug + Send + Sync {
    /// Runs `call` and waits for it.
    ///
    /// # Errors
    ///
    /// The [`io::Error`] of a call that could not be started or read.
    fn run(&self, call: &Call) -> io::Result<Output>;
}

/// srt-win as this binary runs it again with `--srt-win`.
#[cfg(windows)]
#[derive(Debug)]
pub(crate) struct Process;

#[cfg(windows)]
impl Srt for Process {
    fn run(&self, call: &Call) -> io::Result<Output> {
        let mut child = Command::new(std::env::current_exe()?)
            .arg(crabpot_windows::SRT_WIN_DISPATCH_ARG1)
            .args(&call.args)
            .stdin(if call.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        // Written from a thread of its own, so a call that fills its output
        // before it has read all of its input does not wait on this one.
        let writer = child
            .stdin
            .take()
            .zip(call.stdin.clone())
            .map(|(mut pipe, text)| std::thread::spawn(move || pipe.write_all(text.as_bytes())));
        let output = child.wait_with_output()?;
        if let Some(writer) = writer {
            // A call that exits without reading its input closes the pipe
            // under the write, and its exit code is the answer.
            let _ = writer.join();
        }
        Ok(Output {
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

/// A stand-in for srt-win that records its calls and answers from a script.
#[cfg(test)]
pub(crate) mod fake {
    use std::sync::{Arc, Mutex, PoisonError};

    use super::*;

    type Reply = Box<dyn Fn(&Call) -> Output + Send + Sync>;

    /// The calls a [`Fake`] has been given, in order.
    #[derive(Debug, Clone, Default)]
    pub(crate) struct Calls(Arc<Mutex<Vec<Call>>>);

    impl Calls {
        pub(crate) fn all(&self) -> Vec<Call> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }

        /// The calls whose arguments start with `prefix`.
        pub(crate) fn starting(&self, prefix: &[&str]) -> Vec<Call> {
            self.all()
                .into_iter()
                .filter(|call| {
                    call.args.len() >= prefix.len()
                        && call.args.iter().zip(prefix).all(|(a, b)| a == b)
                })
                .collect()
        }
    }

    pub(crate) struct Fake {
        calls: Calls,
        reply: Reply,
    }

    impl fmt::Debug for Fake {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("Fake").field("calls", &self.calls).finish()
        }
    }

    /// An output that ended with `code` and printed `stdout`.
    pub(crate) fn exit(code: i32, stdout: &str) -> Output {
        Output {
            code: Some(code),
            stdout: stdout.to_owned(),
            stderr: String::new(),
        }
    }

    /// An output that ended with `code` and printed `stderr`.
    pub(crate) fn fail(code: i32, stderr: &str) -> Output {
        Output {
            stderr: stderr.to_owned(),
            ..exit(code, "")
        }
    }

    /// A `wfp verify` answer for a fence that blocks the plain attempt.
    pub(crate) const BLOCKED: &str = r#"{"egress_probe":"blocked","target":"127.0.0.1:1"}"#;

    impl Fake {
        /// A srt-win where every call succeeds and the fence holds.
        pub(crate) fn passing() -> (Self, Calls) {
            Self::answering(|call| {
                if call
                    .args
                    .starts_with(&["wfp".to_owned(), "verify".to_owned()])
                {
                    exit(0, BLOCKED)
                } else {
                    exit(0, "[]")
                }
            })
        }

        /// A srt-win that answers each call with `reply`.
        pub(crate) fn answering(
            reply: impl Fn(&Call) -> Output + Send + Sync + 'static,
        ) -> (Self, Calls) {
            let calls = Calls::default();
            (
                Self {
                    calls: calls.clone(),
                    reply: Box::new(reply),
                },
                calls,
            )
        }
    }

    impl Srt for Fake {
        fn run(&self, call: &Call) -> io::Result<Output> {
            self.calls
                .0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(call.clone());
            Ok((self.reply)(call))
        }
    }
}
