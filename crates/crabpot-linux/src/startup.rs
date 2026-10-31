//! The helper's acknowledgement that bwrap reached it
//!
//! A bwrap PID report precedes mount setup. Only the helper's own acknowledgement
//! distinguishes those failures from a command's exit status.

use core::sync::atomic::{AtomicU8, Ordering};
use std::fs::File;
use std::io::{self, Read};
use std::process::Command;
use std::sync::Arc;
use std::thread;

use nix::fcntl::OFlag;
use nix::unistd::pipe2;

use crate::helper::sys;

/// The first descriptor after standard I/O, inherited through bwrap by the helper.
pub const FD: u32 = 3;

/// Whether the helper has acknowledged startup through its inherited pipe.
#[derive(Debug, Clone)]
pub struct Startup(Arc<AtomicU8>);

/// The helper's startup acknowledgement so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Report {
    /// The pipe is still open and no acknowledgement has arrived.
    Pending,
    /// The helper acknowledged startup.
    Started,
    /// The pipe closed without an acknowledgement.
    Missing,
}

impl Startup {
    fn watch(mut reader: impl Read + Send + 'static) -> Self {
        let state = Arc::new(AtomicU8::new(0));
        let shared = Arc::clone(&state);
        thread::spawn(move || {
            let mut byte = [0];
            let started = reader.read_exact(&mut byte).is_ok() && byte == [1];
            shared.store(if started { 1 } else { 2 }, Ordering::Release);
        });
        Self(state)
    }

    /// The acknowledgement, or whether it can still arrive.
    #[must_use]
    pub fn report(&self) -> Report {
        match self.0.load(Ordering::Acquire) {
            0 => Report::Pending,
            1 => Report::Started,
            _ => Report::Missing,
        }
    }
}

/// Gives `command` the acknowledgement pipe as [`FD`].
///
/// Bwrap passes inherited descriptors to its command, whose helper must call [`notify`].
///
/// # Errors
///
/// The pipe or descriptor-copy error when the process has no descriptors left.
pub fn attach(command: &mut Command) -> io::Result<Startup> {
    let (read, write) = pipe2(OFlag::O_CLOEXEC).map_err(io::Error::from)?;
    sys::pass_in_child(command, write, FD)?;
    Ok(Startup::watch(File::from(read)))
}

/// Acknowledges helper startup and closes [`FD`] before any descendants run.
///
/// # Errors
///
/// The write error when [`FD`] is closed or its reader has gone away.
pub fn notify() -> io::Result<()> {
    sys::notify_started(FD)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn only_a_helper_acknowledgement_counts_as_started() {
        for (bytes, expected) in [
            (&b"\x01"[..], Report::Started),
            (&b""[..], Report::Missing),
            (&b"x"[..], Report::Missing),
        ] {
            let startup = Startup::watch(bytes);
            let deadline = Instant::now() + Duration::from_secs(5);
            let report = loop {
                let report = startup.report();
                if report != Report::Pending {
                    break report;
                }
                assert!(Instant::now() < deadline, "startup reader did not finish");
                thread::yield_now();
            };
            assert_eq!(report, expected);
            assert_eq!(startup.report(), expected, "the result remains available");
        }
    }
}
