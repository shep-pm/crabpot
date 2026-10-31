//! The helper's acknowledgement that bwrap reached it
//!
//! A bwrap PID report precedes mount setup. Only the helper's own acknowledgement
//! distinguishes those failures from a command's exit status.

use core::sync::atomic::{AtomicU8, Ordering};
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, OwnedFd};
use std::process::Command;
use std::sync::Arc;
use std::thread;

use nix::fcntl::OFlag;
use nix::unistd::pipe2;

use crate::helper::sys;

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

/// The acknowledgement pipe, before a command is given its write end.
#[derive(Debug)]
pub struct Pipe {
    read: OwnedFd,
    write: OwnedFd,
}

impl Pipe {
    /// Opens the pipe. The write end sits above every descriptor the launcher
    /// can have inherited, so the command keeps what it was handed.
    ///
    /// # Errors
    ///
    /// The pipe or descriptor-copy error when the process has no descriptors left.
    pub fn open() -> io::Result<Self> {
        let (read, write) = pipe2(OFlag::O_CLOEXEC).map_err(io::Error::from)?;
        Ok(Self {
            read,
            write: sys::copy_above_reserved(write)?,
        })
    }

    /// The write end's descriptor number in `command`'s child, which the helper
    /// passes to [`notify`].
    #[must_use]
    pub fn fd(&self) -> u32 {
        u32::try_from(self.write.as_raw_fd()).unwrap_or(u32::MAX)
    }

    /// Gives `command` the write end under [`Pipe::fd`].
    ///
    /// Bwrap passes inherited descriptors to its command, whose helper must call [`notify`].
    pub fn attach(self, command: &mut Command) -> Startup {
        sys::keep_in_child(command, self.write);
        Startup::watch(File::from(self.read))
    }
}

/// Acknowledges helper startup through `fd` and closes it before any descendants run.
///
/// # Errors
///
/// The write error when `fd` is closed or its reader has gone away.
pub fn notify(fd: u32) -> io::Result<()> {
    sys::notify_started(fd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn the_write_end_is_above_the_descriptors_a_launcher_can_inherit() {
        let pipe = Pipe::open().unwrap();
        assert!(pipe.fd() >= 10, "{}", pipe.fd());
    }

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
