//! `--control-fd`: JSON lines on a descriptor that replace the network lists of
//! the running sandbox, as upstream's control descriptor does.
//!
//! Each line is a full config in the `-s` shape, and only its network lists are
//! taken (see [`Sandbox::replace_network_lists`]). The reader runs on a thread
//! of its own for as long as the wrapper runs the command.

mod sys;

#[cfg(test)]
mod tests;

use core::fmt;
use std::fs::File;
use std::io::{self, BufRead, BufReader, PipeWriter, Read, Write};
use std::os::fd::{AsFd, RawFd};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use crabpot_core::config::Config;

use crate::sandbox::Sandbox;

/// What a line may change: the network lists of a running sandbox.
pub(crate) trait Lists: Send + Sync + 'static {
    /// Replaces the lists with those of `config.network`.
    fn replace_network_lists(&self, config: &Config);
}

impl Lists for Sandbox {
    fn replace_network_lists(&self, config: &Config) {
        Sandbox::replace_network_lists(self, config);
    }
}

/// Why the control descriptor cannot be followed.
#[derive(Debug)]
pub(crate) enum ControlError {
    /// The descriptor is not open, or `/dev/null` could not be put in its place.
    Descriptor(io::Error),
    /// The descriptor failed to read before any line came.
    Read(io::Error),
}

impl fmt::Display for ControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Descriptor(e) => write!(f, "cannot use the control descriptor: {e}"),
            Self::Read(e) => write!(f, "cannot read the control descriptor: {e}"),
        }
    }
}

impl core::error::Error for ControlError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Descriptor(e) | Self::Read(e) => Some(e),
        }
    }
}

/// Applies each line of `input` to `lists`, until the end of the input. A line
/// that does not parse is ignored, with one message in `said`.
///
/// # Errors
///
/// Whatever reading `input` fails with. The lists keep what lines came before.
fn follow(input: &mut impl BufRead, lists: &impl Lists, said: &mut impl Write) -> io::Result<()> {
    let mut line = Vec::new();
    loop {
        line.clear();
        if input.read_until(b'\n', &mut line)? == 0 {
            return Ok(());
        }
        let config = std::str::from_utf8(&line)
            .map_err(|_| "not UTF-8".to_owned())
            .and_then(|text| Config::from_json(text).map_err(|e| e.to_string()));
        match config {
            Ok(config) => lists.replace_network_lists(&config),
            Err(reason) => writeln!(said, "crabpot: control line ignored: {reason}")?,
        }
    }
}

/// The descriptor, read until the wake pipe's write end closes.
#[derive(Debug)]
struct Waking {
    input: File,
    wake: std::io::PipeReader,
}

impl Read for Waking {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let ready = sys::poll(self.input.as_fd(), self.wake.as_fd(), true)?;
        // What the host wrote is read to its end first, so a stop never drops a line.
        if ready.input || !ready.woken {
            self.input.read(buf)
        } else {
            Ok(0)
        }
    }
}

/// A reader of the control descriptor, running until it is dropped.
#[derive(Debug)]
pub(crate) struct Control {
    wake: Option<PipeWriter>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for Control {
    fn drop(&mut self) {
        // Closing the write end stops the reader once its input is idle.
        drop(self.wake.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Starts following the descriptor `fd` for `lists`: takes it over, leaving
/// `/dev/null` under its number for the command, and reads it on a thread.
///
/// A descriptor with data, or at its end, is read once before this returns, so
/// that a failure comes before the command starts. A descriptor with nothing
/// yet is read on the thread, and a failure there ends the reading with a
/// message. The descriptor may be close-on-exec.
///
/// # Errors
///
/// [`ControlError::Descriptor`] when `fd` is not open, and
/// [`ControlError::Read`] when its first read fails.
pub(crate) fn start<L: Lists>(fd: RawFd, lists: Arc<L>) -> Result<Control, ControlError> {
    let taken = sys::take(fd).map_err(ControlError::Descriptor)?;
    let (wake_read, wake) = io::pipe().map_err(ControlError::Descriptor)?;
    let mut input = BufReader::new(Waking {
        input: File::from(taken),
        wake: wake_read,
    });
    let idle = {
        let reader = input.get_ref();
        !sys::poll(reader.input.as_fd(), reader.wake.as_fd(), false)
            .map_err(ControlError::Descriptor)?
            .input
    };
    if !idle {
        input.fill_buf().map_err(ControlError::Read)?;
    }
    let thread = thread::Builder::new()
        .name("crabpot-control".into())
        .spawn(move || {
            if let Err(e) = follow(&mut input, &*lists, &mut io::stderr()) {
                eprintln!("crabpot: control descriptor stopped: {e}");
            }
        })
        .map_err(ControlError::Descriptor)?;
    Ok(Control {
        wake: Some(wake),
        thread: Some(thread),
    })
}
