//! The pid bwrap reports for its sandbox, which is where the launcher sends the
//! signals it forwards.
//!
//! `--info-fd` makes bwrap write a JSON object to a descriptor once the
//! sandbox's first process exists. Its `child-pid` is that process as the host
//! sees it, which is bwrap's own init of the new PID namespace, and the helper
//! is the first process it starts.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::fs::File;
use std::io::{self, Read};
use std::process::Command;
use std::sync::Arc;
use std::thread;

use nix::fcntl::OFlag;
use nix::unistd::pipe2;

use crate::helper::sys;
use crate::wrap::INFO_FD;

/// The key whose number is the pid.
const CHILD_PID: &str = "\"child-pid\":";

/// What bwrap has reported about one sandbox so far.
#[derive(Debug, Clone)]
pub struct Info {
    /// The reported pid, or 0 before it arrives: no process has pid 0 for a
    /// host to signal.
    child: Arc<AtomicU32>,
    /// Whether the reader has stopped, with or without a pid.
    ended: Arc<AtomicBool>,
}

/// Where a bwrap's report stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Report {
    /// Nothing has arrived yet.
    Pending,
    /// bwrap reported this pid.
    Pid(u32),
    /// The report ended without a pid, so none will come.
    Missing,
}

impl Info {
    /// Reads bwrap's report from `reader` on a thread of its own.
    fn watch(reader: impl Read + Send + 'static) -> Self {
        let child = Arc::new(AtomicU32::new(0));
        let ended = Arc::new(AtomicBool::new(false));
        let (shared, done) = (Arc::clone(&child), Arc::clone(&ended));
        thread::spawn(move || {
            read_report(reader, |pid| shared.store(pid, Ordering::Release));
            done.store(true, Ordering::Release);
        });
        Self { child, ended }
    }

    /// The sandbox's first process as the host sees it, once bwrap has reported
    /// it.
    #[must_use]
    pub fn report(&self) -> Report {
        match self.child.load(Ordering::Acquire) {
            0 if self.ended.load(Ordering::Acquire) => Report::Missing,
            0 => Report::Pending,
            pid => Report::Pid(pid),
        }
    }
}

/// Gives `command` the write end of a pipe as [`INFO_FD`], which is where the
/// words of [`wrap::info_words`](crate::wrap::info_words) tell bwrap to report,
/// and returns what is read from the other end.
///
/// # Errors
///
/// The error of the `pipe2` call, when the process has no descriptors left.
pub fn attach(command: &mut Command) -> io::Result<Info> {
    let (read, write) = pipe2(OFlag::O_CLOEXEC).map_err(io::Error::from)?;
    sys::pass_in_child(command, write, INFO_FD);
    Ok(Info::watch(File::from(read)))
}

/// Reads bwrap's whole report from `reader` and hands `found` the pid in it.
///
/// bwrap writes the report in pieces: the pid, then the ids of its namespaces,
/// then the closing brace. The reader stays open until the brace, since bwrap
/// dies on a write to a pipe nobody reads, and it does not wait for the end of
/// the stream, which a process of the sandbox that inherited the descriptor
/// keeps open. The pid is handed over as soon as the byte after its digits has
/// arrived.
fn read_report(mut reader: impl Read, found: impl FnOnce(u32)) {
    let mut found = Some(found);
    let mut seen = Vec::new();
    let mut chunk = [0_u8; 256];
    loop {
        let read = reader.read(&mut chunk).unwrap_or(0);
        seen.extend_from_slice(&chunk[..read]);
        let ended = read == 0 || seen.contains(&b'}');
        if let Some(pid) = pid_in(&seen, ended)
            && let Some(found) = found.take()
        {
            found(pid);
        }
        if ended {
            return;
        }
    }
}

/// The number after `child-pid` in `seen`. With `ended` false the number only
/// counts once a byte follows it, since the next read may carry more digits.
fn pid_in(seen: &[u8], ended: bool) -> Option<u32> {
    let text = core::str::from_utf8(seen).ok()?;
    let after = text[text.find(CHILD_PID)? + CHILD_PID.len()..].trim_start();
    let digits = after.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 || (digits == after.len() && !ended) {
        return None;
    }
    after[..digits].parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reader that yields one piece per read, as bwrap's separate writes
    /// arrive.
    struct Pieces(Vec<&'static [u8]>);

    impl Read for Pieces {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.0.is_empty() {
                return Ok(0);
            }
            let piece = self.0.remove(0);
            buf[..piece.len()].copy_from_slice(piece);
            Ok(piece.len())
        }
    }

    fn pid_read(reader: impl Read) -> Option<u32> {
        let mut pid = None;
        read_report(reader, |found| pid = Some(found));
        pid
    }

    #[test]
    fn the_whole_report_is_read_after_the_pid() {
        let reader = Pieces(vec![
            b"{\n    \"child-pid\": 42",
            b",\n    \"ipc-namespace\": 1",
            b"\n}\n",
        ]);
        let mut left = 0;
        let counted = Counting {
            pieces: reader,
            left: &mut left,
        };

        assert_eq!(pid_read(counted), Some(42));
        assert_eq!(left, 0, "every piece was read, so bwrap's writes land");
    }

    /// [`Pieces`] that count what is still unread.
    struct Counting<'a> {
        pieces: Pieces,
        left: &'a mut usize,
    }

    impl Read for Counting<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let read = self.pieces.read(buf);
            *self.left = self.pieces.0.len();
            read
        }
    }

    #[test]
    fn the_pid_is_read_from_a_report_that_arrives_whole() {
        let report = b"{\n    \"child-pid\": 4242,\n    \"ipc-namespace\": 4026531839\n}\n";

        assert_eq!(pid_read(&report[..]), Some(4242));
    }

    #[test]
    fn a_pid_split_across_reads_is_not_cut_short() {
        let reader = Pieces(vec![b"{\n    \"child-pid\": 42", b"42", b"\n}\n"]);

        assert_eq!(pid_read(reader), Some(4242));
    }

    #[test]
    fn a_key_split_across_reads_is_found() {
        let reader = Pieces(vec![b"{\n    \"child-p", b"id\": 7\n}\n"]);

        assert_eq!(pid_read(reader), Some(7));
    }

    #[test]
    fn a_pid_at_the_end_of_the_stream_counts() {
        assert_eq!(pid_read(&b"{\"child-pid\": 99"[..]), Some(99));
    }

    #[test]
    fn a_report_without_a_pid_gives_none() {
        assert_eq!(pid_read(&b""[..]), None);
        assert_eq!(pid_read(&b"{\n}\n"[..]), None);
        assert_eq!(pid_read(&b"{\"child-pid\": x}"[..]), None);
    }

    #[test]
    fn the_pid_arrives_through_the_watch() {
        let info = Info::watch(&b"{\"child-pid\": 55\n}\n"[..]);

        let mut report = info.report();
        while report == Report::Pending {
            thread::yield_now();
            report = info.report();
        }
        assert_eq!(report, Report::Pid(55));
    }

    #[test]
    fn a_report_that_ends_without_a_pid_is_missing() {
        let info = Info::watch(&b"{\n}\n"[..]);

        let mut report = info.report();
        while report == Report::Pending {
            thread::yield_now();
            report = info.report();
        }
        assert_eq!(report, Report::Missing);
    }
}
