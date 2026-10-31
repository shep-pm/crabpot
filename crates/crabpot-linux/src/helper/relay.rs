//! The relay in the command's network namespace, outside its PID namespace (ADR-0014).
//!
//! It is the helper's child in the PID namespace bwrap made, so the command,
//! which gets one of its own below it, cannot see or signal it. It is forked
//! before any filter is installed, so it keeps `AF_UNIX`, which is the one
//! thing the command is denied. The helper waits for it to listen, so the
//! command never runs before the ports answer.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::thread;

use nix::sys::prctl;
use nix::sys::signal::Signal;
use nix::unistd::{ForkResult, dup2_stderr, dup2_stdin, dup2_stdout, pipe};

use super::init::{InitError, Step};
use super::sys;
use crate::net::relay::{bind, serve};
use crate::net::{HTTP_PORT, SOCKS_PORT};

/// What the relay writes to the helper once both ports listen.
const READY: u8 = b'+';

/// What the relay writes first when it cannot listen, then the reason.
const FAILED: u8 = b'-';

/// Forks the relay for the proxy socket at `socket` and returns once it
/// listens on [`HTTP_PORT`] and [`SOCKS_PORT`].
///
/// # Errors
///
/// A step that failed, or [`InitError::Relay`] when the relay could not listen
/// or ended before it did.
pub(super) fn start(socket: &Path) -> Result<(), InitError> {
    let (report, announce) = pipe().map_err(|reason| InitError::step(Step::Relay, reason))?;
    match sys::fork().map_err(|reason| InitError::step(Step::Fork, reason))? {
        ForkResult::Child => {
            drop(report);
            run(announce, socket)
        }
        ForkResult::Parent { .. } => {
            // Only the relay's copy of the write end is left open, so its
            // close is the end of what the relay has to say.
            drop(announce);
            await_ready(File::from(report))
        }
    }
}

fn await_ready(mut report: File) -> Result<(), InitError> {
    let mut message = Vec::new();
    report
        .read_to_end(&mut message)
        .map_err(|error| InitError::Relay(error.to_string()))?;
    match message.split_first() {
        Some((&READY, _)) => Ok(()),
        Some((&FAILED, reason)) => Err(InitError::Relay(
            String::from_utf8_lossy(reason).into_owned(),
        )),
        _ => Err(InitError::Relay(
            "the relay ended before it was ready".to_owned(),
        )),
    }
}

/// The relay process: listens, says so, and forwards until it is killed.
fn run(announce: OwnedFd, socket: &Path) -> ! {
    // It ends with the helper, however the helper ends.
    let _ = prctl::set_pdeathsig(Signal::SIGKILL);
    let mut announce = File::from(announce);
    let (http, socks) = match listen() {
        Ok(listeners) => listeners,
        Err(reason) => {
            let _ = announce.write_all(&[&[FAILED][..], reason.as_bytes()].concat());
            std::process::exit(1)
        }
    };
    let _ = announce.write_all(&[READY]);
    drop(announce);
    detach();
    let socket = socket.to_owned();
    let for_http = socket.clone();
    thread::spawn(move || serve(&http, &for_http));
    serve(&socks, &socket);
    std::process::exit(0)
}

fn listen() -> Result<(TcpListener, TcpListener), String> {
    let listen =
        |port| bind(port).map_err(|error| format!("cannot listen on port {port}: {error}"));
    Ok((listen(HTTP_PORT)?, listen(SOCKS_PORT)?))
}

/// Points the relay's standard streams at `/dev/null`, so a host that waits for
/// the command's streams to close is not kept waiting for the relay.
fn detach() {
    let Ok(null) = OpenOptions::new().read(true).write(true).open("/dev/null") else {
        return;
    };
    let _ = dup2_stdin(&null);
    let _ = dup2_stdout(&null);
    let _ = dup2_stderr(&null);
}
