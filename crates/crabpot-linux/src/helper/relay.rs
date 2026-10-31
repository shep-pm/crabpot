//! The relay in the command's network namespace, outside its PID namespace (ADR-0014).
//!
//! It is the helper's child in the PID namespace bwrap made, so the command,
//! which gets one of its own below it, cannot see or signal it. It is forked
//! before any filter is installed, so it keeps `AF_UNIX`, which is the one
//! thing the command is denied. The helper waits for it to listen, so the
//! command never runs before the ports answer.
//!
//! It also receives the connections the launcher accepts for `network.publish`.
//! Each arrives as a descriptor with the address it came in on. The relay dials
//! that address inside the network namespace and copies both ways.

use core::time::Duration;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;
use std::thread;

use nix::sys::prctl;
use nix::sys::signal::Signal;
use nix::unistd::{ForkResult, dup2_stderr, dup2_stdin, dup2_stdout, pipe};

use super::init::{InitError, Step};
use super::sys;
use crate::net::relay::{bind, bind_loopback, serve, serve_tunnel};
use crate::net::ssh;
use crate::net::{HTTP_PORT, SOCKS_PORT};

/// How long dialing a published address inside the sandbox may take. The
/// address is on this host, so a command that has not accepted by then is stuck.
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

/// What the relay writes to the helper once both ports listen.
const READY: u8 = b'+';

/// What the relay writes first when it cannot listen, then the reason.
const FAILED: u8 = b'-';

/// Forks the relay for the proxy socket at `socket` and returns once it
/// listens on [`HTTP_PORT`] and [`SOCKS_PORT`]. With a `published` descriptor it
/// goes to the relay, and this process closes its copy.
///
/// # Errors
///
/// A step that failed, or [`InitError::Relay`] when the relay could not listen
/// or ended before it did.
pub(super) fn start(
    socket: &Path,
    tcp: &[SocketAddr],
    published: Option<OwnedFd>,
) -> Result<(), InitError> {
    let (report, announce) = pipe().map_err(|reason| InitError::step(Step::Relay, reason))?;
    match sys::fork().map_err(|reason| InitError::step(Step::Fork, reason))? {
        ForkResult::Child => {
            drop(report);
            run(announce, socket, tcp, published)
        }
        ForkResult::Parent { .. } => {
            drop(published);
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
fn run(announce: OwnedFd, socket: &Path, tcp: &[SocketAddr], published: Option<OwnedFd>) -> ! {
    // It ends with the helper, however the helper ends.
    let _ = prctl::set_pdeathsig(Signal::SIGKILL);
    // It holds the proxy credential in its environment, which no other process
    // of the user's may read from `/proc`.
    let _ = prctl::set_dumpable(false);
    let mut announce = File::from(announce);
    let (proxies, tunnels) = match listen(tcp) {
        Ok(listeners) => listeners,
        Err(reason) => {
            let _ = announce.write_all(&[&[FAILED][..], reason.as_bytes()].concat());
            std::process::exit(1)
        }
    };
    let basic = if tcp.is_empty() {
        String::new()
    } else {
        match std::env::var(ssh::CREDENTIAL_VARIABLE) {
            Ok(basic) => basic,
            Err(_) => {
                let _ = announce.write_all(&[&[FAILED][..], b"missing proxy credential"].concat());
                std::process::exit(1)
            }
        }
    };
    let _ = announce.write_all(&[READY]);
    drop(announce);
    detach();
    let socket = socket.to_owned();
    for (listener, address) in tunnels.into_iter().zip(tcp) {
        let socket = socket.clone();
        let basic = basic.clone();
        let target = address.to_string();
        thread::spawn(move || serve_tunnel(&listener, &socket, &target, &basic));
    }
    for listener in proxies {
        let socket = socket.clone();
        thread::spawn(move || serve(&listener, &socket));
    }
    if let Some(channel) = published {
        thread::spawn(move || serve_published(&channel));
    }
    // The relay ends with the helper, and has nothing else to do until then.
    loop {
        thread::park();
    }
}

/// The listeners of the HTTP and SOCKS ports, and one for each TCP grant.
fn listen(tcp: &[SocketAddr]) -> Result<(Vec<TcpListener>, Vec<TcpListener>), String> {
    let mut proxies = Vec::new();
    for port in [HTTP_PORT, SOCKS_PORT] {
        // A wildcard listener holds its port on every address, so a grant at
        // that port on another address would find it taken. The command
        // reaches the proxy as `localhost`, which loopback alone answers.
        let bound = if tcp.iter().any(|address| address.port() == port) {
            bind_loopback(port)
        } else {
            bind(port).map(|listener| vec![listener])
        };
        proxies.extend(bound.map_err(|error| format!("cannot listen on port {port}: {error}"))?);
    }
    let tunnels = tcp
        .iter()
        .map(|address| {
            TcpListener::bind(address)
                .map_err(|error| format!("cannot listen on {address}: {error}"))
        })
        .collect::<Result<_, _>>()?;
    Ok((proxies, tunnels))
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

/// Dials and copies each connection that arrives on `channel`, until the
/// launcher hangs up or the channel fails.
fn serve_published(channel: &OwnedFd) {
    loop {
        match sys::receive_connection(channel.as_fd()) {
            Ok(accepted) => {
                thread::spawn(move || forward_published(accepted));
            }
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {}
            Err(_) => return,
        }
    }
}

/// Copies between the host's `accepted` connection and the command's listener
/// on the address it came in on. A command that is not listening there yet
/// leaves the connection to close when this returns.
fn forward_published(accepted: sys::Accepted) {
    let client = TcpStream::from(accepted.connection);
    let Some(command) = dial(accepted.address) else {
        return;
    };
    let _ = client.set_nonblocking(false);
    let _ = copy_both_ways(&client, &command);
}

/// A connection to the first of the addresses a command listening on `published`
/// answers on, inside the sandbox.
fn dial(published: SocketAddr) -> Option<TcpStream> {
    inside(published)
        .into_iter()
        .find_map(|address| TcpStream::connect_timeout(&address, DIAL_TIMEOUT).ok())
}

/// Where a command that bound `published` is reached from inside the sandbox.
/// A wildcard is reached on loopback, and a command bound to IPv4 only answers
/// an IPv6 wildcard's clients there too.
fn inside(published: SocketAddr) -> Vec<SocketAddr> {
    let port = published.port();
    match published.ip() {
        ip if ip.is_ipv4() && ip.is_unspecified() => vec![(Ipv4Addr::LOCALHOST, port).into()],
        ip if ip.is_unspecified() => vec![
            (Ipv6Addr::LOCALHOST, port).into(),
            (Ipv4Addr::LOCALHOST, port).into(),
        ],
        _ => vec![published],
    }
}

/// Copies each way until both are done. An end of input finishes one direction
/// only: it is passed on as a half-close, and the other direction goes on until
/// its own end. Both sockets close once both are done, or at once on an error.
fn copy_both_ways(left: &TcpStream, right: &TcpStream) -> io::Result<()> {
    let (mut from_left, mut to_right) = (left.try_clone()?, right.try_clone()?);
    let onward = thread::spawn(move || {
        let copied = io::copy(&mut from_left, &mut to_right);
        let _ = to_right.shutdown(Shutdown::Write);
        copied
    });
    let (mut from_right, mut to_left) = (right.try_clone()?, left.try_clone()?);
    let back = io::copy(&mut from_right, &mut to_left);
    let _ = to_left.shutdown(Shutdown::Write);
    if back.is_err() {
        // The service is gone, so the client's upload has nowhere to go.
        let _ = left.shutdown(Shutdown::Both);
        let _ = right.shutdown(Shutdown::Both);
    }
    let onward = onward
        .join()
        .map_err(|_| io::Error::other("the published copy panicked"));
    let _ = left.shutdown(Shutdown::Both);
    let _ = right.shutdown(Shutdown::Both);
    back?;
    onward??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use super::*;

    /// How long a step may take before it fails, so a stalled copy names the
    /// step and does not hold the job.
    const STEP: Duration = Duration::from_secs(10);

    fn connected_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let near = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (far, _) = listener.accept().unwrap();
        for stream in [&near, &far] {
            stream.set_read_timeout(Some(STEP)).unwrap();
        }
        (near, far)
    }

    #[test]
    fn a_service_that_stops_sending_still_receives_the_clients_upload() {
        let (mut client, left) = connected_pair();
        let (right, mut service) = connected_pair();
        let relay = thread::spawn(move || copy_both_ways(&left, &right));

        // The service ends its replies at once and goes on reading.
        service.shutdown(Shutdown::Write).unwrap();
        // The client sees that end of input only after the relay has passed it
        // on, so what it sends next comes after the service-to-client copy ended.
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        client.write_all(b"upload").unwrap();
        client.shutdown(Shutdown::Write).unwrap();

        let mut received = Vec::new();
        service.read_to_end(&mut received).unwrap();
        assert!(reply.is_empty());
        assert_eq!(received, b"upload");
        relay.join().unwrap().unwrap();
    }
}
