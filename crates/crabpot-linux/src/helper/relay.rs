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
//! that address inside the network namespace and copies both ways. The launcher
//! first sends each published address alone, and the relay sends it back once
//! the namespace's `/proc/net/tcp` and `/proc/net/tcp6` show a listening socket
//! there, which is when the launcher starts accepting on the host.

use core::time::Duration;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;
use std::sync::Arc;
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

/// How often the relay looks again for a command that is not listening yet.
const LISTEN_POLL: Duration = Duration::from_millis(20);

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
        let channel = Arc::new(channel);
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

/// Dials and copies each connection that arrives on `channel`, and watches each
/// address that arrives alone, until the launcher hangs up or the channel fails.
fn serve_published(channel: &Arc<OwnedFd>) {
    loop {
        match sys::receive(channel.as_fd()) {
            Ok(sys::Received::Connection(accepted)) => {
                thread::spawn(move || forward_published(accepted));
            }
            Ok(sys::Received::Address(address)) => {
                let channel = Arc::clone(channel);
                thread::spawn(move || announce_when_listening(&channel, address));
            }
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {}
            Err(_) => return,
        }
    }
}

/// Sends `published` back on `channel` once a command listens where the relay
/// would dial it. The table is read, never dialled: a connection would reach
/// the command.
fn announce_when_listening(channel: &OwnedFd, published: SocketAddr) {
    while !is_listening(published) {
        thread::sleep(LISTEN_POLL);
    }
    let _ = sys::send_address(channel.as_fd(), published);
}

/// Whether a socket in this network namespace listens on an address that
/// [`dial`] would reach for `published`.
fn is_listening(published: SocketAddr) -> bool {
    let targets = inside(published);
    ["/proc/net/tcp", "/proc/net/tcp6"].iter().any(|path| {
        std::fs::read_to_string(path).is_ok_and(|table| {
            listening_addresses(&table)
                .any(|listener| targets.iter().any(|target| accepts(listener, *target)))
        })
    })
}

/// The local addresses of the sockets in the `LISTEN` state in `table`, the text
/// of `/proc/net/tcp` or `/proc/net/tcp6`.
fn listening_addresses(table: &str) -> impl Iterator<Item = SocketAddr> + '_ {
    table.lines().skip(1).filter_map(|line| {
        let mut columns = line.split_whitespace();
        let local = columns.nth(1)?;
        // The state follows the remote address.
        let state = columns.nth(1)?;
        if state != LISTEN_STATE {
            return None;
        }
        let (ip, port) = local.split_once(':')?;
        let port = u16::from_str_radix(port, 16).ok()?;
        Some(SocketAddr::new(table_ip(ip)?, port))
    })
}

/// The `st` column of a socket in the `LISTEN` state.
const LISTEN_STATE: &str = "0A";

/// An address as the tables print it: each four bytes of it are one hexadecimal
/// number, in the byte order of the machine.
fn table_ip(text: &str) -> Option<IpAddr> {
    let mut bytes = Vec::new();
    for word in text.as_bytes().chunks(8) {
        let word = u32::from_str_radix(core::str::from_utf8(word).ok()?, 16).ok()?;
        bytes.extend_from_slice(&word.to_ne_bytes());
    }
    match bytes.len() {
        4 => Some(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).ok()?).into()),
        16 => Some(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?).into()),
        _ => None,
    }
}

/// Whether a socket listening on `listener` takes a connection to `target`. An
/// IPv6 wildcard is taken to be dual-stack, which the tables do not say.
fn accepts(listener: SocketAddr, target: SocketAddr) -> bool {
    listener.port() == target.port()
        && match (listener.ip(), target.ip()) {
            (IpAddr::V4(listener), IpAddr::V4(target)) => {
                listener == target || listener.is_unspecified()
            }
            (IpAddr::V6(listener), IpAddr::V6(target)) => {
                listener == target || listener.is_unspecified()
            }
            (IpAddr::V6(listener), IpAddr::V4(target)) => {
                listener.is_unspecified() || listener == target.to_ipv6_mapped()
            }
            (IpAddr::V4(_), IpAddr::V6(_)) => false,
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

    /// The header and rows as the kernel prints them, on a little-endian machine.
    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 11111 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F91 0100007F:C000 01 00000000:00000000 00:00000000 00000000  1000        0 22222 1 0000000000000000 100 0 0 10 0
   2: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 33333 1 0000000000000000 100 0 0 10 0
";

    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:1F92 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 44444 1 0000000000000000 100 0 0 10 0
   1: 0000000000000000FFFF00000100007F:1F93 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 55555 1 0000000000000000 100 0 0 10 0
";

    #[test]
    fn only_sockets_in_the_listen_state_are_listening_addresses() {
        let listening: Vec<_> = listening_addresses(TCP).collect();

        assert_eq!(
            listening,
            [
                SocketAddr::from((Ipv4Addr::LOCALHOST, 8080)),
                SocketAddr::from((Ipv4Addr::UNSPECIFIED, 80)),
            ]
        );
    }

    #[test]
    fn an_ipv6_table_names_its_addresses_in_ipv6() {
        let listening: Vec<_> = listening_addresses(TCP6).collect();

        assert_eq!(
            listening,
            [
                SocketAddr::from((Ipv6Addr::LOCALHOST, 8082)),
                SocketAddr::from((Ipv4Addr::LOCALHOST.to_ipv6_mapped(), 8083)),
            ]
        );
    }

    #[test]
    fn a_table_with_no_rows_or_with_rubbish_lists_nothing() {
        assert_eq!(listening_addresses("").count(), 0);
        assert_eq!(
            listening_addresses("header\nnot a row\n1: zz:yy a 0A\n").count(),
            0
        );
    }

    #[test]
    fn a_listener_takes_a_connection_to_its_own_address_and_to_a_wildcard_of_its_family() {
        let at = |ip: IpAddr| SocketAddr::new(ip, 80);
        let (v4, v6) = (Ipv4Addr::LOCALHOST, Ipv6Addr::LOCALHOST);

        assert!(accepts(at(v4.into()), at(v4.into())));
        assert!(accepts(at(Ipv4Addr::UNSPECIFIED.into()), at(v4.into())));
        assert!(accepts(at(v6.into()), at(v6.into())));
        assert!(accepts(at(Ipv6Addr::UNSPECIFIED.into()), at(v6.into())));
        assert!(accepts(at(Ipv6Addr::UNSPECIFIED.into()), at(v4.into())));
        assert!(accepts(at(v4.to_ipv6_mapped().into()), at(v4.into())));
    }

    #[test]
    fn a_listener_does_not_take_another_port_another_address_or_another_family() {
        let at = |ip: IpAddr, port| SocketAddr::new(ip, port);
        let (v4, v6) = (Ipv4Addr::LOCALHOST, Ipv6Addr::LOCALHOST);

        assert!(!accepts(at(v4.into(), 80), at(v4.into(), 81)));
        assert!(!accepts(
            at(Ipv4Addr::new(10, 0, 0, 5).into(), 80),
            at(v4.into(), 80)
        ));
        assert!(!accepts(at(v4.into(), 80), at(v6.into(), 80)));
        assert!(!accepts(at(v6.into(), 80), at(v4.into(), 80)));
    }

    #[test]
    fn an_address_is_listening_only_while_a_socket_listens_on_it() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        assert!(is_listening(address));
        let wildcard = SocketAddr::from((Ipv4Addr::UNSPECIFIED, address.port()));
        assert!(is_listening(wildcard), "a wildcard is dialled on loopback");

        drop(listener);

        assert!(!is_listening(address));
    }

    #[test]
    fn looking_for_a_listener_opens_no_connection_to_it() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();

        assert!(is_listening(listener.local_addr().unwrap()));

        let seen = listener.accept().unwrap_err();
        assert_eq!(seen.kind(), io::ErrorKind::WouldBlock);
    }
}
