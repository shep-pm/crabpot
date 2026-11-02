//! `network.publish`: the host's listeners for the addresses a sandbox serves.
//!
//! A command in a network namespace of its own is unreachable from the host.
//! The launcher binds each published address instead, with `SO_REUSEPORT`
//! so a second sandbox may take the port during a cutover, and passes every
//! accepted connection into the sandbox as a descriptor over a socket pair. A
//! message carries the descriptor and, as text, the address it came in on. The
//! helper's relay dials that address inside the namespace.
//!
//! A bound port refuses connections until it listens, so a host that probes the
//! port sees it closed while nothing is ready inside. The launcher sends each
//! address into the pair first, and listens on it once the relay sends it back,
//! which it does when a command listens there. The port then stays open.

use core::fmt;
use std::io::{self, IoSlice};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::process::Command;
use std::thread::{self, JoinHandle};

use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::socket::{
    AddressFamily, ControlMessage, MsgFlags, SockFlag, SockType, sendmsg, socketpair,
};

use super::relay::{ACCEPT_RETRY, bind_shared, start_listening};
use crate::helper::sys;

/// Why a sandbox's published addresses could not be served.
#[derive(Debug, Clone, PartialEq, Eq)]
// A kind of failure to serve may be added without breaking a caller's `match`.
#[non_exhaustive]
pub enum PublishError {
    /// The host could not listen on `address`: another socket holds it without
    /// `SO_REUSEPORT`, it is not an address of the host, or the user may not
    /// bind its port.
    Bind {
        /// The published address.
        address: SocketAddr,
        /// How listening failed.
        reason: io::ErrorKind,
    },
    /// The socket pair into the sandbox, the thread that serves the listeners,
    /// or the hand-over of the pair to the command could not be made.
    Channel(io::ErrorKind),
}

impl fmt::Display for PublishError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bind { address, reason } => {
                write!(f, "cannot publish {address}: cannot listen: {reason}")
            }
            Self::Channel(reason) => {
                write!(
                    f,
                    "cannot pass published connections to the sandbox: {reason}"
                )
            }
        }
    }
}

impl core::error::Error for PublishError {}

/// The host's listeners for one command's published addresses, served until it
/// drops or the sandbox's end of the socket pair has closed, which every process
/// holding it exiting does. The port is free again once either has. An address
/// listens once the command inside does.
#[derive(Debug)]
pub struct Published {
    addresses: Vec<SocketAddr>,
    /// The serving thread polls the other end, and stops when this one closes.
    wake: Option<UnixStream>,
    thread: Option<JoinHandle<()>>,
}

impl Published {
    /// The addresses listened on, as bound.
    #[must_use]
    pub fn addresses(&self) -> &[SocketAddr] {
        &self.addresses
    }
}

impl Drop for Published {
    fn drop(&mut self) {
        drop(self.wake.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The inside end of the socket pair, before a command is given it.
#[derive(Debug)]
pub struct Inside(OwnedFd);

impl Inside {
    /// The descriptor number the end has in `command`'s child, which the helper
    /// takes as `--publish-fd`.
    #[must_use]
    pub fn fd(&self) -> u32 {
        u32::try_from(self.0.as_raw_fd()).unwrap_or(u32::MAX)
    }

    /// Gives `command` the end under [`Inside::fd`].
    pub fn attach(self, command: &mut Command) {
        sys::keep_in_child(command, self.0);
    }
}

/// Binds every address in `addresses`. The inside end of the socket pair
/// sits above every descriptor the launcher can have inherited, so the command
/// keeps what it was handed.
///
/// # Errors
///
/// [`PublishError::Bind`] for the first address the host cannot listen on, and
/// [`PublishError::Channel`] when the pair, the thread or the descriptor copy
/// fails.
pub fn publish(addresses: &[SocketAddr]) -> Result<(Published, Inside), PublishError> {
    let (published, inside) = serve(addresses)?;
    let inside =
        sys::copy_above_reserved(inside).map_err(|error| PublishError::Channel(error.kind()))?;
    Ok((published, Inside(inside)))
}

/// Binds every address in `addresses`, and returns the inside end of the socket
/// pair the accepted connections go over.
fn serve(addresses: &[SocketAddr]) -> Result<(Published, OwnedFd), PublishError> {
    let channel = |error: io::Error| PublishError::Channel(error.kind());
    let mut ports = Vec::new();
    for &address in addresses {
        let listener = bind_shared(address).map_err(|error| PublishError::Bind {
            address,
            reason: io::Error::from(error).kind(),
        })?;
        listener.set_nonblocking(true).map_err(channel)?;
        // The bound address names the port the system chose for port 0, and
        // leaves out an interface scope, which means nothing inside.
        let bound = listener.local_addr().map_err(channel)?;
        ports.push(Port {
            listener,
            address: SocketAddr::new(bound.ip(), bound.port()),
            watched: false,
            open: false,
        });
    }
    let (outside, inside) = socketpair(
        AddressFamily::Unix,
        // A sequenced packet pair keeps each message whole, and reports a hang-up
        // when every copy of the other end has closed, which a datagram pair
        // does not.
        SockType::SeqPacket,
        None,
        // The inside end stays blocking: the relay reads it with no poll. The
        // sending end never blocks, because it sends with `MSG_DONTWAIT`.
        SockFlag::SOCK_CLOEXEC,
    )
    .map_err(|error| channel(error.into()))?;
    let (wake, woken) = UnixStream::pair().map_err(channel)?;
    let addresses = ports.iter().map(|port| port.address).collect();
    let thread = thread::Builder::new()
        .name("publish".to_owned())
        .spawn(move || accept_all(ports, &woken, &outside))
        .map_err(channel)?;
    let published = Published {
        addresses,
        wake: Some(wake),
        thread: Some(thread),
    };
    Ok((published, inside))
}

/// One published address: bound from the start, listening once a command does.
struct Port {
    listener: TcpListener,
    address: SocketAddr,
    /// The relay has been asked to watch the address.
    watched: bool,
    open: bool,
}

/// Asks the relay to watch each address, then passes each connection the open
/// ports accept into the sandbox, and opens a port when the relay sends its
/// address back. It ends when `woken` reports its peer has hung up, or the
/// sandbox's end of the pair has closed.
fn accept_all(mut ports: Vec<Port>, woken: &UnixStream, outside: &OwnedFd) {
    loop {
        let Some(pending) = ask_to_watch(&mut ports, outside) else {
            return;
        };
        // A socket that is bound and does not listen reports a hang-up.
        let open: Vec<usize> = (0..ports.len()).filter(|&at| ports[at].open).collect();
        let mut polls: Vec<_> = open
            .iter()
            .map(|&at| PollFd::new(ports[at].listener.as_fd(), PollFlags::POLLIN))
            .collect();
        polls.push(PollFd::new(woken.as_fd(), PollFlags::POLLIN));
        // A full pair is waited on until it takes the next request.
        let wanted = if pending {
            PollFlags::POLLIN | PollFlags::POLLOUT
        } else {
            PollFlags::POLLIN
        };
        polls.push(PollFd::new(outside.as_fd(), wanted));
        match poll(&mut polls, PollTimeout::NONE) {
            Err(Errno::EINTR) => continue,
            Err(_) => return,
            Ok(_) => {}
        }
        let mut events: Vec<PollFlags> = polls
            .iter()
            .map(|polled| polled.revents().unwrap_or(PollFlags::POLLERR))
            .collect();
        let channel = events.pop().unwrap_or(PollFlags::POLLHUP);
        if !events.pop().unwrap_or(PollFlags::POLLHUP).is_empty() {
            return;
        }
        for (&at, ready) in open.iter().zip(events) {
            if !ready.is_empty() {
                accept_ready(&ports[at].listener, ports[at].address, outside);
            }
        }
        if channel.contains(PollFlags::POLLIN) {
            match sys::receive(outside.as_fd()) {
                Ok(sys::Received::Address(address)) => open_port(&mut ports, address),
                // Nothing but an address comes this way.
                Ok(sys::Received::Connection(_)) => {}
                Err(error) if error.kind() == io::ErrorKind::InvalidData => {}
                Err(_) => return,
            }
        } else if channel.intersects(PollFlags::POLLHUP | PollFlags::POLLERR | PollFlags::POLLNVAL)
        {
            return;
        }
    }
}

/// Sends the relay each address it has not been asked to watch. Whether any is
/// still waiting for room in the pair, or `None` when the relay is gone.
fn ask_to_watch(ports: &mut [Port], outside: &OwnedFd) -> Option<bool> {
    for port in ports.iter_mut().filter(|port| !port.watched) {
        match sys::send_address(outside.as_fd(), port.address) {
            Ok(()) => port.watched = true,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Some(true),
            Err(_) => return None,
        }
    }
    Some(false)
}

/// Has the port bound to `address` listen, which it keeps doing.
fn open_port(ports: &mut [Port], address: SocketAddr) {
    for port in ports
        .iter_mut()
        .filter(|port| port.address == address && !port.open)
    {
        port.open = start_listening(&port.listener).is_ok();
    }
}

/// Accepts one connection. The caller polls again, which reports a listener with
/// more waiting, so a stream of clients cannot keep it from seeing `woken`.
fn accept_ready(listener: &TcpListener, address: SocketAddr, outside: &OwnedFd) {
    match listener.accept() {
        Ok((connection, _)) => hand_over(outside, &connection, address),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock
                    | io::ErrorKind::Interrupted
                    | io::ErrorKind::ConnectionAborted
            ) => {}
        // A descriptor limit would otherwise spin the thread.
        Err(_) => thread::sleep(ACCEPT_RETRY),
    }
}

/// Sends `connection` with the `address` it came in on. A sandbox that is not
/// reading, or is gone, loses the connection: its client sees it close.
fn hand_over(outside: &OwnedFd, connection: &TcpStream, address: SocketAddr) {
    let text = address.to_string();
    let _ = sendmsg::<()>(
        outside.as_raw_fd(),
        &[IoSlice::new(text.as_bytes())],
        &[ControlMessage::ScmRights(&[connection.as_raw_fd()])],
        MsgFlags::MSG_DONTWAIT,
        None,
    );
}

#[cfg(test)]
mod tests {
    use core::time::Duration;
    use std::io::{Read, Write};
    use std::net::Ipv4Addr;

    use super::*;

    /// How long a step of a test may take before it fails, so a connection that
    /// never arrives names the step and does not hold the job.
    const STEP: Duration = Duration::from_secs(10);

    const LOCAL: SocketAddr = SocketAddr::new(core::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

    /// The next connection on `inside`, past the addresses the launcher asks
    /// the relay to watch.
    fn receive(inside: &OwnedFd) -> sys::Accepted {
        loop {
            let mut polls = [PollFd::new(inside.as_fd(), PollFlags::POLLIN)];
            let ready = poll(&mut polls, PollTimeout::try_from(STEP).unwrap()).unwrap();
            assert_eq!(ready, 1, "no connection arrived within {STEP:?}");
            if let sys::Received::Connection(accepted) = sys::receive(inside.as_fd()).unwrap() {
                return accepted;
            }
        }
    }

    /// What the relay does once a command listens on `address` inside.
    fn command_listens(inside: &OwnedFd, address: SocketAddr) {
        sys::send_address(inside.as_fd(), address).unwrap();
    }

    /// Connects once `address` accepts, which follows `command_listens` by a
    /// moment. A refusal before then is the case under test elsewhere.
    fn connect_once_open(address: SocketAddr) -> TcpStream {
        let deadline = std::time::Instant::now() + STEP;
        loop {
            match TcpStream::connect_timeout(&address, STEP) {
                Ok(client) => return client,
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "the port never opened"
                    );
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("{error}"),
            }
        }
    }

    #[test]
    fn a_published_port_refuses_connections_until_the_command_listens_inside() {
        let (published, _inside) = serve(&[LOCAL]).unwrap();
        let address = published.addresses()[0];

        let error = TcpStream::connect_timeout(&address, STEP).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
    }

    #[test]
    fn a_published_port_accepts_connections_once_the_command_listens_inside() {
        let (published, inside) = serve(&[LOCAL]).unwrap();
        let address = published.addresses()[0];

        command_listens(&inside, address);

        let _client = connect_once_open(address);
        assert_eq!(receive(&inside).address, address);
    }

    #[test]
    fn a_published_port_stays_open_after_the_command_stops_listening() {
        let (published, inside) = serve(&[LOCAL]).unwrap();
        let address = published.addresses()[0];
        command_listens(&inside, address);
        let _first = connect_once_open(address);
        receive(&inside);

        // The relay says nothing more, whatever the command does next.
        let _second = TcpStream::connect_timeout(&address, STEP).unwrap();

        assert_eq!(receive(&inside).address, address);
    }

    #[test]
    fn the_relay_is_asked_to_watch_each_published_address() {
        let (published, inside) = serve(&[LOCAL, LOCAL]).unwrap();

        let mut asked = Vec::new();
        for _ in 0..2 {
            let mut polls = [PollFd::new(inside.as_fd(), PollFlags::POLLIN)];
            assert_eq!(
                poll(&mut polls, PollTimeout::try_from(STEP).unwrap()).unwrap(),
                1
            );
            match sys::receive(inside.as_fd()).unwrap() {
                sys::Received::Address(address) => asked.push(address),
                sys::Received::Connection(_) => panic!("a connection came before any listened"),
            }
        }

        assert_eq!(asked, published.addresses());
    }

    #[test]
    fn a_connection_arrives_as_a_descriptor_with_the_address_it_came_in_on() {
        let (published, inside) = serve(&[LOCAL]).unwrap();
        let address = published.addresses()[0];
        command_listens(&inside, address);
        let mut client = connect_once_open(address);

        let accepted = receive(&inside);

        assert_eq!(accepted.address, address);
        let mut server = TcpStream::from(accepted.connection);
        server.set_nonblocking(false).unwrap();
        server.write_all(b"pong").unwrap();
        client.set_read_timeout(Some(STEP)).unwrap();
        let mut answer = [0; 4];
        client.read_exact(&mut answer).unwrap();
        assert_eq!(&answer, b"pong");
    }

    #[test]
    fn the_inside_end_is_above_the_descriptors_a_launcher_can_inherit() {
        let (_published, inside) = publish(&[LOCAL]).unwrap();

        assert!(inside.fd() >= 10, "{}", inside.fd());
    }

    #[test]
    fn the_inside_end_waits_for_a_connection_instead_of_failing() {
        let (published, inside) = serve(&[LOCAL]).unwrap();
        let address = published.addresses()[0];
        let reader = std::fs::File::from(inside.try_clone().unwrap());
        let (arrived, accepted) = std::sync::mpsc::channel();
        // The way the relay reads: no poll first, so a read with nothing queued
        // must wait and not return `WouldBlock`.
        thread::spawn(move || {
            let connection = loop {
                match sys::receive(reader.as_fd()) {
                    Ok(sys::Received::Connection(got)) => break Ok(got.address),
                    Ok(sys::Received::Address(_)) => {}
                    Err(error) => break Err(error),
                }
            };
            let _ = arrived.send(connection);
        });
        command_listens(&inside, address);
        let _client = connect_once_open(address);

        let received = accepted.recv_timeout(STEP).expect("the read never ended");

        assert_eq!(received.unwrap(), address);
        drop(inside);
    }

    #[test]
    fn two_publications_share_one_port() {
        let (first, first_inside) = serve(&[LOCAL]).unwrap();
        let address = first.addresses()[0];

        let (second, second_inside) = serve(&[address]).unwrap();

        assert_eq!(second.addresses(), [address]);
        for inside in [&first_inside, &second_inside] {
            command_listens(inside, address);
        }
        for inside in [&first_inside, &second_inside] {
            // The system picks which listener gets a connection, so connect until
            // this one has had one. Each round waits for it on the descriptor,
            // past the address the launcher asked the relay to watch. A port that
            // does not listen yet refuses, and the next round tries again.
            let mut clients = Vec::new();
            let mut rounds = 0;
            loop {
                let mut polls = [PollFd::new(inside.as_fd(), PollFlags::POLLIN)];
                if poll(&mut polls, PollTimeout::from(50_u8)).unwrap() > 0 {
                    if let sys::Received::Connection(_) = sys::receive(inside.as_fd()).unwrap() {
                        break;
                    }
                    continue;
                }
                clients.extend(TcpStream::connect_timeout(&address, STEP));
                rounds += 1;
                assert!(rounds < 400, "the listener never got a connection");
            }
        }
    }

    #[test]
    fn a_port_held_without_reuseport_is_refused_naming_the_address() {
        let held = TcpListener::bind(LOCAL).unwrap();
        let address = held.local_addr().unwrap();

        let error = serve(&[address]).unwrap_err();

        assert_eq!(
            error,
            PublishError::Bind {
                address,
                reason: io::ErrorKind::AddrInUse
            }
        );
        assert!(error.to_string().contains(&address.to_string()), "{error}");
    }

    #[test]
    fn dropping_the_publication_ends_it_while_clients_keep_connecting() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, mpsc};

        let (published, inside) = serve(&[LOCAL]).unwrap();
        let address = published.addresses()[0];
        command_listens(&inside, address);
        let connecting = Arc::new(AtomicBool::new(true));
        let clients = thread::spawn({
            let connecting = Arc::clone(&connecting);
            move || {
                while connecting.load(Ordering::Relaxed) {
                    let _ = TcpStream::connect_timeout(&address, STEP);
                }
            }
        });
        // The stream has started once the first connection has come through.
        receive(&inside);
        let (dropped, ended) = mpsc::channel();
        thread::spawn(move || {
            drop(published);
            let _ = dropped.send(());
        });

        let result = ended.recv_timeout(STEP);

        connecting.store(false, Ordering::Relaxed);
        clients.join().unwrap();
        assert!(result.is_ok(), "the drop never returned");
    }

    #[test]
    fn the_port_is_freed_once_the_inside_end_is_gone() {
        let (published, inside) = serve(&[LOCAL]).unwrap();
        let address = published.addresses()[0];
        command_listens(&inside, address);
        drop(connect_once_open(address));

        drop(inside);

        let deadline = std::time::Instant::now() + STEP;
        loop {
            match TcpStream::connect_timeout(&address, STEP) {
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => break,
                _ => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "the listener outlived the sandbox"
                    );
                    thread::sleep(Duration::from_millis(20));
                }
            }
        }
        drop(published);
    }

    #[test]
    fn dropping_the_publication_frees_the_port() {
        let (published, _inside) = serve(&[LOCAL]).unwrap();
        let address = published.addresses()[0];

        drop(published);

        let error = TcpStream::connect_timeout(&address, STEP).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
    }
}
