//! The relay inside the network namespace: a TCP port that forwards each
//! connection to the proxy's Unix socket, in place of upstream's `socat`
//! (ADR-0014).

use core::time::Duration;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::thread;

use nix::errno::Errno;
use nix::sys::socket::{
    AddressFamily, Backlog, SockFlag, SockType, SockaddrIn, SockaddrIn6, bind as bind_socket,
    listen, setsockopt, socket, sockopt,
};

/// How many connections may wait to be accepted, as upstream's `backlog=4096`.
const BACKLOG: i32 = 4096;

/// [`BACKLOG`], or the most the system names when that is less: nix refuses a
/// value above `SOMAXCONN`, which is 128 on macOS, where the unit tests run.
fn backlog() -> Backlog {
    Backlog::new(BACKLOG).unwrap_or(Backlog::MAXCONN)
}

/// How long an accept that failed waits before the next, so a descriptor limit
/// does not spin the relay.
const ACCEPT_RETRY: Duration = Duration::from_millis(100);

/// Listens on `port` for every address of the machine: IPv6 with IPv4 mapped
/// onto it, as upstream's `TCP6-LISTEN:<port>,ipv6only=0,fork,reuseaddr,backlog=4096`
/// does, and plain IPv4 when the machine has no IPv6.
///
/// # Errors
///
/// The [`io::Error`] of binding. A port that is taken is [`io::ErrorKind::AddrInUse`].
pub fn bind(port: u16) -> io::Result<TcpListener> {
    match listen_on(AddressFamily::Inet6, port) {
        // A taken port is taken for IPv4 too, with the two sharing it.
        Err(Errno::EADDRINUSE) => Err(Errno::EADDRINUSE.into()),
        Err(_) => listen_on(AddressFamily::Inet, port).map_err(io::Error::from),
        Ok(listener) => Ok(listener),
    }
    .map(TcpListener::from)
}

/// A listening socket of `family` on `port`, for every address.
fn listen_on(family: AddressFamily, port: u16) -> Result<OwnedFd, Errno> {
    let fd = socket(family, SockType::Stream, SockFlag::empty(), None)?;
    setsockopt(&fd, sockopt::ReuseAddr, &true)?;
    if family == AddressFamily::Inet6 {
        setsockopt(&fd, sockopt::Ipv6V6Only, &false)?;
        bind_socket(
            fd.as_raw_fd(),
            &SockaddrIn6::from(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0)),
        )?;
    } else {
        bind_socket(
            fd.as_raw_fd(),
            &SockaddrIn::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)),
        )?;
    }
    listen(&fd, backlog())?;
    Ok(fd)
}

/// Accepts connections on `listener` for good, and forwards each to the Unix
/// socket at `socket` on a thread of its own.
pub fn serve(listener: &TcpListener, socket: &Path) {
    loop {
        match listener.accept() {
            Ok((client, _)) => {
                let socket = socket.to_owned();
                thread::spawn(move || {
                    // A connection that fails is that client's alone: it sees
                    // its end close, which is all a relay can tell it.
                    let _ = forward(&client, &socket);
                });
            }
            Err(_) => thread::sleep(ACCEPT_RETRY),
        }
    }
}

/// Copies between `client` and the Unix socket until both directions are done,
/// passing an end of input on to the other side.
fn forward(client: &TcpStream, socket: &Path) -> io::Result<()> {
    let proxy = UnixStream::connect(socket)?;
    let (mut from_client, mut to_proxy) = (client.try_clone()?, proxy.try_clone()?);
    let upstream = thread::spawn(move || {
        let copied = io::copy(&mut from_client, &mut to_proxy);
        let _ = to_proxy.shutdown(Shutdown::Write);
        copied
    });
    let (mut from_proxy, mut to_client) = (proxy, client.try_clone()?);
    let downstream = io::copy(&mut from_proxy, &mut to_client);
    let _ = client.shutdown(Shutdown::Write);
    downstream?;
    upstream
        .join()
        .map_err(|_| io::Error::other("the client's copy panicked"))??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpStream};
    use std::os::unix::net::UnixListener;
    use std::thread;

    use super::*;
    use crate::support::Tree;

    /// A Unix socket that answers `got:` and everything the client sent, once
    /// the client has finished sending.
    fn answering_socket(test: &str) -> (Tree, std::path::PathBuf) {
        let tree = Tree::empty(test);
        let path = tree.root().join("p.sock");
        let listener = UnixListener::bind(&path).unwrap();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let mut sent = Vec::new();
                stream.read_to_end(&mut sent).unwrap();
                stream.write_all(b"got:").unwrap();
                stream.write_all(&sent).unwrap();
            }
        });
        (tree, path)
    }

    fn relay_to(socket: &Path) -> u16 {
        let listener = bind(0).unwrap();
        let port = listener.local_addr().unwrap().port();
        let socket = socket.to_owned();
        thread::spawn(move || serve(&listener, &socket));
        port
    }

    fn exchange(address: SocketAddr, text: &[u8]) -> Vec<u8> {
        let mut client = TcpStream::connect(address).unwrap();
        client.write_all(text).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut answer = Vec::new();
        client.read_to_end(&mut answer).unwrap();
        answer
    }

    #[test]
    fn the_backlog_is_the_largest_the_system_takes() {
        let wanted = BACKLOG.min(i32::from(Backlog::MAXCONN));

        assert_eq!(i32::from(backlog()), wanted);
    }

    #[test]
    fn a_connection_is_forwarded_to_the_unix_socket_and_back() {
        let (_tree, socket) = answering_socket("fwd");
        let port = relay_to(&socket);

        let answer = exchange((Ipv4Addr::LOCALHOST, port).into(), b"ping");

        assert_eq!(answer, b"got:ping");
    }

    #[test]
    fn connections_are_forwarded_side_by_side() {
        let (_tree, socket) = answering_socket("many");
        let port = relay_to(&socket);

        let clients: Vec<_> = (0..4)
            .map(|n| {
                thread::spawn(move || {
                    exchange(
                        (Ipv4Addr::LOCALHOST, port).into(),
                        format!("n{n}").as_bytes(),
                    )
                })
            })
            .collect();

        for (n, client) in clients.into_iter().enumerate() {
            assert_eq!(client.join().unwrap(), format!("got:n{n}").as_bytes());
        }
    }

    #[test]
    fn an_ipv6_listener_takes_ipv4_clients_too() {
        let listener = bind(0).unwrap();
        let port = listener.local_addr().unwrap().port();
        if !listener.local_addr().unwrap().is_ipv6() {
            // The machine has no IPv6, so the IPv4 fallback is what listens.
            return;
        }
        let (_tree, socket) = answering_socket("dual");
        thread::spawn(move || serve(&listener, &socket));

        for address in [
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
        ] {
            assert_eq!(exchange(address, b"x"), b"got:x", "{address}");
        }
    }

    #[test]
    fn a_port_that_is_taken_is_an_error() {
        let held = bind(0).unwrap();
        let port = held.local_addr().unwrap().port();

        let error = bind(port).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
    }
}
