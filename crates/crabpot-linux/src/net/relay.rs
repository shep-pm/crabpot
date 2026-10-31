//! The relay inside the network namespace: a TCP port that forwards each
//! connection to the proxy's Unix socket, in place of upstream's `socat`
//! (ADR-0014).

use core::time::Duration;
use std::io;
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddrV4, SocketAddrV6, TcpListener, TcpStream,
};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::thread;

use super::ssh::{self, Answer};

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
pub(super) const ACCEPT_RETRY: Duration = Duration::from_millis(100);

/// Listens on `port` for every address of the machine: IPv6 with IPv4 mapped
/// onto it, as upstream's `TCP6-LISTEN:<port>,ipv6only=0,fork,reuseaddr,backlog=4096`
/// does, and plain IPv4 when the machine has no IPv6.
///
/// # Errors
///
/// The [`io::Error`] of binding. A port that is taken is [`io::ErrorKind::AddrInUse`].
pub fn bind(port: u16) -> io::Result<TcpListener> {
    match listen_on_any(AddressFamily::Inet6, port) {
        // A taken port is taken for IPv4 too, with the two sharing it.
        Err(Errno::EADDRINUSE) => Err(Errno::EADDRINUSE.into()),
        Err(_) => listen_on_any(AddressFamily::Inet, port).map_err(io::Error::from),
        Ok(listener) => Ok(listener),
    }
    .map(TcpListener::from)
}

/// Listens on `port` for the loopback addresses `127.0.0.1` and `::1` alone,
/// so the port stays free on every other address of the sandbox. A machine with
/// no IPv6 listens on IPv4 only.
///
/// # Errors
///
/// The [`io::Error`] of binding `127.0.0.1`, or of binding `::1` when that is
/// taken. A port that is taken is [`io::ErrorKind::AddrInUse`].
pub fn bind_loopback(port: u16) -> io::Result<Vec<TcpListener>> {
    let mut listeners = vec![TcpListener::from(
        listen_on(AddressFamily::Inet, Ipv4Addr::LOCALHOST.into(), port)
            .map_err(io::Error::from)?,
    )];
    match listen_on(AddressFamily::Inet6, Ipv6Addr::LOCALHOST.into(), port) {
        Ok(listener) => listeners.push(listener.into()),
        Err(Errno::EADDRINUSE) => return Err(Errno::EADDRINUSE.into()),
        // The machine has no IPv6.
        Err(_) => {}
    }
    Ok(listeners)
}

fn listen_on_any(family: AddressFamily, port: u16) -> Result<OwnedFd, Errno> {
    let address = if family == AddressFamily::Inet6 {
        Ipv6Addr::UNSPECIFIED.into()
    } else {
        Ipv4Addr::UNSPECIFIED.into()
    };
    listen_on(family, address, port)
}

/// A listening socket of `family` on `address` and `port`. An IPv6 socket
/// that listens on the unspecified address takes IPv4 too.
fn listen_on(family: AddressFamily, address: IpAddr, port: u16) -> Result<OwnedFd, Errno> {
    listen_with(family, address, port, false)
}

/// Listens on `address` with `SO_REUSEPORT`, so another socket of the same user
/// that sets it may listen on the same address and port.
///
/// # Errors
///
/// The error number of the call that failed. `EADDRINUSE` when a socket without
/// `SO_REUSEPORT` holds the port.
#[cfg(target_os = "linux")]
pub(super) fn listen_shared(address: std::net::SocketAddr) -> Result<TcpListener, Errno> {
    let family = if address.is_ipv4() {
        AddressFamily::Inet
    } else {
        AddressFamily::Inet6
    };
    listen_with(family, address.ip(), address.port(), true).map(TcpListener::from)
}

fn listen_with(
    family: AddressFamily,
    address: IpAddr,
    port: u16,
    reuse_port: bool,
) -> Result<OwnedFd, Errno> {
    // A shared listener is the launcher's, which spawns the command: a copy
    // that survived the exec would keep the port open and accept on it.
    let flags = if reuse_port {
        SockFlag::SOCK_CLOEXEC
    } else {
        SockFlag::empty()
    };
    let fd = socket(family, SockType::Stream, flags, None)?;
    setsockopt(&fd, sockopt::ReuseAddr, &true)?;
    if reuse_port {
        setsockopt(&fd, sockopt::ReusePort, &true)?;
    }
    match address {
        IpAddr::V6(ip) => {
            setsockopt(&fd, sockopt::Ipv6V6Only, &!ip.is_unspecified())?;
            bind_socket(
                fd.as_raw_fd(),
                &SockaddrIn6::from(SocketAddrV6::new(ip, port, 0, 0)),
            )?;
        }
        IpAddr::V4(ip) => bind_socket(
            fd.as_raw_fd(),
            &SockaddrIn::from(SocketAddrV4::new(ip, port)),
        )?,
    }
    listen(&fd, backlog())?;
    Ok(fd)
}

/// Accepts connections on `listener` for good, and forwards each to the Unix
/// socket at `socket` on a thread of its own.
pub fn serve(listener: &TcpListener, socket: &Path) {
    accept(listener, socket, None);
}

/// Forwards each connection through an authenticated `CONNECT` to `target`.
/// The credential is held by the relay, outside the command's PID namespace.
pub fn serve_tunnel(listener: &TcpListener, socket: &Path, target: &str, basic: &str) {
    accept(listener, socket, Some((target, basic)));
}

fn accept(listener: &TcpListener, socket: &Path, tunnel: Option<(&str, &str)>) {
    loop {
        match listener.accept() {
            Ok((client, _)) => {
                let socket = socket.to_owned();
                let tunnel = tunnel.map(|(target, basic)| (target.to_owned(), basic.to_owned()));
                thread::spawn(move || {
                    // A connection that fails is that client's alone: it sees
                    // its end close, which is all a relay can tell it.
                    let _ = forward_tunnel(
                        &client,
                        &socket,
                        tunnel
                            .as_ref()
                            .map(|(target, basic)| (target.as_str(), basic.as_str())),
                    );
                });
            }
            Err(_) => thread::sleep(ACCEPT_RETRY),
        }
    }
}

/// Copies between `client` and the Unix socket, passing an end of input on to
/// the other side. When the proxy is done, both sockets are closed, as
/// upstream's `socat` does, so a client that keeps its end open does not hold
/// the connection's thread and descriptors.
#[cfg(test)]
fn forward(client: &TcpStream, socket: &Path) -> io::Result<()> {
    forward_tunnel(client, socket, None)
}

fn forward_tunnel(
    client: &TcpStream,
    socket: &Path,
    tunnel: Option<(&str, &str)>,
) -> io::Result<()> {
    let mut proxy = UnixStream::connect(socket)?;
    if let Some((target, basic)) = tunnel
        && let Answer::Refused(reason) = ssh::handshake(&mut proxy, target, basic)?
    {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, reason));
    }
    let (mut from_client, mut to_proxy) = (client.try_clone()?, proxy.try_clone()?);
    let upstream = thread::spawn(move || {
        let copied = io::copy(&mut from_client, &mut to_proxy);
        let _ = to_proxy.shutdown(Shutdown::Write);
        copied
    });
    let (mut from_proxy, mut to_client) = (proxy, client.try_clone()?);
    let downstream = io::copy(&mut from_proxy, &mut to_client);
    // Closing both ends wakes the thread above out of its read of the client.
    let _ = client.shutdown(Shutdown::Both);
    let _ = from_proxy.shutdown(Shutdown::Both);
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
    use std::sync::mpsc;
    use std::thread;

    use super::*;
    use crate::support::Tree;

    /// How long one step of an [`exchange`] may take, so a stalled connection
    /// fails the test and names the step instead of holding the job.
    const STEP: Duration = Duration::from_secs(10);

    /// A Unix socket that answers `got:` and everything the client sent, once
    /// the client has finished sending. Each connection has a thread of its
    /// own, so one that stalls does not hold the others.
    fn answering_socket(test: &str) -> (Tree, std::path::PathBuf) {
        let tree = Tree::empty(test);
        let path = tree.root().join("p.sock");
        let listener = UnixListener::bind(&path).unwrap();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                thread::spawn(move || {
                    stream.set_read_timeout(Some(STEP)).unwrap();
                    stream.set_write_timeout(Some(STEP)).unwrap();
                    let mut sent = Vec::new();
                    stream.read_to_end(&mut sent).expect("proxy read to EOF");
                    stream.write_all(b"got:").expect("proxy write prefix");
                    stream.write_all(&sent).expect("proxy write echo");
                });
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
        let mut client = TcpStream::connect_timeout(&address, STEP)
            .unwrap_or_else(|error| panic!("{address}: connect: {error}"));
        client.set_read_timeout(Some(STEP)).unwrap();
        client.set_write_timeout(Some(STEP)).unwrap();
        client
            .write_all(text)
            .unwrap_or_else(|error| panic!("{address}: write: {error}"));
        client
            .shutdown(Shutdown::Write)
            .unwrap_or_else(|error| panic!("{address}: half-close: {error}"));
        let mut answer = Vec::new();
        client
            .read_to_end(&mut answer)
            .unwrap_or_else(|error| panic!("{address}: read to EOF: {error}"));
        answer
    }

    #[test]
    fn a_tcp_grant_carries_payload_and_half_closes_through_connect() {
        use crabpot_core::proxy::{Proxy, TcpGrant, basic_for};

        let server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = server.local_addr().unwrap();
        let proxy = Proxy::start_with_tcp(
            &[],
            &[],
            &[],
            false,
            None,
            &[TcpGrant {
                host: "database.example".to_owned(),
                address,
            }],
        )
        .unwrap();
        let (sent, received) = mpsc::channel();
        thread::spawn(move || {
            let (mut client, _) = server.accept().unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            client
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            // A greeting can arrive in the same read as the CONNECT response.
            client.write_all(b"ready:").unwrap();
            let mut payload = Vec::new();
            client.read_to_end(&mut payload).unwrap();
            client.write_all(&payload).unwrap();
            sent.send(payload).unwrap();
        });
        let listener = bind(0).unwrap();
        let port = listener.local_addr().unwrap().port();
        let socket = proxy.mux_socket().to_owned();
        let basic = basic_for("srt", proxy.token());
        thread::spawn(move || serve_tunnel(&listener, &socket, &address.to_string(), &basic));

        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client.write_all(b"ping\0").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut answer = Vec::new();
        client.read_to_end(&mut answer).unwrap();

        assert_eq!(answer, b"ready:ping\0");
        assert_eq!(
            received.recv_timeout(Duration::from_secs(5)).unwrap(),
            b"ping\0"
        );
    }

    #[test]
    fn the_backlog_is_the_largest_the_system_takes() {
        let wanted = BACKLOG.min(i32::from(Backlog::MAXCONN));

        assert_eq!(i32::from(backlog()), wanted);
    }

    #[test]
    fn a_client_that_keeps_its_end_open_does_not_hold_the_connection() {
        let tree = Tree::empty("held");
        let socket = tree.root().join("p.sock");
        let proxy = UnixListener::bind(&socket).unwrap();
        thread::spawn(move || {
            // Answers and hangs up without waiting for the client.
            let (mut stream, _) = proxy.accept().unwrap();
            stream.write_all(b"bye").unwrap();
        });
        let listener = bind(0).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (done, forwarded) = mpsc::channel();
        thread::spawn(move || {
            let (client, _) = listener.accept().unwrap();
            done.send(forward(&client, &socket)).unwrap();
        });

        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        let mut answer = Vec::new();
        client.read_to_end(&mut answer).unwrap();

        // The client's socket is still open here.
        assert_eq!(answer, b"bye");
        forwarded
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .unwrap();
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
    fn a_loopback_listener_forwards_a_loopback_client() {
        let port = bind(0).unwrap().local_addr().unwrap().port();
        let listeners = bind_loopback(port).unwrap();
        let (_tree, socket) = answering_socket("loopback");
        for listener in listeners {
            let socket = socket.clone();
            thread::spawn(move || serve(&listener, &socket));
        }

        assert_eq!(exchange((Ipv4Addr::LOCALHOST, port).into(), b"x"), b"got:x");
    }

    #[test]
    fn a_port_that_is_taken_is_an_error() {
        let held = bind(0).unwrap();
        let port = held.local_addr().unwrap().port();

        let error = bind(port).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_shared_listener_does_not_survive_an_exec() {
        use nix::fcntl::{FcntlArg, FdFlag, fcntl};

        let listener = listen_shared(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();

        let flags = fcntl(&listener, FcntlArg::F_GETFD).unwrap();

        assert!(FdFlag::from_bits_truncate(flags).contains(FdFlag::FD_CLOEXEC));
    }
}
