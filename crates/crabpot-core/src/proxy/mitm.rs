//! `network.mitmProxy`: the domains sent to an upstream proxy over a Unix
//! socket, as upstream's `getMitmSocketPath` (`src/sandbox/sandbox-manager.ts`)
//! and `openConnectTunnel` (`src/sandbox/parent-proxy.ts`) route them.
//!
//! crabpot terminates no TLS here. A `CONNECT` is answered with a raw `CONNECT`
//! of its own and the bytes relay, and a plain request is written to the socket
//! as an absolute-URI request, so the session ends at the proxy behind the
//! socket and the child is given no CA of that proxy's. A host no pattern
//! covers is dialed direct, which is where upstream's site fails open; the
//! allow and deny lists have been weighed before this is asked.

use std::io;
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::UnixStream;
#[cfg(unix)]
use tokio::time::timeout;

use crate::config::MitmProxy;
use crate::domain::DomainPattern;

/// How long a socket may take to open, and to answer the `CONNECT`, which is
/// upstream's `CONNECT_TIMEOUT_MS`.
#[cfg(unix)]
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// How far a `CONNECT` answer may grow before the tunnel is refused, which is
/// the cap Node's `openConnectTunnel` holds itself to.
#[cfg(unix)]
const MAX_HEAD_BYTES: usize = 16 * 1024;

/// The domains routed through a Unix socket, and the socket they go to.
#[derive(Debug)]
pub(super) struct Route {
    socket_path: String,
    domains: Vec<DomainPattern>,
}

impl Route {
    pub(super) fn new(mitm: &MitmProxy) -> Self {
        Self {
            socket_path: mitm.socket_path.clone(),
            domains: mitm.domains.clone(),
        }
    }

    /// The socket `host` goes to, when one of the route's domains covers it,
    /// and `None` when none does. `host` is the spelling the allow list judged,
    /// which is the spelling upstream matches on.
    pub(super) fn socket_for(&self, host: &str) -> Option<&str> {
        self.domains
            .iter()
            .any(|pattern| pattern.matches(host))
            .then_some(self.socket_path.as_str())
    }
}

/// What an opened tunnel is: the socket, behind a reader that keeps the bytes
/// that came with the `CONNECT` answer.
#[cfg(unix)]
type Tunnel = BufReader<UnixStream>;

/// A stream for a plain request.
#[cfg(unix)]
type Socket = UnixStream;

/// A platform with no Unix sockets has no route to one either.
#[cfg(not(unix))]
type Tunnel = tokio::io::Empty;

/// As above, for a plain request.
#[cfg(not(unix))]
type Socket = tokio::io::Empty;

/// Open a tunnel to `host:port` through the Unix socket at `path`: write the
/// `CONNECT`, read the answer, and hand back the socket for relaying when the
/// answer is a 2xx.
///
/// # Errors
///
/// An [`io::Error`] when the socket cannot be opened, the answer is not a 2xx
/// or never ends, or the handshake outlives [`CONNECT_TIMEOUT`]. A `socketPath`
/// that names nothing is one of these, and the caller answers the client 502
/// for it.
#[cfg(unix)]
pub(super) async fn open_tunnel(path: &str, host: &str, port: u16) -> io::Result<Tunnel> {
    let authority = connect_authority(host, port);
    let handshake = async {
        let mut upstream = BufReader::new(UnixStream::connect(path).await?);
        upstream
            .write_all(
                format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes(),
            )
            .await?;
        upstream.flush().await?;
        let status = read_status_line(&mut upstream).await?;
        if accepted(&status) {
            Ok(upstream)
        } else {
            Err(refused(&status))
        }
    };
    match timeout(CONNECT_TIMEOUT, handshake).await {
        Ok(outcome) => outcome,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "the mitm proxy never answered in time",
        )),
    }
}

/// Open the Unix socket a plain request is written to. The request itself is
/// what the proxy behind the socket is asked for, so there is no `CONNECT` to
/// write first.
///
/// # Errors
///
/// The [`io::Error`] of a socket that cannot be opened, or of one that does not
/// open within [`CONNECT_TIMEOUT`].
#[cfg(unix)]
pub(super) async fn open_socket(path: &str) -> io::Result<Socket> {
    match timeout(CONNECT_TIMEOUT, UnixStream::connect(path)).await {
        Ok(outcome) => outcome,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "the socket never opened in time",
        )),
    }
}

/// There is no Unix socket off Unix, so no route to one.
#[cfg(not(unix))]
pub(super) async fn open_tunnel(_path: &str, _host: &str, _port: u16) -> io::Result<Tunnel> {
    Err(no_unix_sockets())
}

/// As above, for a plain request.
#[cfg(not(unix))]
pub(super) async fn open_socket(_path: &str) -> io::Result<Socket> {
    Err(no_unix_sockets())
}

#[cfg(not(unix))]
fn no_unix_sockets() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "the platform has no Unix sockets",
    )
}

/// Read the answer up to its blank line, and return its status line.
#[cfg(unix)]
async fn read_status_line(upstream: &mut BufReader<UnixStream>) -> io::Result<String> {
    let mut head = Vec::new();
    while head.len() < MAX_HEAD_BYTES {
        if upstream.read_until(b'\n', &mut head).await? == 0 {
            break;
        }
        if head.ends_with(b"\r\n\r\n") {
            let end = head
                .windows(2)
                .position(|w| w == b"\r\n")
                .unwrap_or(head.len());
            return Ok(String::from_utf8_lossy(&head[..end]).into_owned());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "the mitm proxy answered no status line",
    ))
}

/// Whether `line` is the 2xx answer upstream's `openConnectTunnel` accepts.
#[cfg(unix)]
fn accepted(line: &str) -> bool {
    let Some(rest) = line
        .strip_prefix("HTTP/1.1 ")
        .or_else(|| line.strip_prefix("HTTP/1.0 "))
    else {
        return false;
    };
    let (code, phrase) = rest.split_at(rest.len().min(3));
    code.len() == 3
        && code.starts_with('2')
        && code.bytes().all(|b| b.is_ascii_digit())
        && (phrase.is_empty() || phrase.starts_with(char::is_whitespace))
}

#[cfg(unix)]
fn refused(status: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionRefused,
        format!("the mitm proxy refused the CONNECT: {status}"),
    )
}

/// `host:port` as a `CONNECT` target names it: an IPv6 address in brackets, and
/// the port always there.
#[cfg(unix)]
fn connect_authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::future::Future;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};
    use std::thread;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::runtime::Builder;

    use super::*;

    /// How long a test waits for the exchange it asked for, so an exchange
    /// nothing answers is a failure and not a hang.
    const PATIENCE: Duration = Duration::from_secs(5);

    /// A folder of its own, named short enough for a socket path to fit
    /// macOS's 104-byte `sun_path`.
    struct Fixture(PathBuf);

    impl Fixture {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("mitm-{}-{name}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn socket(&self) -> PathBuf {
            self.0.join("s")
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Waits for `task` within [`PATIENCE`], and fails the test when nothing
    /// resolves it.
    async fn within<F: Future>(task: F) -> F::Output {
        timeout(PATIENCE, task)
            .await
            .expect("the socket never answered in time")
    }

    /// Runs `task` on a runtime of its own.
    fn block<F: Future>(task: F) -> F::Output {
        let runtime = Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(within(task))
    }

    /// A Unix socket that answers one `CONNECT` with `answer` as it was given,
    /// then echoes what it reads. It hands back the head it saw.
    fn stand_in(socket: &Path, answer: &'static str) -> thread::JoinHandle<String> {
        let listener = UnixListener::bind(socket).unwrap();
        thread::spawn(move || {
            let (mut client, _) = listener.accept().unwrap();
            client.set_read_timeout(Some(PATIENCE)).unwrap();
            let mut head = Vec::new();
            let mut buf = [0u8; 1024];
            while !head.ends_with(b"\r\n\r\n") {
                let Ok(read) = client.read(&mut buf) else {
                    break;
                };
                if read == 0 {
                    break;
                }
                head.extend_from_slice(&buf[..read]);
            }
            let _ = client.write_all(answer.as_bytes());
            let _ = client.flush();
            while let Ok(read) = client.read(&mut buf) {
                if read == 0 || client.write_all(&buf[..read]).is_err() {
                    break;
                }
            }
            String::from_utf8_lossy(&head).into_owned()
        })
    }

    #[test]
    fn connect_is_written_to_the_socket_and_a_2xx_opens_the_relay() {
        let fixture = Fixture::new("relay");
        let socket = fixture.socket();
        // The 200 and the first bytes of the tunnel arrive in one packet, which
        // the relay has to see.
        let seen = stand_in(&socket, "HTTP/1.1 200 Connection Established\r\n\r\nonward");

        let runtime = Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let path = socket.to_str().unwrap();
            let mut tunnel = within(open_tunnel(path, "example.com", 443))
                .await
                .expect("a 2xx answer opens the relay");

            let mut onward = [0u8; 6];
            within(tunnel.read_exact(&mut onward)).await.unwrap();
            assert_eq!(&onward, b"onward");

            tunnel.write_all(b"hello").await.unwrap();
            tunnel.flush().await.unwrap();
            let mut echoed = [0u8; 5];
            within(tunnel.read_exact(&mut echoed)).await.unwrap();
            assert_eq!(&echoed, b"hello");
        });

        assert_eq!(
            seen.join().unwrap(),
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
        );
    }

    #[test]
    fn a_non_2xx_is_a_refused_tunnel() {
        for (name, answer) in [
            ("403", "HTTP/1.1 403 Forbidden\r\n\r\n"),
            ("302", "HTTP/1.1 302 Found\r\n\r\n"),
            ("500", "HTTP/1.1 500 Internal Server Error\r\n\r\n"),
            ("none", "gibberish\r\n\r\n"),
        ] {
            let fixture = Fixture::new(name);
            let socket = fixture.socket();
            let seen = stand_in(&socket, answer);

            let outcome = block(open_tunnel(socket.to_str().unwrap(), "example.com", 443));

            assert!(outcome.is_err(), "{answer}");
            assert!(
                seen.join()
                    .unwrap()
                    .starts_with("CONNECT example.com:443 HTTP/1.1\r\n"),
                "{answer}"
            );
        }
    }

    #[test]
    fn a_socket_that_is_not_there_is_a_refused_tunnel() {
        let fixture = Fixture::new("absent");

        let outcome = block(open_tunnel(
            fixture.socket().to_str().unwrap(),
            "example.com",
            443,
        ));

        assert!(outcome.is_err());
    }

    #[test]
    fn a_domain_the_route_covers_goes_to_the_socket_and_no_other_does() {
        let route = Route::new(&MitmProxy {
            socket_path: "/run/mitm.sock".to_owned(),
            domains: vec![
                DomainPattern::parse("api.example.com").unwrap(),
                DomainPattern::parse("*.internal.org").unwrap(),
            ],
        });

        assert_eq!(route.socket_for("api.example.com"), Some("/run/mitm.sock"));
        assert_eq!(route.socket_for("a.internal.org"), Some("/run/mitm.sock"));
        assert_eq!(route.socket_for("internal.org"), None);
        assert_eq!(route.socket_for("example.org"), None);
    }
}
