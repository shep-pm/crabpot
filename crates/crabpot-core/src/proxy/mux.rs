//! The one port a sandboxed command reaches the network through, as upstream's
//! `createMuxProxyServer` (`src/sandbox/mux-proxy.ts`) serves it: HTTP and
//! SOCKS5 on the same port.
//!
//! On Unix the same mux is served on a Unix socket too, for a sandbox where no
//! loopback port can be reached at all: inside a network namespace only a socket
//! bound there is one a command can dial (ADR-0014).
//!
//! A connection's first byte chooses. SOCKS5 greets with 0x05 and a SOCKS4
//! CONNECT starts with 0x04, while every HTTP request method starts with an
//! ASCII letter, HTTP/2 prior knowledge with `PRI `, and a stray TLS ClientHello
//! with 0x16, so one byte tells the two apart. A SOCKS connection is served in
//! process, with the byte put back at the front of it. Anything else is piped to
//! the HTTP backend, which listens on a Unix socket in the temp dir named
//! `srt-mux-<pid>-<seq>.sock`, or on Windows on a loopback port inside the
//! range the firewall permits.
//!
//! The backend is bound before the front end accepts anything, so no connection
//! is dispatched to a backend that is not there. Its file goes with the proxy
//! that started it (ADR-0010). The socket binds wherever macOS takes its path,
//! past the 104 bytes of `sun_path`, as upstream's does under Node (ADR-0003).

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

use core::pin::Pin;
use core::task::{Context, Poll};
use std::io;
#[cfg(windows)]
use std::net::Ipv4Addr;
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, copy_bidirectional};
use tokio::time::timeout;

#[cfg(unix)]
pub(super) use unix::{Front, Socket};
#[cfg(windows)]
pub(super) use windows::Socket;

use super::range::{PortRange, RangeError};
use super::shared::{Shared, Stream};
use super::socks;

/// The first bytes that mean SOCKS: 0x05 greets SOCKS5, 0x04 is a SOCKS4 CONNECT.
const SOCKS: [u8; 2] = [0x04, 0x05];

/// How long a connection may take to send its first byte, as upstream's
/// `DEFAULT_FIRST_BYTE_TIMEOUT_MS` has it.
const FIRST_BYTE: Duration = Duration::from_secs(10);

/// Where the mux dials the HTTP backend.
#[derive(Clone, Debug)]
pub(super) enum Dial {
    /// The path of the backend's Unix socket.
    #[cfg(unix)]
    Socket(PathBuf),
    /// The loopback port of the backend, in the range the firewall permits.
    #[cfg(windows)]
    Port(u16),
}

impl Dial {
    /// The loopback port it dials, which the front end may not listen on.
    pub(super) fn port(&self) -> Option<u16> {
        match self {
            #[cfg(unix)]
            Self::Socket(_) => None,
            #[cfg(windows)]
            Self::Port(port) => Some(*port),
        }
    }
}

/// The HTTP backend, bound and not yet served.
pub(super) struct Backend {
    #[cfg(unix)]
    listener: std::os::unix::net::UnixListener,
    #[cfg(windows)]
    listener: std::net::TcpListener,
    dial: Dial,
    socket: Socket,
}

impl Backend {
    /// Binds the backend: a fresh Unix socket on Unix, and on Windows the first
    /// free port of `range` or a port of the OS's choosing without one.
    ///
    /// Call this outside a tokio runtime, and hand the backend to
    /// [`Backend::into_tokio`] inside one.
    ///
    /// # Errors
    ///
    /// [`RangeError::Full`] when no port of `range` is free, and
    /// [`RangeError::Io`] when binding failed.
    #[cfg(unix)]
    pub(super) fn bind(_range: Option<PortRange>) -> Result<Self, RangeError> {
        let (listener, socket) = Socket::bind()?;
        let dial = Dial::Socket(socket.path().to_path_buf());
        Ok(Self {
            listener,
            dial,
            socket,
        })
    }

    /// Binds the backend: a fresh Unix socket on Unix, and on Windows the first
    /// free port of `range` or a port of the OS's choosing without one.
    ///
    /// Call this outside a tokio runtime, and hand the backend to
    /// [`Backend::into_tokio`] inside one.
    ///
    /// # Errors
    ///
    /// [`RangeError::Full`] when no port of `range` is free, and
    /// [`RangeError::Io`] when binding failed.
    #[cfg(windows)]
    pub(super) fn bind(range: Option<PortRange>) -> Result<Self, RangeError> {
        let (listener, port) = super::range::listen(range, &[])?;
        Ok(Self {
            listener,
            dial: Dial::Port(port),
            socket: Socket,
        })
    }

    /// Where to dial to reach the backend.
    pub(super) fn dial(&self) -> Dial {
        self.dial.clone()
    }

    /// Hands the backend to tokio, and the file it leaves behind, which goes
    /// when that does. Call this inside the runtime that will serve it.
    #[cfg(unix)]
    pub(super) fn into_tokio(self) -> io::Result<(tokio::net::UnixListener, Socket)> {
        Ok((
            tokio::net::UnixListener::from_std(self.listener)?,
            self.socket,
        ))
    }

    /// Hands the backend to tokio, and the file it leaves behind, which goes
    /// when that does. Call this inside the runtime that will serve it.
    #[cfg(windows)]
    pub(super) fn into_tokio(self) -> io::Result<(tokio::net::TcpListener, Socket)> {
        Ok((
            tokio::net::TcpListener::from_std(self.listener)?,
            self.socket,
        ))
    }
}

/// The front end's handler for one connection: the byte it peeked at picks the
/// leg, and SOCKS is served with that byte back at the front of the connection.
pub(super) async fn dispatch<S: Stream>(mut client: S, backend: Dial, shared: Arc<Shared>) {
    let mut peeked = [0u8; 1];
    let read = timeout(FIRST_BYTE, client.read(&mut peeked)).await;
    let peeked = match read {
        Ok(Ok(1)) => peeked[0],
        // A client that connected and closed, or reset, before saying anything.
        Ok(_) => return,
        // Upstream destroys one that stalls before its first byte.
        Err(_) => return,
    };
    if SOCKS.contains(&peeked) {
        let served = Peeked {
            inner: client,
            peeked: Some(peeked),
        };
        socks::handle(served, shared).await;
        return;
    }
    let _ = http(client, &backend, peeked).await;
}

/// Pipes `client` to the HTTP backend.
async fn http<S: Stream>(mut client: S, backend: &Dial, peeked: u8) -> io::Result<()> {
    match backend {
        #[cfg(unix)]
        Dial::Socket(path) => {
            pipe(&mut client, crate::unix_socket::connect(path).await, peeked).await
        }
        #[cfg(windows)]
        Dial::Port(port) => {
            let dialed = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, *port)).await;
            pipe(&mut client, dialed, peeked).await
        }
    }
}

/// Pipes `client` to `backend` once it has been dialed, with the byte the front
/// end peeked at written there first, or answers `client` with why it was not.
async fn pipe<S: Stream, B: Stream>(
    client: &mut S,
    backend: io::Result<B>,
    peeked: u8,
) -> io::Result<()> {
    let mut backend = match backend {
        Ok(backend) => backend,
        Err(error) => return refused(client, &error).await,
    };
    backend.write_all(&[peeked]).await?;
    copy_bidirectional(client, &mut backend).await.map(drop)
}

/// The 502 upstream answers a backend it cannot reach with, naming the errno of
/// why. It is an answer, so a client that is waiting for one stops waiting.
async fn refused<S: Stream>(client: &mut S, error: &io::Error) -> io::Result<()> {
    let code = match error.kind() {
        io::ErrorKind::NotFound => "ENOENT",
        io::ErrorKind::PermissionDenied => "EACCES",
        io::ErrorKind::ConnectionRefused => "ECONNREFUSED",
        io::ErrorKind::InvalidInput => "EINVAL",
        _ => "ERR",
    };
    client
        .write_all(
            format!(
                "HTTP/1.1 502 Bad Gateway\r\n\
                 Connection: close\r\n\
                 \r\n\
                 mux backend dial failed ({code})\n"
            )
            .as_bytes(),
        )
        .await
}

/// A connection with the byte the front end peeked at put back at its front,
/// which is what upstream's `unshift` does for the SOCKS handler.
struct Peeked<S> {
    inner: S,
    peeked: Option<u8>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Peeked<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(byte) = self.peeked.take() {
            buf.put_slice(&[byte]);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Peeked<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(all(test, unix))]
mod tests;
