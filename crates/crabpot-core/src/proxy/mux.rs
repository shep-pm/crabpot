//! The one port a sandboxed command reaches the network through, as upstream's
//! `createMuxProxyServer` (`src/sandbox/mux-proxy.ts`) serves it: HTTP and
//! SOCKS5 on the same port.
//!
//! A connection's first byte chooses. SOCKS5 greets with 0x05 and a SOCKS4
//! CONNECT starts with 0x04, while every HTTP request method starts with an
//! ASCII letter, HTTP/2 prior knowledge with `PRI `, and a stray TLS ClientHello
//! with 0x16, so one byte tells the two apart. A SOCKS connection is served in
//! process, with the byte put back at the front of it. Anything else is piped to
//! the HTTP backend, which listens on a Unix socket in the temp dir named
//! `srt-mux-<pid>-<seq>.sock`.
//!
//! The backend is bound before the front end accepts anything, so no connection
//! is dispatched to a backend that is not there. Its file goes with the proxy
//! that started it (ADR-0010). The socket binds wherever macOS takes its path,
//! past the 104 bytes of `sun_path`, as upstream's does under Node (ADR-0003).

use core::pin::Pin;
use core::task::{Context, Poll};
use std::fs;
use std::io;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, copy_bidirectional};
use tokio::time::timeout;

use super::shared::{Shared, Stream};
use super::socks;
use crate::unix_socket;

/// The first bytes that mean SOCKS: 0x05 greets SOCKS5, 0x04 is a SOCKS4 CONNECT.
const SOCKS: [u8; 2] = [0x04, 0x05];

/// How long a connection may take to send its first byte, as upstream's
/// `DEFAULT_FIRST_BYTE_TIMEOUT_MS` has it.
const FIRST_BYTE: Duration = Duration::from_secs(10);

/// The backend sockets bound so far in this process, so that two sandboxes do
/// not name the same file.
static SEQ: AtomicUsize = AtomicUsize::new(0);

/// The backend socket's file, which goes when this goes: with a `Proxy` that
/// took it over, and at once with a proxy that never started.
#[derive(Debug)]
pub(super) struct Socket(PathBuf);

impl Socket {
    /// Binds a fresh `srt-mux-<pid>-<seq>.sock` in the temp dir and takes the
    /// file it names, alongside the listener bound to it. A file a process of
    /// the same pid crashed with is removed first, as upstream's
    /// `listenHttpBackend` does.
    ///
    /// Call this outside a tokio runtime, and hand the listener to tokio's
    /// `UnixListener::from_std` inside one.
    pub(super) fn bind() -> io::Result<(UnixListener, Self)> {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("srt-mux-{}-{seq}.sock", std::process::id()));
        let _ = fs::remove_file(&path);
        let listener = unix_socket::bind(&path)?;
        Ok((listener, Self(path)))
    }

    /// The path to dial to reach the HTTP backend.
    pub(super) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// The front end's handler for one connection: the byte it peeked at picks the
/// leg, and SOCKS is served with that byte back at the front of the connection.
pub(super) async fn dispatch<S: Stream>(mut client: S, socket: PathBuf, shared: Arc<Shared>) {
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
    let _ = http(client, &socket, peeked).await;
}

/// Pipes `client` to the HTTP backend, with the byte the front end peeked at
/// written there first.
async fn http<S: Stream>(mut client: S, socket: &Path, peeked: u8) -> io::Result<()> {
    let mut backend = match unix_socket::connect(socket).await {
        Ok(backend) => backend,
        Err(error) => return refused(&mut client, &error).await,
    };
    backend.write_all(&[peeked]).await?;
    copy_bidirectional(&mut client, &mut backend)
        .await
        .map(drop)
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

#[cfg(test)]
mod tests;
