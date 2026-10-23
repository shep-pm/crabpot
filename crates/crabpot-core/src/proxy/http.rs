//! The HTTP proxy: `CONNECT` tunnels and plain `http://` requests, as upstream's
//! `createHttpProxyServer` (`src/sandbox/http-proxy.ts`) serves them, less
//! what the keys not built yet switch on (TLS termination, a parent proxy,
//! request filters).
//!
//! A plain request is forwarded as its head with the hop-by-hop headers
//! dropped, then as many body bytes as its `Content-Length` says, and the
//! answer passes back as it comes. Anything the client sends after that, such
//! as a second request on the same connection, is not forwarded: it would reach
//! the origin without being read, filtered or stripped of the credential. A
//! body of unknown length (`Transfer-Encoding`) is refused for the same reason.
//! The upstream connection is asked to close after the answer.

use core::pin::Pin;
use core::task::{Context, Poll};
use std::io;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional, join, split};
use tokio::net::TcpStream;

use super::filter::Denial;
use super::shared::{DialError, Shared, Stream, dial, drain};

/// A request head longer than this is refused with 431, as Node's default.
const MAX_HEAD_BYTES: usize = 16 * 1024;
const MAX_HEADERS: usize = 100;

/// One connection. A client that goes away mid-exchange is nobody's failure.
pub(super) async fn handle<S: Stream>(mut client: S, shared: Arc<Shared>) {
    let _ = exchange(&mut client, &shared).await;
}

/// A parsed request head.
struct Head {
    method: String,
    target: String,
    headers: Vec<(String, Vec<u8>)>,
}

impl Head {
    /// The first header called `name`, if it is text.
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(field, _)| field.eq_ignore_ascii_case(name))
            .and_then(|(_, value)| core::str::from_utf8(value).ok())
    }
}

enum Read {
    Head(Head, Vec<u8>),
    /// The status line to answer with.
    Refused(&'static str),
    Closed,
}

async fn exchange<S: Stream>(client: &mut S, shared: &Shared) -> io::Result<()> {
    match read_head(client).await? {
        Read::Head(head, early) if head.method.eq_ignore_ascii_case("CONNECT") => {
            tunnel(client, shared, &head, early).await
        }
        Read::Head(head, early) => forward(client, shared, &head, early).await,
        Read::Refused(status) => end(client, &format!("HTTP/1.1 {status}\r\n\r\n")).await,
        Read::Closed => Ok(()),
    }
}

/// Reads up to the end of the request head. The bytes after it, which are the
/// start of a body or of a tunnel, come back as `early`.
async fn read_head<S: Stream>(client: &mut S) -> io::Result<Read> {
    let mut buf = Vec::with_capacity(1024);
    loop {
        let mut fields = [httparse::EMPTY_HEADER; MAX_HEADERS];
        let mut request = httparse::Request::new(&mut fields);
        match request.parse(&buf) {
            Ok(httparse::Status::Complete(len)) => {
                let head = Head {
                    method: request.method.unwrap_or_default().to_owned(),
                    target: request.path.unwrap_or_default().to_owned(),
                    headers: request
                        .headers
                        .iter()
                        .map(|field| (field.name.to_owned(), field.value.to_vec()))
                        .collect(),
                };
                return Ok(Read::Head(head, buf.split_off(len)));
            }
            Ok(httparse::Status::Partial) if buf.len() < MAX_HEAD_BYTES => {}
            Ok(httparse::Status::Partial) | Err(httparse::Error::TooManyHeaders) => {
                return Ok(Read::Refused("431 Request Header Fields Too Large"));
            }
            Err(_) => return Ok(Read::Refused("400 Bad Request")),
        }
        if client.read_buf(&mut buf).await? == 0 {
            return Ok(Read::Closed);
        }
    }
}

/// Writes `response` and closes: every refusal ends its connection. What the
/// client is still sending is read and dropped for a moment first, since
/// closing on unread bytes resets the connection and can take the response
/// with it.
async fn end<S: Stream>(client: &mut S, response: &str) -> io::Result<()> {
    client.write_all(response.as_bytes()).await?;
    client.shutdown().await?;
    drain(client).await;
    Ok(())
}

const BAD_REQUEST: &str = "HTTP/1.1 400 Bad Request\r\n\r\n";
const BAD_GATEWAY: &str = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
const NOT_IMPLEMENTED: &str = "HTTP/1.1 501 Not Implemented\r\n\r\n";
const AUTH_REQUIRED: &str = "HTTP/1.1 407 Proxy Authentication Required\r\n\
     Proxy-Authenticate: Basic realm=\"srt\"\r\n\
     Content-Length: 0\r\n\
     Connection: close\r\n\r\n";

/// A 403 that marks itself with `tag` in `X-Proxy-Error`.
fn forbidden(phrase: &str, tag: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 403 {phrase}\r\n\
         Content-Type: text/plain\r\n\
         X-Proxy-Error: {tag}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
}

/// The 403 for a refused host. The reason is the status line's phrase for a
/// tunnel, where upstream puts it, and the body says the same for either.
fn denied(phrase: &str) -> String {
    forbidden(
        phrase,
        "blocked-by-allowlist",
        "Connection blocked by network allowlist",
    )
}

/// What a failed dial answers with. A name that resolved only to addresses the
/// guard refuses gets a 403 whose body names the host and the class of address.
/// A tunnel's status line carries the class too, and a plain request's says
/// "Forbidden".
fn undialed(error: &DialError, tunnel: bool) -> String {
    match error {
        DialError::Refused(refusal) => {
            let phrase = if tunnel {
                refusal.reason()
            } else {
                "Forbidden".to_owned()
            };
            forbidden(&phrase, "blocked-by-sandbox-runtime", &refusal.message())
        }
        DialError::Failed(_) => BAD_GATEWAY.to_owned(),
    }
}

/// A `CONNECT`: the tunnel to `host:port` if the filter allows it.
async fn tunnel<S: Stream>(
    client: &mut S,
    shared: &Shared,
    head: &Head,
    early: Vec<u8>,
) -> io::Result<()> {
    if !shared.token.accepts(head.header("proxy-authorization")) {
        return end(client, AUTH_REQUIRED).await;
    }
    let Some((requested, port)) = parse_connect_target(&head.target) else {
        return end(client, BAD_REQUEST).await;
    };
    let host = match shared.filter.check(requested, port) {
        Ok(host) => host,
        Err(denial) => return end(client, &denied(denial.reason())).await,
    };
    let mut upstream = match dial(&shared.guard, &host, port).await {
        Ok(upstream) => upstream,
        Err(error) => return end(client, &undialed(&error, true)).await,
    };
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    pipe(client, &mut upstream, &early).await
}

/// Passes bytes both ways until both sides are done. `early` is what the
/// client sent in the packet of its head.
async fn pipe<S: Stream>(client: &mut S, upstream: &mut TcpStream, early: &[u8]) -> io::Result<()> {
    upstream.write_all(early).await?;
    copy_bidirectional(client, upstream).await.map(drop)
}

/// A request to `http://host[:port]/path`: forwarded to the host if the filter
/// allows it.
async fn forward<S: Stream>(
    client: &mut S,
    shared: &Shared,
    head: &Head,
    early: Vec<u8>,
) -> io::Result<()> {
    if !shared.token.accepts(head.header("proxy-authorization")) {
        return end(client, AUTH_REQUIRED).await;
    }
    let Some(target) = Absolute::parse(&head.target) else {
        return end(client, BAD_REQUEST).await;
    };
    let host = match shared.filter.check(target.host, target.port) {
        Ok(host) => host,
        // Upstream gives the reason to a tunnel's refusal alone.
        Err(Denial::MalformedHost | Denial::Denied | Denial::NotAllowed) => {
            return end(client, &denied("Forbidden")).await;
        }
    };
    let body = match body_length(head) {
        Ok(length) => length,
        Err(refusal) => return end(client, refusal).await,
    };
    let mut upstream = match dial(&shared.guard, &host, target.port).await {
        Ok(upstream) => upstream,
        Err(error) => return end(client, &undialed(&error, false)).await,
    };
    let mut request = format!("{} {} HTTP/1.1\r\n", head.method, target.path).into_bytes();
    for (name, value) in forwarded_headers(head) {
        request.extend_from_slice(name.as_bytes());
        request.extend_from_slice(b": ");
        request.extend_from_slice(value);
        request.extend_from_slice(b"\r\n");
    }
    let authority = authority(&host, target.port);
    request.extend_from_slice(format!("Host: {authority}\r\nConnection: close\r\n\r\n").as_bytes());
    let in_head_packet = early.len().min(usize::try_from(body).unwrap_or(usize::MAX));
    request.extend_from_slice(&early[..in_head_packet]);
    let body_left = body - in_head_packet as u64;
    relay(client, &mut upstream, &request, body_left).await?;
    drain(client).await;
    Ok(())
}

/// How many body bytes the request carries, or the refusal to answer with when
/// that is not known: a `Transfer-Encoding`, or a `Content-Length` that is not
/// one number.
fn body_length(head: &Head) -> Result<u64, &'static str> {
    if head.header("transfer-encoding").is_some() {
        return Err(NOT_IMPLEMENTED);
    }
    let mut lengths = head
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"));
    let Some((_, value)) = lengths.next() else {
        return Ok(0);
    };
    if lengths.next().is_some() {
        return Err(BAD_REQUEST);
    }
    core::str::from_utf8(value)
        .ok()
        .filter(|text| !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|text| text.parse().ok())
        .ok_or(BAD_REQUEST)
}

/// Writes `request` to the origin, then passes `body_left` more bytes from the
/// client and the whole answer back. The origin's write side stays open, since
/// some servers take a half-close for a client that left.
async fn relay<S: Stream>(
    client: &mut S,
    upstream: &mut TcpStream,
    request: &[u8],
    body_left: u64,
) -> io::Result<()> {
    upstream.write_all(request).await?;
    let (client_read, client_write) = split(client);
    let (upstream_read, upstream_write) = split(upstream);
    let mut client = join(client_read.take(body_left), client_write);
    let mut upstream = join(upstream_read, KeepOpen(upstream_write));
    copy_bidirectional(&mut client, &mut upstream)
        .await
        .map(drop)
}

/// A writer whose shutdown does nothing.
struct KeepOpen<W>(W);

impl<W: AsyncWrite + Unpin> AsyncWrite for KeepOpen<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Hop-by-hop headers are for the connection to the proxy, so they are not
/// forwarded, nor is the `Host`, which is rewritten. `Content-Length` is kept,
/// since the body passes as it came.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
    "host",
];
const FRAMING: &[&str] = &["content-length"];

fn forwarded_headers(head: &Head) -> impl Iterator<Item = (&str, &[u8])> {
    let named: Vec<String> = head
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
        .filter_map(|(_, value)| core::str::from_utf8(value).ok())
        .flat_map(|value| value.split(','))
        .map(|token| token.trim().to_ascii_lowercase())
        .collect();
    head.headers
        .iter()
        .filter(move |(name, _)| {
            let name = name.to_ascii_lowercase();
            FRAMING.contains(&name.as_str())
                || !(HOP_BY_HOP.contains(&name.as_str()) || named.contains(&name))
        })
        .map(|(name, value)| (name.as_str(), value.as_slice()))
}

/// `host[:port]` as a `Host` header has it: an IPv6 address in brackets, and
/// port 80 left out.
fn authority(host: &str, port: u16) -> String {
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    if port == 80 {
        host
    } else {
        format!("{host}:{port}")
    }
}

/// Splits a `CONNECT` target, `host:port` or `[ipv6]:port`, as upstream's
/// `parseConnectTarget` does.
fn parse_connect_target(target: &str) -> Option<(&str, u16)> {
    let (host, port) = match target.strip_prefix('[') {
        Some(rest) => {
            let (host, after) = rest.split_once(']')?;
            (host, after.strip_prefix(':')?)
        }
        None => target.split_once(':')?,
    };
    (!host.is_empty()).then_some(())?;
    Some((host, parse_port(port)?))
}

/// A port written in digits, 1 to 65535.
fn parse_port(text: &str) -> Option<u16> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<u32>()
        .ok()
        .filter(|port| (1..=65535).contains(port))
        .and_then(|port| u16::try_from(port).ok())
}

/// The target of a proxied `http://` request.
struct Absolute<'a> {
    host: &'a str,
    port: u16,
    /// The path and query, which is what the origin is asked for.
    path: String,
}

impl<'a> Absolute<'a> {
    /// `None` for anything but `http://host[:port][/path][?query]`. A target
    /// with a userinfo is refused, since a reader that stops at the `@` and one
    /// that stops at the `:` would name different hosts.
    fn parse(target: &'a str) -> Option<Self> {
        let rest = target
            .get(..7)
            .filter(|s| s.eq_ignore_ascii_case("http://"))?;
        let rest = &target[rest.len()..];
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        if authority.contains('@') {
            return None;
        }
        let (host, port) = match authority.strip_prefix('[') {
            Some(inner) => {
                let (host, after) = inner.split_once(']')?;
                match after {
                    "" => (host, None),
                    _ => (host, Some(after.strip_prefix(':')?)),
                }
            }
            None => match authority.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority, None),
            },
        };
        let port = match port {
            None | Some("") => 80,
            Some(port) => parse_port(port)?,
        };
        let tail = tail.split('#').next().unwrap_or_default();
        let path = if tail.starts_with('/') {
            tail.to_owned()
        } else {
            format!("/{tail}")
        };
        (!host.is_empty()).then_some(Self { host, port, path })
    }
}

#[cfg(test)]
mod tests;
