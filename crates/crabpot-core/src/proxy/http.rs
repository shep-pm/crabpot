//! The HTTP proxy: `CONNECT` tunnels and plain `http://` requests, as upstream's
//! `createHttpProxyServer` (`src/sandbox/http-proxy.ts`) serves them, less
//! what the keys not built yet switch on (TLS termination, a parent proxy,
//! request filters).
//!
//! A plain request is forwarded as its head with the hop-by-hop headers
//! dropped, and then the two sockets are joined, so its body and the answer
//! pass as they come. The upstream connection is asked to close after the
//! answer.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, copy, copy_bidirectional, sink};
use tokio::net::{TcpListener, TcpStream, lookup_host};
use tokio::time::{sleep, timeout};

use super::filter::{Denial, Filter};
use super::token::Token;

/// A request head longer than this is refused with 431, as Node's default.
const MAX_HEAD_BYTES: usize = 16 * 1024;
const MAX_HEADERS: usize = 100;

/// How long a dial may take in all, and how long it may spend on one address.
const DIAL_TIMEOUT: Duration = Duration::from_secs(30);
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a refused client may go on sending before the connection is dropped.
const LINGER: Duration = Duration::from_secs(1);

/// What every connection is judged by.
#[derive(Debug)]
pub(super) struct Shared {
    filter: Filter,
    token: Token,
}

impl Shared {
    pub(super) fn new(filter: Filter, token: Token) -> Self {
        Self { filter, token }
    }
}

/// Answers connections to `listener` until the runtime it runs on is dropped.
pub(super) async fn serve(listener: TcpListener, shared: Arc<Shared>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(handle(stream, Arc::clone(&shared)));
            }
            // Out of descriptors, or a peer that reset before it was accepted:
            // wait a moment and take the next one.
            Err(_) => sleep(Duration::from_millis(10)).await,
        }
    }
}

/// One connection. A client that goes away mid-exchange is nobody's failure.
async fn handle(mut client: TcpStream, shared: Arc<Shared>) {
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

async fn exchange(client: &mut TcpStream, shared: &Shared) -> io::Result<()> {
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
async fn read_head(client: &mut TcpStream) -> io::Result<Read> {
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
async fn end(client: &mut TcpStream, response: &str) -> io::Result<()> {
    client.write_all(response.as_bytes()).await?;
    client.shutdown().await?;
    let _ = timeout(LINGER, copy(client, &mut sink())).await;
    Ok(())
}

const BAD_REQUEST: &str = "HTTP/1.1 400 Bad Request\r\n\r\n";
const BAD_GATEWAY: &str = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
const AUTH_REQUIRED: &str = "HTTP/1.1 407 Proxy Authentication Required\r\n\
     Proxy-Authenticate: Basic realm=\"srt\"\r\n\
     Content-Length: 0\r\n\
     Connection: close\r\n\r\n";

/// The 403 for a refused host. The reason is the status line's phrase for a
/// tunnel, where upstream puts it, and the body says the same for either.
fn denied(phrase: &str) -> String {
    const BODY: &str = "Connection blocked by network allowlist";
    format!(
        "HTTP/1.1 403 {phrase}\r\n\
         Content-Type: text/plain\r\n\
         X-Proxy-Error: blocked-by-allowlist\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{BODY}",
        BODY.len()
    )
}

/// A `CONNECT`: the tunnel to `host:port` if the filter allows it.
async fn tunnel(
    client: &mut TcpStream,
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
    let Ok(mut upstream) = dial(&host, port).await else {
        return end(client, BAD_GATEWAY).await;
    };
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    join(client, &mut upstream, &early).await
}

/// Passes bytes both ways until both sides are done. `early` is what the
/// client sent in the packet of its head.
async fn join(client: &mut TcpStream, upstream: &mut TcpStream, early: &[u8]) -> io::Result<()> {
    upstream.write_all(early).await?;
    copy_bidirectional(client, upstream).await.map(drop)
}

/// A request to `http://host[:port]/path`: forwarded to the host if the filter
/// allows it.
async fn forward(
    client: &mut TcpStream,
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
        Err(Denial::MalformedHost | Denial::NotAllowed) => {
            return end(client, &denied("Forbidden")).await;
        }
    };
    let Ok(mut upstream) = dial(&host, target.port).await else {
        return end(client, BAD_GATEWAY).await;
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
    request.extend_from_slice(&early);
    join(client, &mut upstream, &request).await
}

/// Hop-by-hop headers are for the connection to the proxy, so they are not
/// forwarded, nor is the `Host`, which is rewritten. The framing of the body
/// is kept, since the body passes as it came.
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
const FRAMING: &[&str] = &["content-length", "transfer-encoding"];

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

/// Connects to `host:port`, trying each address its name resolves to.
async fn dial(host: &str, port: u16) -> io::Result<TcpStream> {
    let attempts = async {
        let mut last = io::Error::new(io::ErrorKind::NotFound, "the host has no address");
        for address in lookup_host((host, port)).await? {
            match timeout(ATTEMPT_TIMEOUT, TcpStream::connect(address)).await {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(error)) => last = error,
                Err(_) => last = io::ErrorKind::TimedOut.into(),
            }
        }
        Err(last)
    };
    timeout(DIAL_TIMEOUT, attempts)
        .await
        .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()))
}

#[cfg(test)]
mod tests;
