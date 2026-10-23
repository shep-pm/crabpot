//! The SOCKS5 proxy, as upstream's `createSocksProxyServer`
//! (`src/sandbox/socks-proxy.ts`) serves it: `CONNECT` only, behind the
//! username and password of RFC 1929 with the HTTP proxy's token, and judged by
//! the same filter. There is no route to a TLS-terminating proxy here.
//!
//! A refusal is a reply with a code, then the connection ends. Both kinds of
//! [`Denial`] answer "not allowed by ruleset", since a host that is not a DNS
//! name or an IP literal is one the allow list can never cover, and so does a
//! name the guard refuses an address of.

use core::net::SocketAddr;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional};
use tokio::net::TcpStream;

use super::shared::{DialError, Shared, dial, drain};
use super::token::Token;

const VERSION: u8 = 5;
const AUTH_VERSION: u8 = 1;

const USERNAME_PASSWORD: u8 = 2;
const NO_ACCEPTABLE_METHOD: u8 = 0xFF;

const CONNECT: u8 = 1;

const IPV4: u8 = 1;
const DOMAIN: u8 = 3;
const IPV6: u8 = 4;

/// The reply codes of RFC 1928 section 6 that crabpot answers with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reply {
    Succeeded = 0,
    Failure = 1,
    NotAllowed = 2,
    NetworkUnreachable = 3,
    HostUnreachable = 4,
    ConnectionRefused = 5,
    TtlExpired = 6,
    CommandNotSupported = 7,
    AddressNotSupported = 8,
}

impl From<&io::Error> for Reply {
    fn from(error: &io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::ConnectionRefused => Self::ConnectionRefused,
            io::ErrorKind::NetworkUnreachable => Self::NetworkUnreachable,
            io::ErrorKind::HostUnreachable | io::ErrorKind::NotFound => Self::HostUnreachable,
            io::ErrorKind::TimedOut => Self::TtlExpired,
            _ => Self::Failure,
        }
    }
}

impl From<&DialError> for Reply {
    fn from(error: &DialError) -> Self {
        match error {
            DialError::Refused(_) => Self::NotAllowed,
            DialError::Failed(error) => Self::from(error),
        }
    }
}

/// What a client connection is read from and answered on.
trait Stream: AsyncRead + AsyncWrite + Unpin {}

impl<T: AsyncRead + AsyncWrite + Unpin> Stream for T {}

/// One connection. A client that goes away mid-exchange is nobody's failure.
pub(super) async fn handle(mut client: TcpStream, shared: Arc<Shared>) {
    let _ = exchange(&mut client, &shared).await;
}

/// What reading the request ended in.
enum Request {
    Connect(String, u16),
    /// The reply to refuse with.
    Refuse(Reply),
    /// The client spoke something other than SOCKS5: drop the connection.
    Drop,
}

async fn exchange(client: &mut impl Stream, shared: &Shared) -> io::Result<()> {
    match read_greeting(client).await? {
        Some(methods) if methods.contains(&USERNAME_PASSWORD) => {
            client.write_all(&[VERSION, USERNAME_PASSWORD]).await?;
        }
        Some(_) => return refuse_unauthenticated(client).await,
        None => return Ok(()),
    }
    if !authenticate(client, &shared.token).await? {
        return Ok(());
    }
    let (host, port) = match read_connect(client).await? {
        Request::Connect(host, port) => (host, port),
        Request::Refuse(reply) => return refuse(client, reply).await,
        Request::Drop => return Ok(()),
    };
    let host = match shared.filter.check(&host, port) {
        Ok(host) => host,
        Err(_) => return refuse(client, Reply::NotAllowed).await,
    };
    let mut upstream = match dial(&shared.guard, &host, port).await {
        Ok(upstream) => upstream,
        Err(error) => return refuse(client, Reply::from(&error)).await,
    };
    client
        .write_all(&socks_reply(Reply::Succeeded, upstream.local_addr().ok()))
        .await?;
    copy_bidirectional(client, &mut upstream).await.map(drop)
}

/// The methods the client's greeting offers, or `None` for a client that does
/// not speak SOCKS5.
async fn read_greeting(client: &mut impl Stream) -> io::Result<Option<Vec<u8>>> {
    let mut head = [0u8; 2];
    client.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Ok(None);
    }
    let mut methods = vec![0u8; usize::from(head[1])];
    client.read_exact(&mut methods).await?;
    Ok(Some(methods))
}

/// Answers a client that offers no way to present the token, which is every
/// client that does not offer a username and password. Anonymous access
/// would let any local process through.
async fn refuse_unauthenticated(client: &mut impl Stream) -> io::Result<()> {
    client.write_all(&[VERSION, NO_ACCEPTABLE_METHOD]).await?;
    end(client).await
}

/// The subnegotiation of RFC 1929. `false` once the client is answered and
/// ended.
async fn authenticate(client: &mut impl Stream, token: &Token) -> io::Result<bool> {
    let mut version = [0u8; 1];
    client.read_exact(&mut version).await?;
    let user = read_field(client).await?;
    let password = read_field(client).await?;
    let accepted = version[0] == AUTH_VERSION
        && token.accepts_login(
            &String::from_utf8_lossy(&user),
            &String::from_utf8_lossy(&password),
        );
    client
        .write_all(&[AUTH_VERSION, u8::from(!accepted)])
        .await?;
    if !accepted {
        end(client).await?;
    }
    Ok(accepted)
}

/// A length byte, then that many bytes.
async fn read_field(client: &mut impl Stream) -> io::Result<Vec<u8>> {
    let mut length = [0u8; 1];
    client.read_exact(&mut length).await?;
    let mut field = vec![0u8; usize::from(length[0])];
    client.read_exact(&mut field).await?;
    Ok(field)
}

/// The request: the host as the client wrote it, and the port. The whole
/// request is read before a refusal is chosen, so the refusal answers a
/// client that has finished sending.
async fn read_connect(client: &mut impl Stream) -> io::Result<Request> {
    let mut head = [0u8; 4];
    client.read_exact(&mut head).await?;
    let [version, command, _reserved, kind] = head;
    if version != VERSION {
        return Ok(Request::Drop);
    }
    let host = match kind {
        IPV4 => {
            let mut octets = [0u8; 4];
            client.read_exact(&mut octets).await?;
            Ipv4Addr::from(octets).to_string()
        }
        DOMAIN => String::from_utf8_lossy(&read_field(client).await?).into_owned(),
        IPV6 => {
            let mut octets = [0u8; 16];
            client.read_exact(&mut octets).await?;
            Ipv6Addr::from(octets).to_string()
        }
        _ => return Ok(Request::Refuse(Reply::AddressNotSupported)),
    };
    let mut port = [0u8; 2];
    client.read_exact(&mut port).await?;
    if command != CONNECT {
        return Ok(Request::Refuse(Reply::CommandNotSupported));
    }
    Ok(Request::Connect(host, u16::from_be_bytes(port)))
}

/// A reply of RFC 1928 section 6, with the address the proxy connected from,
/// or the zero address when there is none.
fn socks_reply(reply: Reply, bound: Option<SocketAddr>) -> Vec<u8> {
    let mut bytes = vec![VERSION, reply as u8, 0];
    match bound {
        Some(SocketAddr::V4(address)) => {
            bytes.push(IPV4);
            bytes.extend_from_slice(&address.ip().octets());
            bytes.extend_from_slice(&address.port().to_be_bytes());
        }
        Some(SocketAddr::V6(address)) => {
            bytes.push(IPV6);
            bytes.extend_from_slice(&address.ip().octets());
            bytes.extend_from_slice(&address.port().to_be_bytes());
        }
        None => {
            bytes.push(IPV4);
            bytes.extend_from_slice(&[0; 6]);
        }
    }
    bytes
}

async fn refuse(client: &mut impl Stream, reply: Reply) -> io::Result<()> {
    client.write_all(&socks_reply(reply, None)).await?;
    end(client).await
}

/// Closes after a refusal, once what the client is still sending is read.
async fn end(client: &mut impl Stream) -> io::Result<()> {
    client.shutdown().await?;
    drain(client).await;
    Ok(())
}

#[cfg(test)]
mod tests;
