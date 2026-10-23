//! The proxy as a client of its Unix socket sees it (issue #106).
//!
//! Inside a network namespace no loopback port can be reached, and only a socket
//! bound there is one a sandboxed command can dial (ADR-0014). So the mux is
//! served on a Unix socket as well as on the loopback port. These tests dial
//! that socket and judge what answers, which is the whole promise of it: the same
//! two protocols, the same filter, the same token, and a file that is this
//! sandbox's alone and goes with it.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;

use super::testing::{origin, proxy_allowing};
use super::token::base64_encode;
use super::{PortRange, Proxy, username_for};
use crate::domain::DomainEntry;

/// A client of the mux on its Unix socket, in place of a client of the port.
fn mux_client(proxy: &Proxy) -> UnixStream {
    UnixStream::connect(proxy.mux_socket()).unwrap()
}

/// A proxy that lets `allowed` through and refuses `denied` over `allowed`'s head.
fn proxy_denying(allowed: &[&str], denied: &[&str]) -> Proxy {
    let allowed: Vec<DomainEntry> = allowed
        .iter()
        .map(|entry| DomainEntry::parse_allowed(entry).unwrap())
        .collect();
    let denied: Vec<DomainEntry> = denied
        .iter()
        .map(|entry| DomainEntry::parse_denied(entry).unwrap())
        .collect();
    Proxy::start(&allowed, &denied, &[], false, None).unwrap()
}

/// The `Proxy-Authorization` header the HTTP leg wants.
fn credential(proxy: &Proxy) -> String {
    let user = username_for("test");
    format!(
        "Proxy-Authorization: Basic {}\r\n",
        base64_encode(format!("{user}:{}", proxy.token()).as_bytes())
    )
}

/// The SOCKS5 greeting that offers a username and password, and the login with
/// the proxy's token.
fn login(proxy: &Proxy) -> Vec<u8> {
    let user = username_for("test");
    let token = proxy.token();
    let mut sent = vec![5, 1, 2, 1, u8::try_from(user.len()).unwrap()];
    sent.extend_from_slice(user.as_bytes());
    sent.push(u8::try_from(token.len()).unwrap());
    sent.extend_from_slice(token.as_bytes());
    sent
}

/// The SOCKS5 `CONNECT` to an IPv4 literal.
fn connect_request(address: [u8; 4], port: u16) -> Vec<u8> {
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&address);
    request.extend_from_slice(&port.to_be_bytes());
    request
}

/// Reads up to and including the blank line that ends a head.
fn head(stream: &mut UnixStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).unwrap() == 0 {
            break;
        }
        head.push(byte[0]);
    }
    String::from_utf8(head).unwrap()
}

fn read_n<const N: usize>(stream: &mut UnixStream) -> [u8; N] {
    let mut bytes = [0u8; N];
    stream.read_exact(&mut bytes).unwrap();
    bytes
}

fn connect(proxy: &Proxy, target: &str) -> UnixStream {
    let mut stream = mux_client(proxy);
    stream
        .write_all(
            format!(
                "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{}\r\n",
                credential(proxy)
            )
            .as_bytes(),
        )
        .unwrap();
    stream
}

#[test]
fn the_unix_socket_serves_an_http_connect() {
    let proxy = proxy_allowing(&["127.0.0.1"]);
    let (port, _) = origin(None);
    let mut stream = connect(&proxy, &format!("127.0.0.1:{port}"));

    assert_eq!(
        head(&mut stream),
        "HTTP/1.1 200 Connection Established\r\n\r\n",
        "the HTTP leg reaches a client of the socket",
    );
    stream.write_all(b"ping").unwrap();
    assert_eq!(&read_n::<4>(&mut stream), b"ping", "the tunnel");
}

#[test]
fn the_unix_socket_serves_a_socks_connect() {
    let proxy = proxy_allowing(&["127.0.0.1"]);
    let (port, _) = origin(None);
    let mut stream = mux_client(&proxy);
    stream.write_all(&login(&proxy)).unwrap();

    assert_eq!(
        read_n::<4>(&mut stream),
        [5, 2, 1, 0],
        "the SOCKS login is answered on the socket too",
    );
    stream
        .write_all(&connect_request([127, 0, 0, 1], port))
        .unwrap();
    let reply = read_n::<10>(&mut stream);
    assert_eq!(reply[..4], [5, 0, 0, 1], "the CONNECT");
    stream.write_all(b"ping").unwrap();
    assert_eq!(&read_n::<4>(&mut stream), b"ping", "the tunnel");
}

#[test]
fn the_unix_socket_is_mode_0600() {
    let proxy = proxy_allowing(&[]);

    let mode = fs::metadata(proxy.mux_socket()).unwrap().mode() & 0o777;
    assert_eq!(mode, 0o600, "{mode:o} is not owner-only");
}

#[test]
fn the_unix_socket_file_is_removed_on_drop() {
    let proxy = proxy_allowing(&[]);
    let path = proxy.mux_socket().to_path_buf();
    let name = path.file_name().unwrap().to_string_lossy().into_owned();
    let hex = name
        .strip_prefix("claude-http-")
        .and_then(|rest| rest.strip_suffix(".sock"))
        .unwrap_or_default();

    assert!(
        hex.len() == 16 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{name} is not upstream's `claude-http-<16 hex>.sock`",
    );
    assert!(
        fs::metadata(&path).unwrap().file_type().is_socket(),
        "the socket is bound while the proxy runs",
    );

    drop(proxy);
    assert!(!path.exists(), "the socket outlived the proxy");
}

#[test]
fn a_denied_domain_is_refused_on_the_unix_socket() {
    let proxy = proxy_denying(&["*.example.com"], &["blocked.example.com"]);
    let mut stream = connect(&proxy, "blocked.example.com:443");

    let head = head(&mut stream);
    assert!(
        head.starts_with("HTTP/1.1 403 host is on the deny list\r\n"),
        "{head}"
    );
    assert!(
        head.contains("X-Proxy-Error: blocked-by-allowlist\r\n"),
        "{head}"
    );
    let mut body = String::new();
    stream.read_to_string(&mut body).unwrap();
    assert_eq!(body, "Connection blocked by network allowlist");
}

/// `Proxy::start` has no range: it binds the ports the OS picks, so more
/// proxies than the default range holds run at once.
#[test]
fn start_keeps_binding_an_ephemeral_port() {
    let width = usize::from(PortRange::DEFAULT.last() - PortRange::DEFAULT.first()) + 2;

    let proxies: Vec<Proxy> = (0..width).map(|_| proxy_allowing(&[])).collect();

    for proxy in &proxies {
        assert_ne!(proxy.port(), 0);
    }
}
