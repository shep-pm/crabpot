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
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use super::testing::{origin, proxy_allowing};
use super::token::base64_encode;
use super::{PortRange, Proxy, TcpGrant, username_for};
use crate::config::MitmProxy;
use crate::domain::{DomainEntry, DomainPattern};

/// How long a client waits for the proxy to answer, so a proxy that never does
/// fails a test instead of hanging it.
const PATIENCE: Duration = Duration::from_secs(10);

/// A client of the mux on its Unix socket, in place of a client of the port.
fn mux_client(proxy: &Proxy) -> UnixStream {
    let stream = UnixStream::connect(proxy.mux_socket()).unwrap();
    stream.set_read_timeout(Some(PATIENCE)).unwrap();
    stream
}

fn allowed_entries(entries: &[&str]) -> Vec<DomainEntry> {
    entries
        .iter()
        .map(|entry| DomainEntry::parse_allowed(entry).unwrap())
        .collect()
}

fn denied_entries(entries: &[&str]) -> Vec<DomainEntry> {
    entries
        .iter()
        .map(|entry| DomainEntry::parse_denied(entry).unwrap())
        .collect()
}

/// A proxy that lets `allowed` through and refuses `denied` over `allowed`'s head.
fn proxy_denying(allowed: &[&str], denied: &[&str]) -> Proxy {
    Proxy::start(
        &allowed_entries(allowed),
        &denied_entries(denied),
        &[],
        false,
        None,
    )
    .unwrap()
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

#[test]
fn a_domain_added_while_running_is_allowed_on_the_next_request() {
    let proxy = proxy_allowing(&[]);
    let (port, _) = origin(None);
    let target = format!("127.0.0.1:{port}");
    let refused = head(&mut connect(&proxy, &target));
    assert!(
        refused.starts_with("HTTP/1.1 403 host is not on the allow list\r\n"),
        "{refused}"
    );

    proxy.replace_lists(&allowed_entries(&["127.0.0.1"]), &[], &[]);

    let mut stream = connect(&proxy, &target);
    assert_eq!(
        head(&mut stream),
        "HTTP/1.1 200 Connection Established\r\n\r\n",
    );
    stream.write_all(b"ping").unwrap();
    assert_eq!(&read_n::<4>(&mut stream), b"ping", "the tunnel");
}

#[test]
fn a_domain_removed_while_running_is_refused_on_the_next_request() {
    let proxy = proxy_allowing(&["127.0.0.1"]);
    let (port, _) = origin(None);
    let target = format!("127.0.0.1:{port}");
    let mut stream = connect(&proxy, &target);
    assert_eq!(
        head(&mut stream),
        "HTTP/1.1 200 Connection Established\r\n\r\n",
    );
    drop(stream);

    proxy.replace_lists(&[], &[], &[]);

    let refused = head(&mut connect(&proxy, &target));
    assert!(
        refused.starts_with("HTTP/1.1 403 host is not on the allow list\r\n"),
        "{refused}"
    );
}

#[test]
fn a_denied_domain_added_while_running_wins_over_an_allowed_one() {
    let proxy = proxy_allowing(&["127.0.0.1"]);
    let (port, _) = origin(None);

    proxy.replace_lists(
        &allowed_entries(&["127.0.0.1"]),
        &denied_entries(&["127.0.0.1"]),
        &[],
    );

    let refused = head(&mut connect(&proxy, &format!("127.0.0.1:{port}")));
    assert!(
        refused.starts_with("HTTP/1.1 403 host is on the deny list\r\n"),
        "{refused}"
    );
}

#[test]
fn a_tunnel_open_before_the_swap_keeps_running() {
    let proxy = proxy_allowing(&["127.0.0.1"]);
    let (port, _) = origin(None);
    let mut stream = connect(&proxy, &format!("127.0.0.1:{port}"));
    assert_eq!(
        head(&mut stream),
        "HTTP/1.1 200 Connection Established\r\n\r\n",
    );
    stream.write_all(b"ping").unwrap();
    assert_eq!(&read_n::<4>(&mut stream), b"ping");

    proxy.replace_lists(&[], &denied_entries(&["127.0.0.1"]), &[]);

    stream.write_all(b"pong").unwrap();
    assert_eq!(&read_n::<4>(&mut stream), b"pong", "the open tunnel");
}

/// Answers one `CONNECT` on `listener` with a 200, then echoes. It hands back
/// the head it was sent.
fn mitm_stand_in(listener: UnixListener) -> thread::JoinHandle<String> {
    thread::spawn(move || {
        let (mut client, _) = listener.accept().unwrap();
        client.set_read_timeout(Some(PATIENCE)).unwrap();
        let head = self::head(&mut client);
        client.write_all(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
        let mut bytes = [0u8; 64];
        while let Ok(read @ 1..) = client.read(&mut bytes) {
            if client.write_all(&bytes[..read]).is_err() {
                break;
            }
        }
        head
    })
}

#[test]
fn replacing_the_lists_keeps_the_tcp_destinations_and_the_mitm_setting() {
    let socket = std::env::temp_dir().join(format!("swap-mitm-{}.sock", std::process::id()));
    let _ = fs::remove_file(&socket);
    let stand_in = mitm_stand_in(UnixListener::bind(&socket).unwrap());
    let (port, _) = origin(None);
    let mitm = MitmProxy {
        socket_path: socket.to_str().unwrap().to_owned(),
        domains: vec![DomainPattern::parse("mitm.example.com").unwrap()],
    };
    let grant = TcpGrant {
        host: "db.example.com".to_owned(),
        address: format!("127.0.0.1:{port}").parse().unwrap(),
    };
    let proxy = Proxy::start_with_tcp(
        &allowed_entries(&["mitm.example.com"]),
        &[],
        &[],
        false,
        Some(&mitm),
        &[grant],
    )
    .unwrap();

    proxy.replace_lists(
        &allowed_entries(&["mitm.example.com", "other.example.com"]),
        &[],
        &[],
    );

    let mut tunnel = connect(&proxy, &format!("127.0.0.1:{port}"));
    assert_eq!(
        head(&mut tunnel),
        "HTTP/1.1 200 Connection Established\r\n\r\n",
        "the allowTcp grant",
    );
    tunnel.write_all(b"ping").unwrap();
    assert_eq!(&read_n::<4>(&mut tunnel), b"ping");
    let mut routed = connect(&proxy, "mitm.example.com:443");
    assert_eq!(
        head(&mut routed),
        "HTTP/1.1 200 Connection Established\r\n\r\n",
        "the mitmProxy route",
    );
    drop(routed);
    let seen = stand_in.join().unwrap();
    assert!(
        seen.starts_with("CONNECT mitm.example.com:443 HTTP/1.1\r\n"),
        "{seen}"
    );
    let _ = fs::remove_file(&socket);
}

/// With `localhost` allowed and nothing listening on the port, a request ends
/// in a 502 under one set of lists and in a 403 "not on the allow list" under
/// the other, which allows nothing. A filter of one set with the guard of the
/// other ends in the guard's 403, which no whole set gives.
#[test]
fn replacing_the_lists_while_requests_arrive_never_lets_a_request_see_a_half_swapped_set() {
    let port = {
        let held = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        held.local_addr().unwrap().port()
    };
    let proxy = proxy_allowing(&["localhost"]);
    let open = allowed_entries(&["localhost"]);
    let shut = denied_entries(&["127.0.0.1", "[::1]"]);
    let done = AtomicBool::new(false);

    thread::scope(|scope| {
        scope.spawn(|| {
            while !done.load(Ordering::Relaxed) {
                proxy.replace_lists(&open, &[], &[]);
                proxy.replace_lists(&[], &shut, &[]);
            }
        });
        for _ in 0..100 {
            let answer = head(&mut connect(&proxy, &format!("localhost:{port}")));
            assert!(
                answer.starts_with("HTTP/1.1 502 ")
                    || answer.starts_with("HTTP/1.1 403 host is not on the allow list\r\n"),
                "{answer}"
            );
        }
        done.store(true, Ordering::Relaxed);
    });
}
