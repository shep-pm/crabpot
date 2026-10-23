use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use super::super::token::base64_encode;
use super::super::{Proxy, username_for};
use super::{Absolute, parse_connect_target};
use crate::domain::DomainEntry;

fn proxy_allowing(entries: &[&str]) -> Proxy {
    let entries: Vec<DomainEntry> = entries
        .iter()
        .map(|entry| DomainEntry::parse_allowed(entry).unwrap())
        .collect();
    Proxy::start(&entries, &[], false).unwrap()
}

/// A server on a loopback port that answers its first client with `reply`,
/// or echoes it when there is none, and hands back what it read. With a
/// reply it goes on reading for a moment after it has answered.
fn origin(reply: Option<&'static str>) -> (u16, thread::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = thread::spawn(move || {
        let (mut client, _) = listener.accept().unwrap();
        let mut seen = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = client.read(&mut buf).unwrap();
            if n == 0 {
                return seen;
            }
            seen.extend_from_slice(&buf[..n]);
            match reply {
                None => client.write_all(&buf[..n]).unwrap(),
                Some(reply) if seen.windows(4).any(|w| w == b"\r\n\r\n") => {
                    client.write_all(reply.as_bytes()).unwrap();
                    client
                        .set_read_timeout(Some(Duration::from_millis(300)))
                        .unwrap();
                    while let Ok(n @ 1..) = client.read(&mut buf) {
                        seen.extend_from_slice(&buf[..n]);
                    }
                    return seen;
                }
                Some(_) => {}
            }
        }
    });
    (port, seen)
}

fn credential(proxy: &Proxy) -> String {
    let user = username_for("test");
    format!(
        "Proxy-Authorization: Basic {}\r\n",
        base64_encode(format!("{user}:{}", proxy.token()).as_bytes())
    )
}

fn client(proxy: &Proxy, request: &str) -> TcpStream {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy.port())).unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    stream
}

/// Reads up to and including the blank line that ends a head.
fn head(stream: &mut TcpStream) -> String {
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

fn connect(proxy: &Proxy, target: &str, credential: &str) -> TcpStream {
    client(
        proxy,
        &format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{credential}\r\n"),
    )
}

#[test]
fn connect_to_an_allowed_host_is_tunnelled() {
    let proxy = proxy_allowing(&["127.0.0.1"]);
    let (port, _) = origin(None);
    let mut stream = connect(&proxy, &format!("127.0.0.1:{port}"), &credential(&proxy));

    assert_eq!(
        head(&mut stream),
        "HTTP/1.1 200 Connection Established\r\n\r\n"
    );
    stream.write_all(b"ping").unwrap();
    let mut echoed = [0u8; 4];
    stream.read_exact(&mut echoed).unwrap();
    assert_eq!(&echoed, b"ping");
}

#[test]
fn connect_to_another_host_gets_403() {
    let proxy = proxy_allowing(&["example.com"]);
    let mut stream = connect(&proxy, "example.org:443", &credential(&proxy));

    let head = head(&mut stream);
    assert!(head.starts_with("HTTP/1.1 403 "), "{head}");
    assert!(
        head.contains("X-Proxy-Error: blocked-by-allowlist\r\n"),
        "{head}"
    );
    let mut body = String::new();
    stream.read_to_string(&mut body).unwrap();
    assert_eq!(body, "Connection blocked by network allowlist");
}

#[test]
fn a_missing_credential_gets_407() {
    let proxy = proxy_allowing(&["127.0.0.1"]);
    let (port, _) = origin(None);
    let target = format!("127.0.0.1:{port}");
    let wrong = "Proxy-Authorization: Basic c3J0Ondyb25n\r\n";

    for credential in ["", wrong] {
        let head = head(&mut connect(&proxy, &target, credential));
        assert!(head.starts_with("HTTP/1.1 407 "), "{head}");
        assert!(head.contains("Proxy-Authenticate: Basic"), "{head}");
    }
}

#[test]
fn a_control_character_in_the_host_is_refused() {
    let proxy = proxy_allowing(&["*.allowed.com"]);

    for target in [
        "evil.com\u{1}.allowed.com:443",
        "evil.com\u{7f}.allowed.com:443",
    ] {
        let mut stream = connect(&proxy, target, &credential(&proxy));
        let head = head(&mut stream);
        assert!(
            head.starts_with("HTTP/1.1 400 ") || head.starts_with("HTTP/1.1 403 "),
            "{head:?}"
        );
    }
}

#[test]
fn a_request_for_an_allowed_host_is_forwarded_in_origin_form() {
    let proxy = proxy_allowing(&["127.0.0.1"]);
    let (port, seen) = origin(Some("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"));
    let request = format!(
        "GET http://127.0.0.1:{port}/a/b?c=d HTTP/1.1\r\nHost: ignored\r\n\
         {}Proxy-Connection: keep-alive\r\nAccept: */*\r\n\r\n",
        credential(&proxy)
    );
    let mut stream = client(&proxy, &request);

    let mut answer = String::new();
    stream.read_to_string(&mut answer).unwrap();
    assert_eq!(answer, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi");
    let seen = String::from_utf8(seen.join().unwrap()).unwrap();
    assert_eq!(
        seen,
        format!(
            "GET /a/b?c=d HTTP/1.1\r\nAccept: */*\r\nHost: 127.0.0.1:{port}\r\n\
             Connection: close\r\n\r\n"
        )
    );
}

#[test]
fn a_request_for_another_host_gets_403() {
    let proxy = proxy_allowing(&["example.com"]);
    let request = format!(
        "GET http://example.org/ HTTP/1.1\r\nHost: example.org\r\n{}\r\n",
        credential(&proxy)
    );
    let head = head(&mut client(&proxy, &request));

    assert!(head.starts_with("HTTP/1.1 403 Forbidden\r\n"), "{head}");
}

#[test]
fn a_request_with_a_userinfo_in_its_target_is_refused() {
    let proxy = proxy_allowing(&["example.com"]);
    let request = format!(
        "GET http://example.com@evil.net/ HTTP/1.1\r\n{}\r\n",
        credential(&proxy)
    );
    let head = head(&mut client(&proxy, &request));

    assert!(head.starts_with("HTTP/1.1 400 "), "{head}");
}

#[test]
fn a_head_past_16_kib_gets_431() {
    let proxy = proxy_allowing(&["example.com"]);
    let request = format!(
        "GET http://example.com/ HTTP/1.1\r\nX: {}\r\n\r\n",
        "a".repeat(20_000)
    );
    let head = head(&mut client(&proxy, &request));

    assert!(head.starts_with("HTTP/1.1 431 "), "{head}");
}

#[test]
fn connect_targets_and_absolute_targets_are_read_as_upstream_reads_them() {
    assert_eq!(parse_connect_target("a.com:443"), Some(("a.com", 443)));
    assert_eq!(parse_connect_target("[::1]:8080"), Some(("::1", 8080)));
    for bad in [
        "a.com",
        "a.com:",
        "a.com:0",
        "a.com:65536",
        ":443",
        "a.com:44x",
        "[::1]",
        "[::1",
    ] {
        assert_eq!(parse_connect_target(bad), None, "{bad}");
    }
    let url = Absolute::parse("HTTP://Example.com:8080/p?q#frag").unwrap();
    assert_eq!(
        (url.host, url.port, url.path.as_str()),
        ("Example.com", 8080, "/p?q")
    );
    let url = Absolute::parse("http://[::1]").unwrap();
    assert_eq!((url.host, url.port, url.path.as_str()), ("::1", 80, "/"));
    for bad in [
        "/path",
        "https://a.com/",
        "http://",
        "http://a@b.com/",
        "http://a.com:x/",
    ] {
        assert!(Absolute::parse(bad).is_none(), "{bad}");
    }
}

#[test]
fn a_second_request_on_the_connection_is_not_forwarded() {
    let proxy = proxy_allowing(&["127.0.0.1"]);
    let (port, seen) = origin(Some("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"));
    let credential = credential(&proxy);
    let first = format!("GET http://127.0.0.1:{port}/a HTTP/1.1\r\n{credential}\r\n");
    let second = format!("GET http://127.0.0.1:{port}/b HTTP/1.1\r\n{credential}\r\n");
    let mut stream = client(&proxy, &format!("{first}{second}"));

    let mut answer = String::new();
    stream.read_to_string(&mut answer).unwrap();
    let seen = String::from_utf8(seen.join().unwrap()).unwrap();
    assert!(seen.starts_with("GET /a HTTP/1.1\r\n"), "{seen}");
    assert!(!seen.contains("/b"), "{seen}");
    assert!(
        !seen.to_lowercase().contains("proxy-authorization"),
        "{seen}"
    );
    assert_eq!(answer.matches("HTTP/1.1 200").count(), 1, "{answer}");
}

#[test]
fn a_body_of_the_length_the_request_gives_is_forwarded() {
    let proxy = proxy_allowing(&["127.0.0.1"]);
    let (port, seen) = origin(Some("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"));
    let request = format!(
        "POST http://127.0.0.1:{port}/p HTTP/1.1\r\nContent-Length: 5\r\n{}\r\nhelloEXTRA",
        credential(&proxy)
    );
    let mut stream = client(&proxy, &request);

    let mut answer = String::new();
    stream.read_to_string(&mut answer).unwrap();
    let seen = String::from_utf8(seen.join().unwrap()).unwrap();
    assert!(seen.ends_with("\r\n\r\nhello"), "{seen}");
}

#[test]
fn a_body_of_unknown_length_gets_501() {
    let proxy = proxy_allowing(&["127.0.0.1"]);
    let request = format!(
        "POST http://127.0.0.1:1/p HTTP/1.1\r\nTransfer-Encoding: chunked\r\n{}\r\n",
        credential(&proxy)
    );
    let head = head(&mut client(&proxy, &request));

    assert!(head.starts_with("HTTP/1.1 501 "), "{head}");
}

#[test]
fn dropping_the_proxy_does_not_wait_for_a_tunnel() {
    let proxy = proxy_allowing(&["127.0.0.1"]);
    let (port, _) = origin(None);
    let mut stream = connect(&proxy, &format!("127.0.0.1:{port}"), &credential(&proxy));
    head(&mut stream);

    drop(proxy);

    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).unwrap();
    assert!(rest.is_empty());
}
