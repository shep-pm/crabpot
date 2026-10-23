use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream};

use super::super::testing::{origin, proxy_allowing, proxy_refusing_what_localhost_resolves_to};
use super::super::token::base64_encode;
use super::super::{Proxy, username_for};
use super::{Absolute, parse_connect_target};

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

/// The mitm route, seen through the proxy that runs it.
#[cfg(unix)]
mod mitm {
    use std::fs;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};
    use std::thread;
    use std::time::Duration;

    use super::*;
    use crate::config::MitmProxy;
    use crate::domain::{DomainEntry, DomainPattern};

    /// A Unix socket of this test's own, in a folder of its own, removed on drop.
    struct Socket(PathBuf);

    impl Socket {
        fn new(test: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("crabpot-mitm-{}-{test}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self(dir.join("s"))
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Socket {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(self.0.parent().unwrap());
        }
    }

    /// A Unix socket that answers the head it is sent with `answer`, then reads
    /// for a moment before closing. It hands back the head it saw.
    fn served(test: &str, answer: &'static str) -> (Socket, thread::JoinHandle<String>) {
        let socket = Socket::new(test);
        let listener = UnixListener::bind(socket.path()).unwrap();
        let answer = answer.to_owned();
        let seen = thread::spawn(move || {
            let (mut client, _) = listener.accept().unwrap();
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
            client
                .set_read_timeout(Some(Duration::from_millis(300)))
                .unwrap();
            while let Ok(read @ 1..) = client.read(&mut buf) {
                head.extend_from_slice(&buf[..read]);
            }
            String::from_utf8_lossy(&head).into_owned()
        });
        (socket, seen)
    }

    fn proxy_with_mitm(allowed: &[&str], socket: &Path, domains: &[&str]) -> Proxy {
        let allowed: Vec<DomainEntry> = allowed
            .iter()
            .map(|entry| DomainEntry::parse_allowed(entry).unwrap())
            .collect();
        let domains: Vec<DomainPattern> = domains
            .iter()
            .map(|pattern| DomainPattern::parse(pattern).unwrap())
            .collect();
        Proxy::start(
            &allowed,
            &[],
            &[],
            false,
            Some(&MitmProxy {
                socket_path: socket.display().to_string(),
                domains,
            }),
        )
        .unwrap()
    }

    #[test]
    fn a_connect_to_a_mitm_domain_is_tunnelled_through_the_socket() {
        let (socket, seen) = served("tunnel", "HTTP/1.1 200 Connection Established\r\n\r\n");
        let proxy = proxy_with_mitm(&["mitm.example.com"], socket.path(), &["mitm.example.com"]);
        let mut stream = connect(&proxy, "mitm.example.com:443", &credential(&proxy));

        assert_eq!(
            head(&mut stream),
            "HTTP/1.1 200 Connection Established\r\n\r\n"
        );
        assert_eq!(
            seen.join().unwrap(),
            "CONNECT mitm.example.com:443 HTTP/1.1\r\nHost: mitm.example.com:443\r\n\r\n"
        );
    }

    #[test]
    fn a_connect_the_mitm_route_does_not_cover_is_dialed_direct() {
        // The socket refuses, so a host sent to it would get 502 and not 200.
        let (socket, _) = served("direct", "HTTP/1.1 403 Forbidden\r\n\r\n");
        let proxy = proxy_with_mitm(&["127.0.0.1"], socket.path(), &["mitm.example.com"]);
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
    fn a_mitm_socket_that_is_not_there_is_a_502() {
        let proxy = proxy_with_mitm(
            &["mitm.example.com"],
            Path::new("/no/such/crabpot-mitm.sock"),
            &["mitm.example.com"],
        );
        let mut stream = connect(&proxy, "mitm.example.com:443", &credential(&proxy));

        assert_eq!(head(&mut stream), "HTTP/1.1 502 Bad Gateway\r\n\r\n");
    }

    #[test]
    fn a_request_to_a_mitm_domain_names_the_whole_target() {
        let (socket, seen) = served("absolute", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi");
        let proxy = proxy_with_mitm(&["mitm.example.com"], socket.path(), &["mitm.example.com"]);
        let request = format!(
            "GET http://mitm.example.com/a/b?c=d HTTP/1.1\r\nHost: ignored\r\n{}\r\n",
            credential(&proxy)
        );
        let mut stream = client(&proxy, &request);

        let mut answer = String::new();
        stream.read_to_string(&mut answer).unwrap();
        assert_eq!(answer, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi");
        assert_eq!(
            seen.join().unwrap(),
            "GET http://mitm.example.com/a/b?c=d HTTP/1.1\r\n\
             Host: mitm.example.com\r\nConnection: close\r\n\r\n"
        );
    }
}

const REFUSED: &str = "Connection to localhost blocked: resolved to a deny-listed address";

#[test]
fn a_tunnel_to_a_name_that_resolves_to_a_refused_address_gets_403_with_the_class() {
    let proxy = proxy_refusing_what_localhost_resolves_to();
    let (port, seen) = origin(None);
    let mut stream = connect(&proxy, &format!("localhost:{port}"), &credential(&proxy));

    let head = head(&mut stream);
    assert!(
        head.starts_with("HTTP/1.1 403 resolved to a deny-listed address\r\n"),
        "{head}"
    );
    assert!(
        head.contains("X-Proxy-Error: blocked-by-sandbox-runtime\r\n"),
        "{head}"
    );
    let mut body = String::new();
    stream.read_to_string(&mut body).unwrap();
    assert_eq!(body, REFUSED);
    // Nothing reached the origin: it is still waiting for its one client.
    assert!(!seen.is_finished());
}

#[test]
fn a_request_to_a_name_that_resolves_to_a_refused_address_gets_403() {
    let proxy = proxy_refusing_what_localhost_resolves_to();
    let (port, _) = origin(None);
    let request = format!(
        "GET http://localhost:{port}/ HTTP/1.1\r\nHost: localhost\r\n{}\r\n",
        credential(&proxy)
    );
    let mut stream = client(&proxy, &request);

    let head = head(&mut stream);
    assert!(head.starts_with("HTTP/1.1 403 Forbidden\r\n"), "{head}");
    let mut body = String::new();
    stream.read_to_string(&mut body).unwrap();
    assert_eq!(body, REFUSED);
}
