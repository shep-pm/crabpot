use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::os::unix::fs::FileTypeExt;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::runtime::Builder;

use super::super::filter::Filter;
use super::super::guard::Guard;
use super::super::shared::Shared;
use super::super::testing::{origin, proxy_allowing};
use super::super::token::{Token, base64_encode};
use super::super::{Proxy, username_for};
use super::Socket;

/// A client of the one port both protocols answer on.
fn client(proxy: &Proxy) -> TcpStream {
    TcpStream::connect((Ipv4Addr::LOCALHOST, proxy.port())).unwrap()
}

fn read_n<const N: usize>(stream: &mut TcpStream) -> [u8; N] {
    let mut bytes = [0u8; N];
    stream.read_exact(&mut bytes).unwrap();
    bytes
}

/// Reads up to and including the blank line that ends an HTTP head.
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

/// The SOCKS5 greeting that offers a username and password, and the login with
/// the proxy's token.
fn login(token: &str) -> Vec<u8> {
    let user = username_for("test");
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

/// The `Proxy-Authorization` header the HTTP leg wants.
fn credential(proxy: &Proxy) -> String {
    let user = username_for("test");
    format!(
        "Proxy-Authorization: Basic {}\r\n",
        base64_encode(format!("{user}:{}", proxy.token()).as_bytes())
    )
}

#[test]
fn byte_5_goes_to_socks_and_anything_else_to_http() {
    let proxy = proxy_allowing(&["127.0.0.1"]);
    assert_eq!(
        proxy.socks_port(),
        proxy.port(),
        "the child is shown one port"
    );

    let (socks_port, _) = origin(None);
    let mut socks = client(&proxy);
    socks.write_all(&login(proxy.token())).unwrap();
    assert_eq!(read_n::<4>(&mut socks), [5, 2, 1, 0], "the login");
    socks
        .write_all(&connect_request([127, 0, 0, 1], socks_port))
        .unwrap();
    let reply = read_n::<10>(&mut socks);
    assert_eq!(
        reply[..4],
        [5, 0, 0, 1],
        "a 0x05 greeting is SOCKS, answered with the address it bound",
    );
    socks.write_all(b"ping").unwrap();
    assert_eq!(&read_n::<4>(&mut socks), b"ping", "the SOCKS tunnel");

    let (http_port, _) = origin(None);
    let target = format!("127.0.0.1:{http_port}");
    let mut http = client(&proxy);
    http.write_all(
        format!(
            "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{}\r\n",
            credential(&proxy)
        )
        .as_bytes(),
    )
    .unwrap();
    assert_eq!(
        head(&mut http),
        "HTTP/1.1 200 Connection Established\r\n\r\n",
        "a 0x43 'C' is HTTP",
    );
    http.write_all(b"pong").unwrap();
    assert_eq!(&read_n::<4>(&mut http), b"pong", "the HTTP tunnel");
}

#[test]
fn the_backend_socket_is_removed_on_drop() {
    let proxy = proxy_allowing(&[]);
    let socket = proxy.socket.path().to_path_buf();
    let name = socket.file_name().unwrap().to_string_lossy();

    assert!(
        name.starts_with(&format!("srt-mux-{}-", std::process::id())) && name.ends_with(".sock"),
        "{name}",
    );
    assert!(
        std::fs::metadata(&socket).unwrap().file_type().is_socket(),
        "the backend is bound while the proxy runs",
    );

    drop(proxy);
    assert!(!socket.exists(), "the backend socket outlived the proxy");
}

/// The dispatch on its own, with the front end a pair of pipes where a port
/// would be: which leg a connection goes to, and what the backend is dialled
/// with.
#[test]
fn the_first_byte_picks_the_leg_and_the_backend_gets_the_rest() {
    let (backend, socket) = Socket::bind().unwrap();
    let path = socket.path().to_path_buf();
    let token = Token::generate().unwrap();
    let shared = Arc::new(Shared::new(
        Filter::new(&[], &[], false),
        Guard::new(&[], &[], &[]),
        token.clone(),
    ));
    let runtime = Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap();
    let backend = {
        let _entered = runtime.enter();
        tokio::net::UnixListener::from_std(backend).unwrap()
    };

    runtime.block_on(async {
        let (mut client, front) = duplex(1024);
        let http_leg = tokio::spawn(super::dispatch(
            front,
            PathBuf::clone(&path),
            Arc::clone(&shared),
        ));
        client
            .write_all(b"CONNECT x HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        let (mut dialed, _) = backend.accept().await.unwrap();
        let mut arrived = Vec::new();
        dialed.read_to_end(&mut arrived).await.unwrap();
        assert_eq!(
            arrived, b"CONNECT x HTTP/1.1\r\n\r\n",
            "the byte the front end peeked at is written first"
        );
        // The copy ends when both sides leave, so this side goes first.
        drop(dialed);

        // A SOCKS greeting is served in process, with its 0x05 put back.
        let (mut client, front) = duplex(1024);
        let socks_leg = tokio::spawn(super::dispatch(front, path, Arc::clone(&shared)));
        client.write_all(&login(token.as_str())).await.unwrap();
        let mut answered = [0u8; 4];
        client.read_exact(&mut answered).await.unwrap();
        assert_eq!(
            answered,
            [5, 2, 1, 0],
            "the greeting reached the SOCKS handler whole"
        );
        // Both handlers end when their client leaves, which is what dropping
        // the runtime below waits for.
        client.shutdown().await.unwrap();
        http_leg.await.unwrap();
        socks_leg.await.unwrap();
    });
}
