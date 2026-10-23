use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream};

use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::runtime::Builder;

use super::super::filter::Filter;
use super::super::guard::Guard;
use super::super::shared::Shared;
use super::super::testing::{origin, proxy_allowing, proxy_refusing_what_localhost_resolves_to};
use super::super::token::Token;
use super::super::{Proxy, username_for};
use super::exchange;
use crate::domain::DomainEntry;

/// What a refusal answers with: the reply code, then a zero IPv4 address and port.
fn refusal(code: u8) -> [u8; 10] {
    [5, code, 0, 1, 0, 0, 0, 0, 0, 0]
}

/// The greeting that offers a username and password, then the login with
/// `password`. The proxy answers `[5, 2, 1, 0]` to the token.
fn login(password: &str) -> Vec<u8> {
    let user = username_for("test");
    let mut sent = vec![5, 1, 2, 1, u8::try_from(user.len()).unwrap()];
    sent.extend_from_slice(user.as_bytes());
    sent.push(u8::try_from(password.len()).unwrap());
    sent.extend_from_slice(password.as_bytes());
    sent
}

fn connect_request(address: &[u8], port: u16) -> Vec<u8> {
    let mut request = vec![5, 1, 0];
    request.extend_from_slice(address);
    request.extend_from_slice(&port.to_be_bytes());
    request
}

fn domain(name: &str) -> Vec<u8> {
    let mut address = vec![3, u8::try_from(name.len()).unwrap()];
    address.extend_from_slice(name.as_bytes());
    address
}

/// Plays `sent` to a connection served with an allow list of `allowed`, whose
/// token is `token`, and returns everything the proxy answered up to its close.
fn answer(allowed: &[&str], token: &Token, sent: &[u8]) -> Vec<u8> {
    let entries: Vec<DomainEntry> = allowed
        .iter()
        .map(|entry| DomainEntry::parse_allowed(entry).unwrap())
        .collect();
    let shared = Shared::new(
        Filter::new(&entries, &[], false),
        Guard::new(&entries, &[], &[]),
        token.clone(),
        None,
    );
    let runtime = Builder::new_current_thread().enable_time().build().unwrap();
    runtime.block_on(async {
        let (mut client, mut server) = duplex(1024);
        let serving = tokio::spawn(async move {
            let _ = exchange(&mut server, &shared).await;
        });
        client.write_all(sent).await.unwrap();
        let mut answered = Vec::new();
        client.read_to_end(&mut answered).await.unwrap();
        drop(client);
        serving.await.unwrap();
        answered
    })
}

/// What a client sees of a login that works, then of `request`.
fn answer_logged_in(allowed: &[&str], request: &[u8]) -> Vec<u8> {
    let token = Token::generate().unwrap();
    let mut sent = login(token.as_str());
    sent.extend_from_slice(request);
    let answered = answer(allowed, &token, &sent);
    assert_eq!(answered[..4], [5, 2, 1, 0], "the login");
    answered[4..].to_vec()
}

#[test]
fn a_denied_host_gets_a_not_allowed_reply() {
    let answered = answer_logged_in(
        &["example.com"],
        &connect_request(&domain("example.org"), 443),
    );

    assert_eq!(answered, refusal(2));
}

#[test]
fn no_credential_is_refused() {
    let token = Token::generate().unwrap();

    let anonymous = answer(&["127.0.0.1"], &token, &[5, 1, 0]);
    assert_eq!(anonymous, [5, 0xFF]);

    let wrong = answer(&["127.0.0.1"], &token, &login("not the token"));
    assert_eq!(wrong, [5, 2, 1, 1]);

    let empty_user = answer(
        &["127.0.0.1"],
        &token,
        &[&[5, 1, 2, 1, 0, 32][..], token.as_str().as_bytes()].concat(),
    );
    assert_eq!(empty_user, [5, 2, 1, 1]);
}

#[test]
fn a_domain_with_a_null_byte_is_refused() {
    let answered = answer_logged_in(
        &["*.allowed.com"],
        &connect_request(&domain("evil.com\0.allowed.com"), 443),
    );

    assert_eq!(answered, refusal(2));
}

#[test]
fn a_command_other_than_connect_is_not_supported() {
    let mut request = connect_request(&[1, 127, 0, 0, 1], 80);
    request[1] = 2;

    assert_eq!(answer_logged_in(&["127.0.0.1"], &request), refusal(7));
}

#[test]
fn an_address_type_of_no_kind_is_not_supported() {
    assert_eq!(answer_logged_in(&["127.0.0.1"], &[5, 1, 0, 9]), refusal(8));
}

fn connect_to_socks(proxy: &Proxy) -> TcpStream {
    TcpStream::connect((Ipv4Addr::LOCALHOST, proxy.socks_port())).unwrap()
}

fn read_n<const N: usize>(stream: &mut TcpStream) -> [u8; N] {
    let mut bytes = [0u8; N];
    stream.read_exact(&mut bytes).unwrap();
    bytes
}

/// A client of the SOCKS port that has logged in.
fn authenticated(proxy: &Proxy) -> TcpStream {
    let mut stream = connect_to_socks(proxy);
    stream.write_all(&login(proxy.token())).unwrap();
    assert_eq!(read_n::<4>(&mut stream), [5, 2, 1, 0]);
    stream
}

#[test]
fn an_allowed_host_connects() {
    let proxy = proxy_allowing(&["127.0.0.1"]);
    let (port, _) = origin(None);
    let mut stream = authenticated(&proxy);

    stream
        .write_all(&connect_request(&[1, 127, 0, 0, 1], port))
        .unwrap();

    let reply = read_n::<10>(&mut stream);
    assert_eq!(reply[..4], [5, 0, 0, 1]);
    stream.write_all(b"ping").unwrap();
    assert_eq!(&read_n::<4>(&mut stream), b"ping");
}

#[test]
fn a_domain_is_dialed_by_name() {
    let proxy = proxy_allowing(&["localhost"]);
    let (port, _) = origin(None);
    let mut stream = authenticated(&proxy);

    stream
        .write_all(&connect_request(&domain("localhost"), port))
        .unwrap();

    assert_eq!(read_n::<10>(&mut stream)[..2], [5, 0]);
    stream.write_all(b"ping").unwrap();
    assert_eq!(&read_n::<4>(&mut stream), b"ping");
}

#[test]
fn a_host_that_refuses_the_connection_gets_that_reply() {
    let proxy = proxy_allowing(&["127.0.0.1"]);
    let port = {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.local_addr().unwrap().port()
    };
    let mut stream = authenticated(&proxy);

    stream
        .write_all(&connect_request(&[1, 127, 0, 0, 1], port))
        .unwrap();

    assert_eq!(read_n::<10>(&mut stream), refusal(5));
}

#[test]
fn a_name_that_resolves_to_a_refused_address_gets_a_not_allowed_reply() {
    let proxy = proxy_refusing_what_localhost_resolves_to();
    let (port, _) = origin(None);
    let mut stream = authenticated(&proxy);

    stream
        .write_all(&connect_request(&domain("localhost"), port))
        .unwrap();

    assert_eq!(read_n::<10>(&mut stream), refusal(2));
}
