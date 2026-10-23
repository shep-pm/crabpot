//! What the proxies' tests share: a proxy to start and an origin to reach.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::thread;
use std::time::Duration;

use super::Proxy;
use crate::domain::DomainEntry;

pub(super) fn proxy_allowing(entries: &[&str]) -> Proxy {
    let entries: Vec<DomainEntry> = entries
        .iter()
        .map(|entry| DomainEntry::parse_allowed(entry).unwrap())
        .collect();
    Proxy::start(&entries, &[], false, None).unwrap()
}

/// A server on a loopback port that answers its first client with `reply`,
/// or echoes it when there is none, and hands back what it read. With a
/// reply it goes on reading for a moment after it has answered.
pub(super) fn origin(reply: Option<&'static str>) -> (u16, thread::JoinHandle<Vec<u8>>) {
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
