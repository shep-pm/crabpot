//! The listening TCP sockets of this network namespace, from the kernel's socket diagnostics.
//!
//! `/proc/net/tcp6` does not say whether a socket set `IPV6_V6ONLY`, which decides
//! whether an IPv6 wildcard takes IPv4 connections. A `NETLINK_SOCK_DIAG` dump
//! (`inet_diag_req_v2`) carries it in the `INET_DIAG_SKV6ONLY` attribute.

use core::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;

use nix::errno::Errno;
use nix::sys::socket::{
    AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType, bind, recv, sendto,
    socket,
};

/// A socket in the `LISTEN` state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Listener {
    pub(super) address: SocketAddr,
    /// Whether an IPv6 socket refuses IPv4 connections. It is `false` for an IPv4 socket.
    pub(super) v6only: bool,
}

/// A listener the `/proc` tables show, which do not say whether it is IPv6-only, so
/// it is taken to be dual-stack.
impl From<SocketAddr> for Listener {
    fn from(address: SocketAddr) -> Self {
        Self {
            address,
            v6only: false,
        }
    }
}

/// Why the kernel's list of listeners could not be had.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DiagError {
    /// A socket call, or the kernel's reply to the request, failed with this error.
    Syscall(Errno),
    /// A message or attribute in the reply runs past the end of what was received.
    Truncated,
    /// A message or attribute in the reply is shorter than its own header or body needs.
    Malformed,
}

impl fmt::Display for DiagError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syscall(errno) => write!(f, "the socket diagnostics failed: {errno}"),
            Self::Truncated => f.write_str("the socket diagnostics reply was cut short"),
            Self::Malformed => f.write_str("the socket diagnostics reply was malformed"),
        }
    }
}

impl core::error::Error for DiagError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Syscall(errno) => Some(errno),
            Self::Truncated | Self::Malformed => None,
        }
    }
}

/// `SOCK_DIAG_BY_FAMILY`, the message type of a request and of each socket in the reply.
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 0x300;
/// The attribute that holds the socket's `IPV6_V6ONLY` as one byte.
const INET_DIAG_SKV6ONLY: u16 = 11;
/// `TCP_LISTEN`.
const TCP_LISTEN: u8 = 10;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const IPPROTO_TCP: u8 = 6;
/// `nlmsghdr`: length, type, flags, sequence, port id.
const HEADER: usize = 16;
/// `inet_diag_msg` before its attributes: four bytes of family and state, a 48-byte
/// socket id, and five 32-bit counters and ids.
const DIAG_MESSAGE: usize = 72;
/// `inet_diag_req_v2`: four bytes, the state mask and a 48-byte socket id.
const REQUEST: usize = 56;
/// Large enough for a dump's messages to arrive whole.
const RECEIVE: usize = 32 * 1024;

/// Every socket in the `LISTEN` state in the calling process's network namespace.
///
/// # Errors
///
/// A [`DiagError`] when the kernel refuses the request or answers with something
/// that is not a socket list, as an older kernel or a filter on netlink would.
pub(super) fn listeners() -> Result<Vec<Listener>, DiagError> {
    let fd = socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::NetlinkSockDiag,
    )
    .map_err(DiagError::Syscall)?;
    bind(fd.as_raw_fd(), &NetlinkAddr::new(0, 0)).map_err(DiagError::Syscall)?;
    let mut found = Vec::new();
    let mut buffer = vec![0; RECEIVE];
    for family in [AF_INET, AF_INET6] {
        sendto(
            fd.as_raw_fd(),
            &request(family),
            &NetlinkAddr::new(0, 0),
            MsgFlags::empty(),
        )
        .map_err(DiagError::Syscall)?;
        loop {
            let len =
                recv(fd.as_raw_fd(), &mut buffer, MsgFlags::empty()).map_err(DiagError::Syscall)?;
            let reply = parse(&buffer[..len])?;
            found.extend(reply.listeners);
            if reply.done {
                break;
            }
        }
    }
    Ok(found)
}

/// A dump request for the listening TCP sockets of `family`.
fn request(family: u8) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER + REQUEST);
    bytes.extend_from_slice(&((HEADER + REQUEST) as u32).to_ne_bytes());
    bytes.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    bytes.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    bytes.extend_from_slice(&1_u32.to_ne_bytes());
    bytes.extend_from_slice(&0_u32.to_ne_bytes());
    // The kernel adds `INET_DIAG_SKV6ONLY` to a listening IPv6 socket without an
    // extension bit, which `idiag_ext`'s eight bits could not hold for attribute 11.
    bytes.extend_from_slice(&[family, IPPROTO_TCP, 0, 0]);
    bytes.extend_from_slice(&(1_u32 << TCP_LISTEN).to_ne_bytes());
    bytes.resize(HEADER + REQUEST, 0);
    bytes
}

/// What one `recv` of a dump held.
#[derive(Debug, PartialEq, Eq)]
struct Reply {
    listeners: Vec<Listener>,
    /// Whether the dump's last message was in it.
    done: bool,
}

fn parse(mut bytes: &[u8]) -> Result<Reply, DiagError> {
    let mut reply = Reply {
        listeners: Vec::new(),
        done: false,
    };
    while !bytes.is_empty() {
        let header = bytes.get(..HEADER).ok_or(DiagError::Truncated)?;
        let len = u32::from_ne_bytes([header[0], header[1], header[2], header[3]]) as usize;
        let kind = u16::from_ne_bytes([header[4], header[5]]);
        if len < HEADER {
            return Err(DiagError::Malformed);
        }
        let message = bytes.get(HEADER..len).ok_or(DiagError::Truncated)?;
        match kind {
            NLMSG_DONE => {
                reply.done = true;
                return Ok(reply);
            }
            NLMSG_ERROR => {
                let code = message.get(..4).ok_or(DiagError::Malformed)?;
                let code = i32::from_ne_bytes([code[0], code[1], code[2], code[3]]);
                return Err(DiagError::Syscall(Errno::from_raw(-code)));
            }
            SOCK_DIAG_BY_FAMILY => reply.listeners.extend(listener(message)?),
            _ => {}
        }
        bytes = bytes.get(align(len)..).unwrap_or_default();
    }
    Ok(reply)
}

/// The socket in an `inet_diag_msg` and its attributes, or `None` when it is not listening.
fn listener(message: &[u8]) -> Result<Option<Listener>, DiagError> {
    let fixed = message.get(..DIAG_MESSAGE).ok_or(DiagError::Malformed)?;
    let (family, state) = (fixed[0], fixed[1]);
    // The socket id follows: source port in network order, destination port, then
    // the source address as four 32-bit words in network order.
    let port = u16::from_be_bytes([fixed[4], fixed[5]]);
    let source = &fixed[8..24];
    let ip = match family {
        AF_INET => IpAddr::V4(Ipv4Addr::new(source[0], source[1], source[2], source[3])),
        AF_INET6 => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(source).map_err(|_| DiagError::Malformed)?,
        )),
        _ => return Err(DiagError::Malformed),
    };
    let mut v6only = false;
    let mut attributes = &message[DIAG_MESSAGE..];
    while !attributes.is_empty() {
        let header = attributes.get(..4).ok_or(DiagError::Truncated)?;
        let len = usize::from(u16::from_ne_bytes([header[0], header[1]]));
        let kind = u16::from_ne_bytes([header[2], header[3]]);
        if len < 4 {
            return Err(DiagError::Malformed);
        }
        let value = attributes.get(4..len).ok_or(DiagError::Truncated)?;
        if kind == INET_DIAG_SKV6ONLY {
            v6only = value.first().ok_or(DiagError::Malformed)? != &0;
        }
        attributes = attributes.get(align(len)..).unwrap_or_default();
    }
    Ok((state == TCP_LISTEN).then_some(Listener {
        address: SocketAddr::new(ip, port),
        v6only,
    }))
}

/// `len` rounded up to netlink's four-byte alignment.
const fn align(len: usize) -> usize {
    (len + 3) & !3
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use nix::sys::socket::{Backlog, SockaddrIn6, listen, setsockopt, sockopt};

    use super::*;

    /// One `inet_diag_msg` as the kernel sends it on a little-endian machine:
    /// a listening `[::]:8080` with `INET_DIAG_SKV6ONLY` set.
    #[rustfmt::skip]
    const V6ONLY_WILDCARD: [u8; 96] = [
        // nlmsghdr: length 96, SOCK_DIAG_BY_FAMILY, NLM_F_MULTI, sequence 1, port 0
        0x60, 0, 0, 0,  0x14, 0,  0x02, 0,  1, 0, 0, 0,  0, 0, 0, 0,
        // family AF_INET6, state TCP_LISTEN, timer, retrans
        10, 10, 0, 0,
        // source port 8080, destination port 0, then the source address ::
        0x1f, 0x90,  0, 0,
        0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
        // destination address, interface, cookie
        0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
        0, 0, 0, 0,
        0xff, 0xff, 0xff, 0xff,  0xff, 0xff, 0xff, 0xff,
        // expires, rqueue, wqueue, uid, inode
        0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0xe8, 3, 0, 0,  0x39, 0x30, 0, 0,
        // attribute: length 5, INET_DIAG_SKV6ONLY, value 1, padding
        5, 0,  11, 0,  1, 0, 0, 0,
    ];

    /// The flag byte of [`V6ONLY_WILDCARD`].
    const FLAG: usize = 92;

    /// `NLMSG_DONE` with a zero status.
    const DONE: [u8; 20] = [20, 0, 0, 0, 3, 0, 2, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    fn wildcard(v6only: bool) -> Listener {
        Listener {
            address: SocketAddr::from((Ipv6Addr::UNSPECIFIED, 8080)),
            v6only,
        }
    }

    #[test]
    fn a_reply_parses_into_addresses_and_their_v6only_flag() {
        let mut dual = V6ONLY_WILDCARD;
        dual[FLAG] = 0;
        // An IPv4 loopback listener on port 80, with no attribute.
        let mut v4 = V6ONLY_WILDCARD[..88].to_vec();
        v4[0] = 88;
        v4[16] = 2;
        v4[20..22].copy_from_slice(&80_u16.to_be_bytes());
        v4[24..28].copy_from_slice(&[127, 0, 0, 1]);
        // A socket that is not listening is left out.
        let mut established = V6ONLY_WILDCARD;
        established[17] = 1;

        let reply = [&V6ONLY_WILDCARD[..], &dual, &v4, &established, &DONE].concat();

        assert_eq!(
            parse(&reply),
            Ok(Reply {
                listeners: vec![
                    wildcard(true),
                    wildcard(false),
                    Listener {
                        address: SocketAddr::from((Ipv4Addr::LOCALHOST, 80)),
                        v6only: false,
                    },
                ],
                done: true,
            })
        );
    }

    #[test]
    fn a_reply_without_its_last_message_is_not_done() {
        assert_eq!(
            parse(&V6ONLY_WILDCARD),
            Ok(Reply {
                listeners: vec![wildcard(true)],
                done: false,
            })
        );
    }

    #[test]
    fn the_kernels_refusal_is_its_error() {
        let mut refusal = vec![36, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0];
        refusal.extend_from_slice(&(-libc::EPERM).to_ne_bytes());
        refusal.resize(36, 0);

        assert_eq!(parse(&refusal), Err(DiagError::Syscall(Errno::EPERM)));
    }

    #[test]
    fn a_truncated_reply_is_an_error_at_every_cut() {
        for cut in 1..V6ONLY_WILDCARD.len() {
            assert_eq!(
                parse(&V6ONLY_WILDCARD[..cut]),
                Err(DiagError::Truncated),
                "cut at {cut}"
            );
        }
    }

    #[test]
    fn a_malformed_reply_is_an_error() {
        // A message shorter than its own header.
        let mut short = V6ONLY_WILDCARD;
        short[0] = 8;
        assert_eq!(parse(&short), Err(DiagError::Malformed));

        // An attribute shorter than its own header.
        let mut attribute = V6ONLY_WILDCARD;
        attribute[88] = 2;
        assert_eq!(parse(&attribute), Err(DiagError::Malformed));

        // A family that is neither IPv4 nor IPv6.
        let mut family = V6ONLY_WILDCARD;
        family[16] = 1;
        assert_eq!(parse(&family), Err(DiagError::Malformed));

        // A socket message with no room for a socket.
        let mut body = V6ONLY_WILDCARD[..24].to_vec();
        body[0] = 24;
        assert_eq!(parse(&body), Err(DiagError::Malformed));
    }

    #[test]
    fn nothing_received_is_nothing_listening() {
        assert_eq!(
            parse(&[]),
            Ok(Reply {
                listeners: Vec::new(),
                done: false,
            })
        );
    }

    fn listening_wildcard(v6only: bool) -> (TcpListener, u16) {
        let fd = socket(
            AddressFamily::Inet6,
            SockType::Stream,
            SockFlag::SOCK_CLOEXEC,
            None,
        )
        .unwrap();
        setsockopt(&fd, sockopt::Ipv6V6Only, &v6only).unwrap();
        bind(
            fd.as_raw_fd(),
            &SockaddrIn6::from(std::net::SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
        )
        .unwrap();
        listen(&fd, Backlog::new(8).unwrap()).unwrap();
        let listener = TcpListener::from(fd);
        let port = listener.local_addr().unwrap().port();
        (listener, port)
    }

    #[test]
    fn a_v6only_listener_reports_its_flag() {
        let (_only, only_port) = listening_wildcard(true);
        let (_dual, dual_port) = listening_wildcard(false);

        let found = listeners().unwrap();

        let on = |port| {
            found
                .iter()
                .find(|listener| {
                    listener.address == SocketAddr::from((Ipv6Addr::UNSPECIFIED, port))
                })
                .copied()
        };
        assert_eq!(
            on(only_port),
            Some(Listener {
                address: SocketAddr::from((Ipv6Addr::UNSPECIFIED, only_port)),
                v6only: true,
            })
        );
        assert_eq!(
            on(dual_port),
            Some(Listener {
                address: SocketAddr::from((Ipv6Addr::UNSPECIFIED, dual_port)),
                v6only: false,
            })
        );
    }

    #[test]
    fn an_ipv4_listener_is_listed_without_the_flag() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();

        let found = listeners().unwrap();

        assert!(found.contains(&Listener {
            address,
            v6only: false
        }));
    }
}
