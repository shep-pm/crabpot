//! The `connect` mode: the hop a sandboxed `git` over ssh asks for (ADR-0014).
//!
//! ssh runs a `ProxyCommand` through `/bin/sh -c` with its `%h` and `%p`
//! replaced by the host and port it wants, and gives the process it starts the
//! connection's bytes on stdin and stdout. This mode answers that with an HTTP
//! `CONNECT` to the relay on the sandbox's own HTTP port, and then copies both
//! ways until either side is done. It is upstream's `socat` hop, replaced by
//! crabpot's own binary (decision #90).
//!
//! It is the one helper job a command starts itself: bwrap re-enters the binary
//! as `init`, and `init`'s command is what re-enters it here, through ssh. The
//! credential comes from the environment, so it is in no argv, and the
//! sandbox's processes are not dumpable, so their environment is not readable
//! from `/proc` either.

use core::fmt;
use std::env;
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpStream};
use std::thread;

use crate::net::ssh::{self, Answer, SshError};

/// How many bytes are copied at a time.
const CHUNK: usize = 8 * 1024;

/// Runs the `connect` mode on `args`, which are the relay's port and the host
/// and port ssh named, and copies the tunnel to this process's stdin and
/// stdout.
///
/// # Errors
///
/// [`ConnectError`] says whether the arguments, the credential, the target, the
/// relay, the proxy's answer or a socket was the reason there is no tunnel.
pub fn connect(args: &[OsString]) -> Result<(), ConnectError> {
    let [relay, host, port] = args else {
        return Err(ConnectError::Usage);
    };
    let relay = relay
        .to_string_lossy()
        .parse::<u16>()
        .map_err(|_| ConnectError::Usage)?;
    let target = ssh::authority(&host.to_string_lossy(), &port.to_string_lossy())
        .map_err(ConnectError::Target)?;
    let basic = env::var(ssh::CREDENTIAL_VARIABLE).map_err(|_| ConnectError::Credential)?;

    let mut tunnel = TcpStream::connect((Ipv4Addr::LOCALHOST, relay))
        .map_err(|reason| ConnectError::Relay(reason.kind()))?;
    let answer = ssh::handshake(&mut tunnel, &target, &basic).map_err(|reason| {
        if reason.kind() == io::ErrorKind::InvalidData {
            ConnectError::Head
        } else {
            ConnectError::Tunnel(reason.kind())
        }
    })?;
    match answer {
        Answer::Open => copy(tunnel),
        Answer::Refused(reason) => Err(ConnectError::Refused { target, reason }),
    }
}

/// Copies stdin to the tunnel and the tunnel to stdout, until the tunnel ends.
///
/// Each side ends the other: the end of what ssh sends closes the tunnel's far
/// end, and the end of what the far end sends closes this process's read of it,
/// as the relay's [`crate::net::relay`] copy does.
///
/// The copy out of stdin is left to end with the process. Its read is ssh's to
/// end, and waiting for it here would wait for ssh to notice that the tunnel
/// has ended, which is what this process ending is for ssh to learn from.
fn copy(tunnel: TcpStream) -> Result<(), ConnectError> {
    let (mut to_tunnel, mut from_tunnel) = (
        tunnel
            .try_clone()
            .map_err(|reason| ConnectError::Tunnel(reason.kind()))?,
        tunnel,
    );
    thread::spawn(move || {
        let copied = pump(&mut io::stdin().lock(), &mut to_tunnel);
        // ssh has sent all it has: say so to the far end, which answers it by
        // closing.
        let _ = to_tunnel.shutdown(Shutdown::Write);
        let _ = copied;
    });
    let down = pump(&mut from_tunnel, &mut io::stdout().lock());
    // Closing both ends wakes the other copy out of its read of stdin, and out
    // of any write the tunnel no longer takes.
    let _ = from_tunnel.shutdown(Shutdown::Both);
    down.map_err(|reason| ConnectError::Tunnel(reason.kind()))
}

/// Copies `from` to `to` until `from` ends, flushing every chunk. A tunnel
/// carries no newlines to flush a buffer on, and a chunk held in one is the
/// other side waiting for bytes it has already been given.
fn pump(from: &mut dyn Read, to: &mut dyn Write) -> io::Result<()> {
    let mut buf = [0u8; CHUNK];
    loop {
        match from.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(read) => {
                to.write_all(&buf[..read])?;
                to.flush()?;
            }
            Err(reason) if reason.kind() == io::ErrorKind::Interrupted => {}
            Err(reason) => return Err(reason),
        }
    }
}

/// Why there is no tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectError {
    /// The mode was not given the relay's port and ssh's host and port.
    Usage,
    /// The credential is not in the environment to read.
    Credential,
    /// ssh's host or port is not something to ask the proxy for.
    Target(SshError),
    /// The proxy refused the tunnel, in its own words.
    Refused {
        /// The `host:port` it was asked for.
        target: String,
        /// The reason its status line gave.
        reason: String,
    },
    /// The relay's port could not be reached.
    Relay(io::ErrorKind),
    /// The proxy gave no answer to read.
    Head,
    /// A socket or a stream ended the tunnel.
    Tunnel(io::ErrorKind),
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage => write!(
                f,
                "connect needs `<port> <host> <port>`, as ssh's ProxyCommand gives it"
            ),
            Self::Credential => write!(f, "{} is not set", ssh::CREDENTIAL_VARIABLE),
            Self::Target(error) => fmt::Display::fmt(error, f),
            Self::Refused { target, reason } => {
                write!(f, "the proxy refused {target}: {reason}")
            }
            Self::Relay(reason) => write!(f, "cannot reach the sandbox's relay: {reason}"),
            Self::Head => write!(f, "the sandbox's proxy gave no answer"),
            Self::Tunnel(reason) => write!(f, "the tunnel ended: {reason}"),
        }
    }
}

impl core::error::Error for ConnectError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn the_mode_needs_the_relay_port_and_sshs_host_and_port() {
        assert_eq!(connect(&words(&[])), Err(ConnectError::Usage));
        assert_eq!(
            connect(&words(&["3128", "example.com"])),
            Err(ConnectError::Usage)
        );
        assert_eq!(
            connect(&words(&["nope", "example.com", "22"])),
            Err(ConnectError::Usage)
        );
    }

    #[test]
    fn a_target_that_cannot_be_asked_is_refused_before_the_relay_is_dialled() {
        assert_eq!(
            connect(&words(&["3128", "example.com\r\nHost: evil", "22"])),
            Err(ConnectError::Target(SshError::BadHost(
                "example.com\r\nHost: evil".to_owned()
            )))
        );
    }
}
