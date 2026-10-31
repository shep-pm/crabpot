//! The variables that carry ssh's `ProxyCommand` on Linux, where the route to
//! the proxy is the relay on the sandbox's own HTTP port (ADR-0014).
//!
//! Upstream builds this hop on `socat`, which crabpot has no reason to borrow
//! (decision #90): the hop is crabpot's own binary in the `connect` mode. What
//! the command needs travels in variables of its own, as macOS carries its
//! script in `SRT_SSH_PROXY_COMMAND`. The credential is one of them, so what
//! reads an argv reads no credential. The binary's path is the other, for a
//! harsher reason: three layers read the command text as shell text and as
//! percent text, and an install path is whatever the install put there.

use core::fmt;
use core::net::Ipv6Addr;
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::path::Path;

use crabpot_core::proxy::basic_for;

use super::HTTP_PORT;

/// ssh's own connection multiplexing, turned off, for the reasons
/// `crabpot-macos/src/env/ssh.rs` gives: a mux socket path comes from the
/// user's ssh_config, typically under `~/.ssh`, which the sandbox does not let
/// a socket bind at, and OpenSSH treats a mux listener that failed to bind as
/// fatal even with `ControlMaster=auto`. These options outrank ssh_config.
const MUX_OVERRIDE: &str = "-o ControlMaster=no -o ControlPath=none";

/// The re-entry the `ProxyCommand` names: this binary in the `connect` mode,
/// which [`crate::helper`] runs. The facade reads the same two words when it
/// re-enters the binary as the helper (ADR-0010).
pub const CONNECT_REENTRY: &str = "--crabpot-helper connect";

/// The name of the variable that carries this binary's path, which ssh's
/// `ProxyCommand` expands to reach the `connect` mode.
///
/// The path is the one word of the route that an install chooses, and it is
/// never part of a word a shell reads: `GIT_SSH_COMMAND` expands it.
pub const BINARY_VARIABLE: &str = "SRT_SSH_PROXY_BINARY";

/// The name of the variable that carries the proxy's `Basic` credential for the
/// `connect` mode to read. It is set on the wrapped command's environment and
/// never in a bwrap word, and the command's own processes are not dumpable, so
/// their environment is not readable from `/proc`.
pub const CREDENTIAL_VARIABLE: &str = "SRT_SSH_PROXY_CREDENTIAL";

/// The variables a command needs to send git over ssh through the relay, for a
/// proxy that wants `username` and `token` from a client.
///
/// `binary` is this binary as bwrap binds it into the sandbox, and the command
/// is pointed at the sandbox's HTTP port, which the relay forwards to the proxy.
#[must_use]
pub fn vars(binary: &Path, username: &str, token: &str) -> Vec<(&'static str, OsString)> {
    vec![
        ("GIT_SSH_COMMAND", OsString::from(command())),
        (BINARY_VARIABLE, binary.as_os_str().to_os_string()),
        (
            CREDENTIAL_VARIABLE,
            OsString::from(basic_for(username, token)),
        ),
    ]
}

/// The value of `GIT_SSH_COMMAND`: ssh, the mux override, and a `ProxyCommand`
/// of words that never change, asked for the host and port ssh names with its
/// own `%h` and `%p`.
///
/// No part of the binary's path is in this text. Three layers read it, and a
/// path is whatever the install put there:
///
/// - git runs the value through a shell of its own, which expands a `$` and
///   ends a word at an apostrophe. It is `/bin/sh -c` unless `core.shell` names
///   another, and a `core.shell` that is not POSIX is not something any
///   `GIT_SSH_COMMAND` text can answer at the same time as a POSIX one;
/// - ssh expands `%` in `ProxyCommand` before it runs anything, and stops at a
///   `%` it cannot name;
/// - ssh runs what is left through a shell again, `$SHELL -c "exec ..."`, and
///   `SHELL` is the caller's own, which crabpot passes into the sandbox and
///   never sets. It is not a shell that has to read this text.
///
/// So the text ssh's shell is handed is one command in a known shell:
/// `/bin/sh -c '<the connect mode>' sh '<host>' <port>`, with the host and port
/// arriving as its `$1` and `$2`. Single quotes are the one quoting every shell
/// agrees on, and everything that is POSIX-only syntax (`${VAR:?msg}`, the
/// double quotes around the expansion) is inside them, where only `/bin/sh`
/// reads it. `:?` is what makes a variable that is not there a named error from
/// `/bin/sh` rather than an empty word run as a command. The host is quoted for
/// the same reason macOS quotes it: a `$` or a backtick in a double-quoted host
/// would be run, and ssh substitutes it from a git URL, which a repository
/// chooses.
fn command() -> String {
    let binary = format!("${{{BINARY_VARIABLE}:?unset, but GIT_SSH_COMMAND needs it}}");
    format!(
        "ssh {MUX_OVERRIDE} -o ProxyCommand=\"/bin/sh -c '\\\"\\{binary}\\\" {CONNECT_REENTRY} {HTTP_PORT} \\\"\\$1\\\" \\\"\\$2\\\"' sh '%h' %p\""
    )
}

/// Opens a `CONNECT` tunnel without consuming any payload bytes
///
/// # Errors
///
/// Returns socket errors, or `InvalidData` for an incomplete or oversized response head.
pub fn handshake<S: Read + Write>(tunnel: &mut S, target: &str, basic: &str) -> io::Result<Answer> {
    const MAX_HEAD_BYTES: usize = 16 * 1024;
    tunnel.write_all(request(target, basic).as_bytes())?;
    tunnel.flush()?;
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_HEAD_BYTES {
            return Err(io::ErrorKind::InvalidData.into());
        }
        match tunnel.read(&mut byte) {
            Ok(0) => return Err(io::ErrorKind::InvalidData.into()),
            Ok(_) => head.push(byte[0]),
            Err(reason) if reason.kind() == io::ErrorKind::Interrupted => {}
            Err(reason) => return Err(reason),
        }
    }
    Ok(answer(
        String::from_utf8_lossy(&head)
            .lines()
            .next()
            .unwrap_or_default(),
    ))
}

/// What the proxy answered a `CONNECT` with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// The tunnel is open, and the bytes can flow.
    Open,
    /// The refusal, as the status line named it.
    Refused(String),
}

/// Whether `code` is a 2xx status, as `mitm.rs` accepts for its own `CONNECT`.
fn is_success(code: &str) -> bool {
    code.len() == 3 && code.starts_with('2') && code.bytes().all(|byte| byte.is_ascii_digit())
}

/// The `Answer` to the proxy's status line `line`.
#[must_use]
pub fn answer(line: &str) -> Answer {
    let status = line
        .strip_prefix("HTTP/1.1 ")
        .or_else(|| line.strip_prefix("HTTP/1.0 "))
        .map(|rest| rest.trim_end());
    match status {
        Some(status) if status.split(' ').next().is_some_and(is_success) => Answer::Open,
        Some(status) => Answer::Refused(status.to_owned()),
        None => Answer::Refused(format!("its answer was {line:?}")),
    }
}

/// The `host:port` a `CONNECT` asks the proxy for, from ssh's `%h` and `%p`.
///
/// A host that is not a name or an address literal, and in particular one that
/// carries a character that could end the request line, is refused before
/// anything is sent. ssh substitutes `%h` from a git URL, which a repository
/// chooses.
///
/// # Errors
///
/// [`SshError::BadHost`] for an empty host or one with a character no host name
/// or address literal carries, and [`SshError::BadPort`] for a port that is not
/// a port number.
pub fn authority(host: &str, port: &str) -> Result<String, SshError> {
    if host.is_empty()
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(SshError::BadHost(host.to_owned()));
    }
    if port.is_empty()
        || port.len() > 5
        || !port.bytes().all(|byte| byte.is_ascii_digit())
        || port.parse::<u16>().is_err()
    {
        return Err(SshError::BadPort(port.to_owned()));
    }
    // A host with a colon is an IPv6 literal or nothing: a port glued to a name
    // is ssh's `%h` and `%p` mixed up, and not a host to ask for.
    if host.contains(':') && host.parse::<Ipv6Addr>().is_err() {
        return Err(SshError::BadHost(host.to_owned()));
    }
    // An IPv6 literal is bracketed in a request target, as the macOS script
    // brackets it too.
    let host = match host.contains(':') {
        true => format!("[{host}]"),
        false => host.to_owned(),
    };
    Ok(format!("{host}:{port}"))
}

/// The request head the `connect` mode sends for the tunnel to `authority`, with
/// the proxy's `Basic` credential `basic`.
#[must_use]
pub fn request(authority: &str, basic: &str) -> String {
    format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: Basic {basic}\
         \r\n\r\n"
    )
}

/// Why a `ProxyCommand` target cannot be asked of the proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshError {
    /// An empty host, or one with a character that could end the request line.
    BadHost(String),
    /// A port that is not a port number.
    BadPort(String),
}

impl fmt::Display for SshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadHost(host) => write!(f, "{host:?} is not a host to ask the proxy for"),
            Self::BadPort(port) => write!(f, "{port:?} is not a port to ask the proxy for"),
        }
    }
}

impl core::error::Error for SshError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// This binary, as bwrap binds it into the sandbox.
    const BINARY: &str = "/opt/crabpot/bin/crabpot";

    fn value(vars: &[(&str, OsString)], name: &str) -> String {
        vars.iter()
            .find(|(var, _)| *var == name)
            .map(|(_, value)| value.to_string_lossy().into_owned())
            .unwrap_or_else(|| panic!("{name} is not set"))
    }

    struct Connection {
        incoming: io::Cursor<Vec<u8>>,
        outgoing: Vec<u8>,
    }

    impl Read for Connection {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.incoming.read(buf)
        }
    }

    impl Write for Connection {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.outgoing.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_connect_handshake_leaves_the_servers_greeting_in_the_stream() {
        let mut connection = Connection {
            incoming: io::Cursor::new(
                b"HTTP/1.1 200 Connection Established\r\n\r\nready\0".to_vec(),
            ),
            outgoing: Vec::new(),
        };

        assert_eq!(
            handshake(&mut connection, "db.example:5432", "c3J0OnRva2Vu").unwrap(),
            Answer::Open
        );
        let mut payload = Vec::new();
        connection.read_to_end(&mut payload).unwrap();
        assert_eq!(payload, b"ready\0");
        assert_eq!(connection.outgoing, b"CONNECT db.example:5432 HTTP/1.1\r\nHost: db.example:5432\r\nProxy-Authorization: Basic c3J0OnRva2Vu\r\n\r\n");
    }

    #[test]
    fn a_connect_handshake_reports_refusals_and_incomplete_heads() {
        let mut connection = Connection {
            incoming: io::Cursor::new(
                b"HTTP/1.1 403 host is not on the allow list\r\n\r\n".to_vec(),
            ),
            outgoing: Vec::new(),
        };
        assert_eq!(
            handshake(&mut connection, "db.example:5432", "credential").unwrap(),
            Answer::Refused("403 host is not on the allow list".to_owned())
        );

        for head in [b"HTTP/1.1 200 OK\r\n".to_vec(), vec![b'x'; 16 * 1024 + 1]] {
            let mut connection = Connection {
                incoming: io::Cursor::new(head),
                outgoing: Vec::new(),
            };
            assert_eq!(
                handshake(&mut connection, "db.example:5432", "credential")
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn the_credential_is_not_in_the_command_text() {
        let token = "f00dfacecafe0123";
        let vars = vars(Path::new(BINARY), "srt", token);
        let command = value(&vars, "GIT_SSH_COMMAND");
        let basic = value(&vars, CREDENTIAL_VARIABLE);

        // `srt:f00dfacecafe0123`, which is what the `connect` mode puts in its
        // `Proxy-Authorization` header.
        assert_eq!(basic, "c3J0OmYwMGRmYWNlY2FmZTAxMjM=");
        assert!(!command.contains(token), "{command}");
        assert!(
            !command.contains(&basic),
            "the credential is not in a command line any process can read: {command}"
        );
    }

    #[test]
    fn the_command_names_the_binary_and_port_3128() {
        let vars = vars(Path::new(BINARY), "srt", "0123abcd");

        assert_eq!(
            value(&vars, "GIT_SSH_COMMAND"),
            "ssh -o ControlMaster=no -o ControlPath=none -o ProxyCommand=\
             \"/bin/sh -c '\\\"\\${SRT_SSH_PROXY_BINARY:?unset, but GIT_SSH_COMMAND needs it}\\\" \
             --crabpot-helper connect 3128 \\\"\\$1\\\" \\\"\\$2\\\"' sh '%h' %p\""
        );
        assert_eq!(
            value(&vars, BINARY_VARIABLE),
            BINARY,
            "the binary the command names, in a variable of its own"
        );
    }

    /// The shape this design is for. An install path is whatever the install put
    /// there, and every character of it would be shell text or `%` text in a
    /// command that named it: git runs `GIT_SSH_COMMAND` with a shell, ssh
    /// expands `%` in `ProxyCommand` and runs what is left with a shell again.
    #[test]
    fn the_command_text_does_not_change_with_the_path() {
        let nasty = "/opt/it's a $dir %with \"quotes\" `back` \\slash/crabpot";

        let plain = vars(Path::new(BINARY), "srt", "0123abcd");
        let tricky = vars(Path::new(nasty), "srt", "0123abcd");

        assert_eq!(
            value(&plain, "GIT_SSH_COMMAND"),
            value(&tricky, "GIT_SSH_COMMAND"),
            "no word of the command is the path, so no path can break one"
        );
        assert_eq!(value(&tricky, BINARY_VARIABLE), nasty);
    }

    #[test]
    fn the_request_asks_the_relay_for_the_tunnel_with_the_credential() {
        let request = request("example.com:22", "c3J0OjEyMzRhYmNk");

        assert_eq!(
            request,
            "CONNECT example.com:22 HTTP/1.1\r\nHost: example.com:22\r\n\
             Proxy-Authorization: Basic c3J0OjEyMzRhYmNk\r\n\r\n"
        );
    }

    #[test]
    fn a_host_that_could_end_the_request_line_is_refused() {
        assert_eq!(
            authority("example.com", "22").as_deref(),
            Ok("example.com:22")
        );
        assert_eq!(
            authority("github.com", "443").as_deref(),
            Ok("github.com:443")
        );
        assert_eq!(
            authority("2001:db8::1", "22").as_deref(),
            Ok("[2001:db8::1]:22"),
            "an IPv6 literal is bracketed in a request target"
        );

        for host in [
            "",
            "exam ple.com",
            "example.com\r\nHost: evil",
            "example.com$",
            "example.com:22",
        ] {
            assert_eq!(
                authority(host, "22"),
                Err(SshError::BadHost(host.to_owned())),
                "{host:?}"
            );
        }
        for port in ["", "2o", "70000"] {
            assert_eq!(
                authority("example.com", port),
                Err(SshError::BadPort(port.to_owned())),
                "{port:?}"
            );
        }
    }

    #[test]
    fn the_proxy_says_what_it_refused_with() {
        assert_eq!(answer("HTTP/1.1 200 Connection Established"), Answer::Open);
        assert_eq!(answer("HTTP/1.1 204 No Content"), Answer::Open);
        assert_eq!(
            answer("HTTP/1.1 2000 Too Long"),
            Answer::Refused("2000 Too Long".to_owned())
        );
        assert_eq!(
            answer("HTTP/1.1 403 host is not on the allow list"),
            Answer::Refused("403 host is not on the allow list".to_owned())
        );
        assert_eq!(
            answer("HTTP/1.1 407 Proxy Authentication Required"),
            Answer::Refused("407 Proxy Authentication Required".to_owned())
        );
    }
}
