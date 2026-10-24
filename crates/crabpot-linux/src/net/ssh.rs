//! The variables that carry ssh's `ProxyCommand` on Linux, where the route to
//! the proxy is the relay on the sandbox's own HTTP port (ADR-0014).
//!
//! Upstream builds this hop on `socat`, which crabpot has no reason to borrow
//! (decision #90): the hop is crabpot's own binary in the `connect` mode. The
//! credential is not in the command: it rides in a variable of its own, as
//! macOS carries it in `SRT_SSH_PROXY_COMMAND`, so what reads an argv reads no
//! credential.

use core::fmt;
use core::net::Ipv6Addr;
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

/// The name of the variable that carries the proxy's `Basic` credential for the
/// `connect` mode to read. It is set on the wrapped command's environment and
/// never in a bwrap word, and the command's own processes are not dumpable, so
/// their environment is not readable from `/proc`.
pub const CREDENTIAL_VARIABLE: &str = "SRT_SSH_PROXY_CREDENTIAL";

/// The variables a command needs to send git over ssh through the relay, for a
/// proxy that wants `username` and `token` from a client.
///
/// The `ProxyCommand` names `binary`, which is this binary as bwrap binds it
/// into the sandbox, and the sandbox's HTTP port, which the relay forwards to
/// the proxy.
#[must_use]
pub fn vars(binary: &Path, username: &str, token: &str) -> Vec<(&'static str, String)> {
    vec![
        ("GIT_SSH_COMMAND", command(binary)),
        (CREDENTIAL_VARIABLE, basic_for(username, token)),
    ]
}

/// ssh's `ProxyCommand` value: this binary in the `connect` mode, asked for the
/// host and port ssh names with ssh's own `%h` and `%p`.
///
/// The binary is quoted for the `/bin/sh -c` ssh runs the value with, and the
/// whole value quoted for the shell-like splitting git reads
/// `GIT_SSH_COMMAND` with. git's split leaves the inner quotes for ssh's shell,
/// which is what keeps a path with a space one word.
fn command(binary: &Path) -> String {
    format!(
        "ssh {MUX_OVERRIDE} -o ProxyCommand='\"{}\" {CONNECT_REENTRY} {HTTP_PORT} %h %p'",
        binary.display()
    )
}

/// What the proxy answered a `CONNECT` with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// The tunnel is open, and the bytes can flow.
    Open,
    /// The refusal, as the status line named it.
    Refused(String),
}

/// The `Answer` to the proxy's status line `line`.
#[must_use]
pub fn answer(line: &str) -> Answer {
    let status = line
        .strip_prefix("HTTP/1.1 ")
        .or_else(|| line.strip_prefix("HTTP/1.0 "))
        .map(|rest| rest.trim_end());
    match status {
        Some(status) if status.split(' ').next() == Some("200") => Answer::Open,
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

    fn value<'a>(vars: &'a [(&str, String)], name: &str) -> &'a str {
        vars.iter()
            .find(|(var, _)| *var == name)
            .map(|(_, value)| value.as_str())
            .unwrap_or_else(|| panic!("{name} is not set"))
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
            !command.contains(basic),
            "the credential is not in a command line any process can read: {command}"
        );
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
        assert_eq!(
            answer("HTTP/1.1 403 host is not on the allow list"),
            Answer::Refused("403 host is not on the allow list".to_owned())
        );
        assert_eq!(
            answer("HTTP/1.1 407 Proxy Authentication Required"),
            Answer::Refused("407 Proxy Authentication Required".to_owned())
        );
    }

    #[test]
    fn the_command_names_the_binary_and_port_3128() {
        let vars = vars(Path::new(BINARY), "srt", "0123abcd");

        assert_eq!(
            value(&vars, "GIT_SSH_COMMAND"),
            "ssh -o ControlMaster=no -o ControlPath=none -o ProxyCommand=\
             '\"/opt/crabpot/bin/crabpot\" --crabpot-helper connect 3128 %h %p'"
        );
    }
}
