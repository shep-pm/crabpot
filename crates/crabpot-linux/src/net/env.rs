//! The variables that point a command's clients at the relays, as upstream's
//! `generateProxyEnvVars` (`src/sandbox/sandbox-utils.ts`) sets them on Linux.
//!
//! The builders are [`crabpot_core::env::http`] and [`crabpot_core::env::socks`],
//! which macOS uses with the proxy's own ports. Here the ports are the ones the
//! relays listen on. The variables hold the proxy's credential, so they are set
//! on the wrapped `Command`'s environment and never as bwrap words, which any
//! process on the host can read from `/proc`.

use crabpot_core::env::{http, socks};

use super::{HTTP_PORT, SOCKS_PORT};

/// The proxy's ports on the host, which the command can read but not dial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostPorts {
    /// The HTTP proxy's port.
    pub http: u16,
    /// The SOCKS5 proxy's port.
    pub socks: u16,
}

/// The variables for a command that presents `username` and `token` to the
/// proxy, as name and value pairs.
#[must_use]
pub fn vars(host: HostPorts, username: &str, token: &str) -> Vec<(&'static str, String)> {
    let mut vars = http::vars(HTTP_PORT, username, token);
    vars.extend(socks::vars(SOCKS_PORT, username, token));
    vars.extend([
        ("CLAUDE_CODE_HOST_HTTP_PROXY_PORT", host.http.to_string()),
        ("CLAUDE_CODE_HOST_SOCKS_PROXY_PORT", host.socks.to_string()),
    ]);
    vars
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crabpot_core::config::Config;

    use super::*;
    use crate::wrap;

    const HOST: HostPorts = HostPorts {
        http: 41_000,
        socks: 41_001,
    };

    fn value(vars: &[(&str, String)], name: &str) -> String {
        vars.iter()
            .find(|(var, _)| *var == name)
            .map(|(_, value)| value.clone())
            .unwrap_or_else(|| panic!("{name} is not set"))
    }

    #[test]
    fn the_http_variables_point_at_localhost_3128() {
        let vars = vars(HOST, "srt.bHM=", "0123abcd");
        let url = "http://srt.bHM%3D:0123abcd@localhost:3128";

        for name in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "http_proxy",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
            "GRPC_PROXY",
            "grpc_proxy",
        ] {
            assert_eq!(value(&vars, name), url, "{name}");
        }
        assert_eq!(
            value(&vars, "GIT_CONFIG_PARAMETERS"),
            "'http.proxyAuthMethod=basic'"
        );
    }

    #[test]
    fn the_socks_variables_point_at_localhost_1080() {
        let vars = vars(HOST, "srt.bHM=", "0123abcd");
        let url = "socks5h://srt.bHM%3D:0123abcd@localhost:1080";

        for name in [
            "FTP_PROXY",
            "ftp_proxy",
            "DOCKER_HTTP_PROXY",
            "DOCKER_HTTPS_PROXY",
        ] {
            assert_eq!(value(&vars, name), url, "{name}");
        }
        assert_eq!(value(&vars, "RSYNC_PROXY"), "localhost:1080");
        assert_eq!(value(&vars, "CLOUDSDK_PROXY_TYPE"), "socks5");
        assert_eq!(value(&vars, "CLOUDSDK_PROXY_ADDRESS"), "localhost");
        assert_eq!(value(&vars, "CLOUDSDK_PROXY_PORT"), "1080");
        assert_eq!(value(&vars, "CLOUDSDK_PROXY_USERNAME"), "srt.bHM=");
        assert_eq!(value(&vars, "CLOUDSDK_PROXY_PASSWORD"), "0123abcd");
    }

    #[test]
    fn the_token_is_not_in_a_bwrap_word() {
        let token = "f00dfacecafe0123";
        let vars = vars(HOST, "srt", token);
        let words = wrap::words(
            Path::new("/usr/bin/bwrap"),
            &Config::default(),
            Path::new("/opt/crabpot/bin/crabpot"),
            Path::new("/tmp/claude-http-0123456789abcdef.sock"),
            false,
        )
        .expect("the config resolves")
        .words;

        assert!(
            vars.iter().any(|(_, value)| value.contains(token)),
            "the variables carry the token: {vars:?}"
        );
        assert!(
            words
                .iter()
                .all(|word| !word.to_string_lossy().contains(token)),
            "bwrap's argv is readable from /proc by every process of the user: {words:?}"
        );
    }

    #[test]
    fn the_hosts_own_ports_are_named_for_the_command() {
        let vars = vars(HOST, "srt", "t");

        assert_eq!(value(&vars, "CLAUDE_CODE_HOST_HTTP_PROXY_PORT"), "41000");
        assert_eq!(value(&vars, "CLAUDE_CODE_HOST_SOCKS_PROXY_PORT"), "41001");
    }
}
