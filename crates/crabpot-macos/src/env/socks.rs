//! The variables that need the SOCKS proxy's port, as upstream's
//! `generateProxyEnvVars` (`src/sandbox/sandbox-utils.ts`) sets them for a
//! SOCKS proxy: the clients that speak SOCKS5 and the ones that only take a
//! proxy's address.
//!
//! ssh is not among them. Its `ProxyCommand` is the `ssh` part's, which reaches
//! the one port by HTTP `CONNECT` when one port serves both protocols.

/// The variables for a SOCKS5 proxy on `127.0.0.1:port` that wants `username`
/// and `token` from a client, as name and value pairs.
#[must_use]
pub fn vars(port: u16, username: &str, token: &str) -> Vec<(&'static str, String)> {
    let url = format!(
        "socks5h://{}@localhost:{port}",
        super::http::login(username, token)
    );
    let mut vars = Vec::new();
    for name in ["FTP_PROXY", "ftp_proxy"] {
        vars.push((name, url.clone()));
    }
    vars.push(("RSYNC_PROXY", format!("localhost:{port}")));
    for name in ["DOCKER_HTTP_PROXY", "DOCKER_HTTPS_PROXY"] {
        vars.push((name, url.clone()));
    }
    vars.extend([
        ("CLOUDSDK_PROXY_TYPE", "socks5".to_owned()),
        ("CLOUDSDK_PROXY_ADDRESS", "localhost".to_owned()),
        ("CLOUDSDK_PROXY_PORT", port.to_string()),
        ("CLOUDSDK_PROXY_USERNAME", username.to_owned()),
        ("CLOUDSDK_PROXY_PASSWORD", token.to_owned()),
    ]);
    vars
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_socks_vars_use_the_socks_port() {
        let vars = vars(51235, "srt.bHM=", "0123abcd");
        let url = "socks5h://srt.bHM%3D:0123abcd@localhost:51235";

        let expected: Vec<(&str, &str)> = vec![
            ("FTP_PROXY", url),
            ("ftp_proxy", url),
            ("RSYNC_PROXY", "localhost:51235"),
            ("DOCKER_HTTP_PROXY", url),
            ("DOCKER_HTTPS_PROXY", url),
            ("CLOUDSDK_PROXY_TYPE", "socks5"),
            ("CLOUDSDK_PROXY_ADDRESS", "localhost"),
            ("CLOUDSDK_PROXY_PORT", "51235"),
            ("CLOUDSDK_PROXY_USERNAME", "srt.bHM="),
            ("CLOUDSDK_PROXY_PASSWORD", "0123abcd"),
        ];
        let got: Vec<(&str, &str)> = vars
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn ssh_is_left_to_the_part_that_knows_the_port_it_needs() {
        let vars = vars(51235, "srt", "0123abcd");

        assert!(vars.iter().all(|(name, _)| *name != "GIT_SSH_COMMAND"));
        assert!(vars.iter().any(|(name, _)| *name == "FTP_PROXY"));
    }
}
