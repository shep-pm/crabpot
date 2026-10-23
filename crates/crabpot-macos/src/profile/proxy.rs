//! The network a sandboxed command has through the proxy: its loopback port,
//! and no other host. The Unix sockets a command may use are another section,
//! in `unix_sockets`.

/// The rules of upstream's `generateSandboxProfile` for `httpProxyPort`: the
/// command may bind, accept on and dial that one port. A host is reached by
/// asking the proxy, which decides.
pub(super) fn rules(proxy_port: Option<u16>) -> String {
    let Some(port) = proxy_port else {
        return String::new();
    };
    format!(
        "\n; Network\n\
         (allow network-bind (local ip \"localhost:{port}\"))\n\
         (allow network-inbound (local ip \"localhost:{port}\"))\n\
         (allow network-outbound (remote ip \"localhost:{port}\"))\n"
    )
}

#[cfg(test)]
mod tests {
    use crabpot_core::config::Config;

    use super::super::render;

    #[test]
    fn the_profile_admits_only_the_proxy_port() {
        let profile = render(&Config::default(), Some(51234)).unwrap();

        let network: Vec<&str> = profile
            .lines()
            .filter(|line| line.contains("network"))
            .collect();
        assert_eq!(
            network,
            [
                r#"(allow network-bind (local ip "localhost:51234"))"#,
                r#"(allow network-inbound (local ip "localhost:51234"))"#,
                r#"(allow network-outbound (remote ip "localhost:51234"))"#,
            ]
        );
    }

    #[test]
    fn without_a_proxy_the_profile_admits_no_network() {
        let profile = render(&Config::default(), None).unwrap();

        assert!(!profile.contains("(allow network"), "{profile}");
    }
}
