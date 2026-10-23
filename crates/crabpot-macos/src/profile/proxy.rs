//! The network a sandboxed command has: the proxies' loopback ports, and nothing else.
//! The Unix sockets a command may use are another section, in `unix_sockets`.

/// The rules of upstream's `generateSandboxProfile` for `httpProxyPort` and
/// `socksProxyPort`: the command may bind, accept on and dial those ports. A
/// host is reached by asking the proxy, which decides. A SOCKS port that is the
/// HTTP port has its rules once.
pub(super) fn rules(proxy_port: Option<u16>, socks_port: Option<u16>) -> String {
    let socks_port = socks_port.filter(|port| Some(*port) != proxy_port);
    let mut ports = proxy_port.into_iter().chain(socks_port).peekable();
    if ports.peek().is_none() {
        return String::new();
    }
    let mut rules = String::from("\n; Network\n");
    for port in ports {
        rules.push_str(&format!(
            "(allow network-bind (local ip \"localhost:{port}\"))\n\
             (allow network-inbound (local ip \"localhost:{port}\"))\n\
             (allow network-outbound (remote ip \"localhost:{port}\"))\n"
        ));
    }
    rules
}

#[cfg(test)]
mod tests {
    use crabpot_core::config::Config;

    use super::super::render;

    #[test]
    fn the_profile_admits_only_the_proxy_port() {
        let profile = render(&Config::default(), Some(51234), None).unwrap();

        assert_eq!(
            network_lines(&profile),
            [
                r#"(allow network-bind (local ip "localhost:51234"))"#,
                r#"(allow network-inbound (local ip "localhost:51234"))"#,
                r#"(allow network-outbound (remote ip "localhost:51234"))"#,
            ]
        );
    }

    #[test]
    fn without_a_proxy_the_profile_admits_no_network() {
        let profile = render(&Config::default(), None, None).unwrap();

        assert!(!profile.contains("(allow network"), "{profile}");
    }

    fn network_lines(profile: &str) -> Vec<&str> {
        profile
            .lines()
            .filter(|line| line.contains("network"))
            .collect()
    }

    #[test]
    fn the_socks_port_gets_the_same_three_rules() {
        let profile = render(&Config::default(), Some(51234), Some(51235)).unwrap();

        assert_eq!(
            network_lines(&profile),
            [
                r#"(allow network-bind (local ip "localhost:51234"))"#,
                r#"(allow network-inbound (local ip "localhost:51234"))"#,
                r#"(allow network-outbound (remote ip "localhost:51234"))"#,
                r#"(allow network-bind (local ip "localhost:51235"))"#,
                r#"(allow network-inbound (local ip "localhost:51235"))"#,
                r#"(allow network-outbound (remote ip "localhost:51235"))"#,
            ]
        );
    }

    #[test]
    fn a_socks_port_that_is_the_http_port_is_not_ruled_twice() {
        let shared = render(&Config::default(), Some(51234), Some(51234)).unwrap();
        let alone = render(&Config::default(), Some(51234), None).unwrap();

        assert_eq!(shared, alone);
    }
}
