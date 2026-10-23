//! The variables that point a command's clients at the HTTP proxy, as
//! upstream's `generateProxyEnvVars` (`src/sandbox/sandbox-utils.ts`) sets them
//! for an HTTP proxy alone.

/// Hosts a client reaches without the proxy. `*.local` is absent on purpose,
/// as upstream has it: the command has no resolver of its own to find one.
const NO_PROXY: &str =
    "localhost,127.0.0.1,::1,169.254.0.0/16,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16";

/// The variables for a proxy on `127.0.0.1:port` that wants `username` and
/// `token` from a client, as name and value pairs.
#[must_use]
pub fn vars(port: u16, username: &str, token: &str) -> Vec<(&'static str, String)> {
    let user = if username == "srt" {
        username.to_owned()
    } else {
        percent_encode(username)
    };
    let url = format!("http://{user}:{token}@localhost:{port}");
    let mut vars = vec![
        ("NO_PROXY", NO_PROXY.to_owned()),
        ("no_proxy", NO_PROXY.to_owned()),
    ];
    for name in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
        vars.push((name, url.clone()));
    }
    // Sent before git is asked for it, so git never meets a 407 and never
    // asks a credential helper about the proxy's URL.
    vars.push((
        "GIT_CONFIG_PARAMETERS",
        "'http.proxyAuthMethod=basic'".to_owned(),
    ));
    for name in ["ALL_PROXY", "all_proxy", "GRPC_PROXY", "grpc_proxy"] {
        vars.push((name, url.clone()));
    }
    vars
}

/// What JavaScript's `encodeURIComponent` leaves alone is `A-Z a-z 0-9` and
/// `- _ . ! ~ * ' ( )`. The rest, byte by byte, becomes `%XX`.
fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&byte) {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value<'a>(vars: &'a [(&str, String)], name: &str) -> &'a str {
        vars.iter()
            .find(|(var, _)| *var == name)
            .map(|(_, value)| value.as_str())
            .unwrap_or_else(|| panic!("{name} is not set"))
    }

    #[test]
    fn every_client_is_pointed_at_the_proxy_with_its_credential() {
        let vars = vars(51234, "srt.bHMgLWxh", "0123abcd");
        let url = "http://srt.bHMgLWxh:0123abcd@localhost:51234";

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
        let no_proxy =
            "localhost,127.0.0.1,::1,169.254.0.0/16,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16";
        assert_eq!(value(&vars, "NO_PROXY"), no_proxy);
        assert_eq!(value(&vars, "no_proxy"), no_proxy);
    }

    #[test]
    fn the_base64_of_a_username_is_percent_encoded() {
        // `bHM/Pz8+` carries `/` and `+`, and `=` is padding.
        let vars = vars(1, "srt.bHM/Pz8+Zg==", "t");

        assert_eq!(
            value(&vars, "HTTP_PROXY"),
            "http://srt.bHM%2FPz8%2BZg%3D%3D:t@localhost:1"
        );
        assert_eq!(
            value(&super::vars(1, "srt", "t"), "HTTP_PROXY"),
            "http://srt:t@localhost:1"
        );
    }
}
