//! The variables that carry ssh's `ProxyCommand`, as upstream's
//! `generateProxyEnvVars` (`src/sandbox/sandbox-utils.ts`) sets them on macOS.
//!
//! With one port serving both protocols, the route is an HTTP `CONNECT` with the
//! proxy's credential, run by what macOS ships. BSD `nc` has no SOCKS
//! authentication to give the proxy, so `nc -X 5` is only the fallback for a
//! sandbox whose SOCKS port is not the HTTP proxy's.
//!
//! The script travels in a variable of its own, `SRT_SSH_PROXY_COMMAND`. That
//! keeps the credential out of ssh's arguments and out of what ssh starts, and
//! keeps the script out of git's `sh -c`, ssh's `%` expansions and the user's
//! own shell, which see plain and single-quoted words only.

use crabpot_core::proxy::basic_for;

/// ssh's own connection multiplexing, turned off. A mux socket path comes from
/// the user's ssh config, typically under `~/.ssh`, which the sandbox does not
/// let a socket bind at, and OpenSSH treats a mux listener that failed to bind
/// as fatal even with `ControlMaster=auto`: it exits right after
/// authentication, before running the git command. These options outrank
/// ssh_config. `ControlPath=none` is needed beside `ControlMaster=no`, since
/// with `no` alone ssh still tries to connect to an existing mux socket at the
/// configured path.
const MUX_OVERRIDE: &str = "-o ControlMaster=no -o ControlPath=none";

/// The variables that carry ssh's `ProxyCommand` for a sandbox whose HTTP proxy
/// answers on `http_port` and whose SOCKS proxy on `socks_port`, wanting
/// `username` and `token` from a client.
///
/// The two ports are equal when one port serves both protocols, which is what
/// the mux shows a command. Then ssh goes through the HTTP proxy, and the
/// credential rides in `SRT_SSH_PROXY_COMMAND`.
#[must_use]
pub fn vars(
    http_port: u16,
    socks_port: u16,
    username: &str,
    token: &str,
) -> Vec<(&'static str, String)> {
    if http_port != socks_port {
        // `nc` is on every Mac, and `-X 5` is SOCKS5. It cannot log in, so a
        // proxy that wants a credential refuses it, and this is the route left.
        return vec![(
            "GIT_SSH_COMMAND",
            format!("ssh {MUX_OVERRIDE} -o ProxyCommand='nc -X 5 -x localhost:{socks_port} %h %p'"),
        )];
    }
    vec![
        (
            "SRT_SSH_PROXY_COMMAND",
            connect_script(socks_port, &basic_for(username, token)),
        ),
        (
            "GIT_SSH_COMMAND",
            format!(
                "ssh {MUX_OVERRIDE} -o ProxyCommand=\"/bin/sh -c 'eval \\\"${{SRT_SSH_PROXY_COMMAND:?unset, but GIT_SSH_COMMAND needs it}}\\\"' sh '%h' %p\""
            ),
        ),
    ]
}

/// POSIX shell that answers `sh <host> <port>`: an HTTP `CONNECT` to
/// `127.0.0.1:port` with the `Basic` credential `basic`, then stdin and stdout
/// relayed by `/usr/bin/nc`. It is upstream's `sshConnectScript` word for word.
///
/// The host comes from a git URL, which a repository chooses. It is never script
/// text or printf's format, and one that could end the request line is refused
/// before anything is sent.
///
/// The response head is read here, so a refusal is one line on stderr with the
/// status line's own words. The pipeline runs in the background (hence stdin as
/// fd 3) so that this shell can close its own copy of stdout: held, it would
/// keep an end of file from ssh.
///
/// `/usr/bin/nc` is the one macOS ships, by path: it leaves when the network
/// side ends, which is how ssh learns of it. Current OpenBSD and Debian ones
/// stay until their stdin ends too, and ssh would wait.
#[must_use]
pub fn connect_script(port: u16, basic: &str) -> String {
    format!(
        "LC_ALL=C; no() {{ printf \"sandbox proxy: %s\\n\" \"$*\" >&2; exit 1; }}; \
         case $1 in \"\"|*[!A-Za-z0-9._:-]*) no bad host;; *:*) set -- \"[$1]\" \"$2\";; esac; \
         case $2 in \"\"|*[!0-9]*) no bad port;; esac; \
         exec 3<&0; \
         {{ printf \"CONNECT %s HTTP/1.1\\r\\nHost: %s\\r\\nProxy-Authorization: Basic {basic}\\r\\n\\r\\n\" \"$1:$2\" \"$1:$2\"; exec /bin/cat <&3; }} | \
         /usr/bin/nc 127.0.0.1 {port} | \
         {{ read -r v why; while read -r v; do case $v in \"\"|?) break;; esac; done; \
         case $why in \"200 \"*) exec /bin/cat;; esac; \
         why=${{why%?}}; no \"$1:$2: ${{why:-no answer}}\"; }} & \
         exec >&-; wait $!"
    )
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
    fn git_ssh_command_uses_the_script_when_the_ports_are_equal() {
        let vars = vars(51234, 51234, "srt", "0123abcd");

        assert_eq!(
            value(&vars, "GIT_SSH_COMMAND"),
            "ssh -o ControlMaster=no -o ControlPath=none -o ProxyCommand=\"/bin/sh -c \
             'eval \\\"${SRT_SSH_PROXY_COMMAND:?unset, but GIT_SSH_COMMAND needs it}\\\"' \
             sh '%h' %p\""
        );
        let script = value(&vars, "SRT_SSH_PROXY_COMMAND");
        assert!(
            script.contains("Proxy-Authorization: Basic c3J0OjAxMjNhYmNk"),
            "{script}"
        );
        assert!(script.contains("/usr/bin/nc 127.0.0.1 51234"), "{script}");
        assert!(
            !vars.iter().any(|(name, _)| *name == "FTP_PROXY"),
            "the SOCKS part's variables are its own"
        );
    }

    #[test]
    fn git_ssh_command_falls_back_to_nc_when_the_ports_differ() {
        let vars = vars(51234, 51235, "srt", "0123abcd");

        assert_eq!(
            value(&vars, "GIT_SSH_COMMAND"),
            "ssh -o ControlMaster=no -o ControlPath=none -o ProxyCommand=\
             'nc -X 5 -x localhost:51235 %h %p'"
        );
        assert!(
            !vars
                .iter()
                .any(|(name, _)| *name == "SRT_SSH_PROXY_COMMAND")
        );
    }

    #[test]
    fn the_script_is_one_line_and_ends_its_own_pipeline() {
        let script = connect_script(1, "eA==");

        assert!(!script.contains('\n'), "one line, for a variable value");
        assert!(script.ends_with("exec >&-; wait $!"), "{script}");
        assert!(script.starts_with("LC_ALL=C; "), "{script}");
    }
}
