//! What `network.allowUnixSockets` opens: the Unix sockets a command may bind
//! and dial, by path.
//!
//! Upstream's `allowUnixSockets` branch of its seatbelt profile at aceba124
//! (`src/sandbox/macos-sandbox-utils.ts:1301-1313`): one `AF_UNIX`
//! `system-socket` line, then a bind rule and an outbound rule per path.
//! `allowAllUnixSockets`, which drops the path, is still refused.

use crabpot_core::PathError;
use crabpot_core::config::Config;

use super::rule;

pub(super) fn rules(config: &Config) -> Result<String, PathError> {
    let paths = config.network.unix_socket_paths()?;
    if paths.is_empty() {
        return Ok(String::new());
    }
    let mut section = String::from("\n; Unix sockets\n");
    section.push_str("(allow system-socket (socket-domain AF_UNIX))\n");
    for path in &paths {
        let socket = format!("(subpath {})", rule::string(path));
        section.push_str(&format!(
            "(allow network-bind (local unix-socket {socket}))\n\
             (allow network-outbound (remote unix-socket {socket}))\n"
        ));
    }
    Ok(section)
}

#[cfg(test)]
mod tests {
    use super::super::render;
    use super::*;

    /// A config whose `allowUnixSockets` is `allow_unix_sockets`.
    fn allowing(allow_unix_sockets: &str) -> Config {
        Config::from_json(&format!(
            r#"{{
                "network": {{"allowedDomains": [], "deniedDomains": [],
                    "allowUnixSockets": {allow_unix_sockets}}},
                "filesystem": {{"denyRead": [], "allowWrite": [], "denyWrite": []}}
            }}"#
        ))
        .unwrap()
    }

    #[test]
    fn each_path_gets_a_bind_and_an_outbound_rule() {
        let profile = rules(&allowing(
            r#"["/crabpot-nowhere/socks", "/crabpot-nowhere/live.sock"]"#,
        ))
        .unwrap();

        assert_eq!(
            profile,
            r#"
; Unix sockets
(allow system-socket (socket-domain AF_UNIX))
(allow network-bind (local unix-socket (subpath "/crabpot-nowhere/socks")))
(allow network-outbound (remote unix-socket (subpath "/crabpot-nowhere/socks")))
(allow network-bind (local unix-socket (subpath "/crabpot-nowhere/live.sock")))
(allow network-outbound (remote unix-socket (subpath "/crabpot-nowhere/live.sock")))
"#
        );
    }

    #[test]
    fn an_empty_string_normalises_to_the_cwd() {
        // The working directory the wrapper runs in, which is what upstream's
        // `path.resolve(cwd, "")` names for an empty entry.
        let cwd = std::env::current_dir().unwrap().canonicalize().unwrap();
        let cwd = cwd.to_str().unwrap();

        let profile = rules(&allowing(r#"[""]"#)).unwrap();

        assert_eq!(
            profile,
            format!(
                "\n; Unix sockets\n\
                 (allow system-socket (socket-domain AF_UNIX))\n\
                 (allow network-bind (local unix-socket (subpath {cwd:?})))\n\
                 (allow network-outbound (remote unix-socket (subpath {cwd:?})))\n"
            )
        );
    }

    #[test]
    fn nothing_listed_renders_nothing() {
        assert_eq!(rules(&allowing("[]")).unwrap(), "");
        assert_eq!(rules(&Config::default()).unwrap(), "");
    }

    #[test]
    fn the_socket_rules_come_after_the_write_rules() {
        let profile = render(&allowing(r#"["/crabpot-nowhere/socks"]"#), None).unwrap();

        let write = profile.find("; Writes").unwrap();
        let sockets = profile.find("; Unix sockets").unwrap();
        assert!(write < sockets, "{profile}");
    }
}
