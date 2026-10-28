//! The environment a sandboxed command is given on Windows.
//!
//! The proxy variables are the core builders' ([`crabpot_core::env::base`],
//! [`crabpot_core::env::http`] and [`crabpot_core::env::socks`]) with the
//! changes upstream makes for Windows in `wrapCommandWithSandboxWindows`
//! (`src/sandbox/windows-sandbox-utils.ts`). Three layers merge ignoring
//! case, as Windows reads names, with a later one winning: the host's own
//! names, the proxy set, and the git config.
//!
//! The result is name and value pairs, one `--env KEY=VALUE` for
//! `srt-win exec` each. The rules read text, so they compile and run on
//! every host.

mod git_config;

use crabpot_core::env::{base, http, socks};

/// `no_proxy` for a sandboxed command when the fence lets it dial loopback
/// directly: the loopback hosts, so proxy-aware clients reach local servers
/// without the proxy. Private networks stay proxied, and fenced.
pub const WINDOWS_LOOPBACK_NO_PROXY: &str = "localhost,127.0.0.1,::1";

/// The per-tool trust-store variables a command reads to accept the certs
/// the proxy signs, as upstream's `CA_TRUST_VARS`
/// (`src/sandbox/sandbox-utils.ts`) lists them. Schannel trust comes from
/// the registry write the install did. These cover the OpenSSL-backed tools.
const CA_TRUST_VARS: &[&str] = &[
    "NODE_EXTRA_CA_CERTS",
    "SSL_CERT_FILE",
    "CURL_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
    "PIP_CERT",
    "GIT_SSL_CAINFO",
    "AWS_CA_BUNDLE",
    "CARGO_HTTP_CAINFO",
    "DENO_CERT",
    "CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE",
    "NIX_SSL_CERT_FILE",
];

/// What the environment is built from.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Facts {
    /// Whether the fence lets the command dial loopback directly.
    pub allow_loopback: bool,
    /// The HTTP proxy's port, or `None` when the sandbox runs no HTTP proxy.
    pub http_proxy_port: Option<u16>,
    /// The SOCKS5 proxy's port, or `None` when the sandbox runs no SOCKS proxy.
    pub socks_proxy_port: Option<u16>,
    /// The proxy's TLS trust bundle, as the host names it. Emitted with
    /// forward slashes.
    pub ca_cert_path: Option<String>,
    /// The directories git is told are safe: the command's working directory,
    /// the write grants over it and the config's `git.safeDirectories`, as the
    /// host names them.
    pub safe_dirs: Vec<String>,
    /// The `GIT_CONFIG_COUNT` the command brings, as text. The git config
    /// numbering continues from it, and `0` leaves the command with none.
    pub git_config_count: Option<String>,
    /// `PATH`, as the host carries it. The child runs as the sandbox user,
    /// so the host's `PATH` reaches it only through this.
    pub path: Option<String>,
    /// `PATHEXT`, as the host carries it.
    pub pathext: Option<String>,
}

/// The variables to hand `srt-win exec`, as name and value pairs.
#[must_use]
pub fn vars(facts: &Facts, username: &str, token: &str) -> Vec<(String, String)> {
    merge(&[
        host_layer(facts),
        proxy_layer(facts, username, token),
        git_config::vars_from(
            &facts.safe_dirs,
            facts.git_config_count.as_deref(),
            facts.ca_cert_path.is_some(),
        ),
    ])
}

/// The names the host hands the child, first in the merge so the sandbox's
/// own proxy set wins over them.
fn host_layer(facts: &Facts) -> Vec<(String, String)> {
    let mut layer: Vec<(String, String)> = Vec::new();
    if let Some(path) = &facts.path {
        layer.push(("PATH".to_owned(), path.clone()));
    }
    if let Some(pathext) = &facts.pathext {
        layer.push(("PATHEXT".to_owned(), pathext.clone()));
    }
    // Node's built-in clients read the proxy variables only with this set.
    if facts.http_proxy_port.is_some() {
        layer.push(("NODE_USE_ENV_PROXY".to_owned(), "1".to_owned()));
    }
    layer
}

/// The base and proxy variables, with the Windows changes applied to them.
fn proxy_layer(facts: &Facts, username: &str, token: &str) -> Vec<(String, String)> {
    // The temp folder is dropped below, so its name is not asked for.
    let mut vars: Vec<(String, String)> = base::vars(None, None)
        .into_iter()
        .map(|(name, value)| {
            (
                name.to_string_lossy().into_owned(),
                value.to_string_lossy().into_owned(),
            )
        })
        // TMPDIR names a POSIX temp folder. Windows has no such folder, and
        // msys2 tools (mktemp and the rest) break on the name.
        .filter(|(name, _)| name != "TMPDIR")
        .collect();
    if let Some(path) = &facts.ca_cert_path {
        let path = path.replace('\\', "/");
        vars.extend(
            CA_TRUST_VARS
                .iter()
                .map(|name| ((*name).to_owned(), path.clone())),
        );
    }
    if let Some(port) = facts.http_proxy_port {
        vars.extend(
            http::vars(port, username, token)
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value)),
        );
    }
    if let Some(port) = facts.socks_proxy_port {
        vars.extend(
            socks::vars(port, username, token)
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value)),
        );
    }
    // The WFP fence blocks every direct connect outside the proxy ports,
    // loopback included, so a NO_PROXY match makes a client bypass the proxy
    // and hit the fence. With loopback open the fence admits it, and only the
    // loopback hosts skip the proxy.
    vars.retain(|(name, _)| name != "NO_PROXY" && name != "no_proxy");
    if facts.allow_loopback && (facts.http_proxy_port.is_some() || facts.socks_proxy_port.is_some())
    {
        vars.push(("no_proxy".to_owned(), WINDOWS_LOOPBACK_NO_PROXY.to_owned()));
    }
    vars
}

/// The one spelling each proxy variable keeps in the child's environment:
/// the one the case-sensitive Cygwin/MSYS2 tools read. It must match
/// `PROXY_NAME_SPELLING` of `srt-win` (`src/launch.rs`), which enforces it
/// again when it builds the child's env block.
const PROXY_NAME_SPELLING: &[&str] = &[
    "http_proxy",
    "https_proxy",
    "ftp_proxy",
    "all_proxy",
    "no_proxy",
    "grpc_proxy",
    "RSYNC_PROXY",
];

/// The spelling `PROXY_NAME_SPELLING` gives the folded name, if it lists it.
fn proxy_spelling(folded: &str) -> Option<&'static str> {
    PROXY_NAME_SPELLING
        .iter()
        .copied()
        .find(|spelling| spelling.to_uppercase() == folded)
}

/// The layers merged with a later layer replacing an earlier one, name and
/// value, ignoring case as Windows reads names: two names in one block that
/// differ only by case make .NET's `Process.Start` throw. A name listed in
/// `PROXY_NAME_SPELLING` keeps the spelling it lists.
fn merge(layers: &[Vec<(String, String)>]) -> Vec<(String, String)> {
    use std::collections::HashMap;
    use std::collections::hash_map::Entry;

    let mut merged: Vec<(String, String)> = Vec::new();
    let mut at: HashMap<String, usize> = HashMap::new();
    for layer in layers {
        for (name, value) in layer {
            let folded = name.to_uppercase();
            let spelling = match proxy_spelling(&folded) {
                Some(spelling) => spelling.to_owned(),
                None => name.clone(),
            };
            match at.entry(folded) {
                Entry::Occupied(slot) => merged[*slot.get()] = (spelling, value.clone()),
                Entry::Vacant(slot) => {
                    slot.insert(merged.len());
                    merged.push((spelling, value.clone()));
                }
            }
        }
    }
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(vars: &[(String, String)], wanted: &str) -> String {
        vars.iter()
            .find(|(name, _)| *name == wanted)
            .map(|(_, value)| value.clone())
            .unwrap_or_else(|| panic!("{wanted} is not set"))
    }

    fn folded_count(vars: &[(String, String)], folded: &str) -> usize {
        vars.iter()
            .filter(|(name, _)| name.to_uppercase() == folded)
            .count()
    }

    #[test]
    fn tmpdir_is_removed() {
        let vars = vars(&Default::default(), "srt", "t");
        assert!(
            !vars
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("TMPDIR")),
            "the base builder names a POSIX temp folder, and Windows has no such folder: {vars:?}"
        );
        assert!(
            vars.contains(&("SANDBOX_RUNTIME".to_owned(), "1".to_owned())),
            "the marker the base builder sets stays: {vars:?}"
        );
    }

    #[test]
    fn no_proxy_is_set_only_with_loopback_and_a_proxy() {
        let open = vars(
            &Facts {
                allow_loopback: true,
                http_proxy_port: Some(51_234),
                ..Default::default()
            },
            "srt",
            "t",
        );
        assert_eq!(value(&open, "no_proxy"), WINDOWS_LOOPBACK_NO_PROXY);

        let socks = vars(
            &Facts {
                allow_loopback: true,
                socks_proxy_port: Some(51_235),
                ..Default::default()
            },
            "srt",
            "t",
        );
        assert_eq!(value(&socks, "no_proxy"), WINDOWS_LOOPBACK_NO_PROXY);

        let fenced = vars(
            &Facts {
                http_proxy_port: Some(51_234),
                ..Default::default()
            },
            "srt",
            "t",
        );
        assert_eq!(
            folded_count(&fenced, "NO_PROXY"),
            0,
            "a NO_PROXY match makes a client bypass the proxy and hit the fence: {fenced:?}"
        );

        let bare = vars(
            &Facts {
                allow_loopback: true,
                ..Default::default()
            },
            "srt",
            "t",
        );
        assert_eq!(
            folded_count(&bare, "NO_PROXY"),
            0,
            "with no proxy there is nothing for no_proxy to skip: {bare:?}"
        );
    }

    #[test]
    fn variable_names_merge_case_insensitively() {
        let merged = merge(&[
            vec![("Https_Proxy".to_owned(), "http://a".to_owned())],
            vec![("HTTPS_PROXY".to_owned(), "http://b".to_owned())],
        ]);
        assert_eq!(
            merged,
            vec![("https_proxy".to_owned(), "http://b".to_owned())],
            "one name, the later layer's value, the listed spelling"
        );

        let vars = vars(
            &Facts {
                allow_loopback: true,
                http_proxy_port: Some(51_234),
                socks_proxy_port: Some(51_235),
                ..Default::default()
            },
            "srt",
            "t",
        );
        let http_url = "http://srt:t@localhost:51234";
        let socks_url = "socks5h://srt:t@localhost:51235";
        for (name, expected) in [
            ("http_proxy", http_url),
            ("https_proxy", http_url),
            ("all_proxy", http_url),
            ("grpc_proxy", http_url),
            ("ftp_proxy", socks_url),
            ("no_proxy", WINDOWS_LOOPBACK_NO_PROXY),
            ("RSYNC_PROXY", "localhost:51235"),
        ] {
            assert_eq!(
                folded_count(&vars, &name.to_uppercase()),
                1,
                "{name} must have exactly one spelling: {vars:?}"
            );
            assert_eq!(value(&vars, name), expected, "{name}");
        }
    }

    #[test]
    fn the_ca_path_uses_forward_slashes() {
        let facts = Facts {
            ca_cert_path: Some(r"C:\sandbox\ca-bundle.pem".to_owned()),
            ..Default::default()
        };
        let vars = vars(&facts, "srt", "t");
        for name in CA_TRUST_VARS {
            assert_eq!(
                value(&vars, name),
                "C:/sandbox/ca-bundle.pem",
                "{name}: msys2 leaves `C:/…` alone, and a backslash would be mangled on a bash command line"
            );
        }
    }

    #[test]
    fn git_safe_directory_is_set() {
        // The sandbox runs the command as its own user, so git would call a
        // directory the host owns a dubious owner and refuse it.
        let facts = Facts {
            safe_dirs: vec![r"C:\repo".to_owned()],
            ..Default::default()
        };
        let vars = vars(&facts, "srt", "t");
        assert_eq!(value(&vars, "GIT_CONFIG_KEY_0"), "safe.directory");
        assert_eq!(value(&vars, "GIT_CONFIG_VALUE_0"), "C:/repo");
        assert_eq!(value(&vars, "GIT_CONFIG_KEY_1"), "safe.directory");
        assert_eq!(value(&vars, "GIT_CONFIG_VALUE_1"), "C:/repo/*");
        assert_eq!(value(&vars, "GIT_CONFIG_KEY_2"), "http.sslBackend");
        assert_eq!(value(&vars, "GIT_CONFIG_VALUE_2"), "openssl");
        assert_eq!(value(&vars, "GIT_CONFIG_COUNT"), "3");
    }

    #[test]
    fn the_host_path_and_pathext_pass_through() {
        let facts = Facts {
            path: Some(r"C:\Windows\system32;C:\Windows".to_owned()),
            pathext: Some(".COM;.EXE".to_owned()),
            ..Default::default()
        };
        let vars = vars(&facts, "srt", "t");
        assert_eq!(value(&vars, "PATH"), r"C:\Windows\system32;C:\Windows");
        assert_eq!(value(&vars, "PATHEXT"), ".COM;.EXE");
    }

    #[test]
    fn node_is_told_about_the_env_proxy_only_with_an_http_proxy_port() {
        let with = vars(
            &Facts {
                http_proxy_port: Some(51_234),
                ..Default::default()
            },
            "srt",
            "t",
        );
        assert_eq!(value(&with, "NODE_USE_ENV_PROXY"), "1");

        let socks_only = vars(
            &Facts {
                socks_proxy_port: Some(51_235),
                ..Default::default()
            },
            "srt",
            "t",
        );
        assert!(
            !socks_only
                .iter()
                .any(|(name, _)| name == "NODE_USE_ENV_PROXY"),
            "Node's env-proxy support reads the HTTP proxy variables, which a SOCKS-only sandbox does not set: {socks_only:?}"
        );
    }
}
