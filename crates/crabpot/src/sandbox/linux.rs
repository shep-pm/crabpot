//! Linux command wrapping and helper options

use std::collections::HashMap;
use std::ffi::OsString;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::process::Command;
use std::sync::PoisonError;

use crabpot_core::config::Config;
use crabpot_core::proxy::{TcpGrant, username_for};
use crabpot_linux::info::Info;
use crabpot_linux::net::env::HostPorts;
use crabpot_linux::net::{HTTP_PORT, SOCKS_PORT};
use crabpot_linux::startup::{Pipe, Startup};

use crate::args::{
    HELPER_FLAG, HelperMode, LOOPBACK_FLAG, PUBLISH_FD_FLAG, RELAY_FLAG, REPORT_STARTED_FLAG,
};

use super::{Sandbox, StartError, WrapError, carry_over, command_line};

pub(super) fn resolve_tcp(config: &Config) -> Result<Vec<TcpGrant>, StartError> {
    let mut resolved: HashMap<&str, Vec<SocketAddr>> = HashMap::new();
    let mut grants = Vec::new();
    for destination in config.network.allow_tcp.as_deref().unwrap_or_default() {
        let host = destination.host();
        // The scope is an interface index of the host. The sandbox's network
        // namespace has its own, and the proxy's filter refuses a zone.
        if host.contains('%') {
            return Err(StartError::ScopedTcp {
                host: host.to_owned(),
            });
        }
        if !resolved.contains_key(host) {
            let addresses: Vec<_> =
                match format!("[{host}]:{}", destination.port()).parse::<SocketAddr>() {
                    Ok(address) => vec![address],
                    Err(_) => (host, destination.port())
                        .to_socket_addrs()
                        .map_err(|_| StartError::UnresolvedTcp {
                            host: host.to_owned(),
                        })?
                        .collect(),
                };
            // A name can resolve to a link-local address with a scope, which is
            // as unusable in the sandbox's network as a scoped literal.
            let addresses: Vec<_> = addresses
                .into_iter()
                .filter(|address| !matches!(address, SocketAddr::V6(v6) if v6.scope_id() != 0))
                .collect();
            if addresses.is_empty() {
                return Err(StartError::UnresolvedTcp {
                    host: host.to_owned(),
                });
            }
            resolved.insert(host, addresses);
        }
        for mut address in resolved[host].iter().copied() {
            address.set_port(destination.port());
            let grant = TcpGrant {
                host: host.to_owned(),
                address,
            };
            if !grants.contains(&grant) {
                grants.push(grant);
            }
        }
    }
    Ok(grants)
}

/// The addresses `network.publish` names, as the host listens on them and the
/// helper dials them inside.
///
/// The relay holds the proxy ports on every address of the sandbox, so the
/// command could not bind a published port that is one of them. An interface
/// scope is a number of the host's, and means another interface in the
/// sandbox's own network. An IPv4-mapped address is the IPv4 address it wraps,
/// which an IPv6-only bind would refuse.
pub(super) fn resolve_publish(config: &Config) -> Result<Vec<SocketAddr>, StartError> {
    let mut resolved: Vec<SocketAddr> = Vec::new();
    for &address in config.network.publish.as_deref().unwrap_or_default() {
        if matches!(address, SocketAddr::V6(v6) if v6.scope_id() != 0) {
            return Err(StartError::ScopedPublish { address });
        }
        if [HTTP_PORT, SOCKS_PORT].contains(&address.port()) {
            return Err(StartError::PublishedProxyPort { address });
        }
        let address = SocketAddr::new(address.ip().to_canonical(), address.port());
        if !resolved.contains(&address) {
            resolved.push(address);
        }
    }
    Ok(resolved)
}

impl Sandbox {
    /// [`Sandbox::command`], and with it what bwrap reports of the sandbox,
    /// which tells the launcher which process to signal in place of bwrap
    /// itself. The command is given the descriptor the report goes to, so it
    /// is spawned from the returned [`Command`] and not from one a plain
    /// [`Sandbox::command`] gave.
    pub(crate) fn command_reporting(
        &self,
        command: &Command,
    ) -> Result<(Command, Info, Startup), WrapError> {
        let pipe = Pipe::open().map_err(|e| WrapError::Bwrap(e.to_string()))?;
        let mut wrapped = self.linux_command(command, Some(pipe.fd()), &[])?;
        let info = crabpot_linux::info::attach(&mut wrapped)
            .map_err(|e| WrapError::Bwrap(e.to_string()))?;
        let startup = pipe.attach(&mut wrapped);
        Ok((wrapped, info, startup))
    }

    pub(super) fn linux_command(
        &self,
        command: &Command,
        report: Option<u32>,
        loopback: &[IpAddr],
    ) -> Result<Command, WrapError> {
        let mut words = vec![
            self.helper.clone().into_os_string(),
            OsString::from(HELPER_FLAG),
            OsString::from(HelperMode::Init.word()),
            OsString::from(RELAY_FLAG),
            self.proxy.mux_socket().as_os_str().to_owned(),
        ];
        if let Some(fd) = report {
            words.extend([
                OsString::from(REPORT_STARTED_FLAG),
                OsString::from(fd.to_string()),
            ]);
        }
        if !self.publish.is_empty() {
            words.extend([
                OsString::from(PUBLISH_FD_FLAG),
                crabpot_linux::wrap::PUBLISH_FD.to_string().into(),
            ]);
        }
        for address in loopback.iter().chain(&self.published_addresses(loopback)) {
            words.extend([OsString::from(LOOPBACK_FLAG), address.to_string().into()]);
        }
        for grant in &self.tcp {
            words.extend([
                OsString::from(LOOPBACK_FLAG),
                grant.address.to_string().into(),
            ]);
        }
        words.push(OsString::from("--"));
        words.push(command.get_program().to_owned());
        words.extend(command.get_args().map(OsString::from));
        let mut bwrap_words = self.words.clone();
        if report.is_some() {
            bwrap_words.splice(1..1, crabpot_linux::wrap::info_words());
        }
        let rendered = crabpot_linux::argv::render(&bwrap_words, &words, &std::env::temp_dir())
            .map_err(|e| WrapError::Bwrap(e.to_string()))?;
        let mut wrapped = rendered.command;
        if !self.publish.is_empty() {
            let published = crabpot_linux::net::publish::publish(&self.publish, &mut wrapped)
                .map_err(|e| WrapError::Publish(e.to_string()))?;
            self.published
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(published);
        }
        carry_over(command, &mut wrapped);
        for (name, value) in crabpot_linux::env::vars(&self.facts.for_command(command)) {
            wrapped.env(name, value);
        }
        // On the command's environment, not in bwrap's words: its argv is
        // readable from `/proc` by every process of the user, and the token
        // is the proxy's credential.
        let username = username_for(&command_line(command));
        let host = HostPorts {
            http: self.proxy.port(),
            socks: self.proxy.socks_port(),
        };
        let ssh = crabpot_linux::net::ssh::vars(&self.helper, &username, self.proxy.token());
        for (name, value) in crabpot_linux::net::env::vars(host, &username, self.proxy.token())
            .into_iter()
            .map(|(name, value)| (name, OsString::from(value)))
            .chain(ssh)
        {
            wrapped.env(name, value);
        }
        if let Some(args_file) = rendered.args_file {
            self.args_files
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(args_file);
        }
        Ok(wrapped)
    }
}

impl Sandbox {
    /// The published addresses the command can only bind once `lo` holds them:
    /// neither loopback, which `lo` has, nor a wildcard, nor one in `have`.
    fn published_addresses(&self, have: &[IpAddr]) -> Vec<IpAddr> {
        let mut addresses: Vec<IpAddr> = Vec::new();
        for ip in self.publish.iter().map(SocketAddr::ip) {
            if !ip.is_loopback()
                && !ip.is_unspecified()
                && !have.contains(&ip)
                && !addresses.contains(&ip)
            {
                addresses.push(ip);
            }
        }
        addresses
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scoped_ipv6_grant_refuses_the_sandbox_naming_it() {
        let config = Config::from_json(
            r#"{"network":{"allowedDomains":[],"deniedDomains":[],"allowTcp":["[fe80::1%2]:22"]},
                "filesystem":{"denyRead":[],"allowWrite":[],"denyWrite":[]}}"#,
        )
        .unwrap();

        let error = resolve_tcp(&config).unwrap_err();

        assert!(
            matches!(&error, StartError::ScopedTcp { host } if host == "fe80::1%2"),
            "{error}"
        );
        assert!(error.to_string().contains("fe80::1%2"), "{error}");
    }

    #[test]
    fn the_helper_receives_each_loopback_address_before_the_command() {
        let sandbox = match Sandbox::start(&Config::default()) {
            Ok(sandbox) => sandbox,
            // The machine has no bwrap to wrap a command in.
            Err(StartError::Missing { .. } | StartError::Uid0WithoutSetfcap) => return,
            Err(error) => panic!("{error}"),
        };
        let addresses = ["10.0.0.5".parse().unwrap(), "fd00::5".parse().unwrap()];
        let mut command = Command::new("echo");
        command.arg("--loopback");
        let wrapped = sandbox.linux_command(&command, None, &addresses).unwrap();
        let args: Vec<_> = wrapped
            .get_args()
            .skip_while(|arg| *arg != HELPER_FLAG)
            .map(OsString::from)
            .collect();
        let helper = crate::args::parse_helper(args).unwrap().unwrap();
        let init = crate::args::parse_init(&helper.args).unwrap();

        assert_eq!(init.loopback, addresses);
        assert_eq!(init.relay, Some(sandbox.proxy.mux_socket()));
        assert_eq!(
            init.command,
            [OsString::from("echo"), OsString::from("--loopback")]
        );
    }

    fn publishing(entries: &[&str]) -> Config {
        Config::from_json(
            &serde_json::json!({
                "network": {"allowedDomains": [], "deniedDomains": [], "publish": entries},
                "filesystem": {"denyRead": [], "allowWrite": [], "denyWrite": []}
            })
            .to_string(),
        )
        .unwrap()
    }

    #[test]
    fn a_published_port_the_proxy_relay_holds_inside_refuses_the_sandbox_naming_it() {
        for entry in ["127.0.0.1:3128", "[::]:1080", "10.0.0.5:3128"] {
            let error = resolve_publish(&publishing(&[entry])).unwrap_err();

            assert!(
                matches!(&error, StartError::PublishedProxyPort { address } if address.to_string() == entry),
                "{entry}: {error}"
            );
            assert!(error.to_string().contains(entry), "{error}");
        }
    }

    #[test]
    fn a_scoped_ipv6_publish_entry_refuses_the_sandbox_naming_it() {
        let error = resolve_publish(&publishing(&["[fe80::1%2]:8001"])).unwrap_err();

        assert!(
            matches!(&error, StartError::ScopedPublish { address } if address.to_string() == "[fe80::1%2]:8001"),
            "{error}"
        );
        assert!(error.to_string().contains("fe80::1%2"), "{error}");
    }

    #[test]
    fn an_ipv4_mapped_publish_entry_is_the_ipv4_address_once() {
        let published = resolve_publish(&publishing(&[
            "[::ffff:10.0.0.5]:8001",
            "10.0.0.5:8001",
            "[::ffff:0.0.0.0]:8002",
        ]))
        .unwrap();

        assert_eq!(
            published,
            [
                "10.0.0.5:8001".parse::<SocketAddr>().unwrap(),
                "0.0.0.0:8002".parse().unwrap()
            ]
        );
    }

    #[test]
    fn other_publish_entries_pass_as_written() {
        let entries = [
            "127.0.0.1:8001",
            "[::1]:8001",
            "[::]:8002",
            "[2001:db8::1]:80",
        ];

        let published = resolve_publish(&publishing(&entries)).unwrap();

        assert_eq!(
            published,
            entries.map(|entry| entry.parse::<SocketAddr>().unwrap())
        );
    }

    /// A started sandbox that publishes `addresses`. They are set after the
    /// start, since a settings file refuses port 0, which these cases need to
    /// bind a port nothing else holds.
    fn started_publishing(addresses: &[&str]) -> Option<Sandbox> {
        let mut sandbox = match Sandbox::start(&Config::default()) {
            Ok(sandbox) => sandbox,
            // The machine has no bwrap to wrap a command in.
            Err(StartError::Missing { .. } | StartError::Uid0WithoutSetfcap) => return None,
            Err(error) => panic!("{error}"),
        };
        sandbox.publish = addresses.iter().map(|text| text.parse().unwrap()).collect();
        Some(sandbox)
    }

    fn init_of(wrapped: &Command) -> Vec<OsString> {
        wrapped
            .get_args()
            .skip_while(|arg| *arg != HELPER_FLAG)
            .map(OsString::from)
            .collect()
    }

    #[test]
    fn the_helper_learns_the_publish_descriptor_and_nothing_extra_for_loopback_or_wildcards() {
        let Some(sandbox) =
            started_publishing(&["127.0.0.1:0", "0.0.0.0:0", "[::]:0", "127.0.0.2:0"])
        else {
            return;
        };
        let wrapped = sandbox
            .linux_command(&Command::new("true"), None, &[])
            .unwrap();
        let args = init_of(&wrapped);
        let helper = crate::args::parse_helper(args).unwrap().unwrap();
        let init = crate::args::parse_init(&helper.args).unwrap();

        assert_eq!(init.publish_fd, Some(crabpot_linux::wrap::PUBLISH_FD));
        // Loopback and wildcard addresses need nothing added to `lo`.
        assert_eq!(init.loopback, Vec::<IpAddr>::new());
    }

    #[test]
    fn a_published_address_that_is_not_loopback_goes_to_the_helper_once() {
        let Some(sandbox) = started_publishing(&[]) else {
            return;
        };
        let mut sandbox = sandbox;
        sandbox.publish = vec![
            "10.9.9.9:80".parse().unwrap(),
            "10.9.9.9:81".parse().unwrap(),
            "10.9.9.8:80".parse().unwrap(),
        ];
        let have = ["10.9.9.8".parse().unwrap()];

        let addresses = sandbox.published_addresses(&have);

        assert_eq!(addresses, ["10.9.9.9".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn a_sandbox_without_published_addresses_passes_no_descriptor() {
        let Some(sandbox) = started_publishing(&[]) else {
            return;
        };
        let wrapped = sandbox
            .linux_command(&Command::new("true"), None, &[])
            .unwrap();
        let helper = crate::args::parse_helper(init_of(&wrapped))
            .unwrap()
            .unwrap();

        assert_eq!(
            crate::args::parse_init(&helper.args).unwrap().publish_fd,
            None
        );
    }

    #[test]
    fn a_published_address_the_host_cannot_bind_refuses_the_command_naming_it() {
        let Some(sandbox) = started_publishing(&["127.0.0.1:0"]) else {
            return;
        };
        let mut sandbox = sandbox;
        // A plain listener holds its port without `SO_REUSEPORT`.
        let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = held.local_addr().unwrap();
        sandbox.publish = vec![address];

        let error = sandbox.command(&Command::new("true")).unwrap_err();

        assert!(matches!(error, WrapError::Publish(_)), "{error}");
        assert!(error.to_string().contains(&address.to_string()), "{error}");
    }

    #[test]
    fn a_command_is_wrapped_in_bwrap() {
        let sandbox = match Sandbox::start(&Config::default()) {
            Ok(sandbox) => sandbox,
            // The machine has no bwrap to wrap a command in.
            Err(StartError::Missing { .. } | StartError::Uid0WithoutSetfcap) => return,
            Err(error) => panic!("{error}"),
        };
        let mut echo = Command::new("echo");
        echo.arg("hello").env("CALLER", "kept").current_dir("/");

        let wrapped = sandbox.command(&echo).unwrap();

        assert!(wrapped.get_program().to_string_lossy().ends_with("bwrap"));
        let args: Vec<_> = wrapped
            .get_args()
            .map(|arg| arg.to_string_lossy())
            .collect();
        assert_eq!(args[..3], ["--ro-bind", "/", "/"]);
        let helper = std::env::current_exe().unwrap();
        let helper = helper.to_string_lossy();
        let socket = sandbox.proxy.mux_socket().to_string_lossy();
        assert_eq!(
            args[args.len() - 9..],
            [
                "--",
                &*helper,
                "--crabpot-helper",
                "init",
                "--relay",
                &*socket,
                "--",
                "echo",
                "hello"
            ][..]
        );
        assert!(
            args.windows(3)
                .any(|run| run == ["--bind", &*socket, &*socket]),
            "the proxy's socket is bound into the sandbox: {args:?}"
        );
        assert!(
            args.iter().any(|arg| arg == "--unshare-net"),
            "the network stays unshared: {args:?}"
        );
        assert_eq!(wrapped.get_current_dir(), Some(std::path::Path::new("/")));
        assert!(wrapped.get_envs().any(|(name, value)| {
            name == "CALLER" && value.is_some_and(|value| value == "kept")
        }));
    }

    #[test]
    fn a_wrapped_command_gains_the_sandbox_environment() {
        let sandbox = match Sandbox::start(&Config::default()) {
            Ok(sandbox) => sandbox,
            // The machine has no bwrap to wrap a command in.
            Err(StartError::Missing { .. } | StartError::Uid0WithoutSetfcap) => return,
            Err(error) => panic!("{error}"),
        };
        let mut echo = Command::new("echo");
        echo.arg("hello").env("TMPDIR", "/caller/tmp");

        let wrapped = sandbox.command(&echo).unwrap();
        let last = |name: &str| {
            wrapped
                .get_envs()
                .filter(|(key, _)| *key == name)
                .last()
                .and_then(|(_, value)| value)
                .map(|value| value.to_string_lossy().into_owned())
        };

        assert_eq!(last("SANDBOX_RUNTIME").as_deref(), Some("1"));
        let tmpdir = last("TMPDIR");
        assert!(tmpdir.is_some(), "the sandbox sets TMPDIR: {tmpdir:?}");
        assert_ne!(
            tmpdir.as_deref(),
            Some("/caller/tmp"),
            "the sandbox's TMPDIR is set over the caller's: {tmpdir:?}"
        );
    }

    #[test]
    fn a_wrapped_command_is_pointed_at_the_relays_and_the_token_stays_out_of_argv() {
        let sandbox = match Sandbox::start(&Config::default()) {
            Ok(sandbox) => sandbox,
            // The machine has no bwrap to wrap a command in.
            Err(StartError::Missing { .. } | StartError::Uid0WithoutSetfcap) => return,
            Err(error) => panic!("{error}"),
        };

        let wrapped = sandbox.command(&Command::new("true")).unwrap();
        let env = |name: &str| {
            wrapped
                .get_envs()
                .find(|(key, _)| *key == name)
                .and_then(|(_, value)| value)
                .map(|value| value.to_string_lossy().into_owned())
                .unwrap_or_else(|| panic!("{name} is not set"))
        };

        let token = sandbox.proxy.token();
        assert!(env("HTTPS_PROXY").ends_with("@localhost:3128"));
        assert!(env("HTTPS_PROXY").contains(token));
        assert!(env("FTP_PROXY").ends_with("@localhost:1080"));
        assert_eq!(
            env("CLAUDE_CODE_HOST_HTTP_PROXY_PORT"),
            sandbox.proxy.port().to_string()
        );

        let helper = std::env::current_exe().unwrap();
        let ssh = env("GIT_SSH_COMMAND");
        assert!(
            ssh.contains("--crabpot-helper connect 3128") && ssh.contains("SRT_SSH_PROXY_BINARY"),
            "git's ssh is told to ask this binary for the tunnel: {ssh}"
        );
        assert_eq!(
            env(crabpot_linux::net::ssh::BINARY_VARIABLE),
            helper.to_string_lossy().into_owned(),
            "the binary the command expands, on the environment and not in a word \
             git's shell reads"
        );
        assert!(
            !ssh.contains(token),
            "the credential is not in a command line: {ssh}"
        );
        assert!(
            !env("SRT_SSH_PROXY_CREDENTIAL").is_empty(),
            "the credential rides in a variable of its own"
        );

        assert!(
            wrapped
                .get_args()
                .all(|arg| !arg.to_string_lossy().contains(token)),
            "bwrap's argv is readable from /proc: {wrapped:?}"
        );
    }
}
