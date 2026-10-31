//! Linux command wrapping and helper options

use std::ffi::OsString;
use std::net::IpAddr;
use std::process::Command;
use std::sync::PoisonError;

use crabpot_core::proxy::username_for;
use crabpot_linux::info::Info;
use crabpot_linux::net::env::HostPorts;
use crabpot_linux::startup::Startup;

use crate::args::{HELPER_FLAG, HelperMode, LOOPBACK_FLAG, RELAY_FLAG, REPORT_STARTED_FLAG};

use super::{Sandbox, WrapError, carry_over, command_line};

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
        let mut wrapped = self.linux_command(command, true, &[])?;
        let info = crabpot_linux::info::attach(&mut wrapped)
            .map_err(|e| WrapError::Bwrap(e.to_string()))?;
        let startup = crabpot_linux::startup::attach(&mut wrapped)
            .map_err(|e| WrapError::Bwrap(e.to_string()))?;
        Ok((wrapped, info, startup))
    }

    pub(super) fn linux_command(
        &self,
        command: &Command,
        report: bool,
        loopback: &[IpAddr],
    ) -> Result<Command, WrapError> {
        let mut words = vec![
            self.helper.clone().into_os_string(),
            OsString::from(HELPER_FLAG),
            OsString::from(HelperMode::Init.word()),
            OsString::from(RELAY_FLAG),
            self.proxy.mux_socket().as_os_str().to_owned(),
        ];
        if report {
            words.push(OsString::from(REPORT_STARTED_FLAG));
        }
        for address in loopback {
            words.extend([OsString::from(LOOPBACK_FLAG), address.to_string().into()]);
        }
        words.push(OsString::from("--"));
        words.push(command.get_program().to_owned());
        words.extend(command.get_args().map(OsString::from));
        let mut bwrap_words = self.words.clone();
        if report {
            bwrap_words.splice(1..1, crabpot_linux::wrap::info_words());
        }
        let rendered = crabpot_linux::argv::render(&bwrap_words, &words, &std::env::temp_dir())
            .map_err(|e| WrapError::Bwrap(e.to_string()))?;
        let mut wrapped = rendered.command;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::StartError;
    use crabpot_core::config::Config;

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
        let wrapped = sandbox.linux_command(&command, false, &addresses).unwrap();
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
