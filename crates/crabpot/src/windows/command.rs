//! The command a Windows host spawns in place of the one it was given: this
//! binary again as `srt-win exec`, which launches the command as the sandbox
//! user in two hops (upstream's `wrapCommandWithSandboxWindows`,
//! `src/sandbox/windows-sandbox-utils.ts`).

use std::path::Path;
use std::process::Command;

use crabpot_core::proxy::username_for;
use crabpot_windows::env::{Facts, vars};

use crate::args::SRT_WIN_FLAG;
use crate::sandbox::command_line;

/// What a session tells every command it wraps.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Params<'a> {
    /// This binary, which runs as srt-win.
    pub(crate) exe: &'a Path,
    /// The process whose session the command belongs to.
    pub(crate) held_by: u32,
    /// The roots the session granted write on.
    pub(crate) write_roots: &'a [String],
    /// Whether the fence leaves loopback open for the command.
    pub(crate) allow_loopback: bool,
    /// The port both proxies answer on.
    pub(crate) proxy_port: u16,
    /// The credential a client of either proxy presents.
    pub(crate) token: &'a str,
}

/// `command`, wrapped to run through `srt-win exec`.
///
/// The command runs as `cmd.exe /d /s /c <line>`: srt-win puts the line in the
/// one pair of quotes `/s` strips and passes it on as written. The sandbox
/// user's own profile environment is the command's, with the overlay of
/// `--env` pairs on it: the caller's changes, then the sandbox's own, which win.
pub(crate) fn wrap(params: &Params<'_>, command: &Command) -> Command {
    let mut wrapped = Command::new(params.exe);
    wrapped
        .arg(SRT_WIN_FLAG)
        .args(["exec", "--quiet", "--held-by"])
        .arg(params.held_by.to_string())
        .arg("--write-restricted-token");
    for root in params.write_roots {
        wrapped.arg("--write-root").arg(root);
    }
    if params.allow_loopback {
        wrapped.arg("--allow-loopback");
    }
    for (name, value) in overlay(params, command) {
        wrapped.arg("--env").arg(format!("{name}={value}"));
    }
    wrapped.args(["--", &shell(), "/d", "/s", "/c", &line_of(command)]);
    if let Some(dir) = command.get_current_dir() {
        wrapped.current_dir(dir);
    }
    wrapped
}

/// The variables the command gets, name and value, the caller's first.
fn overlay(params: &Params<'_>, command: &Command) -> Vec<(String, String)> {
    let mut overlay: Vec<(String, String)> = command
        .get_envs()
        .filter_map(|(name, value)| {
            Some((
                name.to_string_lossy().into_owned(),
                value?.to_string_lossy().into_owned(),
            ))
        })
        .collect();
    let cwd = command
        .get_current_dir()
        .map(Path::to_path_buf)
        .or_else(|| std::env::current_dir().ok());
    let facts = Facts {
        allow_loopback: params.allow_loopback,
        http_proxy_port: Some(params.proxy_port),
        socks_proxy_port: Some(params.proxy_port),
        ca_cert_path: None,
        safe_dirs: cwd
            .iter()
            .filter_map(|dir| dir.to_str())
            .chain(params.write_roots.iter().map(String::as_str))
            .map(str::to_owned)
            .collect(),
        path: std::env::var("PATH").ok(),
        pathext: std::env::var("PATHEXT").ok(),
    };
    let username = username_for(&command_line(command));
    overlay.extend(vars(&facts, &username, params.token));
    overlay
}

/// The shell the command line runs in: `cmd.exe` of the system folder.
fn shell() -> String {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
    format!(r"{root}\System32\cmd.exe")
}

/// The words of `command` as one `cmd.exe` line: a word with whitespace in it,
/// or no characters, is in quotes.
fn line_of(command: &Command) -> String {
    core::iter::once(command.get_program())
        .chain(command.get_args())
        .map(|word| word.to_string_lossy())
        .map(|word| {
            if word.is_empty() || word.contains(char::is_whitespace) {
                format!("\"{word}\"")
            } else {
                word.into_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXE: &str = r"C:\crabpot\crabpot.exe";

    fn params<'a>(write_roots: &'a [String], allow_loopback: bool) -> Params<'a> {
        Params {
            exe: Path::new(EXE),
            held_by: 4242,
            write_roots,
            allow_loopback,
            proxy_port: 60080,
            token: "tok",
        }
    }

    fn args_of(command: &Command) -> Vec<String> {
        command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    fn echo() -> Command {
        let mut echo = Command::new("echo");
        echo.arg("hello");
        echo
    }

    #[test]
    fn the_command_line_carries_held_by_and_the_restricted_token() {
        let wrapped = wrap(&params(&[], false), &echo());
        let args = args_of(&wrapped);

        assert_eq!(wrapped.get_program(), EXE);
        assert_eq!(
            args[..6],
            [
                "--srt-win",
                "exec",
                "--quiet",
                "--held-by",
                "4242",
                "--write-restricted-token"
            ]
        );
        let split = args.iter().position(|arg| arg == "--").unwrap();
        let [shell, flags @ .., line] = &args[split + 1..] else {
            panic!("the shell and its line follow the separator: {args:?}");
        };
        assert!(
            shell.to_lowercase().ends_with(r"system32\cmd.exe"),
            "{shell}"
        );
        assert_eq!(flags, ["/d", "/s", "/c"]);
        assert_eq!(line, "echo hello");
    }

    #[test]
    fn loopback_adds_allow_loopback() {
        let closed = args_of(&wrap(&params(&[], false), &echo()));
        let open = args_of(&wrap(&params(&[], true), &echo()));

        assert!(!closed.iter().any(|arg| arg == "--allow-loopback"));
        assert!(open.iter().any(|arg| arg == "--allow-loopback"));
    }

    #[test]
    fn each_write_root_is_a_flag_of_its_own() {
        let roots = [r"C:\work".to_owned(), r"D:\scratch".to_owned()];
        let args = args_of(&wrap(&params(&roots, false), &echo()));

        let at = args.iter().position(|arg| arg == "--write-root").unwrap();
        assert_eq!(
            args[at..at + 4],
            ["--write-root", r"C:\work", "--write-root", r"D:\scratch"]
        );
    }

    #[test]
    fn the_overlay_points_the_command_at_the_proxy_and_carries_its_own_variables() {
        let mut command = echo();
        command.env("CALLER", "kept");
        let args = args_of(&wrap(&params(&[], false), &command));

        let overlay: Vec<&str> = args
            .windows(2)
            .filter(|pair| pair[0] == "--env")
            .map(|pair| pair[1].as_str())
            .collect();
        assert!(overlay.contains(&"CALLER=kept"), "{overlay:?}");
        let proxy = overlay
            .iter()
            .find_map(|pair| pair.strip_prefix("https_proxy="))
            .expect("https_proxy is in the overlay");
        assert!(proxy.ends_with(":tok@localhost:60080"), "{proxy}");
    }

    #[test]
    fn a_word_with_a_space_is_quoted_in_the_line() {
        let mut command = Command::new(r"C:\Program Files\tool.exe");
        command.arg("plain").arg("two words");
        let args = args_of(&wrap(&params(&[], false), &command));

        assert_eq!(
            args.last().unwrap(),
            r#""C:\Program Files\tool.exe" plain "two words""#
        );
    }

    #[test]
    fn the_callers_working_directory_is_kept() {
        let mut command = echo();
        command.current_dir(r"C:\work");

        let wrapped = wrap(&params(&[], false), &command);

        assert_eq!(wrapped.get_current_dir(), Some(Path::new(r"C:\work")));
    }
}
