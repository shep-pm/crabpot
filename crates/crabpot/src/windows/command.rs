//! The command a Windows host spawns in place of the one it was given: this
//! binary again as `srt-win exec`, which launches the command as the sandbox
//! user in two hops (upstream's `wrapCommandWithSandboxWindows`,
//! `src/sandbox/windows-sandbox-utils.ts`).

use std::borrow::Cow;
use std::ffi::OsStr;
use std::path::Path;
use std::process::Command;

use crabpot_core::proxy::username_for;
use crabpot_windows::env::{Facts, vars};

use crate::args::SRT_WIN_FLAG;
use crate::sandbox::{WrapError, command_line};

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
///
/// # Errors
///
/// [`WrapError::Cmd`] when a word of `command` cannot be put on a `cmd.exe`
/// line as itself.
pub(crate) fn wrap(params: &Params<'_>, command: &Command) -> Result<Command, WrapError> {
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
    wrapped.args(["--", &shell(), "/d", "/s", "/c", &line_of(command)?]);
    if let Some(dir) = command.get_current_dir() {
        wrapped.current_dir(dir);
    }
    Ok(wrapped)
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
        path: carried(command, "PATH"),
        pathext: carried(command, "PATHEXT"),
    };
    let username = username_for(&command_line(command));
    overlay.extend(vars(&facts, &username, params.token));
    overlay
}

/// What the command sees as `name`: the caller's value or removal when the
/// caller changed it, else this process's.
fn carried(command: &Command, name: &str) -> Option<String> {
    let changed = command
        .get_envs()
        .find(|(key, _)| key.to_string_lossy().eq_ignore_ascii_case(name));
    match changed {
        Some((_, value)) => value.map(|value| value.to_string_lossy().into_owned()),
        None => std::env::var(name).ok(),
    }
}

/// The shell the command line runs in: `cmd.exe` of the system folder.
fn shell() -> String {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
    format!(r"{root}\System32\cmd.exe")
}

/// The words of `command` as one `cmd.exe` line, each in quotes when `cmd.exe`
/// or the program would read it as more than itself.
fn line_of(command: &Command) -> Result<String, WrapError> {
    let words = core::iter::once(command.get_program()).chain(command.get_args());
    let mut quoted = Vec::new();
    for word in words {
        quoted.push(quote(word)?);
    }
    Ok(quoted.join(" "))
}

/// `word` as one word of a `cmd.exe` line. A word with a character `cmd.exe`
/// acts on, whitespace, or no characters is in quotes, with the backslashes
/// before the closing quote doubled for the program's own parse.
///
/// A word that is not valid Unicode is refused, since the line is text.
///
/// A double quote, a percent sign and a line break cannot be made literal:
/// `cmd.exe` expands `%name%` and ends a quote at `"` whatever escapes the
/// program would read, so a word with one is refused.
fn quote(word: &OsStr) -> Result<Cow<'_, str>, WrapError> {
    const SPECIAL: &str = "&|<>^()!,;=";
    let Some(text) = word.to_str() else {
        return Err(WrapError::Cmd(format!(
            "{word:?} is not valid Unicode, which a cmd.exe line cannot carry as it is"
        )));
    };
    if let Some(bad) = text
        .chars()
        .find(|c| matches!(c, '"' | '%' | '\r' | '\n' | '\0'))
    {
        return Err(WrapError::Cmd(format!(
            "{text:?} has {bad:?}, which cmd.exe would not read as part of a word"
        )));
    }
    if !text.is_empty() && !text.contains(|c: char| c.is_whitespace() || SPECIAL.contains(c)) {
        return Ok(Cow::Borrowed(text));
    }
    let trailing = text.len() - text.trim_end_matches('\\').len();
    Ok(Cow::Owned(format!("\"{text}{}\"", "\\".repeat(trailing))))
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
        let wrapped = wrap(&params(&[], false), &echo()).unwrap();
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
        let closed = args_of(&wrap(&params(&[], false), &echo()).unwrap());
        let open = args_of(&wrap(&params(&[], true), &echo()).unwrap());

        assert!(!closed.iter().any(|arg| arg == "--allow-loopback"));
        assert!(open.iter().any(|arg| arg == "--allow-loopback"));
    }

    #[test]
    fn each_write_root_is_a_flag_of_its_own() {
        let roots = [r"C:\work".to_owned(), r"D:\scratch".to_owned()];
        let args = args_of(&wrap(&params(&roots, false), &echo()).unwrap());

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
        let args = args_of(&wrap(&params(&[], false), &command).unwrap());

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
        let args = args_of(&wrap(&params(&[], false), &command).unwrap());

        assert_eq!(
            args.last().unwrap(),
            r#""C:\Program Files\tool.exe" plain "two words""#
        );
    }

    #[test]
    fn the_callers_working_directory_is_kept() {
        let mut command = echo();
        command.current_dir(r"C:\work");

        let wrapped = wrap(&params(&[], false), &command).unwrap();

        assert_eq!(wrapped.get_current_dir(), Some(Path::new(r"C:\work")));
    }

    fn line(words: &[&str]) -> Result<String, WrapError> {
        let mut command = Command::new(words[0]);
        command.args(&words[1..]);
        line_of(&command)
    }

    #[test]
    fn a_word_cmd_would_act_on_is_quoted_so_it_stays_one_argument() {
        assert_eq!(
            line(&["tool.exe", "a&whoami", "x|y", "(z)", "a>b", "c^d"]).unwrap(),
            r#"tool.exe "a&whoami" "x|y" "(z)" "a>b" "c^d""#
        );
        assert_eq!(line(&["tool.exe", ""]).unwrap(), r#"tool.exe """#);
    }

    #[test]
    fn backslashes_before_the_closing_quote_are_doubled() {
        assert_eq!(
            line(&["tool.exe", r"C:\my dir\"]).unwrap(),
            r#"tool.exe "C:\my dir\\""#
        );
        assert_eq!(
            line(&["tool.exe", r"C:\plain\"]).unwrap(),
            r"tool.exe C:\plain\"
        );
    }

    #[test]
    fn a_word_that_cannot_be_literal_is_refused() {
        for word in [r#"say "hi""#, "%PATH%", "a\nb", "a\rb"] {
            let error = line(&["tool.exe", word]).unwrap_err();
            assert!(matches!(error, WrapError::Cmd(_)), "{word:?}: {error:?}");
        }
        assert!(line(&["to%ol.exe"]).is_err());
    }

    #[test]
    fn a_word_that_is_not_unicode_is_refused() {
        #[cfg(windows)]
        let word = std::os::windows::ffi::OsStringExt::from_wide(&[0xD800]);
        #[cfg(unix)]
        let word = std::os::unix::ffi::OsStringExt::from_vec(vec![0xff]);
        let mut command = echo();
        command.arg::<std::ffi::OsString>(word);

        assert!(matches!(line_of(&command), Err(WrapError::Cmd(_))));
    }

    #[test]
    fn a_callers_path_and_pathext_win_over_this_processs() {
        let mut command = echo();
        command.env("Path", r"C:\tools").env_remove("PATHEXT");
        let args = args_of(&wrap(&params(&[], false), &command).unwrap());

        let paths: Vec<&String> = args
            .iter()
            .filter(|arg| arg.to_lowercase().starts_with("path="))
            .collect();
        assert!(
            paths.iter().all(|arg| arg.ends_with(r"=C:\tools")),
            "{paths:?}"
        );
        assert!(!paths.is_empty());
        assert!(
            !args
                .iter()
                .any(|arg| arg.to_lowercase().starts_with("pathext="))
        );
    }
}
