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
use crate::windows::resolve::executable;

/// What Windows allows a command line, in characters (`CreateProcessW`).
const COMMAND_LINE_LIMIT: usize = 32_767;

/// What a word costs on the line beyond its characters: a pair of quotes and
/// a space.
const QUOTES_AND_SPACE: usize = 3;

/// What a session tells every command it wraps.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Params<'a> {
    /// This binary, which runs as srt-win.
    pub(crate) exe: &'a Path,
    /// The process whose session the command belongs to.
    pub(crate) held_by: u32,
    /// The roots the session granted write on.
    pub(crate) write_roots: &'a [String],
    /// The config's `git.safeDirectories`, which git is told are safe and
    /// which are granted no write.
    pub(crate) git_safe_directories: &'a [String],
    /// Whether the fence leaves loopback open for the command.
    pub(crate) allow_loopback: bool,
    /// The port both proxies answer on.
    pub(crate) proxy_port: u16,
    /// The credential a client of either proxy presents.
    pub(crate) token: &'a str,
}

/// `command`, wrapped to run through `srt-win exec`.
///
/// A program that resolves to a `.exe` or `.com` file runs as itself, with its
/// arguments as given: srt-win quotes them so the program reads them back
/// unchanged. Any other program runs as `cmd.exe /d /s /c <line>`: srt-win puts
/// the line in the one pair of quotes `/s` strips and passes it on as written.
/// The sandbox user's own profile environment is the command's, with the
/// overlay of `--env` pairs on it: the caller's changes, then the sandbox's own,
/// which win and which the caller's of the same name, whatever its case, give
/// way to.
///
/// # Errors
///
/// [`WrapError::Cmd`] when `command` runs through `cmd.exe` and a word of it
/// cannot be put on the line as itself, or the overlay makes the line longer
/// than Windows spawns.
pub(crate) fn wrap(params: &Params<'_>, command: &Command) -> Result<Command, WrapError> {
    wrap_with(params, command, &|path| path.is_file())
}

/// [`wrap`] with `is_file` as the lookup of a file on disk.
fn wrap_with(
    params: &Params<'_>,
    command: &Command,
    is_file: &dyn Fn(&Path) -> bool,
) -> Result<Command, WrapError> {
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
    let overlay = overlay(params, command);
    for (name, value) in &overlay {
        wrapped.arg("--env").arg(format!("{name}={value}"));
    }
    let program = command.get_program().to_str();
    let path = carried(command, "PATH");
    match program.and_then(|program| executable(program, path.as_deref(), is_file)) {
        Some(program) => {
            wrapped.arg("--").arg(program).args(command.get_args());
        }
        None => {
            wrapped.args(["--", &shell(), "/d", "/s", "/c", &line_of(command)?]);
        }
    }
    check_length(&wrapped, &overlay)?;
    if let Some(dir) = command.get_current_dir() {
        wrapped.current_dir(dir);
    }
    Ok(wrapped)
}

/// Refuses a `wrapped` command line that Windows cannot spawn, by the largest
/// of the `overlay` variables, which is what makes a line long.
fn check_length(wrapped: &Command, overlay: &[(String, String)]) -> Result<(), WrapError> {
    let length: usize = core::iter::once(wrapped.get_program())
        .chain(wrapped.get_args())
        .map(|word| word.to_string_lossy().encode_utf16().count() + QUOTES_AND_SPACE)
        .sum();
    if length <= COMMAND_LINE_LIMIT {
        return Ok(());
    }
    let largest = overlay
        .iter()
        .max_by_key(|(name, value)| name.len() + value.len())
        .map_or("", |(name, _)| name.as_str());
    Err(WrapError::Cmd(format!(
        "the environment makes the srt-win command line {length} characters, over the \
         {COMMAND_LINE_LIMIT} Windows allows; the largest variable is {largest}"
    )))
}

/// The variables the command gets, name and value: the caller's that the
/// sandbox does not set, then the sandbox's own.
fn overlay(params: &Params<'_>, command: &Command) -> Vec<(String, String)> {
    let changes: Vec<(String, String)> = command
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
            .chain(params.git_safe_directories.iter().map(String::as_str))
            .map(str::to_owned)
            .collect(),
        // The host's own never reaches the child, which starts from the sandbox
        // user's profile: the count is the one the caller sets.
        git_config_count: changes
            .iter()
            .rev()
            .find(|(name, _)| name.eq_ignore_ascii_case("GIT_CONFIG_COUNT"))
            .map(|(_, value)| value.clone()),
        path: carried(command, "PATH"),
        pathext: carried(command, "PATHEXT"),
    };
    let username = username_for(&command_line(command));
    let own = vars(&facts, &username, params.token);
    let mut overlay: Vec<(String, String)> = changes
        .into_iter()
        .filter(|(name, _)| !own.iter().any(|(set, _)| set.eq_ignore_ascii_case(name)))
        .collect();
    overlay.extend(own);
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
            git_safe_directories: &[],
            allow_loopback,
            proxy_port: 60080,
            token: "tok",
        }
    }

    fn wrap_over(
        is_file: &dyn Fn(&str) -> bool,
        params: &Params<'_>,
        command: &Command,
    ) -> Result<Command, WrapError> {
        wrap_with(params, command, &|path| {
            path.to_str()
                .is_some_and(|path| is_file(&path.to_lowercase()))
        })
    }

    fn wrap_bare(params: &Params<'_>, command: &Command) -> Result<Command, WrapError> {
        wrap_over(&|_| false, params, command)
    }

    fn after_separator(wrapped: &Command) -> Vec<String> {
        let args = args_of(wrapped);
        let split = args.iter().position(|arg| arg == "--").unwrap();
        args[split + 1..].to_vec()
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
        let wrapped = wrap_bare(&params(&[], false), &echo()).unwrap();
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
    fn every_command_carries_the_write_restricted_token() {
        let roots = [r"C:\work".to_owned()];
        for (roots, allow_loopback) in [(&[][..], false), (&roots[..], false), (&roots[..], true)] {
            let args = args_of(&wrap_bare(&params(roots, allow_loopback), &echo()).unwrap());

            let split = args.iter().position(|arg| arg == "--").unwrap();
            let count = args[..split]
                .iter()
                .filter(|arg| *arg == "--write-restricted-token")
                .count();
            assert_eq!(count, 1, "{args:?}");
        }
    }

    #[test]
    fn loopback_adds_allow_loopback() {
        let closed = args_of(&wrap_bare(&params(&[], false), &echo()).unwrap());
        let open = args_of(&wrap_bare(&params(&[], true), &echo()).unwrap());

        assert!(!closed.iter().any(|arg| arg == "--allow-loopback"));
        assert!(open.iter().any(|arg| arg == "--allow-loopback"));
    }

    #[test]
    fn each_write_root_is_a_flag_of_its_own() {
        let roots = [r"C:\work".to_owned(), r"D:\scratch".to_owned()];
        let args = args_of(&wrap_bare(&params(&roots, false), &echo()).unwrap());

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
        let args = args_of(&wrap_bare(&params(&[], false), &command).unwrap());

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

    fn overlay_of(command: &Command) -> Vec<String> {
        let args = args_of(&wrap(&params(&[], false), command).unwrap());
        args.windows(2)
            .filter(|pair| pair[0] == "--env")
            .map(|pair| pair[1].clone())
            .collect()
    }

    fn git_values(overlay: &[String]) -> Vec<&str> {
        overlay
            .iter()
            .filter_map(|pair| {
                let (name, value) = pair.split_once('=')?;
                name.starts_with("GIT_CONFIG_VALUE_").then_some(value)
            })
            .collect()
    }

    #[test]
    fn a_configured_safe_directory_joins_the_working_directory() {
        let roots = [r"C:\root".to_owned()];
        let safe = [r"D:\shared\.git".to_owned()];
        let params = Params {
            git_safe_directories: &safe,
            ..params(&roots, false)
        };
        let mut command = echo();
        command.current_dir(r"C:\work");

        let args = args_of(&wrap(&params, &command).unwrap());
        let overlay: Vec<String> = args
            .windows(2)
            .filter(|pair| pair[0] == "--env")
            .map(|pair| pair[1].clone())
            .collect();

        assert_eq!(
            git_values(&overlay),
            [
                "C:/work",
                "C:/work/*",
                "C:/root",
                "C:/root/*",
                "D:/shared/.git",
                "D:/shared/.git/*",
                "openssl"
            ],
            "the working directory, the write roots, then the config's list"
        );
        assert!(
            !args.iter().any(|arg| arg == r"D:\shared\.git"),
            "a safe directory is granted no write root: {args:?}"
        );
    }

    #[test]
    fn the_numbering_continues_from_the_count_the_caller_sets() {
        let mut command = echo();
        command.current_dir(r"C:\work").env("GIT_CONFIG_COUNT", "2");
        let overlay = overlay_of(&command);

        assert!(
            overlay.contains(&"GIT_CONFIG_KEY_2=safe.directory".to_owned()),
            "{overlay:?}"
        );
        assert!(
            overlay.contains(&"GIT_CONFIG_COUNT=5".to_owned()),
            "{overlay:?}"
        );
        assert_eq!(
            overlay
                .iter()
                .filter(|pair| pair.starts_with("GIT_CONFIG_COUNT="))
                .count(),
            1,
            "the caller's count gives way to the new total: {overlay:?}"
        );

        command.env("GIT_CONFIG_COUNT", "0");
        let overlay = overlay_of(&command);
        assert_eq!(git_values(&overlay), [] as [&str; 0], "{overlay:?}");
        assert!(
            overlay.contains(&"GIT_CONFIG_COUNT=0".to_owned()),
            "the caller's opt-out stays: {overlay:?}"
        );
    }

    #[test]
    fn a_variable_the_sandbox_sets_is_on_the_line_once_whatever_its_case() {
        let mut command = echo();
        command.env("Path", r"C:\host").env("SANDBOX_RUNTIME", "no");
        let overlay = overlay_of(&command);

        for name in ["path", "sandbox_runtime"] {
            let count = overlay
                .iter()
                .filter(|pair| {
                    pair.split('=')
                        .next()
                        .is_some_and(|key| key.eq_ignore_ascii_case(name))
                })
                .count();
            assert_eq!(count, 1, "{name}: {overlay:?}");
        }
        assert!(!overlay.contains(&"SANDBOX_RUNTIME=no".to_owned()));
    }

    #[test]
    fn an_environment_too_long_for_a_command_line_is_refused_by_name() {
        let mut command = echo();
        command.env("BIG", "x".repeat(33_000));

        let Err(WrapError::Cmd(reason)) = wrap(&params(&[], false), &command) else {
            panic!("a 33000 character variable is refused");
        };
        assert!(reason.contains("BIG"), "{reason}");
    }

    #[test]
    fn a_word_with_a_space_is_quoted_in_the_line() {
        let mut command = Command::new(r"C:\Program Files\tool.exe");
        command.arg("plain").arg("two words");
        let args = args_of(&wrap_bare(&params(&[], false), &command).unwrap());

        assert_eq!(
            args.last().unwrap(),
            r#""C:\Program Files\tool.exe" plain "two words""#
        );
    }

    fn last_arg(words: &[&str]) -> String {
        let mut command = Command::new(words[0]);
        command.args(&words[1..]);
        args_of(&wrap_bare(&params(&[], false), &command).unwrap())
            .pop()
            .unwrap()
    }

    #[test]
    fn a_backslash_argument_is_not_quoted() {
        assert_eq!(
            last_arg(&["tool.exe", r"C:\work\out.txt", r"\\host\share", r"C:\work\"]),
            r"tool.exe C:\work\out.txt \\host\share C:\work\"
        );
    }

    #[test]
    fn an_argument_with_spaces_stays_one_word() {
        assert_eq!(
            last_arg(&["tool.exe", r"C:\my dir\out.txt", "two words"]),
            r#"tool.exe "C:\my dir\out.txt" "two words""#
        );
    }

    #[test]
    fn the_callers_working_directory_is_kept() {
        let mut command = echo();
        command.current_dir(r"C:\work");

        let wrapped = wrap_bare(&params(&[], false), &command).unwrap();

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
        let args = args_of(&wrap_bare(&params(&[], false), &command).unwrap());

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

    #[test]
    fn an_executable_runs_without_cmd_and_keeps_every_argument() {
        let mut command = Command::new(r"C:\tools\env.exe");
        command.arg("a\nb \"c\" %PATH%");

        let wrapped = wrap_over(
            &|path| path == r"c:\tools\env.exe",
            &params(&[], false),
            &command,
        )
        .unwrap();

        assert_eq!(
            after_separator(&wrapped),
            [r"C:\tools\env.exe", "a\nb \"c\" %PATH%"]
        );
    }

    #[test]
    fn a_bare_name_on_the_commands_path_runs_as_that_executable() {
        let mut command = Command::new("env");
        command.env("Path", r"C:\mine;C:\other").arg("a\nb");

        let wrapped = wrap_over(
            &|path| path.ends_with(r"\env.exe"),
            &params(&[], false),
            &command,
        )
        .unwrap();

        assert_eq!(after_separator(&wrapped), [r"C:\mine\env.exe", "a\nb"]);
    }

    #[test]
    fn a_command_without_a_path_is_not_looked_up_on_this_processs() {
        let mut command = Command::new("env");
        command.env_remove("PATH").arg("a\nb");

        let error = wrap_over(
            &|path| path.ends_with(r"\env.exe"),
            &params(&[], false),
            &command,
        )
        .unwrap_err();

        assert!(matches!(error, WrapError::Cmd(_)), "{error:?}");
    }

    #[test]
    fn a_batch_file_still_runs_through_cmd_and_refuses_a_line_break() {
        let on_disk = |path: &str| path == r"c:\tools\run.bat";
        let plain = wrap_over(
            &on_disk,
            &params(&[], false),
            Command::new(r"C:\tools\run.bat").arg("one"),
        )
        .unwrap();
        let broken = wrap_over(
            &on_disk,
            &params(&[], false),
            Command::new(r"C:\tools\run.bat").arg("a\nb"),
        );

        let [shell, flags @ .., line] = &after_separator(&plain)[..] else {
            panic!("the shell and its line follow the separator");
        };
        assert!(
            shell.to_lowercase().ends_with(r"system32\cmd.exe"),
            "{shell}"
        );
        assert_eq!(flags, ["/d", "/s", "/c"]);
        assert_eq!(line, r"C:\tools\run.bat one");
        assert!(matches!(broken, Err(WrapError::Cmd(_))), "{broken:?}");
    }

    #[test]
    fn cmd_itself_keeps_its_words_quoted_on_the_line() {
        let mut command = Command::new("cmd");
        command
            .env("PATH", r"C:\Windows\System32")
            .args(["/c", "echo", "x&y"]);

        let wrapped = wrap_over(
            &|path| path == r"c:\windows\system32\cmd.exe",
            &params(&[], false),
            &command,
        )
        .unwrap();

        let after = after_separator(&wrapped);
        assert_eq!(after[1..], ["/d", "/s", "/c", r#"cmd /c echo "x&y""#]);
    }

    #[test]
    fn a_name_that_resolves_to_nothing_still_runs_through_cmd() {
        let mut echo = Command::new("echo");
        echo.arg("hi there");
        let mut broken = Command::new("echo");
        broken.arg("100%");

        let wrapped = wrap_bare(&params(&[], false), &echo).unwrap();

        let after = after_separator(&wrapped);
        assert!(after[0].to_lowercase().ends_with(r"system32\cmd.exe"));
        assert_eq!(after[1..], ["/d", "/s", "/c", r#"echo "hi there""#]);
        assert!(matches!(
            wrap_bare(&params(&[], false), &broken),
            Err(WrapError::Cmd(_))
        ));
    }
}
