//! A Windows path as text: the string rules of upstream's `sandbox-utils.ts`
//! and of node's `path.win32`, which hold on every host.

/// `normalizeCaseForComparison`: lower case on every platform, so a mixed-case
/// spelling cannot get past a comparison.
pub(super) fn normalize_case(path: &str) -> String {
    path.to_lowercase()
}

/// `isAtOrUnder`: `path` is `dir` itself or lies beneath it, by segment, in the
/// `/` spelling of [`path_key`](super::path_key).
pub(super) fn is_at_or_under(path: &str, dir: &str) -> bool {
    if dir == "/" {
        return path.starts_with('/');
    }
    path.strip_prefix(dir)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

fn is_separator(c: char) -> bool {
    c == '\\' || c == '/'
}

/// `containsGlobCharsWin`: `[` and `]` are legal in a Win32 name, so only `*`
/// and `?` make a pattern. The `?` of a `\\?\` prefix is the namespace, not a
/// wildcard.
pub(super) fn contains_glob_chars(path: &str) -> bool {
    let body = match path.as_bytes() {
        [first, second, b'?' | b'.', last, ..]
            if [first, second, last]
                .iter()
                .all(|byte| matches!(byte, b'\\' | b'/')) =>
        {
            &path[4..]
        }
        _ => path,
    };
    body.contains(['*', '?'])
}

fn has_drive(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

/// `path.win32.isAbsolute`: a root, with or without a drive. `C:dir` is
/// relative to the drive's own working directory.
pub(super) fn is_absolute(path: &str) -> bool {
    path.starts_with(is_separator) || (has_drive(path) && path[2..].starts_with(is_separator))
}

/// `stripExtendedPathPrefix`: `\\?\UNC\srv\share` is `\\srv\share` and `\\?\C:\f`
/// is `C:\f`. Any other `\\?\` path is a device (`\\?\GLOBALROOT\x`), which has
/// no drive form to strip to, so it is kept for [`is_unprobed`] to see.
pub(super) fn strip_extended_prefix(path: &str) -> String {
    if path.len() >= 8 && path.is_char_boundary(8) && path[..8].eq_ignore_ascii_case(r"\\?\UNC\") {
        return format!(r"\\{}", &path[8..]);
    }
    match path.strip_prefix(r"\\?\") {
        Some(rest) if has_drive(rest) => rest.to_owned(),
        _ => path.to_owned(),
    }
}

/// `isUncPath`: a network share in any spelling, `\\srv\share`,
/// `\\?\UNC\srv\share` or `\\.\UNC\srv\share`, with either separator. A server
/// with no share is not one.
pub(super) fn is_unc_path(path: &str) -> bool {
    let path = path.replace('/', "\\");
    let Some(rest) = path.strip_prefix(r"\\") else {
        return false;
    };
    if let Some(device) = rest.strip_prefix(['?', '.']) {
        return device
            .strip_prefix('\\')
            .and_then(|after| after.get(..4))
            .is_some_and(|marker| marker.eq_ignore_ascii_case(r"unc\"));
    }
    let mut parts = rest.split('\\');
    let server = parts.next().unwrap_or_default();
    let mut after_server = parts.skip_while(|part| part.is_empty());
    !server.is_empty() && after_server.next().is_some_and(|share| !share.is_empty())
}

/// A device path other than a drive: `\\.\pipe\x`, `\\?\GLOBALROOT\x`. Like a
/// share, it is not looked at on disk.
fn is_device_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 4
        && matches!(bytes[0], b'\\' | b'/')
        && matches!(bytes[1], b'\\' | b'/')
        && matches!(bytes[2], b'?' | b'.')
        && matches!(bytes[3], b'\\' | b'/')
        && !has_drive(&path[4..])
}

/// `isUnprobedWindowsPath`: a path no `stat` or `realpath` is made for, since
/// each is an SMB request with the real user's credentials.
pub(super) fn is_unprobed(path: &str) -> bool {
    is_unc_path(path) || is_device_path(path)
}

/// `expandWindowsEnvRefs` for one name: every `%NAME%`, in any case, becomes
/// `value`.
fn replace_reference(text: &str, name: &str, value: &str) -> String {
    let needle = format!("%{}%", name.to_ascii_lowercase());
    // Lower-casing ASCII keeps every byte offset, so the match in `lower` is
    // the same span of `text`.
    let lower = text.to_ascii_lowercase();
    let mut out = String::with_capacity(text.len());
    let mut from = 0;
    while let Some(at) = lower[from..].find(&needle) {
        out.push_str(&text[from..from + at]);
        out.push_str(value);
        from += at + needle.len();
    }
    out.push_str(&text[from..]);
    out
}

/// Whether `text` holds a `%USERPROFILE%`, `%HOMEDRIVE%` or `%HOMEPATH%`.
pub(super) fn has_env_references(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    ["%userprofile%", "%homedrive%", "%homepath%"]
        .iter()
        .any(|name| lower.contains(name))
}

/// `expandWindowsEnvRefs`: `%USERPROFILE%`, `%HOMEDRIVE%` and `%HOMEPATH%` as
/// the home directory, its drive, and the rest. The drive is empty when the
/// home has none.
pub(super) fn expand_env_references(text: &str, home: &str) -> String {
    let (drive, home_path) = if has_drive(home) {
        home.split_at(2)
    } else {
        ("", home)
    };
    let text = replace_reference(text, "USERPROFILE", home);
    let text = replace_reference(&text, "HOMEDRIVE", drive);
    replace_reference(&text, "HOMEPATH", home_path)
}

/// `expandTilde` on Windows: what follows the `~` of `~`, `~/…` and `~\…`,
/// which the home directory goes in front of.
pub(super) fn tilde_rest(path: &str) -> Option<&str> {
    path.strip_prefix('~')
        .filter(|rest| rest.is_empty() || rest.starts_with(is_separator))
}

/// The root of a path and the rest of it, as `path.win32` reads them: a share
/// is `\\server\share\`, a drive is `C:\` or, with no separator, `C:`, and a
/// rooted path with neither is `\`.
fn split_root(path: &str) -> (String, &str) {
    if let Some(after) = path.strip_prefix(is_separator) {
        if let Some(body) = after.strip_prefix(is_separator)
            && let Some((server, rest)) = body.split_once(is_separator)
            && !server.is_empty()
        {
            let rest = rest.trim_start_matches(is_separator);
            if !rest.is_empty() {
                let (share, tail) = rest.split_once(is_separator).unwrap_or((rest, ""));
                return (format!(r"\\{server}\{share}\"), tail);
            }
        }
        return (r"\".to_owned(), after);
    }
    if has_drive(path) {
        let (drive, rest) = path.split_at(2);
        return match rest.strip_prefix(is_separator) {
            Some(tail) => (format!(r"{drive}\"), tail),
            None => (drive.to_owned(), rest),
        };
    }
    (String::new(), path)
}

/// `path.win32.normalize`: `/` is `\`, runs of separators are one, `.` is gone
/// and `..` folds, none above the root. A trailing separator stays.
pub(super) fn win32_normalize(path: &str) -> String {
    let (root, rest) = split_root(path);
    let absolute = root.ends_with('\\');
    let mut parts: Vec<&str> = Vec::new();
    for part in rest.split(is_separator) {
        match part {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|last| *last != "..") {
                    parts.pop();
                } else if !absolute {
                    parts.push("..");
                }
            }
            name => parts.push(name),
        }
    }
    let mut out = root;
    out.push_str(&parts.join("\\"));
    if !parts.is_empty() && rest.ends_with(is_separator) {
        out.push('\\');
    }
    if out.is_empty() { ".".to_owned() } else { out }
}

/// `path.win32.resolve(cwd, path)` for a path that is not absolute: against
/// `cwd`, normalized, with no separator at its end.
pub(super) fn win32_resolve(cwd: &str, path: &str) -> String {
    let joined = if has_drive(path) && !is_absolute(path) {
        // `C:dir` is relative to the working directory of drive C.
        if has_drive(cwd) && cwd[..2].eq_ignore_ascii_case(&path[..2]) {
            format!(r"{cwd}\{}", &path[2..])
        } else {
            format!(r"{}\{}", &path[..2], &path[2..])
        }
    } else {
        format!(r"{cwd}\{path}")
    };
    let normal = win32_normalize(&joined);
    let (root, _) = split_root(&normal);
    if normal.len() > root.len() {
        normal.trim_end_matches('\\').to_owned()
    } else {
        normal
    }
}

/// The comparison key of a path already looked at: no `\\?\`, `/` for `\`, no
/// separator at the end, lower case.
pub(super) fn key_of(path: &str) -> String {
    let normal = win32_normalize(&strip_extended_prefix(path)).replace('\\', "/");
    normalize_case(normal.trim_end_matches('/'))
}

/// `profilePathKey`: a recorded exclusion for comparison. Not normalized, as a
/// wildcard component has no meaning to a normalizer.
pub(super) fn profile_key(path: &str) -> String {
    let stripped = strip_extended_prefix(path).replace('\\', "/");
    stripped.trim_end_matches('/').to_lowercase()
}
