//! Path text folded as Node's `path` module folds it on POSIX. Nothing here
//! reads the disk.

/// Whether `path` starts at the root.
pub(crate) fn is_absolute(path: &str) -> bool {
    path.starts_with('/')
}

/// The components of `path` once `.` and empty ones are gone and each `..` has
/// taken the component before it. A `..` with nothing to take stays when
/// `keep_leading_parents` (a relative path) and goes otherwise, since nothing
/// is above the root.
fn fold_components(path: &str, keep_leading_parents: bool) -> Vec<&str> {
    let mut folded: Vec<&str> = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if folded.last().is_some_and(|last| *last != "..") {
                    folded.pop();
                } else if keep_leading_parents {
                    folded.push("..");
                }
            }
            name => folded.push(name),
        }
    }
    folded
}

/// `path.normalize`: `.`, `..` and `//` folded in text, a trailing `/` kept.
pub(crate) fn normalize(path: &str) -> String {
    if path.is_empty() {
        return ".".to_owned();
    }
    let absolute = is_absolute(path);
    let mut folded = fold_components(path, !absolute).join("/");
    if folded.is_empty() {
        return match (absolute, path.ends_with('/')) {
            (true, _) => "/".to_owned(),
            (false, true) => "./".to_owned(),
            (false, false) => ".".to_owned(),
        };
    }
    if path.ends_with('/') {
        folded.push('/');
    }
    if absolute {
        folded.insert(0, '/');
    }
    folded
}

/// `path.resolve(cwd, path)` for an absolute `cwd`: `path` made absolute and
/// folded in text, with no trailing `/`.
pub(crate) fn resolve(cwd: &str, path: &str) -> String {
    let joined = if is_absolute(path) {
        path.to_owned()
    } else {
        format!("{cwd}/{path}")
    };
    format!("/{}", fold_components(&joined, false).join("/"))
}

/// `path.dirname`, for a path with no `//` in it.
pub(crate) fn dirname(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    match trimmed.rfind('/') {
        None if is_absolute(path) => "/",
        None => ".",
        Some(0) => "/",
        Some(at) => &trimmed[..at],
    }
}

/// Runs of `/` collapsed to one and `/./` components dropped, leaving the rest
/// of the spelling (a trailing `/` or `/.`, a `..`) to the caller.
pub(crate) fn collapse_interior_spellings(path: &str) -> String {
    let mut single = String::with_capacity(path.len());
    for c in path.chars() {
        if c != '/' || !single.ends_with('/') {
            single.push(c);
        }
    }
    let mut collapsed = String::with_capacity(single.len());
    let mut rest = single.as_str();
    while let Some(c) = rest.chars().next() {
        // A `/.` before another `/` is dropped; that `/` stays to be read next.
        if let Some(tail) = rest.strip_prefix("/.")
            && tail.starts_with('/')
        {
            rest = tail;
            continue;
        }
        collapsed.push(c);
        rest = &rest[c.len_utf8()..];
    }
    collapsed
}

/// `path` is `dir` itself or lies beneath it, by component (`/xy` is not under
/// `/x`). Nothing but the root has `//` for a prefix, so the root is told
/// apart.
pub fn is_at_or_under(path: &str, dir: &str) -> bool {
    path == dir
        || if dir == "/" {
            path.starts_with('/')
        } else {
            path.strip_prefix(dir)
                .is_some_and(|rest| rest.starts_with('/'))
        }
}
