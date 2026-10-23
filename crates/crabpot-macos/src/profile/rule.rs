//! What the sections share to write a rule.

use crabpot_core::ResolvedPath;

/// What a denied operation logs.
pub(super) const LOG_TAG: &str = "crabpot";

/// `text` as a profile's string literal, which reads JSON's escapes.
pub(super) fn string(text: &str) -> String {
    let mut quoted = String::with_capacity(text.len() + 2);
    quoted.push('"');
    for c in text.chars() {
        match c {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            '\u{8}' => quoted.push_str("\\b"),
            '\u{c}' => quoted.push_str("\\f"),
            c if c < ' ' => quoted.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => quoted.push(c),
        }
    }
    quoted.push('"');
    quoted
}

/// One rule applying `action` to each of `operations` for any path a filter
/// matches. Each filter is written once, and nothing is written for none: a
/// rule with no filter would match every path.
pub(super) fn render(action: &str, operations: &[&str], filters: &[String]) -> String {
    let mut rule = String::new();
    let mut written: Vec<&String> = Vec::new();
    for filter in filters {
        if !written.contains(&filter) {
            written.push(filter);
            rule.push_str(&format!("  {filter}\n"));
        }
    }
    if rule.is_empty() {
        return rule;
    }
    format!(
        "({action} {}\n{rule}  (with message {}))\n",
        operations.join(" "),
        string(LOG_TAG)
    )
}

/// The filter that matches what a deny of `path` hides: a pattern's regular
/// expression, or a name and everything beneath it.
pub(super) fn deny_filter(path: &ResolvedPath) -> String {
    match path.deny_regex() {
        Some(regex) => format!("(regex {})", string(&regex)),
        None => format!("(subpath {})", string(path.path())),
    }
}

/// The filter that matches what an allow of `path` opens: the paths a pattern
/// spells, or a name and everything beneath it.
pub(super) fn allow_filter(path: &ResolvedPath) -> String {
    match path.allow_regex() {
        Some(regex) => format!("(regex {})", string(&regex)),
        None => format!("(subpath {})", string(path.path())),
    }
}
