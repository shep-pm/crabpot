//! A glob as the regular expression upstream makes of it, for the seatbelt profile.
//!
//! Upstream's syntax has quirks no glob crate shares, so this is a port of
//! `src/sandbox/glob-pattern.ts`. No character escapes another, nothing
//! negates, a set ends at the first `]`, and `{a,b}` and a broken bracket are
//! text.

/// One piece of a pattern, as upstream's `GlobToken` reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    /// Characters that stand for themselves, none of them a separator.
    Text(String),
    /// `/`
    Separator,
    /// `?`: one character of a name.
    AnyChar,
    /// `*`: any number of characters of a name.
    Star,
    /// `**`: any number of characters, separators among them.
    Globstar,
    /// `**` with the `/` after it: any number of directories.
    GlobstarSlash,
    /// `[abc]`, `[a-z]`: what is written between the brackets.
    Set(String),
}

/// Whether `members` spell a set: there is at least one, and no range runs
/// backwards. A `-` is a member where it is the first or the last. Ranges are
/// read in UTF-16 code units, as a regular expression without the `u` flag
/// reads them.
fn spells_a_set(members: &str) -> bool {
    let units: Vec<u16> = members.encode_utf16().collect();
    if units.is_empty() {
        return false;
    }
    let mut i = 0;
    while i < units.len() {
        let from = units[i];
        if units.get(i + 1) == Some(&u16::from(b'-')) && i + 2 < units.len() {
            i += 2;
        }
        if units[i] < from {
            return false;
        }
        i += 1;
    }
    true
}

fn kind_at(tokens: &[Token], from_end: usize) -> Option<&Token> {
    tokens.len().checked_sub(from_end).map(|i| &tokens[i])
}

/// Adds a wildcard that stands right after the last token. Wildcards side by
/// side are kept to the fewest that match the same, two at most, because a
/// regular expression tries every way to share a path out among them.
fn add_wildcard(tokens: &mut Vec<Token>, kind: Token) {
    if kind_at(tokens, 1) == Some(&Token::Globstar) || kind_at(tokens, 1) == Some(&kind) {
        return;
    }
    let is_globstar = kind == Token::Globstar
        || (kind_at(tokens, 2) == Some(&kind)
            && matches!(kind_at(tokens, 1), Some(Token::Star | Token::GlobstarSlash)));
    if !is_globstar {
        tokens.push(kind);
        return;
    }
    while matches!(tokens.last(), Some(Token::Star | Token::GlobstarSlash)) {
        tokens.pop();
    }
    tokens.push(Token::Globstar);
}

fn end_text(tokens: &mut Vec<Token>, pattern: &str, text_start: usize, at: usize) {
    if text_start < at {
        tokens.push(Token::Text(pattern[text_start..at].to_owned()));
    }
}

/// `pattern` as its tokens. Every string is a pattern, and no character
/// escapes another:
///
/// - A set runs from a `[` to the first `]` after it, be that the next
///   character. A `*`, `?`, `/` or `[` between the two is a member, and `^`
///   and `!` do not negate.
/// - Brackets that spell no set are text, as are a `[` that nothing closes and
///   a `]` that nothing opens. What is between them keeps its meaning.
/// - Of a run of `*`, the last two go with a `/` that follows. Two or more of
///   the rest are a `**`.
fn parse_glob(pattern: &str) -> Vec<Token> {
    let bytes = pattern.as_bytes();
    let mut tokens = Vec::new();
    let mut text_start = 0;
    // A `[` before this is inside brackets already found to open no set.
    let mut brackets_are_text_until = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'/' | b'?' => {
                end_text(&mut tokens, pattern, text_start, i);
                tokens.push(if bytes[i] == b'/' {
                    Token::Separator
                } else {
                    Token::AnyChar
                });
                i += 1;
                text_start = i;
            }
            b'*' => {
                end_text(&mut tokens, pattern, text_start, i);
                let start = i;
                while bytes.get(i) == Some(&b'*') {
                    i += 1;
                }
                let with_separator = i - start >= 2 && bytes.get(i) == Some(&b'/');
                let rest = i - start - if with_separator { 2 } else { 0 };
                if rest >= 2 {
                    add_wildcard(&mut tokens, Token::Globstar);
                }
                if rest == 1 {
                    add_wildcard(&mut tokens, Token::Star);
                }
                if with_separator {
                    add_wildcard(&mut tokens, Token::GlobstarSlash);
                    i += 1;
                }
                text_start = i;
            }
            b'[' if i >= brackets_are_text_until => {
                let Some(close) = pattern[i + 1..].find(']').map(|at| at + i + 1) else {
                    brackets_are_text_until = pattern.len();
                    i += 1;
                    continue;
                };
                let members = &pattern[i + 1..close];
                if !spells_a_set(members) {
                    brackets_are_text_until = close + 1;
                    i += 1;
                    continue;
                }
                end_text(&mut tokens, pattern, text_start, i);
                tokens.push(Token::Set(members.to_owned()));
                i = close + 1;
                text_start = i;
            }
            _ => i += 1,
        }
    }
    end_text(&mut tokens, pattern, text_start, i);
    tokens
}

/// A regular expression that matches `text` and nothing else.
pub(crate) fn escape_regex_literal(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for c in text.chars() {
        if ".*+?^${}()|[]\\".contains(c) {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    escaped
}

fn token_to_regex(token: &Token) -> String {
    match token {
        Token::Text(text) => escape_regex_literal(text),
        Token::Separator => "/".to_owned(),
        Token::AnyChar => "[^/]".to_owned(),
        Token::Star => "[^/]*".to_owned(),
        Token::Globstar => ".*".to_owned(),
        Token::GlobstarSlash => "(.*/)?".to_owned(),
        Token::Set(members) => {
            // A `-` stays what it is to the set, and the rest are its members.
            let mut set = String::with_capacity(members.len() + 2);
            set.push('[');
            for c in members.chars() {
                if ".^$+{}()|\\".contains(c) {
                    set.push('\\');
                }
                set.push(c);
            }
            set.push(']');
            set
        }
    }
}

/// The regular expression for `pattern`, anchored at both ends. Whatever the
/// pattern spells, it compiles.
pub(crate) fn glob_to_regex(pattern: &str) -> String {
    let body: String = parse_glob(pattern).iter().map(token_to_regex).collect();
    format!("^{body}$")
}

/// [`glob_to_regex`] plus an optional `/...` tail, so a deny covers everything
/// beneath each match the way `subpath` does for a literal. It only ever
/// widens a deny.
pub(crate) fn deny_glob_regex(pattern: &str) -> String {
    let mut regex = glob_to_regex(pattern);
    regex.pop();
    regex.push_str("(/.*)?$");
    regex
}

/// Whether `deny_glob_regex(pattern)` matches `text`, which is how a deny glob
/// is asked whether it covers a path.
pub(crate) fn deny_glob_matches(pattern: &str, text: &str) -> bool {
    let tokens = parse_glob(pattern);
    // The tail `(/.*)?` takes whatever follows a `/`, or nothing.
    (0..=text.len())
        .filter(|&at| {
            text.is_char_boundary(at) && (at == text.len() || text[at..].starts_with('/'))
        })
        .any(|at| tokens_match(&tokens, &text[..at]))
}

/// Whether `tokens` match all of `text`. The wildcards try every way to share
/// `text` out, which is cheap for the short texts this is asked about.
fn tokens_match(tokens: &[Token], text: &str) -> bool {
    let Some((token, rest)) = tokens.split_first() else {
        return text.is_empty();
    };
    let ends = || (0..=text.len()).filter(|&at| text.is_char_boundary(at));
    let first = text.chars().next();
    match token {
        Token::Text(literal) => text
            .strip_prefix(literal.as_str())
            .is_some_and(|after| tokens_match(rest, after)),
        Token::Separator => text
            .strip_prefix('/')
            .is_some_and(|after| tokens_match(rest, after)),
        Token::AnyChar => {
            first.is_some_and(|c| c != '/' && tokens_match(rest, &text[c.len_utf8()..]))
        }
        Token::Star => ends()
            .take_while(|&at| !text[..at].contains('/'))
            .any(|at| tokens_match(rest, &text[at..])),
        Token::Globstar => ends().any(|at| tokens_match(rest, &text[at..])),
        Token::GlobstarSlash => {
            tokens_match(rest, text)
                || ends().any(|at| text[..at].ends_with('/') && tokens_match(rest, &text[at..]))
        }
        Token::Set(members) => first
            .is_some_and(|c| set_holds(members, c) && tokens_match(rest, &text[c.len_utf8()..])),
    }
}

/// Whether the set `members` holds `c`, as a regular expression without the
/// `u` flag reads it: by UTF-16 code unit, so a character outside the basic
/// plane is held by no set.
fn set_holds(members: &str, c: char) -> bool {
    let mut unit = [0u16; 2];
    let [only] = *c.encode_utf16(&mut unit) else {
        return false;
    };
    let units: Vec<u16> = members.encode_utf16().collect();
    let mut i = 0;
    while i < units.len() {
        let from = units[i];
        let to = if units.get(i + 1) == Some(&u16::from(b'-')) && i + 2 < units.len() {
            i += 2;
            units[i]
        } else {
            from
        };
        if (from..=to).contains(&only) {
            return true;
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // Each row is a pattern, then what upstream's `globToRegex` and
    // `denyGlobRegex` give for it. Generated once by running both from the
    // `dist/sandbox/glob-pattern.js` of npm's @anthropic-ai/sandbox-runtime
    // 0.0.81 over this list of patterns and printing the rows as Rust.
    const UPSTREAM: &[(&str, &str, &str)] = &[
        ("", "^$", "^(/.*)?$"),
        ("a", "^a$", "^a(/.*)?$"),
        ("/", "^/$", "^/(/.*)?$"),
        ("src/main.rs", "^src/main\\.rs$", "^src/main\\.rs(/.*)?$"),
        ("*", "^[^/]*$", "^[^/]*(/.*)?$"),
        ("**", "^.*$", "^.*(/.*)?$"),
        ("*.ts", "^[^/]*\\.ts$", "^[^/]*\\.ts(/.*)?$"),
        ("?", "^[^/]$", "^[^/](/.*)?$"),
        ("file?.txt", "^file[^/]\\.txt$", "^file[^/]\\.txt(/.*)?$"),
        (
            "file[0-9].txt",
            "^file[0-9]\\.txt$",
            "^file[0-9]\\.txt(/.*)?$",
        ),
        (
            "src/**/*.ts",
            "^src/(.*/)?[^/]*\\.ts$",
            "^src/(.*/)?[^/]*\\.ts(/.*)?$",
        ),
        ("**/secrets", "^(.*/)?secrets$", "^(.*/)?secrets(/.*)?$"),
        (
            "**/secrets/**",
            "^(.*/)?secrets/.*$",
            "^(.*/)?secrets/.*(/.*)?$",
        ),
        ("**/", "^(.*/)?$", "^(.*/)?(/.*)?$"),
        ("a/**/b", "^a/(.*/)?b$", "^a/(.*/)?b(/.*)?$"),
        ("a/**b", "^a/.*b$", "^a/.*b(/.*)?$"),
        ("a**b", "^a.*b$", "^a.*b(/.*)?$"),
        ("a/**", "^a/.*$", "^a/.*(/.*)?$"),
        ("***", "^.*$", "^.*(/.*)?$"),
        ("****/", "^.*$", "^.*(/.*)?$"),
        ("*/**/*", "^[^/]*/(.*/)?[^/]*$", "^[^/]*/(.*/)?[^/]*(/.*)?$"),
        (
            "**/*/**/",
            "^(.*/)?[^/]*/(.*/)?$",
            "^(.*/)?[^/]*/(.*/)?(/.*)?$",
        ),
        ("**/**/", "^(.*/)?$", "^(.*/)?(/.*)?$"),
        ("*/**/", "^[^/]*/(.*/)?$", "^[^/]*/(.*/)?(/.*)?$"),
        ("/**/*", "^/(.*/)?[^/]*$", "^/(.*/)?[^/]*(/.*)?$"),
        ("[abc]", "^[abc]$", "^[abc](/.*)?$"),
        ("[a-z]", "^[a-z]$", "^[a-z](/.*)?$"),
        ("[a-zA-Z0-9_]", "^[a-zA-Z0-9_]$", "^[a-zA-Z0-9_](/.*)?$"),
        ("[]", "^\\[\\]$", "^\\[\\](/.*)?$"),
        ("[]]", "^\\[\\]\\]$", "^\\[\\]\\](/.*)?$"),
        ("[a]b]", "^[a]b\\]$", "^[a]b\\](/.*)?$"),
        ("[!a]", "^[!a]$", "^[!a](/.*)?$"),
        ("[^a]", "^[\\^a]$", "^[\\^a](/.*)?$"),
        ("[a", "^\\[a$", "^\\[a(/.*)?$"),
        ("a]", "^a\\]$", "^a\\](/.*)?$"),
        ("[", "^\\[$", "^\\[(/.*)?$"),
        ("]", "^\\]$", "^\\](/.*)?$"),
        ("[user-id]", "^\\[user-id\\]$", "^\\[user-id\\](/.*)?$"),
        ("[z-a]", "^\\[z-a\\]$", "^\\[z-a\\](/.*)?$"),
        ("[a-]", "^[a-]$", "^[a-](/.*)?$"),
        ("[-a]", "^[-a]$", "^[-a](/.*)?$"),
        ("[+-9]", "^[\\+-9]$", "^[\\+-9](/.*)?$"),
        ("[*]", "^[*]$", "^[*](/.*)?$"),
        ("[?]", "^[?]$", "^[?](/.*)?$"),
        ("[/]", "^[/]$", "^[/](/.*)?$"),
        ("[[]", "^[[]$", "^[[](/.*)?$"),
        ("[a.b]", "^[a\\.b]$", "^[a\\.b](/.*)?$"),
        ("[a$b]", "^[a\\$b]$", "^[a\\$b](/.*)?$"),
        ("{a,b}", "^\\{a,b\\}$", "^\\{a,b\\}(/.*)?$"),
        ("{a,b}.ts", "^\\{a,b\\}\\.ts$", "^\\{a,b\\}\\.ts(/.*)?$"),
        ("a{b", "^a\\{b$", "^a\\{b(/.*)?$"),
        ("}", "^\\}$", "^\\}(/.*)?$"),
        ("a.b", "^a\\.b$", "^a\\.b(/.*)?$"),
        ("a+b", "^a\\+b$", "^a\\+b(/.*)?$"),
        ("a(b)", "^a\\(b\\)$", "^a\\(b\\)(/.*)?$"),
        ("a|b", "^a\\|b$", "^a\\|b(/.*)?$"),
        ("a^b", "^a\\^b$", "^a\\^b(/.*)?$"),
        ("a$b", "^a\\$b$", "^a\\$b(/.*)?$"),
        ("a\\b", "^a\\\\b$", "^a\\\\b(/.*)?$"),
        ("a\\*b", "^a\\\\[^/]*b$", "^a\\\\[^/]*b(/.*)?$"),
        (".git/config", "^\\.git/config$", "^\\.git/config(/.*)?$"),
        ("~/.ssh/*", "^~/\\.ssh/[^/]*$", "^~/\\.ssh/[^/]*(/.*)?$"),
        (
            "/home/*/.config",
            "^/home/[^/]*/\\.config$",
            "^/home/[^/]*/\\.config(/.*)?$",
        ),
        (
            "/tmp/[abc]*/x?",
            "^/tmp/[abc][^/]*/x[^/]$",
            "^/tmp/[abc][^/]*/x[^/](/.*)?$",
        ),
        ("[a][b]", "^[a][b]$", "^[a][b](/.*)?$"),
        ("[a]*[b]", "^[a][^/]*[b]$", "^[a][^/]*[b](/.*)?$"),
        ("é*", "^é[^/]*$", "^é[^/]*(/.*)?$"),
        (
            "dir/日本語/*",
            "^dir/日本語/[^/]*$",
            "^dir/日本語/[^/]*(/.*)?$",
        ),
        ("[é-ü]", "^[é-ü]$", "^[é-ü](/.*)?$"),
        ("[😀]", "^[😀]$", "^[😀](/.*)?$"),
        ("[a-😀]", "^[a-😀]$", "^[a-😀](/.*)?$"),
        ("a b", "^a b$", "^a b(/.*)?$"),
        ("a\nb", "^a\nb$", "^a\nb(/.*)?$"),
        ("*[", "^[^/]*\\[$", "^[^/]*\\[(/.*)?$"),
        ("[*", "^\\[[^/]*$", "^\\[[^/]*(/.*)?$"),
        ("[a]]", "^[a]\\]$", "^[a]\\](/.*)?$"),
        ("[[a]", "^[[a]$", "^[[a](/.*)?$"),
    ];

    #[test]
    fn every_table_pattern_gives_upstreams_regex() {
        assert!(UPSTREAM.len() >= 40);
        for &(pattern, regex, deny_regex) in UPSTREAM {
            assert_eq!(glob_to_regex(pattern), regex, "glob_to_regex({pattern:?})");
            assert_eq!(
                deny_glob_regex(pattern),
                deny_regex,
                "deny_glob_regex({pattern:?})"
            );
        }
    }

    #[test]
    fn a_set_ends_at_the_first_bracket() {
        assert_eq!(glob_to_regex("[a]b]"), r"^[a]b\]$");
        assert_eq!(glob_to_regex("[*?/[]x"), r"^[*?/[]x$");
    }

    #[test]
    fn braces_stay_text() {
        assert_eq!(glob_to_regex("{a,b}.ts"), r"^\{a,b\}\.ts$");
    }

    #[test]
    fn a_broken_bracket_stays_text() {
        assert_eq!(glob_to_regex("[a"), r"^\[a$");
        assert_eq!(glob_to_regex("[z-a]"), r"^\[z-a\]$");
        assert_eq!(glob_to_regex("[]]"), r"^\[\]\]$");
    }

    #[test]
    fn double_star_works_mid_pattern() {
        assert_eq!(glob_to_regex("a**b"), "^a.*b$");
        assert_eq!(glob_to_regex("a/**b"), "^a/.*b$");
        assert_eq!(glob_to_regex("a/**/b"), "^a/(.*/)?b$");
    }

    #[test]
    fn a_regex_metacharacter_is_escaped() {
        assert_eq!(glob_to_regex("a.b+c(d)|e^f$g"), r"^a\.b\+c\(d\)\|e\^f\$g$");
        assert_eq!(glob_to_regex(r"a\b"), r"^a\\b$");
    }
}
