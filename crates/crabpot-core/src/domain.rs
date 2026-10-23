//! Domain patterns and the rules that read and match them, as upstream's
//! `src/sandbox/domain-pattern.ts` has them.
//!
//! A [`DomainPattern`] is a host alone. A [`DomainEntry`] is a host pattern with an optional
//! `:port` suffix, the form `network.allowedDomains` and `network.deniedDomains` take. Both
//! parse on construction, so a bad entry fails when the config loads.
//!
//! Upstream canonicalizes a bracketed host with the WHATWG URL parser. Here an IPv6 literal and
//! a dotted, hex, octal or shorthand IPv4 address are canonicalized, and any other bracketed
//! text that the URL parser would reduce (`[x.com:80]` to `x.com`) is kept as written.

#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the config and the proxies do not use domain patterns yet"
    )
)]

use core::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A domain pattern with no port: `example.com`, `*.example.com`, `localhost` or an IPv6 literal.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DomainPattern(String);

impl DomainPattern {
    /// Parse a host-only domain pattern.
    ///
    /// # Errors
    ///
    /// [`DomainParseError::Pattern`] when `pattern` is not a domain, a wildcard such as
    /// `*.example.com`, `localhost` or a bare IPv6 literal.
    pub fn parse(pattern: &str) -> Result<Self, DomainParseError> {
        if is_valid_domain_pattern(pattern) {
            Ok(Self(pattern.to_owned()))
        } else {
            Err(DomainParseError::Pattern)
        }
    }

    /// The pattern as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether `hostname` is covered by this pattern.
    pub fn matches(&self, hostname: &str) -> bool {
        matches_domain_pattern(hostname, &self.0)
    }
}

/// A domain pattern with an optional port: `example.com:443`, `*.example.com`, `[::1]:8080`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DomainEntry {
    raw: String,
    host: String,
    port: Option<u16>,
}

impl DomainEntry {
    /// Parse an `allowedDomains` entry.
    ///
    /// # Errors
    ///
    /// [`DomainParseError::AllowedEntry`] when `entry` has an unbracketed IPv6 literal, a host
    /// that is not a valid domain pattern, or a bare `*`.
    pub fn parse_allowed(entry: &str) -> Result<Self, DomainParseError> {
        if is_valid_allowed_domain_entry(entry) {
            Ok(Self::new(entry))
        } else {
            Err(DomainParseError::AllowedEntry)
        }
    }

    /// Parse a `deniedDomains` entry, which also allows a bare `*` or `*:port`.
    ///
    /// # Errors
    ///
    /// [`DomainParseError::DeniedEntry`] when `entry` has an unbracketed IPv6 literal, or a host
    /// that is neither `*` nor a valid domain pattern.
    pub fn parse_denied(entry: &str) -> Result<Self, DomainParseError> {
        let host = split_domain_pattern_port(entry).0;
        if has_valid_ipv6_bracketing(entry) && (host == "*" || is_valid_domain_pattern(&host)) {
            Ok(Self::new(entry))
        } else {
            Err(DomainParseError::DeniedEntry)
        }
    }

    fn new(entry: &str) -> Self {
        let (host, port) = split_domain_pattern_port(entry);
        Self {
            raw: entry.to_owned(),
            host,
            port,
        }
    }

    /// The entry as written.
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// The host pattern: the entry without its port, an IPv6 literal without brackets and
    /// compressed.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port the entry is limited to, or `None` for every port.
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// Whether a connection to `hostname` on `port` is covered by this entry.
    pub fn matches(&self, hostname: &str, port: u16) -> bool {
        self.port.is_none_or(|own| own == port) && matches_domain_pattern(hostname, &self.host)
    }
}

impl AsRef<str> for DomainEntry {
    fn as_ref(&self) -> &str {
        &self.raw
    }
}

/// Why a domain pattern or entry was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainParseError {
    /// A [`DomainPattern`] is not a domain, a wildcard with at least two labels after `*.`,
    /// `localhost` or a bare IPv6 literal.
    Pattern,
    /// An `allowedDomains` entry has an unbracketed IPv6 literal, or a host that is not a valid
    /// pattern. A bare `*` is refused here.
    AllowedEntry,
    /// A `deniedDomains` entry has an unbracketed IPv6 literal, or a host that is neither `*`
    /// nor a valid pattern.
    DeniedEntry,
}

impl fmt::Display for DomainParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Pattern => {
                "not a domain pattern: expected a domain such as \"example.com\", a wildcard \
                 such as \"*.example.com\" or an IPv6 literal such as \"::1\", with no scheme \
                 or path; a wildcard over a whole top-level domain such as \"*.com\", and a \
                 bare \"*\", are refused as too broad"
            }
            Self::AllowedEntry => {
                "not an allowed domain entry: expected a domain such as \"example.com\", a \
                 wildcard such as \"*.example.com\" or a bracketed IPv6 literal such as \
                 \"[::1]\", with an optional \":port\" suffix from 1 to 65535 such as \
                 \"[2001:db8::1]:443\"; a wildcard over a whole top-level domain such as \
                 \"*.com\", and a bare \"*\", are refused as too broad"
            }
            Self::DeniedEntry => {
                "not a denied domain entry: expected a domain such as \"example.com\", a \
                 wildcard such as \"*.example.com\" or a bracketed IPv6 literal such as \
                 \"[::1]\", with an optional \":port\" suffix from 1 to 65535 such as \
                 \"[2001:db8::1]:443\", or a bare \"*\" (deny-all) with or without a port; a \
                 wildcard over a whole top-level domain such as \"*.com\" is refused as too \
                 broad"
            }
        })
    }
}

impl core::error::Error for DomainParseError {}

/// An IP address a list entry names, for judging a hostname that resolves to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpLiteralRule {
    /// The address the entry names.
    pub range: IpAddr,
    /// The port the entry is limited to, or `None` for every port.
    pub port: Option<u16>,
}

/// The entries that name an IP address, as rules for the resolved-address check.
fn ip_literal_rules<S: AsRef<str>>(entries: &[S]) -> Vec<IpLiteralRule> {
    entries
        .iter()
        .filter_map(|entry| {
            let (host, port) = split_domain_pattern_port(entry.as_ref());
            let range = host.parse().ok()?;
            Some(IpLiteralRule { range, port })
        })
        .collect()
}

/// Split an optional `:port` suffix off a domain pattern.
///
/// Only a number from 1 to 65535 without leading zeros counts as a port, so
/// `evil.com:443.allowed.com` stays whole. An IPv6 literal is returned bare and compressed. An
/// unbracketed string with two or more colons is never split.
fn split_domain_pattern_port(pattern: &str) -> (String, Option<u16>) {
    if pattern.starts_with('[') {
        let Some(close) = pattern.find(']') else {
            return (pattern.to_owned(), None);
        };
        let inner = drop_zone(&pattern[1..close]);
        let host = canonicalize_host(inner).unwrap_or_else(|| inner.to_owned());
        let rest = &pattern[close + 1..];
        if rest.is_empty() {
            return (host, None);
        }
        return match parse_port_suffix(rest.strip_prefix(':').unwrap_or("")) {
            Some(port) => (host, Some(port)),
            None => (pattern.to_owned(), None),
        };
    }
    let Some(last) = pattern.rfind(':') else {
        return (pattern.to_owned(), None);
    };
    if pattern.find(':') != Some(last) {
        let host = drop_zone(pattern);
        return (
            canonicalize_host(host).unwrap_or_else(|| host.to_owned()),
            None,
        );
    }
    match parse_port_suffix(&pattern[last + 1..]) {
        Some(port) => (pattern[..last].to_owned(), Some(port)),
        None => (pattern.to_owned(), None),
    }
}

fn strip_domain_pattern_port(pattern: &str) -> String {
    split_domain_pattern_port(pattern).0
}

fn drop_zone(host: &str) -> &str {
    host.split_once('%').map_or(host, |(bare, _)| bare)
}

fn parse_port_suffix(suffix: &str) -> Option<u16> {
    let digits = suffix.as_bytes();
    if !(1..=5).contains(&digits.len())
        || digits[0] == b'0'
        || !digits.iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    suffix.parse().ok()
}

/// A host-only pattern: `example.com`, `*.npmjs.org`, `localhost` or an IPv6 literal. Protocols,
/// paths, ports and wildcards over a whole top-level domain are refused.
fn is_valid_domain_pattern(val: &str) -> bool {
    if is_ipv6(val) {
        return true;
    }
    if val.contains('/') || val.contains(':') {
        return false;
    }
    if val == "localhost" {
        return true;
    }
    if let Some(domain) = val.strip_prefix("*.") {
        return domain.contains('.')
            && !domain.starts_with('.')
            && !domain.ends_with('.')
            && domain.split('.').all(|label| !label.is_empty());
    }
    if val.contains('*') {
        return false;
    }
    val.contains('.') && !val.starts_with('.') && !val.ends_with('.')
}

/// An entry with two or more colons is an IPv6 literal and must be bracketed. Unbracketed
/// `2001:db8::1:443` is itself an address, so it is refused rather than guessed at.
fn has_valid_ipv6_bracketing(val: &str) -> bool {
    let multi_colon = val
        .find(':')
        .is_some_and(|first| val[first + 1..].contains(':'));
    !multi_colon || val.starts_with('[')
}

fn is_valid_allowed_domain_entry(val: &str) -> bool {
    has_valid_ipv6_bracketing(val) && is_valid_domain_pattern(&split_domain_pattern_port(val).0)
}

/// Match a hostname against a host pattern, ignoring case. `*` matches everything and
/// `*.example.com` any strict subdomain, but never an IP literal: an IPv6 zone such as
/// `::ffff:192.0.2.4%x.allowed.com` must not pass for a subdomain while the OS dials the bare IP.
fn matches_domain_pattern(hostname: &str, pattern: &str) -> bool {
    let host = hostname.to_lowercase();
    if pattern == "*" {
        return true;
    }
    if let Some(base) = pattern.strip_prefix("*.") {
        if is_ip(strip_brackets(&host)) {
            return false;
        }
        return host.ends_with(&format!(".{}", base.to_lowercase()));
    }
    host == pattern.to_lowercase()
}

/// [`matches_domain_pattern`] with an optional `:port` on the pattern, which limits it to that
/// port.
fn matches_domain_pattern_with_port(hostname: &str, port: u16, pattern: &str) -> bool {
    let (host_pattern, pattern_port) = split_domain_pattern_port(pattern);
    pattern_port.is_none_or(|own| own == port) && matches_domain_pattern(hostname, &host_pattern)
}

fn strip_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host)
}

/// Node's `net.isIP(host) === 6`: an address with an optional zone of `[0-9A-Za-z.:-]`.
fn is_ipv6(host: &str) -> bool {
    let (address, zone) = match host.split_once('%') {
        Some((address, zone)) => (address, Some(zone)),
        None => (host, None),
    };
    zone.is_none_or(|zone| {
        !zone.is_empty()
            && zone
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b':' | b'-'))
    }) && address.parse::<Ipv6Addr>().is_ok()
}

/// Node's `net.isIP(host) !== 0`.
fn is_ip(host: &str) -> bool {
    is_ipv6(host) || host.parse::<Ipv4Addr>().is_ok()
}

/// What the WHATWG URL parser makes of `http://{host}/`'s host, as far as it is reproduced here
/// (see the module docs). `None` leaves the text as written.
fn canonicalize_host(host: &str) -> Option<String> {
    if let Ok(address) = host.parse::<Ipv6Addr>() {
        return Some(serialize_ipv6(address));
    }
    let plain = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_graphic() && !b"#%/:<>?@[\\]^|".contains(&b));
    if !plain {
        return None;
    }
    let host = host.to_ascii_lowercase();
    if ends_in_number(&host) {
        return parse_ipv4(&host).map(|address| address.to_string());
    }
    Some(host.strip_suffix('.').unwrap_or(&host).to_owned())
}

/// The URL parser's IPv6 serialization (lowercase, the first longest run of two or more zero
/// groups compressed), except that an IPv4-mapped address is spelled as the IPv4 address it
/// connects to, so entries and requests compare equal.
fn serialize_ipv6(address: Ipv6Addr) -> String {
    let groups = address.segments();
    if groups[..5].iter().all(|&g| g == 0) && groups[5] == 0xffff {
        let [a, b] = groups[6].to_be_bytes();
        let [c, d] = groups[7].to_be_bytes();
        return Ipv4Addr::new(a, b, c, d).to_string();
    }
    let mut compress = None;
    let mut longest = 1;
    let mut start = 0;
    while start < 8 {
        let run = groups[start..].iter().take_while(|&&g| g == 0).count();
        if run > longest {
            compress = Some(start);
            longest = run;
        }
        start += run.max(1);
    }
    let mut out = String::new();
    let mut skipping = false;
    for (i, group) in groups.iter().enumerate() {
        if skipping && *group == 0 {
            continue;
        }
        skipping = false;
        if compress == Some(i) {
            out.push_str(if i == 0 { "::" } else { ":" });
            skipping = true;
            continue;
        }
        out.push_str(&format!("{group:x}"));
        if i != 7 {
            out.push(':');
        }
    }
    out
}

/// The URL parser's "ends in a number" test, which sends a host to the IPv4 parser.
fn ends_in_number(host: &str) -> bool {
    let mut labels: Vec<&str> = host.split('.').collect();
    if labels.last() == Some(&"") {
        if labels.len() == 1 {
            return false;
        }
        labels.pop();
    }
    labels.last().is_some_and(|last| {
        !last.is_empty() && last.bytes().all(|b| b.is_ascii_digit())
            || parse_ipv4_number(last).is_some()
    })
}

/// An IPv4 address in the URL parser's lenient forms: one to four parts, each decimal, `0x` hex
/// or leading-zero octal, the last filling the rest of the address.
fn parse_ipv4(host: &str) -> Option<Ipv4Addr> {
    let mut parts: Vec<&str> = host.split('.').collect();
    if parts.last() == Some(&"") && parts.len() > 1 {
        parts.pop();
    }
    if parts.len() > 4 {
        return None;
    }
    let numbers: Vec<u64> = parts
        .iter()
        .map(|part| parse_ipv4_number(part))
        .collect::<Option<_>>()?;
    let (last, leading) = numbers.split_last()?;
    if leading.iter().any(|&n| n > 255) || *last >= 256u64.pow(5 - numbers.len() as u32) {
        return None;
    }
    let address = leading
        .iter()
        .zip((1..=3).rev())
        .fold(*last, |sum, (&n, place)| sum + n * 256u64.pow(place));
    Some(Ipv4Addr::from(address as u32))
}

fn parse_ipv4_number(part: &str) -> Option<u64> {
    let (digits, radix) = match part {
        "" => return None,
        _ if part.starts_with("0x") || part.starts_with("0X") => (&part[2..], 16),
        _ if part.len() > 1 && part.starts_with('0') => (&part[1..], 8),
        _ => (part, 10),
    };
    if digits.is_empty() {
        return Some(0);
    }
    if !digits.chars().all(|c| c.is_digit(radix)) {
        return None;
    }
    u64::from_str_radix(digits, radix).ok()
}

#[cfg(test)]
mod tests;
