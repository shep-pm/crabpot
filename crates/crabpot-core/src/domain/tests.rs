use std::net::IpAddr;

use super::{
    DomainEntry, DomainPattern, has_valid_ipv6_bracketing, ip_literal_rules,
    is_valid_allowed_domain_entry, is_valid_domain_pattern, matches_domain_pattern_with_port,
    split_domain_pattern_port, strip_domain_pattern_port,
};

mod table;

/// One entry and what upstream's `domain-pattern.js` and `sandbox-config.js` say about it.
pub(super) struct Row {
    pub(super) entry: &'static str,
    /// `isValidDomainPattern(entry)`
    pub(super) domain_pattern: bool,
    /// `isValidAllowedDomainEntry(entry)`
    pub(super) allowed: bool,
    /// The `deniedDomains` schema's check.
    pub(super) denied: bool,
    /// `splitDomainPatternPort(entry)`
    pub(super) split: (&'static str, Option<u16>),
    /// The `table::PROBES` that `matchesDomainPatternWithPort` accepts.
    pub(super) hits: &'static [(&'static str, u16)],
    /// `ipLiteralRules([entry])`
    pub(super) ip_rule: Option<(&'static str, Option<u16>)>,
}

fn hits_of(matches: impl Fn(&str, u16) -> bool) -> Vec<(&'static str, u16)> {
    table::PROBES
        .iter()
        .copied()
        .filter(|&(host, port)| matches(host, port))
        .collect()
}

#[test]
fn every_table_entry_gets_upstreams_verdict() {
    assert!(table::rows().count() >= 40);
    let mut wrong = Vec::new();
    for row in table::rows() {
        let entry = row.entry;
        let mut check = |what: &str, ok: bool| {
            if !ok {
                wrong.push(format!("{entry:?}: {what}"));
            }
        };

        check(
            "isValidDomainPattern",
            is_valid_domain_pattern(entry) == row.domain_pattern,
        );
        check(
            "DomainPattern::parse",
            DomainPattern::parse(entry).is_ok() == row.domain_pattern,
        );
        check(
            "isValidAllowedDomainEntry",
            is_valid_allowed_domain_entry(entry) == row.allowed,
        );
        check(
            "DomainEntry::parse_allowed",
            DomainEntry::parse_allowed(entry).is_ok() == row.allowed,
        );
        check(
            "DomainEntry::parse_denied",
            DomainEntry::parse_denied(entry).is_ok() == row.denied,
        );
        let (host, port) = split_domain_pattern_port(entry);
        check("split", (host.as_str(), port) == row.split);
        check(
            "stripDomainPatternPort",
            strip_domain_pattern_port(entry) == row.split.0,
        );
        check(
            "matchesDomainPatternWithPort",
            hits_of(|host, port| matches_domain_pattern_with_port(host, port, entry)) == row.hits,
        );
        let rule = ip_literal_rules(&[entry]);
        let expected = row
            .ip_rule
            .map(|(range, port)| (range.parse::<IpAddr>(), port));
        check(
            "ipLiteralRules",
            match (rule.as_slice(), expected) {
                ([], None) => true,
                ([got], Some((Ok(range), port))) => got.range == range && got.port == port,
                _ => false,
            },
        );
        if row.allowed {
            let parsed = DomainEntry::parse_allowed(entry).unwrap();
            check(
                "allowed entry matches",
                hits_of(|host, port| parsed.matches(host, port)) == row.hits,
            );
        }
        if row.denied {
            let parsed = DomainEntry::parse_denied(entry).unwrap();
            check(
                "denied entry matches",
                hits_of(|host, port| parsed.matches(host, port)) == row.hits,
            );
        }
    }
    assert!(
        wrong.is_empty(),
        "differs from upstream:\n{}",
        wrong.join("\n")
    );
}

#[test]
fn a_bare_star_is_refused_as_an_allowed_entry_and_accepted_as_a_denied_one() {
    assert!(DomainEntry::parse_allowed("*").is_err());
    assert!(DomainEntry::parse_allowed("*:22").is_err());
    assert!(DomainPattern::parse("*").is_err());

    let any = DomainEntry::parse_denied("*").unwrap();
    assert!(any.matches("example.com", 443));
    assert!(any.matches("192.0.2.4", 22));

    let ssh_only = DomainEntry::parse_denied("*:22").unwrap();
    assert!(ssh_only.matches("example.com", 22));
    assert!(!ssh_only.matches("example.com", 443));

    assert!(DomainEntry::parse_denied("*.com").is_err());
}

#[test]
fn an_untrimmed_entry_parses_and_matches_nothing() {
    for entry in [" example.com", "example.com ", "*.example.com "] {
        let allowed = DomainEntry::parse_allowed(entry).unwrap();
        let denied = DomainEntry::parse_denied(entry).unwrap();
        let pattern = DomainPattern::parse(entry).unwrap();
        for host in ["example.com", "api.example.com"] {
            assert!(!allowed.matches(host, 443), "{entry:?} allowed {host:?}");
            assert!(!denied.matches(host, 443), "{entry:?} denied {host:?}");
            assert!(!pattern.matches(host), "{entry:?} pattern {host:?}");
        }
    }
}

#[test]
fn an_ipv6_literal_needs_brackets_with_a_port() {
    let bracketed = DomainEntry::parse_allowed("[2001:db8::1]:443").unwrap();
    assert_eq!(bracketed.as_str(), "[2001:db8::1]:443");
    assert_eq!(bracketed.host(), "2001:db8::1");
    assert_eq!(bracketed.port(), Some(443));
    assert!(bracketed.matches("2001:db8::1", 443));
    assert!(!bracketed.matches("2001:db8::1", 22));

    let no_port = DomainEntry::parse_allowed("[::1]").unwrap();
    assert_eq!(no_port.port(), None);
    assert!(no_port.matches("::1", 22));

    // `2001:db8::1:443` is itself an address, so it is refused rather than read as a port.
    assert!(DomainEntry::parse_allowed("2001:db8::1:443").is_err());
    assert!(DomainEntry::parse_allowed("::1").is_err());
    assert!(DomainEntry::parse_denied("::1").is_err());
    assert!(!has_valid_ipv6_bracketing("::1"));
    assert!(has_valid_ipv6_bracketing("[::1]"));
    assert!(has_valid_ipv6_bracketing("example.com:443"));

    // A host-only pattern takes the bare address.
    assert_eq!(DomainPattern::parse("::1").unwrap().as_str(), "::1");
}

#[test]
fn a_refusal_says_what_the_entry_may_look_like() {
    let pattern = DomainPattern::parse("*.com").unwrap_err().to_string();
    let allowed = DomainEntry::parse_allowed("*").unwrap_err().to_string();
    let denied = DomainEntry::parse_denied("*.com").unwrap_err().to_string();
    assert!(pattern.contains("*.example.com"));
    assert!(!pattern.contains(":port"));
    assert!(allowed.contains(":port"));
    assert!(denied.contains("deny-all"));
}
