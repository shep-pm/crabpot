//! Upstream's verdicts on sample entries, produced by running npm 0.0.81's
//! `dist/sandbox/domain-pattern.js` over each one.

use super::Row;

mod hostnames;
mod ip_literals;

/// Every row, hostnames first.
pub(super) fn rows() -> impl Iterator<Item = &'static Row> {
    hostnames::ROWS.iter().chain(ip_literals::ROWS)
}

pub(super) const PROBES: &[(&str, u16)] = &[
    ("example.com", 443),
    ("EXAMPLE.COM", 443),
    ("api.example.com", 443),
    ("a.b.example.com", 443),
    ("example.com.evil.com", 443),
    ("evilexample.com", 443),
    ("localhost", 443),
    ("github.com", 443),
    ("192.0.2.4", 443),
    ("127.0.0.1", 443),
    ("::1", 443),
    ("[::1]", 443),
    ("2001:db8::1", 443),
    ("::ffff:192.0.2.4%x.example.com", 443),
    ("::1%eth0", 443),
    ("example.com", 22),
    ("api.example.com", 22),
    ("localhost", 3000),
    ("192.0.2.4", 80),
    ("::1", 22),
    ("", 443),
];
