//! The cases in `harness/cases/`, each run under upstream and under crabpot.
//!
//! Both sandboxes are macOS's for now. Without Node, or without `npm ci` in
//! `harness/`, a case skips on a developer's machine and fails when `CI` is set.

#![cfg(target_os = "macos")]

use crabpot_harness::runner::{self, Crabpot, Upstream};

/// Runs the case file `harness/cases/<file>`.
fn run(name: &str, file: &str) {
    let probe = env!("CARGO_BIN_EXE_probe");
    let upstream = match Upstream::find(probe) {
        Ok(upstream) => upstream,
        Err(error) if std::env::var_os("CI").is_none() => {
            eprintln!("skipping {name}: {error}");
            return;
        }
        Err(error) => panic!("{name}: {error}"),
    };
    let path = format!("{}/cases/{file}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap();
    if let Err(error) = runner::run_case(&text, name, &upstream, &Crabpot::new(probe)) {
        panic!("{name}: {error}");
    }
}

#[test]
fn default_settings() {
    run("default_settings", "default-settings.json");
}

#[test]
fn refused_invalid_json() {
    run("refused_invalid_json", "refused-invalid-json.json");
}

#[test]
fn refused_empty_file() {
    run("refused_empty_file", "refused-empty-file.json");
}

#[test]
fn refused_missing_settings() {
    run("refused_missing_settings", "refused-missing-settings.json");
}

#[test]
fn allowed_domain_example_com() {
    run(
        "allowed_domain_example_com",
        "allowed-domains-example-com.json",
    );
}

#[test]
fn other_domain_example_org_is_refused() {
    run(
        "other_domain_example_org_is_refused",
        "allowed-domains-other-domain.json",
    );
}

#[test]
fn refused_allowed_domains_bad_entry() {
    run(
        "refused_allowed_domains_bad_entry",
        "refused-allowed-domains-bad-entry.json",
    );
}

#[test]
fn allowed_domain_untrimmed_matches_nothing() {
    run(
        "allowed_domain_untrimmed_matches_nothing",
        "allowed-domains-untrimmed.json",
    );
}
