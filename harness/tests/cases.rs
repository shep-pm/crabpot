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
fn allow_read_file() {
    run("allow_read_file", "allow-read-file.json");
}

#[test]
fn allow_read_folder() {
    run("allow_read_folder", "allow-read-folder.json");
}

#[test]
fn allow_read_glob() {
    run("allow_read_glob", "allow-read-glob.json");
}

#[test]
fn allow_read_folder_alone_glob() {
    run(
        "allow_read_folder_alone_glob",
        "allow-read-folder-alone-glob.json",
    );
}

#[test]
fn deny_read_folder() {
    run("deny_read_folder", "deny-read-folder.json");
}

#[test]
fn deny_read_glob() {
    run("deny_read_glob", "deny-read-glob.json");
}

#[test]
fn deny_read_literal() {
    run("deny_read_literal", "deny-read-literal.json");
}

#[test]
fn deny_read_tilde() {
    run("deny_read_tilde", "deny-read-tilde.json");
}

#[test]
fn refused_deny_read_empty() {
    run("refused_deny_read_empty", "refused-deny-read-empty.json");
}

#[test]
fn refused_deny_read_unmarked_object() {
    run(
        "refused_deny_read_unmarked_object",
        "refused-deny-read-unmarked-object.json",
    );
}

#[test]
fn refused_deny_read_trailing_separator_glob() {
    run(
        "refused_deny_read_trailing_separator_glob",
        "refused-deny-read-trailing-separator-glob.json",
    );
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

#[test]
fn allow_write_folder() {
    run("allow_write_folder", "allow-write-folder.json");
}

#[test]
fn allow_write_outside_is_refused() {
    run(
        "allow_write_outside_is_refused",
        "allow-write-outside-is-refused.json",
    );
}

#[test]
fn allow_write_glob() {
    run("allow_write_glob", "allow-write-glob.json");
}

#[test]
fn default_write_dev_null() {
    run("default_write_dev_null", "default-write-dev-null.json");
}

#[test]
fn default_write_tmp_claude() {
    run("default_write_tmp_claude", "default-write-tmp-claude.json");
}

#[test]
fn deny_write_file() {
    run("deny_write_file", "deny-write-file.json");
}

#[test]
fn deny_write_glob() {
    run("deny_write_glob", "deny-write-glob.json");
}

#[test]
fn deny_write_literal() {
    run("deny_write_literal", "deny-write-literal.json");
}

#[test]
fn mandatory_git_hooks() {
    run("mandatory_git_hooks", "mandatory-git-hooks.json");
}

#[test]
fn mandatory_shell_rc() {
    run("mandatory_shell_rc", "mandatory-shell-rc.json");
}

#[test]
fn mandatory_nested_git_config() {
    run(
        "mandatory_nested_git_config",
        "mandatory-nested-git-config.json",
    );
}

#[test]
fn move_blocking_file() {
    run("move_blocking_file", "move-blocking-file.json");
}

#[test]
fn move_blocking_parent() {
    run("move_blocking_parent", "move-blocking-parent.json");
}

#[test]
fn move_blocking_read() {
    run("move_blocking_read", "move-blocking-read.json");
}

#[test]
fn refused_deny_write_trailing_separator_glob() {
    run(
        "refused_deny_write_trailing_separator_glob",
        "refused-deny-write-trailing-separator-glob.json",
    );
}

#[test]
fn allow_mach_lookup_loads() {
    run("allow_mach_lookup_loads", "allow-mach-lookup-services.json");
}

#[test]
fn refused_allow_mach_lookup_mid_wildcard() {
    run(
        "refused_allow_mach_lookup_mid_wildcard",
        "allow-mach-lookup-mid-wildcard.json",
    );
}

#[test]
fn socks_allowed_example_com() {
    run(
        "socks_allowed_example_com",
        "socks-allowed-example-com.json",
    );
}

#[test]
fn socks_other_domain_refused() {
    run(
        "socks_other_domain_refused",
        "socks-other-domain-refused.json",
    );
}

#[test]
fn denied_beats_allowed() {
    run("denied_beats_allowed", "denied-domains-beats-allowed.json");
}

#[test]
fn denied_port_only() {
    run("denied_port_only", "denied-domains-port-only.json");
}

#[test]
fn denied_star() {
    run("denied_star", "denied-domains-star.json");
}

#[test]
fn strict_allowlist_false() {
    run(
        "strict_allowlist_false",
        "denied-domains-strict-allowlist-false.json",
    );
}

#[test]
fn refused_denied_domains_bad_entry() {
    run(
        "refused_denied_domains_bad_entry",
        "refused-denied-domains-bad-entry.json",
    );
}
