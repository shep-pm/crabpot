//! The cases in `harness/cases/`, each run under upstream and under crabpot.
//!
//! macOS runs every case as a comparison of the two Seatbelt runners. Linux
//! runs crabpot only on the cases `LINUX_READY` names, and each Linux slice adds
//! the cases it makes pass there. Any other case runs under upstream's bwrap path
//! alone, which is what proves that path holds the settings the same way. There,
//! a probe that reported a code and could not tell what upstream's mounts left
//! it is written to the log as `report:` rather than failed: a Linux read deny
//! answers by removing what the probe asks about, and no answer is compared with
//! another runner's.
//!
//! Without Node, or without `npm ci` in `harness/`, a case skips on a
//! developer's machine and fails when `CI` is set. On Linux upstream also needs
//! `bubblewrap`, `socat` and `ripgrep`, and a kernel that lets bwrap take its
//! namespaces: `sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`.
//!
//! Windows runs crabpot only on the cases `WINDOWS_READY` names, which is none
//! yet, and every other case under upstream's `srt-win` path alone. That needs
//! `windows-install` run once: `node harness/node_modules/@anthropic-ai/sandbox-runtime/dist/cli.js
//! windows-install`. The cases that mean only Unix name their platforms and are
//! skipped there. Upstream refuses a session whose `network.allowLocalBinding` is
//! not the loopback mode the filters were installed with, so a case that opens
//! loopback runs only after `windows-install --allow-loopback --force` and with
//! `CRABPOT_HARNESS_LOOPBACK=open`, and every other case runs only without them.

use crabpot_harness::runner::{self, Crabpot, Upstream};

/// The cases that run under crabpot on Linux. Each Linux slice of #99 appends
/// the cases it makes pass.
const LINUX_READY: &[&str] = &[
    "default_settings",
    "refused_invalid_json",
    "refused_empty_file",
    "refused_missing_settings",
    "refused_deny_read_empty",
    "refused_deny_read_unmarked_object",
    "refused_deny_read_trailing_separator_glob",
    "refused_allowed_domains_bad_entry",
    "refused_deny_write_trailing_separator_glob",
    "refused_allow_mach_lookup_mid_wildcard",
    "refused_denied_domains_bad_entry",
    "refused_mitm_empty_domains",
    "refused_resolved_address_bad_cidr",
    "deny_read_folder",
    "deny_read_glob",
    "deny_read_literal",
    "deny_read_tilde",
    "allow_read_file",
    "allow_read_folder",
    "allow_read_glob",
    "allow_read_folder_alone_glob",
    "allow_write_folder",
    "allow_write_outside_is_refused",
    "allow_write_glob",
    "default_write_dev_null",
    "default_write_tmp_claude",
    "deny_write_file",
    "deny_write_glob",
    "deny_write_literal",
    "move_blocking_file",
    "move_blocking_parent",
    "move_blocking_read",
    "move_blocking_read_glob",
    "allowed_domain_example_com",
    "socks_allowed_example_com",
    "weaker_isolation_true",
    "weaker_isolation_false",
    "local_binding_bind_refused_by_default",
    "local_binding_bind_allowed",
    "local_binding_connect_to_loopback",
    "kelpie_loopback_bind",
    "kelpie_bind_allowed",
    "mandatory_git_hooks",
    "mandatory_nested_git_config",
    "mandatory_shell_rc",
    "other_domain_example_org_is_refused",
    "allowed_domain_untrimmed_matches_nothing",
    "socks_other_domain_refused",
    "mux_http_allowed",
    "mux_socks_allowed",
    "mux_other_domain_refused",
    "denied_beats_allowed",
    "denied_port_only",
    "denied_star",
    "strict_allowlist_false",
    "mitm_matching_domain_reaches_the_socket",
    "mitm_other_domain_goes_direct",
    "mitm_bad_socket_path_is_502",
    "resolved_address_loopback_name",
    "resolved_address_listed_cidr",
    "local_binding_other_host_still_refused",
    "unix_socket_listed_folder",
    "unix_socket_unlisted_is_refused",
    "unix_socket_empty_string_grants_cwd",
];

/// The cases that run under crabpot on Windows. Each Windows slice of #143
/// appends the cases it makes pass.
const WINDOWS_READY: &[&str] = &[];

/// Whether crabpot runs `name` beside upstream on this platform.
fn runs_crabpot(name: &str) -> bool {
    if cfg!(target_os = "macos") {
        true
    } else if cfg!(windows) {
        WINDOWS_READY.contains(&name)
    } else {
        LINUX_READY.contains(&name)
    }
}

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
    let outcome = if runs_crabpot(name) {
        runner::run_case(&text, name, &upstream, &Crabpot::new(probe))
    } else {
        runner::run_upstream_only(&text, name, &upstream)
    };
    match outcome {
        Ok(true) => {}
        Ok(false) => {
            eprintln!("skipping {name}: the case is not for this platform or this install")
        }
        Err(error) => panic!("{name}: {error}"),
    }
}

#[test]
fn default_settings() {
    run("default_settings", "default-settings.json");
}

#[test]
fn weaker_isolation_true() {
    run("weaker_isolation_true", "weaker-isolation-true.json");
}

#[test]
fn weaker_isolation_false() {
    run("weaker_isolation_false", "weaker-isolation-false.json");
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
fn move_blocking_read_glob() {
    run("move_blocking_read_glob", "move-blocking-read-glob.json");
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
fn unix_socket_listed_folder() {
    run(
        "unix_socket_listed_folder",
        "unix-sockets-listed-folder.json",
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
fn mux_http_allowed() {
    run("mux_http_allowed", "mux-http-allowed.json");
}

#[test]
fn mux_socks_allowed() {
    run("mux_socks_allowed", "mux-socks-allowed.json");
}

#[test]
fn mux_other_domain_refused() {
    run("mux_other_domain_refused", "mux-other-domain-refused.json");
}

#[test]
fn unix_socket_unlisted_is_refused() {
    run(
        "unix_socket_unlisted_is_refused",
        "unix-sockets-unlisted-is-refused.json",
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

#[test]
fn mitm_matching_domain_reaches_the_socket() {
    run(
        "mitm_matching_domain_reaches_the_socket",
        "mitm-matching-domain.json",
    );
}

#[test]
fn mitm_other_domain_goes_direct() {
    run("mitm_other_domain_goes_direct", "mitm-other-domain.json");
}

#[test]
fn mitm_bad_socket_path_is_502() {
    run("mitm_bad_socket_path_is_502", "mitm-bad-socket-path.json");
}

#[test]
fn refused_mitm_empty_domains() {
    run(
        "refused_mitm_empty_domains",
        "refused-mitm-empty-domains.json",
    );
}

#[test]
fn unix_socket_empty_string_grants_cwd() {
    run(
        "unix_socket_empty_string_grants_cwd",
        "unix-sockets-empty-string-grants-cwd.json",
    );
}

#[test]
fn resolved_address_loopback_name() {
    run(
        "resolved_address_loopback_name",
        "resolved-addresses-loopback-name.json",
    );
}

#[test]
fn resolved_address_listed_cidr() {
    run(
        "resolved_address_listed_cidr",
        "resolved-addresses-listed-cidr.json",
    );
}

#[test]
fn refused_resolved_address_bad_cidr() {
    run(
        "refused_resolved_address_bad_cidr",
        "resolved-addresses-bad-cidr.json",
    );
}

#[test]
fn local_binding_bind_refused_by_default() {
    run(
        "local_binding_bind_refused_by_default",
        "local-binding-bind-refused-by-default.json",
    );
}

#[test]
fn local_binding_bind_allowed() {
    run(
        "local_binding_bind_allowed",
        "local-binding-bind-allowed.json",
    );
}

#[test]
fn local_binding_connect_to_loopback() {
    run(
        "local_binding_connect_to_loopback",
        "local-binding-connect-to-loopback.json",
    );
}

#[test]
fn local_binding_other_host_still_refused() {
    run(
        "local_binding_other_host_still_refused",
        "local-binding-other-host-still-refused.json",
    );
}

/// A worker's policy has no `allowLocalBinding`, so nothing it runs may take a
/// port. With it, which is what a call that runs a dev server gets, the same
/// probes are allowed.
#[test]
fn kelpie_loopback_bind() {
    run("kelpie_loopback_bind", "kelpie-loopback-bind-refused.json");
    run("kelpie_bind_allowed", "kelpie-loopback-bind-allowed.json");
}

#[test]
fn kelpie_group_signal() {
    run("kelpie_group_signal", "kelpie-group-signal.json");
}

#[test]
fn kelpie_ps() {
    run("kelpie_ps", "kelpie-ps.json");
}

#[test]
fn kelpie_socket_path_104_bytes() {
    run(
        "kelpie_socket_path_104_bytes",
        "kelpie-socket-path-104-bytes.json",
    );
}

#[test]
fn kelpie_full_policy() {
    run("kelpie_full_policy", "kelpie-full-policy.json");
}
