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
