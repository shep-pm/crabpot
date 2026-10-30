//! What the seccomp filters and the pid namespace refuse, under crabpot's
//! wrapper alone. Upstream is not run: each probe has one right answer,
//! whatever upstream says, and a case that compares the two runners needs Node.

#![cfg(target_os = "linux")]

use std::fs;
use std::path::PathBuf;

use crabpot_harness::case::{Env, Family, Probe};
use crabpot_harness::probe;
use crabpot_harness::runner::{Crabpot, Runner};

const SETTINGS: &str = r#"{
    "network": {"allowedDomains": [], "deniedDomains": []},
    "filesystem": {"denyRead": [], "allowRead": [], "allowWrite": [], "denyWrite": []}
}"#;

/// The code `probe` reports under a default sandbox. The folder is the
/// wrapper's home and working directory, one a test.
fn under_crabpot(name: &str, probe: &Probe) -> u8 {
    let home: PathBuf = [env!("CARGO_TARGET_TMPDIR"), "linux", name]
        .iter()
        .collect();
    fs::create_dir_all(&home).unwrap();
    let settings = home.join("settings.json");
    fs::write(&settings, SETTINGS).unwrap();
    Crabpot::new(env!("CARGO_BIN_EXE_probe"))
        .run(&settings, probe, &Env::new())
        .unwrap_or_else(|error| panic!("{name}: {error}"))
}

#[test]
fn af_unix_socket_creation_is_refused() {
    let code = under_crabpot("af-unix", &Probe::Socket(Family::Unix));

    assert_eq!(code, probe::REFUSED);
}

#[test]
fn af_vsock_socket_creation_is_refused() {
    let code = under_crabpot("af-vsock", &Probe::Socket(Family::Vsock));

    assert_eq!(code, probe::REFUSED);
}

#[test]
fn io_uring_setup_is_refused() {
    let code = under_crabpot("io-uring", &Probe::IoUringSetup);

    assert_eq!(code, probe::REFUSED);
}

#[test]
fn a_nested_user_namespace_is_refused() {
    let code = under_crabpot("unshare-user", &Probe::UnshareUser);

    assert_eq!(code, probe::REFUSED);
}

#[test]
fn ps_lists_the_sandbox_and_not_the_harness() {
    let code = under_crabpot("ps-outside", &Probe::PsOutside);

    assert_eq!(code, probe::REFUSED);
}
