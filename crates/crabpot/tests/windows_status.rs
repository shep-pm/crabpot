//! `windows_status` runs this binary again as srt-win, so the test binary is
//! its own host: it calls `run_from_args` first, and has no libtest harness to
//! run in place of srt-win.

#[cfg(windows)]
fn main() {
    crabpot::run_from_args();
    let status = crabpot::windows_status().expect("srt-win answers the queries");
    assert_eq!(
        status.user,
        crabpot::UserState::NotProvisioned,
        "this runs on a machine with no install: {status:?}"
    );
    assert_eq!(status.setup_version.installed, None);
    assert!(crabpot::windows_preflight().is_err());
}

#[cfg(not(windows))]
fn main() {}
