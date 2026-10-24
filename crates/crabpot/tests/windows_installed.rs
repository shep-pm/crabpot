//! `windows_status` on a machine where an install has run, by crabpot's
//! `windows-install` or by upstream's `windows-install`: both leave the same
//! user, sublayer and setup version. Like `windows_status`, it is its own host
//! for the `--srt-win` relaunch.

#[cfg(windows)]
fn main() {
    crabpot::run_from_args();
    let status = crabpot::windows_status().expect("srt-win answers the queries");
    assert_eq!(
        status.user,
        crabpot::UserState::Provisioned,
        "this runs on a machine with an install: {status:?}"
    );
    assert_eq!(
        status.setup_version.installed,
        Some(status.setup_version.expected)
    );
    assert_eq!(status.loopback, crabpot::LoopbackMode::Closed);
}

#[cfg(not(windows))]
fn main() {}
