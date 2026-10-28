//! A sandbox started on a machine where an install has run, and a command run
//! through it. Like `windows_status`, it is its own host for the `--srt-win`
//! relaunch: the wrapped command runs this binary again as `srt-win exec`.
//! It is its own command too: `--print-env <name>` prints one variable.

#[cfg(windows)]
const WRAPPER_VARIABLE: &str = "CRABPOT_WRAPPER_VARIABLE";

#[cfg(windows)]
fn main() {
    crabpot::run_from_args();
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() == Some("--print-env") {
        let name = args.next().expect("--print-env names a variable");
        print!("{}", std::env::var(name).unwrap_or_default());
        return;
    }
    a_command_runs_in_the_sandbox();
    the_wrapper_keeps_its_environment_but_not_the_profile();
}

#[cfg(windows)]
fn a_command_runs_in_the_sandbox() {
    use std::process::Command;

    let sandbox = crabpot::Sandbox::start(&crabpot::Config::default())
        .expect("a sandbox starts where the install has run");
    let mut echo = Command::new("cmd");
    echo.args(["/c", "echo", "crabpot-windows-tracer"]);

    let output = sandbox
        .command(&echo)
        .expect("the command is wrapped")
        .output()
        .expect("srt-win launches the command");

    assert!(
        output.status.success(),
        "{:?}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("crabpot-windows-tracer"),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

/// Runs this binary as `--crabpot -- <itself> --print-env <name>` with
/// [`WRAPPER_VARIABLE`] set on the wrapper, and returns what the command printed.
#[cfg(windows)]
fn printed_through_the_wrapper(name: &str) -> String {
    use std::process::Command;

    let me = std::env::current_exe().expect("the test binary has a path");
    let output = Command::new(&me)
        .env(WRAPPER_VARIABLE, "set-on-the-wrapper")
        .args(["--crabpot", "--"])
        .arg(&me)
        .args(["--print-env", name])
        .output()
        .expect("the wrapper runs");
    assert!(
        output.status.success(),
        "{:?}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

#[cfg(windows)]
fn the_wrapper_keeps_its_environment_but_not_the_profile() {
    assert_eq!(
        printed_through_the_wrapper(WRAPPER_VARIABLE),
        "set-on-the-wrapper"
    );
    let wrappers_profile = std::env::var("USERPROFILE").expect("the host has a profile");
    let childs_profile = printed_through_the_wrapper("USERPROFILE");
    assert!(!childs_profile.is_empty(), "the command has a profile");
    assert!(
        !childs_profile.eq_ignore_ascii_case(&wrappers_profile),
        "{childs_profile} is the wrapper's profile"
    );
}

#[cfg(not(windows))]
fn main() {}
