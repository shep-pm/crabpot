//! A sandbox started on a machine where an install has run, and a command run
//! through it. Like `windows_status`, it is its own host for the `--srt-win`
//! relaunch: the wrapped command runs this binary again as `srt-win exec`.

#[cfg(windows)]
fn main() {
    use std::process::Command;

    crabpot::run_from_args();
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

#[cfg(not(windows))]
fn main() {}
