//! A sandbox started on a machine where an install has run, and a command run
//! through it. Like `windows_status`, it is its own host for the `--srt-win`
//! relaunch: the wrapped command runs this binary again as `srt-win exec`. The
//! second command is this binary once more, as an executable that prints its
//! argument back.

#[cfg(windows)]
fn main() {
    use std::process::Command;

    const PRINT_ARG: &str = "--print-arg";
    const ARGUMENT: &str = "line one\nline \"two\" %PATH%";

    crabpot::run_from_args();
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() == Some(PRINT_ARG) {
        print!("{}", args.next().expect("an argument to print"));
        return;
    }
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

    let mut print = Command::new(std::env::current_exe().expect("the test binary has a path"));
    print.arg(PRINT_ARG).arg(ARGUMENT);

    let output = sandbox
        .command(&print)
        .expect("the command is wrapped")
        .output()
        .expect("srt-win launches the command");

    assert!(
        output.status.success(),
        "{:?}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), ARGUMENT);
}

#[cfg(not(windows))]
fn main() {}
