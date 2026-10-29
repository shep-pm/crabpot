//! A sandbox started on a machine where an install has run, and a command run
//! through it. Like `windows_status`, it is its own host for the `--srt-win`
//! relaunch: the wrapped command runs this binary again as `srt-win exec`. The
//! other commands are this binary once more: `--print-arg <text>` prints its
//! argument back, `--print-env <name>` prints one variable and `--probe <stat |
//! list | read> <path>` prints `ok` (and the file, for `read`) or `denied`.

#[cfg(windows)]
const PRINT_ARG: &str = "--print-arg";
#[cfg(windows)]
const ARGUMENT: &str = "line one\nline \"two\" %PATH%";
#[cfg(windows)]
const WRAPPER_VARIABLE: &str = "CRABPOT_WRAPPER_VARIABLE";

#[cfg(windows)]
fn main() {
    crabpot::run_from_args();
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some(PRINT_ARG) => {
            print!("{}", args.next().expect("an argument to print"));
            return;
        }
        Some("--print-env") => {
            let name = args.next().expect("--print-env names a variable");
            print!("{}", std::env::var(name).unwrap_or_default());
            return;
        }
        Some("--probe") => {
            let operation = args.next().expect("--probe names an operation");
            let path = args.next().expect("--probe names a path");
            print!("{}", probe(&operation, &path));
            return;
        }
        _ => {}
    }
    a_command_runs_in_the_sandbox();
    the_wrapper_keeps_its_environment_but_not_the_profile();
    the_folders_between_a_deny_and_a_grant_can_be_statd();
}

/// What `--probe` prints: `ok`, with the file after it for `read`, or `denied`.
#[cfg(windows)]
fn probe(operation: &str, path: &str) -> String {
    use std::fs;

    let outcome = match operation {
        "stat" => fs::metadata(path).map(|_| String::new()),
        "list" => fs::read_dir(path).map(|_| String::new()),
        "read" => fs::read_to_string(path),
        other => panic!("unknown --probe operation {other}"),
    };
    match outcome {
        Ok(text) => format!("ok{text}"),
        Err(_) => "denied".to_owned(),
    }
}

#[cfg(windows)]
fn a_command_runs_in_the_sandbox() {
    use std::process::Command;

    // The same check `Sandbox::start` makes below, read ahead of it: this test
    // binary is the runner a sandboxed command launches.
    let status = crabpot::windows_status().expect("srt-win answers the queries");
    assert_eq!(
        status.runner_readable,
        Some(true),
        "the sandbox user can read this test binary: {status:?}"
    );

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

/// A sandbox that denies reading a folder and allows reading a file two folders
/// beneath it: the command can stat the folders between, cannot list them, and
/// can read the file.
#[cfg(windows)]
fn the_folders_between_a_deny_and_a_grant_can_be_statd() {
    use std::fs;
    use std::process::Command;

    let denied = std::env::temp_dir().join(format!("crabpot-metadata-{}", std::process::id()));
    let between = denied.join("one").join("two");
    fs::create_dir_all(&between).expect("the folders are made");
    let file = between.join("granted.txt");
    fs::write(&file, "granted").expect("the file is written");
    let path = |path: &std::path::Path| path.to_str().expect("a UTF-8 path").to_owned();
    let config = crabpot::Config::from_json(
        &serde_json::json!({
            "network": {"allowedDomains": [], "deniedDomains": []},
            "filesystem": {
                "denyRead": [path(&denied)],
                "allowRead": [path(&file)],
                "allowWrite": [],
                "denyWrite": [],
            }
        })
        .to_string(),
    )
    .expect("the settings are valid");
    let sandbox =
        crabpot::Sandbox::start(&config).expect("a sandbox starts where the install has run");
    let probe_of = |operation: &str, target: &std::path::Path| {
        let mut probe = Command::new(std::env::current_exe().expect("the test binary has a path"));
        probe.args(["--probe", operation]).arg(target);
        let output = sandbox
            .command(&probe)
            .expect("the command is wrapped")
            .output()
            .expect("srt-win launches the command");
        String::from_utf8_lossy(&output.stdout).into_owned()
    };

    let outcomes = (
        probe_of("stat", &denied.join("one")),
        probe_of("stat", &between),
        probe_of("list", &between),
        probe_of("read", &file),
    );

    drop(sandbox);
    fs::remove_dir_all(&denied).ok();
    assert_eq!(
        outcomes,
        (
            "ok".to_owned(),
            "ok".to_owned(),
            "denied".to_owned(),
            "okgranted".to_owned()
        )
    );
}

#[cfg(not(windows))]
fn main() {}
