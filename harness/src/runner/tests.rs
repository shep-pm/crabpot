#[cfg(unix)]
use super::wrapper::{exit_code, refusal};
use super::*;
use std::cell::{Cell, RefCell};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(unix)]
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::json;

/// Answers each probe with what `answer` says.
struct StandIn(&'static str, fn(&Probe) -> u8);

impl Runner for StandIn {
    fn name(&self) -> &'static str {
        self.0
    }

    fn run(&self, _settings: &Path, probe: &Probe, _env: &Env) -> Result<u8, Error> {
        Ok((self.1)(probe))
    }

    fn refuses(&self, _settings: &Path, _probe: &Probe, _env: &Env) -> Result<bool, Error> {
        Ok(false)
    }
}

fn case() -> Case {
    Case {
        files: Vec::new(),
        settings: json!({}),
        refused: false,
        serve: None,
        env: Env::new(),
        upstream: Vec::new(),
        probes: vec![Probe::Read("/r/in".to_owned()), Probe::Bind],
        platforms: Vec::new(),
    }
}

fn compare_with(upstream: fn(&Probe) -> u8, crabpot: fn(&Probe) -> u8) -> Result<(), Error> {
    compare(
        &case(),
        Path::new("/r/settings.json"),
        &|| Ok(()),
        &StandIn("upstream", upstream),
        &StandIn("crabpot", crabpot),
    )
}

#[test]
fn differing_probe_outcomes_fail_the_case() {
    let outcome = compare_with(
        |_| probe::ALLOWED,
        |probe| match probe {
            Probe::Bind => probe::REFUSED,
            _ => probe::ALLOWED,
        },
    );
    assert!(matches!(
        outcome,
        Err(Error::Differ {
            probe: Probe::Bind,
            upstream: probe::ALLOWED,
            crabpot: probe::REFUSED,
        })
    ));
}

#[test]
fn matching_probe_outcomes_pass_the_case() {
    let outcome = compare_with(
        |probe| match probe {
            Probe::Bind => probe::REFUSED,
            _ => probe::ALLOWED,
        },
        |probe| match probe {
            Probe::Bind => probe::REFUSED,
            _ => probe::ALLOWED,
        },
    );
    outcome.unwrap();
}

/// A case whose one probe records upstream as exiting 1.
fn difference_case() -> Case {
    Case {
        probes: vec![Probe::BackslashArgument {
            value: r"C:\work".to_owned(),
        }],
        upstream: vec![Some(1)],
        ..case()
    }
}

fn compare_difference(upstream: u8, crabpot: u8) -> Result<(), Error> {
    compare_recorded(&difference_case(), upstream, crabpot)
}

fn compare_recorded(case: &Case, upstream: u8, crabpot: u8) -> Result<(), Error> {
    let answer = |code: u8| -> fn(&Probe) -> u8 {
        match code {
            0 => |_| 0,
            1 => |_| 1,
            _ => |_| 2,
        }
    };
    compare(
        case,
        Path::new("/r/settings.json"),
        &|| Ok(()),
        &StandIn("upstream", answer(upstream)),
        &StandIn("crabpot", answer(crabpot)),
    )
}

/// A case whose one `write` probe records upstream as exiting 1.
fn write_difference_case() -> Case {
    Case {
        probes: vec![Probe::Write("/r/tmp/out".to_owned())],
        upstream: vec![Some(1)],
        ..case()
    }
}

#[test]
fn a_recorded_difference_on_a_write_probe_passes_when_crabpot_differs() {
    compare_recorded(&write_difference_case(), 1, 0).unwrap();
}

#[test]
fn a_recorded_difference_on_a_write_probe_fails_when_crabpot_agrees() {
    assert!(matches!(
        compare_recorded(&write_difference_case(), 1, 1),
        Err(Error::NotDifferent {
            probe: Probe::Write(_),
            upstream: 1,
            crabpot: 1,
        })
    ));
}

/// A write into a folder only crabpot makes cannot be told by upstream, which
/// exits [`probe::ERROR`]; the case records that and it is not an error.
#[test]
fn a_recorded_difference_may_be_a_probe_upstream_could_not_tell() {
    let case = Case {
        upstream: vec![Some(probe::ERROR)],
        ..write_difference_case()
    };

    compare_recorded(&case, probe::ERROR, probe::ALLOWED).unwrap();
    assert!(matches!(
        compare_recorded(&case, probe::ALLOWED, probe::ALLOWED),
        Err(Error::Changed { .. })
    ));
    assert!(matches!(
        compare_recorded(&case, probe::ERROR, probe::ERROR),
        Err(Error::Erred {
            runner: "crabpot",
            ..
        })
    ));
}

/// Remembers the environment each run was given.
struct Recording<'a>(&'static str, &'a RefCell<Vec<Env>>);

impl Runner for Recording<'_> {
    fn name(&self) -> &'static str {
        self.0
    }

    fn run(&self, _settings: &Path, _probe: &Probe, env: &Env) -> Result<u8, Error> {
        self.1.borrow_mut().push(env.clone());
        Ok(probe::ALLOWED)
    }

    fn refuses(&self, _settings: &Path, _probe: &Probe, _env: &Env) -> Result<bool, Error> {
        unreachable!("a compared case is not a refused one")
    }
}

#[test]
fn both_runners_get_the_environment_the_case_sets() {
    let seen = RefCell::new(Vec::new());
    let case = Case {
        env: Env::from([("CLAUDE_CODE_TMPDIR".to_owned(), "/r/fresh".to_owned())]),
        ..case()
    };

    compare(
        &case,
        Path::new("/r/settings.json"),
        &|| Ok(()),
        &Recording("upstream", &seen),
        &Recording("crabpot", &seen),
    )
    .unwrap();

    let seen = seen.into_inner();
    assert_eq!(seen.len(), 4, "two probes under two runners");
    assert!(seen.iter().all(|env| *env == case.env), "{seen:?}");
}

#[test]
fn a_recorded_difference_passes_when_upstream_gives_its_code_and_crabpot_another() {
    compare_difference(1, 0).unwrap();
}

#[test]
fn a_recorded_difference_fails_when_crabpot_gives_upstreams_code() {
    assert!(matches!(
        compare_difference(1, 1),
        Err(Error::NotDifferent {
            upstream: 1,
            crabpot: 1,
            ..
        })
    ));
}

#[test]
fn a_recorded_difference_fails_when_upstream_gives_another_code() {
    assert!(matches!(
        compare_difference(0, 0),
        Err(Error::Changed {
            recorded: 1,
            upstream: 0,
            ..
        })
    ));
}

/// A runner that fails the moment it is asked for anything.
struct Never(&'static str);

impl Runner for Never {
    fn name(&self) -> &'static str {
        self.0
    }

    fn run(&self, _settings: &Path, _probe: &Probe, _env: &Env) -> Result<u8, Error> {
        unreachable!("{} ran a case that means another platform", self.0)
    }

    fn refuses(&self, _settings: &Path, _probe: &Probe, _env: &Env) -> Result<bool, Error> {
        unreachable!("{} ran a case that means another platform", self.0)
    }
}

/// A one-probe case that names the platform this test does not run on.
fn elsewhere_case() -> String {
    let elsewhere = match Platform::current() {
        Platform::MacOs | Platform::Windows => "linux",
        Platform::Linux => "macos",
    };
    format!(
        r#"{{"files": {{}}, "settings": {{}}, "platforms": ["{elsewhere}"], "probes": [{{"kind": "bind"}}]}}"#
    )
}

#[test]
fn a_case_that_names_another_platform_runs_on_neither_runner() {
    let text = elsewhere_case();
    assert!(!run_case(&text, "elsewhere", &Never("upstream"), &Never("crabpot")).unwrap());
    assert!(!run_upstream_only(&text, "elsewhere", &Never("upstream")).unwrap());
}

/// One runner alone has nothing to agree with, so a probe it refuses and a
/// probe it allows are both a case that passes, and so is one that reported a
/// code and could not tell what the sandbox did: with nothing to compare the
/// answer with, the answer is the finding, and it goes to the log. A runner
/// that never ran the probe is not.
#[test]
fn one_runner_alone_runs_a_case_without_comparing_it() {
    let text =
        r#"{"files": {}, "settings": {}, "probes": [{"kind": "bind"}, {"kind": "loopback"}]}"#;
    let ran = run_upstream_only(
        text,
        "upstream_only",
        &StandIn("upstream", |probe| match probe {
            Probe::Bind => probe::REFUSED,
            _ => probe::ALLOWED,
        }),
    )
    .unwrap();
    assert!(ran);

    assert!(
        run_upstream_only(
            text,
            "upstream_only",
            &StandIn("upstream", |_| probe::ERROR)
        )
        .unwrap(),
        "a probe that could not tell is the finding under one runner, not a failure"
    );
}

#[test]
fn one_runner_alone_must_refuse_a_refused_case() {
    let text = r#"{"files": {}, "settings": "", "refused": true, "probes": [{"kind": "bind"}]}"#;
    assert!(run_upstream_only(text, "refused_only", &Refusing("upstream", true)).unwrap());
    assert!(matches!(
        run_upstream_only(text, "refused_only", &Refusing("upstream", false)),
        Err(Error::NotRefused {
            runner: "upstream",
            probe: Probe::Bind,
        })
    ));
}

/// A case's served socket is under its root, so the root must outlive the
/// serve: a listener whose path is gone has no connect that ends the accept
/// its serve thread waits in, and the case never ends.
#[test]
#[cfg(unix)]
fn a_case_stops_its_served_socket_before_it_removes_its_root() {
    let text = r#"{"files": {}, "settings": {}, "serve": {"unixSocket": "$ROOT/mitm.sock", "status": "200 OK"}, "probes": [{"kind": "bind"}]}"#;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let upstream: &dyn Runner = &StandIn("upstream", |_| probe::ALLOWED);
        let _ = tx.send(run_case_under(text, "served_socket", &[upstream]));
    });
    let outcome = rx.recv_timeout(std::time::Duration::from_secs(10)).expect(
        "the case never ended: its served socket waited on a path its root had already removed",
    );
    assert!(outcome.unwrap());
}

/// The same order on the way out that a panic takes. A runner that panics must
/// reach the caller as a panic, and the test process must end: unwinding drops
/// `Prepared`, and its `Drop` stops the served socket before the root takes the
/// socket's path with it.
#[test]
#[cfg(unix)]
fn a_case_ends_when_a_runner_panics_under_it() {
    struct Panicking(&'static str);

    impl Runner for Panicking {
        fn name(&self) -> &'static str {
            self.0
        }

        fn run(&self, _settings: &Path, _probe: &Probe, _env: &Env) -> Result<u8, Error> {
            panic!("the runner is broken")
        }

        fn refuses(&self, _settings: &Path, _probe: &Probe, _env: &Env) -> Result<bool, Error> {
            unreachable!("the case is not a refused one")
        }
    }

    let text = r#"{"files": {}, "settings": {}, "serve": {"unixSocket": "$ROOT/mitm.sock", "status": "200 OK"}, "probes": [{"kind": "bind"}]}"#;
    // The panic is the point of the test, so its hook output is kept out of the
    // log. The hook goes back before anything here asserts, which its own
    // failure has to reach the log.
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let upstream: &dyn Runner = &Panicking("upstream");
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_case_under(text, "panicking_runner", &[upstream])
        }));
        let _ = tx.send(unwound.is_err());
    });
    let ended = rx.recv_timeout(std::time::Duration::from_secs(10));
    std::panic::set_hook(hook);
    assert!(
        ended.expect("the case never ended: the panic unwound past the served socket, which waited on a path its root had already removed"),
        "the runner's panic reached the caller"
    );
}

/// Runs a probe by dialing the socket at a `connect-unix` probe's path,
/// resolving a relative one against the case root as a wrapper's working
/// directory does.
#[cfg(unix)]
struct Dialer;

#[cfg(unix)]
impl Runner for Dialer {
    fn name(&self) -> &'static str {
        "dialer"
    }

    fn run(&self, settings: &Path, probe: &Probe, _env: &Env) -> Result<u8, Error> {
        let Probe::ConnectUnix(path) = probe else {
            return Ok(probe::ALLOWED);
        };
        let path = socket_path(settings, path);
        match UnixStream::connect(path) {
            Ok(_) => Ok(probe::ALLOWED),
            Err(_) => Ok(probe::REFUSED),
        }
    }

    fn refuses(&self, _settings: &Path, _probe: &Probe, _env: &Env) -> Result<bool, Error> {
        Ok(false)
    }
}

#[test]
#[cfg(unix)]
fn a_connect_unix_probe_finds_a_socket_served_for_it() {
    let root = std::env::temp_dir().join(format!("crabpot-serve-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let case = Case {
        probes: vec![
            // A case names its socket against the case root, which is where
            // each wrapper runs, and the harness serves it there too.
            Probe::ConnectUnix("live.sock".to_owned()),
            Probe::ConnectUnix(root.join("named.sock").display().to_string()),
        ],
        ..case()
    };

    let outcome = compare(
        &case,
        &root.join("settings.json"),
        &|| Ok(()),
        &Dialer,
        &StandIn("always", |_| probe::ALLOWED),
    );

    let _ = fs::remove_dir_all(&root);
    outcome.unwrap();
}

#[test]
#[cfg(unix)]
fn a_case_folder_leaves_room_for_a_socket_under_it() {
    let root = Root::new("unix_socket_listed_folder").unwrap();
    let socket = Path::new(&root.0).join("socks/live.sock");
    fs::create_dir_all(socket.parent().unwrap()).unwrap();
    // macOS caps a Unix socket path at `sun_path`, 104 bytes, and a bind
    // onto a longer one fails before the sandbox is asked anything.
    UnixListener::bind(&socket).unwrap();
}

#[test]
fn a_probe_that_exits_2_fails_the_case_even_when_both_agree() {
    let outcome = compare_with(|_| probe::ERROR, |_| probe::ERROR);
    assert!(matches!(
        outcome,
        Err(Error::Erred {
            runner: "upstream",
            probe: Probe::Read(_),
        })
    ));
}

/// A read deny on Linux hides a folder under an empty tmpfs, so a probe of a
/// file the case made in it reads a path that is not there and exits 2. Both
/// runners doing so is the answer; a path the case never made is a typo.
#[test]
fn a_read_of_a_file_the_case_made_may_exit_2_when_both_runners_do() {
    let hidden = Case {
        files: vec![(PathBuf::from("/r/in"), String::new())],
        ..case()
    };
    let run = |upstream: fn(&Probe) -> u8, crabpot: fn(&Probe) -> u8| {
        compare(
            &hidden,
            Path::new("/r/settings.json"),
            &|| Ok(()),
            &StandIn("upstream", upstream),
            &StandIn("crabpot", crabpot),
        )
    };
    let hides = |probe: &Probe| match probe {
        Probe::Read(_) => probe::ERROR,
        _ => probe::ALLOWED,
    };

    run(hides, hides).unwrap();
    assert!(matches!(
        run(hides, |_| probe::REFUSED),
        Err(Error::Differ {
            probe: Probe::Read(_),
            upstream: probe::ERROR,
            crabpot: probe::REFUSED,
        })
    ));
}

/// Runs only on a restored fixture, which its run then spoils.
struct Spoiling<'a>(&'static str, &'a Cell<bool>);

impl Runner for Spoiling<'_> {
    fn name(&self) -> &'static str {
        self.0
    }

    fn run(&self, _settings: &Path, _probe: &Probe, _env: &Env) -> Result<u8, Error> {
        assert!(self.1.replace(false), "{} ran on a spoiled fixture", self.0);
        Ok(probe::ALLOWED)
    }

    fn refuses(&self, _settings: &Path, _probe: &Probe, _env: &Env) -> Result<bool, Error> {
        unreachable!("a compared case is not a refused one")
    }
}

#[test]
fn each_runner_gets_a_restored_fixture_for_each_probe() {
    let clean = Cell::new(false);
    compare(
        &case(),
        Path::new("/r/settings.json"),
        &|| {
            clean.set(true);
            Ok(())
        },
        &Spoiling("upstream", &clean),
        &Spoiling("crabpot", &clean),
    )
    .unwrap();
}

#[cfg(unix)]
fn sh(script: &str) -> Command {
    let mut command = Command::new("sh");
    command.args(["-c", script]);
    command
}

#[test]
#[cfg(unix)]
fn a_wrapper_that_fails_before_the_probe_runs_is_not_a_refusal() {
    let outcome = exit_code(sh("echo 'crabpot: bad settings' >&2; exit 1"), "crabpot");
    assert!(matches!(
        outcome,
        Err(Error::Unreported {
            runner: "crabpot",
            status: 1
        })
    ));
}

#[test]
#[cfg(unix)]
fn the_code_a_probe_reports_is_the_wrappers_status() {
    let outcome = exit_code(sh("echo 'probe exited 1'; exit 1"), "upstream");
    assert_eq!(outcome.unwrap(), probe::REFUSED);
}

#[test]
#[cfg(unix)]
fn a_status_the_probe_did_not_report_is_not_a_probe_outcome() {
    let outcome = exit_code(sh("echo 'probe exited 0'; exit 71"), "upstream");
    assert!(matches!(
        outcome,
        Err(Error::Unreported {
            runner: "upstream",
            status: 71
        })
    ));
}

#[test]
#[cfg(unix)]
fn a_wrapper_that_exits_1_without_its_probe_refuses() {
    assert!(refusal(sh("echo 'crabpot: bad settings' >&2; exit 1"), "crabpot").unwrap());
}

#[test]
#[cfg(unix)]
fn a_wrapper_whose_probe_ran_did_not_refuse() {
    assert!(!refusal(sh("echo 'probe exited 0'; exit 0"), "upstream").unwrap());
    assert!(!refusal(sh("echo 'probe exited 1'; exit 1"), "upstream").unwrap());
}

#[test]
#[cfg(unix)]
fn a_wrapper_that_fails_in_another_way_is_not_a_refusal() {
    assert!(matches!(
        refusal(sh("exit 71"), "upstream"),
        Err(Error::Unreported {
            runner: "upstream",
            status: 71
        })
    ));
}

/// Refuses, or says it ran, as built.
struct Refusing(&'static str, bool);

impl Runner for Refusing {
    fn name(&self) -> &'static str {
        self.0
    }

    fn run(&self, _settings: &Path, _probe: &Probe, _env: &Env) -> Result<u8, Error> {
        unreachable!("a refused case is not run")
    }

    fn refuses(&self, _settings: &Path, _probe: &Probe, _env: &Env) -> Result<bool, Error> {
        Ok(self.1)
    }
}

fn refused_case(marker: &Path) -> Case {
    Case {
        probes: vec![Probe::Write(marker.display().to_string())],
        refused: true,
        ..case()
    }
}

fn compare_refused_with(
    case: &Case,
    upstream: &dyn Runner,
    crabpot: &dyn Runner,
) -> Result<(), Error> {
    compare_refused(
        case,
        Path::new("/r/settings.json"),
        &|| Ok(()),
        upstream,
        crabpot,
    )
}

#[test]
fn a_case_passes_when_both_runners_refuse_and_leave_no_marker() {
    let case = refused_case(Path::new("/r/never-written"));
    compare_refused_with(
        &case,
        &Refusing("upstream", true),
        &Refusing("crabpot", true),
    )
    .unwrap();
}

#[test]
fn a_runner_that_does_not_refuse_fails_the_case() {
    let case = refused_case(Path::new("/r/never-written"));
    let outcome = compare_refused_with(
        &case,
        &Refusing("upstream", true),
        &Refusing("crabpot", false),
    );
    assert!(matches!(
        outcome,
        Err(Error::NotRefused {
            runner: "crabpot",
            ..
        })
    ));
}

#[test]
fn a_marker_left_behind_fails_the_case_even_when_both_refuse() {
    let marker = std::env::current_exe().unwrap();
    let case = refused_case(&marker);
    let outcome = compare_refused_with(
        &case,
        &Refusing("upstream", true),
        &Refusing("crabpot", true),
    );
    assert!(matches!(
        outcome,
        Err(Error::NotRefused {
            runner: "upstream",
            ..
        })
    ));
}

/// Upstream wraps an argument with a backslash in single quotes, which `cmd`
/// does not read as quotes, so a Windows root is spelled with forward slashes
/// and without the `\\?\` prefix `canonicalize` gives it.
#[test]
fn a_windows_path_is_spelled_with_forward_slashes_for_upstream() {
    for (path, spelled) in [
        (
            r"\\?\C:\Users\runner\Temp\c1-case",
            "C:/Users/runner/Temp/c1-case",
        ),
        (r"C:\Users\runner\Temp", "C:/Users/runner/Temp"),
        (r"\\?\UNC\host\share\dir", r"\\?\UNC\host\share\dir"),
        ("/tmp/c1-case", "/tmp/c1-case"),
    ] {
        assert_eq!(spell_for_upstream(path), spelled, "{path}");
    }
}

/// Each sandbox's proxies take two loopback ports from the range the installed
/// filters permit, so the range holds half as many sandboxes as it has ports.
/// `cargo test` runs one case per logical CPU, and a machine with more CPUs than
/// the range holds ports ran more sandboxes than the range could answer for.
#[test]
fn the_gate_holds_half_the_proxy_port_range() {
    // The range `windows-install` leaves open unless it is told another.
    assert_eq!(sandboxes_in_range(60080, 60089), 5);
    // The odd port out holds no sandbox.
    assert_eq!(sandboxes_in_range(60080, 60090), 5);
    assert_eq!(sandboxes_in_range(60080, 60081), 1);
    // The widest range an install may take is 65 ports.
    assert_eq!(sandboxes_in_range(60001, 60065), 32);
    // A range too narrow to pair holds no sandbox, and the gate still lets one
    // through: the case gets the answer a sandbox that cannot bind gives, and
    // not a harness that waits for a slot that never frees.
    assert_eq!(sandboxes_in_range(60080, 60080), 1);
}

/// A slot is held for the whole probe run that took it, so a gate of `n` never
/// has more than `n` runs inside it at once.
#[test]
fn a_gate_holds_no_more_than_its_capacity_at_once() {
    let gate = Gate::new(2);
    let live = AtomicUsize::new(0);
    let peak = AtomicUsize::new(0);
    let ran = AtomicUsize::new(0);

    std::thread::scope(|scope| {
        for _ in 0..6 {
            scope.spawn(|| {
                let _slot = gate.acquire();
                let held = live.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(held, Ordering::SeqCst);
                std::thread::sleep(std::time::Duration::from_millis(20));
                live.fetch_sub(1, Ordering::SeqCst);
                ran.fetch_add(1, Ordering::SeqCst);
            });
        }
    });

    assert_eq!(ran.load(Ordering::SeqCst), 6, "every run reached the gate");
    assert_eq!(
        live.load(Ordering::SeqCst),
        0,
        "every run gave its slot back"
    );
    assert!(
        (1..=2).contains(&peak.load(Ordering::SeqCst)),
        "the gate held {} at once, and its capacity is 2",
        peak.load(Ordering::SeqCst)
    );
}

#[test]
fn a_runner_alone_must_give_every_probe_the_expected_code() {
    let expect_with = |answer: fn(&Probe) -> u8| {
        expect(
            &case(),
            Path::new("/r/settings.json"),
            &|| Ok(()),
            &StandIn("crabpot", answer),
            probe::ALLOWED,
        )
    };

    expect_with(|_| probe::ALLOWED).unwrap();
    assert!(matches!(
        expect_with(|probe| match probe {
            Probe::Bind => probe::REFUSED,
            _ => probe::ALLOWED,
        }),
        Err(Error::Unexpected {
            runner: "crabpot",
            probe: Probe::Bind,
            expected: probe::ALLOWED,
            got: probe::REFUSED,
        })
    ));
}
