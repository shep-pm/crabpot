//! `--control-fd` reads JSON lines that replace the network lists of the
//! running sandbox. The cases drive the `crabpot` binary, which gets the
//! descriptor the way a host without a run loop hands it: through a shell's
//! redirect.

#![cfg(unix)]

use std::fs::{self, File};
use std::io::{BufRead, BufReader, PipeWriter, Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

const CRABPOT: &str = env!("CARGO_BIN_EXE_crabpot");

/// Real time bounds every wait on the sandbox and the shell it runs.
const TIMEOUT: Duration = Duration::from_secs(60);

/// A folder of the case's own, holding settings that allow nothing.
fn home(case: &str) -> PathBuf {
    let home = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("cf-{case}-{}", std::process::id()));
    // The proxy's socket, `claude-http-<16 hex>.sock`, is made in this folder,
    // and a `sockaddr_un` takes 107 bytes of path.
    let socket = home.as_os_str().len() + "/claude-http-0123456789abcdef.sock".len();
    assert!(
        socket <= 107,
        "{} is too long for the proxy's socket",
        home.display()
    );
    fs::create_dir_all(&home).unwrap();
    fs::write(home.join("settings.json"), line(&[])).unwrap();
    home
}

/// A config that allows `allowed` and nothing else, as one line.
fn line(allowed: &[&str]) -> String {
    format!(
        "{}\n",
        serde_json::json!({
            "network": {"allowedDomains": allowed, "deniedDomains": []},
            "filesystem": {"denyRead": [], "allowWrite": [], "denyWrite": []},
        })
    )
}

/// A wrapper that is ended when the case is, so a hung case leaves nothing
/// running. It leads a process group of its own, which holds what it started.
#[derive(Debug)]
struct Wrapper(Child);

impl Drop for Wrapper {
    fn drop(&mut self) {
        let group = format!("-{}", self.0.id());
        let _ = Command::new("kill").args(["-KILL", "--", &group]).status();
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Starts crabpot on `script` with `descriptor` as the launcher's standard
/// input, which a shell redirect moves to the redirect's descriptor.
fn launch(home: &Path, redirect: &str, descriptor: Stdio, script: &str) -> Wrapper {
    let child = Command::new("sh")
        .args(["-c", &format!(r#"exec "$@" {redirect}"#), "sh", CRABPOT])
        .args(["--control-fd", "3", "-s"])
        .arg(home.join("settings.json"))
        .args(["--", "sh", "-c", script])
        .env("HOME", home)
        .env("TMPDIR", home)
        .env("CLAUDE_CODE_TMPDIR", home.join("tmp"))
        .stdin(descriptor)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .unwrap();
    Wrapper(child)
}

/// What `wrapper` printed and how it ended, or a panic when it outlives
/// [`TIMEOUT`], which ends it.
fn finish(mut wrapper: Wrapper) -> (Option<i32>, String, String) {
    let (mut out, mut err) = (
        wrapper.0.stdout.take().unwrap(),
        wrapper.0.stderr.take().unwrap(),
    );
    let (done, printed) = mpsc::channel();
    thread::spawn(move || {
        let (mut stdout, mut stderr) = (String::new(), String::new());
        let _ = out.read_to_string(&mut stdout);
        let _ = err.read_to_string(&mut stderr);
        let _ = done.send((stdout, stderr));
    });
    let (stdout, stderr) = printed
        .recv_timeout(TIMEOUT)
        .expect("the wrapper ended in time");
    (wrapper.0.wait().unwrap().code(), stdout, stderr)
}

#[test]
fn the_command_cannot_read_the_control_descriptor() {
    let home = home("withheld");
    let (read, write) = std::io::pipe().unwrap();
    // The write end stays open here, so a read of the real pipe would block.
    let child = launch(
        &home,
        "3<&0 </dev/null",
        Stdio::from(read),
        "cat <&3; echo withheld",
    );

    let (code, stdout, stderr) = finish(child);

    assert_eq!((code, stdout.as_str()), (Some(0), "withheld\n"), "{stderr}");
    drop(write);
    fs::remove_dir_all(home).unwrap();
}

#[test]
fn a_failing_descriptor_before_the_first_line_refuses_the_command_with_exit_125() {
    let home = home("failing");
    // Reading a directory fails at once.
    let child = launch(
        &home,
        "3<&0 </dev/null",
        Stdio::from(File::open(&home).unwrap()),
        "echo ran",
    );

    let (code, stdout, stderr) = finish(child);

    assert_eq!((code, stdout.as_str()), (Some(125), ""), "{stderr}");
    assert!(
        stderr.contains("cannot read the control descriptor"),
        "{stderr}"
    );
    fs::remove_dir_all(home).unwrap();
}

/// The port of an origin on loopback that answers every request with a 200.
fn origin() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("the origin binds");
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for connection in listener.incoming() {
            let Ok(mut client) = connection else { continue };
            let mut head = Vec::new();
            let mut buf = [0u8; 1024];
            while !head.ends_with(b"\r\n\r\n") {
                match client.read(&mut buf) {
                    Ok(read @ 1..) => head.extend_from_slice(&buf[..read]),
                    _ => break,
                }
            }
            let _ = client
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });
    port
}

/// The lines `child` prints to standard output, as they come.
fn lines_of(child: &mut Wrapper) -> Receiver<String> {
    let stdout = child.0.stdout.take().unwrap();
    let (send, lines) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if send.send(line).is_err() {
                break;
            }
        }
    });
    lines
}

#[test]
fn a_line_written_while_the_command_runs_changes_what_it_can_reach() {
    // Linux needs bwrap, user namespaces and curl, which only CI is known to
    // have.
    if cfg!(target_os = "linux") && std::env::var_os("CI").is_none() {
        eprintln!("skipped: set CI to run a Linux sandbox");
        return;
    }
    let home = home("lines");
    let port = origin();
    // The sandbox exempts loopback from the proxy. `--noproxy` replaces that
    // list, so the request goes through the proxy the environment names.
    let probe = format!(
        "curl -s -o /dev/null -w '%{{http_code}}' --max-time 20 \
         --noproxy example.invalid http://127.0.0.1:{port}/"
    );
    let script = format!(
        r#"[ "$({probe})" = 403 ] || exit 3
echo shut
n=0
until [ "$({probe})" = 200 ]; do
  n=$((n + 1)); [ $n -lt 150 ] || exit 4; sleep 0.2
done
echo open"#
    );
    let (read, mut write): (_, PipeWriter) = std::io::pipe().unwrap();
    let mut child = launch(&home, "3<&0 </dev/null", Stdio::from(read), &script);
    let lines = lines_of(&mut child);

    assert_eq!(lines.recv_timeout(TIMEOUT).as_deref(), Ok("shut"));
    write.write_all(line(&["127.0.0.1"]).as_bytes()).unwrap();
    let opened = lines.recv_timeout(TIMEOUT);

    assert_eq!(opened.as_deref(), Ok("open"));
    drop(write);
    assert!(child.0.wait().unwrap().success());
    fs::remove_dir_all(home).unwrap();
}
