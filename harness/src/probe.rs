//! The probe: one action run inside a sandbox, reported as an exit code.
//!
//! Both runners run the same `probe` binary, so a case compares exit codes.
//! The binary also prints [`REPORT`] and its code to stdout, which is how a
//! runner tells a probe that ran from a wrapper that failed before running it.

/// Exit code of an action the sandbox allowed.
pub const ALLOWED: u8 = 0;
/// Exit code of an action the sandbox refused.
pub const REFUSED: u8 = 1;
/// Exit code of a probe that could not tell, such as a missing file or bad arguments.
pub const ERROR: u8 = 2;

/// What the `probe` binary prints to stdout, before its code, once it has run.
pub const REPORT: &str = "probe exited ";

/// The variable a runner sets to the harness's own pid, which `ps-outside`
/// looks for from inside the sandbox.
pub const HARNESS_PID: &str = "CRABPOT_HARNESS_PID";

mod argument;
#[cfg(target_os = "linux")]
mod kernel;
mod socks;

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(unix)]
use std::os::unix::process::{CommandExt, ExitStatusExt};
#[cfg(unix)]
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use crate::signal;

/// Why a probe could not tell whether the sandbox allowed its action.
#[derive(Debug)]
pub enum Error {
    /// The arguments are not one of the probe actions with their operands.
    Usage,
    /// `HTTP_PROXY` is not an `http://` URL with a host.
    BadProxy,
    /// `FTP_PROXY`, which holds the SOCKS5 proxy's URL, is not a `socks5://`
    /// or `socks5h://` URL with a host.
    BadSocksProxy,
    /// The proxy's answer to `CONNECT` does not start with an HTTP status line.
    BadAnswer(String),
    /// The SOCKS5 proxy's answer does not start with version 5.
    BadSocksAnswer(Vec<u8>),
    /// [`HARNESS_PID`] is not set to a pid.
    BadHarnessPid(Option<String>),
    /// A `backslash-argument` probe was given an argument with no backslash,
    /// which proves nothing about how a backslash travels.
    NoBackslash(String),
    /// The action failed with an error that is not a refusal, such as a missing file.
    Io(std::io::Error),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Usage => f.write_str(
                "usage: probe read <path> | write <path> | rename <from> <to> | connect <host> \
                 <port> [--via socks5] | bind | bind-unix <path> | connect-unix <path> | loopback \
                 | signal-group | ps | ps-outside | backslash-argument <text> | socket <unix|vsock> | io-uring-setup | unshare-user",
            ),
            Self::BadProxy => f.write_str("HTTP_PROXY is not an http:// URL with a host"),
            Self::BadSocksProxy => {
                f.write_str("FTP_PROXY is not a socks5:// or socks5h:// URL with a host")
            }
            Self::BadAnswer(line) => write!(f, "the proxy answered {line:?}, not a status line"),
            Self::BadSocksAnswer(bytes) => {
                write!(f, "the proxy answered {bytes:?}, not a SOCKS5 reply")
            }
            Self::BadHarnessPid(value) => {
                write!(f, "{HARNESS_PID} is {value:?}, not a pid")
            }
            Self::NoBackslash(argument) => {
                write!(f, "{argument:?} has no backslash for the probe to follow")
            }
            Self::Io(source) => write!(f, "{source}"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Usage
            | Self::BadProxy
            | Self::BadSocksProxy
            | Self::BadAnswer(_)
            | Self::BadSocksAnswer(_)
            | Self::BadHarnessPid(_)
            | Self::NoBackslash(_) => None,
            Self::Io(source) => Some(source),
        }
    }
}

/// Whether the sandbox allowed the action.
type Outcome = Result<bool, Error>;

/// Runs the probe for `args` (the words after `probe`) and returns its exit code.
///
/// `http_proxy` is the value of `HTTP_PROXY`, and `socks_proxy` the value of
/// `FTP_PROXY`, which holds the SOCKS5 proxy's URL. `harness_pid` is the value
/// of [`HARNESS_PID`]. A diagnostic for an [`ERROR`] goes to stderr.
pub fn run(
    args: &[String],
    http_proxy: Option<&str>,
    socks_proxy: Option<&str>,
    harness_pid: Option<&str>,
) -> u8 {
    match attempt(args, http_proxy, socks_proxy, harness_pid) {
        Ok(true) => ALLOWED,
        Ok(false) => REFUSED,
        Err(error) => {
            eprintln!("probe: {error}");
            ERROR
        }
    }
}

#[cfg_attr(
    not(unix),
    expect(
        unused_variables,
        reason = "only `ps-outside` reads the pid, and it is Unix only"
    )
)]
fn attempt(
    args: &[String],
    http_proxy: Option<&str>,
    socks_proxy: Option<&str>,
    harness_pid: Option<&str>,
) -> Outcome {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["read", path] => read(path),
        ["write", path] => write(path),
        ["rename", from, to] => rename(from, to),
        ["connect", host, port] => connect(host, port, http_proxy),
        ["connect", host, port, "--via", "socks5"] => connect_socks(host, port, socks_proxy),
        ["bind"] => bind(),
        #[cfg(unix)]
        ["bind-unix", path] => bind_unix(path),
        #[cfg(unix)]
        ["connect-unix", path] => connect_unix(path),
        ["loopback"] => loopback(),
        #[cfg(unix)]
        ["signal-group"] => signal_group(),
        #[cfg(unix)]
        ["ps"] => ps(),
        #[cfg(unix)]
        ["ps-outside"] => ps_outside(harness_pid),
        #[cfg(target_os = "linux")]
        ["socket", family] => kernel::socket(family),
        #[cfg(target_os = "linux")]
        ["io-uring-setup"] => kernel::io_uring_setup(),
        #[cfg(target_os = "linux")]
        ["unshare-user"] => kernel::unshare_user(),
        ["backslash-argument", argument] => argument::backslash(argument),
        _ => Err(Error::Usage),
    }
}

/// Maps the error of an action to a refusal when the sandbox is what caused it.
fn judge(result: std::io::Result<()>, refusals: &[std::io::ErrorKind]) -> Outcome {
    match result {
        Ok(()) => Ok(true),
        Err(error) if refusals.contains(&error.kind()) => Ok(false),
        Err(error) => Err(Error::Io(error)),
    }
}

/// EPERM and EACCES both surface as `PermissionDenied`.
const READ_REFUSED: &[std::io::ErrorKind] = &[std::io::ErrorKind::PermissionDenied];

/// A write is also refused with EROFS, which is what bubblewrap's read-only binds answer.
const WRITE_REFUSED: &[std::io::ErrorKind] = &[
    std::io::ErrorKind::PermissionDenied,
    std::io::ErrorKind::ReadOnlyFilesystem,
];

/// A rename is also refused with EBUSY, which is what the kernel answers for a
/// path that is a mount point or holds one, and with EXDEV for one that crosses
/// mounts: how Linux's sandbox blocks a move of a protected path.
const RENAME_REFUSED: &[std::io::ErrorKind] = &[
    std::io::ErrorKind::PermissionDenied,
    std::io::ErrorKind::ReadOnlyFilesystem,
    std::io::ErrorKind::ResourceBusy,
    std::io::ErrorKind::CrossesDevices,
];

/// EPERM and ECONNREFUSED refuse a bind or a direct connect. ENETUNREACH is how a
/// network namespace with no interfaces refuses a connect.
const NETWORK_REFUSED: &[std::io::ErrorKind] = &[
    std::io::ErrorKind::PermissionDenied,
    std::io::ErrorKind::ConnectionRefused,
    std::io::ErrorKind::NetworkUnreachable,
];

fn read(path: &str) -> Outcome {
    judge(std::fs::File::open(path).map(drop), READ_REFUSED)
}

fn write(path: &str) -> Outcome {
    let opened = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(path);
    judge(opened.map(drop), WRITE_REFUSED)
}

fn rename(from: &str, to: &str) -> Outcome {
    judge(std::fs::rename(from, to), RENAME_REFUSED)
}

/// Dials `host:port` directly, or asks the proxy at `http_proxy` for a tunnel to it.
fn connect(host: &str, port: &str, http_proxy: Option<&str>) -> Outcome {
    let port: u16 = port.parse().map_err(|_| Error::Usage)?;
    match http_proxy {
        Some(url) => connect_through(url, host, port),
        None => judge(dial((host, port)).map(drop), NETWORK_REFUSED),
    }
}

/// How long to wait on a peer before calling it an error: a connect that never
/// completes, or an accept whose dial never lands.
const PATIENCE: Duration = Duration::from_secs(10);

/// Dials the first of `address`'s endpoints that answers within [`PATIENCE`].
fn dial(address: impl ToSocketAddrs) -> std::io::Result<TcpStream> {
    let mut last = None;
    for endpoint in address.to_socket_addrs()? {
        match TcpStream::connect_timeout(&endpoint, PATIENCE) {
            Ok(stream) => return Ok(stream),
            Err(error) => last = Some(error),
        }
    }
    Err(last.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "the proxy has no address")
    }))
}

/// `host:port` as a `CONNECT` target, with an IPv6 literal in brackets.
fn target(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Asks the SOCKS5 proxy at `socks_proxy` for a tunnel to `host:port`.
fn connect_socks(host: &str, port: &str, socks_proxy: Option<&str>) -> Outcome {
    let port: u16 = port.parse().map_err(|_| Error::Usage)?;
    let proxy = socks_proxy
        .and_then(Proxy::parse_socks)
        .ok_or(Error::BadSocksProxy)?;
    let io = Error::Io;
    let mut stream = dial(&proxy.address).map_err(io)?;
    stream.set_read_timeout(Some(PATIENCE)).map_err(io)?;
    let login = proxy
        .credentials
        .map(|credentials| credentials.split_once(':').unwrap_or((credentials, "")))
        .map(|(user, password)| (socks::percent_decode(user), socks::percent_decode(password)));
    socks::connect(
        &mut stream,
        login
            .as_ref()
            .map(|(user, password)| (user.as_str(), password.as_str())),
        host,
        port,
    )
}

fn connect_through(url: &str, host: &str, port: u16) -> Outcome {
    let proxy = Proxy::parse(url).ok_or(Error::BadProxy)?;
    let io = Error::Io;
    let mut stream = dial(&proxy.address).map_err(io)?;
    stream.set_read_timeout(Some(PATIENCE)).map_err(io)?;
    let auth = proxy.credentials.map_or_else(String::new, |credentials| {
        format!(
            "Proxy-Authorization: Basic {}\r\n",
            base64(credentials.as_bytes())
        )
    });
    let target = target(host, port);
    write!(
        stream,
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{auth}\r\n"
    )
    .map_err(io)?;
    let mut status_line = String::new();
    BufReader::new(stream)
        .read_line(&mut status_line)
        .map_err(io)?;
    let mut words = status_line.split_whitespace();
    let status = words
        .next()
        .filter(|version| version.starts_with("HTTP/"))
        .and_then(|_| words.next())
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| Error::BadAnswer(status_line.trim_end().to_owned()))?;
    Ok((200..300).contains(&status))
}

/// The parts of a `scheme://[user:pass@]host[:port][/]` URL that a tunnel needs.
struct Proxy<'a> {
    /// `host:port`, the port defaulting to the scheme's.
    address: String,
    /// The `user:pass` of the URL, as written.
    credentials: Option<&'a str>,
}

impl<'a> Proxy<'a> {
    /// An `http://` URL, whose port defaults to 80.
    fn parse(url: &'a str) -> Option<Self> {
        Self::parse_scheme(url, &["http://"], 80)
    }

    /// A `socks5://` or `socks5h://` URL, whose port defaults to 1080.
    fn parse_socks(url: &'a str) -> Option<Self> {
        Self::parse_scheme(url, &["socks5h://", "socks5://"], 1080)
    }

    fn parse_scheme(url: &'a str, schemes: &[&str], default_port: u16) -> Option<Self> {
        let rest = schemes.iter().find_map(|scheme| url.strip_prefix(scheme))?;
        let authority = rest.split('/').next().unwrap_or_default();
        let (credentials, host_port) = match authority.rsplit_once('@') {
            Some((credentials, host_port)) => (Some(credentials), host_port),
            None => (None, authority),
        };
        if host_port.is_empty() {
            return None;
        }
        // A colon inside a bracketed IPv6 literal is not a port separator.
        let after_host = host_port
            .rsplit_once(']')
            .map_or(host_port, |(_, rest)| rest);
        let address = if after_host.contains(':') {
            host_port.to_owned()
        } else {
            format!("{host_port}:{default_port}")
        };
        Some(Self {
            address,
            credentials,
        })
    }
}

/// Standard base64 with padding, for a `Proxy-Authorization` header.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let word = chunk.iter().enumerate().fold(0u32, |word, (at, byte)| {
            word | u32::from(*byte) << (16 - 8 * at)
        });
        for at in 0..4 {
            if at <= chunk.len() {
                out.push(char::from(
                    ALPHABET[(word >> (18 - 6 * at) & 0x3f) as usize],
                ));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn bind() -> Outcome {
    judge(
        TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).map(drop),
        NETWORK_REFUSED,
    )
}

/// How long to wait before asking a listener that has taken nothing again.
const ASK_AGAIN: Duration = Duration::from_millis(20);

/// Bind a loopback listener, dial it and accept the dial, which are the three
/// operations `allowLocalBinding` opens: `network-bind`, `network-outbound` and
/// `network-inbound`. The probe dials itself rather than a port someone else
/// opened, so a case needs no listener of its own and no port it expects to be
/// free.
fn loopback() -> Outcome {
    let listener = match TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)) {
        Ok(listener) => listener,
        Err(error) => return judge(Err(error), NETWORK_REFUSED),
    };
    let port = listener.local_addr().map_err(Error::Io)?.port();
    // So that the accept below waits for a connect still on its way instead of
    // for a peer that never dials.
    listener.set_nonblocking(true).map_err(Error::Io)?;

    // The kernel answers a connect to a listening socket before anything
    // accepts it, so the dial is read on its own.
    let dialed = match dial(("127.0.0.1", port)) {
        Ok(stream) => stream,
        Err(error) => return judge(Err(error), NETWORK_REFUSED),
    };
    let accepted = accept(&listener);
    // The dial stays open while the listener takes it, so what the accept
    // answers is the sandbox's ruling and not the end of a connection.
    drop(dialed);
    accepted
}

/// The connection `listener` is next to take. A refused one answers at once, so
/// the wait is only for a connect that has not landed.
fn accept(listener: &TcpListener) -> Outcome {
    let until = Instant::now() + PATIENCE;
    loop {
        match listener.accept() {
            Ok((_stream, _address)) => return Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= until {
                    return Err(Error::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "nothing dialed the listener",
                    )));
                }
                thread::sleep(ASK_AGAIN);
            }
            Err(error) => return judge(Err(error), NETWORK_REFUSED),
        }
    }
}

/// The longest path a Unix socket can be named by. `sun_path` is 104 bytes on
/// macOS and 108 on Linux, and the last byte of it is the terminator, so a path
/// of that length or more does not fit at all. Rust's own socket types answer
/// such a path before the kernel is asked, and the probe answers it the way a
/// refusal reads: the command cannot use that socket path. Upstream keeps the
/// limit where it hits it, and so does crabpot (ADR-0003).
#[cfg(unix)]
const SOCKET_PATH_LIMIT: usize = if cfg!(target_os = "macos") { 104 } else { 108 };

/// Whether `path` is too long for a Unix socket to be named by.
#[cfg(unix)]
fn socket_path_too_long(path: &str) -> bool {
    path.len() >= SOCKET_PATH_LIMIT
}

/// A socket the sandbox will not let the command use answers `EPERM`, which is
/// what a refused `bind` or `connect` on `AF_UNIX` gives back.
#[cfg(unix)]
const UNIX_BIND_REFUSED: &[std::io::ErrorKind] = &[std::io::ErrorKind::PermissionDenied];

/// A dial of a socket file nobody is listening on is answered, and an answer
/// is not a refusal.
#[cfg(unix)]
const UNIX_CONNECT_REFUSED: &[std::io::ErrorKind] = &[
    std::io::ErrorKind::PermissionDenied,
    std::io::ErrorKind::ConnectionRefused,
];

/// Binds a Unix socket at `path`, which is how a command takes a path the
/// profile lists for it.
#[cfg(unix)]
fn bind_unix(path: &str) -> Outcome {
    if socket_path_too_long(path) {
        return Ok(false);
    }
    judge(UnixListener::bind(path).map(drop), UNIX_BIND_REFUSED)
}

/// Dials the Unix socket at `path`, which is how a command reaches a socket
/// the profile lists for it.
#[cfg(unix)]
fn connect_unix(path: &str) -> Outcome {
    if socket_path_too_long(path) {
        return Ok(false);
    }
    judge(UnixStream::connect(path).map(drop), UNIX_CONNECT_REFUSED)
}

/// The program the probe starts as the member of the group it means to signal.
#[cfg(unix)]
const SLEEP: &str = "/bin/sleep";

/// The program that names a process and how it runs, which a host asks when it
/// decides whether a session it attached to still holds.
#[cfg(unix)]
const PS: &str = "/bin/ps";

/// How long the probe's child lives on its own, in seconds. A sandbox that
/// refuses both the group signal and the signal to the child alone still leaves
/// nothing behind once this runs out.
#[cfg(unix)]
const CHILD_LIFE: &str = "5";

/// Starts `sleep` as the leader of a process group of its own, which is how a
/// host leads a group it means to signal: the child's pid is the group's.
#[cfg(unix)]
fn start_group() -> Result<Child, Error> {
    Command::new(SLEEP)
        .arg(CHILD_LIFE)
        .process_group(0)
        .stdin(Stdio::null())
        .spawn()
        .map_err(Error::Io)
}

/// Signals the process group the probe started, and asks whether it took the
/// signal.
///
/// Allowed when the group died by it, refused when the sandbox would not let a
/// group signal through, which is what a host meets when it ends a call it
/// started inside a worker.
#[cfg(unix)]
fn signal_group() -> Outcome {
    let mut child = start_group()?;
    let group = child.id();
    match signal::signal_group(group, signal::TERM) {
        Ok(()) => {
            let ended = child.wait().map_err(Error::Io)?;
            Ok(ended.signal() == Some(signal::TERM as i32))
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            // The group is out of reach. End the child on its own so the run
            // leaves nothing behind, and report what the group signal answered.
            let _ = child.kill();
            let _ = child.wait();
            Ok(false)
        }
        Err(error) => Err(Error::Io(error)),
    }
}

/// Asks `ps` whether a process runs, which is how a host tells whether a
/// session it attached to still holds.
///
/// Allowed when `ps` names the process. Refused when `ps` cannot run at all or
/// runs and names nothing: macOS answers `EPERM` to a sandboxed command that
/// tries to run it, which is the sandbox refusing the action and not the probe
/// failing to run.
#[cfg(unix)]
fn ps() -> Outcome {
    let mut child = start_group()?;
    let asked = ps_names(child.id());
    // Whatever `ps` answered, end the child the probe started.
    let _ = child.kill();
    let _ = child.wait();
    asked
}

/// Asks `ps` whether the harness's own process runs, which it does not from
/// inside a pid namespace of the sandbox's own: `ps` lists the sandbox's pids
/// and no others.
///
/// Allowed when `ps` names the process, which is the sandbox showing what
/// runs outside it. Refused when it does not.
#[cfg(unix)]
fn ps_outside(harness_pid: Option<&str>) -> Outcome {
    let pid = harness_pid
        .and_then(|pid| pid.parse().ok())
        .ok_or_else(|| Error::BadHarnessPid(harness_pid.map(str::to_owned)))?;
    ps_names(pid)
}

/// Whether `ps` names the process `pid`.
#[cfg(unix)]
fn ps_names(pid: u32) -> Outcome {
    let asked = Command::new(PS)
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output();
    match asked {
        Ok(output) => {
            Ok(output.status.success()
                && output.stdout.iter().any(|byte| !byte.is_ascii_whitespace()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => Ok(false),
        Err(error) => Err(Error::Io(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{BufRead, BufReader, Write};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(unix)]
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};

    /// A folder unique to one test, removed with its permissions restored on drop.
    struct Fixture(PathBuf);

    impl Fixture {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("probe-{}-{name}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        #[cfg(unix)]
        fn set_mode(&self, path: &Path, mode: u32) {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            #[cfg(unix)]
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o755));
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn probe(args: &[&str]) -> u8 {
        probe_via(args, None)
    }

    fn probe_via(args: &[&str], http_proxy: Option<&str>) -> u8 {
        let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
        run(&args, http_proxy, None, None)
    }

    /// The code `ps-outside` reports when the harness's pid is `harness_pid`.
    #[cfg(unix)]
    fn probe_outside(harness_pid: Option<&str>) -> u8 {
        run(&["ps-outside".to_owned()], None, None, harness_pid)
    }

    /// A proxy on a free port that answers one request with `status`.
    /// Returns its URL, with credentials, and the thread that yields the request it saw.
    fn stand_in_proxy(status: &str) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://user:pass@{}", listener.local_addr().unwrap());
        let status = status.to_owned();
        let seen = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request = String::new();
            while !request.ends_with("\r\n\r\n") {
                if reader.read_line(&mut request).unwrap() == 0 {
                    break;
                }
            }
            write!(stream, "HTTP/1.1 {status}\r\n\r\n").unwrap();
            request
        });
        (url, seen)
    }

    fn probe_path(verb: &str, path: &Path) -> u8 {
        probe(&[verb, path.to_str().unwrap()])
    }

    #[test]
    fn read_of_a_readable_file_exits_0() {
        let fixture = Fixture::new("read-ok");
        let file = fixture.path().join("file");
        fs::write(&file, "x").unwrap();
        assert_eq!(probe_path("read", &file), 0);
    }

    #[test]
    #[cfg(unix)]
    fn read_of_an_unreadable_file_exits_1() {
        let fixture = Fixture::new("read-denied");
        let file = fixture.path().join("file");
        fs::write(&file, "x").unwrap();
        fixture.set_mode(&file, 0o000);
        assert_eq!(probe_path("read", &file), 1);
    }

    #[test]
    fn read_of_a_missing_file_exits_2() {
        let fixture = Fixture::new("read-missing");
        assert_eq!(probe_path("read", &fixture.path().join("absent")), 2);
    }

    #[test]
    fn write_into_a_writable_folder_exits_0() {
        let fixture = Fixture::new("write-ok");
        assert_eq!(probe_path("write", &fixture.path().join("file")), 0);
    }

    #[test]
    #[cfg(unix)]
    fn write_into_a_read_only_folder_exits_1() {
        let fixture = Fixture::new("write-denied");
        fixture.set_mode(fixture.path(), 0o555);
        assert_eq!(probe_path("write", &fixture.path().join("file")), 1);
    }

    #[test]
    fn rename_in_a_writable_folder_exits_0_and_moves_the_file() {
        let fixture = Fixture::new("rename-ok");
        let from = fixture.path().join("from");
        let to = fixture.path().join("to");
        fs::write(&from, "x").unwrap();
        assert_eq!(
            probe(&["rename", from.to_str().unwrap(), to.to_str().unwrap()]),
            0
        );
        assert!(to.exists() && !from.exists());
    }

    #[test]
    #[cfg(unix)]
    fn rename_in_a_read_only_folder_exits_1() {
        let fixture = Fixture::new("rename-denied");
        let from = fixture.path().join("from");
        fs::write(&from, "x").unwrap();
        fixture.set_mode(fixture.path(), 0o555);
        let to = fixture.path().join("to");
        assert_eq!(
            probe(&["rename", from.to_str().unwrap(), to.to_str().unwrap()]),
            1
        );
    }

    /// A bind mount cannot be renamed, which is how Linux's sandbox blocks a move
    /// of a protected path. The kernel answers EBUSY, as it does for `.`.
    #[cfg(target_os = "linux")]
    #[test]
    fn rename_of_a_busy_path_exits_1() {
        let fixture = Fixture::new("rename-busy");
        let from = fixture.path().join(".");
        let to = fixture.path().join("to");
        assert_eq!(
            probe(&["rename", from.to_str().unwrap(), to.to_str().unwrap()]),
            1
        );
    }

    /// A rename across mounts is EXDEV, and the kernel answers it before it looks
    /// for the source: a protected path under a tmpfs mask cannot be moved out of it.
    #[cfg(target_os = "linux")]
    #[test]
    fn rename_across_mounts_exits_1() {
        let fixture = Fixture::new("rename-exdev");
        let to = fixture.path().join("to");
        assert_eq!(
            probe(&["rename", "/proc/self/absent", to.to_str().unwrap()]),
            1
        );
    }

    #[test]
    fn rename_of_a_missing_file_exits_2() {
        let fixture = Fixture::new("rename-missing");
        let from = fixture.path().join("absent");
        let to = fixture.path().join("to");
        assert_eq!(
            probe(&["rename", from.to_str().unwrap(), to.to_str().unwrap()]),
            2
        );
    }

    #[test]
    fn bind_exits_0() {
        assert_eq!(probe(&["bind"]), 0);
    }

    /// Nothing refuses them here: the probe starts a process group, signals it,
    /// and asks `ps` about a process. Under a sandbox either can be refused,
    /// which is what the `kelpie-group-signal` and `kelpie-ps` cases pin.
    #[test]
    #[cfg(unix)]
    fn signal_group_and_ps_exit_0_unsandboxed() {
        assert_eq!(probe(&["signal-group"]), 0);
        assert_eq!(probe(&["ps"]), 0);
    }

    /// Unsandboxed the pid namespace is the harness's own, so `ps` names it.
    #[test]
    #[cfg(unix)]
    fn ps_outside_exits_0_for_a_process_it_can_see() {
        assert_eq!(probe_outside(Some(&std::process::id().to_string())), 0);
    }

    #[test]
    #[cfg(unix)]
    fn ps_outside_exits_1_for_a_process_that_is_gone() {
        let mut gone = Command::new(SLEEP).arg("0").spawn().unwrap();
        gone.wait().unwrap();
        assert_eq!(probe_outside(Some(&gone.id().to_string())), 1);
    }

    #[test]
    #[cfg(unix)]
    fn ps_outside_exits_2_without_a_pid_to_look_for() {
        assert_eq!(probe_outside(None), 2);
        assert_eq!(probe_outside(Some("harness")), 2);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn a_kernel_probe_given_the_wrong_words_exits_2() {
        assert_eq!(probe(&["socket"]), 2);
        assert_eq!(probe(&["socket", "inet"]), 2);
        assert_eq!(probe(&["io-uring-setup", "extra"]), 2);
        assert_eq!(probe(&["unshare-user", "extra"]), 2);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn a_unix_socket_is_made_unsandboxed() {
        assert_eq!(probe(&["socket", "unix"]), 0);
    }

    #[test]
    fn loopback_exits_0() {
        assert_eq!(probe(&["loopback"]), 0);
    }

    #[test]
    #[cfg(unix)]
    fn bind_unix_and_connect_unix_exit_0_on_a_free_path() {
        let fixture = Fixture::new("unix-ok");
        let bound = fixture.path().join("bound.sock");
        assert_eq!(probe_path("bind-unix", &bound), 0);

        let live = fixture.path().join("live.sock");
        let listener = UnixListener::bind(&live).unwrap();
        assert_eq!(probe_path("connect-unix", &live), 0);
        drop(listener);
    }

    #[test]
    #[cfg(unix)]
    fn connect_unix_to_a_socket_nobody_listens_on_exits_1() {
        // The file is left behind by a listener that has gone, so the dial
        // reaches it and is answered.
        let fixture = Fixture::new("unix-dead");
        let dead = fixture.path().join("dead.sock");
        UnixListener::bind(&dead).unwrap();
        assert_eq!(probe_path("connect-unix", &dead), 1);
    }

    #[test]
    #[cfg(unix)]
    fn a_unix_probe_that_reaches_no_socket_exits_2() {
        let fixture = Fixture::new("unix-absent");

        assert_eq!(
            probe_path("bind-unix", &fixture.path().join("none/absent.sock")),
            2
        );
        assert_eq!(
            probe_path("connect-unix", &fixture.path().join("absent.sock")),
            2
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_unix_probe_without_a_path_exits_2() {
        assert_eq!(probe(&["bind-unix"]), 2);
        assert_eq!(probe(&["connect-unix"]), 2);
    }

    /// A socket path of `sun_path` bytes or more is a refusal, and one byte
    /// under it is allowed. The case root a differential run names its sockets
    /// against is under the same temp folder, so the room here is the room a
    /// case has.
    #[test]
    #[cfg(unix)]
    fn a_socket_path_at_the_limit_is_refused_and_one_byte_under_is_not() {
        let fixture = Fixture::new("socket-limit");
        let dir = fixture.path().to_str().unwrap();
        // The name length that makes a path in `dir` exactly `SOCKET_PATH_LIMIT`.
        let at_the_limit = SOCKET_PATH_LIMIT - dir.len() - 1;
        assert!(
            at_the_limit > 1,
            "the temp folder {dir} leaves no room for the test"
        );

        let under = fixture.path().join("s".repeat(at_the_limit - 1));
        let at = fixture.path().join("s".repeat(at_the_limit));
        assert_eq!(
            under.as_os_str().to_string_lossy().len(),
            SOCKET_PATH_LIMIT - 1
        );
        assert_eq!(at.as_os_str().to_string_lossy().len(), SOCKET_PATH_LIMIT);

        assert_eq!(probe_path("bind-unix", &under), 0);
        assert_eq!(probe_path("bind-unix", &at), 1);
    }

    #[test]
    fn connect_through_a_proxy_that_answers_200_exits_0() {
        let (url, seen) = stand_in_proxy("200 Connection established");
        assert_eq!(probe_via(&["connect", "example.com", "443"], Some(&url)), 0);
        let request = seen.join().unwrap();
        assert!(request.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
        assert!(request.contains("\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
    }

    #[test]
    fn connect_through_a_proxy_that_answers_403_exits_1() {
        let (url, seen) = stand_in_proxy("403 Forbidden");
        assert_eq!(probe_via(&["connect", "example.com", "443"], Some(&url)), 1);
        seen.join().unwrap();
    }

    #[test]
    fn connect_with_unknown_arguments_exits_2() {
        assert_eq!(probe(&["connect", "example.com"]), 2);
        assert_eq!(probe(&["connect", "example.com", "https"]), 2);
    }

    #[test]
    fn connect_to_an_ipv6_literal_through_a_proxy_brackets_the_target() {
        let (url, seen) = stand_in_proxy("200 Connection established");
        assert_eq!(probe_via(&["connect", "::1", "443"], Some(&url)), 0);
        let request = seen.join().unwrap();
        assert!(request.starts_with("CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n"));
    }

    #[test]
    fn a_proxy_url_without_a_port_gets_port_80() {
        for (url, address) in [
            ("http://proxy", "proxy:80"),
            ("http://u:p@proxy/", "proxy:80"),
            ("http://[::1]", "[::1]:80"),
            ("http://[::1]:3128", "[::1]:3128"),
            ("http://proxy:3128", "proxy:3128"),
        ] {
            assert_eq!(Proxy::parse(url).unwrap().address, address, "{url}");
        }
    }

    #[test]
    fn a_socks_proxy_url_without_a_port_gets_port_1080() {
        for (url, address) in [
            ("socks5h://proxy", "proxy:1080"),
            ("socks5://u:p@proxy/", "proxy:1080"),
            ("socks5h://u:p@localhost:51235", "localhost:51235"),
        ] {
            assert_eq!(Proxy::parse_socks(url).unwrap().address, address, "{url}");
        }
        assert!(Proxy::parse_socks("http://proxy").is_none());
        assert!(Proxy::parse_socks("socks5h://").is_none());
    }

    #[test]
    fn connect_via_socks5_without_a_socks_proxy_exits_2() {
        let args = ["connect", "example.com", "443", "--via", "socks5"];
        let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();

        assert_eq!(run(&args, None, None, None), 2);
        assert_eq!(run(&args, None, Some("http://localhost:1"), None), 2);
    }

    #[test]
    fn a_read_only_mount_refuses_a_write_and_an_unreachable_network_refuses_a_connect() {
        use std::io::ErrorKind;
        let refused = |kind: ErrorKind, refusals| judge(Err(kind.into()), refusals).unwrap();
        assert!(!refused(ErrorKind::ReadOnlyFilesystem, WRITE_REFUSED));
        assert!(!refused(ErrorKind::NetworkUnreachable, NETWORK_REFUSED));
    }
}
