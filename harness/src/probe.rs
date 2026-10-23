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

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::Duration;

/// Why a probe could not tell whether the sandbox allowed its action.
#[derive(Debug)]
pub enum Error {
    /// The arguments are not one of the probe actions with their operands.
    Usage,
    /// `HTTP_PROXY` is not an `http://` URL with a host.
    BadProxy,
    /// The proxy's answer to `CONNECT` does not start with an HTTP status line.
    BadAnswer(String),
    /// The action failed with an error that is not a refusal, such as a missing file.
    Io(std::io::Error),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Usage => f.write_str(
                "usage: probe read <path> | write <path> | connect <host> <port> | bind | \
                 bind-unix <path> | connect-unix <path>",
            ),
            Self::BadProxy => f.write_str("HTTP_PROXY is not an http:// URL with a host"),
            Self::BadAnswer(line) => write!(f, "the proxy answered {line:?}, not a status line"),
            Self::Io(source) => write!(f, "{source}"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Usage | Self::BadProxy | Self::BadAnswer(_) => None,
            Self::Io(source) => Some(source),
        }
    }
}

/// Whether the sandbox allowed the action.
type Outcome = Result<bool, Error>;

/// Runs the probe for `args` (the words after `probe`) and returns its exit code.
///
/// `http_proxy` is the value of `HTTP_PROXY`. A diagnostic for an [`ERROR`] goes to stderr.
pub fn run(args: &[String], http_proxy: Option<&str>) -> u8 {
    match attempt(args, http_proxy) {
        Ok(true) => ALLOWED,
        Ok(false) => REFUSED,
        Err(error) => {
            eprintln!("probe: {error}");
            ERROR
        }
    }
}

fn attempt(args: &[String], http_proxy: Option<&str>) -> Outcome {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["read", path] => read(path),
        ["write", path] => write(path),
        ["connect", host, port] => connect(host, port, http_proxy),
        ["bind"] => bind(),
        ["bind-unix", path] => bind_unix(path),
        ["connect-unix", path] => connect_unix(path),
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

/// Dials `host:port` directly, or asks the proxy at `http_proxy` for a tunnel to it.
fn connect(host: &str, port: &str, http_proxy: Option<&str>) -> Outcome {
    let port: u16 = port.parse().map_err(|_| Error::Usage)?;
    match http_proxy {
        Some(url) => connect_through(url, host, port),
        None => judge(dial((host, port)).map(drop), NETWORK_REFUSED),
    }
}

/// How long to wait on a peer that has stopped answering before calling it an error.
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

fn connect_through(url: &str, host: &str, port: u16) -> Outcome {
    let proxy = Proxy::parse(url)?;
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

/// The parts of an `http://[user:pass@]host[:port][/]` URL that a tunnel needs.
struct Proxy<'a> {
    /// `host:port`, the port defaulting to 80.
    address: String,
    /// The `user:pass` of the URL, as written.
    credentials: Option<&'a str>,
}

impl<'a> Proxy<'a> {
    fn parse(url: &'a str) -> Result<Self, Error> {
        let rest = url.strip_prefix("http://").ok_or(Error::BadProxy)?;
        let authority = rest.split('/').next().unwrap_or_default();
        let (credentials, host_port) = match authority.rsplit_once('@') {
            Some((credentials, host_port)) => (Some(credentials), host_port),
            None => (None, authority),
        };
        if host_port.is_empty() {
            return Err(Error::BadProxy);
        }
        // A colon inside a bracketed IPv6 literal is not a port separator.
        let after_host = host_port
            .rsplit_once(']')
            .map_or(host_port, |(_, rest)| rest);
        let address = if after_host.contains(':') {
            host_port.to_owned()
        } else {
            format!("{host_port}:80")
        };
        Ok(Self {
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
        std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).map(drop),
        NETWORK_REFUSED,
    )
}

/// A socket the sandbox will not let the command use answers `EPERM`, which is
/// what a refused `bind` or `connect` on `AF_UNIX` gives back.
const UNIX_BIND_REFUSED: &[std::io::ErrorKind] = &[std::io::ErrorKind::PermissionDenied];

/// A dial of a socket file nobody is listening on is answered, and an answer
/// is not a refusal.
const UNIX_CONNECT_REFUSED: &[std::io::ErrorKind] = &[
    std::io::ErrorKind::PermissionDenied,
    std::io::ErrorKind::ConnectionRefused,
];

/// Binds a Unix socket at `path`, which is how a command takes a path the
/// profile lists for it.
fn bind_unix(path: &str) -> Outcome {
    judge(UnixListener::bind(path).map(drop), UNIX_BIND_REFUSED)
}

/// Dials the Unix socket at `path`, which is how a command reaches a socket
/// the profile lists for it.
fn connect_unix(path: &str) -> Outcome {
    judge(UnixStream::connect(path).map(drop), UNIX_CONNECT_REFUSED)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};
    use std::thread;

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

        fn set_mode(&self, path: &Path, mode: u32) {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o755));
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn probe(args: &[&str]) -> u8 {
        probe_via(args, None)
    }

    fn probe_via(args: &[&str], http_proxy: Option<&str>) -> u8 {
        let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
        run(&args, http_proxy)
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
    fn write_into_a_read_only_folder_exits_1() {
        let fixture = Fixture::new("write-denied");
        fixture.set_mode(fixture.path(), 0o555);
        assert_eq!(probe_path("write", &fixture.path().join("file")), 1);
    }

    #[test]
    fn bind_exits_0() {
        assert_eq!(probe(&["bind"]), 0);
    }

    #[test]
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
    fn connect_unix_to_a_socket_nobody_listens_on_exits_1() {
        // The file is left behind by a listener that has gone, so the dial
        // reaches it and is answered.
        let fixture = Fixture::new("unix-dead");
        let dead = fixture.path().join("dead.sock");
        UnixListener::bind(&dead).unwrap();
        assert_eq!(probe_path("connect-unix", &dead), 1);
    }

    #[test]
    fn a_unix_probe_that_reaches_no_socket_exits_2() {
        let fixture = Fixture::new("unix-absent");

        assert_eq!(probe_path("bind-unix", &fixture.path().join("none/absent.sock")), 2);
        assert_eq!(probe_path("connect-unix", &fixture.path().join("absent.sock")), 2);
    }

    #[test]
    fn a_unix_probe_without_a_path_exits_2() {
        assert_eq!(probe(&["bind-unix"]), 2);
        assert_eq!(probe(&["connect-unix"]), 2);
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
    fn a_read_only_mount_refuses_a_write_and_an_unreachable_network_refuses_a_connect() {
        use std::io::ErrorKind;
        let refused = |kind: ErrorKind, refusals| judge(Err(kind.into()), refusals).unwrap();
        assert!(!refused(ErrorKind::ReadOnlyFilesystem, WRITE_REFUSED));
        assert!(!refused(ErrorKind::NetworkUnreachable, NETWORK_REFUSED));
    }
}
