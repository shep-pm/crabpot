//! The peer a case serves for its probes to reach: a Unix socket, or on Windows
//! a named pipe, that answers the request head it is given with the status the
//! case names, and echoes what follows it. On Windows a Unix socket is an
//! AF_UNIX one through Winsock.

use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::case::Endpoint;

#[cfg(unix)]
mod peer {
    use std::io;
    use std::path::Path;

    pub(super) use std::os::unix::net::{UnixListener as Listener, UnixStream as Stream};

    pub(super) fn bind(path: &Path) -> io::Result<Listener> {
        Listener::bind(path)
    }

    pub(super) fn accept(listener: &Listener) -> io::Result<Stream> {
        listener.accept().map(|(stream, _)| stream)
    }

    pub(super) fn connect(path: &Path) -> io::Result<Stream> {
        Stream::connect(path)
    }
}

#[cfg(windows)]
mod peer {
    use std::io;
    use std::path::Path;

    pub(super) use std::net::TcpStream as Stream;

    pub(super) use crate::win32::Listener;

    pub(super) fn bind(path: &Path) -> io::Result<Listener> {
        Listener::bind(path)
    }

    pub(super) fn accept(listener: &Listener) -> io::Result<Stream> {
        listener.accept()
    }

    pub(super) fn connect(path: &Path) -> io::Result<Stream> {
        crate::win32::connect_unix(path)
    }
}

/// A Windows named pipe, served from a runtime of its own.
#[cfg(windows)]
mod pipe {
    use std::fs::OpenOptions;
    use std::io;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::thread::{self, JoinHandle};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use tokio::runtime::Builder;
    use tokio::time::timeout;

    use super::{MAX_HEAD_BYTES, PATIENCE, head_end, reply};

    /// Listens on the pipe `name`, which is open for connections once this
    /// returns.
    ///
    /// # Errors
    ///
    /// The [`io::Error`] of a pipe that cannot be created, or of the thread that
    /// serves it.
    pub(super) fn start(
        name: &str,
        status: &str,
        running: Arc<AtomicBool>,
    ) -> io::Result<JoinHandle<()>> {
        let (name, status) = (name.to_owned(), status.to_owned());
        let (ready, created) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("crabpot-harness-serve".to_owned())
            .spawn(move || {
                let outcome = Builder::new_current_thread()
                    .enable_io()
                    .enable_time()
                    .build()
                    .and_then(|runtime| {
                        runtime.block_on(async {
                            let first = ServerOptions::new()
                                .first_pipe_instance(true)
                                .create(&name)?;
                            let _ = ready.send(Ok(()));
                            accept(first, &name, &status, &running).await;
                            Ok(())
                        })
                    });
                if let Err(error) = outcome {
                    let _ = ready.send(Err(error));
                }
            })?;
        created
            .recv()
            .map_err(|_| io::Error::other("the pipe thread ended before it made the pipe"))??;
        Ok(thread)
    }

    /// Serves one connection at a time. The next instance exists before the
    /// current one is served, so a client never finds the pipe gone.
    async fn accept(mut server: NamedPipeServer, name: &str, status: &str, running: &AtomicBool) {
        while running.load(Ordering::SeqCst) {
            if server.connect().await.is_err() {
                break;
            }
            let Ok(next) = ServerOptions::new().create(name) else {
                break;
            };
            let connected = std::mem::replace(&mut server, next);
            if running.load(Ordering::SeqCst) {
                serve(connected, status).await;
            }
        }
    }

    /// One connection, as [`super::serve`] serves one.
    async fn serve(mut stream: NamedPipeServer, status: &str) {
        let mut buf = [0u8; 4096];
        let mut head = Vec::new();
        let end = loop {
            let Ok(Ok(read)) = timeout(PATIENCE, stream.read(&mut buf)).await else {
                return;
            };
            if read == 0 {
                return;
            }
            head.extend_from_slice(&buf[..read]);
            if let Some(end) = head_end(&head) {
                break end;
            }
            if head.len() > MAX_HEAD_BYTES {
                return;
            }
        };
        if stream.write_all(reply(status).as_bytes()).await.is_err()
            || stream.write_all(&head[end..]).await.is_err()
        {
            return;
        }
        while let Ok(Ok(read)) = timeout(PATIENCE, stream.read(&mut buf)).await {
            if read == 0 || stream.write_all(&buf[..read]).await.is_err() {
                break;
            }
        }
    }

    /// A connect, closed at once, which ends the accept the thread waits in.
    pub(super) fn wake(name: &str) {
        let _ = OpenOptions::new().read(true).write(true).open(name);
    }
}

#[cfg(not(windows))]
mod pipe {
    use std::io;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::thread::JoinHandle;

    pub(super) fn start(
        _name: &str,
        _status: &str,
        _running: Arc<AtomicBool>,
    ) -> io::Result<JoinHandle<()>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the harness serves a named pipe only on Windows",
        ))
    }

    pub(super) fn wake(_name: &str) {}
}

use peer::Stream;

/// How long a served connection may go quiet before the harness drops it, which
/// bounds how long dropping a server can wait on one that will not close.
const PATIENCE: Duration = Duration::from_secs(2);

/// How far a request head may grow before the connection is dropped.
const MAX_HEAD_BYTES: usize = 64 * 1024;

/// A Unix socket or named pipe served while one case's probes run. It stops
/// when it is dropped.
#[derive(Debug)]
pub struct Served {
    endpoint: Endpoint,
    running: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Served {
    /// Listens on `endpoint`, answering each request head with `status` and
    /// echoing what comes after it.
    ///
    /// # Errors
    ///
    /// The [`io::Error`] of an endpoint that cannot be bound, of the thread that
    /// serves it, or of a named pipe asked for off Windows.
    pub fn start(endpoint: &Endpoint, status: &str) -> Result<Self, io::Error> {
        let running = Arc::new(AtomicBool::new(true));
        let thread = match endpoint {
            Endpoint::UnixSocket(socket) => {
                start_socket(Path::new(socket), status, Arc::clone(&running))?
            }
            Endpoint::NamedPipe(name) => pipe::start(name, status, Arc::clone(&running))?,
        };
        Ok(Self {
            endpoint: endpoint.clone(),
            running,
            thread: Some(thread),
        })
    }
}

/// Listens on the Unix socket at `socket`.
fn start_socket(
    socket: &Path,
    status: &str,
    running: Arc<AtomicBool>,
) -> io::Result<JoinHandle<()>> {
    let _ = fs::remove_file(socket);
    let listener = peer::bind(socket)?;
    let answer = status.to_owned();
    thread::Builder::new()
        .name("crabpot-harness-serve".to_owned())
        .spawn(move || {
            while running.load(Ordering::SeqCst) {
                match peer::accept(&listener) {
                    Ok(stream) => serve(stream, &answer),
                    Err(_) => break,
                }
            }
        })
}

impl Drop for Served {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        // A connect, closed at once, is what ends the accept the thread waits in.
        match &self.endpoint {
            Endpoint::UnixSocket(socket) => {
                let _ = peer::connect(Path::new(socket));
            }
            Endpoint::NamedPipe(name) => pipe::wake(name),
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Where a request head ends in `bytes`, after its blank line.
fn head_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|at| at + 4)
}

/// The answer to a request head.
fn reply(status: &str) -> String {
    format!("HTTP/1.1 {status}\r\n\r\n")
}

/// One connection: read the request head, answer it, then echo what the peer
/// sends, including what it sent in the same packet as the head.
fn serve(mut stream: Stream, status: &str) {
    let _ = stream.set_read_timeout(Some(PATIENCE));
    let mut buf = [0u8; 4096];
    let mut head = Vec::new();
    let end = loop {
        let Ok(read) = stream.read(&mut buf) else {
            return;
        };
        if read == 0 {
            return;
        }
        head.extend_from_slice(&buf[..read]);
        if let Some(end) = head_end(&head) {
            break end;
        }
        if head.len() > MAX_HEAD_BYTES {
            return;
        }
    };
    let _ = stream.write_all(reply(status).as_bytes());
    let _ = stream.flush();
    if stream.write_all(&head[end..]).is_err() {
        return;
    }
    while let Ok(read) = stream.read(&mut buf) {
        if read == 0 || stream.write_all(&buf[..read]).is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader};
    use std::path::PathBuf;

    use super::*;

    /// A folder of its own, removed on drop.
    struct Fixture(PathBuf);

    impl Fixture {
        fn new(test: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("harness-serve-{}-{test}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn socket(&self) -> PathBuf {
            self.0.join("s")
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn endpoint_of(socket: &Path) -> Endpoint {
        Endpoint::UnixSocket(socket.to_str().unwrap().to_owned())
    }

    #[test]
    fn a_served_socket_answers_the_status_and_echoes() {
        let fixture = Fixture::new("answer");
        let socket = fixture.socket();
        let served = Served::start(&endpoint_of(&socket), "200 Connection Established").unwrap();

        let mut client = peer::connect(&socket).unwrap();
        client.set_read_timeout(Some(PATIENCE)).unwrap();
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\npayload")
            .unwrap();
        client.flush().unwrap();
        let mut reader = BufReader::new(&client);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert_eq!(line, "HTTP/1.1 200 Connection Established\r\n");
        let mut blank = String::new();
        reader.read_line(&mut blank).unwrap();
        assert_eq!(blank, "\r\n");

        let mut echoed = [0u8; 7];
        reader.read_exact(&mut echoed).unwrap();
        assert_eq!(&echoed, b"payload");

        drop(served);
        assert!(
            peer::connect(&socket).is_err(),
            "the socket is served no more"
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_served_pipe_answers_the_status_and_echoes() {
        let name = format!(r"\\.\pipe\harness-serve-{}-answer", std::process::id());
        let served = Served::start(
            &Endpoint::NamedPipe(name.clone()),
            "200 Connection Established",
        )
        .unwrap();

        let mut client = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&name)
            .unwrap();
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\npayload")
            .unwrap();
        let expected = b"HTTP/1.1 200 Connection Established\r\n\r\npayload";
        let mut answer = vec![0u8; expected.len()];
        client.read_exact(&mut answer).unwrap();
        assert_eq!(answer, expected);

        drop(client);
        drop(served);
        assert!(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&name)
                .is_err(),
            "the pipe is served no more"
        );
    }

    #[test]
    fn dropping_a_served_socket_ends_a_tunnel_open_on_it() {
        let fixture = Fixture::new("drop");
        let socket = fixture.socket();
        let served = Served::start(&endpoint_of(&socket), "200 Connection Established").unwrap();

        let mut client = peer::connect(&socket).unwrap();
        client.set_read_timeout(Some(PATIENCE * 4)).unwrap();
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
            .unwrap();
        client.flush().unwrap();
        let mut answer = String::new();
        BufReader::new(&client).read_line(&mut answer).unwrap();
        assert_eq!(answer, "HTTP/1.1 200 Connection Established\r\n");

        drop(served);

        let mut rest = Vec::new();
        client.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty());
    }
}
