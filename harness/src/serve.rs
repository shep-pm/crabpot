//! The peer a case serves for its probes to reach: a Unix socket that answers
//! the request head it is given with the status the case names, and echoes what
//! follows it. On Windows the socket is an AF_UNIX one through Winsock.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

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

use peer::Stream;

/// How long a served connection may go quiet before the harness drops it, which
/// bounds how long dropping a server can wait on one that will not close.
const PATIENCE: Duration = Duration::from_secs(2);

/// How far a request head may grow before the connection is dropped.
const MAX_HEAD_BYTES: usize = 64 * 1024;

/// A Unix socket served while one case's probes run. It stops when it is dropped.
#[derive(Debug)]
pub struct Served {
    socket: PathBuf,
    running: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Served {
    /// Listens on the Unix socket at `socket`, answering each request head with
    /// `status` and echoing what comes after it.
    ///
    /// # Errors
    ///
    /// The [`io::Error`] of a socket that cannot be bound, or of the thread that
    /// serves it.
    pub fn start(socket: &Path, status: &str) -> Result<Self, io::Error> {
        let _ = fs::remove_file(socket);
        let listener = peer::bind(socket)?;
        let running = Arc::new(AtomicBool::new(true));
        let serving = Arc::clone(&running);
        let answer = status.to_owned();
        let thread = thread::Builder::new()
            .name("crabpot-harness-serve".to_owned())
            .spawn(move || {
                while serving.load(Ordering::SeqCst) {
                    match peer::accept(&listener) {
                        Ok(stream) => serve(stream, &answer),
                        Err(_) => break,
                    }
                }
            })?;
        Ok(Self {
            socket: socket.to_path_buf(),
            running,
            thread: Some(thread),
        })
    }
}

impl Drop for Served {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        // A connect, closed at once, is what ends the accept the thread waits in.
        let _ = peer::connect(&self.socket);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
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
        if let Some(at) = head.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        if head.len() > MAX_HEAD_BYTES {
            return;
        }
    };
    let _ = stream.write_all(format!("HTTP/1.1 {status}\r\n\r\n").as_bytes());
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

    #[test]
    fn a_served_socket_answers_the_status_and_echoes() {
        let fixture = Fixture::new("answer");
        let socket = fixture.socket();
        let served = Served::start(&socket, "200 Connection Established").unwrap();

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

    #[test]
    fn dropping_a_served_socket_ends_a_tunnel_open_on_it() {
        let fixture = Fixture::new("drop");
        let socket = fixture.socket();
        let served = Served::start(&socket, "200 Connection Established").unwrap();

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
