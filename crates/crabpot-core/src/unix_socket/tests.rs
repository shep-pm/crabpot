use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::thread;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Builder;

use super::{MAX_PATH, bind, connect};

/// A folder of its own, and the paths in it of exact lengths.
struct Fixture(PathBuf);

impl Fixture {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("sock-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    /// A socket path in this folder that is `len` bytes long.
    fn socket_of(&self, len: usize) -> PathBuf {
        let dir = self.0.as_os_str().len() + 1;
        let name = "s".repeat(len - dir);
        let path = self.0.join(name);
        assert_eq!(path.as_os_str().len(), len);
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Binds `path`, dials it, and sends a byte each way.
fn round_trip(path: &Path) {
    let listener = bind(path).unwrap();
    listener.set_nonblocking(false).unwrap();
    let server = thread::spawn(move || {
        let (mut client, _) = listener.accept().unwrap();
        let mut byte = [0u8];
        client.read_exact(&mut byte).unwrap();
        client.write_all(&[byte[0] + 1]).unwrap();
    });
    let runtime = Builder::new_current_thread().enable_io().build().unwrap();
    runtime.block_on(async {
        let mut stream = connect(path).await.unwrap();
        stream.write_all(&[41]).await.unwrap();
        let mut answer = [0u8];
        stream.read_exact(&mut answer).await.unwrap();
        assert_eq!(answer, [42], "{} bytes", path.as_os_str().len());
    });
    server.join().unwrap();
}

/// The lengths a path round-trips at: the ones past `sun_path` are macOS's to
/// take, and a Linux kernel refuses them as it does for upstream.
#[cfg(target_os = "macos")]
const LENGTHS: [usize; 4] = [103, 104, 110, 120];
#[cfg(not(target_os = "macos"))]
const LENGTHS: [usize; 1] = [103];

#[test]
fn a_path_binds_and_dials_at_every_length_the_platform_takes() {
    let fixture = Fixture::new("lengths");
    for len in LENGTHS {
        round_trip(&fixture.socket_of(len));
    }
}

#[test]
fn the_longest_path_the_platform_takes_round_trips() {
    let fixture = Fixture::new("longest");
    round_trip(&fixture.socket_of(MAX_PATH));
}

#[test]
fn a_path_past_the_most_is_refused_with_its_name_and_the_limit() {
    let fixture = Fixture::new("too-long");
    let path = fixture.socket_of(MAX_PATH + 1);
    let expected = format!(
        "the socket path {} is {} bytes, and this platform takes {MAX_PATH} at most",
        path.display(),
        MAX_PATH + 1,
    );

    let bound = bind(&path).unwrap_err();
    assert_eq!(bound.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(bound.to_string(), expected);

    let runtime = Builder::new_current_thread().enable_io().build().unwrap();
    let dialed = runtime.block_on(connect(&path)).unwrap_err();
    assert_eq!(dialed.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(dialed.to_string(), expected);
    assert!(!path.exists(), "nothing was bound");
}

#[test]
fn a_path_with_a_nul_is_refused() {
    let fixture = Fixture::new("nul");
    let path = fixture.0.join("a\0b");
    let error = bind(&path).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(
        error.to_string(),
        format!("the socket path {} holds a NUL byte", path.display()),
    );
}

#[test]
fn dialing_a_path_nothing_listens_on_is_the_kernels_error() {
    let fixture = Fixture::new("missing");
    let runtime = Builder::new_current_thread().enable_io().build().unwrap();
    let error = runtime
        .block_on(connect(&fixture.socket_of(110)))
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
}
