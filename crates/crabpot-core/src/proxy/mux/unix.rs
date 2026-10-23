//! The mux's Unix sockets: the HTTP backend's, and the front end's own.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::proxy::token;
use crate::unix_socket;

/// The backend sockets bound so far in this process, so that two sandboxes do
/// not name the same file.
static SEQ: AtomicUsize = AtomicUsize::new(0);

/// The backend socket's file, which goes when this goes: with a `Proxy` that
/// took it over, and at once with a proxy that never started.
#[derive(Debug)]
pub(in crate::proxy) struct Socket(PathBuf);

impl Socket {
    /// Binds a fresh `srt-mux-<pid>-<seq>.sock` in the temp dir and takes the
    /// file it names, alongside the listener bound to it. A file a process of
    /// the same pid crashed with is removed first, as upstream's
    /// `listenHttpBackend` does.
    ///
    /// Call this outside a tokio runtime, and hand the listener to tokio's
    /// `UnixListener::from_std` inside one.
    pub(in crate::proxy) fn bind() -> io::Result<(UnixListener, Self)> {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("srt-mux-{}-{seq}.sock", std::process::id()));
        let _ = fs::remove_file(&path);
        let listener = unix_socket::bind(&path)?;
        Ok((listener, Self(path)))
    }

    /// The path to dial to reach the HTTP backend.
    pub(in crate::proxy) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// What a sandbox's own socket is open to: its owner alone.
const OWNER_ONLY: u32 = 0o600;

/// The front end's Unix socket, which a sandboxed command dials where a loopback
/// port cannot reach it. It carries the whole mux, both protocols, and is served
/// by [`dispatch`](super::dispatch) exactly as the port is.
///
/// Its file is only for the sandbox that bound it, so it is mode 0600, and it
/// goes when the `Proxy` that started it goes.
#[derive(Debug)]
pub(in crate::proxy) struct Front(PathBuf);

impl Front {
    /// Binds a fresh `claude-http-<16 hex>.sock` in the temp dir, which is how
    /// upstream names it, and hands back the listener bound to it and its path.
    /// The file is mode 0600, and nothing is accepted from it before that is set.
    ///
    /// Call this outside a tokio runtime, and hand the listener to tokio's
    /// `UnixListener::from_std` inside one.
    ///
    /// # Errors
    ///
    /// The [`io::Error`] of whatever failed: reading random bytes for the name,
    /// binding, or setting the mode. A socket bound before the mode failed is
    /// removed before this returns.
    pub(in crate::proxy) fn bind() -> io::Result<(UnixListener, Self)> {
        let path = std::env::temp_dir().join(format!("claude-http-{}.sock", token::random_hex(8)?));
        let listener = unix_socket::bind(&path)?;
        let front = Self(path);
        fs::set_permissions(&front.0, fs::Permissions::from_mode(OWNER_ONLY))?;
        Ok((listener, front))
    }

    /// The path to dial to reach the mux.
    pub(in crate::proxy) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Front {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
