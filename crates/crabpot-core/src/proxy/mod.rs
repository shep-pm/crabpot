//! The proxies a sandboxed command reaches the network through, as upstream's
//! `src/sandbox/http-proxy.ts` and `src/sandbox/socks-proxy.ts` serve them.
//!
//! Both answer on the one loopback port upstream's mux shows the child, and both
//! run on one thread crabpot owns (ADR-0006), so a caller needs no runtime of
//! its own. They judge a host by the same filter, the address it resolves to by
//! the same guard, and a client by the same token.

mod filter;
mod guard;
mod host;
mod http;
mod mitm;
mod mux;
mod shared;
mod socks;
#[cfg(test)]
mod testing;
#[cfg(test)]
mod tests;
mod token;

use core::fmt;
use std::io;
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use tokio::runtime::Builder;
use tokio::sync::oneshot;

pub use token::{basic_for, username_for};

use crate::address::AddressRange;
use crate::config::MitmProxy;
use crate::domain::DomainEntry;
use filter::Filter;
use guard::Guard;
use shared::{Shared, serve};
use token::Token;

/// A running HTTP proxy and SOCKS5 proxy, on the one loopback port and on a
/// Unix socket.
///
/// They stop when it is dropped, the tunnels open through them end with it, and
/// the Unix sockets they are served from go with it.
pub struct Proxy {
    port: u16,
    token: Token,
    stop: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
    /// The mux's own Unix socket, which a sandbox that can reach no loopback
    /// port dials instead.
    mux: mux::Front,
    /// Last, so it goes after the listeners that were served from it have.
    socket: mux::Socket,
}

impl Proxy {
    /// Starts the proxies, which let a client reach the hosts `allowed` covers
    /// and no host `denied` covers, which beat `allowed`. A name they dial may
    /// not resolve to a loopback, link-local, multicast, broadcast, unspecified
    /// or cloud metadata address, to one of this host's own addresses, or to
    /// one `listed` holds, unless an IP literal in `allowed` names it.
    ///
    /// `strict` is `network.strictAllowlist`, which changes nothing about what
    /// this proxy lets through yet: crabpot has no ask callback and no
    /// per-command allow list for it to gate.
    ///
    /// `mitm` is `network.mitmProxy`: the domains it names are sent to its Unix
    /// socket instead of being dialed direct, for the HTTP proxy alone.
    ///
    /// # Errors
    ///
    /// The [`io::Error`] of whatever failed: reading the token, binding the port
    /// or a socket, or starting the runtime or its thread. A socket bound before
    /// a later step failed is removed before this returns.
    pub fn start(
        allowed: &[DomainEntry],
        denied: &[DomainEntry],
        listed: &[AddressRange],
        strict: bool,
        mitm: Option<&MitmProxy>,
    ) -> io::Result<Self> {
        let token = Token::generate()?;
        // The backend is bound before either front end, so no connection is ever
        // dispatched to a backend that is not there.
        let (backend, socket) = mux::Socket::bind()?;
        let backend_path = socket.path().to_path_buf();
        let mux_backend_path = PathBuf::clone(&backend_path);
        let (mux_listener, mux) = mux::Front::bind()?;
        let (front, port) = bind()?;
        let runtime = Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()?;
        let (tcp_front, http_backend, mux_front) = {
            let _entered = runtime.enter();
            (
                tokio::net::TcpListener::from_std(front)?,
                tokio::net::UnixListener::from_std(backend)?,
                tokio::net::UnixListener::from_std(mux_listener)?,
            )
        };
        let shared = Arc::new(Shared::new(
            Filter::new(allowed, denied, strict),
            Guard::new(allowed, denied, listed),
            token.clone(),
            mitm.map(mitm::Route::new),
        ));
        runtime.spawn(serve(http_backend, Arc::clone(&shared), http::handle));
        runtime.spawn(serve(
            tcp_front,
            Arc::clone(&shared),
            move |client, shared| {
                let socket = PathBuf::clone(&backend_path);
                async move { mux::dispatch(client, socket, shared).await }
            },
        ));
        // The same mux again, on the socket a sandbox that can reach no loopback
        // port has to dial (ADR-0014).
        runtime.spawn(serve(
            mux_front,
            Arc::clone(&shared),
            move |client, shared| {
                let socket = PathBuf::clone(&mux_backend_path);
                async move { mux::dispatch(client, socket, shared).await }
            },
        ));
        let (stop, stopped) = oneshot::channel();
        let thread = thread::Builder::new()
            .name("crabpot-proxy".to_owned())
            .spawn(move || {
                // A dropped sender ends the wait as a sent one does.
                let _ = runtime.block_on(stopped);
                // Dropping the runtime would wait for a name lookup still
                // running on its blocking pool, and so would the caller.
                runtime.shutdown_background();
            })?;
        Ok(Self {
            port,
            token,
            stop: Some(stop),
            thread: Some(thread),
            mux,
            socket,
        })
    }

    /// The port both proxies answer on, on `127.0.0.1`.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The path of the Unix socket the full mux is served on, for a sandbox that
    /// can dial no loopback port: inside a network namespace, only a socket bound
    /// there reaches the proxy (ADR-0014).
    #[must_use]
    pub fn mux_socket(&self) -> &Path {
        self.mux.path()
    }

    /// The port the SOCKS5 handler answers on. It is [`Proxy::port`], because
    /// one port serves both protocols, the way upstream's mux shows the child
    /// one port.
    #[must_use]
    pub fn socks_port(&self) -> u16 {
        self.port
    }

    /// The credential a client of either proxy presents as the password, with
    /// the username [`username_for`] gives.
    #[must_use]
    pub fn token(&self) -> &str {
        self.token.as_str()
    }
}

/// A listener on a free loopback port, and the port.
fn bind() -> io::Result<(TcpListener, u16)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    Ok((listener, port))
}

impl Drop for Proxy {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        // The backend socket goes with the struct's fields, which drop after
        // this body, so nothing is left that can dial it.
    }
}

impl fmt::Debug for Proxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Proxy")
            .field("port", &self.port)
            .field("mux", &self.mux)
            .field("socket", &self.socket)
            .field("token", &self.token)
            .finish_non_exhaustive()
    }
}
