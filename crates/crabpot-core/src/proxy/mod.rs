//! The proxies a sandboxed command reaches the network through, as upstream's
//! `src/sandbox/http-proxy.ts` and `src/sandbox/socks-proxy.ts` serve them.
//!
//! Each listens on a port of its own on `127.0.0.1`, and both run on one
//! thread crabpot owns (ADR-0006), so a caller needs no runtime of its own.
//! They judge a host by the same filter and a client by the same token.

mod filter;
mod host;
mod http;
mod shared;
mod socks;
#[cfg(test)]
mod testing;
mod token;

use core::fmt;
use std::io;
use std::net::{Ipv4Addr, TcpListener};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use tokio::runtime::Builder;
use tokio::sync::oneshot;

pub use token::username_for;

use crate::domain::DomainEntry;
use filter::Filter;
use shared::{Shared, serve};
use token::Token;

/// A running HTTP proxy and SOCKS5 proxy. They stop when it is dropped, and the
/// tunnels open through them end with it.
pub struct Proxy {
    port: u16,
    socks_port: u16,
    token: Token,
    stop: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl Proxy {
    /// Starts the proxies, which let a client reach the hosts `allowed` covers.
    ///
    /// # Errors
    ///
    /// The [`io::Error`] of whatever failed: reading the token, binding the
    /// ports, or starting the runtime or its thread.
    pub fn start(allowed: &[DomainEntry]) -> io::Result<Self> {
        let token = Token::generate()?;
        let (http, port) = bind()?;
        let (socks, socks_port) = bind()?;
        let runtime = Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()?;
        let (http, socks) = {
            let _entered = runtime.enter();
            (
                tokio::net::TcpListener::from_std(http)?,
                tokio::net::TcpListener::from_std(socks)?,
            )
        };
        let shared = Arc::new(Shared::new(Filter::new(allowed), token.clone()));
        runtime.spawn(serve(http, Arc::clone(&shared), http::handle));
        runtime.spawn(serve(socks, shared, socks::handle));
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
            socks_port,
            token,
            stop: Some(stop),
            thread: Some(thread),
        })
    }

    /// The port the HTTP proxy listens on, on `127.0.0.1`.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The port the SOCKS5 proxy listens on, on `127.0.0.1`. It is not the
    /// HTTP proxy's.
    #[must_use]
    pub fn socks_port(&self) -> u16 {
        self.socks_port
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
    }
}

impl fmt::Debug for Proxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Proxy")
            .field("port", &self.port)
            .field("socks_port", &self.socks_port)
            .field("token", &self.token)
            .finish_non_exhaustive()
    }
}
