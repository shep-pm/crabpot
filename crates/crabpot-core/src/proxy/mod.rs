//! The proxy a sandboxed command reaches the network through, as upstream's
//! `src/sandbox/http-proxy.ts` serves it.
//!
//! It listens on a port of its own on `127.0.0.1` and runs on a thread crabpot
//! owns (ADR-0006), so a caller needs no runtime of its own.

mod filter;
mod host;
mod http;
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
use token::Token;

/// A running HTTP proxy. It stops when it is dropped, and the tunnels open
/// through it end with it.
pub struct Proxy {
    port: u16,
    token: Token,
    stop: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl Proxy {
    /// Starts a proxy that lets a client reach the hosts `allowed` covers and
    /// no host `denied` covers, which beat `allowed`.
    ///
    /// `strict` is `network.strictAllowlist`, which changes nothing about what
    /// this proxy lets through yet: crabpot has no ask callback and no
    /// per-command allow list for it to gate.
    ///
    /// # Errors
    ///
    /// The [`io::Error`] of whatever failed: reading the token, binding the
    /// port, or starting the runtime or its thread.
    pub fn start(
        allowed: &[DomainEntry],
        denied: &[DomainEntry],
        strict: bool,
    ) -> io::Result<Self> {
        let token = Token::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let runtime = Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()?;
        let listener = {
            let _entered = runtime.enter();
            tokio::net::TcpListener::from_std(listener)?
        };
        let shared = Arc::new(http::Shared::new(
            Filter::new(allowed, denied, strict),
            token.clone(),
        ));
        runtime.spawn(http::serve(listener, shared));
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
        })
    }

    /// The port the proxy listens on, on `127.0.0.1`.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The credential a client presents as the password, with the username
    /// [`username_for`] gives.
    #[must_use]
    pub fn token(&self) -> &str {
        self.token.as_str()
    }
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
            .field("token", &self.token)
            .finish_non_exhaustive()
    }
}
