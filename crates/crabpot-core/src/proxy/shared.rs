//! What the proxy's servers have in common: the filter, the guard and the token
//! every connection is judged by, the accept loop, and the dial to an allowed
//! host.

use core::future::Future;
use core::net::{IpAddr, SocketAddr};
use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, copy, sink};
use tokio::net::{TcpListener, TcpStream, lookup_host};
use tokio::time::{sleep, timeout};

use super::filter::Filter;
use super::guard::{Guard, Refusal};
use super::mitm;
use super::token::Token;

/// How long a dial may take in all, and how long it may spend on one address.
const DIAL_TIMEOUT: Duration = Duration::from_secs(30);
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a refused client may go on sending before the connection is dropped.
const LINGER: Duration = Duration::from_secs(1);

/// What every connection is judged by.
#[derive(Debug)]
pub(super) struct Shared {
    pub(super) filter: Filter,
    pub(super) guard: Guard,
    pub(super) token: Token,
    /// `network.mitmProxy`: the domains sent to a Unix socket instead of being
    /// dialed direct.
    mitm: Option<mitm::Route>,
}

impl Shared {
    pub(super) fn new(
        filter: Filter,
        guard: Guard,
        token: Token,
        mitm: Option<mitm::Route>,
    ) -> Self {
        Self {
            filter,
            guard,
            token,
            mitm,
        }
    }

    /// The socket `host` is sent to, when `network.mitmProxy` covers it. The
    /// SOCKS proxy has no such route, and dials what it allows.
    pub(super) fn socket_for(&self, host: &str) -> Option<&str> {
        self.mitm.as_ref().and_then(|route| route.socket_for(host))
    }
}

/// Hands each connection to `listener` to `handle`, until the runtime it runs
/// on is dropped.
pub(super) async fn serve<H, F>(listener: TcpListener, shared: Arc<Shared>, handle: H)
where
    H: Fn(TcpStream, Arc<Shared>) -> F,
    F: Future<Output = ()> + Send + 'static,
{
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(handle(stream, Arc::clone(&shared)));
            }
            // Out of descriptors, or a peer that reset before it was accepted:
            // wait a moment and take the next one.
            Err(_) => sleep(Duration::from_millis(10)).await,
        }
    }
}

/// Reads and drops what `client` is still sending, for a moment. Closing on
/// unread bytes resets the connection and can take the last response with it.
pub(super) async fn drain<R: AsyncRead + Unpin>(client: &mut R) {
    let _ = timeout(LINGER, copy(client, &mut sink())).await;
}

/// Why a dial did not connect.
#[derive(Debug)]
pub(super) enum DialError {
    /// The guard dropped every address the name resolved to.
    Refused(Refusal),
    /// The name did not resolve, or no address it resolved to answered.
    Failed(io::Error),
}

/// Connects to `host:port`, trying each address its name resolves to that
/// `guard` allows. The system resolver answers, once.
pub(super) async fn dial(guard: &Guard, host: &str, port: u16) -> Result<TcpStream, DialError> {
    let attempts = async {
        let resolved: Vec<IpAddr> = lookup_host((host, port))
            .await
            .map_err(DialError::Failed)?
            .map(|address| address.ip())
            .collect();
        let allowed = guard
            .vet(host, port, &resolved)
            .map_err(DialError::Refused)?;
        let mut last = io::Error::new(io::ErrorKind::NotFound, "the host has no address");
        for address in allowed {
            match timeout(
                ATTEMPT_TIMEOUT,
                TcpStream::connect(SocketAddr::new(address, port)),
            )
            .await
            {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(error)) => last = error,
                Err(_) => last = io::ErrorKind::TimedOut.into(),
            }
        }
        Err(DialError::Failed(last))
    };
    timeout(DIAL_TIMEOUT, attempts)
        .await
        .unwrap_or_else(|_| Err(DialError::Failed(io::ErrorKind::TimedOut.into())))
}
