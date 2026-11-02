//! What the proxy's servers have in common: the filter, the guard and the token
//! every connection is judged by, the accept loop, and the dial to an allowed
//! host.

use core::future::Future;
use core::net::{IpAddr, SocketAddr};
use std::io;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, copy, sink};
use tokio::net::{TcpListener, TcpStream, lookup_host};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::time::{sleep, timeout};

use super::filter::Filter;
use super::guard::{Guard, Refusal};
use super::mitm;
use super::token::Token;
use crate::address::AddressRange;
use crate::domain::DomainEntry;

/// How long a dial may take in all, and how long it may spend on one address.
const DIAL_TIMEOUT: Duration = Duration::from_secs(30);
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a refused client may go on sending before the connection is dropped.
const LINGER: Duration = Duration::from_secs(1);

/// The filter and the guard of one set of lists, which a request is judged by
/// from its first check to its dial.
#[derive(Debug)]
pub(super) struct Lists {
    pub(super) filter: Filter,
    pub(super) guard: Guard,
}

/// What every connection is judged by.
#[derive(Debug)]
pub(super) struct Shared {
    lists: RwLock<Arc<Lists>>,
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
            lists: RwLock::new(Arc::new(Lists { filter, guard })),
            token,
            mitm,
        }
    }

    /// The lists in force now. A swap after this returns does not touch them,
    /// so a request judged by them is judged by one set throughout.
    pub(super) fn lists(&self) -> Arc<Lists> {
        // A lock poisoned by a panic elsewhere still holds a whole set, since
        // a swap assigns once.
        Arc::clone(&self.lists.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Swaps the domain lists and the resolved-address list for the next
    /// request, keeping the filter's `strict` and `tcp` and the guard's `local`.
    pub(super) fn replace_lists(
        &self,
        allowed: &[DomainEntry],
        denied: &[DomainEntry],
        listed: &[AddressRange],
    ) {
        let mut lists = self.lists.write().unwrap_or_else(PoisonError::into_inner);
        *lists = Arc::new(Lists {
            filter: lists.filter.replaced(allowed, denied),
            guard: lists.guard.replaced(allowed, denied, listed),
        });
    }

    /// The socket `host` is sent to, when `network.mitmProxy` covers it. The
    /// SOCKS proxy has no such route, and dials what it allows.
    pub(super) fn socket_for(&self, host: &str) -> Option<&str> {
        self.mitm.as_ref().and_then(|route| route.socket_for(host))
    }
}

/// What a connection is read from and answered on.
pub(super) trait Stream: AsyncRead + AsyncWrite + Unpin {}

impl<T: AsyncRead + AsyncWrite + Unpin> Stream for T {}

/// A listener that hands out connections of one kind, as tokio's TCP and Unix
/// listeners do.
pub(super) trait Listener {
    /// The kind of connection it hands out.
    type Connection: Stream + Send + 'static;

    /// The next connection.
    fn accept(&self) -> impl Future<Output = io::Result<Self::Connection>> + Send;
}

impl Listener for TcpListener {
    type Connection = TcpStream;

    async fn accept(&self) -> io::Result<Self::Connection> {
        TcpListener::accept(self)
            .await
            .map(|(connection, _)| connection)
    }
}

#[cfg(unix)]
impl Listener for UnixListener {
    type Connection = UnixStream;

    async fn accept(&self) -> io::Result<Self::Connection> {
        UnixListener::accept(self)
            .await
            .map(|(connection, _)| connection)
    }
}

/// Hands each connection to `listener` to `handle`, until the runtime it runs
/// on is dropped.
pub(super) async fn serve<L, H, F>(listener: L, shared: Arc<Shared>, handle: H)
where
    L: Listener + Send + Sync,
    H: Fn(L::Connection, Arc<Shared>) -> F,
    F: Future<Output = ()> + Send + 'static,
{
    loop {
        match listener.accept().await {
            Ok(connection) => {
                tokio::spawn(handle(connection, Arc::clone(&shared)));
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
