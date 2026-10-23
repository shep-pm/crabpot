//! The loopback ports a proxy may listen on, as upstream's `listenInRange`
//! (`src/sandbox/listen-in-range.ts`) and `portRange` in
//! `src/sandbox/sandbox-manager.ts` have them.
//!
//! On Windows the Windows Filtering Platform permits the sandbox user to reach
//! the loopback ports of one range and no others, so the proxy binds inside it.
//! Each sandbox takes two ports there, the mux's front end and its HTTP backend.

use core::fmt;
use std::io;
use std::net::{Ipv4Addr, TcpListener};

/// A first and last loopback port, both included, that the proxy may listen
/// on. It is at most [`PortRange::MAX_WIDTH`] ports wide and never holds port 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PortRange {
    first: u16,
    last: u16,
}

/// A range [`PortRange::new`] refuses, or a proxy that could not listen in one.
#[derive(Debug)]
#[non_exhaustive]
pub enum RangeError {
    /// The first port is port 0, which asks the OS for any port and so is no
    /// range.
    Zero,
    /// The first port is past the last.
    Inverted {
        /// The first port asked for.
        first: u16,
        /// The last port asked for.
        last: u16,
    },
    /// The range holds more than [`PortRange::MAX_WIDTH`] ports.
    TooWide {
        /// The first port asked for.
        first: u16,
        /// The last port asked for.
        last: u16,
    },
    /// Every port in the range is in use or is already taken by this sandbox's
    /// other listener.
    Full(PortRange),
    /// Binding failed for a reason other than a port being in use, or a later
    /// step of starting the proxy failed.
    Io(io::Error),
}

impl PortRange {
    /// The range srt-win's firewall rule permits unless it is told another:
    /// 60080 to 60089, which holds five sandboxes at two ports each.
    pub const DEFAULT: Self = Self {
        first: 60080,
        last: 60089,
    };

    /// The most ports a range may hold.
    pub const MAX_WIDTH: u16 = 64;

    /// The range from `first` to `last`, both included.
    ///
    /// # Errors
    ///
    /// - [`RangeError::Zero`] when `first` is 0.
    /// - [`RangeError::Inverted`] when `first` is past `last`.
    /// - [`RangeError::TooWide`] when the range holds more than
    ///   [`PortRange::MAX_WIDTH`] ports.
    pub fn new(first: u16, last: u16) -> Result<Self, RangeError> {
        if first == 0 {
            return Err(RangeError::Zero);
        }
        if first > last {
            return Err(RangeError::Inverted { first, last });
        }
        if last - first >= Self::MAX_WIDTH {
            return Err(RangeError::TooWide { first, last });
        }
        Ok(Self { first, last })
    }

    /// The first port.
    #[must_use]
    pub fn first(self) -> u16 {
        self.first
    }

    /// The last port.
    #[must_use]
    pub fn last(self) -> u16 {
        self.last
    }
}

impl Default for PortRange {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.first, self.last)
    }
}

impl fmt::Display for RangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero => f.write_str("a proxy port range may not start at port 0"),
            Self::Inverted { first, last } => {
                write!(
                    f,
                    "the proxy port range {first}-{last} ends before it starts"
                )
            }
            Self::TooWide { first, last } => write!(
                f,
                "the proxy port range {first}-{last} holds more than {} ports",
                PortRange::MAX_WIDTH
            ),
            Self::Full(range) => write!(
                f,
                "no free loopback port in the proxy port range {range}: each sandbox takes \
                 two, so widen it with --proxy-port-range or stop a sandbox"
            ),
            Self::Io(error) => error.fmt(f),
        }
    }
}

impl core::error::Error for RangeError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for RangeError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<RangeError> for io::Error {
    fn from(error: RangeError) -> Self {
        match error {
            RangeError::Io(error) => error,
            other => Self::other(other),
        }
    }
}

/// A non-blocking listener on `127.0.0.1` and its port: the first free port of
/// `range` that is not in `exclude`, or a port the OS picks when there is no
/// range. A port in use is skipped, as upstream skips one on `EADDRINUSE`, and
/// any other failure ends the search.
///
/// # Errors
///
/// - [`RangeError::Full`] when every port of the range is excluded or in use.
/// - [`RangeError::Io`] when binding failed for another reason.
pub(super) fn listen(
    range: Option<PortRange>,
    exclude: &[u16],
) -> Result<(TcpListener, u16), RangeError> {
    let Some(range) = range else {
        return bind(0);
    };
    for port in range.first..=range.last {
        if exclude.contains(&port) {
            continue;
        }
        match bind(port) {
            Err(RangeError::Io(error)) if error.kind() == io::ErrorKind::AddrInUse => {}
            bound => return bound,
        }
    }
    Err(RangeError::Full(range))
}

fn bind(port: u16) -> Result<(TcpListener, u16), RangeError> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    Ok((listener, port))
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicU16, Ordering};

    use super::super::Proxy;
    use super::*;

    /// Where the next window is looked for, so that tests running together do
    /// not choose the same ports.
    static NEXT: AtomicU16 = AtomicU16::new(20_000);

    /// A range of `width` free ports no other test holds, none of them bound
    /// when this returns.
    fn free_range(width: u16) -> PortRange {
        loop {
            let first = NEXT.fetch_add(width, Ordering::Relaxed);
            let last = first + width - 1;
            let held: Result<Vec<TcpListener>, io::Error> = (first..=last)
                .map(|port| TcpListener::bind((Ipv4Addr::LOCALHOST, port)))
                .collect();
            match held {
                Ok(_) => return PortRange::new(first, last).unwrap(),
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => {}
                Err(error) => panic!("cannot probe {first}-{last}: {error}"),
            }
        }
    }

    fn start_in(range: PortRange) -> Result<Proxy, RangeError> {
        Proxy::start_in_range(&[], &[], &[], false, None, range)
    }

    #[test]
    fn the_proxy_binds_inside_the_range() {
        let range = free_range(2);

        let proxy = start_in(range).unwrap();

        assert!(
            (range.first()..=range.last()).contains(&proxy.port()),
            "{} is outside {range}",
            proxy.port()
        );
    }

    #[test]
    fn the_front_end_skips_the_backend_port() {
        let range = free_range(3);

        let (_listener, port) = listen(Some(range), &[range.first()]).unwrap();

        assert_eq!(port, range.first() + 1);
    }

    #[test]
    fn a_taken_port_is_retried_and_a_full_range_is_an_error() {
        let range = free_range(2);
        let (_first, _) = listen(Some(range), &[]).unwrap();

        let (_second, port) = listen(Some(range), &[]).unwrap();
        assert_eq!(port, range.last(), "the taken port is skipped");

        let full = listen(Some(range), &[]).unwrap_err();
        assert!(
            matches!(full, RangeError::Full(full) if full == range),
            "{full:?}"
        );
        let message = full.to_string();
        assert!(message.contains(&range.to_string()), "{message}");
        assert!(message.contains("--proxy-port-range"), "{message}");
    }

    #[test]
    fn a_range_wider_than_64_is_refused() {
        assert!(PortRange::new(60000, 60063).is_ok(), "64 ports fit");
        assert!(matches!(
            PortRange::new(60000, 60064),
            Err(RangeError::TooWide { .. })
        ));
        assert!(matches!(
            PortRange::new(60089, 60080),
            Err(RangeError::Inverted { .. })
        ));
        assert!(matches!(PortRange::new(0, 10), Err(RangeError::Zero)));
        assert_eq!(PortRange::default().to_string(), "60080-60089");
    }

    #[test]
    fn a_proxy_in_a_full_range_is_refused_with_the_range() {
        let range = free_range(2);
        let mut running = Vec::new();

        let refused = loop {
            match start_in(range) {
                Ok(proxy) => running.push(proxy),
                Err(refused) => break refused,
            }
        };

        assert!(!running.is_empty(), "a range of two holds a sandbox");
        assert!(
            matches!(refused, RangeError::Full(full) if full == range),
            "{refused:?}"
        );
    }
}
