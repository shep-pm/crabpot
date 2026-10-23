//! The mux's HTTP backend on Windows, which listens on a loopback port.

/// What the HTTP backend leaves behind to remove: nothing, since it is a port
/// and not a file.
#[derive(Debug)]
pub(in crate::proxy) struct Socket;
