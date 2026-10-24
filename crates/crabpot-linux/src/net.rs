//! How a command inside the network namespace reaches the proxy (ADR-0014).
//!
//! `--unshare-net` leaves the command with a loopback of its own and nothing
//! else. The proxy's Unix socket is bound into the sandbox, the `relay`
//! forwards the ports below to it, and [`env`](mod@env) points the command's
//! clients at those ports.

pub mod env;
#[cfg(unix)]
pub mod relay;

/// The port inside the sandbox that reaches the proxy for HTTP clients, as
/// upstream's `socat` relay listens on it.
pub const HTTP_PORT: u16 = 3128;

/// The port inside the sandbox that reaches the proxy for SOCKS5 clients.
pub const SOCKS_PORT: u16 = 1080;
