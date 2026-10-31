//! The jobs crabpot's own binary does when bwrap re-enters it (ADR-0014, ADR-0010).
//!
//! bwrap runs the binary as the first process of the sandbox, in place of
//! upstream's `apply-seccomp`. Each stage of the helper is a file in the folder
//! of this module's name, so slices that add one do not touch another. The
//! facade reads the `--crabpot-helper` argument and hands the stage its
//! arguments.
//!
//! [`exec`] runs the command and does nothing else. On Linux, `init` puts the
//! command in a PID and mount namespace of its own first, as PID 1's child. When
//! it is given the proxy's socket, it forks the relay for the network namespace
//! before that, and waits for the relay to listen. The command is started with
//! both seccomp filters installed, and a filter that cannot be installed ends
//! the helper with status 125 before the command runs. The `connect` mode is the
//! other way the binary is re-entered: a sandboxed ssh starts it for its
//! `ProxyCommand`.
//!
//! With extra loopback addresses, `init_with_loopback` first makes a user and
//! network namespace and configures `lo`. The relay shares that network namespace.

#[cfg(target_os = "linux")]
mod connect;
mod exec;
#[cfg(target_os = "linux")]
mod filters;
#[cfg(target_os = "linux")]
mod init;
#[cfg(target_os = "linux")]
mod relay;
#[cfg(target_os = "linux")]
pub(crate) mod sys;

#[cfg(target_os = "linux")]
pub use connect::{ConnectError, connect};
pub use exec::{ExecError, exec};
#[cfg(target_os = "linux")]
pub use init::{InitError, Step, hold_signals, init, init_with_loopback, init_with_tcp};
