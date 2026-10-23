//! `probe read <path> | write <path> | connect <host> <port> | bind`: see [`crabpot_harness::probe`].

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let http_proxy = std::env::var("HTTP_PROXY").ok();
    ExitCode::from(crabpot_harness::probe::run(&args, http_proxy.as_deref()))
}
