//! `probe read <path> | write <path> | rename <from> <to> | connect <host> <port> [--via socks5]
//! | bind | bind-unix <path> | connect-unix <path>`: see [`crabpot_harness::probe`].
//!
//! `probe --crabpot ...` is crabpot's wrapper (ADR-0010), which lets a case run
//! crabpot through this same binary.

use std::process::ExitCode;

fn main() -> ExitCode {
    crabpot::run_from_args();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let http_proxy = std::env::var("HTTP_PROXY").ok();
    let socks_proxy = std::env::var("FTP_PROXY").ok();
    let code = crabpot_harness::probe::run(&args, http_proxy.as_deref(), socks_proxy.as_deref());
    println!("{}{code}", crabpot_harness::probe::REPORT);
    ExitCode::from(code)
}
