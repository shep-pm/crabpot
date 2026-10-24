//! The `crabpot` command line: upstream's arguments, run under the sandbox.

fn main() {
    // bwrap runs this binary again inside the sandbox as the helper.
    crabpot::run_from_args();
    crabpot::run_args(std::env::args_os().skip(1));
}
