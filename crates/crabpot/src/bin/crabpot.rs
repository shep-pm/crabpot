//! The `crabpot` command line: upstream's arguments, run under the sandbox.

fn main() {
    crabpot::run_args(std::env::args_os().skip(1));
}
