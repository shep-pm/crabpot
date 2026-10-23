# On Linux, crabpot needs only bwrap

Upstream needs `socat`, `rg` and its own `apply-seccomp` helper on Linux besides `bwrap`. crabpot needs only `bwrap`, and its own binary does the other three jobs:

- `socat`: on the host, the proxy listens on the Unix socket that is bound into the sandbox. Inside the network namespace, crabpot's binary relays TCP ports 3128 and 1080 to that socket and is the `GIT_SSH_COMMAND` hop.
- `apply-seccomp`: crabpot's binary is re-entered inside bwrap and does what the helper does at parity: the nested PID and mount namespace, signal forwarding, reaping as PID 1, and both filters, built with `seccompiler`, before it execs the command. A filter that cannot be installed is an error, as it is in upstream's helper. Upstream's other path, warning and running unfiltered when the helper is missing, cannot happen, since crabpot always has its binary.
- `rg`: crabpot walks the tree with `std::fs` for the mandatory denies, matching upstream's `rg` flags: hidden files listed, no ignore or config files, `node_modules` skipped, names matched without case, symlinks not followed, the same depth and 10 s limit. A test compares its list with `rg`'s on the same trees.

bwrap binds crabpot's binary into the sandbox read-only after the deny binds, so no `denyRead` can hide it.

The reason is what a user installs. Each of the three is a small job in Rust next to a whole tool to install, and some hosts, such as an immutable Fedora, ship `bwrap` but make extra packages awkward. bwrap itself stays (ADR-0002). The differential harness compares outcomes, not processes, so parity is unaffected.

## Considered options

- **Keep `socat` and `rg`, as upstream does.** Rejected because both are plain helpers rather than the sandbox, and each is another package for every Linux user.
- **Hand bwrap a compiled filter with `--seccomp` and drop the rest of the helper.** Rejected because it loses the nested PID namespace, the reaping and the non-dumpable outer process, which kelpie's process-group and `ps` red tests exercise.
- **Hand-written BPF over `libc` in place of `seccompiler`.** Kept as the fallback. `seccompiler` handles the arch checks and masked compares, and its repository was archived in 2026, so it is pinned exactly and can be replaced inside the one module that uses it.
