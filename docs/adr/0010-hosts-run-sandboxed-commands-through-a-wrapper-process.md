# Hosts run sandboxed commands through a wrapper process

A sandbox's proxies have to live exactly as long as the command they serve. kelpie's `Sandbox` port hands back a `std::process::Command` for the caller to spawn, and today that command is `node` running upstream's CLI, so each call gets its own proxies, gone when its command exits. crabpot keeps that shape. The library's core is a `Sandbox` value that starts the proxies from a config, wraps a `&Command` into a new `Command`, and stops the proxies when it drops. On top of it, `run_from_args()` lets a host's own binary act as the wrapper: the host calls it first thing in `main`, and when the arguments start with `--crabpot` it parses the CLI's own arguments, runs the command inside its sandbox, and exits with it. The `crabpot` CLI is the same code. The parser is hand-written in the library, so a host built without the `cli` feature (ADR-0009) still has it.

Cleanup stays at parity: the child stays in the wrapper's process group, SIGINT and SIGTERM are forwarded to it, and the wrapper's exit status is mapped as upstream maps it. A host that signals the wrapper's group, as kelpie does, reaches the command and the wrapper together. Ending a command's whole process tree from inside crabpot is left for after kelpie-ready, built on a process-tree crate shared with shep and kelpie rather than a third copy of that code.

## Considered options

- **The `Sandbox` value alone.** Rejected because a port that returns a `Command` has nowhere to keep the value alive, so every caller in kelpie would have to change.
- **Depend on shep's supervision code for cleanup.** Rejected because `shep-daemon` is a whole async engine, and the parts that end a process tree are private to it.
- **`run_from_args` behind the `cli` feature.** Rejected because kelpie builds without it, and five flags do not need a parser crate.
