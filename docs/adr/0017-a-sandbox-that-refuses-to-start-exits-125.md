# A sandbox that refuses to start exits 125

The wrapper exits 125 when it refuses to start a sandbox. Upstream exits 1,
which is also an ordinary command failure. A supervisor running
`crabpot -s <settings> -- <cmd>` needs to report "sandbox refused" rather than
restart a service in a crash loop (shep-pm/shep-sandbox#5).

125 follows `env`, `timeout` and `chroot`, which reserve it for their own
failure. This supersedes ADR-0013's exit status 1 and its rule that refusals
match upstream's status. The differential harness accepts crabpot's 125 and
upstream's 1 when neither ran its probe.

Parsing the wrapper's command line, settings loading, sandbox startup, runtime
and signal listener setup, and spawning the wrapped command all refuse with 125.
The exceptions below keep 1.
On Linux, helper initialization errors also exit 125, except `InitError::Exec`,
which keeps 1 for a command that could not start. If bwrap ends without
reporting a pid, the wrapper exits 125 whatever bwrap's status was.
The PID report precedes bwrap's mount setup and does not prove the helper ran.
The wrapper also requires the helper's startup acknowledgement through an inherited
pipe. Bwrap preserves descriptor 3 for that pipe. The helper acknowledges and closes
it before initialization, so the relay and command cannot inherit it. Bwrap failures
before that acknowledgement exit 125, including failures after a PID report.
On macOS and Windows, only refusals before spawning the wrapped command change.
Post-spawn failures from `sandbox-exec` or `srt-win` retain their own exit status.
`windows-install` and `windows-uninstall` keep 0 and 1 because they run no command.
That includes a command line they do not parse.

The remaining paths that keep 1 all go through `fail` in `crates/crabpot/src/run.rs`:

- The Linux helper's own argument-parse errors, for `--crabpot-helper` and for the
  `init` arguments.
- The helper's `relay` mode, which is not supported yet.
- A failed `connect` tunnel, which is the sandboxed ssh's `ProxyCommand`
  and not a wrapped command.
- The helper entry points on a host that is not Linux.
- `InitError::Exec`, above.

The first, second and fourth fail before the helper's startup acknowledgement.
When the wrapper started that helper, it sees no acknowledgement and still exits
125, so a supervisor never reads their 1. They keep 1 for a host or a person that
runs the helper directly, where there is no wrapper to refuse. `connect` and `Exec`
run after the sandbox has started, and the exit status is the helper's own.

The command's own exit code passes through, including 1 and 125. A supervisor
reads a command that itself exits 125 as a refusal, the same trade `env` makes.
Unix signal exit mapping stays as ADR-0010 specifies.

## Considered options

- Keep upstream's 1. A supervisor cannot distinguish a sandbox refusal from
  an ordinary command failure.
- Add a separate status channel. Every caller would need to read another
  channel when it already has the wrapper's exit status.
