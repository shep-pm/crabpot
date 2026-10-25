# Smoke run on the maintainer's Windows VM

Run on 2026-10-25 at crabpot 9b1ca4b, for #164.

## The machine

- Windows 11 build 26200, ARM64, 8 logical CPUs, 8 GB, UAC off, in UTM
- The desktop session is session 1, reached through an interactive scheduled task. ssh lands in session 0
- crabpot built on the VM in 41 s, at `C:\crabpot-smoke`, outside the profile
- The sandbox user and filters were already installed by npm's srt 0.0.81 (setup version 3). `crabpot windows-install` read that install and changed nothing: "already installed ... no changes"

## Desktop session

Settings: `allowWrite` on a work folder, `denyWrite` on its `.env`, `denyRead` on a secret folder, and `github.com`, `api.github.com` and `example.com` allowed.

| Probe | Result |
|---|---|
| `cmd /c echo hello` | exit 0, `hello` |
| write in `allowWrite` | written |
| write to the `denyWrite` file | Access is denied |
| write outside `allowWrite` | Access is denied |
| read in `denyRead` | Access is denied |
| `echo C:\a\b` | `C:\a\b`, no quotes added |
| node `fetch` to `example.com` | 200 |
| node `fetch` to another host | refused |
| `git ls-remote https://github.com/shep-pm/crabpot.git` | the remote's `HEAD` |
| crabpot copied under `%USERPROFILE%` | refused with seclogon's misleading "Access is denied" (#215) |
| the same copy after `crabpot --srt-win profile grant` (4 s) | exit 0, and `~\.ssh` stays unreadable |

## Session 0

Over ssh, `crabpot --crabpot` exits 1 with `this process is in session 0, and the sandbox runs from the desktop session only` (#141).

## The harness

The full case set, in the desktop session, against upstream's runner:

| Run | Result |
|---|---|
| default threads (8) | 18 of 76 failed before their probe ran, under both runners: the 10-port range holds five sandboxes (#216, #217) |
| `--test-threads=4`, loopback closed | 76 of 76 |
| `--test-threads=4`, `--allow-loopback` install with `CRABPOT_HARNESS_LOOPBACK=open` | 76 of 76 |

The install was put back to loopback closed afterwards.

## The live kelpie worker

Not run: kelpie routes Windows workers through crabpot only once shep-pm/shep-kelpie#1217 lands. #218 holds that run.

## Gaps

- #215: `windows-install` makes no profile read grant, and `Sandbox::start` never refuses an unreadable runner, so crabpot or kelpie under the profile fails with seclogon's message. Blocks the release
- #216: a full port range reads `cannot start the proxy: other error`. Blocks the release
- #217: the harness runs more Windows sandboxes at once than the range holds on a machine with more than 5 CPUs
- #218: the live kelpie worker run, after shep-pm/shep-kelpie#1217
