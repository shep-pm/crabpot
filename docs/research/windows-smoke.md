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

Run on 2026-10-29 for #218, in the desktop session, against shep-pm/kelpie-scratch.

| Run | Build | Result |
|---|---|---|
| shep-pm/kelpie-scratch#22 | a kelpie build from before the fixes below | merged as shep-pm/kelpie-scratch#23, with four host stopgaps |
| shep-pm/kelpie-scratch#24 | kelpie 41dff50, crabpot 0.5.2, shep 0.19.0 | merged as shep-pm/kelpie-scratch#25, with no stopgaps |

The second run went from its worker's turn to a merge ruling in 8 minutes: the worker committed and pushed from a clone with its own git dir, opened the PR, and passed kelpie's review and CI.

Each stopgap of the first run became a fix:

| Stopgap on the VM | Fix |
|---|---|
| git identity in the checkout's own config, since the sandbox read no `~\.gitconfig` | #253, in 0.5.2: a host reads the profile grant's `GIT_CONFIG_GLOBAL` and the other config pointers, as upstream exports them. Kelpie sets them (shep-pm/shep-kelpie#1523) |
| `credential.helper` set to gh in the checkout, since Git for Windows' credential manager hung | shep-pm/shep-kelpie#1511 |
| `Modify` grants on the checkout's ref folders, so the worker could lock its branch ref | shep-pm/shep-kelpie#1515, shep-pm/shep-kelpie#1516 and shep-pm/shep-kelpie#1517: a worker gets its own clone. Every session runs as one sandbox user, so no grant on a shared `.git` lets a session create a ref lock without letting the others overwrite it |
| `profile grant` run again for a `~\.gitconfig` made after the grant | none needed: the grant is a snapshot, as the README says |

The second run met one more: `cargo install` builds in `%TEMP%` and moves the binary into `~\.cargo\bin`, so the new binary keeps the temporary folder's access list and misses the grant's inherited entry. Every turn then fails with `RunnerUnreadable`, and running `profile grant` again writes nothing. `icacls <exe> /reset` repairs it. crabpot 0.5.3 names that repair (#258), and 0.5.4 lets a host check its runner ahead of a start (#259).

A third run, shep-pm/kelpie-scratch#26 on kelpie 1414937 with crabpot 0.5.4, checked the repair path. Straight after `cargo install`, kelpie's doctor reported the unreadable binary with the `icacls` line and exited 1 (shep-pm/shep-kelpie#1530). After the reset it passed, and the worker took the issue through review and CI to a merge as shep-pm/kelpie-scratch#27.

## Gaps

- #215, #216, #217, #258 and #259 are fixed
- A `cargo install` upgrade still leaves the binary unreadable until `icacls /reset` runs. crabpot and kelpie name the repair, and neither applies it, since it changes a file the user owns
