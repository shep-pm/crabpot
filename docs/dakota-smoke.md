# Smoke run on dakota

Run on 2026-10-25 at crabpot 9b1ca4b, for #123.

## The machine

| | dakota | Reference: GitHub's `ubuntu-latest` |
|---|---|---|
| OS | Bluefin (Fedora Atomic) | Ubuntu 24.04 |
| Kernel | 7.2.6 | 6.17.0-1022-azure |
| bwrap | 0.12.0, not setuid | 0.9.0 |
| `socat`, `rg` | none | installed |
| Upstream's runner | cannot run | runs |
| `max_user_namespaces` | 252898, no sysctl set | AppArmor's restriction lifted, as CI does |

## How it ran

The harness compares crabpot with upstream, and skips every case where upstream can't run, so on dakota it skips them all. A scratch driver outside the repo ran each case file in `harness/cases/` under crabpot alone, through `runner::run_upstream_only` with the `Crabpot` runner, and printed each probe's exit code. The same driver ran on `ubuntu-latest` with upstream beside crabpot, from a throwaway branch, to give the reference.

## Results

- All 76 cases: 74 ran and 2 were skipped as Windows-only (`kelpie_full_policy_windows`, `windows_backslash_argument`)
- Every probe code on dakota is the same as crabpot's on Ubuntu, and on Ubuntu crabpot matches upstream on every case
- The 12 `report:` lines are reads of paths a deny removed, the same on both machines
- The whole set takes about 1.6 s on dakota

## The helper's user namespace

The helper runs with its user-namespace fallback on dakota. bwrap isn't setuid there, so it starts the helper with no capabilities, `unshare` of the PID and mount namespaces is refused, and the helper makes a user namespace of its own first. Seen from the host during a sandboxed `sleep`:

| Process | User namespace | PID namespace |
|---|---|---|
| bwrap's sandbox child | `4026533481` | `4026533295` |
| crabpot's helper | `4026533482` | `4026533295` |
| the relay, forked before the unshare | `4026533481` | `4026533295` |
| the helper's PID 1 and the command | `4026533482` | `4026533490` |

## Gaps

None in crabpot.
