# Port to parity with a baseline, then follow upstream

Upstream moves fast (0.0.81 on 2026-10-21, with commits most days), and a rewrite that chases every release never ships. So crabpot is measured against one upstream commit, the baseline, until it reaches parity with it. Upstream changes after the baseline are not ported during that time. Once parity ships, crabpot follows upstream: it reads upstream's changes since the last commit it took, ports the ones it wants, and records each new commit it takes.

The baseline is `aceba124fd725f4a43d7016ed3f5651d61f83115` (2026-10-21).

## Considered options

- **A one-time port, then diverge.** Rejected because the maintainer wants crabpot to keep up with upstream after parity.
- **Lockstep with every upstream release.** Rejected because before parity, every upstream release would push parity further away.
