# Parity is proven by running upstream beside crabpot

Upstream has 131 test files (77,000 lines), and 128 of them import its TypeScript modules directly, so they test upstream's internals rather than what a sandbox does. crabpot proves parity with a differential harness: each case is a settings file plus probes (read a path, write one, connect to a host, bind a socket), run once under upstream's `srt` at the baseline and once under crabpot, and the outcomes must match. Upstream's tests are mined for the cases. A module gets Rust unit tests of its own where it needs them, written for crabpot's code. The harness keeps working while following: moving the baseline re-runs every case against the new commit.

## Considered options

- **Port upstream's tests file by file.** Rejected because most of them are tied to TypeScript internals crabpot does not have.
