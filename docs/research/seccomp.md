# Which crate builds and installs a seccomp filter from Rust?

Throwaway findings for shep-pm/crabpot#89, never merged. Gathered 2026-10-23 from web sources; two facts re-checked by hand (marked).

## Recommendation

`seccompiler` 0.5.0 builds the filter, with no system library. Two ways to install it:

1. crabpot's own binary, re-entered inside bwrap, installs it and then execs the command
2. crabpot compiles the BPF and hands it to `bwrap --seccomp FD`, so crabpot runs no unsafe seccomp call

`libseccomp` needs the LGPL C library installed, which is what crabpot exists to avoid. Hand-written BPF over `libc` works, but must get the arch check and x32 right by hand.

## Options

| | seccompiler 0.5.0 | libseccomp 0.4.0 | hand-written over libc |
|---|---|---|---|
| Licence | Apache-2.0 OR BSD-3-Clause (checked) | MIT OR Apache-2.0, C library LGPL-2.1 | MIT OR Apache-2.0 |
| MSRV | none declared (checked), untested on 1.88 | 1.67 | libc 1.65 |
| x86_64, aarch64 | yes (README) | through the C library | by hand |
| Compare `socket`'s domain | yes, `Dword` condition on arg 0 | yes, `SCMP_A0` | yes, `seccomp_data.args[0]` |
| User installs | nothing | libseccomp 2.5+ | nothing |
| Unsafe for crabpot | none from the docs, not confirmed in source | none in the high-level crate | one `prctl` or `seccomp` call |
| Maintained | repo archived 2026-08 (checked), README points to a mono-repo, not confirmed | active, last push 2026-10-14 | n/a |

Sources: crates.io API for each crate, github.com/rust-vmm/seccompiler, github.com/libseccomp-rs/libseccomp-rs, man7.org seccomp(2), kernel.org `userspace-api/seccomp_filter`.

## Where it must be installed

- Filters are inherited across fork and execve, so installing before bwrap would also filter bwrap's own setup. It goes in after the namespace is up, just before exec.
- Installing needs `PR_SET_NO_NEW_PRIVS`, which bubblewrap already sets (`bubblewrap.c`).
- From a single-threaded process just before exec, TSYNC is not needed.

## bwrap's `--seccomp FD`

- Reads a raw array of 8-byte `sock_filter` instructions; only the last `--seccomp` is used. `--add-seccomp-fd` is repeatable and can't be combined with it.
- bubblewrap applies it as the last step before execve, which avoids the threading question.
- seccompiler can compile without applying; the exact function and output type are not confirmed.
- A filter handed to bwrap doesn't cover any path where crabpot runs a command without bwrap.
