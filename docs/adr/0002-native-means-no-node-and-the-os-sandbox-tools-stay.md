# Native means no Node, and the OS sandbox tools stay

Upstream needs Node at runtime and ships helpers in other languages. crabpot's own code is all Rust, so at runtime it needs no Node, no npm package and no helper from upstream's `vendor/`. It still calls the operating system's own sandbox tools (`sandbox-exec` on macOS, `bwrap` on Linux) as upstream does. Rewriting what bubblewrap does with raw namespaces would be a second project, and gains nothing a user can see.

## Considered options

- **No external binaries at all.** Rejected for bubblewrap's sake, as above.
- **Reuse upstream's prebuilt helpers where easier.** Rejected because it brings back the multi-language build and release that crabpot exists to remove.
- **`sandbox_init` over FFI in place of `sandbox-exec`.** Rejected because the public call takes only Apple's named profiles (`sandbox.h`: flags "Must be SANDBOX_NAMED"), so a custom profile means reserved or private API. Running it in the child after `fork` would also run code that is not async-signal-safe in a process whose proxy thread is already up. It nests no better: an already sandboxed process is refused either way. `sandbox-exec` also lets the differential harness compare crabpot's profile and argv with upstream's byte for byte.
