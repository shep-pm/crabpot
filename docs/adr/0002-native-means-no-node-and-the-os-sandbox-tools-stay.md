# Native means no Node, and the OS sandbox tools stay

Upstream needs Node at runtime and ships helpers in other languages. crabpot's own code is all Rust, so at runtime it needs no Node, no npm package and no helper from upstream's `vendor/`. It still calls the operating system's own sandbox tools (`sandbox-exec` on macOS, `bwrap` on Linux) as upstream does. Rewriting what bubblewrap does with raw namespaces would be a second project, and gains nothing a user can see.

## Considered options

- **No external binaries at all.** Rejected for bubblewrap's sake, as above.
- **Reuse upstream's prebuilt helpers where easier.** Rejected because it brings back the multi-language build and release that crabpot exists to remove.
