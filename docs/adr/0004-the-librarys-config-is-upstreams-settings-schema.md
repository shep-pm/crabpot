# The library's config is upstream's settings schema

crabpot is a library first. Its consumers are Rust programs, starting with kelpie, which only drove upstream through its CLI because upstream is TypeScript. The library's config type mirrors upstream's settings JSON field for field (`serde`, camelCase keys, the same nesting), so a settings file and the Rust value are one thing, and parity can be checked key by key. The leaves are still typed and checked when a config is loaded: a domain list is `Vec<DomainPattern>`, not `Vec<String>`, so a bad entry fails before anything is spawned. The library's operations are idiomatic Rust rather than a copy of upstream's `SandboxManager` object. The `srt`-compatible CLI is a thin layer over the library, there for parity.

## Considered options

- **A config of crabpot's own design** (platform sections, an enum in place of upstream's rule that a path without a glob means the folder and everything under it). Rejected because it needs a translation layer from upstream's JSON that has to stay correct forever, and parity could no longer be checked key by key. It can be offered later on top of this type.
- **Mirror `SandboxManager` method for method.** Rejected because it would make an unidiomatic Rust API that has to follow a TypeScript object's changes.
