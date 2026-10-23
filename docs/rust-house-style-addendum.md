# rust-house-style addendum

The rules are shep-pm/rust-house-style, IR-1..IR-48. This file holds crabpot's
own exceptions, and it wins where the two disagree.

## IR-22 and IR-23: `crates/crabpot-windows/srt-win/` is exempt

IR-22 puts `unsafe_code` at `deny` with the unsafe reached through one module
per crate, and IR-23 wants a `// SAFETY:` comment on every unsafe block.

`crates/crabpot-windows/srt-win/` is upstream's `srt-win` source, copied byte
for byte (ADR-0005). It carries about 313 unsafe sites, written by upstream and
with no `// SAFETY:` comments, and crabpot does not rewrite upstream's Windows
security code. Adding an attribute or a comment to each site would make every
sync from upstream a merge instead of a copy.

So the exemption is the crate's own `[lints]` table in
`crates/crabpot-windows/Cargo.toml`, which does not inherit the workspace's:
`unsafe_code` and `undocumented_unsafe_blocks` are `allow` there, and so are
`missing_docs` and `missing_debug_implementations`, for the same reason. The
exemption is confined to that crate, which is what ADR-0012's split buys:
nothing else in the workspace may unsafe without one module and a `// SAFETY:`
comment.

The exemption covers the copied tree only. `crates/crabpot-windows/src/lib.rs`
is crabpot's own file and follows the rules like every other crabpot file.
