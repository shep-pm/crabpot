# crabpot #11: Can a crate match upstream's globs exactly?

Upstream: anthropics/sandbox-runtime @ aceba124fd725f4a43d7016ed3f5651d61f83115 (local clone read). All upstream line refs are `src/sandbox/<file>:<line>` at that commit.

## Short answer

No crate matches exactly. Upstream's dialect is bespoke: no escaping, sets end at the first `]`, backwards-range brackets degrade to text, `**` is legal anywhere, no `[!..]`, no `{a,b}`, and a deny regex gets a `(/.*)?` tail. globset, glob and wildmatch each differ on several of these (table below). Porting is the only exact path. The port is small: about 120 lines of Rust for parseGlob + token-to-regex + deny tail (glob-pattern.ts is 253 lines, about half comments). About 300-450 lines with the consumer-facing parts (entry splitting, `literalReadings`, anchor splicing, tilde/normalize). Emit the same regex string, and test it with the Rust `regex` crate against the TS output as an oracle (the macOS Seatbelt engine, not JS, is the real matcher; not tested here).

Caveat: a crate (e.g. globset) could serve only as a post-parse matcher if you first translate upstream tokens into a pattern it accepts. That translation is the port anyway, so it saves nothing.

## Upstream semantics

| Topic | Upstream behaviour | Source |
|---|---|---|
| Entry is a pattern if | contains any of `* ? [ ]` (POSIX; Windows only `* ?`) | sandbox-utils.ts:145-151, 161-163 |
| `*` | `[^/]*`: any chars except `/`. A run of `*`s: last two go with a following `/`, rest of 2+ is `**` | glob-pattern.ts:130-141, 201-202 |
| `**` | `.*`: crosses `/`, legal anywhere (`a**b`, `**.pem`) | glob-pattern.ts:203-204, 74-75; README.md:546 |
| `**/` | `(.*/)?`: zero or more directories. `**/**/` collapses to `**/`; `*` `**/` `*` collapses to `**` | glob-pattern.ts:92-111, 205-206 |
| `?` | `[^/]`: one char, not `/` | glob-pattern.ts:125-128, 199-200 |
| `[abc]`, `[a-z]` | set from `[` to the FIRST `]` after it. Members include `* ? / [`. A `/` inside a set CAN match `/` (e.g. `[+-9]`) | glob-pattern.ts:68-70, 21-33, 207-209 |
| `[!..]` / `[^..]` | NOT negation: `!`/`^` are ordinary members (`^` is regex-escaped) | glob-pattern.ts:69-70, 209 |
| `[]]`, `[]` | `[]` is empty so no set; text. A `]` is never a member | glob-pattern.ts:49, 68, 147-160 |
| Bad brackets | reversed range (`[user-id]`), empty, unclosed `[`, stray `]` become literal text, never an error; debug warning only | glob-pattern.ts:46-47, 71-73, 148-160, 178-183; README.md:546 |
| `{a,b}` | not supported; `{ }` and `,` are literal text (regex-escaped) | glob-pattern.ts:189 (escape list includes `{}`), no brace case in parseGlob:119-175 |
| Escaping | none: "no character escapes another". `\` is literal text. Literal metachar only via a bracket set (`[*]`) or a `{path, literal: true}` entry | glob-pattern.ts:65-66; README.md:546 |
| Anchoring | whole path: `^...$` | glob-pattern.ts:232 |
| Case | regex has no case flag, so the pattern is case-sensitive as emitted. Whether the Seatbelt regex engine folds case on case-insensitive APFS: not found in docs or code (looked in macos-sandbox-utils.ts, glob-pattern.ts, README Path Syntax). Case-folding exists only as a path-compare helper (sandbox-utils.ts:53-62) | glob-pattern.ts:231-233 |
| Leading dot | no dot special-casing: `*` matches dotfiles | glob-pattern.ts:201-202 |
| Trailing slash | glob with trailing `/` keeps it in the regex and matches nothing; deny entries with it are rejected at config validation. Non-glob entries have trailing `/` stripped | sandbox-config.ts:1139-1166; sandbox-utils.ts:473-494; README.md:581 |
| Trailing `/**` | stripped before compile (`dir/**` means `dir`) | sandbox-utils.ts:248-251; macos-sandbox-utils.ts:200-206 |
| `~` | leading `~` or `~/` expanded to homedir (`~\` only on Windows); `~user` not expanded. Relative paths resolve against cwd | sandbox-utils.ts:366-376, 495-501 |
| Normalizing | `//` runs and `/./` collapsed. For globs only the static directory prefix before the first `* ? [ ]` is symlink-resolved; the pattern is not | sandbox-utils.ts:403-405, 521-548 |
| No glob chars | `(subpath "<path>")`: the folder and everything beneath it | macos-sandbox-utils.ts:164-168; macos-sandbox-utils.ts:286-293 (toPathEntry) |
| Literal entry | `{path, literal: true}` is never a pattern; resolved as a name, emitted as `subpath`. Any other object shape throws | path-entries.ts:1-14, 61-71; sandbox-utils.ts:177-193 |
| String that is also a name | a pattern string is ALSO read as the path it names where the glob-bearing leading components exist on disk (`literalReadings`), plus anchored readings (anchor spliced in via `escapeRegexLiteral`, tail compiled) | path-entries.ts:157-248; macos-sandbox-utils.ts:172-191 |
| Allow vs deny (macOS) | allow: `(regex globToRegex)` = exactly `^...$`. deny: `denyGlobRegex` = same with `(/.*)?$` tail, so a deny also covers everything beneath each match; allow does not widen. Deny existence checks count symlinks and unreadable paths; allow rejects symlinks | macos-sandbox-utils.ts:164-168, 207-216; glob-pattern.ts:235-252; path-entries.ts:40-45, 118-144 |
| Consumer's bracket-everything trick | `/k/odd[1]*?` to `/k/odd[[]1[]][*][?]`: each char becomes a one-member set so it matches itself. `[[]` parses as a set with member `[` (first `]` closes); `[]]` would NOT work (empty set, text), so the trick relies on the bracket-per-character form | glob-pattern.ts:142-172 |

## Crate comparison

| Topic | Upstream | globset | glob | wildmatch |
|---|---|---|---|---|
| `*` and `/` | never crosses `/` | crosses `/` by default; `literal_separator(true)` stops it | crosses by default (`require_literal_separator` false) | crosses (no separator notion) |
| `**` | anywhere; `a**b` = `.*` | legal only as a whole component (start, end, middle); elsewhere an error. `foo/**` does not match `foo` itself | must be a whole component (`**a` error); 3+ stars invalid | not supported |
| `?` | one char, not `/` | one char; `/` only with `literal_separator` | one char; `/` unless option set | one char, any |
| `[abc]` | set to the first `]`; `[` `*` `?` `/` members | supported; `[]]`-style first `]` rules and class contents handled by globset's own parser (not verified in source) | supported; `]` right after `[` or `[!` is a member (`[]]` matches `]`) | not documented (no classes) |
| `[!x]` | no negation; `!` is a member | negation | negation | n/a |
| Bad bracket | text, warning | parse error unless `allow_unclosed_class` (unclosed only, not reversed ranges) | unclosed bracket is an error | n/a |
| `{a,b}` | literal text | alternation; nested not allowed | not supported | none |
| Escaping | none; `\` literal | `\` escapes by default on Unix; `[*]` | brackets only (`Pattern::escape`); `\` not an escape | none ("no escape characters") |
| Case | emitted case-sensitive | case-sensitive by default; `case_insensitive` option | `MatchOptions::new()` is case-sensitive; docs say `default()` sets false (insensitive) | not documented |
| Leading dot | no special case | no special case | `require_literal_leading_dot` option, default false | none |
| Deny `(/.*)?` tail | yes | no; caller would add a second `foo/**` glob | no | no |
| Emits a regex string | yes (needed for `(regex ...)` in SBPL) | `Glob::regex()` gives its own regex, not upstream's | no regex output | no |
| Result | reference | closest but differs on `**`, `[!]`, `{}`, `\`, bad brackets | differs more | far off |

I found no closer crate (one web search found no Rust port of sandbox-runtime; microsandbox is unrelated). That search is thin evidence, not proof none exists.

## Sources

- Upstream, github.com/anthropics/sandbox-runtime @ aceba124fd725f4a43d7016ed3f5651d61f83115: src/sandbox/glob-pattern.ts, path-entries.ts, macos-sandbox-utils.ts, sandbox-utils.ts, sandbox-config.ts, README.md (Path Syntax sections). The table rows above come from source, not docs, except where README.md is cited.
- https://docs.rs/globset/latest/globset/#syntax
- https://docs.rs/globset/latest/globset/struct.GlobBuilder.html
- https://docs.rs/glob/latest/glob/struct.Pattern.html
- https://docs.rs/glob/latest/glob/struct.MatchOptions.html
- https://docs.rs/wildmatch/latest/wildmatch/
- https://raw.githubusercontent.com/becheran/wildmatch/master/README.md

Not verified: globset's treatment of `]` as first class member and behaviour on a reversed range (docs fetched do not state it; read globset source before relying on it); glob's `default()` vs `new()` case default is taken from the docs page as fetched.
