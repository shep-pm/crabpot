# crabpot's start, as kelpie should one day run it

crabpot is the first project taken from nothing to merged work, as shep-pm/shep-kelpie#897 describes. This log records every step: who did it, how, and what kelpie lacked. Each gap becomes a shep-kelpie issue at the end.

Step numbers follow the table in #897. A step it does not list gets a letter.

## Step 0: the idea, and the tracking issue

- **Who:** the maintainer.
- **How:** opened shep-pm/shep-kelpie#897 and created `shep-pm/crabpot` on GitHub (private and empty, with no branch pushed). A local checkout had one commit holding GitHub's Rust `.gitignore` and `.gitattributes`. `crabpot` 0.0.0 was published to crates.io as a placeholder to reserve the name.
- **Gaps:**
  - Nothing records that the repo exists, or that the crates.io name is reserved, so the next step had to rediscover both.

## Step 1: settle the inputs

- **Who:** a Claude Code session, through the `init-shep` skill, asking the maintainer.
- **Decided:**

  | input | value | why |
  |---|---|---|
  | name | `crabpot` | the maintainer's |
  | description | Native Rust sandbox runtime for AI agents, rewritten from Anthropic's sandbox-runtime | written by the session from upstream's README; the maintainer did not choose it |
  | kind | `lib` | upstream is a library (`SandboxManager`) plus the `srt` CLI. The template renders only one, so the library comes first |
  | visibility | public | the repo on GitHub was private and got flipped |
  | publish | yes | the maintainer owns the reserved crate |
  | licence | MIT OR Apache-2.0 plus `NOTICE` | upstream is Apache-2.0 only, and a port is a derivative work |

- **Gaps:**
  - `init-shep` step 2 treats a taken crates.io name as a reason to stop. It cannot tell a name the maintainer reserved (same owner as `gh api user`) from one somebody else holds. The session had to ask.
  - `init-shep` assumes a new repo. Here the repo already existed, as private, empty and with no branches. Step 6 ("existing repo → branch and PR") does not fit an empty one, which has no `main` to open a PR against.
  - Nothing checks the licence of upstream when the project is a port or a fork. The dual-licence template went in by default, and the `NOTICE` was a judgement call.
  - `--kind` is lib or bin, never both. A crate that ships a library and a CLI is common.
  - The description went in without the maintainer choosing it.

## Step 3: render the org's setup

- **Who:** the session, running `init-shep`'s `render.py` into the existing checkout, then again into a scratch dir to diff the files it skipped.
- **Flags:** `--name crabpot --description "…" --holder TurtIeSocks --funding TurtIeSocks --kind lib --public --publish`
- **By hand afterwards:**
  - Merged the template's Claude Code lines into the existing `.gitignore`.
  - Filled the `init-shep:` markers in README.md and CLAUDE.md.
  - Added `NOTICE` and a README line pointing to it.
  - Swapped Cargo.toml's `keywords = ["shep"]` for sandbox keywords.
  - Added a `.coderabbit.yaml` `path_instructions` entry for `src/**` that treats the sandbox as a security boundary.
- **Gaps:**
  - The templates assume every repo is part of shep. Cargo.toml's `keywords = ["shep"]`, the "shep's MSRV" comment and CLAUDE.md's sheep/flock/dogs vocabulary make no sense in a project that is not a shep dog or client.
  - `unsafe_code = "forbid"` comes from the template. A sandbox runtime needs FFI (`sandbox_init`, seccomp, namespaces), so this has to be relaxed to `deny` with a written exception before the first platform module lands. The template has no `--kind` or flag for a crate that needs FFI.
  - The skill's prompts (the inputs table, merging skipped files, the markers) live only in a Claude Code session. Kelpie cannot run any of it.

<!-- Steps 4 onward are appended as they happen. -->
