# On Windows, the folders above a grant in a read deny can be stat'd

A read deny on Windows is one inheritable `FILE_ALL` deny ACE on the folder. A grant beneath it wins on the path it names, because an ACE set on an object comes before the ones it inherits. The folders in between have no ACE of their own, so they keep the inherited deny, and the sandbox user cannot read their attributes. A program that checks each component of a path fails there: kelpie denies the home folder and grants paths under `~\.shep`, and claude refused its own settings file with "a component that could not be examined".

Upstream's macOS profile allows `file-read-metadata` on every directory for this reason (`src/sandbox/macos-sandbox-utils.ts:922-930`). Its Windows path has no counterpart, so a deny with a grant beneath it behaves differently on the two platforms. crabpot follows the macOS profile here and goes past upstream's Windows path, which is the first change to upstream's behaviour in `crates/crabpot-windows/srt-win/` (`crates/crabpot-windows/PATCHES.md`).

Each existing folder that lies above a read or write grant and strictly beneath a read deny gets a non-inherited allow of `FILE_READ_ATTRIBUTES | SYNCHRONIZE` (`0x0010_0080`) for the sandbox user. `NO_INHERIT` keeps it on that folder: nothing beneath it is reached, listing the folder stays denied, and so do the files next to the grant. `acl grant` reads the folders from a `metadata` list in its stdin, which the plan writes only when it is not empty. On a folder that the session also read-denies, which happens to a path the profile read grant records, the metadata allow is written ahead of that deny: the deny carries the attribute bits too and would win otherwise. The deny still blocks every other right. The list is per session, like the read grants, and is left out of the check of grants against the profile exclusions, since it reads no content.

A folder that is itself a read deny keeps its explicit deny, which outranks an explicit allow. So a deny nested in another deny, with a grant beneath both, stays unreadable. That case is left as it is: it is rare, and such a folder is left out of the list.

## Considered options

- **Leave it, as upstream's Windows path does.** Rejected: the two platforms differ for the same settings, and kelpie's own configuration hits it.
- **Grant the folders `FILE_LIST_DIRECTORY` too.** Rejected: macOS allows metadata only, and a listing would show the names of what the deny hides.
- **Make the metadata allow inheritable.** Rejected: it would reach every file and folder beneath, including the denied ones next to the grant.
