# The keychain is blocked with a `denyMachLookup` list

Upstream writes `com.apple.securityd.xpc` and `com.apple.SecurityServer` into every macOS profile, so any sandboxed command can ask for a login the `security` command stored, with no prompt. kelpie removes both lines from upstream's compiled JavaScript, which it cannot do to a Rust binary. ADR-0003 lets crabpot add an optional setting for this, and the setting is `network.denyMachLookup`: a list of Mach service names in `allowMachLookup`'s syntax, a trailing `*` matching by prefix. Each entry becomes a `(deny mach-lookup ...)` rule at the end of the profile, so it wins over the built-in allows and over the caller's own `allowMachLookup`, `"*"` included. It is macOS only and ignored elsewhere, as `allowMachLookup` is. Left out, the profile is upstream's.

kelpie passes the two keychain services. The differential harness cannot compare a key upstream lacks, so a crabpot test on the macOS runner proves it: an item stored with `security add-generic-password` is refused to `security find-generic-password` and `git credential-osxkeychain` inside the sandbox, while `curl`, Go's TLS and `git ls-remote` still work.

## Considered options

- **A keychain switch, crabpot knowing the two names.** Rejected because it reaches only the keychain, while a list covers any service and pairs with a key upstream already has, which makes it the one to propose upstream. The cost is that a misspelt name leaves the service open, which the test above catches for kelpie's two.
