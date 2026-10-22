# Before parity, crabpot only adds optional settings

kelpie patches upstream's compiled JavaScript to block the macOS keychain, because upstream has no setting for it. kelpie cannot patch a Rust binary, so crabpot has to offer that as a setting before kelpie can move to it. Before parity, crabpot may add a settings key that upstream lacks when the proving ground needs one. A key upstream has keeps upstream's meaning exactly, and upstream's known defects (every Unix socket refused on Linux, sandboxes that cannot nest, socket paths over 104 bytes) stay until parity. Fixing them earlier would make "does crabpot do what upstream does" impossible to answer.

## Considered options

- **Nothing beyond upstream until parity.** Rejected because kelpie could not move to crabpot without the keychain setting.
- **Fix upstream's defects as they come up.** Rejected because parity would no longer be checkable against the baseline.
