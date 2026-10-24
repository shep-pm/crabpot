# crabpot

crabpot is a Rust rewrite of Anthropic's sandbox runtime. It confines a process's filesystem and network access with the operating system's own sandboxing.

## Language

### Upstream

**Upstream**:
anthropics/sandbox-runtime, the TypeScript project crabpot is rewritten from.
_Avoid_: the original, srt (as the name of the project), the TS version

**Baseline**:
The one upstream commit crabpot is measured against until parity. Recorded in ADR-0001.
_Avoid_: pin, target version

**Parity**:
The state where crabpot does what upstream does at the baseline, on macOS and Linux, except the Java proxy agent. Windows comes after parity.
_Avoid_: feature-complete, done

**Kelpie-ready**:
A milestone per platform: crabpot does on that platform everything kelpie asks of upstream there, and kelpie moves to it on that platform. Always named with its platform, as in kelpie-ready on Linux. Each comes before parity.
_Avoid_: MVP, v0.1, beta

**Following**:
How crabpot keeps up after parity: reading upstream's changes since the last commit it took and porting the ones it wants.
_Avoid_: syncing, tracking, lockstep

**Differential harness**:
The test rig that runs the same case under upstream and under crabpot and compares the outcomes. Parity is reached when every case matches.
_Avoid_: conformance suite, compat tests

**Case**:
A settings file, the files it starts from, and the probes run against it.
_Avoid_: scenario, fixture (for the whole case), test

**Probe**:
One action a case runs inside the sandbox (read, write, rename, connect, bind, bind-unix,
connect-unix, loopback, signal-group, ps), whose outcome is allowed or refused.
_Avoid_: check, assertion

### Running

**Wrapper**:
The process that holds one sandbox's proxies and runs the sandboxed command as its child, for as long as that command lives. It is the crabpot CLI, or a host's own binary started in multicall. Recorded in ADR-0010.
_Avoid_: launcher, shim, the srt process

**Args file**:
The unnamed file a bwrap policy too long for one `exec` line moves its flags to, which `bwrap` reads back with `--args`. It is opened `O_TMPFILE`, and the line reaches it through `/proc/<pid>/fd/<n>`.
_Avoid_: profile file, args profile, response file

### Filesystem

**Mandatory denies**:
The write protection a sandbox applies in and below its own working directory whatever the settings say: shell and tool settings files and each git repository's hooks and config, and the directories holding them, found by a walk down to the search depth. They are in no list of the settings, and on Linux they go through the same deny loop as `denyWrite`.
_Avoid_: built-in denies, implicit denies, system denies

### Consumers

**Proving ground**:
kelpie, whose agent workers run inside crabpot before anyone else depends on it.
_Avoid_: first customer, beta
