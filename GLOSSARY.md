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
The first milestone: crabpot does on macOS everything kelpie asks of upstream, and kelpie moves to it. It comes before parity.
_Avoid_: MVP, v0.1, beta

**Following**:
How crabpot keeps up after parity: reading upstream's changes since the last commit it took and porting the ones it wants.
_Avoid_: syncing, tracking, lockstep

**Differential harness**:
The test rig that runs the same case under upstream and under crabpot and compares the outcomes. Parity is reached when every case matches.
_Avoid_: conformance suite, compat tests

**Probe**:
One action a case runs inside the sandbox (read, write, connect, bind), whose outcome is allowed or refused.
_Avoid_: check, assertion

### Running

**Wrapper**:
The process that holds one sandbox's proxies and runs the sandboxed command as its child, for as long as that command lives. It is the crabpot CLI, or a host's own binary started in multicall. Recorded in ADR-0010.
_Avoid_: launcher, shim, the srt process

### Consumers

**Proving ground**:
kelpie, whose agent workers run inside crabpot before anyone else depends on it.
_Avoid_: first customer, beta
