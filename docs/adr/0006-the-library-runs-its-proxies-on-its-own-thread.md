# The library runs its proxies on its own thread

Upstream runs its HTTP, SOCKS and MITM proxies inside the Node process for as long as a sandbox lives. As a library, crabpot runs them inside the host's process, on a runtime thread crabpot owns, so a host does not have to be async or use any particular runtime. The cost is that a crash in the host takes the proxies down with it, and the MITM CA key sits in the host's memory.

A separate proxy process is the alternative left open. Upstream's `srt proxy` is part of parity, so crabpot builds that mode anyway, and it can become an option for hosts that want the isolation.

## Considered options

- **On the caller's tokio runtime.** Rejected because every consumer would have to run tokio.
- **A separate process from the start.** Deferred, as above: it is more to manage before kelpie-ready, and parity brings it later.
