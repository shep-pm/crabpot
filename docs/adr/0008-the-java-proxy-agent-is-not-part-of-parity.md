# The Java proxy agent is not part of parity

Upstream ships `srt-proxy-agent.jar`, a JVM agent it injects through `JAVA_TOOL_OPTIONS` so Java programs use the sandbox's proxy. It has to run inside the JVM, so it cannot be Rust, and building it would put a JDK in crabpot's build for a helper few hosts need. crabpot leaves it out and is at parity without it. It still honours the `javaAgentJarPath` setting, so a host that needs the agent can point it at upstream's jar.

## Considered options

- **Build the jar from upstream's Java source and ship it.** Rejected for the JDK in the build, and because ADR-0002 keeps upstream's helpers out.
