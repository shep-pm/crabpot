# Research for crabpot #9: which crates carry the proxies kelpie needs

Data pulled 2026-10-22 from the crates.io API (version, created_at, rust_version, downloads, dependency lists, feature tables). "MSRV" = crates.io `rust_version` field; "unset" means the crate declares none, so 1.88 compatibility is unverified.

## Short answer

- Runtime: tokio 1.54.1 (MSRV 1.85), `default-features = false`, features `rt`, `net`, `io-util`, `time`, `sync` (`rt-multi-thread` optional). Own the runtime on a dedicated thread via `Builder::new_current_thread()` or multi-thread.
- HTTP proxy, mux, Unix-socket forwarding and the resolved-address guard are simplest hand-written on tokio. Parse request heads with `httparse` (no deps, MSRV unset); do not use hyper for the proxy.
- SOCKS5 server: hand-write (about 150 lines, RFC 1928 CONNECT only) or use fast-socks5 1.0.0 (unset MSRV, pulls anyhow, thiserror 1, async-trait, log, socket2 0.5, tokio-stream). Hand-written is leaner.
- DNS: `tokio::net::lookup_host` (getaddrinfo on the blocking pool, same as Node `dns.lookup` that upstream uses). Skip hickory-resolver: it is async-native with its own cache and resolv.conf logic, and a different resolver than libc, so it can disagree with the OS.
- No candidate pushes MSRV above 1.88. hickory-resolver 0.26.3 is exactly 1.88 (the only one at the limit), so it is the one to watch. Not checked: transitive MSRV of unset-MSRV crates.

## Upstream behaviour being matched (local clone, commit aceba124fd725f4a43d7016ed3f5651d61f83115)

- `src/sandbox/mux-proxy.ts`: one-byte peek; 0x04/0x05 go to SOCKS, anything else to HTTP.
- `src/sandbox/resolved-address-guard.ts`: wraps `dns.lookup`, resolves once, drops denied addresses, dials a surviving one (no second resolution). Hostnames only.
- `src/sandbox/http-proxy.ts` ~L890-905: mitm socket path is dialed with `connect({ path })` for CONNECT.

## Part 1: async runtime

| Crate | Version / date | MSRV | Downloads (total / recent) | Deps (needed) | Notes |
|---|---|---|---|---|---|
| tokio | 1.54.1 / 2026-10-21 | 1.85 | 1.096B / 270M | Required: pin-project-lite. With `net` adds mio (nodef), socket2 0.6, libc; `rt` and `io-util` add bytes | Default features are empty. Enable only `rt`, `net`, `io-util`, `time`, `sync`. Has `UnixStream`, `UnixListener`, `lookup_host`, `copy_bidirectional`. Actively maintained. |
| smol 2.0.2 (async-io 2.6.0, async-net 2.0.0, async-executor 1.14.0) | smol 2024-09-07 | 1.63 (smol); async-io 1.71 | smol 26.6M / 7.1M | smol pulls 9 crates (async-channel, async-executor, async-fs, async-io, async-lock, async-net, async-process, blocking, futures-lite) | Works, but the ecosystem (hyper, fast-socks5, socks5-server, hickory default) assumes tokio. smol is quieter (last release 2024-09; async-net 2023-10). No reason to pick it. |

Recommendation: tokio. A single owned `Runtime` on a thread the library spawns. The host needs no tokio.

## Part 2: HTTP/1.1 proxy with CONNECT

| Option | Version / date | MSRV | Downloads (total / recent) | Deps | Verdict |
|---|---|---|---|---|---|
| httparse | 1.10.1 / 2025-03-03 | unset | 815M / 200M | none; default feature `std` | Hand-written proxy on top. Gives `Request` parsing (method, URI, headers) with zero deps. Needs own loop for header limits, absolute-URI forwarding, hop-by-hop headers, chunked bodies. CONNECT itself is trivial: read head, filter, dial, write `200`, `copy_bidirectional`. |
| hyper | 1.12.0 / 2026-10-06 | 1.63 | 1.037B / 246M | Required: bytes, http, http-body, tokio. Optional via `server`+`http1`: httparse, httpdate, itoa, pin-project-lite, smallvec, want, futures-channel, futures-core, atomic-waker | Doable (`serve_connection(...).with_upgrades()` handles CONNECT), but pulls `http`/`http-body` and a service-trait layer. Pays off only if you must forward plain-HTTP bodies robustly. |
| hyper-util | 0.1.21 / 2026-09-24 | 1.85 | 564M / 180M | Required: bytes, http, http-body, hyper, pin-project-lite; the rest optional | Needed with hyper 1.x for `TokioIo` and the legacy client. Adds weight for little. |
| http-body-util | 0.1.5 / 2026-08-12 | 1.61 | 548M / 180M | (hyper helper) | Only if using hyper. |
| tiny_http | 0.12.0 / 2022-10-06 | unset | 71M / 16.5M | sync | Stale, no CONNECT support seen (not verified), skip. |

Recommendation: httparse plus hand-written logic on tokio. Reason: CONNECT plus absolute-URI forwarding is a small state machine, and hyper adds http, http-body, bytes, tower-style APIs. If plain-HTTP forwarding proves large, take hyper with `default-features = false, features = ["server","client","http1"]` and hyper-util (`tokio`, `client-legacy`) later; both are compatible with 1.88.

## Part 3: SOCKS5 server

| Crate | Version / date | MSRV | Downloads (total / recent) | Deps | Notes |
|---|---|---|---|---|---|
| fast-socks5 | 1.0.0 / 2026-01-20 | unset | 2.45M / 466K | anyhow, async-trait, log, socket2 0.5, thiserror 1, tokio, tokio-stream (all required, no optional) | Server and client. Heaviest dependency set; socket2 0.5 duplicates tokio's 0.6; thiserror 1 old. |
| socks5-server | 0.10.1 / 2024-04-10 | unset | 268K / 54K | async-trait, bytes, socks5-proto, tokio (all nodef) | Small, but stale (2024-04). This is the crate family upstream's JS server is not related to. |
| socks5-impl | 0.10.3 / 2026-10-19 | unset | 449K / 79K | all optional; default feature `protocol`; server features add tokio, async-trait, bytes | Active. Less adopted. |
| tokio-socks | 0.5.3 / 2026-05-29 | unset | 24M / 3.9M | client only | Not a server. Not relevant. |
| hand-written | n/a | n/a | n/a | tokio only | Greeting (0x05, methods; pick no-auth), request (CONNECT only; ATYP IPv4/IPv6/domain), reply codes. Upstream also accepts SOCKS4 first byte 0x04 in the mux (mux-proxy.ts L21); hand-written can reply per its own policy. |

Recommendation: hand-write. Reason: the server needs only no-auth CONNECT, and the hand-written code lets the allow-list and address guard sit directly between "parse request" and "dial" with no callbacks or extra deps. Fallback: socks5-impl with only the server features, or fast-socks5.

## Part 4: first-byte mux

| Option | Notes |
|---|---|
| Hand-written on tokio | `TcpStream::peek(&mut [0u8;1])` (no consume, so no unshift needed, unlike Node's `read(1)`+`unshift`), then dispatch 0x04/0x05 to SOCKS, else HTTP. Add a first-byte timeout (upstream has `firstByteTimeoutMs`) with `tokio::time::timeout`. For a Unix-socket listener use `UnixStream::peek` where available (not verified; fall back to a small buffered wrapper that replays the byte). No crate needed. |

Recommendation: hand-written, about 30 lines.

## Part 5: DNS with a resolved-address check

| Option | Version / date | MSRV | Downloads (total / recent) | Deps | Notes |
|---|---|---|---|---|---|
| `tokio::net::lookup_host` | in tokio | 1.85 | n/a | none extra | Runs `getaddrinfo` via the blocking pool; returns every address. Matches upstream (`dns.lookup`). Check each address against the deny ranges, then `TcpStream::connect(addr)` to the surviving `SocketAddr` so there is no second resolution. |
| hickory-resolver | 0.26.3 / 2026-09-10 | 1.88 (at the limit) | 90.7M / 28.9M | Required: cfg-if, futures-util, hickory-net, hickory-proto, ipnet, moka, once_cell, parking_lot, rand 0.10, smallvec, thiserror 2, tracing. Default features `system-config`, `tokio`; turn off `system-config` only if supplying own config | Pure-Rust, own cache and config; large tree; can answer differently from libc (hosts file, nsswitch, mDNS). Only worth it if getaddrinfo's blocking-pool behaviour becomes a problem. Maintained. |
| `std::net::ToSocketAddrs` | std | 1.88 | n/a | none | Blocking; wrap in `spawn_blocking`. Same as `lookup_host`. |
| IP range check | hand-written, or `ipnet` 2.x (not looked up here) | n/a | n/a | | Deny ranges are a handful of CIDRs; `std` `Ipv4Addr`/`Ipv6Addr` helpers plus masks suffice. Remember IPv4-mapped IPv6 (`::ffff:a.b.c.d`) when checking. |

Recommendation: `tokio::net::lookup_host` plus a hand-written guard. Reason: one resolution, same resolver as the OS, no extra crates.

## Part 6: forwarding a tunnel to a Unix socket (mitmProxy)

| Option | Notes |
|---|---|
| `tokio::net::UnixStream::connect(path)` + `tokio::io::copy_bidirectional` | In tokio (`net` + `io-util`), unix-only (`cfg(unix)`). No extra crates. Matches upstream `connect({ path: mitmSocketPath })` in http-proxy.ts. Windows is not covered by tokio's UnixStream; upstream's mux also differs on Windows (TCP). Whether crabpot targets Windows was not part of this question. |

Recommendation: tokio only.

## Recommended stack

| Part | Pick | One-line reason |
|---|---|---|
| Runtime | tokio 1.54.1, no default features, `rt net io-util time sync` | MSRV 1.85, only pin-project-lite required, everything else below needs it anyway |
| HTTP proxy + CONNECT | httparse 1.10.1 + hand-written | zero deps; CONNECT is a small state machine |
| SOCKS5 server | hand-written (fallback socks5-impl) | no-auth CONNECT only; keeps policy checks inline, no extra deps |
| Mux | hand-written `peek(1)` | about 30 lines; peek avoids upstream's unshift |
| DNS + guard | `tokio::net::lookup_host` + hand-written range check, dial the checked `SocketAddr` | single resolution, OS resolver semantics |
| Unix forwarding | `UnixStream` + `copy_bidirectional` | built in |

Net new deps: tokio (with bytes, mio, socket2, libc via features) and httparse.

## MSRV above 1.88

None of the candidates found. Closest: hickory-resolver/hickory-proto 0.26.3 at exactly 1.88 (a future minor could raise it). Unset-MSRV crates (httparse, fast-socks5, socks5-*) were not compiled against 1.88 here; their MSRV was not verified.

## Sources

- https://crates.io/api/v1/crates/tokio, /tokio/1.54.1/dependencies
- https://crates.io/api/v1/crates/hyper, /hyper/1.12.0/dependencies
- https://crates.io/api/v1/crates/hyper-util, /hyper-util/0.1.21/dependencies
- https://crates.io/api/v1/crates/httparse, /http-body-util, /httpdate, /tiny_http
- https://crates.io/api/v1/crates/fast-socks5, /fast-socks5/1.0.0/dependencies
- https://crates.io/api/v1/crates/socks5-server, /socks5-impl, /tokio-socks (plus /dependencies)
- https://crates.io/api/v1/crates/hickory-resolver, /hickory-resolver/0.26.3/dependencies
- https://crates.io/api/v1/crates/smol, /async-io, /async-net, /async-executor, /async-std
- https://github.com/anthropics/sandbox-runtime at aceba124fd725f4a43d7016ed3f5651d61f83115: src/sandbox/{mux-proxy,resolved-address-guard,http-proxy,socks-proxy}.ts (read via a local clone)
- Claims about `tokio::net::lookup_host`, `UnixStream`, `copy_bidirectional`, `TcpStream::peek` and hyper's `with_upgrades` come from memory of tokio and hyper docs (docs.rs), not re-fetched this session; verify before committing to the design.
