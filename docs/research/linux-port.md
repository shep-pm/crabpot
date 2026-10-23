Throwaway findings for shep-pm/crabpot#87, never merged. Traced by Comrade Q (escalated to pi) at `aceba124`; 6 of 6 spot-checked citations hold.

# `srt` on Linux: `SandboxManager.initialize()` → `wrapWithSandbox()` trace

Repo: `anthropics/sandbox-runtime` @ `aceba124` (v0.0.81). All line numbers are
from `git show aceba124:<path>`.

Config under trace (nothing else set):

```json
{
  "filesystem": { "allowRead": [...], "denyRead": [...], "allowWrite": [...], "denyWrite": [...] },
  "network": {
    "allowedDomains": [...], "deniedDomains": [...], "strictAllowlist": true,
    "deniedResolvedAddresses": [...],
    "mitmProxy": { "socketPath": "...", "domains": [...] },
    "allowUnixSockets": [...], "allowLocalBinding": true
  },
  "enableWeakerNetworkIsolation": true
}
```

Not set (so library defaults apply): `credentials`, `ripgrep`, `mandatoryDenySearchDepth`
(→ 3), `allowGitConfig` (→ false), `enableWeakerNestedSandbox` (→ false),
`allowNestedUserNamespaces` (→ false), `allowAllUnixSockets` (→ undefined/false),
`seccomp`, `bwrapPath`, `socatPath`, `binShell` (→ `bash`), `filesystem.disabled` (→ false),
`git.safeDirectories`, `tlsTerminate`, `parentProxy`, `httpProxyPort`/`socksProxyPort`,
`ignoreViolations`, `allowPty`.

---

## 0. How the CLI drives it (`src/cli.ts`, 665 lines)

| Step | file:line |
|---|---|
| `main()` | `src/cli.ts:175` |
| config path `~/.srt-settings.json` | `src/cli.ts:19` (`getDefaultConfigPath`), used at `:369` |
| `loadConfig(configPath)` → zod parse | `src/cli.ts:370` → `src/utils/config-loader.ts:46` (schema `safeParse` at `:78`) |
| built-in default config (only when the file is *missing and unnamed*) | `src/cli.ts:63` (`getDefaultConfig`), reached at `:389`; a named/empty/invalid file exits 1 via `refuseSettings` `src/cli.ts:46` |
| Windows-only `srtWin` injection | `src/cli.ts:409-423` — **not reached** on Linux |
| control-fd plumbing (`openControlFd` `:94`, `parseControlFd` `:130`, `sandboxedStdio` `:149`) | reached only with `--control-fd`; `sandboxedStdio` is unconditional at `src/cli.ts:609` (returns plain `[inherit,inherit,inherit]` when no fd) |
| `await SandboxManager.initialize(runtimeConfig)` | **`src/cli.ts:505`** — one argument only |
| `getNetworkRestrictionConfig()` (debug print) | `src/cli.ts:573` |
| `wrapWithSandbox(command, undefined, undefined, interrupted.signal)` | **`src/cli.ts:600`** (`command` is `quote(commandArgs)` at `:562`, or raw `-c` string at `:555`) |
| `spawn(sandboxedCommand, { shell: true, stdio: sandboxedStdio(controlFd) })` | `src/cli.ts:607-610` |
| `SandboxManager.cleanupAfterCommand()` on child exit | `src/cli.ts:618` |

**Key consequence of `src/cli.ts:505`:** `initialize`'s third parameter
`enableLogMonitor` defaults to `false` (`src/sandbox/sandbox-manager.ts:1102`), and the CLI
never passes it. See §6.

---

## 1. Every function on the path, grouped by file

Legend: **N** = needed for this config, **U** = unconditional (runs whatever the config says),
**✗** = not reached on this path.

### `src/cli.ts` (665 lines)
| fn | line | size | verdict |
|---|---|---|---|
| `main` | 175 | ~485 | N |
| `getDefaultConfigPath` | 19 | 10 | U |
| `getPackageVersion` | 31 | 4 | U (only `--version`) — ✗ for a run |
| `refuseSettings` | 46 | 15 | ✗ (only on a bad settings file) |
| `getDefaultConfig` | 63 | 17 | ✗ (config file exists) |
| `openControlFd` / `parseControlFd` | 94 / 130 | 35 / 8 | ✗ (no `--control-fd`) |
| `sandboxedStdio` | 149 | 25 | U |
| `onControlError` (closure) | 433 | ~33 | ✗ |
| `aboutToSpawn` (closure) | 497 | 5 | U |

### `src/utils/config-loader.ts` (90 lines)
| fn | line | verdict |
|---|---|---|
| `loadConfig` | 46 | N |
| `loadConfigFromString` | 11 | ✗ (only for `--control-fd` updates) |

### `src/sandbox/sandbox-manager.ts` (3579 lines)
| fn | line | size | verdict |
|---|---|---|---|
| `initialize` | 1099 | 21 | N — `enableLogMonitor=false` default at `:1102` |
| `initializeSteps` | 1121 | ~480 | N |
| `resolveParentProxy` (call) | 1140 | — | U (returns `undefined` with no `parentProxy`) |
| `createResolvedAddressGuard` (call) | 1146 | — | N (`network.deniedResolvedAddresses` feeds it) |
| `assertTlsTerminationSupported` / `createMitmCA` | 1163 / 1170 | — | ✗ (no `tlsTerminate`) → `mitmCA` stays `undefined` |
| `checkDependenciesAsync` | 1715 (called 1176) | 13 | N |
| `getApplySeccompBinaryPathAsync` | 1722 (in `checkDependenciesAsync`) | — | N when `seccomp.argv0` unset (`generate-seccomp-filter.ts:217`) |
| `checkDependenciesCommon` | 1623 | 75 | N — Linux branch `:1643-1660` |
| `whichSync('rg')` check | 1646-1650 | — | N |
| `checkLinuxDependencies` (call) | 1652 | — | N |
| `ownInstallWarning` (call) | 1688 | — | U (warning only) |
| `startMacOSSandboxLogMonitor` | 1199 | — | ✗ (platform) |
| `startLinuxSandboxViolationMonitor` | **1220** (block 1206-1256) | — | **✗ — `enableLogMonitor` is false** |
| `getFsWriteConfig` (monitor input) | 2028 (called 1219) | 28 | ✗ (only inside that block) |
| `linuxGetCwdMandatoryDenyPaths` (monitor input) | 441 (called 1246) | 39 | ✗ (same block) |
| `registerCleanup` | 417 (called 1259) | 40 | U |
| Windows block (`resolveSrtWin`, `getWindowsSandboxUserStatusAsync`, `grantWindowsAclPersistent`, `verifyWindowsWfpEgress`, …) | 1272-1508 | ~240 | ✗ |
| network-init async block | 1513-1598 | ~85 | N |
| `startMuxProxyServer` | 967 (called 1546) | 122 | N (both proxy ports are internal here) |
| `filterNetworkRequest` | 731 (called 975 / 1027) | 108 | N — `deniedDomains` → `allowedDomains` → `strictAllowlist` (`:786-791`) → per-command list → ask callback (none: CLI passes no callback) |
| `getMitmSocketPath` | 906 (passed to the HTTP proxy at 980) | 15 | N — host-side only; matches `mitmProxy.domains`, returns `mitmProxy.socketPath` |
| `shouldTerminateTLSForHost` | 935 | 33 | ✗ (no `tlsTerminate`) |
| `directLookup` (const) | 672 | 12 | N — the proxies' `lookupFor`, applies the resolved-address guard |
| `getJavaProxyAgentJarPathAsync` | 1548 | — | U (jar shipped in the published package; `null` → no `JAVA_TOOL_OPTIONS`) |
| `mitmCA.crlUrl = …` | 1560-1563 | — | ✗ (gated on `getPlatform() === 'windows'`) |
| **`initializeLinuxNetworkBridge`** | **1572** (defined `linux-sandbox-utils.ts:1513`) | 163 | N |
| `isSupportedPlatform` | 1603 | 8 | U (WSL1 → false → dependency error) |
| `getNetworkRestrictionConfig` | 2193 | 18 | U (CLI debug print) |
| `getAllowUnixSockets` | 2213 | 3 | **✗ on Linux** — called only in the `case 'macos'` branch (`:2702`) |
| `getAllowLocalBinding` | 2221 | 3 | **✗ on Linux** — `:2704` only |
| `getAllowMachLookup` | 2225 | 3 | ✗ (macOS-only key) |
| `getEnableWeakerNetworkIsolation` | 2237 | 3 | **✗ on Linux** — `:2710` only |
| `getEnableWeakerNestedSandbox` | 2233 | 3 | N (→ `undefined` → `--proc /proc`) |
| `getAllowAllUnixSockets` | 2217 | 3 | N (`:2744`, the only unix-socket knob Linux reads) |
| `getIgnoreViolations` | 2229 | 3 | ✗ on Linux (macOS branch only) |
| `getRipgrepConfig` | 2245 | 3 | N → `{ command: 'rg' }` |
| `getMandatoryDenySearchDepth` | 2249 | 3 | N → **3** |
| `getAllowGitConfig` | 2253 | 9 | N → false |
| `getGitSafeDirectories` | 2263 | 8 | N → `[]` |
| `getSeccompConfig` | 2272 | 3 | N → `undefined` |
| `getProxyPort` / `getSocksProxyPort` | 2280 / 2284 | — | N (mux port) |
| `getLinuxHttpSocketPath` / `getLinuxSocksSocketPath` | 2288 / 2292 | — | N |
| `waitForNetworkInitialization` | 2300 (called 2647) | 15 | N |
| `waitToWalk` | 2365 (called 2417) | 26 | U |
| `wrapWithSandbox` | 2393 | 14 | N |
| `wrapWithSandboxAgain` | 2409 | 22 | U (restart loop, `RESTARTS_IN_TURNS = 2` at 2361) |
| `wrapWithSandboxOnce` | 2434 | ~343 | N |
| `registerCommandText` | 522 (called 2445) | 22 | U |
| `stripWriteGlobs` | 1938 (2511, 2527) | 18 | N (drops `allowWrite`/`denyWrite` patterns that are not names on Linux) |
| `defaultWritePathsUnder` | 1842 (2515) | 16 | N |
| `getCredentialDenyReadPaths` | 1824 | 7 | U → `[]` (no `credentials`) |
| `literalWriteLists` / `literalReadLists` | path-entries 355 / 344 | — | U → absent |
| `ownInstallWarning` (wrap-time) | 2544 | — | U once per process |
| `resolveReadPathEntries` | 1894 (2566) | 31 | N (`allowRead`) |
| `expandAllowReadGlob` | 1958 | 9 | N only if an `allowRead` entry has glob chars |
| `walkGlobPatternSteps` | sandbox-utils 1622 | — | conditional |
| `reExposedBy` | path-entries 384 (2588) | 17 | N |
| `resolveReadDenies` | 1861 (2595) | 20 | N (`denyRead`) |
| `expandReadDenyGlobLinuxSteps` | read-deny-glob.ts (called 2600) | — | N only for glob `denyRead` entries |
| `getCredentialRestrictions` | 1740 (2507) | 78 | U → all-empty |
| `case 'macos': wrapCommandWithSandboxMacOS` | 2685-2713 | — | ✗ |
| **`case 'linux': wrapCommandWithSandboxLinux`** | **2715-2759** | 45 | N |
| `case 'windows'` throw | 2761-2768 | — | ✗ |
| `cleanupAfterCommand` | 3072 | 2 | N (CLI `:618`) |
| `reset` | 3188 | ~120 | U (via `registerCleanup` at exit) |
| `updateConfig` | 3015 | — | ✗ (no control fd) |

### `src/sandbox/linux-sandbox-utils.ts` (3937 lines)
| fn | line | size | verdict |
|---|---|---|---|
| **`wrapCommandWithSandboxLinux`** | **3532** | 405 | N |
| `readNamesOf` / `writeNamesOf` | path-entries 401 / 427 (3566-3567) | — | N (fold `literal…` lists into name lists) |
| early "nothing to sandbox" return | 3583-3592 | — | ✗ (`needsNetworkRestriction` is true) |
| seccomp prefix block | 3614-3641 | 28 | N (see §4) |
| `resolveApplySeccompPrefix` | 1731 (3618) | 15 | N |
| `helperEnvironmentPrefix` | 1684 (3632) | 5 | N |
| observe-socket block | 3644-3659 | 16 | **✗** (`observeSocketPath` undefined, §6) |
| env restrictions block | 3661-3677 | — | ✗ (no `credentials`) |
| git `safe.directory` block | 3679-3693 | — | ✗ (`gitSafeDirectories` empty) |
| network block | 3695-3778 | 84 | N |
| `generateProxyEnvVars` | sandbox-utils 772 (3730) | 227 | N |
| `buildJavaToolOptions` | java-proxy-agent 104 (3752) | — | conditional (jar present) |
| `generateFilesystemArgs` | 2095 (3789) | **1388** | N |
| `capabilityArgs` | 788 (3825) | 17 | N |
| `processHasBoundingCapability` | 726 (3817) | 32 | N (reads `/proc/self/status` once) |
| `bwrapCanDisableUserns` | 1696 (3857) | 21 | **✗ when the seccomp helper is in use** (3847-3866) |
| `buildSandboxCommand` | 1793 (3891) | 63 | N (network-restricted wrap) |
| `renderBwrapInvocation` | 1035 (3907) | 82 | N |
| `maxArgStrlen` | 827 | 33 | N (reads `/proc/self/auxv`) |
| `openBwrapArgsProfile` | 916 | 31 | conditional (profile > 128 KiB − 4 KiB) |
| `cleanupBwrapMountPoints` | 1163 | 80 | N (via `cleanupAfterCommand`) |
| `registerExitCleanupHandler` | 1128 | 33 | U (only if a placeholder was planned) |
| `initializeLinuxNetworkBridge` | 1513 | 163 | N (§3) |
| `checkLinuxDependencies` | 1304 | 50 | N (§7) |
| `getLinuxDependencyStatus` | 1286 | 17 | ✗ (not on this path; public helper) |
| `probeBwrapVersion` / `compareVersions` / `outdatedBwrapWarning` | 1366 / 1385 / 1406 | — | U (inside `checkLinuxDependencies`) |
| `uid0SandboxError` / `probeUid0UserNamespace` | 1433 / 1462 | 20 / 30 | conditional (euid 0 and no `CAP_SETFCAP`) |
| `WorkingDirectoryChanged` | 1017 | — | conditional (cwd moved during the rg scan) |
| `LinuxSandboxProfileError` | 985 | — | conditional (§2 limits) |

Inside `generateFilesystemArgs` (2095-3483):

| helper | line | verdict |
|---|---|---|
| `canonicalForm` / `canonicalLocationOf` / `mountForms` / `nameLocationOf` | 2169 / 2191 / 2201 / 2209 | N |
| `isWithinAnyAllowedWritePath` / `meetsAnyAllowedWritePath` / `isAllowedWriteRoot` | 2220 / 2231 / 2236 | N |
| `readAllowPaths` / `ownReadAllowPaths` | 2242 / 2247 | N / ✗-empty (`ownAllowWithinDeny` unset: no `mitmCA`, no jar under deny) |
| `readDenyTargetOf` | 2264 | N |
| `readDenyMountOf` | 2294 | N |
| `readDenyEntries` | 2344 | N (expands a `denyRead: ["/"]` into the root's children; always appends `/etc/ssh/ssh_config.d` when it exists, 2375-2377) |
| `readDenyPlan` | 2404 | N |
| `ancestorPinArgs` | 1917 (3302) | 59 | N |
| `getStubSkipVetoInputs` | 2557 | 60 | conditional (only when a deny path lies strictly under a recorded read-only deny dir) |
| `linuxGetMandatoryDenyPaths` | 542 (2611) | 122 | **N — unconditional whenever `writeConfig` exists** (§5) |
| `linuxGetCwdMandatoryDenyPaths` | 441 (551) | 39 | N |
| `unreadableDirectories` | 480 (617) | 60 | conditional (rg exit 2 / killed) |
| pre-pass over `denyPaths` | 2646-2697 | — | N |
| `coveringDirIsUnsafe` | 2706 | 50 | conditional |
| `uncoveredWritePaths` | 2758 | — | N |
| `coveredBySafeReadOnlyDenyDir` | 2769 | 55 | conditional |
| `mountPointFor` | 2829 | 80 | conditional (absent `denyWrite` path) |
| `makeableMountPoint` | 335 | 84 | conditional |
| `fileOnTheWay` / `findFirstNonExistentComponent` | 261 / 288 | — | conditional |
| `resolveSymlinkedDenyPath` / `findSymlinkInPath` | 190 / 121 | — | N (per deny entry) |
| `ensureEmptyMountSourceDir` | 673 (2917) | 32 | conditional |
| `mountSourceFor` | 2911 | 12 | conditional |
| main deny loop | 2924-3060 | 137 | N |
| `pushReadDenyDirMounts` | 1984 (3229) | 110 | N (per read-denied directory) |
| `isHiddenByTmpfs` | 3099 | 28 | N |
| `credentialMaskFakes` / `fileMaskLandings` | 3129 / 3139 | — | U → empty (no `credentials`) |
| `readDeniedLocations` / `readDenialAround` | 3150 / 3163 | — | N |
| `outsideCredentials` / `restorableReadPaths` / `restorableWritePaths` | 3182 / 3195 / 3198 | — | N (all pass, no credential denies) |
| read-deny emission loop | 3200-3280 | 80 | N |
| denyWrite emission + emission filter | 3346-3412 | 67 | N |
| tmpfs / mask re-application passes | 3422-3459 | 38 | conditional |
| store-dir + empty-dir ro-binds | 3466-3481 | — | conditional |

### `src/sandbox/generate-seccomp-filter.ts` (307 lines)
| fn | line | verdict |
|---|---|---|
| `getApplySeccompBinaryPath` | 194 | N (called from `resolveApplySeccompPrefix`, `linux-sandbox-utils.ts:1741`) |
| `getApplySeccompBinaryPathAsync` | 217 | N (called from `checkDependenciesAsync`, `sandbox-manager.ts:1722`) |
| `findLocalApplySeccompPath` | 239 | N |
| `getLocalSeccompPaths` | 162 | N |
| `getVendorArchitecture` | 133 | N (x64/arm64; `ia32` → `null` + error log 136-143) |
| `findGlobalApplySeccompPath` | 283 | conditional |
| `getGlobalNpmPaths` / `getGlobalNpmPathsAsync` | 26 / 51 | conditional (`npm root -g`, 5 s timeout) |

### `src/utils/*`
| fn | file:line | verdict |
|---|---|---|
| `ripGrep` | `src/utils/ripgrep.ts:22` | N (§5) |
| `whichSync` | `src/utils/which.ts:9` | N (`bwrap`, `socat`, `rg`, `bash`) |
| `getPlatform` / `getWslVersion` | `src/utils/platform.ts:44 / 11` | U |
| `quote` | `src/utils/shell-quote.ts` | N |
| `realPathOf` / `wayTo` | `src/utils/real-path.ts` | N |
| `logForDebugging` | `src/utils/debug.ts` | U (`SRT_DEBUG`-gated) |

### `src/sandbox/sandbox-utils.ts` (2057 lines)
| fn | line | verdict |
|---|---|---|
| `getDefaultWritePaths` | 636 | N (§5) |
| `SANDBOX_OWN_WRITE_PATHS` / `HOME_CONVENIENCE_WRITE_DIRS` | 585 / 601 | N |
| `DANGEROUS_FILES` / `DANGEROUS_DIRECTORIES` / `getDangerousDirectories` | 21 / 37 / 44 | N |
| `normalizePathForSandbox` | 451 | N (strips trailing slashes, `~`, resolves symlinks) |
| `isSymlinkOutsideBoundary` | 266 | N (write-path symlink guard, 2481-2497) |
| `isAtOrUnder` / `isStrictlyUnder` / `properAncestors` / `nameLocation` | 69 / 74 / 79 / 110 | N |
| `generateProxyEnvVars` | 772 | N (§3) |
| `buildPosixGitSafeDirEnv` | 1132 | ✗ |
| `attributionKeyFor` / `encodeSandboxedCommand` | 1156 / 1170 | U |
| `proxyUsernameFor` | 1205 | N (embedded in the proxy URL userinfo) |
| `walkGlobPatternSteps` | 1622 | conditional |

### `src/sandbox/read-deny-glob.ts`, `path-entries.ts`
`expandReadDenyGlobLinuxSteps` (glob `denyRead` → covering directory mounts),
`readRulesOf` (305), `reExposedBy` (384), `writeRootsOf` (373), `spelledOf` (74),
`withOtherReadings` (279) — all N when globs are used, otherwise pass-through.

### `src/sandbox/proxy side` (host-side, reached from `startMuxProxyServer`)
`createMuxProxyServer` (`mux-proxy.ts`), `createHttpProxyServer` (`http-proxy.ts`),
`createSocksProxyServer` (`socks-proxy.ts`), `listenInRange` (`listen-in-range.ts:…`),
`createResolvedAddressGuard` (`resolved-address-guard.ts:199`), `isResolvedAddressDenied`
(`:121`), `matchesDomainPatternWithPort` (`domain-pattern.ts`). All N.
`mitmProxy.socketPath` is used only by the HTTP proxy through `getMitmSocketPath`
(`sandbox-manager.ts:906`); the sandboxed child never sees that socket.

---

## 2. The exact bwrap argv, and how bind ordering implements allow/deny

`bwrapArgs` starts at `linux-sandbox-utils.ts:3611` and is rendered by
`renderBwrapInvocation` (`:1035`, called at `:3907`) as `quote(['bwrap', ...bwrapArgs])`
(`:1059`), i.e. one shell-quoted string the CLI runs with `sh -c` (`src/cli.ts:607`).

Order for this config (`writeConfig` defined because `filesystem.disabled` is absent):

```
bwrap
  --new-session --die-with-parent                       # 3611
  # (observe-socket --bind/--setenv SRT_OBSERVE_SOCK/SRT_ENCODED_CMD)   ✗ §6
  # (--unsetenv <credential vars> / --setenv <masked vars>)             ✗ no credentials
  # (--setenv GIT_CONFIG_COUNT …)                                       ✗ no git.safeDirectories
  --unshare-net                                          # 3699
  --bind <tmpdir>/claude-http-<id>.sock <same>          # 3720
  [--bind <tmpdir>/claude-socks-<id>.sock <same>]       # 3725 (skipped when mux: same path)
  --setenv SANDBOX_RUNTIME=1                             # 3739 ← generateProxyEnvVars
  --setenv TMPDIR=/tmp/claude
  --setenv NO_PROXY=localhost,127.0.0.1,::1,169.254.0.0/16,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
  --setenv no_proxy=<same>
  --setenv HTTP_PROXY=http://srt<encoded-cmd>:<token>@localhost:3128
  --setenv HTTPS_PROXY=…  --setenv http_proxy=…  --setenv https_proxy=…
  --setenv GIT_CONFIG_PARAMETERS='http.proxyAuthMethod=basic'
  --setenv ALL_PROXY=… --setenv all_proxy=… --setenv GRPC_PROXY=… --setenv grpc_proxy=…
  --setenv GIT_SSH_COMMAND=ssh -o ControlMaster=no -o ControlPath=none -o ProxyCommand='socat - PROXY:localhost:%h:%p,proxyport=<hostHttpPort>,proxyauth=…'
  --setenv FTP_PROXY=socks5h://…@localhost:1080  --setenv ftp_proxy=…
  --setenv RSYNC_PROXY=localhost:1080
  --setenv DOCKER_HTTP_PROXY=… --setenv DOCKER_HTTPS_PROXY=…
  --setenv CLOUDSDK_PROXY_TYPE=http / _ADDRESS=localhost / _PORT=<hostHttpPort> / _USERNAME / _PASSWORD
  [--setenv JAVA_TOOL_OPTIONS=-javaagent:<jar>]          # 3758 (jar shipped)
  --setenv CLAUDE_CODE_HOST_HTTP_PROXY_PORT=<port>       # 3764
  --setenv CLAUDE_CODE_HOST_SOCKS_PROXY_PORT=<port>      # 3771
  # ---- filesystem args (generateFilesystemArgs, spliced at 3793) ----
  --ro-bind / /                                          # 2436  (read-only baseline)
  --bind <allowWrite p> <p> …                            # 2500  (allowWrite + default write paths)
  [--ro-bind <ancestor dir> <dir> …]                     # 3314  ancestor pins, spliced at 2503 marker
  # read denies, shallow-first by canonical depth (2404):
  --tmpfs <denied dir>                                   # 2006
  --bind <write path> <write path>                       # 2063  (write paths the tmpfs wiped)
  --ro-bind <allowRead carve-out> <carve-out>            # 2083  (allowRead inside a denied dir)
  --ro-bind /dev/null <denied file>                      # 3275
  # (credential masks --ro-bind <fake> <landing>)        ✗ 3288
  # denyWrite binds, buffered in denyWriteArgs, emitted LAST:
  --ro-bind <denyWrite path> <path>                      # 3056 → emitted 3405
  --ro-bind /dev/null <placeholder for an absent deny>   # 3011 (or the empty dir, 2917)
  --ro-bind /dev/null <symlink component>                # 2957 / 2991 (symlink mask)
  # re-application passes (only when a denyWrite bind re-exposed something):
  --tmpfs <landing>                                      # 3443
  --ro-bind <restored source> <dest>                     # 3445 / 3393
  --ro-bind <mask source> <landing>                      # 3457
  [--ro-bind <maskedFileStoreDir> <same>]                ✗ 3468
  [--ro-bind <tmpdir>/claude-empty-XXXX <same>]          # 3480 (only if an empty-dir placeholder was used)
  # ---- end filesystem args ----
  --dev /dev                                             # 3801
  --unshare-pid                                          # 3810
  --unshare-user --cap-drop ALL [--cap-add CAP_SETFCAP]  # 3823 + capabilityArgs 788
  --proc /proc                                           # 3833  (enableWeakerNestedSandbox off)
  --unsetenv SRT_ALLOW_NESTED_USERNS                     # 3845
  [--disable-userns]                                     # 3859 ✗ when the seccomp helper runs
  -- bash -c                                             # 3885 (whichSync('bash') at 3878)
  "<inner script>"                                       # 3899 (buildSandboxCommand)
```

`--proc /proc` becomes `--bind /proc /proc` (3839) only under `enableWeakerNestedSandbox`.
`--unshare-all`, `--unshare-ipc`, `--unshare-uts`, `--unshare-cgroup` are never passed;
srt names user/PID/net namespaces explicitly and bubblewrap always makes its own mount
namespace.

### The inner script (`buildSandboxCommand`, 1793-1855)

```
bash -c '<socat relay 3128> &
_srt_http=$!
<socat relay 1080> &
_srt_socks=$!
trap '"'"'rc=$?; kill %1 %2 2>/dev/null; exit $rc'"'"' EXIT
<RELAYS_LISTEN poll, 1771-1791>
SRT_ALLOW_NESTED_USERNS=0 <apply-seccomp> bash -c <user command>'
```

* relay (1810-1813): `{ socat TCP6-LISTEN:<port>,ipv6only=0,fork,reuseaddr,backlog=4096 UNIX-CONNECT:<socketPath> || exec socat TCP4-LISTEN:<port>,… UNIX-CONNECT:<socketPath>; } >/dev/null 2>&1 &`
* `RELAYS_LISTEN` (1771) polls `/proc/net/sockstat{,6}` until 2 TCP sockets are in use
  (the two relays listening), giving up after 0.3 s read from `/proc/uptime`; it starts
  no program because it runs **before** the seccomp filter is installed.
* apply-seccomp is appended **after** the socat relays (1830-1837) so `socat` can still
  call `socket(AF_UNIX, …)`.

### How ordering implements allow/deny (bwrap is last-mount-wins)

1. `--ro-bind / /` (2436) makes the whole host tree read-only → *writes denied by default*.
2. Each `allowOnly` entry gets a writable `--bind p p` (2500) **after** the root → allow
   overrides the default. Entries are skipped when they are under `/dev/` (2462), do not
   exist (2466), or are a symlink leading outside their own boundary
   (`isSymlinkOutsideBoundary`, 2478-2497).
3. Read denies come next: a directory gets `--tmpfs <landing>` (2006) which *wipes* any
   write bind placed under it, so `pushReadDenyDirMounts` immediately re-binds the allowed
   write paths (2063, writable) and the `allowRead` carve-outs (2083, read-only) back on
   top. A file deny is `--ro-bind /dev/null <landing>` (3275). `allowRead` therefore beats
   `denyRead` only because it is re-mounted after the tmpfs.
4. `denyWrite` binds are **buffered** in `denyWriteArgs` (2957/2991/3011/2957/3056) and
   emitted after the whole read section (3405) — so `denyWrite` beats `allowWrite`, the
   opposite precedence from reads.
5. Two corrections keep that ordering sound:
   * a `denyWrite` dest already hidden by a `denyRead` tmpfs is **dropped** (3355-3403),
     because re-binding the host path on top of the tmpfs would make the read-denied
     contents visible again; the write paths the tmpfs restored are instead re-bound
     read-only (3393).
   * a `denyWrite` bind that *contains* a read-denied dir re-exposes it, so the tmpfs and
     its restores are **re-applied on top** (3422-3459).
6. Ancestor pins (`ancestorPinArgs` 1917, spliced 3314) put a read-only bind on every
   directory between a mount seed and its covering write root, so `rename`/`rmdir` cannot
   move a deny out of the sandbox. They are spliced *below* the allow binds
   (`beneathAllowBinds`, 2437/2503) except when `/` itself is a write root, where they go
   *after* the allow binds and a writable cover `--bind D D` is emitted for the top-level
   directory (2503, 1955-1972).
7. `--dev /dev` (3801) and `--proc /proc` (3833) land last and replace those subtrees.
8. Absent `denyWrite` paths are blocked by mounting `/dev/null` (or the shared empty
   directory `claude-empty-*`, 673) at the first missing component (2829-2921); those host
   mount points are removed by `cleanupBwrapMountPoints` (1163) via the CLI's
   `cleanupAfterCommand()` (`src/cli.ts:618`).

### Size limits
* `BWRAP_MAX_ARGS = 9000` (863) → `LinuxSandboxProfileError('too_many_arguments')` (1044).
* `MAX_ARG_STRLEN` from `/proc/self/auxv` (827) minus `ARG_HEADROOM_BYTES = 4096` (860):
  over that, the mount words go to an unnamed `O_TMPFILE` file (916) and the string becomes
  `/bin/sh -c 'exec 9<"$1" && shift && exec "$@"' srt-args /proc/<pid>/fd/<n> bwrap … --args 9 …`
  (1084-1099).
* NUL in a mount path → `nul_in_path` (1052).

---

## 3. `initializeLinuxNetworkBridge` (`linux-sandbox-utils.ts:1513-1675`)

Called from `sandbox-manager.ts:1572` inside the `initializationPromise` block, with
`(httpProxyPort, socksProxyPort, config.socatPath)`.

**Outside the sandbox (host, children of the `srt` process):**

1. The Node proxies: `startMuxProxyServer` (`sandbox-manager.ts:967`) binds one
   `127.0.0.1` ephemeral port (`listenInRange`) serving both HTTP/CONNECT and SOCKS5;
   `httpProxyPort === socksProxyPort === muxPort` unless `network.httpProxyPort` /
   `network.socksProxyPort` name external proxies.
2. HTTP bridge (`:1523-1529`):
   `socat UNIX-LISTEN:<tmpdir>/claude-http-<16 hex>.sock,fork,reuseaddr TCP:localhost:<httpProxyPort>,keepalive,keepidle=10,keepintvl=5,keepcnt=3`
   (`stdio: 'ignore'`, error/exit handlers registered *before* the `!pid` check, 1534-1546).
3. SOCKS bridge (`:1557-1580`) is spawned **only when `socksProxyPort !== httpProxyPort`**;
   in the mux case `socksBridgeProcess = httpBridgeProcess` and
   `socksSockPath = httpSocketPath` (1553-1555), so the `claude-socks-*.sock` path allocated
   at 1521 is unused.
4. Readiness: up to 5 `fs.existsSync` polls of both socket paths with `i*100 ms` delays
   (1607-1660); failure SIGTERMs both bridges and throws
   `Failed to create bridge sockets after 5 attempts`.

Socket paths: `join(tmpdir(), 'claude-http-' + randomBytes(8).hex + '.sock')` (1519) and
`join(tmpdir(), 'claude-socks-' + … + '.sock')` (1521).

**Inside the sandbox (in the new netns):** the two socket *files* are bind-mounted
(3720/3725) and `buildSandboxCommand` (1793) starts two background `socat` relays:

* `TCP6-LISTEN:3128,ipv6only=0,fork,reuseaddr,backlog=4096` → `UNIX-CONNECT:<httpSocketPath>`
  (fallback `TCP4-LISTEN:3128`),
* `TCP6-LISTEN:1080,…` → `UNIX-CONNECT:<socksSocketPath>` (fallback `TCP4-LISTEN:1080`).

The child's proxy env points at those listeners (`HTTP_PROXY=…localhost:3128`,
`ALL_PROXY`, `FTP_PROXY=socks5h://…:1080`, `GIT_SSH_COMMAND` with
`socat - PROXY:localhost:%h:%p,proxyport=<host mux port>` — `sandbox-utils.ts:918-926`),
and `CLAUDE_CODE_HOST_{HTTP,SOCKS}_PROXY_PORT` record the host-side ports (3764/3771).

So the chain is: **child → socat(TCP 3128/1080, inside netns) → unix socket (bind-mounted)
→ socat(UNIX-LISTEN, host) → TCP 127.0.0.1:<muxPort> → Node HTTP/SOCKS proxy → filtered
outbound**. Domain allow/deny, `strictAllowlist` and the resolved-address check all happen
in the Node proxy, not in the namespace: `--unshare-net` is all-or-nothing
(documented at `linux-sandbox-utils.ts:1506-1512`).

The bridges are SIGTERMed by `reset()` (`sandbox-manager.ts:3188`, `BRIDGE_EXIT_TIMEOUT_MS
= 1500` at 3087).

---

## 4. The seccomp helpers

### What is built and where the binary comes from
* `vendor/seccomp/build.ts` (73 lines, `npm run build:seccomp`, Linux-only, needs `gcc` +
  `libseccomp-dev`): compiles `vendor/seccomp-src/seccomp-unix-block.c` with `-lseccomp`
  (build.ts:20-26), runs it twice to export **two BPF blobs** — `unix` and `namespaces` —
  for `x86_64`/`aarch64` (33-40), writes them as C arrays into `unix-block-bpf.h` (42-53),
  then compiles `apply-seccomp.c` `-static -O2` against that header and strips it (55-63).
* Output lands in `vendor/seccomp/{x64,arm64}/apply-seccomp`, which is **gitignored**
  (`.gitignore:5-6`) and shipped via `package.json` `"files": ["vendor/seccomp", …]`.
* `src/sandbox/generate-seccomp-filter.ts` does **no runtime generation** in this version:
  it only *locates* the binary. Lookup order (`findLocalApplySeccompPath` 239 →
  `getLocalSeccompPaths` 162 → `findGlobalApplySeccompPath` 283):
  1. `seccomp.applyPath` if it exists,
  2. `<module dir>/vendor/seccomp/<arch>/apply-seccomp`,
  3. `../../vendor/…` (package root), `../vendor/…` (dist/vendor),
  4. a global npm install (`npm root -g`, `getGlobalNpmPaths` 26 / Async 50, 5 s timeout).
  Arch map `getVendorArchitecture` (133): `x64`, `arm64`; `ia32` → `null` with an error log
  (141-148, `socketcall()` is not filtered — see the TODO at
  `seccomp-unix-block.c:14-24`); anything else → `null`. Results are cached per requested
  path (`applySeccompPathCache`, 9/194/217).

### What the filters block
`seccomp-unix-block.c` is a **generator** (`main` 146, default action `SCMP_ACT_ALLOW` at 166):

* `unix` rule set (default):
  * `socket(AF_UNIX)` → `EPERM` (212-213, `SCMP_A0(SCMP_CMP_MASKED_EQ, 0xffffffff, AF_UNIX)`),
  * `socket(AF_VSOCK)` → `EPERM` (224-225) — the netns does not fence VM sockets,
  * `io_uring_setup` / `io_uring_enter` / `io_uring_register` → `EPERM` (238-249) —
    `IORING_OP_SOCKET` would create sockets without the `socket()` syscall.
  * AF_INET/AF_INET6 and every other syscall stay allowed; inherited unix FDs, `bind`,
    `connect`, `sendto` and `SCM_RIGHTS` are **not** blocked (documented at
    `linux-sandbox-utils.ts:3506-3513`).
* `namespaces` rule set (`add_namespace_rules` 73-140): `unshare` and `clone` with
  `CLONE_NEWUSER|CLONE_NEWNS|UNSHARE_EMPTY_MNTNS` in arg0 → `EPERM` (90-92);
  `clone3` → `ENOSYS` (97, so libc falls back to `clone`); `setns`, `mount`, `umount2`,
  `pivot_root`, `open_tree`, `move_mount`, `fsopen`, `fsconfig`, `fsmount`, `fspick`,
  `mount_setattr` (nr 442), `open_tree_attr` (nr 467) → `EPERM` (101-112). Added with
  `seccomp_rule_add_exact` (127-133).

### When they are applied (`apply-seccomp.c`, 965 lines)
`main` at 673:

1. Read `SRT_ALLOW_NESTED_USERNS` (683-684) — set by `helperEnvironmentPrefix`
   (`linux-sandbox-utils.ts:1684`) to `0` unless `allowNestedUserNamespaces` is true.
2. `unshare(CLONE_NEWPID|CLONE_NEWNS)` (737); on `EPERM`, `unshare(CLONE_NEWUSER)` (761) +
   `setgroups=deny` (765) + `uid_map`/`gid_map` (770/773) + retry the PID+mount unshare (776).
3. `PR_SET_DUMPABLE 0` (787) in both halves → the unfiltered outer half is not ptraceable
   and its `/proc/N/mem` is closed to the command.
4. `fork()` (791). **Outer stub** (797-846): installs the `namespaces` filter (805-810,
   skipped when `SRT_ALLOW_NESTED_USERNS=1`), forwards SIGTERM/INT/HUP/QUIT/USR1/USR2
   (`install_forwarders` 632), optionally services the observation `USER_NOTIF` fd, relays
   the child's exit status.
5. **Inner init (PID 1)** (857-938): `mount("/", MS_REC|MS_PRIVATE)` (866), fresh
   `mount("proc","/proc",…)` tolerating `EPERM` (874), write
   `/proc/sys/user/max_user_namespaces = 0` when a userns was made (888),
   `PR_CAP_AMBIENT_CLEAR_ALL` (920), fork the worker (925) and reap (`reap_until` 650).
6. **Worker (inner PID 2)** (940-963): `unsetenv` of `SRT_OBSERVE_SOCK`, `SRT_ENCODED_CMD`,
   `SRT_ALLOW_NESTED_USERNS` (940-942), `PR_SET_NO_NEW_PRIVS` (943), optional observation
   filter (950), `PR_SET_SECCOMP` with `namespace_block_bpf` (955) then `unix_block_bpf`
   (958), `execvp` (962). Any setup failure `die()`s — it never falls back to running
   unfiltered (comment at 27-28).

Process layout (comment at 11-20): `bwrap init → bash/socat → apply-seccomp[outer] →
apply-seccomp[inner PID 1] → user command (PID 2, filtered)`.

### Where the wrap inserts it
* `resolveApplySeccompPrefix` (`linux-sandbox-utils.ts:1731`):
  * `seccomp.argv0` mode → `ARGV0=<quoted argv0> <quoted applyPath> ` with **no existence
    check**; `argv0` without `applyPath` throws
    `seccompConfig.argv0 requires seccompConfig.applyPath` (1735-1738).
  * otherwise `quote([getApplySeccompBinaryPath(applyPath)]) + ' '`, or `undefined`.
* Skipped entirely when `allowAllUnixSockets` is true (3617, 3638-3640).
* Prefix is prefixed with `SRT_ALLOW_NESTED_USERNS=0|1 ` (3631-3632) and appended either
  directly (`applySeccompCmd = prefix + quote([shell,'-c',command])`, 3901-3902) or after
  the socat relays inside the inner script (1832-1836).
* `capabilityArgs` (788) adds `--cap-add CAP_SETFCAP` only for a uid-0 caller **with** the
  helper, because the helper's nested userns maps uid 0.

### When the binary is missing
* `resolveApplySeccompPrefix` returns `undefined` → warning
  `apply-seccomp binary not available - unix socket blocking disabled. Install
  @anthropic-ai/sandbox-runtime globally for full protection.` (3626-3630). The wrap
  **still succeeds**: no AF_UNIX/AF_VSOCK/io_uring blocking, no nested PID namespace, no
  `namespaces` filter.
* `checkLinuxDependencies` records it as a **warning, not an error**:
  `seccomp not available - unix socket access not restricted` (1322-1327) — so
  `initialize()` does not refuse.
* Fallback for the namespace limit: with no helper and `allowNestedUserNamespaces !== true`,
  bwrap is given `--disable-userns` if `bwrapCanDisableUserns(bwrap)` (3847-3866, needs
  bwrap ≥ 0.8.0, non-setuid, `enableWeakerNestedSandbox` off); otherwise a once-per-process
  warning (3861-3865). `allowAllUnixSockets` + `enableWeakerNestedSandbox` together leave
  the limit off entirely (README:717).
* `checkLinuxDependencies`'s `argv0` mode skips the on-disk lookup entirely
  (`getLinuxDependencyStatus` 1296-1299, `checkLinuxDependencies` 1322).

---

## 5. What Linux gives the child without being asked

### Default write paths
`defaultWritePathsUnder` (`sandbox-manager.ts:1842`, called at 2515) →
`getDefaultWritePaths` (`sandbox-utils.ts:636`):

* `SANDBOX_OWN_WRITE_PATHS` (`sandbox-utils.ts:585`): `/dev/stdout`, `/dev/stderr`,
  `/dev/null`, `/dev/tty`, `/dev/dtracehelper`, `/dev/autofs_nowait`, `/tmp/claude`,
  `/private/tmp/claude`.
* `HOME_CONVENIENCE_WRITE_DIRS` (`:601`): `~/.npm/_logs`, `~/.claude/debug` — dropped when
  a `denyRead` entry names them or a directory above them, kept when an `allowRead` entry
  beneath that deny re-opens them (`homeDirsNotReadDenied` 655).
* On Linux the `/dev/*` entries are skipped in the bind loop (`linux-sandbox-utils.ts:2462`,
  `--dev /dev` covers them) and non-existent paths are skipped (`:2466`), so in practice
  the extra writable binds are `/tmp/claude` (if it exists) plus the two home directories.
* `filesystem.disabled` is absent, so `writeConfig` is always defined → `--ro-bind / /`
  baseline and writes are deny-by-default.

### Mandatory (built-in) write denies
`linuxGetMandatoryDenyPaths` (`linux-sandbox-utils.ts:542`), called unconditionally from
`generateFilesystemArgs:2611` whenever `writeConfig` exists. Its cwd part
(`linuxGetCwdMandatoryDenyPaths` 441):

* every `DANGEROUS_FILES` (`sandbox-utils.ts:21-33`: `.gitconfig`, `.gitmodules`, `.bashrc`,
  `.bash_profile`, `.zshrc`, `.zprofile`, `.profile`, `.ripgreprc`, `.mcp.json`) resolved
  against `process.cwd()`;
* every `getDangerousDirectories()` (`:44`): `.vscode`, `.idea`, `.claude/commands`,
  `.claude/agents` (`.git` itself is *not* denied wholesale);
* `cwd/.git/hooks` always, `cwd/.git/config` unless `allowGitConfig`, or `cwd/.git` itself
  when it is a **file** (worktree/submodule pointer) — `dotGitKindAt` 421.

### Where `rg` is invoked and with which flags
`linuxGetMandatoryDenyPaths` builds one call (`iglobArgs` 556-570) and runs it at
`linux-sandbox-utils.ts:582-602` through `ripGrep` (`src/utils/ripgrep.ts:22`, which
prepends `ripgrep.args`, honours `ripgrep.argv0`, and kills the child after **10 s**,
`ripgrep.ts:31`):

```
rg --files --hidden --no-ignore --no-config --line-buffered \
   --max-depth <mandatoryDenySearchDepth + 1> \
   --iglob .gitconfig --iglob .gitmodules --iglob .bashrc --iglob .bash_profile \
   --iglob .zshrc --iglob .zprofile --iglob .profile --iglob .ripgreprc --iglob .mcp.json \
   --iglob '**/.vscode/**' --iglob '**/.idea/**' \
   --iglob '**/.claude/commands/**' --iglob '**/.claude/agents/**' \
   --iglob '**/.git/hooks/**' --iglob '**/.git/HEAD' \
   --iglob '**/.git/config'            # only when allowGitConfig is false
   -g '!**/node_modules/**'  <cwd>
```

`--no-ignore`/`--no-config` are deliberate: no `.gitignore`/`.ignore` or rg config file may
decide what gets denied (comment 586-589). On failure (`RipgrepError`, exit 2 or the 10 s
kill) the already-listed matches are kept (`linuxGetMandatoryDenyPaths:612`) and every
directory rg complained about that this user owns, is not a symlink and cannot be read is
denied whole (`unreadableDirectories` 480, called 617). An abort rethrows (609).

Match → deny mapping (626-660): a dangerous **file** may sit at depth ≤ `maxDepth - 1`;
a dangerous **directory** name (`.vscode`, `.idea`, `.claude/commands`, `.claude/agents`,
`.git/hooks`, `.git/config`, `.git/HEAD`) at depth ≤ `maxDepth - 2`; a `.git/HEAD` match is
rewritten to deny `.git/hooks` instead (655-656), so a repo is protected before it has hooks.

### `mandatoryDenySearchDepth`
Default **3**: `getMandatoryDenySearchDepth` (`sandbox-manager.ts:2249-2251`,
`config?.mandatoryDenySearchDepth ?? 3`) and `DEFAULT_MANDATORY_DENY_SEARCH_DEPTH`
(`linux-sandbox-utils.ts:112`), also the parameter default at 2101. Schema bounds 1..10
(`sandbox-config.ts:1224-1232`). It is passed to the wrapper at `sandbox-manager.ts:2747`.
These denies are *not* in any configured list — `renderBwrapInvocation`'s error text says how
many of the 9000 bwrap arguments they account for (`linux-sandbox-utils.ts:1043`), counted by
`mandatoryDenyArgs` (3316-3328, 3406).

### Other unconditional defaults
* `/etc/ssh/ssh_config.d` is always read-hidden when a read policy exists
  (`linux-sandbox-utils.ts:2375-2377`).
* `TMPDIR=/tmp/claude` (or `CLAUDE_CODE_TMPDIR`/`CLAUDE_TMPDIR`) and `SANDBOX_RUNTIME=1`
  (`sandbox-utils.ts:791-802`), the full proxy env set (§2), `--unsetenv
  SRT_ALLOW_NESTED_USERNS` (3845), `--new-session`, `--die-with-parent` (3611),
  `--cap-drop ALL` (797), `--unshare-user`/`--unshare-pid`/`--proc /proc`.
* `GIT_SSH_COMMAND` rewritten to route ssh through the HTTP proxy via `socat`
  (`sandbox-utils.ts:919-926`).
* `binShell` defaults to `bash`, resolved with `whichSync` and hard-failing if absent
  (`linux-sandbox-utils.ts:3876-3881`).

---

## 6. Does the CLI enable `linux-violation-monitor.ts`? — **No.**

* `initialize(runtimeConfig, sandboxAskCallback?, enableLogMonitor = false, options?)`
  — `sandbox-manager.ts:1099-1104`.
* `src/cli.ts:505` calls `SandboxManager.initialize(runtimeConfig)` with **one** argument,
  and the CLI has no flag that sets it.
* Therefore the Linux monitor block `sandbox-manager.ts:1206-1256`
  (`if (enableLogMonitor && getPlatform() === 'linux')`) is **not reached**: `linuxMonitor`
  (declared `:180`) stays `undefined`, `startLinuxSandboxViolationMonitor`
  (`linux-violation-monitor.ts:80`) is never called, and `observeSocketPath` passed to the
  wrapper at `sandbox-manager.ts:2753` is `undefined`.
* Consequently the observe block in the wrapper (`linux-sandbox-utils.ts:3646-3659`) is
  skipped: no `--bind <observe socket>`, no `--setenv SRT_OBSERVE_SOCK`, no
  `--setenv SRT_ENCODED_CMD`, so `apply-seccomp` never installs the `USER_NOTIF`
  observation filter (`apply-seccomp.c:335 install_observe_filter`, gated on
  `SRT_OBSERVE_SOCK` at 702-708) and never connects to the monitor socket.
* Violations on the CLI path therefore come only from the **proxy side**
  (`recordProxyViolation` 638 / `recordOutboundDeny` 659 → `SandboxViolationStore` 401);
  filesystem write attempts are not observed. `annotateStderrWithSandboxFailures` is not
  called by the CLI either.

---

## 7. External binaries required on Linux, and `checkLinuxDependencies`

Required (README:682-697):

| Binary | Used at | Checked by |
|---|---|---|
| `bwrap` (bubblewrap, ≥ 0.5.0 recommended; 0.4.0 minimum with one caveat) | `renderBwrapInvocation` 1059/1093 (`bwrapPath ?? 'bwrap'`, 3909); probes `--version` 1371, `--unshare-user --dev-bind / / true` 1468, `--help` 1700 | `checkLinuxDependencies` 1312-1318 → **error** `bubblewrap (bwrap) not installed` / `not executable at <path>` |
| `socat` | host bridges (`initializeLinuxNetworkBridge` 1529/1571) and the in-sandbox relays (`buildSandboxCommand` 1806) | 1320-1325 → **error** `socat not installed` / `not executable at <path>` |
| `rg` (ripgrep) | `linuxGetMandatoryDenyPaths` 582 via `ripGrep` | `checkDependenciesCommon` 1646-1650 → **error** `ripgrep (<cmd>) not found` (Linux-only check; macOS never invokes rg) |
| `apply-seccomp` (bundled, not system) | `resolveApplySeccompPrefix` 1741 | 1322-1327 → **warning** only |
| `/bin/sh` | only for an over-long profile (`renderBwrapInvocation` 1084) | not checked |
| `bash` (or `binShell`) | `whichSync(shellName)` 3878 | wrap-time `Error: Shell '<x>' not found in PATH` |
| `which` | `whichSync` fallback when not running under Bun (`utils/which.ts:16`) | not checked |
| `npm` (`npm root -g`) | global fallback lookup for `apply-seccomp` (`generate-seccomp-filter.ts:15,31,57`) and the java jar | not checked; failure just yields the static fallback paths |
| `gcc` + `libseccomp-dev` | only to build `vendor/seccomp` (`vendor/seccomp/build.ts`), not at runtime | — |

`checkLinuxDependencies` (`linux-sandbox-utils.ts:1304-1352`) also:
* `uid0SandboxError` (1433, called 1330): euid 0 without `CAP_SETFCAP` in the bounding∪inheritable
  set (`processHasBoundingCapability` 726, `boundingCapabilitiesFromStatus` 758) → predicted
  error, confirmed by `probeUid0UserNamespace` (1462) running
  `bwrap --unshare-user --dev-bind / / true` → **error** (`CAP_SETFCAP_MISSING_MESSAGE` 815).
* `outdatedBwrapWarning` (1406) → **warning** for bwrap < `OLDEST_FULLY_SUPPORTED_BWRAP_VERSION`
  = `0.5.0` (1355).

`checkDependenciesCommon` (`sandbox-manager.ts:1623`) adds the rg check, calls
`checkLinuxDependencies` (1652), and adds `ownInstallWarning` (`own-files.ts`, 1688) when the
write roots cover this library's own install. `checkDependenciesAsync` (1715) first awaits
`getApplySeccompBinaryPathAsync` (1722) so the `npm root -g` fallback does not block the
event loop. `initializeSteps` throws at 1177-1195 if `errors.length > 0`
(`Sandbox dependencies not available: …`), so a missing `bwrap`, `socat` or `rg` stops the
CLI before any command runs (`src/cli.ts:391` prints it and exits 1).

---

## 8. Which of the listed settings behave differently on Linux than on macOS

| Setting | macOS | Linux on this path |
|---|---|---|
| `filesystem.allowRead` | seatbelt regex/subpath rules; globs matched natively | globs **expanded against the disk** (`expandAllowReadGlob` 1958 → `walkGlobPatternSteps`), re-bound read-only over a `denyRead` tmpfs (`pushReadDenyDirMounts` 2083); an `allowRead` entry re-allows only the **name** it names, not its symlink target |
| `filesystem.denyRead` | `(deny file-read*)` rules | `--tmpfs <dir>` for directories (2006), `--ro-bind /dev/null <file>` for files (3275), mounted at the **resolved** location (2294), `/` expanded into the root's children (2344-2378), a stand-in tmpfs over the deepest inspectable ancestor when a path cannot be inspected (2316-2338) |
| `filesystem.allowWrite` | seatbelt `file-write*` | writable `--bind p p` after `--ro-bind / /` (2500); symlink-outside-boundary paths are **skipped** (2478-2497); globs that are not a path name are dropped (`stripWriteGlobs` 1938) |
| `filesystem.denyWrite` | deny rules | buffered and emitted **last** (3405) so deny beats allow; absent paths get a `/dev/null` or empty-dir **host mount point** that exists while the sandbox lives and is removed by `cleanupAfterCommand()` (2829-2921, 1163) |
| `network.allowedDomains` / `deniedDomains` | enforced by the proxy; seatbelt only allows the proxy port | identical proxy logic (`filterNetworkRequest` 731), but the boundary is `--unshare-net` + socat bridges: **all-or-nothing** at the namespace, filtering only at the host proxy (1506-1512) |
| `network.strictAllowlist` | proxy-side | identical (786-791) — platform-independent |
| `network.deniedResolvedAddresses` | proxy-side `dns.lookup` guard | identical (`resolved-address-guard.ts:199`, `directLookup` 672) — platform-independent; still not evaluated for `parentProxy`/`mitmProxy` hops |
| `network.mitmProxy{socketPath,domains}` | host-side unix socket the HTTP proxy dials | **same, host-side only**: `getMitmSocketPath` 906 is consulted by the proxy process; the sandboxed child never touches that socket, and the seccomp filter is irrelevant to it. Also `deniedResolvedAddresses` is not applied on that hop |
| `network.allowUnixSockets` | **works**: seatbelt allows those specific socket paths (`macos-sandbox-utils.ts`, param passed at `sandbox-manager.ts:2702`) | **ignored entirely.** Schema says "macOS only: … Ignored on Linux (seccomp cannot filter by path)" (`sandbox-config.ts:714-718`); `getAllowUnixSockets()` is never called on the Linux branch (2702 vs 2716-2759); `linux-sandbox-utils.ts:3515-3517` states the same. On Linux *all* `socket(AF_UNIX)` creation is refused by the seccomp filter, path-based allowance is impossible — e.g. an ssh agent socket cannot be admitted by path; only `allowAllUnixSockets` changes anything |
| `network.allowLocalBinding` | allows binding/accepting any local port and connecting to localhost on any port (`:2704`) | **not passed to the Linux wrapper at all.** Schema: "Linux: ignored — the sandbox has its own network namespace, whose loopback is always usable and is not the host one. Every service listening on localhost becomes reachable…" (`sandbox-config.ts:726-737`). On Linux the in-netns socat listeners on 3128/1080 are always bindable, and any *host* localhost service is unreachable (separate netns) — the opposite shape from macOS, where the setting gates it |
| `enableWeakerNetworkIsolation` | macOS-only: opens `com.apple.trustd.agent` for Go TLS verification (`sandbox-config.ts:1201-1209`), read only at `sandbox-manager.ts:2710` | **not reached on Linux** — never read on the `case 'linux'` branch. The Linux analogue is structural: the child reaches the proxy through the socat bridge and there is no trustd equivalent; Go cert verification there depends on `SSL_CERT_FILE`/`NODE_EXTRA_CA_CERTS` (`CA_TRUST_VARS` `sandbox-utils.ts:753`) which are only set when `tlsTerminate`/`mitmCA` exists |
| `allowAllUnixSockets` (not in the listed config, but the only unix knob Linux reads) | relaxes seatbelt's unix rules | passed at 2744; **removes the seccomp helper entirely** (3617-3641) — no AF_UNIX block, no AF_VSOCK block, no nested PID/mount namespace from `apply-seccomp`, and it also disables the `--disable-userns` fallback path (3847-3866) |
| `enableWeakerNestedSandbox` (default false) | n/a | `--proc /proc` (3833) vs `--bind /proc /proc` (3839) |
| `allowNestedUserNamespaces` (default false) | n/a (Linux-only, `sandbox-config.ts:1192-1199`) | `SRT_ALLOW_NESTED_USERNS=0|1` (1684) + `--unsetenv` (3845); with the helper it also decides whether the `namespaces` filter and `max_user_namespaces=0` apply |
| `mandatoryDenySearchDepth` | n/a (macOS uses glob patterns, rg never invoked — `sandbox-manager.ts:1644-1645`) | Linux-only, drives the rg scan (§5) |
| `ripgrep`, `bwrapPath`, `socatPath`, `seccomp` | n/a | Linux-only (`sandbox-config.ts:1237-1252`, README:596-599) |
| `allowPty`, `allowMachLookup`, `allowAppleEvents` | macOS-only | not read on the Linux branch |

### Other Linux-vs-macOS behavioural differences worth noting for a port
* Network filtering strength: macOS seatbelt restricts which ports/hosts the profile allows;
  Linux relies on `--unshare-net` plus the host proxy — a sandboxed process can reach
  anything the proxy will carry, and `NO_PROXY` deliberately excludes `*.local`
  (`sandbox-utils.ts:822-824`).
* The MITM CRL distribution point URL is set **only on Windows**
  (`sandbox-manager.ts:1560-1563`): on Linux the child cannot reach the host mux port
  directly, so `mitmCA.crlUrl` is left unset.
* Process isolation: Linux adds the nested PID namespace + `PR_SET_DUMPABLE 0` via
  `apply-seccomp`; there is no macOS analogue.
* Host-visible side effects: bwrap creates mount-point files/dirs on the host for absent
  `denyWrite` paths (`linux-sandbox-utils.ts:2829-2921`), cleaned by
  `cleanupBwrapMountPoints` (1163) — macOS has no equivalent.
* Profile size limits (9000 bwrap args, `MAX_ARG_STRLEN` 128 KiB per argument, the
  `O_TMPFILE` `--args` file) are Linux-only (`renderBwrapInvocation` 1035).
