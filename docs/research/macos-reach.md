# Trace: `SandboxManager.initialize()` + `wrapWithSandbox()` on macOS
### config limited to `filesystem.{allowRead,denyRead,allowWrite,denyWrite}` + `network.{allowedDomains,deniedDomains,strictAllowlist,deniedResolvedAddresses,mitmProxy{socketPath,domains},allowUnixSockets,allowLocalBinding,allowMachLookup}` + `enableWeakerNetworkIsolation`

Repo: github.com/anthropics/sandbox-runtime @ `aceba12` (v0.0.81). All line numbers verified by reading the files.

---

## 0. The two entry points

| | file:line |
|---|---|
| `SandboxManager` namespace object | `src/sandbox/sandbox-manager.ts:3541` (interface `3410` `initialize`, `3440` `wrapWithSandbox`) |
| CLI caller (`srt run`) | `src/cli.ts:505` `initialize(runtimeConfig)` → `src/cli.ts:600` `wrapWithSandbox(...)` → `spawn(sandboxedCommand,{shell:true})` `src/cli.ts:604` |

Note: `initialize(runtimeConfig, askCallback?, **enableLogMonitor = false**, options?)` — `sandbox-manager.ts:1099-1104`. The CLI does **not** pass `enableLogMonitor`, so the macOS log monitor is off unless the embedder opts in (§2.4).

---

## 1. Every function on the path, grouped by file

Legend: **N** = needed for your settings · **U** = runs unconditionally but is not driven by your settings · **✗** = not reached with this config.

### `src/sandbox/sandbox-manager.ts` (3579 lines)

**initialize() arm**

| lines | count | fn | verdict |
|---|---|---|---|
| 1099-1120 | 22 | `initialize` | **N** |
| 1121-1602 | 482 | `initializeSteps` | **N** (the whole body; see sub-steps below) |
| 1603-1611 | 9 | `isSupportedPlatform` | **N** (called at 1165 → 1623) |
| 1623-1699 | 77 | `checkDependenciesCommon` | **N** — on macOS only the tail at 1683-1690 runs (`ownInstallWarning`); the ripgrep block 1641-1647 and `checkLinuxDependencies` 1648-1651 are Linux-only, the Windows block 1652-1671 is Windows-only |
| 1700-1714 / 1715-1739 | 15 / 25 | `checkDependencies` / `checkDependenciesAsync` | **N** (async is the one called, at 1165); the `getApplySeccompBinaryPathAsync` prewarm at 1722-1724 is Linux-only ✗ |
| 417-460 | 44 | `registerCleanup` | **N** (called 1259) |
| 967-1098 | 132 | `startMuxProxyServer` | **N** (called 1526) |
| 731-849 | 119 | `filterNetworkRequest` | **N** — this is where `allowedDomains` / `deniedDomains` / `strictAllowlist` are enforced (deny loop 770-778, allow loop 781-786, strict 789-794) |
| 906-934 | 29 | `getMitmSocketPath` | **N** — `mitmProxy.domains` → `socketPath` (§3) |
| 638-658 / 659-695 | 21 / 37 | `recordProxyViolation` / `recordOutboundDeny` | **N** |
| 671-683 | 13 | `directLookup` (const) | **N** — carries `deniedResolvedAddresses` into every direct dial |
| 2213-2228 | 4×4 | `getAllowUnixSockets`, `getAllowAllUnixSockets`, `getAllowLocalBinding`, `getAllowMachLookup` | **N** (called 2705-2708) |
| 2237-2240 | 4 | `getEnableWeakerNetworkIsolation` | **N** (2710) |
| 2276-2287 | 4×3 | `getProxyAuthToken`, `getProxyPort`, `getSocksProxyPort` | **N** (2691-2693) |
| 2300-2364 | 65 | `waitForNetworkInitialization` | **N** (2647) |
| 522-545 / 546-569 | 24 / 24 | `registerCommandText` / `resolveCommandText` | **N** (2450; 1202 for the log monitor) |
| 2365-2392 | 28 | `waitToWalk` | **N** (2417) |
| 2393-2410 / 2411-2438 / 2439-2800 | 18 / 28 / 362 | `wrapWithSandbox` / `wrapWithSandboxAgain` / `wrapWithSandboxOnce` | **N** |
| 1842-1865 | 24 | `defaultWritePathsUnder` | **N** (2526) |
| 1938-1956 | 19 | `stripWriteGlobs` | **N** as a call, but its Linux glob filter (1945-1952) never fires on macOS |
| 1866-1900 | 35 | `resolveReadDenies` | **N** (2595) |
| 1901-1937 | 37 | `resolveReadPathEntries` | **N** (2566, 2595) — the glob-expansion branch 1914-1923 is `getPlatform()==='linux'` only ✗ |
| 1957-1975 | 19 | `expandAllowReadGlob` | ✗ **Linux-only** (passed as a callback at 2570, never invoked on macOS) |
| 1976-2027 / 2028-2075 | 52 / 48 | `getFsReadConfig` / `getFsWriteConfig` | **U** — not called by `wrapWithSandbox`; called by `checkDependenciesCommon:1685` and the Linux monitor. Getter for embedders |
| 2193-2212 | 20 | `getNetworkRestrictionConfig` | **U** (display only; `cli.ts:560`) |
| 2253-2262 / 2263-2271 | 10 / 9 | `getAllowGitConfig` / `getGitSafeDirectories` | **N** (2709, 2681) — feed the mandatory `.git/config` deny and `GIT_CONFIG_*` |
| 2992-3014 / 3015-3071 | 23 / 57 | `getConfig` / `updateConfig` | **U** (lifecycle) |
| 3072-3097 / 3188-3312 | 26 / 125 | `cleanupAfterCommand` / `reset` | **U** (lifecycle) |
| 3317-3349 | 33 | `annotateStderrWithSandboxFailures` | **U** (embedder-side) |
| **✗** 227-283, 284-416, 461-521 | 21/36/133 + 21/19/21 | `windowsSrtWinIdentity`, `assertWindowsSrtWinCapable`, `windowsProfileReadWarningsOf`, `logWindowsAclOutcomes`, `windowsAclRestoreAllowed`, `releaseWindowsSessionAcls` | **✗ Windows** |
| **✗** 2076-2118, 2119-2133, 2134-2192 | 43/15/16/20/8/15 | `computeWindowsFsAccessSet`, `windowsMaskedFileDenies`, `rawWindowsFsInputs`, `sameRawWindowsFsInputs`, `sameWindowsStampSet`, `windowsLoopbackModeChanged` | **✗ Windows** |
| **✗** 850-865, 866-877, 878-905 | 16/12/28 | `buildCredentialInjector`, `buildBodyCredentialInjector`, `buildSigv4Planner` | **✗ credential masking / sigv4** — all three return `undefined` when `config.credentials` is absent (851, 867, 879); still *called* at 968-970 |
| **✗** 935-966 | 32 | `shouldTerminateTLSForHost` | **✗ TLS termination** — passed to the proxy (984) but only consulted when `mitmCA` is set |
| **✗** 1740-1823, 1824-1841 | 84 / 18 | `getCredentialRestrictions`, `getCredentialDenyReadPaths` | **✗ in effect** — called at 2507 and returns the all-empty object at 1744-1751 (no `credentials` block); `buildMaskedEnvVars`/`registerAwsPairs`/`buildMaskedFileBinds` are invoked with empty arrays |
| **✗** 2229-2236, 2241-2252, 2272-2299 | 4 each | `getIgnoreViolations`, `getEnableWeakerNestedSandbox`, `getAllowAppleEvents`, `getRipgrepConfig`, `getMandatoryDenySearchDepth`, `getSeccompConfig`, `getLinuxHttpSocketPath`, `getLinuxSocksSocketPath` | **✗** (`getIgnoreViolations` is only needed if you also set `ignoreViolations`; `getMandatoryDenySearchDepth` is used only at 2747 = Linux) |
| **✗** 2801-2991 | 191 | `wrapWithSandboxArgv` | **✗ Windows-only argv path** |
| **✗** 3098-3187, 3350-3580 | 65/25/231 | `killBridgeProcess`, `forceCloseHttpServer`, `getLinuxGlobPatternWarnings` | **✗ Linux / teardown** |
| **✗** 570-637 | 52/16 | `registerCommandNetworkLists` / `unregisterCommandNetworkLists` | **✗** unless the embedder calls them (they only matter when `strictAllowlist` is *false*, 798-806) |

**Inside `initializeSteps` (1121-1602), what actually executes on macOS with your config:**

| line | what |
|---|---|
| 1123-1127 | early-return if `initializationPromise` exists |
| 1130-1131 | `config = runtimeConfig; configInstalls++` |
| 1134 | `resolveParentProxy(...)` — `parent-proxy.ts:75-125` (**U**: also reads `HTTP_PROXY`/`HTTPS_PROXY` from the host env) |
| 1139 | `resolvedAddressGuard = createResolvedAddressGuard(runtimeConfig.network)` — **N**, this is `deniedResolvedAddresses` |
| 1144-1147 | `tlsTerminate` + `mitmProxy` mutual-exclusion throw — **N** (you set `mitmProxy`, so `tlsTerminate` must be absent) |
| 1150 | `assertTlsTerminationSupported()` — ✗ (gated on `tlsTerminate`) |
| 1155-1162 | `mitmCA = tlsTerminate && … ? createMitmCA(...) : undefined` → **`mitmCA` stays `undefined`** ✗ `mitm-ca.ts` never runs |
| 1165-1183 | `checkDependenciesAsync()` |
| 1186-1190 | macOS log monitor **only if `enableLogMonitor`** |
| 1191-1256 | Linux seccomp monitor ✗ |
| 1259 | `registerCleanup()` |
| 1262-1497 | entire Windows block ✗ |
| 1500-1596 | `initializationPromise` IIFE: `portRange` 1506-1509 (**macOS → `undefined`**), `proxyAuthToken = randomBytes(16)` 1514-1517, `needLocalProxy` 1522-1524, `startMuxProxyServer` 1526, ports 1528-1529, `getJavaProxyAgentJarPathAsync` 1533-1534 (**U**), `mitmCA.crlUrl` 1544-1551 ✗ (Windows-gated), `initializeLinuxNetworkBridge` 1559-1564 ✗ |

### `src/sandbox/macos-sandbox-utils.ts` (1726 lines) — all **N** unless marked

| lines | count | fn |
|---|---|---|
| 1412-1626 | 215 | `wrapCommandWithSandboxMacOS` |
| 1047-1404 | 358 | `generateSandboxProfile` |
| 103-154 | 52 | `macGetMandatoryDenyEntries` |
| 155-163 | 9 | `generateLogTag` |
| 164-182 / 183-192 / 193-206 / 207-211 / 212-223 | 19/10/14/5/12 | `pathFilter`, `anchorRegex`, `globRegex`, `denyGlobEntryRegex`, `denyPathFilter` |
| 224-238 / 239-272 | 15/34 | `entrySamplePath`, `carveFilter` |
| 273-334 | 13/17/11/8/13 | `anchoredGlobEntry`, `toPathEntry`, `toLiteralPathEntry`, `alsoReadAs`, `callerEntries` |
| 335-365 | 5/26 | `denyGlobCovers`, `isStrictlyUnder` |
| 366-393 / 394-463 / 464-498 | 28/70/35 | `inBothSpellings`, `resolveReadConfig`, `lateReadDenyFilters` |
| 499-550 | 13/39 | `globBaseDir`, `entryBaseDir` |
| 551-618 | 68 | `generateReadDenyUnlinkRules` |
| 619-636 | 18 | `renderRule` |
| 637-689 | 53 | `getAncestorDirectories` |
| 690-821 | 62/4/4/11/51 | `groupLiteralDenyPaths`, `regexLength`, `groupRegexPrefix`, `groupDenyTail`, `literalDenyGroupFilters` |
| 822-883 | 13/49 | `generateMoveBlockingRules`, `moveBlockingFilters` |
| 884-969 / 970-978 / 979-1046 | 86/9/68 | `generateReadRules`, `writeRootEntries`, `generateWriteRules` |
| 1405-1411 | 7 | `escapePath` |
| 1627-1726 | 100 | `startMacOSSandboxLogMonitor` — **only with `enableLogMonitor`** |

### `src/sandbox/sandbox-utils.ts` (2058 lines)

| lines | count | fn | verdict |
|---|---|---|---|
| 451-585 | 185 | `normalizePathForSandbox` | **N** (the single path chokepoint) |
| 636-654 / 655-698 / 699-721 / 722-752 | 19/44/23/31 | `getDefaultWritePaths`, `homeDirsNotReadDenied`, `readRuleCovers`, `compiledDenyGlob` | **N** |
| 21-43 | 16/7 | `DANGEROUS_FILES`, `DANGEROUS_DIRECTORIES` | **N** |
| 44-60 | 17 | `getDangerousDirectories` | **N** |
| 772-1000 | 229 | `generateProxyEnvVars` | **N** |
| 1001-1060 | 60 | `sshConnectScript` | **N** (macOS + token + mux port ⇒ §2.3) |
| 1061-1131 / 1132-1149 | 71/18 | `buildGitConfigEnv`, `buildPosixGitSafeDirEnv` | **N** only if `git.safeDirectories` is set |
| 1156-1224 | 14/8/5/20 | `attributionKeyFor`, `encodeSandboxedCommand`, `decodeSandboxedCommand`, `proxyUsernameFor` | **N** |
| 1225-1274 | 50 | `encodedCommandFromProxyUser` | **N** (proxy-side) |
| 69-94 / 95-119 / 120-131 / 145-176 / 248-265 / 266-365 / 366-388 / 403-414 / 415-450 | small | `isAtOrUnder`, `isStrictlyUnder`, `pathSpellings`, `nameLocation`, `workingDirectory`, `containsGlobChars*`, `removeTrailingGlobSuffix`, `isSymlinkOutsideBoundary`, `expandTilde`, `collapseInteriorSpellings`, `warnIfParentRefUnfolded` | **N** |
| 1275-1350 / 1351-1411 / 1412-1574 / 1614-2058 | 16/61/163/445 | `finish`, `finishInTurns`, `globPositions`, `walkGlobPattern` | **N** (`finishInTurns` drives the wrap walk at 2519-2524); `globPositions`/`walkGlobPattern` only if a glob is expanded ⇒ effectively ✗ on macOS |
| 753-771 | 19 | `CA_TRUST_VARS` | ✗ **TLS termination** (only used when `caCertPath` is passed, i.e. `tlsTerminate`) |
| 61-68, 161-165, 177-204, 205-247, 389-402 | small | `normalizeCaseForComparison`, `containsGlobCharsWin`, `markedLiteralPath`, `stripExtendedPathPrefix`, `isUncPath`, `expandWindowsEnvRefs` | ✗ Windows-only branches inside them |

### `src/sandbox/http-proxy.ts` (1440 lines)

| lines | count | fn | verdict |
|---|---|---|---|
| 417-1412 | 996 | `createHttpProxyServer` | **N** — the `connect` handler 497-965 and the `request` handler 968-1410 |
| 483-499 | 17 | `checkAuth` (closure) | **N** (407 challenge) |
| 1413-1429 / 1430-1440 | 17/11 | `parseConnectTarget`, `isAsciiAuthority` | **N** |
| 413-416 | 4 | `markHandedInConnection` | **U** |
| 420 | 1 | `assertTlsTerminationSupported()` call | ✗ (`options.mitmCA` undefined) |
| 596-621, 640-655, 657-658 | — | decision-window EOF/capture machinery | **N** |
| 729-881 | ~150 | the `mitmCA` ClientHello-sniff + `terminateAndForward` branch | ✗ **TLS termination** |
| 890-916 | 27 | **mitm unix-socket CONNECT route** | **N** (§3) |
| 1079-1085, 1259-1290 | 7/32 | **mitm unix-socket plain-HTTP route** | **N** (§3) |
| 1131-1140 `gateSocketOnBufferedBody` | — | ✗ unless `maxBufferedRequestBody` set |

### `src/sandbox/socks-proxy.ts` (481) — **N**: `createSocksProxyServer` 98-299 (202), `readSocksGreeting` 300-340 (41), `refuseUnauthenticated` 341-382 (42), `socksReply` 383-387, `readSocksConnect` 388-447 (60), `sshDisconnectPacket` 476-481. **No mitm route here** — SOCKS dials `parentProxy` or `dialDirect` (socks-proxy.ts:202-212).

### `src/sandbox/mux-proxy.ts` (258) — **N**: `unixSocketPath` 77-95 (19), `createMuxProxyServer` 96-258 (163); `dispatchHttp` 111-158, `listenHttpBackend` 196-232.

### `src/sandbox/parent-proxy.ts` (639) — **N**: `resolveParentProxy` 75-125, `parseNoProxy` 126-177, `shouldBypassParentProxy` 178-205, `selectParentProxyUrl` 206-236, **`openConnectTunnel` 237-326 (90)**, `connectViaParentProxy` 327-357, `proxyAuthHeader` 358-387, `relayResponseHead` 388-424, `stripHopByHop` 451-474, `isValidHost` 505-526, `canonicalizeHost` 527-549, `formatAuthority` 550-581, `directRequestOptions` 582-612, `dialDirect` 613-639.

### `src/sandbox/domain-pattern.ts` (250) — **N**: `matchesDomainPattern` 189-208, `matchesDomainPatternWithPort` 209-234, `splitDomainPatternPort` 41-72, `isValidDomainPattern` 83-123, `ipLiteralRules` 161-170, `stripDomainPatternPort` 171-188, `dropZone` 15-40. (`isInjectHostCoveredByAllowedDomains` 235-250 ✗ credentials.)

### `src/sandbox/resolved-address-guard.ts` (310) — **N**: `createResolvedAddressGuard` 199-310 (112), `buildRuleSet` 175-190, `inRuleSet` 191-198, `localInterfaceAddresses` 89-102, `isResolvedAddressDenied` 121-130, `ResolvedAddressDeniedError` 103-120. Built-in `DENIED_CLASSES` at 55-70.

### `src/sandbox/glob-pattern.ts` (254) — **N**: `parseGlob` 77-187 (111), `globTokenToRegex` 193-230, `globToRegex` 231-249, `denyGlobRegex` 250-254, `escapeRegexLiteral` 188-192.

### `src/sandbox/path-entries.ts` (446) — **N**: `splitPathEntries` 61-73, `spelledOf` 74-84, `literalReadings` 182-253 (72), `readRulesOf` 305-331, `literalReadLists` 344-354, `literalWriteLists` 355-372, `writeRootsOf` 373-383, `reExposedBy` 384-400. ✗ `hasNameReading` 270-304 (only reached through the Linux branch of `stripWriteGlobs`), `mayBeThere`/`isThereUnlinked`/`isDirectoryFor` 124-181 (disk probes used by `literalReadings` — partially N).

### `src/sandbox/listen-in-range.ts` (56) — **N**: `listenInRange` 8-56 (49).

### `src/sandbox/sandbox-violation-store.ts` (178) — **N**: `SandboxViolationStore` 11-84 (74), `shouldIgnoreViolation` 85-130, `sanitizeUnregisteredCommandKey` 145-155, `sanitizeDenialReason` 165-171.

### `src/utils/` — **N**: `shell-quote.ts:26-47` `quote` (22), `which.ts:10-29` `whichSync` (20), `real-path.ts:42-60` `realPathOf` (19), `debug.ts:4-30` `logForDebugging` (27), `platform.ts:43-57` `getPlatform` (15).

### Files **entirely off this path**

| file | why |
|---|---|
| `linux-sandbox-utils.ts` (3937), `generate-seccomp-filter.ts` (307), `linux-violation-monitor.ts` (223), `read-deny-glob.ts` (239) | **Linux** — `read-deny-glob.ts:96` `expandReadDenyGlobLinuxSteps` is *passed* as a callback at `sandbox-manager.ts:2599` but never invoked on macOS (`resolveReadPathEntries` gates on `getPlatform()==='linux'`, 1914-1917) |
| `windows-sandbox-utils.ts` (4606) | **Windows** |
| `mitm-ca.ts` (646), `mitm-leaf.ts` (168), `tls-terminate-proxy.ts` (1514), `body-substitution.ts` (164) | **TLS termination** — all gated on `mitmCA`/`tlsTerminate` |
| `credential-sentinel.ts` (247), `credential-mask-env.ts` (228), `credential-mask-files.ts` (358), `credential-extract.ts` (161), `credential-decode.ts` (162), `credential-aws-pairs.ts` (383), `aws-sigv4.ts` (357) | **credential masking / sigv4** — empty inputs with no `credentials` block |
| `decider-client.ts` (859), `proxy-only.ts` (330), `proxy-cli.ts` (169), `proxy-main.ts` (5) | separate **proxy-only mode** (`srt proxy`, `cli.ts:327`) |
| `java-proxy-agent.ts` (131) | **U** — `getJavaProxyAgentJarPathAsync` runs at `sandbox-manager.ts:1533` regardless of your settings (may spawn `npm root -g`); `buildJavaToolOptions` then emits `-Djava.net.preferIPv4Stack=true` at `macos-sandbox-utils.ts:1539-1551` because the proxy ports make loopback reachable |
| `own-files.ts` (42) | **U** — `ownInstallWarning` at 1685 and 2552 |
| `emitted-connection.ts` (238) | mixed: `createByteBudget` 155-162 **N** (http-proxy.ts:430); `assertTlsTerminationSupported` 48-71 ✗ |

---

## 2. What the sandboxed child gets **without asking**

### 2.1 Default write paths (always added, `allowWrite` is *appended after them*)

`getDefaultWritePaths` — `sandbox-utils.ts:636-654`, list at 585-594:

```
/dev/stdout  /dev/stderr  /dev/null  /dev/tty  /dev/dtracehelper  /dev/autofs_nowait
/tmp/claude  /private/tmp/claude
```
plus the *home convenience dirs* (`HOME_CONVENIENCE_WRITE_DIRS`, 601-604): `~/.npm/_logs`, `~/.claude/debug` — these two are **dropped** when a `denyRead` entry names them or a directory above them, and re-kept when an `allowRead` entry beneath that deny re-opens them (`homeDirsNotReadDenied` 655-698).

Merged at `sandbox-manager.ts:2525-2531` (`defaultWritePathsUnder` 1842-1865 → `getDefaultWritePaths(readRulesOf(...))`) with your `allowWrite` appended at 2531. `filesystem.disabled` is not in your config, so `writeConfig !== undefined` ⇒ `hasWriteRestrictions` true (`macos-sandbox-utils.ts:1470`) ⇒ `(allow file-write*)` is **not** emitted; only the roots are.

Also implicit: `TMPDIR` is rewritten to `$CLAUDE_CODE_TMPDIR || $CLAUDE_TMPDIR || /tmp/claude` (`sandbox-utils.ts:798-806`) — skipped only when `writeConfig === undefined` (`skipTmpdir`, passed as `writeConfig === undefined` at `macos-sandbox-utils.ts:1517`).

### 2.2 Mandatory deny paths (write denies, always on)

`macGetMandatoryDenyEntries(allowGitConfig)` — `macos-sandbox-utils.ts:103-154`, consumed in `generateWriteRules` at 999-1006. Each name is emitted **twice**: a literal `subpath` at the cwd, and an anchored glob `**/<name>[/…]` as a `regex`.

- `DANGEROUS_FILES` (`sandbox-utils.ts:21-35`, 9 entries): `.gitconfig .gitmodules .bashrc .bash_profile .zshrc .zprofile .profile .ripgreprc .mcp.json`
- `getDangerousDirectories()` (`sandbox-utils.ts:44-60`): `.vscode`, `.idea`, `.claude/commands`, `.claude/agents` — **`.git` is filtered out** so the `.git` directory itself stays writable
- `.git/hooks` + `**/.git/hooks/**` — always (macos 129-130)
- `.git/config` + `**/.git/config` — unless `filesystem.allowGitConfig` (macos 133-136)

⇒ **30 PathEntry objects** with `allowGitConfig:false`, 28 with `true`. All are joined onto `normalizePathForSandbox(process.cwd(), {literal:true})` (macos 107).

Plus the anti-`mv` layer: `generateMoveBlockingRules` 822-834 / `moveBlockingFilters` 835-883 (deny `file-write-unlink`/`file-write-create` on each denied path **and every ancestor directory**), the read-side twin at `generateReadRules:920`, the write-side twin at `generateWriteRules:1017-1035`, and the trailing re-deny `generateReadDenyUnlinkRules` 551-618 emitted last in the profile (1157-1166).

### 2.3 Env vars set on the child

Assembled in `wrapCommandWithSandboxMacOS` (`macos-sandbox-utils.ts:1512-1570`) and placed in `env … /usr/bin/sandbox-exec` order at 1591-1603: `env [-u NAME…] [SET=…] [PROXY VARS…] sandbox-exec -p <profile> <shell> -c <command>`.

From `generateProxyEnvVars` (`sandbox-utils.ts:772-1000`):

| var | line |
|---|---|
| `SANDBOX_RUNTIME=1` | 793 |
| `TMPDIR=…` | 805 |
| `NO_PROXY` / `no_proxy` = `localhost,127.0.0.1,::1,169.254.0.0/16,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16` (deliberately **no `*.local`**) | 826-838 |
| `HTTP_PROXY` `HTTPS_PROXY` `http_proxy` `https_proxy` = `http://srt.<b64(cmd)>:<token>@localhost:<muxPort>` | 841-845 |
| **`GIT_CONFIG_PARAMETERS='http.proxyAuthMethod=basic'`** (only when a token exists) | 850 |
| `ALL_PROXY` / `all_proxy` (HTTP URL preferred over socks5h) | 869-870 |
| `GRPC_PROXY` / `grpc_proxy` | 880-881 |
| **`SRT_SSH_PROXY_COMMAND=<sh script>`** + **`GIT_SSH_COMMAND=ssh -o ControlMaster=no -o ControlPath=none -o ProxyCommand="/bin/sh -c 'eval …' sh '%h' %p"`** — macOS + token + `httpProxyPort===socksProxyPort` (always true here, one mux port) | 893-912, script built by `sshConnectScript` 1001-1060 |
| (fallback when no token: `GIT_SSH_COMMAND=ssh … -o ProxyCommand='nc -X 5 -x localhost:<port> %h %p'`) | 913-918 |
| `FTP_PROXY` / `ftp_proxy` = `socks5h://…` | 937-938 |
| `RSYNC_PROXY=localhost:<socksPort>` | 943 |
| `DOCKER_HTTP_PROXY` / `DOCKER_HTTPS_PROXY` | 951-954 |
| `CLOUDSDK_PROXY_TYPE/ADDRESS/PORT/USERNAME/PASSWORD` | 963-969 |
| `JAVA_TOOL_OPTIONS=-javaagent:<jar> -Djava.net.preferIPv4Stack=true` | macos 1539-1553 |
| `GIT_CONFIG_KEY_n` / `GIT_CONFIG_VALUE_n` / `GIT_CONFIG_COUNT` (`safe.directory`) | macos 1559-1568 → `buildPosixGitSafeDirEnv` 1132-1149 → `buildGitConfigEnv` 1061-1131 |

**CA-trust vars are NOT set with `mitmProxy`.** `NODE_EXTRA_CA_CERTS, SSL_CERT_FILE, CURL_CA_BUNDLE, REQUESTS_CA_BUNDLE, PIP_CERT, GIT_SSL_CAINFO, AWS_CA_BUNDLE, CARGO_HTTP_CAINFO, DENO_CERT, CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE, NIX_SSL_CERT_FILE` (`CA_TRUST_VARS` 753-771) are emitted only inside `if (caCertPath)` at 811-815, and `caCertPath` comes from `mitmCA?.trustBundlePath` (`sandbox-manager.ts:2694`) — `undefined` unless `tlsTerminate`. So with `mitmProxy` the child must already trust the external MITM CA through the inherited host environment.

`env -u NAME…` (1581) and `NAME=sentinel` (1585) come only from the `credentials` block ⇒ **none** with your config.

### 2.4 The macOS log monitor

Started only at `sandbox-manager.ts:1198-1205` when `enableLogMonitor===true && getPlatform()==='macos'`; the CLI never sets it.

`startMacOSSandboxLogMonitor` — `macos-sandbox-utils.ts:1627-1726` (100 lines):
- spawns `log stream --predicate '(eventMessage ENDSWITH "<sessionSuffix>")' --style compact` (1641-1645)
- `sessionSuffix = _<random base36>_SBX` (149) — one per process, not per command
- pairs a `Sandbox: … deny` line with a `CMD64_…_END` line (1652-1660), decodes the key (`decodeSandboxedCommand`) and maps it back through `resolveCommandText` (1670)
- hard-coded noise filter: `mDNSResponder`, `mach-lookup com.apple.diagnosticd`, `mach-lookup com.apple.analyticsd` (1688-1694)
- `shouldIgnoreViolation(...)` (1697) → `sandbox-violation-store.ts:85-130`
- callback → `sandboxViolationStore.addViolation` (1701-1707)
- returns a shutdown closure stored in `logMonitorShutdown` (1199), called by `reset()` (3214-3217)

Correlation works because every emitted rule carries `(with message "<logTag>")` (`renderRule` 619-636) and the profile opens with `(deny default (with message "<logTag>"))` (1085); `logTag = CMD64_<b64>_END_<sessionSuffix>` (`generateLogTag` 155-163).

---

## 3. How `mitmProxy.socketPath` routes a matching domain

**It is a raw HTTP `CONNECT` tunnel to the external proxy over the unix socket. ASRT does not terminate TLS on this route.**

1. `sandbox-manager.ts:906-934` `getMitmSocketPath(host)` — canonicalizes (`canonicalizeHost`, `parent-proxy.ts:527-549`), then `matchesDomainPattern(canonicalHost, pattern)` (`domain-pattern.ts:189-208`) over `mitmProxy.domains`; returns `socketPath` on the first hit, else `undefined` (**fails open**: no match ⇒ direct dial).
2. Handed to the proxy as `getMitmSocketPath` at `sandbox-manager.ts:982`.
3. **CONNECT path** — `http-proxy.ts:890` re-computes it from the *canonical* host, then 900-910:
   ```ts
   upstream = await openConnectTunnel({
     dial: () => connect({ path: mitmSocketPath }),   // AF_UNIX dial
     readyEvent: 'connect', destHost: hostname, destPort: port,
   })
   ```
   `openConnectTunnel` (`parent-proxy.ts:237-326`) writes
   `CONNECT host:port HTTP/1.1\r\nHost: host:port\r\n\r\n` (300-305), waits for a `2xx` status line (322-326 → `Proxy refused CONNECT` otherwise), unshifts surplus bytes, resolves the socket. Back in `http-proxy.ts:944-965`: `200 Connection Established` to the child, `allowHalfOpen = true`, `upstream.pipe(socket); socket.pipe(upstream)` — **pure byte relay**. No `peekForClientHello`, no leaf cert, no SNI re-handshake.
4. **Plain-HTTP path** — `http-proxy.ts:1079` + 1259-1290: `new Agent({ socketPath: mitmSocketPath })` (1263-1266) and `httpRequest({agent, path: absUrl, method, headers: fwdHeaders})` (1267-1271) — the request is forwarded as an **absolute-URI proxied request** (`http://host/path` as the request target, `Host:` rebuilt from the canonical authority at 1072-1074 via `formatAuthority`).
5. Route precedence, both handlers: **mitm unix socket > parentProxy > direct** (`http-proxy.ts:726-733`, `1078-1085`). `parentProxy` is skipped whenever mitm matches (901-905, 1080-1085). `deniedResolvedAddresses` is **not** evaluated on this hop — the guard's `lookup` is only passed to `dialDirect` (`http-proxy.ts:915`, `socks-proxy.ts:207-210`); the schema says so explicitly (`sandbox-config.ts:710-713`).
6. Allow/deny still runs *before* the mitm hop: `options.filter(...)` at `http-proxy.ts:686-695` → `filterNetworkRequest` (`sandbox-manager.ts:731-849`).
7. **SOCKS has no mitm route** — `socks-proxy.ts` never calls `getMitmSocketPath`; a SOCKS tunnel is parent-proxy-or-direct (202-212).
8. Consequence: the dial of `socketPath` happens in the **unsandboxed parent process**, so `network.allowUnixSockets` is *not* required for `mitmProxy` to work. And because nothing is decrypted, `mutateHeaders` / body substitution / SigV4 (all TLS-terminated-path only, `sandbox-manager.ts:1021-1035`) cannot apply, and the child gets no CA-trust env vars (§2.3).

---

## 4. What the proxies listen on, and how Seatbelt admits the child

**Topology (macOS):**

```
child ──TCP──> 127.0.0.1:<muxPort>  (net.Server, ephemeral)      mux-proxy.ts:161-184
                    │ first byte 0x04/0x05 → SOCKS in-process     mux-proxy.ts:20, 176-181
                    └ otherwise → pipe to unix socket             mux-proxy.ts:111-158
                              /tmp/srt-mux-<pid>-<seq>.sock       mux-proxy.ts:77-95, 196-215
                                     └ http.Server (http-proxy.ts)  ← never listens on TCP here
```

- **Front end**: `createMuxProxyServer` (`mux-proxy.ts:96-258`) → `mux.listenHttpBackend()` first (`sandbox-manager.ts:1082`) so the front end never dispatches to an unbound backend, then `listenInRange(mux.server, p => mux.server.listen(p,'127.0.0.1'), portRange, {backendPort})` (`sandbox-manager.ts:1083-1087`). On macOS `portRange` is `undefined` (`sandbox-manager.ts:1506-1509`), so `listenInRange` binds **port 0 → OS-chosen ephemeral port** (`listen-in-range.ts:20, 51`). `mux.getPort()` (1085, `mux-proxy.ts:186-189`) → `managerContext.httpProxyPort === socksProxyPort === muxPort` (`sandbox-manager.ts:1528-1529`). `mux.unref()` 1094.
- **HTTP back end**: a **unix socket** `join(tmpdir(), 'srt-mux-<pid>-<seq>.sock')` (`mux-proxy.ts:77-95`; comment at 78: "Keep it short — macOS `sun_path` is 104 bytes"). Chosen because Bun's `http.Server` doesn't support `emit('connection')` injection (`mux-proxy.ts:88-95`).
- **SOCKS**: no listener of its own — `socksProxyServer.handleConnection(s)` is called with the peeked byte unshifted (`sandbox-manager.ts:1071`, `socks-proxy.ts:262-281`).
- **Auth**: the child must present `Proxy-Authorization: Basic base64("srt.<b64(command)>:<proxyAuthToken>")` — username built by `proxyUsernameFor` (`sandbox-utils.ts:1205-1224`), checked by `checkAuth` (`http-proxy.ts:483-499`, 407 on failure) and `socksServer.setAuthHandler` (`socks-proxy.ts:101-113`). Token is `randomBytes(16)` per session (`sandbox-manager.ts:1514-1517`), `undefined` when `network.httpProxyPort` is external (1512-1513).

**Seatbelt admission** (`generateSandboxProfile`, network block `macos-sandbox-utils.ts:1256-1345`):

| setting | emitted | lines |
|---|---|---|
| no network config | `(allow network*)` | 1258 |
| your config ⇒ `needsNetworkRestriction` true (`sandbox-manager.ts:2631-2641`) | everything below, `(deny default)` at 1085 stays the floor | — |
| `allowLocalBinding` | `(allow network-bind (local ip "*:*"))`, `(allow network-inbound (local ip "*:*"))`, `(allow network-outbound (remote ip "localhost:*"))` — `*:*` because Seatbelt's `localhost` filter misses `::ffff:127.0.0.1`; outbound stays `localhost:*` so the allowlist still bites | 1280-1284 |
| `allowUnixSockets` | `(allow system-socket (socket-domain AF_UNIX))` + per-path `(allow network-bind (local unix-socket (subpath P)))` and `(allow network-outbound (remote unix-socket (subpath P)))`, P = `normalizePathForSandbox(p)` | 1301-1313 |
| (`allowAllUnixSockets` variant) | `path-regex #"^/"` for both | 1292-1300 |
| **proxy ports** | `(allow network-bind / network-inbound / network-outbound (local|remote ip "localhost:<httpProxyPort>"))` | **1318-1328** |
| SOCKS port | same triple, **skipped when it equals the HTTP port** (the mux case) | **1333-1344** |
| `allowMachLookup` | `global-name` or `global-name-prefix` for a trailing `*` | 1136-1144 |
| `enableWeakerNetworkIsolation` | **only** `(allow mach-lookup (global-name "com.apple.trustd.agent"))` — needed for Go TLS cert verification; it does not relax any file/network rule and is macOS-only | **1116-1120** |

So the child only ever needs `connect()` to `127.0.0.1:<muxPort>` (matched by 1326). The two AF_UNIX dials — mux→HTTP-backend (`mux-proxy.ts:122`) and HTTP-proxy→mitm socket (`http-proxy.ts:905`) — are performed by the **parent**, which is not under `sandbox-exec`; `allowUnixSockets` is therefore unrelated to `mitmProxy`. The `network-bind`/`network-inbound` clauses for the proxy ports are belt-and-braces (the listener lives in the parent); the operative one is `network-outbound`.

Because `NO_PROXY` contains `127.0.0.1`/`localhost` (826-838) while the profile only admits `localhost:<muxPort>`, a child that talks to a *local* service directly is blocked unless `allowLocalBinding` widens outbound to `localhost:*` (1283).

---

## 5. One-line summary of the wrapped result

```
env <proxy vars> /usr/bin/sandbox-exec -p '(version 1)
  (deny default (with message "CMD64_…_END_<rand>_SBX"))
  …mach/sysctl/iokit/pty allowlists…
  ; Network   → localhost:<muxPort> only (+ your allowUnixSockets/allowLocalBinding/allowMachLookup)
  ; File read → (allow file-read*) then your denyRead denies, then allowRead, then late re-denies
  ; File write→ your allowWrite + defaults, then denyWrite + the 30 mandatory denies, then unlink pins
' <which(bash|binShell)> -c '<command>'
```
built at `macos-sandbox-utils.ts:1591-1603` via `quote()` (`src/utils/shell-quote.ts:26-47`), returned from `wrapWithSandbox` (`sandbox-manager.ts:2686-2713`).
