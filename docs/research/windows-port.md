# sandbox-runtime (srt) on Windows — verified read of the code

Upstream: anthropics/sandbox-runtime @ `aceba12`.
Consumer: shep-pm/shep-kelpie.

All line numbers below were read from the files, not inferred from grep hits.

---

## 0. Shape of the Windows backend (one paragraph of orientation)

Windows isolation is **not** a kernel sandbox like seatbelt/bwrap. It is:

1. a **separate local user account** (`srt-sandbox`) that the child runs as, so its
   token carries a *different user SID* — `vendor/srt-win-src/src/user.rs:1-15`;
2. a **machine-wide WFP filter set keyed on that user's SID** at the two ALE
   connect layers — `vendor/srt-win-src/src/wfp.rs:613` (`sddl_sandbox_user`),
   `wfp.rs:426` (`ALE_LAYERS`);
3. **additive explicit ACEs** for that SID (grants/denies) on real-user files —
   `vendor/srt-win-src/src/acl.rs:1-33`;
4. a **two-hop launch** (broker as real user → `CreateProcessWithLogonW` →
   `srt-win runner` as `srt-sandbox` → restricted-token child) —
   `vendor/srt-win-src/src/runner.rs:1-19`, `src/logon.rs:1-30`.

The TS layer (`src/sandbox/windows-sandbox-utils.ts`) is a thin CLI wrapper over
`srt-win.exe`; there is no marker file, all status comes from live enumeration
(`windows-sandbox-utils.ts:44-58`).

---

## 1. `src/sandbox/windows-sandbox-utils.ts` — its jobs, with line counts

4606 lines. Grouped by purpose (function → start line → rough span):

### 1a. Error surface (~200 lines)
- `WindowsSandboxErrorCode` union — **:73-184** (~112). 40 stable codes:
  `srt_win_not_found`, `spawn_failed`, `srt_win_timeout`, `srt_win_nonzero`,
  `srt_win_bad_json`, `bin_shell_invalid`, `wfp_verify_bind_failed`,
  `wfp_verify_unparseable`, `wfp_fence_inactive`, `wfp_verify_inconclusive`,
  `wfp_loopback_mismatch`, `srt_win_too_old`, `trust_ca_failed`,
  `trust_ca_not_installed`, `trust_ca_thumbprint_mismatch`, `install_wfp_failed`,
  `install_user_failed`, `install_config_conflict`, `install_ambient_failed`,
  `install_timeout`, `install_failed`, `uninstall_failed`, `acl_stamp_failed`,
  `acl_grant_failed`, `profile_grant_outdated`, `profile_grant_failed`,
  `profile_forget_failed`, `kept_grants_in_use`, `srt_win_outdated`,
  `profile_grant_blocked_by_session`, `profile_operation_in_progress`,
  `session_ended`, `profile_exclusion_read_grant`, `argv_too_long`,
  `not_provisioned`, `reinstall_required`, `mapped_drive_cwd`, `seclogon_disabled`.
- `class WindowsSandboxError` (`.code`, `.subcommand`) — **:185-199**.

### 1b. Fence constants and status types (~230 lines)
- `DEFAULT_WINDOWS_PROXY_PORT_RANGE = [60080, 60089]` — **:204**.
- `WINDOWS_LOOPBACK_PROBE_PORT = 1` — **:213** (mirrors `wfp::LOOPBACK_PROBE_PORT`, `wfp.rs:104`).
- `WINDOWS_ALLOW_LOOPBACK_EFFECT` (plain-words warning) — **:216-233**.
- `WindowsWfpStatus` — **:234**; `WindowsWfpStatusResult` — **:240-265**;
  `WindowsWfpProbeOutcome` — **:266**; `WindowsWfpResidual` — **:279**;
  `WindowsWfpVerifyResult` — **:290-324**; `WindowsSeclogonState` — **:325**;
  `WindowsSandboxUserStatus` — **:331-418** (~88, the biggest status object:
  `provisioned/sid/groupExists/groupSid/inBuiltinUsers/inSandboxGroup/
  hiddenFromLogon/credPresent/markerVersion/setupVersion/realUserSid/
  caCertThumb/caCertPem/seclogon/persistentGrants/profileGrant/capabilities/sessionUserSid`).

### 1c. Inner-shell normalisation (~110 lines)
- `WindowsBinShell` type — **:419-443** (doc: `exe` must come from trusted host
  config, never workspace content).
- `parseWindowsBinShell` — **:444-526** (~83). Sole normalizer; `cmd` default
  `System32\cmd.exe` + `/d /s /c` (:447-451), `pwsh`/`powershell` `-NoProfile -Command`
  (:426, :494-509), `bash`/`sh` require an absolute path (:479-490), everything
  else throws `bin_shell_invalid` (:511-519). Uses `path.win32` explicitly so it
  tests on any platform.

### 1d. Wrap parameters (~150 lines)
- `WindowsSandboxParams` — **:527-671**: `command`, `commandId`, `httpProxyPort`,
  `socksProxyPort`, `proxyAuthToken`, `allowLoopback`, `setEnvVars` (mask
  sentinels), `denyRead`, `denyReadExcept`, `heldBy`, `denyWrite`, `cwd`,
  `allowWrite`, `gitSafeDirectories`, `caCertPath`, `quiet`, `srtWin`,
  `writeRoots`, `binShell`.

### 1e. Binary resolution (~120 lines)
- `repoRoot` — **:676**; `VENDORED_SRT_WIN_EXE` (`vendor/srt-win/<arch>/srt-win.exe`) — **:694-718** (with the WARNING that in a dev checkout it may sit inside the write grant);
- `getSrtWinPath` (dev/CI lookup: vendored, then `vendor/srt-win-src/target/release`) — **:719-753**;
- `SRT_WIN_DISPATCH_ARG1 = '--srt-win'` — **:754-761** (must match `srt_win::SRT_WIN_DISPATCH_ARG1`, `cli.rs:56`);
- `SrtWinSpawn` — **:762**; `resolveSrtWin` (no implicit vendor fallback) — **:781-798**.

### 1f. Spawn chokepoint + exit-code contract (~270 lines)
- `runSrtWin` (`spawnSync`, 15 s default) — **:816-861**;
- exit consts `SRT_WIN_EXIT_PROFILE_BUSY=25` — **:862**, `SESSION_ENDED=26` — **:868**, `HELD_BY_OTHERS=22` — **:870**, `GRANT_BLOCKED=24` — **:872**;
- `describeWindowsHolder`/`describeWindowsHolders` (`{"held_by":[…]}`) — **:875**, **:899**;
- `throwIfRefusedBesideOthers` (25/22/24 → typed errors) — **:918-965**;
- `runSrtWinAsync` (event-loop-friendly twin, manual timer so a timeout is
  distinguishable from an external kill) — **:966-1026**;
- `parseSrtWinJson` — **:1027**; `runSrtWinJson` — **:1047**; `runSrtWinJsonAsync` — **:1051**;
  `runSrtWinJsonAllowFail` (parse before exit-code check, for teardown) — **:1064-1087**.

### 1g. Status mapping / capability gate (~230 lines)
- `RawWfpStatus` — **:1088**; `wfpStatusArgs` — **:1097**; `mapWfpStatus` — **:1103**;
- `RawUserStatus` — **:1115-1150**;
- `WINDOWS_SRT_WIN_CAPABILITIES` (`profile-deny-expansion`, `kept-grant-holders`,
  `profile-session-grant-check`, `read-deny-except`, `exec-holder`) — **:1151-1186**;
- `missingWindowsSrtWinCapability` — **:1187**; `capabilityList` — **:1195**;
  `windowsSrtWinOutdatedError` — **:1202-1215**;
- `mapUserStatus` — **:1223-1277** (note: anything but an explicit `"none"` counts
  as *present* for `persistent_grants`/`profile_grant`, :1252-1276 — fail closed);
- `seclogonDisabledMessage` — **:1278**; `SRT_WIN_EXIT_SECLOGON_DISABLED=18` — **:1289**;
  `seclogonDisabledFrom` — **:1295-1306**;
- `checkWindowsSandboxStatus` / `…Async` (one `srt-win status` spawn) — **:1320**, **:1332-1357**;
- `getWindowsWfpStatus` / `…Async` — **:1358**, **:1369-1378**.

### 1h. WFP fence verification (~370 lines)
- `RawWfpVerify` — **:1379-1401**; `WindowsInstallContext` — **:1402**;
- `windowsInstallFlags` / `windowsInstallCommand` (the command an error suggests) — **:1414**, **:1431**;
- `rejectsAllowLoopback` (old binary that doesn't know `--allow-loopback`) — **:1442**;
  `srtWinTooOld` — **:1446-1472**;
- `WFP_RESIDUAL_TEXT` + `isWfpResidual` — **:1455-1481**;
- `interpretWindowsWfpVerify` (pure; 183 lines) — **:1482-1664**: exit 19 →
  `wfp_loopback_mismatch` (:1536-1547); any of `plain`/`lowIntegrity`/
  `lowIntegrityLoopback`/`untrustedIntegrity`/`untrustedIntegrityLoopback`
  `connected|refused` → `wfp_fence_inactive` (:1553-1585); exit 3 same (:1577);
  exit ≠ 0 → `wfp_verify_inconclusive` (:1587-1597); **exit 0 alone is not a pass**
  — `egress_probe` must literally be `blocked` (:1600-1608); residuals → warnings
  only (:1610-1625); open loopback appends `WINDOWS_ALLOW_LOOPBACK_EFFECT` (:1631).
- `verifyWindowsWfpEgress` — **:1665-1751**: binds an ephemeral loopback listener
  **outside** the permit range, retrying 5× so an in-range port can't fake a
  `connected` (:1683-1703); argv `wfp verify --target … [--anonymous-egress]
  [--allow-loopback] --write-restricted-token --write-root <each>` (:1707-1714);
  30 s timeout (:1719-1721); exit 18 handled before JSON parse (:1723-1725).

### 1i. Sandbox user + CA (~370 lines)
- `getWindowsSandboxUserStatus` / `…Async` — **:1752**, **:1761-1786**;
- `getWindowsSandboxCaCert` — **:1787-1811** (the `tlsTerminate` gate reads this);
- `windowsTrustCa` / `windowsTrustCaAsync` / `checkTrustCaResult` — **:1812**,
  **:1826**, **:1837-1863** (60 s: first call may create the sandbox profile);
- `windowsStateDir()` = `%ProgramData%\sandbox-runtime` — **:1864-1870** (mirrors
  `state_db::machine_store_dir()`, `state_db.rs:837`);
- `WindowsPersistentCa` — **:1871-1954**; `ensurePersistentWindowsCa` —
  **:1955-2129** (~175): provisioning gate (:1968-1984), `ca.json` tmp+rename
  atomic write (:1999-2004, :2114), re-read after write so concurrent brokers
  converge (:2105-2113), trust reconcile through a per-call unique
  `.trust.<pid>.<ts>.pem` never a shared mutable path (:2032-2043), stale
  `.tmp.*`/`.trust.*` sweep (:2098-2107).

### 1j. Install / uninstall (~490 lines)
- `WindowsInstallOptions` — **:2130-2195**; `WindowsInstallProfileGrant` — **:2196**;
  `WindowsInstallResult` — **:2212-2233**;
- `INSTALL_TIMEOUT_MS = 120_000` (UAC dialog auto-dismisses ~2 min) — **:2234-2236**;
- `installArgs` — **:2241-2260**; `remapInstallTimeout` — **:2261-2280**;
- `throwOnInstallFailure` (the exit-code contract 0/10/12/13/14/17/1) — **:2281-2345**;
- `installWindowsSandbox` — **:2346-2386**; `installWindowsSandboxAsync` —
  **:2387-2422** (both: install → `checkWindowsSandboxStatus` → profile grant);
- profile-grant skip logic: `WINDOWS_SERVICE_ACCOUNT_SIDS` — **:2423**;
  `windowsProfileGrantSkipReason` — **:2434-2464**; `installProfileGrantSkip` —
  **:2465**; `windowsProfileGrantNotice` — **:2477-2489**;
  `installProfileGrantOptions` — **:2490**; `throwInstallProfileGrantFailure` —
  **:2507-2541** ("the sandbox *is* installed, the grant is not");
- `uninstallWindowsSandbox` — **:2542-2619** (timeout = install + grant budgets
  unless `--keep-user`, :2571-2575).

### 1k. Path expansion + ranking (~270 lines)
- `expandWindowsFsPaths` — **:2620-2682** (globs expanded point-in-time at
  initialize, not per exec; missing literal **dropped for grant, passed through
  for deny** so `srt-win` can materialize a placeholder chain, :2666-2676; UNC
  literals pass raw with no stat probe, :2645-2649);
- `isUnprobedWindowsPath` — **:2683**; `ResolvedWindowsPath` — **:2688**;
  `isAbsentError` — **:2699**; `resolveWindowsPath` (`fs.realpathSync.native`) —
  **:2708-2726**; `windowsPathKey`/`windowsPathKeyOf` — **:2727**, **:2732-2745**;
  `coveringWindowsPath` — **:2746**; `windowsGrantsBeneathDenies` — **:2763-2784**;
- `WindowsFsAccessSet` — **:2785-2812**; `rankWindowsFsAccess` — **:2813-2871**
  (three ranks, see §4).

### 1l. Typed launch errors from `exec` stderr (~120 lines)
- `MappedDriveCwdError` — **:2872-2877**; `SeclogonDisabledError` — **:2878-2898**;
- `parseWindowsSandboxError` — **:2899-2909**; `parseSrtWinLaunchError` —
  **:2910-2986** (`profile_operation_in_progress`, `session_ended`,
  `mapped_drive_cwd` + `.drive`, `wfp_loopback_mismatch`, `seclogon_disabled` + `.state`).

### 1m. ACL operations (~380 lines)
- `stampWindowsAcl` (`acl stamp`, stdin JSON) — **:3016-3053**;
- `WindowsAclAceOutcome` — **:3054**; `WINDOWS_ACL_GRANT_RELEASED_STATUSES` —
  **:3063-3077**; `windowsAclGrantReleased` (`missing` counts only if the path is
  really gone) — **:3078-3096**;
- `restoreWindowsAcl` (`acl restore --json`, never throws) — **:3097-3144**;
- `WindowsAclGrantOptions` — **:3145-3162**; `allowProfileExclusionArgs` — **:3163**;
- `grantWindowsAcl` (`acl grant`) — **:3181-3211**;
- `grantWindowsAclPersistent` (`acl grant --persistent`, 600 s) — **:3212-3252**;
- `WindowsAclRevokeResult` — **:3253**; `revokeWindowsAclChecked` — **:3274-3311**;
  `windowsAclRevokeResult` — **:3312-3333**; `revokeWindowsAcl` — **:3334-3346**.

### 1n. Profile read grant (status / grant / forget / conflicts) (~800 lines)
- `WindowsProfileGrantState` — **:3347**; `WindowsProfileGrantPath` — **:3355**;
  `WindowsProfileGrantStatus` — **:3366-3417**; `RawProfileStatus` — **:3418-3459**;
- `WINDOWS_PROFILE_READ_ENV_VARS` (`NPM_CONFIG_USERCONFIG`, `GIT_CONFIG_GLOBAL`,
  `PIP_CONFIG_FILE`, `MAVEN_ARGS`, `RUSTUP_HOME`, `CARGO_HOME`) — **:3460-3472**;
- `WINDOWS_PROFILE_RECORD_VERSION = 1` — **:3473**; `stringList` — **:3475**;
  `profileStatusProblem` (a `current` grant with no exclusion list is *outdated*) —
  **:3484-3500**; `mapProfileStatus` — **:3501-3556**;
- `getWindowsProfileReadStatus` / `…Async` (`profile status [--paths]`, and
  `state:"in_progress"` → `profile_operation_in_progress`) — **:3557**, **:3575-3589**;
- `WindowsProfileGrantOptions` — **:3590**; `WindowsProfileGrantItem` — **:3614-3642**;
  `WindowsProfileGrantResult` — **:3643-3696**; `grantItems` — **:3697-3738**;
- `grantWindowsProfileRead` (streaming stderr progress lines, 30 min default) —
  **:3739-3805**; `profileGrantArgs` (`profile grant --json [--exclude …]
  [--replace-excludes]`) — **:3806-3812**; `profileGrantResult` — **:3813-3873**;
  `grantWindowsProfileReadSync` — **:3874-3892**;
- `forgetWindowsProfileRead` / `…Async` (`profile forget --json`) — **:3893**,
  **:3904-3916**; `profileForgetResult` — **:3917-3932**;
- `profilePathKey` — **:3933**; `WindowsProfileExclusionConflict` — **:3941-3964**;
  `exclusionComponentMatches` (`*` = one name, `x*` = prefix) — **:3965-3974**;
  `exclusionMatchedBeneath` — **:3975-4018**; `windowsProfileExclusionConflicts` —
  **:4019-4115** (~97, fails closed on a path it cannot list);
- `windowsProfileReadEnv` — **:4116-4133**.

### 1o. Wrap (~215 lines)
- `WINDOWS_LOOPBACK_NO_PROXY` — **:4143-4162**;
- `wrapCommandWithSandboxWindows` — **:4163-4303** (~157, see §4);
- `WINDOWS_PROXY_NAME_SPELLING` (must match `PROXY_NAME_SPELLING` in `launch.rs`) —
  **:4304-4319**; `mergeWindowsEnv` (case-folded merge, one spelling per name) —
  **:4320-4341**; `envListToObject` — **:4342-4360**.

### 1p. Dependency / readiness check (~250 lines)
- `windowsSetupVersionMismatch` — **:4361-4388**; `windowsInstallCommandLines` —
  **:4389**; `windowsInstallInstructions` — **:4400-4412**; `settle` — **:4413**;
- `interpretDependencyProbes` — **:4431-4561** (~131, shared by both variants so
  `errors[]` is byte-identical);
- `checkWindowsDependencies` — **:4562-4590**; `checkWindowsDependenciesAsync` —
  **:4591-4606** (two probes concurrently).

### 1q. What happens **before**, **around** and **after** spawning `srt-win`

**Before any spawn of a command** (`SandboxManager.initialize`,
`sandbox-manager.ts:1265-1500`):
1. `resolveSrtWin(runtimeConfig.windows?.srtWin)` — `:1267` (resolved once,
   captured module-level for wrap/reset).
2. `getWindowsSandboxUserStatusAsync` → `not_provisioned` if `!provisioned ||
   !credPresent` — `:1269-1280`.
3. `windowsSetupVersionMismatch` → `reinstall_required` — `:1282-1290`.
4. capability gate `missingWindowsSrtWinCapability(u.capabilities)` →
   `windowsSrtWinOutdatedError` — `:1299-1303` (asked once per binary identity,
   `windowsSrtWinIdentity` `:227-246`).
5. `getWindowsProfileReadStatusAsync` → `profile_grant_outdated` unless
   `none`/`current`; warnings surfaced — `:1305-1338`.
6. `ensurePersistentWindowsCa` when `tlsTerminate` without explicit paths — `:1356-1370`.
7. `computeWindowsFsAccessSet` + `windowsProfileExclusionConflicts` →
   `profile_exclusion_read_grant` — `:1384-1449`.
8. `grantWindowsAclPersistent` (one call, always: it also records this process as
   a session) — `:1454-1463`.
9. `verifyWindowsWfpEgress` under the session's write roots + loopback mode,
   once per (account, loopback mode) per process — `:1480-1497`, memo vars
   `windowsWfpVerifiedFor`/`…Loopback` `:214-217` (deliberately **not** cleared
   by `reset()`, `:3208`).

**Around the spawn** (per command): `wrapWithSandboxArgv` Windows branch
(`sandbox-manager.ts:2809-2970`) → `wrapCommandWithSandboxWindows`
(`windows-sandbox-utils.ts:4163`) builds `{argv, env}`; the caller **must** spawn
with `{shell:false}` and the returned `env` (`:4166-4171`; the CLI does exactly
that at `src/cli.ts:584-596`). Inside `srt-win exec`
(`vendor/srt-win-src/src/cli.rs:2739-3011`): credential+setup read first (exit 15,
`:2756-2772`), `seclogon_state()` check (`:2775-2786`), write-restricted-token /
persistent-grant refusal (exit 20, `:2786-2800`), `share_lock_current_exe`
(self-protect the broker binary, `:2806-2822`), `require_allow_loopback` (exit 19,
`:2829-2838`), session watch `--held-by` (`:2839-2846`), per-exec deny stamps
(`:2856-2905`), `install_broker_dacl` (`:2921-2923`), then
`logon::spawn_runner` (`:2953-2970`) → `runner` → `launch::run_lockdown`
(restricted token, job, non-interactive desktop, mitigations, handle whitelist —
`runner.rs:1-19`, `token.rs`, `launch.rs`).

**After**: `drop(per_exec_guard)` releases the per-exec deny ACEs before
`process::exit` (`cli.rs:3007-3011`, `PerExecRestore` `cli.rs:1107`, `Drop` `:1113`); the child's
exit code is propagated (`cli.rs:3011`, `cli.rs:33-39`); at session end
`reset()` → `releaseWindowsSessionAcls` = `acl revoke --json` then, only if it
completed, `acl restore --json` (`sandbox-manager.ts:3191-3208`, `:482-510`);
kept (persistent) write roots and the denies under them are **not** released
(`:3189-3190`).

---

## 2. Every `srt-win` subcommand the TypeScript calls

CLI definition: `vendor/srt-win-src/src/cli.rs` — `enum Cmd` **:116**, arms in
`fn run` **:1304**. Dispatch keys on `argv[1] == "--srt-win"`
(`cli.rs:56`, stripped at `cli.rs:88-90`), because Windows cannot preserve a
spoofed `argv[0]` across `CreateProcessWithLogonW` / `ShellExecuteExW(runas)`.

| Subcommand | TS call site | Arguments actually passed | Elevation | Runs as |
|---|---|---|---|---|
| `install` | `installArgs` `windows-sandbox-utils.ts:2241-2260`, spawned `:2351`, `:2392` | `--sublayer-guid`, `--proxy-port-range lo-hi`, `--allow-loopback`, `--sandbox-user`, `--force` | **self-elevating** (`maybe_self_elevate` `cli.rs:1343` → `ShellExecuteExW(verb="runas")` `cli.rs:3268-3345`) | elevated child = Administrator; parent relays exit code |
| `uninstall` | `uninstallWindowsSandbox` `:2557-2576` | `--sublayer-guid`, `--keep-user` | **self-elevating** (`cli.rs:1625`); adds hidden `--elevated-step` itself (`cli.rs:1621-1622`, arg at `cli.rs:188`) | same |
| `status` | `checkWindowsSandboxStatus{,Async}` `:1323`, `:1335` | `--sublayer-guid` | none | broker (real user) |
| `wfp status` | `wfpStatusArgs` `:1097-1101` | `--sublayer-guid` | none (BFE enum is admin-gated → `state:"cannot-read"`, `wfp.rs:873-928`) | broker |
| `wfp verify` | `verifyWindowsWfpEgress` `:1707-1714` | `--target`, `--anonymous-egress` (optional), `--allow-loopback`, `--write-restricted-token`, `--write-root <each>` | none | broker spawns **`runner` as `srt-sandbox`** (`cli.rs:1885-1893`); with `--write-restricted-token` the probe runs as a lockdown child `srt-win probe egress` (`RunnerCmd::ProbeEgress` `cli.rs:1878-1884`) |
| `user status` | `getWindowsSandboxUserStatus{,Async}` `:1756`, `:1765` | — | none | broker |
| `user trust-ca <path>` | `windowsTrustCa{,Async}` `:1818`, `:1830` | positional PEM/DER path | none | broker; the **registry write is done by `runner` as `srt-sandbox`** (`install.rs:470-495` → `RunnerCmd::InstallCa`, `runner.rs:36-41` → `cert_store.rs`) |
| `acl stamp` | `stampWindowsAcl` `:3016-3053` | `--holder-pid`, `--sandbox-user-sid`, stdin `{denyRead,denyWrite}` | none | broker. **Exported for embedders; `SandboxManager` does not call it** (only `src/index.ts:81` re-exports it) — session denies go through `acl grant --persistent` and per-exec `--deny-*` |
| `acl grant` | `grantWindowsAcl` `:3181-3211` | `--holder-pid`, `--sandbox-user-sid`, `--allow-profile-exclusion <each>`, stdin `{read,write}` | none | broker. Also embedder-only |
| `acl grant --persistent` | `grantWindowsAclPersistent` `:3212-3252` | as above + `--persistent`, stdin `{read,write,denyRead,denyWrite}` | none | broker |
| `acl revoke --json` | `revokeWindowsAclChecked` `:3284-3291` | `--holder-pid`, `--sandbox-user-sid`, `--json` | none | broker |
| `acl restore --json` | `restoreWindowsAcl` `:3114-3121` | `--holder-pid`, `--sandbox-user-sid`, `--json` | none | broker |
| `profile status` | `getWindowsProfileReadStatus{,Async}` `:3560`, `:3578` | `--paths` (optional) | none | broker (as the profile's owner) |
| `profile grant --json` | `profileGrantArgs` `:3806-3812` | `--exclude <each>`, `--replace-excludes`, `--json` | none (refuses as a service account, exit 21, `cli.rs:2530-2537`) | the **calling real user whose profile it is** |
| `profile forget --json` | `forgetWindowsProfileRead{,Async}` `:3896`, `:3910` | `--json` | none | calling user |
| `exec` | `wrapCommandWithSandboxWindows` `:4227-4262` | `--quiet`, `--held-by <pid>`, `--write-restricted-token`, `--write-root <each>`, `--allow-loopback`, `--deny-read <each>`, `--deny-read-except <each>`, `--deny-write <each>`, `--env K=V <each>`, `--`, then `<shell exe> <flags> <command>` | none | broker (real user) → **child as `srt-sandbox`** |

Subcommands that exist but the TS layer never invokes: `acl forget`
(`cli.rs:670`, `AclCmd::Forget`), `acl recover` (`cli.rs:709`), `user read-cred`
(`cli.rs:539`), `wfp uninstall` (`cli.rs:1298`, self-elevating at `cli.rs:1978`),
and the hidden `runner` (`cli.rs:364`) / `probe connect|egress|token|parent-access`
(`cli.rs:370-412`) — those are `srt-win`'s own internal hops and CI hooks.

**Who runs as whom, in one line:** only `install`, `uninstall` and `wfp uninstall`
elevate (`cli.rs:1343`, `:1625`, `:1978`); everything else is an unelevated broker
that either answers from state (`status`, `user status`, `wfp status`,
`profile status`) or hops through `CreateProcessWithLogonW` into
`srt-sandbox` (`exec`, `wfp verify`, `user trust-ca`) — `logon.rs:1-30`,
`runner.rs:1-19`.

---

## 3. `windows-install` and its undo — what is provisioned, and where

CLI arm: `cli.rs:1318-1602`. TS entry: `installWindowsSandbox{,Async}`
(`windows-sandbox-utils.ts:2346`, `:2387`); CLI command `src/cli.ts:189-292`.

Order of the elevated install (all inside the one self-elevated child):

1. **Validate the port range before the UAC prompt** so a refused range doesn't
   cost a prompt — `cli.rs:1325-1337` (and it refuses a range that would cover
   `LOOPBACK_PROBE_PORT` when `--allow-loopback`, `cli.rs:1331-1337`).
2. **Self-elevate** — `cli.rs:1343-1345`.
3. **Idempotency / conflict pre-check** — `cli.rs:1347-1470`:
   newer setup marker → exit 13 (`install.rs:38-46`, `cli.rs:1349-1355`);
   different port range / loopback mode / sandbox-user name without `--force` →
   exit 13 (`cli.rs:1356-1390`); early-out only when the install is **complete**
   (user + group membership + current marker + filters installed + both records'
   loopback mode + credential decryptable + ambient stamps complete,
   `cli.rs:1391-1425`), and even then it **re-asserts the LSA logon denials**
   first (`cli.rs:1427-1441`, `user.rs:591-600`).
4. **Account + group** — `user::provision` (`cli.rs:1502`, `user.rs:109-137`):
   - local group `sandbox-runtime-users` (`user.rs:52`, created at `user.rs:110` via `sam::ensure_local_group`);
   - local user `srt-sandbox` (`user.rs:48`) via `NetUserAdd(level=1)` with a
     32-char CSPRNG password (`gen_password` `user.rs:209-263`, `ensure_user`
     `user.rs:283-360`), `UF_SCRIPT|UF_DONT_EXPIRE_PASSWD` (`user.rs:317`), retry ×5
     on policy rejection 2245 (`user.rs:320-325`, `:345-346`, `MAX_PW_ATTEMPTS`
     `user.rs:363`); an existing account the marker doesn't own is refused outright
     (`we_own_it` guard `user.rs:292-299`, set from the marker at `cli.rs:1493-1501`);
   - membership in **`BUILTIN\Users`** resolved from the well-known SID
     `S-1-5-32-545` so it works on localized Windows (`user.rs:96`, `:118-125`),
     and in `sandbox-runtime-users` (`user.rs:126`);
   - hidden from the logon picker: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList\<user> = 0`
     (`user.rs:92`, `set_logon_ui_hidden` `user.rs:433-465`);
   - **LSA logon-type denials on the group**: `SeDenyNetworkLogonRight`,
     `SeDenyBatchLogonRight`, `SeDenyServiceLogonRight`,
     `SeDenyRemoteInteractiveLogonRight` (`LOGON_DENIALS` `user.rs:518-523`, `apply_logon_denials`
     `user.rs:591-600`) — everything except interactive, which the launch needs.
5. **Machine state store** — `install::provision_machine_store` (`cli.rs:1506`,
   `install.rs:96-140`): `%ProgramData%\sandbox-runtime` taken with
   `SeTakeOwnershipPrivilege`+`SeRestorePrivilege` (`install.rs:104-105`), opened
   **no-follow** so a planted junction is deleted not followed (`install.rs:107-118`),
   owner set to Administrators (`install.rs:120`), DACL rewritten by handle:
   `D:P(D;OICI;FA;;;<sbGroup>)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;BU)`
   — sandbox group DENY, SYSTEM/Admins full, BUILTIN\Users modify (`install.rs:124-130`);
   legacy files swept (`install.rs:132-139`).
6. **Credential + setup marker in the registry** — `install::write_setup`
   (`cli.rs:1508`, `install.rs:152-200`): `HKLM\SOFTWARE\sandbox-runtime`
   (`reg.rs:51`) values `SandboxUser`, `SandboxUserSid`, `SandboxGroupSid`,
   `CreatedAt`, and **`MarkerVersion` written last as the commit point**
   (`install.rs:191-196`, `SETUP_VERSION = 3` `install.rs:24`); the DPAPI
   (machine-scope) password blob in the `Cred` subkey created with
   `O:BAD:P(D;;KA;;;<group>)(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;BU)` — Users read,
   sandbox group DENY (`install.rs:166-172`, `reg.rs:52`); the `Ca` subkey with
   Users `KEY_READ|KEY_SET_VALUE` (0x2001b) so unelevated `trust-ca` can record
   the DER, sandbox group DENY (`install.rs:175-181`, `reg.rs:53`); a `--force`
   re-install under a **different** name drops the recorded CA (`install.rs:159-165`, `:182-184`).
7. **Ambient write-denies** — `install::set_ambient_denies` (`cli.rs:1526`,
   `install.rs:246-292`): `(D;OICI;WriteDeny;;;<sb-SID>)` on the stock
   world-writable corners — `%ProgramData%`, `%PUBLIC%`, `%SystemRoot%\Temp`,
   `\Tasks`, `\tracing`, `\Registration\CRMLog`, `\System32\FxsTmp`,
   `\System32\com\dmp`, `\System32\spool\PRINTERS`,
   `\System32\spool\drivers\color` and the SysWOW64 twins (`ambient_deny_targets` `ambient.rs:40-60`);
   the applied list is recorded in HKLM `AmbientDenies` MULTI_SZ
   (`install.rs:288-290`) so every later ACL converge re-folds the deny
   (`ambient_deny_recorded` `install.rs:215-221`). All-fail → exit 17
   (`cli.rs:1546-1552`). Drive roots are deliberately **not** stamped
   (`ambient.rs:16-19`).
8. **WFP filters** — `mark_loopback_mode_changing` first so a half-done mode
   change reads as an error, not as "closed" (`cli.rs:1558-1563`,
   `install.rs:378-381`); then `wfp::install_filters` (`cli.rs:1565`,
   `wfp.rs:625-747`) in one transaction: persistent sublayer
   (`wfp.rs:638-655`), delete every stale `srt-win`-tagged filter including
   legacy group-keyed ones (`wfp.rs:660-666`, `delete_tagged_filters` `wfp.rs:526`,
   `for_each_tagged_filter` `wfp.rs:441`, `FilterTag` `wfp.rs:328-357`,
   kind names `wfp.rs:359-361`), then per ALE layer (`wfp.rs:426`):
   - `permit-loopback-user` PERMIT, loopback address ∩ proxy port range,
     `filter_specs` `wfp.rs:389-410`, added `wfp.rs:696-714`, weights `wfp.rs:421-422`);
   - `permit-loopback-open` PERMIT, loopback ∩ ports `2..65535` when
     `--allow-loopback` (`wfp.rs:109`, `:402-405`, `:715-727`);
   - `block-user` BLOCK keyed on `ALE_USER_ID` with SD
     `O:LSG:LSD:(A;;CC;;;<sb-SID>)(A;;CC;;;S-1-15-2-1)(A;;CC;;;S-1-15-2-2)`
     (`sddl_sandbox_user` `wfp.rs:613-615`, added `wfp.rs:728-741`), weight
     `W_BLOCK = 0x0F40…` — below the PERMIT so the proxy ports stay reachable
     (`wfp.rs:421-422`).
   Then `install::write_loopback_mode` records `<sublayerGuid>=open|closed` in
   HKLM `LoopbackModes` for the unelevated broker to consult
   (`cli.rs:1571-1574`, `install.rs:392-395`, `:341-345`).
9. Legacy group `sandbox-runtime-net` removed best-effort (`cli.rs:1581`).

**Not part of install:** the MITM CA. `install` never touches it
(`install.rs:466-469`; `cli.rs` `UserCmd::TrustCa` doc `cli.rs:541-547`).
`srt-win user trust-ca` writes the serialized cert element
(`CertSerializeCertificateStoreElement`, not raw DER) directly to
`HKEY_USERS\<sb-SID>\Software\Microsoft\SystemCertificates\Root\Certificates\<thumb>`
with value `Blob` — a raw registry write that bypasses crypt32's protected-root
consent dialog, which would hang the runner on a non-interactive desktop
(`cert_store.rs:1-40`), and only then records the DER in the `Ca` key
(`install.rs:470-495`).

**Undo** — `srt-win uninstall` (`cli.rs:1603-1722`): refuses beside a live
session (`exit_unless_quiet` → exit 22, `cli.rs:1611-1616`, `:1417-1440`);
elevated step removes the filters (`remove_fence` `cli.rs:1012-1020`,
`wfp::uninstall_filters` `wfp.rs:749-790`, which also clears the recorded
loopback line); removes the ambient denies **before** deprovisioning so the SID
still resolves (`cli.rs:1666-1680`, `install.rs:295-330`); `user::deprovision`
(`cli.rs:1704`, `user.rs:142-173`) — LSA denials removed (`remove_logon_denials`
`user.rs:601`), `DeleteProfileW` for the sandbox user's profile (this is what kills
the installed CA, `user.rs:160`), `NetUserDel`, group deleted, Winlogon hide value deleted;
`install::clear_setup` deletes the whole HKLM tree (or keeps `AmbientDenies`
entries that failed to clear, `install.rs:499-521`); then, in the *unelevated*
caller's process, `forget_grants_after_removal` forgets that user's profile read
grant and kept write grants (`cli.rs:1716-1721`, `:1451-1500`), returning exit 23
if anything stays recorded (`EXIT_GRANTS_NOT_FORGOTTEN` `cli.rs:1445`).
`--keep-user` keeps the account, credential, marker **and its ambient floor**
(`cli.rs:1644-1652`, `:1653-1660`).

**Persisted state, in one list:**
- `HKLM\SOFTWARE\sandbox-runtime` — `SandboxUser`, `SandboxUserSid`,
  `SandboxGroupSid`, `CreatedAt`, `MarkerVersion`, `LoopbackModes`,
  `AmbientDenies` (`reg.rs:51`, `install.rs:186-196`, `:288-290`, `:341-345`);
- `HKLM\SOFTWARE\sandbox-runtime\Cred\Blob` — DPAPI machine blob (`install.rs:166-173`);
- `HKLM\SOFTWARE\sandbox-runtime\Ca\Der` (`install.rs:175-184`, `:446-456`);
- `HKCU\Software\sandbox-runtime\PersistentGrants` — `Roots`, `EverEnabled`,
  `Pending`, `GroupSid`, `PreviousGroupSids` (`persist.rs:64-68`);
- `HKLM\…\Winlogon\SpecialAccounts\UserList\<user>` (`user.rs:92`);
- LSA account-rights entries for the group SID (`user.rs:525-600`);
- the local SAM account + group and the sandbox user's profile hive
  (incl. `CurrentUser\Root\Certificates\<thumb>`) (`user.rs:109-137`, `cert_store.rs`);
- `%ProgramData%\sandbox-runtime` (ACL'd) + `ca\ca.json|cert.pem|key.pem`
  (`install.rs:96-130`, `windows-sandbox-utils.ts:1864-1870`, `:1990-2129`);
- `%LOCALAPPDATA%\sandbox-runtime\state.db` — brokers/holders/`working_aces`/
  profile-grant records (`state_db.rs:7-17`, `:77`, `:94`; machine store
  `machine_store_dir` `:837-849`);
- WFP persistent filters (`add_filter` `wfp.rs:549-610`) + persistent sublayer (`wfp.rs:638-655`).

---

## 4. How sandbox traffic reaches the proxies, and how FS settings become ACLs / a plan

### 4a. Network path

1. The fence **blocks** every connect whose token matches the sandbox SID's SD at
   `ALE_AUTH_CONNECT_V4/V6` (`wfp.rs:613`, `:728-741`) — i.e. before any packet
   leaves, so an active fence yields `WSAEACCES` immediately
   (`windows-sandbox-utils.ts:1655-1663`, `probe.rs:864-890`).
2. It **permits** loopback destinations inside the proxy port range
   (`permit-loopback-user`, `wfp.rs:696-714`, conditions
   `loopback_permit_conditions` `wfp.rs:299-320`: remote address `127.0.0.0/8` (v4) /
   `::1` (v6) AND remote port in range).
3. The JS proxies therefore **bind inside that range**: `portRange` is passed to
   `startMuxProxyServer` only on Windows (`sandbox-manager.ts:1516-1522`), the
   HTTP backend is bound first inside the range (`:1060`, `:1069-1074`) and the
   mux front-end binds in-range excluding the backend port (`:1076-1084`).
   Default `[60080,60089]` (`windows-sandbox-utils.ts:204`, `wfp.rs:93`; schema
   cap width ≤ 64 `sandbox-config.ts:1101-1105`, `wfp.rs:99`).
4. The child is told where they are by env only: `wrapCommandWithSandboxWindows`
   calls `generateProxyEnvVars` (`windows-sandbox-utils.ts:4178-4189`,
   `sandbox-utils.ts:772-880`) → `HTTP(S)_PROXY`, lowercase twins, `ALL_PROXY`,
   `SANDBOX_RUNTIME=1`, CA-trust vars (`CA_TRUST_VARS`), with the per-command
   attribution key and the session token embedded in the URL userinfo
   (`sandbox-utils.ts:789-792`, `:840-851`).
   Windows-specific adjustments: `TMPDIR` deleted (`:4191-4193`), **`NO_PROXY`/
   `no_proxy` deleted** because a NO_PROXY match would make clients bypass the
   proxy and hit the fence (`:4194-4205`), and `no_proxy=localhost,127.0.0.1,::1`
   re-added **only** when loopback is open and a proxy exists
   (`:4206-4209`, `WINDOWS_LOOPBACK_NO_PROXY` `:4143`).
5. Those pairs are passed as repeated `--env K=V` (`:4222-4225`); the broker does
   **not** forward its own environment — the runner starts from the sandbox
   user's `LOGON_WITH_PROFILE` profile env and overlays exactly `--env`
   (`cli.rs:306-312`, `logon.rs:17-24`, `runner.rs` `build_env_block`).
   `mergeWindowsEnv` folds names case-insensitively and forces one spelling per
   proxy var (`:4304-4341`) to match `PROXY_NAME_SPELLING` in `launch.rs`.
6. The proxy itself runs as the **real user**, so its own connects are not
   fenced — that is the whole design ("the proxy connects on the child's behalf,
   from the broker's SID", `windows-sandbox-utils.ts:4200-4204`).
7. TLS trust: env vars cover OpenSSL-backed clients; Schannel/.NET/Go clients
   trust via the registry write in the sandbox user's `CurrentUser\Root`
   (`windows-sandbox-utils.ts:624-640`, `cert_store.rs:1-40`). The CA bundle path
   is emitted with **forward slashes** so msys2 doesn't mangle it
   (`:4172-4177`). The CRL CDP URL is Windows-only
   (`sandbox-manager.ts:1552-1563`).
8. With `--allow-loopback` the fence permits all loopback except port 1, which
   exists only so the fence can prove itself (`wfp.rs:104`, `:109`,
   `probe.rs:857-862`, `windows-sandbox-utils.ts:213-232`).

### 4b. Filesystem settings → ACEs

Pipeline: `filesystem.{allowRead,allowWrite,denyRead,denyWrite}` +
`credentials.files` → `computeWindowsFsAccessSet` (`sandbox-manager.ts:2076-2101`)
→ `expandWindowsFsPaths` (glob expansion, `windows-sandbox-utils.ts:2620`) →
`rankWindowsFsAccess` (`:2813-2871`) → one `acl grant --persistent` call
(`:3212`) → `cli.rs:2066-2233` → `canonicalize_ace_targets` (`cli.rs:805-975`) →
`persist::apply` / `db.apply_aces*` → `acl::persistent_aces`
(`acl.rs:1491-1524`) / `acl::apply_sandbox_aces` (`acl.rs:1170-1254`).

The ranks (`rankWindowsFsAccess`, `windows-sandbox-utils.ts:2813-2871`):
- `allowRead` **beats** a `denyRead` above it, because an explicit ACE on an
  object is evaluated before inherited ones — so a grant further down wins;
- `denyWrite` **beats** `allowWrite`: a write grant at/below a write deny is
  downgraded to a **read** grant (`:2838-2846`, `:2856-2862`);
- `credentials.files` deny **beats** both allow lists: such a grant is dropped
  entirely (`:2839-2845`).

ACE shapes (`acl.rs`):
- grant read → `(A;OICI;READ_EXEC;;;<sb-SID>)` (`GrantMask::ReadOnly`
  `acl.rs:953`, mask `Mask::FILE_READ_EXEC` `acl.rs:109`, applied `acl.rs:995`);
  grant write → `MODIFY_NO_FDC` — deliberately **without** `FILE_DELETE_CHILD` so a
  denied file inside a granted tree can't be deleted through the parent
  (`acl.rs:117-126`, applied `acl.rs:996`);
- `denyRead` → `(D;OICI;FILE_ALL;;;<sb>)` (`DenyMask::ReadDeny` `acl.rs:961`, applied `acl.rs:1001-1008`);
- `denyWrite` → `FILE_GENERIC_WRITE|DELETE|WRITE_ATTRIBUTES` minus
  `SYNCHRONIZE`/`READ_CONTROL` (denying SYNCHRONIZE would block *any* synchronous
  open, i.e. reads too) (`acl.rs:1011-1017`);
- plus `(D;OICI;FILE_DELETE_CHILD;;;<sb>)` on the **parent** of every denied
  target (`SbAce::DenyFdc` `acl.rs:981`), because the sandbox user is a
  `BUILTIN\Users` member and would otherwise inherit `Users:(F)` there;
- plus `(D;;DELETE;;;<sb>)`, object-only, on a **placeholder intermediate**
  directory created for a deny of a path that doesn't exist
  (`SbAce::DenyDelete` `acl.rs:989`; chain creation `cli.rs:852-880`,
  `path_id::create_placeholder_chain`) — a full `(OI)(CI)` deny there would leak
  over the subtree if the placeholder later becomes a real directory;
- globs are **rejected** by `srt-win` (`CanonError::Glob` `cli.rs:846-851`,
  `acl.rs:31`), which is why the TS expands them first;
- missing **UNC** deny targets are dropped rather than materialized
  (`cli.rs:853-860`);
- everything is refcounted per holder PID in `state.db`'s `working_aces`
  (`state_db.rs:77`, `working_aces` table `state_db.rs:94`, `acl.rs:18-22`), and the install-time ambient denies are folded
  into every converge so a session can't strip them (`ambient.rs:9-13`,
  `install.rs:215-221`, `:287-289`).

**Mandatory denies:** Linux has `linuxGetMandatoryDenyPaths` /
`mandatoryDenySearchDepth` (`sandbox-manager.ts:2249-2250`, `:2747`); **Windows
has no equivalent** — there is no such call in `windows-sandbox-utils.ts` or in
`vendor/srt-win-src`. The Windows floor is instead (a) the install-time ambient
write-denies (`ambient.rs`), (b) the placeholder-chain denies for missing
targets, and (c) the `WRITE_RESTRICTED` token (§4c). `filesystem.disabled` on
Windows means *no grants and no stamps except a masked file's*
(`sandbox-manager.ts:2085-2093`).

**Write roots and the restricted token:** `allowWrite` roots are granted
`--persistent`, each getting its own **capability SID**
`S-1-0-1936880739-<4×u32>` (`capability_sid_from` `persist.rs:30-56`,
`capability_sids_for` `:985`) and ACEs for the sandbox **group**
plus that SID, never for the sandbox user SID — the user SID is a restricting SID
of every session, so an allow for it would pass both checks
(`acl.rs:1491-1516`, `persist.rs:1-9`). `exec --write-restricted-token` puts
`[capabilitySids…, sbUserSID, Everyone, RESTRICTED]` in the child token's
restricting list (`token.rs:93-106`), which is what lets the child write those
roots and only those; without the flag, `exec` is refused (exit 20) while any
kept grant or profile read grant exists (`cli.rs:2786-2800`,
`persist::unrestricted_block_reason`).

### 4c. The profile read grant (`profile_plan.rs` + `profile.rs`)

This is the one place a **read** grant is made for the whole user profile, and it
is opt-in (`cli.rs:269-279`, `windows-sandbox-utils.ts:3739`).

- `profile_plan.rs` is the pure half: what is never readable and which directory
  gets which entry (`profile_plan.rs:1-10`).
- `LIST_VERSION = 3` — a recorded grant made with another list is `outdated`
  (`profile_plan.rs:15`).
- Built-in exclusions `BUILT_IN` — `profile_plan.rs:102-245` (~140 entries):
  `.ssh`, `.gnupg`, `.aws`, `.azure`, `.kube`, `.docker`, `.terraform.d`,
  `.wrangler`, `.vercel`, `.netlify`, `.claude` (`:103-114`); XDG `.config\…`
  variants (`:116-121`); CLI token stores (`gcloud`, `GitHub CLI`, `gnupg`,
  `doctl`, `op`, `hub`, `.gem\credentials`, `.pulumi\credentials.json`,
  `pgpass.conf`, `Composer\auth.json`, `.fly\config.yml`, `.databrickscfg`,
  `.boto`, `.s3cfg`, `kaggle`, `snowsql`, `.oci`, `.bluemix`, `.ibmcloud`,
  `.railway`, `.supabase`, `:123-158`); package-feed token caches
  `.IdentityService`, `MicrosoftCredentialProvider` (`:160-163`); credential
  files `.git-credentials`, `.netrc`, `.pypirc`, `.vault-token`, `.terraformrc`,
  `.cargo\credentials[.toml]`, gradle key properties (`:165-177`); the registry
  hives `NTUSER.DAT*`, `ntuser.ini`, `UsrClass.dat*` (`:179-184`); browser
  profiles incl. channel variants and `*\EBWebView` (`:186-212`); password
  managers (`:214-219`); Windows' own per-user secret stores
  `Microsoft\{Credentials,Protect,Vault,Crypto,SystemCertificates}`,
  `IdentityCache`, `TokenBroker`, `OneAuth`, `INetCookies/Cache`, `WebCache`
  (`:221-236`); `Packages` (`:238`); this library's own state dir (`:240`);
  and the one **ungranted-only** entry `AppData\Local\Temp`
  (`profile_plan.rs:244`, `ungranted()` `:86-98`).
- `READABLE_ROOT_FILES = [".npmrc", ".gitconfig"]` and `READABLE_CONFIG`
  (npm/git/pip/NuGet/Maven/Gradle) are readable **by design** even though they
  can hold a feed sign-in (`profile_plan.rs:247-267`).
- The walk rule: a directory is a **container** (non-inheriting list/traverse
  entry, children granted one by one) exactly when an exclusion *could* lie
  beneath it; otherwise it is granted whole with one inheriting entry — so no
  excluded path ever has an ancestor carrying an inheriting allow
  (`profile_plan.rs:5-9`, `Kind` `:864-905`, `Node` `:906-920`,
  `plan` `:940-944`, link resolution loop `plan_resolved` `:946-1006`,
  `MAX_LINK_ROUNDS = 8` `:936`).
- What each kind writes is decided in `acl::persistent_aces`
  (`acl.rs:1491-1540`): `Container` → `DIR_LIST` for the group, no inheritance;
  `Granted` → `READ_EXEC (OICI)`; `File` → `READ_EXEC` object-only; `Denied` →
  read **deny** for the group, written before the first allow (`cli.rs:417-427`).
- Trustee is the **sandbox group** SID, not the user (`profile.rs:1-4`,
  `profile.rs:1840-1842`).
- Deny expansion: a session `denyRead` is also written on every **recorded
  allow path of the grant** beneath it, except ones the session allows more
  specifically (`RecordedAllows` `profile_plan.rs:1193`, `covered` `:1219-1237`; used at
  `cli.rs:820-822` and `cli.rs:2130-2145`; capability name
  `profile-deny-expansion` + `read-deny-except`,
  `windows-sandbox-utils.ts:1151-1186`).
- Session grants are checked against the exclusions on every `acl grant`
  (`profile::check_session_grants` `cli.rs:2114-2122`,
  `profile_plan::session_grant_refusal` `profile_plan.rs:614-683`) and again in
  TS before anything is granted (`windowsProfileExclusionConflicts`
  `windows-sandbox-utils.ts:4019-4115`, called `sandbox-manager.ts:1388-1449`).
- `env` pointers an embedder may set (`NPM_CONFIG_USERCONFIG`,
  `GIT_CONFIG_GLOBAL`, `PIP_CONFIG_FILE`, `MAVEN_ARGS`, `RUSTUP_HOME`,
  `CARGO_HOME`) — `profile.rs:2617-2642`, `windows-sandbox-utils.ts:3460-3472`,
  `windowsProfileReadEnv` `:4116-4133` (the library sets none itself).
- The grant runs only while **no sandbox session or command is live**
  (`with_profile_lock` + `exit_unless_quiet` → exit 24, `cli.rs:2551-2556`,
  `:1417-1440`), refuses as a service account (exit 21, `cli.rs:2528-2537`), and
  requires this build's setup marker (exit 15, `cli.rs:2540-2544`).

---

## 5. Settings keys: honoured / ignored / refused on Windows, and the pre-command checks

### Honoured
| Key | Where |
|---|---|
| `network.allowedDomains`, `deniedDomains`, `strictAllowlist`, `filterRequest`, `allowPlaintextHeaderSet`, `requireHostMatch`, `refuseOpaqueTunnels`, … | proxy-side, identical on every platform (`sandbox-manager.ts:967-1058`, `filterNetworkRequest`) — read per request, so `updateConfig` swaps them live (`:2999-3005`) |
| `network.allowLocalBinding` | honoured **only as a match against the install**: `exec` launches nothing on a mismatch (exit 19, `cli.rs:2829-2838`), `wfp verify` refuses (exit 19 = `probe::EXIT_LOOPBACK_MISMATCH`, `probe.rs:241`, raised `cli.rs:1819-1832`), `initialize` refuses (`windows-sandbox-utils.ts:1536-1547`, `sandbox-manager.ts:1185-1191`), and a mid-session change is refused at wrap (`sandbox-manager.ts:2911-2922`, message `windowsLoopbackModeChanged` `:2178-2209`) |
| `network.tlsTerminate` (+ `extraCaCertPaths`, `maxTunnels`, `handshakeTimeoutMs`, `excludeDomains`) | honoured; with no explicit `caCertPath`/`caKeyPath` the **persistent CA** is used (`sandbox-manager.ts:1165-1171`, `:1356-1370`, `windows-sandbox-utils.ts:1955`) |
| `filesystem.allowRead` | `(A;OICI;READ_EXEC)` for the sandbox SID (`sandbox-manager.ts:2095-2100`, `acl.rs:953`) |
| `filesystem.allowWrite` | persistent root + capability SID + `MODIFY_NO_FDC` (`sandbox-manager.ts:1454-1463`, `persist.rs`, `acl.rs:1505-1512`) |
| `filesystem.denyRead` / `denyWrite` | DENY ACEs + parent-FDC DENY + placeholder chains (`windows-sandbox-utils.ts:2620-2682`, `acl.rs:961-1017`) |
| `filesystem.disabled` | drops every FS rule, credential file denies included, masked files still denied (`sandbox-manager.ts:2085-2093`, `:2846-2860`) |
| `credentials.envVars` `mode:'deny'` | **structurally absent**: the child starts from the sandbox user's fresh profile env, so an `env -u` scrub is moot (`windows-sandbox-utils.ts:549-560`, `:4232-4241`, `logon.rs:17-24`) |
| `credentials.envVars` `mode:'mask'` | sentinels passed via `--env`, applied *before* the proxy vars so masking `HTTPS_PROXY` can't break the plumbing (`windows-sandbox-utils.ts:549-560`, `:4232-4241`) |
| `credentials.files` `mode:'deny'` | unioned into `denyRead` (`sandbox-manager.ts:2098-2100`) |
| `credentials.files` `mode:'mask'` | becomes a **read deny** — an ACL cannot redirect a read, so a masked file is simply unreadable (`windowsMaskedFileDenies` `sandbox-manager.ts:2104-2115`) |
| `git.safeDirectories` | `GIT_CONFIG_*` `safe.directory` + `GIT_SSL_CAINFO`, OpenSSL backend (`windows-sandbox-utils.ts:4192-4200`, `buildGitConfigEnv`) |
| `windows.sandboxUser`, `windows.sublayerGuid` (+ deprecated `wfpSublayerGuid`, resolved at read sites `sandbox-manager.ts:1284-1285`, `:1670-1672`), `windows.proxyPortRange`, `windows.srtWin.path` | `sandbox-config.ts:1073-1122`; `srtWin.path` is **required** — no ambient vendor fallback (`windows-sandbox-utils.ts:781-798`) |
| `ripgrep`, `ignoreViolations` | Linux/macOS monitors only (`sandbox-manager.ts:1198-1250`, `:1646`); on Windows violations come from the proxy with the per-command attribution key (`:646-650`) |

### Ignored silently on Windows (accepted by the schema, never reaches the wrapper)
`network.allowUnixSockets`, `network.allowAllUnixSockets`,
`network.allowMachLookup`, `enableWeakerNetworkIsolation`, `allowAppleEvents`,
`allowPty` (macOS-only: passed only in the `case 'macos'` arm
`sandbox-manager.ts:2702-2712`); `enableWeakerNestedSandbox`,
`allowNestedUserNamespaces`, `mandatoryDenySearchDepth`, `seccomp`, `bwrapPath`,
`socatPath`, `ripgrep` (Linux-only arm `:2735-2755`). The Windows arm
(`:2809-2970`) simply never reads them. `network.mitmProxy` is a **Unix socket
path** used by the host-side proxy (`sandbox-manager.ts:906-920`) — nothing in
the Windows path supports or rejects it.

### Refused (hard error) on Windows
- per-call `filesystem.allowRead` / `allowWrite` at wrap time — `srt-win exec`
  exposes only per-exec **denies** (`sandbox-manager.ts:2850-2857`);
- a session grant that is, contains, or lies above a profile-read-grant
  exclusion → `profile_exclusion_read_grant` (`sandbox-manager.ts:1388-1449`);
- an `srt-win` that doesn't report a required capability → `srt_win_outdated`
  (`sandbox-manager.ts:248-257`, `windows-sandbox-utils.ts:1202-1215`);
- an install made by another release's setup version → `reinstall_required`
  (`sandbox-manager.ts:1282-1290`, `windows-sandbox-utils.ts:4361-4388`,
  `install.rs:24-46`);
- loopback mode mismatch in either direction → `wfp_loopback_mismatch`;
- `binShell` object form on macOS/Linux, and any unrecognized `binShell` string
  (`sandbox-manager.ts:2972-2976`, `windows-sandbox-utils.ts:444-526`);
- an argv that would exceed `CreateProcessW`'s 32 767-char command line →
  `argv_too_long` (`windows-sandbox-utils.ts:4271-4290`);
- a deny glob whose trailing separator makes it inert → schema rejection,
  Windows-aware (`sandbox-config.ts:1141-1176`).

### Dependency / install checks that run before a command on Windows
1. `checkDependenciesAsync()` (called `sandbox-manager.ts:1176`, defined `:1715-1726`) →
   `checkDependenciesCommon` Windows branch (`:1658-1680`) →
   `checkWindowsDependencies{,Async}` (`windows-sandbox-utils.ts:4562`, `:4591`) →
   `interpretDependencyProbes` (`:4431-4561`), which checks, in order:
   binary present (`resolveSrtWin`), `srt-win user status` →
   provisioned + credential readable (`:4461-4471`), setup-version match
   (`:4473-4478`), **Secondary Logon service** usable — `disabled`/`missing` is
   an error, `cannot-read` is not (`:4482-4491`, `logon::seclogon_state`),
   `srt-win wfp status` — `cannot-read` is informational (BFE enum is
   admin-gated), `loopback-mismatch` and `absent` are errors (`:4496-4521`), and
   the installed loopback mode vs the configured one (`:4527-4549`).
2. The Windows block in `initialize()` (`sandbox-manager.ts:1265-1500`) — see §1q.
3. Per wrap: `assertWindowsSrtWinCapable` (`sandbox-manager.ts:2904-2909`,
   definition `:248-257`) and the loopback-mode check (`:2911-2922`).
4. Per `exec`, inside `srt-win` (`cli.rs:2739-3011`): credential + setup marker
   (exit 15), `seclogon_state` (exit 18), persistent-grant/profile-grant block
   without `--write-restricted-token` (exit 20), recorded loopback mode
   (exit 19), `--write-root` capability SID lookup (`persist::capability_sids_for`,
   `cli.rs:2788`), `self_protect::share_lock_current_exe`
   (`cli.rs:2806-2822`), per-exec deny stamping (fails the exec if any path
   can't be stamped, `cli.rs:2884-2905`).

---

## 6. `src/cli.ts` — how `windows-install` is routed, and the rest of the Windows CLI surface

- `program.command('windows-install')` — **`src/cli.ts:189-292`**. Options:
  `--sublayer-guid` (:199), `--proxy-port-range <lo-hi>` (:200-203),
  `--allow-loopback` (:204-208), `--sandbox-user <name>` (:209-212),
  `--force` (:213), `--profile-exclude <path>` repeatable (:214-220),
  `--skip-profile-grant` (:221-229). Action (:231-291): dynamic import of
  `installWindowsSandboxAsync`, `resolveSrtWin`, `VENDORED_SRT_WIN_EXE`,
  `WINDOWS_ALLOW_LOOPBACK_EFFECT` (:232-238); parses the range (:239-242);
  calls the install with `srtWin: resolveSrtWin({path: VENDORED_SRT_WIN_EXE})`
  — the CLI opts into the packaged exe **explicitly**, there is no ambient
  fallback (:253-255); prints the grant notice/progress to stderr (:249-251);
  UAC cancel → exit 2 (:257-262); prints user SID, WFP state+filters+range, and
  the profile-grant outcome (:263-286), appending
  `WINDOWS_ALLOW_LOOPBACK_EFFECT` when loopback is open (:283-285).
- `program.command('windows-uninstall')` — **`src/cli.ts:294-317`**,
  `--sublayer-guid` only; cancel → exit 2 (:307-311).
- There is **no** `srt-win` passthrough command, no `windows-status`, no
  `windows-trust-ca`, no `profile-grant` CLI: those are library-only
  (`src/index.ts:59-106` exports `installWindowsSandbox`,
  `uninstallWindowsSandbox`, `grantWindowsProfileRead`,
  `forgetWindowsProfileRead`, `windowsTrustCa`, `stampWindowsAcl`,
  `grantWindowsAcl`, `checkWindowsSandboxStatus`, `verifyWindowsWfpEgress`,
  `windowsStateDir`, `VENDORED_SRT_WIN_EXE`, …), checked by
  `test/public-exports.test.ts:40-100`.
- The default `run` command's Windows-only behaviour:
  - injects `windows.srtWin.path = VENDORED_SRT_WIN_EXE` when the user's config
    doesn't set it — **`src/cli.ts:405-423`**;
  - spawns the wrapped result as `spawn(argv[0], argv.slice(1), {shell:false,
    stdio:'inherit', env})` instead of the shell-string path —
    **`src/cli.ts:579-606`** (with the note that the control fd has no slot to
    displace, :588-592);
  - `SandboxManager.cleanupAfterCommand()` on child exit (:611-613) is a no-op
    for Windows (bwrap mount-point cleanup).
- `proxy` subcommand (`src/cli.ts:319-329`) and `--control-fd`
  (`src/cli.ts:344-349`) are cross-platform; the control-fd *spawn* difference is
  Windows-specific as above.

---

## 7. What shep-kelpie expects of srt (and what that means for Windows)

### `crates/adapters/src/adapters/srt/mod.rs` (451 lines)
- It shells out to **`node <tools>/node_modules/@anthropic-ai/sandbox-runtime/dist/cli.js --settings <file> -- <program> <args…>`**
  (`mod.rs:60-70`; paths from `crates/process/src/tools/mod.rs:52-54`,
  `:128-132`), pinning **srt 0.0.81** (`crates/process/src/tools/package.json:6`).
- It writes a settings JSON built by `settings_on(policy, macos)`
  (`mod.rs:91-141`) and passes the command's cwd and env through (`mod.rs:71-79`).
- **There is no Windows branch at all.** The only platform flag is
  `macos: cfg!(target_os = "macos")` (`mod.rs:20`, `:26-29`), and
  `settings_on` gates `open`, `scratch` and `socket_folders` on macOS alone
  (`mod.rs:88-90`, `:112-124`). On a non-macOS host it emits:
  `network.allowedDomains/deniedDomains/strictAllowlist` (:96-100),
  `deniedResolvedAddresses` (:101-103), `mitmProxy{socketPath,domains}`
  (:104-109), `allowUnixSockets` (:110-113), `allowLocalBinding: true` when
  `policy.listen` (:114-116), `allowMachLookup` (:117-119),
  `filesystem.{denyRead,allowRead,allowWrite,denyWrite}` (:129-135),
  `enableWeakerNetworkIsolation` (:136).
  Consequences on Windows: `allowMachLookup` and `enableWeakerNetworkIsolation`
  are inert (§5); `allowUnixSockets` is inert; `allowLocalBinding: true` is
  **not** inert — it must match a `srt-win install --allow-loopback` or every
  command is refused with `wfp_loopback_mismatch`
  (`sandbox-manager.ts:2911-2922`); `mitmProxy.socketPath` is a Unix socket path
  (§5); and nothing in the adapter sets `windows.srtWin.path`, which upstream
  **requires** (`windows-sandbox-utils.ts:781-798`) — the CLI injects the vendored
  exe for its own run (`src/cli.ts:405-423`), so a kelpie call would work only
  through that CLI default, and only after `npx sandbox-runtime windows-install`
  has been run once by an admin.
- macOS-only patching expectations: the keychain-blocked copy of the runtime
  (`mod.rs:47-58`, `tools/mod.rs:56-76`, patching
  `dist/sandbox/macos-sandbox-utils.js`, `tools/mod.rs:130-132`) — no analogue
  on Windows; `SandboxError::Unpatched` is only reachable when `no_keychain` is
  set on macOS (`mod.rs:47-57`, test `there_is_no_keychain_to_block_off_macos`
  `mod.rs:399-416`).
- It asserts srt does **not** get `allowNestedUserNamespaces` on either platform
  (`mod.rs:186-196`), and pins the Linux/macOS split for sockets
  (`mod.rs:300-330`), `open`/`scratch` glob handling (`mod.rs:215-241`), and the
  exact argv shape (`mod.rs:419-450`).

### `docs/facts/worker-profile-and-sandbox.md` (144 lines)
Everything measured is on **macOS** (e.g. `:57`, `:88`, `:128`) or **Linux**
(`:112-118`). Windows appears only twice, incidentally: a Windows path spelling
in the private-path matcher (`:69`) and `productionresultssa*.blob.core.windows.net`
as a domain-pattern case (`:109`). Expectations that bear on a Windows port:
- "Sandboxes do not nest" — `srt` under `srt` cannot start
  (`:58`, `:139`); on Windows the analogue would be the WFP fence + separate
  account, not a nested profile.
- `allowUnixSockets` is macOS-only; the seccomp filter kills `AF_UNIX` on Linux
  (`:114`) — Windows has neither, so kelpie's `sockets`/`socket_folders` policy
  (`mod.rs:110-113`) has no Windows meaning.
- `denyWrite` beats `allowWrite` (`:16`) — on Windows this is
  `rankWindowsFsAccess`'s write-deny-over-write-grant rank, which **downgrades**
  such a grant to read rather than carving it out
  (`windows-sandbox-utils.ts:2838-2846`).
- deny globs hold inside allow-opened folders (`:100-107`) — Windows honours
  this too, but only because globs are expanded point-in-time at `initialize()`
  (`windows-sandbox-utils.ts:2620-2682`); a path created *after* initialize is
  not covered, the same gap kelpie notes for Linux (`:113`).
- `srt` hands every process `GIT_CONFIG_PARAMETERS='http.proxyAuthMethod=basic'`
  (`:120-123`) — emitted by `generateProxyEnvVars` (`sandbox-utils.ts:846-851`)
  and re-emitted on Windows through `GIT_CONFIG_*` (`windows-sandbox-utils.ts:4192-4200`).
- `TMPDIR` must not be set for srt on macOS (`:63-66`); on Windows
  `wrapCommandWithSandboxWindows` **deletes** `TMPDIR` from the generated set
  (`:4191-4193`) because it breaks msys2 tools, and the child gets the sandbox
  user's own `%TEMP%` from the fresh profile logon (`logon.rs:17-24`) — so
  kelpie's "writable temp folder" story (`:129-133`) has a different mechanism
  on Windows and the profile `Temp` is deliberately **ungranted-only**
  (`profile_plan.rs:242-244`), i.e. neither granted nor denied, so a session may
  grant its own directory inside it.
- `allowNestedUserNamespaces` stays off (`:118`) — irrelevant on Windows, which
  has no namespace mechanism.

Net: kelpie's adapter and facts doc assume macOS/Linux. A Windows port needs, at
minimum: an admin-run `windows-install` (with `--allow-loopback` if
`policy.listen`), `windows.srtWin.path` in the settings file (or reliance on the
CLI's vendored-exe injection), a decision on `allowLocalBinding` being
install-pinned rather than per-call, and a replacement for the Unix-socket and
`mitmProxy.socketPath` mechanisms.
