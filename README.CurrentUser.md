# JTS Windows Companion

This directory contains the Windows-side foundation for JTS Terminal 2.0. It is a .NET 8 current-user agent for Windows 10/11 x64. Its only remote transport to the Mac is the named `JTS.Companion.v1` RDP Dynamic Virtual Channel (DVC); elevation and optional managed mode use authenticated local named pipes. It does not open a TCP or UDP listener.

**Distribution decision, 2026-09-05:** Authenticode signing is now optional by
owner request, and administrator/UAC capability is retained. Setup and runtime
now authenticate exact release bytes through a project-owned P-256 manifest
whose public key is compiled into Core; no commercial certificate or installed
trusted-root certificate is required. This is not yet completed Windows release
acceptance. See [Distribution policy](docs/DISTRIBUTION_POLICY.md) for initial
installer provenance, operating-system warnings, and remaining gates.

## What is implemented

- A versioned DVC frame protocol with bounded payloads, monotonically increasing sequence numbers, incremental decoding, and SHA-256 payload-integrity prefixes.
- JSON request/response envelopes plus a disk-backed, hash-verified binary transfer coordinator with exact-offset resume and duplicate-chunk validation.
- A production WTS DVC adapter using `WTSVirtualChannelOpenEx`, `WTSVirtualChannelRead`, and `WTSVirtualChannelWrite`, with an in-memory transport used by tests.
- Mutual P-256 identity proof and explicit pairing. The Windows identity private key and the single approved Mac peer grant are protected for the current Windows user with DPAPI and are never logged.
- Windows UI Automation contracts and a Windows adapter for snapshots, selectors, Invoke, SetValue, Select, Wait, and bounded event subscriptions.
- Current-user PowerShell execution through standard input, with no elevation, bounded runtime/output, an explicitly sandboxed working directory, and a scrubbed environment.
- Sandboxed file list/stat/read/write operations with explicit roots, size/concurrency limits, hash validation, atomic replacement, and rejection of traversal, symbolic links, and reparse points.
- A concrete VRC Factory bridge for the existing fixed worker runtime. It accepts only `doctor`, `submit`, `status`, `cancel`, and `collect`, launches one installation-pinned `.exe` without a shell, rechecks its SHA-256 before every operation, and rejects extra request fields before process launch.
- Mutually verified P-256 VRC job/result envelopes bind both device identities, job ID, byte count, SHA-256, state, and issuance time. Swift and .NET share fixed canonical fixtures and reject wrong-key, tampered, expired, or extra-field envelopes before accepting or downloading result bytes.
- Authenticated exact-request and same-live-owner cancellation for deadline, disconnect, unpair, manual takeover, and Emergency Stop. Cancellation controls bypass the normal work limit, drain owned work, and do not terminate the Agent or discard an otherwise valid pairing.
- A single fail-fast sensitive-interaction barrier covers pairing confirmation, elevation consent, UI Automation, shell/file/worker mutation, and managed execution. Conflicting AI work receives `SENSITIVE_INTERACTION_ACTIVE` instead of queuing behind a human prompt; status, release, and cancellation paths stay available.
- A release-manifest-verified, one-session UAC broker path with a user-visible full-script/scope approval page, Windows `runas` consent, mutually authenticated local named-pipe IPC, and 15-minute maximum leases bound to one exact payload hash. Agent/Broker peers must match their own authenticated release inventory; locked files, PID checks, and nonces prevent a peer from substituting an unverified image. The current-user shell never becomes an administrator shell.
- An optional native Windows service host with a protected LocalSystem + configured-user pipe DACL. It loads only installation-pinned `WindowsTaskProviderManifest` operations, rechecks both the fixed handler hash and authenticated release inventory before every launch, and rejects arbitrary shell/PowerShell operations and argument fields. This separate managed deployment is not shipped by current-user Setup.
- Sanitized security events containing action type and result only, never scripts, typed values, paths, credentials, payloads, screenshots, or process output.

## Solution layout

- `JTS.WindowsCompanion.Core`: platform-neutral protocol, policy, file, shell, worker, elevation, release-manifest trust, and agent logic. Production publishing embeds only the designated release public key.
- `JTS.WindowsCompanion.Windows`: WTS DVC, DPAPI identity, and Windows UI Automation adapters.
- `JTS.WindowsCompanion.Installation`: setup argument parsing, cross-session operation leasing, path safety, crash-recoverable directory transactions, durable journal validation, exact-user installed-process control, registration-snapshot codecs, cleanup, and Windows command-line helpers with unit coverage.
- `JTS.WindowsCompanion.Agent`: the current-user executable and protocol method registration.
- `JTS.WindowsCompanion.UacBroker`: the one-lease interactive UAC broker, bound to exact Agent/Broker hashes in an authenticated release manifest.
- `JTS.WindowsCompanion.ManagedService`: the optional Session 0 service for installed, manifest-whitelisted task providers. It never performs UI Automation or desktop input.
- `JTS.WindowsCompanion.Setup`: the project-owned, transactional current-user installer for Agent, UAC broker, and their authenticated release manifest. It uses only HKCU and Local AppData and never creates a listener, firewall rule, or machine service.
- `JTS.WindowsCompanion.Tests`: protocol, replay, pairing, path boundary, file integrity, binary transfer, policy, worker, routing, in-memory transport, installer rollback, and interrupted-upgrade recovery tests.
- `JTS.WindowsCompanion.UiAutomationFixture`: a QA-only Win32 executable used as an independently launched UI Automation target. It is not part of the Companion package or any shipping artifact.
- `JTS.WindowsCompanion.ElevationQaRunner`: a QA-only executable published under the Agent peer name. Its schema-3 evidence and runtime require a diagnostic release ID beginning with `qa-elevation-`; it is not a shipping artifact. The PowerShell harness builds its own diagnostic peer pair and binds pre/post-run hashes; actual Windows execution remains required.
- `JTS.WindowsCompanion.ReleaseManifestTool`: an independent .NET publishing tool for protected project-key creation, public-key export, and release-manifest signing. It never prints or packages a private key.

## Build and test

Cross-platform core verification works on macOS and Windows:

```powershell
dotnet restore JTS.WindowsCompanion.sln
dotnet build JTS.WindowsCompanion.sln --configuration Release --no-restore
dotnet test JTS.WindowsCompanion.sln --configuration Release --no-restore
```

The checked-in [release test inventory](tests/JTS.WindowsCompanion.Tests/release-test-inventory.json)
defines current methods, declared cases, and named skip policies. macOS does not
execute Windows-integration, interactive-consent, or independent-process
interactive-UIA cases. A zero-skip Windows inventory still does not replace
separate actual-UAC, DVC, installation lifecycle, artifact-integrity, or Windows
10/11 runtime evidence.

The Release suite also covers exact elevation payload binding, framed broker IPC, lease expiry/release, managed-manifest loading, handler hash pinning, fail-closed shell rejection, whole-directory setup commit/rollback, durable phase recovery, two-step committed cleanup, replayable purge and Agent-launch intent, first-install and pre-journal residue cleanup, cross-process setup-lock exclusion, transaction-ID/phase validation, exact-user process-stop orchestration, Agent image gating, DVC-connected PID-bound readiness, pre-child detached-Setup cleanup ownership, registration-snapshot serialization, and pairing-state preservation. Windows-only Authenticode, HKCU restoration, native process handles, detached-Setup self-cleanup, current-user/PID pipe verification, DPAPI, DVC, UIA, UAC, and service integration tests remain gated to the Windows release runner. The two interactive Companion consent-dialog tests run only when `JTS_RUN_INTERACTIVE_CONSENT_TESTS=1` is explicitly set. The former `JTS_RUN_INTERACTIVE_UAC_TESTS=1` name remains a consent-only migration alias and is never accepted as real UAC evidence.

The UI Automation end-to-end test is skipped unless it runs on a Windows 10/11 interactive desktop outside Session 0 with `JTS_RUN_INTERACTIVE_UIA_TESTS=1`. The release solution builds a dedicated Win32 fixture executable; the test launches that executable as an independent child, binds every selector to its verified PID, verifies `Wait`, `Find`, `SetValue`, `Invoke`, and `Snapshot`, and requires a clean child exit.

The production UI Automation branch references Windows `UIAutomationClient` and is enabled only when built on Windows. Release artifacts must therefore be published on a Windows x64 runner; macOS cross-publishing intentionally compiles a fail-closed UIA adapter and is diagnostic only. Authenticode remains optional.

On Windows, the adapter and its consumers target `net8.0-windows`; the adapter's
`UseWPF` setting resolves UI Automation through the .NET Desktop framework and
includes its runtime dependencies during self-contained publishing. Do not
replace this with references to machine-specific .NET Framework DLLs. The
macOS build retains `net8.0` and the fail-closed adapter.

Real UAC evidence is a separate gate, not either consent-dialog TRX result. The
schema-3 QA runner authenticates its diagnostic manifest and exact Broker image
while locked, and exercises real `runas`, exact-payload execution, tamper
rejection, active expiry cancellation, and natural Broker exit. The
`-RequireInteractiveUAC` PowerShell orchestration now uses a separate temporary
key rather than a production certificate or installed production Broker. The
authorized-lab Setup matrix similarly uses a pinned diagnostic build snapshot;
neither installs a trusted root. Both need actual Windows runs. Old signed-run
results remain historical and are not relabeled as new-profile acceptance.

For normal current-user distribution, publish the self-contained Setup on a
Windows x64 release runner using a designated, externally protected project key:

```powershell
.\scripts\build-current-user-setup.ps1 `
  -ReleasePrivateKeyPath 'C:\JTS-Release-Secrets\companion-release-private.pem' `
  -ReleaseId '2.0.0'
```

The example path is a protected-key location, not a repository file or a key
already provisioned by this task. `JTS_RELEASE_PRIVATE_KEY_PATH` is the equivalent
publisher input. No production private key has been generated. The publisher
derives a public key, embeds it through `CompanionReleasePublicKeyPath` in every
executable, then signs the final Agent/Broker inventory and embeds it into Setup
through `ReleaseManifestPath`. The independent tool is available separately:

```powershell
dotnet run --project tools/JTS.WindowsCompanion.ReleaseManifestTool `
  --configuration Release -- --help
```

Its `keygen`, `public-key`, and `sign` commands require explicit new output paths.
Key provisioning is a separate deliberate release-management action, not an
automatic build side effect. `-AllowUnsignedDevelopmentBuild` uses a temporary
diagnostic key and marks its artifact `UNSIGNED-DEVELOPMENT`; that artifact must
not be renamed into a release or bundled in the Mac application.

Authenticode can be added by supplying both `-CertificateThumbprint` and
`-TimestampUrl`; partial or failed optional signing fails the build. The original
strict Authenticode verifier remains available for that additional policy.
Initial Setup authenticity comes from the exact installer hash carried inside
the Apple-signed Mac app, or another independently trusted release channel.
Setup cannot include its final hash in its own embedded manifest; staged and
detached copies instead compare their bytes with the locked running original.
An editable adjacent checksum is not independent proof of publisher identity.

See [CURRENT_USER_SETUP.md](docs/CURRENT_USER_SETUP.md) for installed paths and
repair/uninstall behavior, and [REAL_WINDOWS_QA_RUNBOOK.md](docs/REAL_WINDOWS_QA_RUNBOOK.md)
for lifecycle and real-machine evidence coverage. Earlier mandatory Authenticode
instructions in those documents or scripts are superseded by the distribution
policy, not by skipping integrity or Windows checks. Windows 10/11 acceptance
still requires the exact released artifacts, named Windows test cases, DPAPI
cross-user denial, DVC/no-listener traces, actual UAC and the Mac input interlock,
and tampered-manifest/image/impostor-peer rejection. Timestamped evidence copies
under `build/release-evidence` remain historical only.

The normal 2.0 current-user package intentionally does not install `JTS.WindowsCompanion.ManagedService`. Managed mode remains an optional, no-ship source path until a separate administrator-approved installer proves service identity, protected ACLs, transactional upgrade/removal, authenticated service/handler inventory, and the Windows 10/11 negative-access matrix.

## Running the current-user agent

The agent must run inside the interactive RDP user session. File and shell access are disabled unless the user provides one or more explicit roots:

```powershell
JTS.WindowsCompanion.Agent.exe `
  --root factory=D:\VRC_Factory `
  --read-only-root references=D:\VRC_References `
  --vrc-worker "C:\Program Files\JTS Terminal\VRC Factory\vrc-factory-worker.exe" `
  --vrc-worker-sha256 <64-hex-sha256> `
  --uac-broker "$env:LOCALAPPDATA\Programs\JTS Terminal\Windows Companion\JTS.WindowsCompanion.UacBroker.exe" `
  --managed-service-pipe "JTS.Terminal.Managed.v1"
```

The root ID, not an unrestricted Windows path, is used by protocol requests. PowerShell can run only in a directory under one of these roots and always as the current interactive user.

`--uac-broker` is optional for a manual launch and requires at least one configured root; normal Setup enables it. Agent and Broker require adjacent release manifests authenticated by their compiled key, and each verifies its actual peer against its own immutable inventory. `--managed-service-pipe` is optional and should be supplied only for a separately installed managed deployment; the Agent checks SCM/PID/path/LocalSystem/Session-0 identity and release-pinned service bytes before sending a request. Neither feature opens a TCP or UDP listener.

`--vrc-worker` and `--vrc-worker-sha256` are an installer/admin configuration pair; omitting both disables all `worker.*` methods with `WORKER_NOT_CONFIGURED`. The DVC request cannot supply an executable, subcommand, argument list, working directory, environment, or shell text. See [VRC_FACTORY_PROVIDER.md](docs/VRC_FACTORY_PROVIDER.md) for the exact contract and binary-transfer boundary.

## Protocol boundary

Each DVC frame begins with a 24-byte big-endian header:

| Offset | Size | Field |
| --- | ---: | --- |
| 0 | 4 | `JTSD` magic |
| 4 | 2 | protocol version |
| 6 | 1 | frame type |
| 7 | 1 | flags |
| 8 | 8 | sequence |
| 16 | 4 | payload length |
| 20 | 4 | first four bytes of SHA-256(payload) |

Control payloads are capped at 1 MiB and individual binary frames at 8 MiB. Production transfers use 4 MiB chunks, are capped at 512 MiB, and verify both each frame and the complete SHA-256 digest. `companion.hello` returns the Windows proof plus a fresh, random, single-use 32-byte client-authorization challenge that expires after two minutes. The Mac signs the domain-separated challenge payload with its P-256 identity and submits it to `companion.authorize`. First use requires a local Windows fingerprint-comparison dialog; later sessions accept only the exact stored device ID, public key, and SHA-256 fingerprint. Strict frame-sequence checking rejects replays for a live channel.

The Mac client identity is scoped to the saved RDP profile's stable target ID, while Windows persists exactly one approved Mac peer. The macOS setup surface therefore shows both fingerprints and enables **Unpair This Mac Client** only for the currently authenticated profile. Unpair blocks structured Companion access before sending the authenticated `companion.unpair` request, keeps the RDP profile and visible desktop, and requires a fresh fingerprint confirmation before that or another profile can pair. An uncertain response remains fail-closed until reconnect.

Every cancellable non-handshake control operation is owned by the verified peer public key plus the fresh live-session binding and runs with a linked deadline/disconnect cancellation token. `companion.cancel` targets one exact request ID; `companion.cancelPending` cancels and drains all other operations for the same live owner and is used by macOS manual takeover without discarding pairing. Both controls are frame-authenticated and bypass the normal 32-operation admission cap. Unknown, completed, old-session, and different-owner targets all return the same `REQUEST_NOT_ACTIVE` result. Disconnect and unpair cancel and drain owned work, while an individual cancellation or deadline returns `REQUEST_CANCELLED` or `DEADLINE_EXCEEDED` without stopping the Agent.

See [ELEVATION_AND_MANAGED_MODE.md](docs/ELEVATION_AND_MANAGED_MODE.md) for the exact consent payload, lease workflow, pipe ACL, service configuration/manifest format, installer requirements, and Windows verification matrix.

## Deliberate fail-closed boundaries

- The macOS/FreeRDP source bridge registers `JTS.Companion.v1`, forwards bounded DVC bytes through the XPC boundary, and reconnects the Swift Companion client. A real Windows 10/11 end-to-end DVC trace is still required before claiming runtime interoperability.
- Until the Mac client consumes `clientAuthorization` from `companion.hello` and completes `companion.authorize`, Windows permits only `companion.hello`, `companion.authorize`, and `companion.state`. Every structured control method and every inbound or outbound binary frame fails closed with `PAIRING_REQUIRED`.
- Without a configured UAC broker, elevation fails with `UAC_BROKER_REQUIRED`/`ELEVATION_LEASE_REQUIRED`. A missing or invalid release key, manifest, or executable hash fails closed; it never falls back to unverified or current-user execution while reporting elevated success.
- The managed service has no arbitrary administrator shell surface. `managed.execute` can reach only an installed provider/operation/argument/root combination accepted by its manifest. Service mode does not run UIA and cannot interact with the desktop in Session 0.
- Binary uploads and downloads are connected to a per-agent-session disk spool. Transfers are limited to 512 MiB, four concurrent entries, 4 MiB chunks, exact offsets, a 15-minute idle lifetime, and full SHA-256 verification. Session shutdown removes unfinished and unreleased transfer files. Inline file read/write remains capped at 512 KiB.
- The Mac MCP boundary keeps the existing VRC `bundleBase64` JSON contract for compatibility, but converts it to binary DVC frames before it reaches Windows. Production Windows-side submit/collect therefore no longer place the VRC ZIP in a 1 MiB control frame or process memory. A real Windows 10/11 DVC run is still required to validate disconnect/resume behavior against the WTS implementation.
- `companion.unpair` is available only to the currently authorized peer. It deletes the DPAPI-protected grant and immediately clears live authorization; a replacement Mac identity cannot silently overwrite the stored grant.
- Windows 10 and Windows 11 UIA, interactive Companion consent, DPAPI, DVC, actual UAC, service ACL, and manifest/image tamper checks require the real Windows integration matrix; macOS tests cover only platform-neutral behavior. Authenticode-specific checks remain applicable when that optional publishing policy is selected.
