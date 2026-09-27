# Windows Companion current-user setup

JTS Terminal 2.0 ships its Windows Companion as one project-owned, current-user setup executable. The setup has no third-party installer runtime, opens no network listener, requests no administrator token, and writes no machine-wide service or firewall rule.

Authenticode is optional; administrator/UAC functionality is retained. Release
identity uses the project's P-256 manifest, not a purchased Windows certificate.
See [DISTRIBUTION_POLICY.md](DISTRIBUTION_POLICY.md) for the trust boundary and
the remaining real-Windows release gates. This document describes the implemented
source; it is not a claim that the package has completed runtime acceptance.

## Installed layout

The setup installs these release-verified files for the current Windows user:

```text
%LOCALAPPDATA%\Programs\JTS Terminal\Windows Companion\
  JTS.WindowsCompanion.Agent.exe
  JTS.WindowsCompanion.UacBroker.exe
  JTS.WindowsCompanion.Setup.exe
  JTS.WindowsCompanion.release.json
```

Mutable pairing and transfer state remains separate so repair and normal uninstall cannot silently replace or delete the paired identity:

```text
%LOCALAPPDATA%\JTSTerminal\WindowsCompanion\
  identity.v1.json
  paired-peer.v1.json
  Transfers\
```

Setup also keeps one empty coordination file beside the install directory:

```text
%LOCALAPPDATA%\Programs\JTS Terminal\.jts-windows-companion-setup.lock
```

The file contains no identifier, secret, or transaction data. Setup holds its handle exclusively across recovery, process shutdown, directory activation, HKCU changes, the committed Agent launch, and transaction cleanup so simultaneous local/RDP sessions cannot mutate one transaction. The path is intentionally stable and is not deleted during uninstall; deleting a held lock path could let another session lock a different replacement file. Setup releases the lease before waiting for the new Agent's DVC-readiness proof.

The installer registers only:

- an `HKCU` startup entry for the interactive Agent;
- an `HKCU` Add/Remove Programs entry with repair and uninstall commands; and
- two explicit writable roots, the current user's Documents and Desktop folders.

The Agent communicates through `JTS.Companion.v1` inside the existing RDP session. Setup does not install a Windows service, bind a TCP/UDP port, create a firewall exception, or make an inbound discovery surface.

## Security behavior

- Setup runs with `asInvoker`; installing the current-user Companion must not cause a UAC prompt.
- Setup verifies its embedded P-256 release manifest using the public key compiled into Core, then verifies the exact Agent/Broker hashes. Agent and Broker each validate themselves and their actual peer against their own authenticated inventory while holding file locks.
- Initial Setup provenance comes from its expected hash in the signed Mac app or another independently trusted release channel. Setup cannot include its own final hash in its embedded payload manifest; staged/detached copies retain locked byte-for-byte continuity with the running Setup. Optional Authenticode is additional evidence, not the default runtime gate.
- Setup verifies the complete staged Agent/Broker/Setup set before replacing anything and refuses reparse-point installation paths, payloads, transaction state, or recovery targets.
- Every Setup entry point takes the same per-user file lease across Windows sessions. A journal is created without overwrite, and every phase update or deletion must match the expected transaction ID and prior phase.
- Setup identifies running Agent/Broker processes before stopping any of them. Only an exact installed path owned by the current Windows SID is eligible; unrelated or other-user same-name processes are never terminated, and an elevated target that cannot be stopped fails before the installation changes.
- Install and repair replace the whole installed directory on the same volume. The previous directory and exact owned HKCU values remain recoverable until the new registration durably commits. Agent launch happens only after that commit; the committed journal retains the launch obligation until the process is started, so a forced termination before launch is replayed by the next Setup instead of exposing an uncommitted Agent.
- Normal uninstall uses the same recoverable directory and HKCU snapshot boundary; it discards the old binaries only after registration removal commits. An explicit `--purge-data` is recorded as a post-commit obligation before destructive state removal begins. If Setup is terminated during purge, the committed journal replays the idempotent state deletion before cleanup.
- A write-through transaction journal records only fixed Local AppData sibling paths, the prior owned registration values, operation type, prior Agent state, and post-commit Agent-launch/purge intent. A normal pre-commit exception rolls back immediately; an interrupted pre-commit process resumes rollback and restores the old Agent state before deleting the journal. The separate DPAPI pairing/state root is never rolled back.
- The installed Agent observes the same operation gate at startup and hashes its loaded installation image before and after waiting. An old Agent created during upgrade/uninstall exits if the on-disk image was replaced or removed; a new Agent cannot open the DVC until Setup releases the committed operation lease. Setup then accepts readiness only over a current-user-only named pipe whose client PID exactly matches the process it launched, after `WTSVirtualChannelOpenEx` succeeds.
- Before each new transaction, Setup removes only strict GUID-named orphan staging and journal-publish residue while it owns the operation lease and no journal exists. When repair is launched from the installed Setup, a locked, hash-identical temporary copy performs the internal operation after the installed executable exits. The parent schedules a bounded external cleanup helper before copying or launching the child and holds a non-shareable launch sentinel, so parent termination cannot make the helper delete early or leave the prepared root without a cleanup owner. A distribution Setup outside the install directory runs synchronously.
- The startup command exposes only Documents and Desktop through stable sandbox root IDs. Additional roots remain an explicit administrator/user configuration step.
- Current-user shell requests use `rootId=documents` or `rootId=desktop`; an exact `cwd="."` starts at that configured root after a fresh existence/reparse check. Nested `.`/`..` segments remain rejected, and file operations still require a descendant path.
- Normal uninstall preserves the DPAPI-protected Windows identity and paired Mac grant. `--purge-data` is an explicit destructive choice and removes that state after confirmation.
- The UAC broker remains a separate, release-verified executable. Its presence does not grant elevation: each elevated payload still requires visible consent, Windows UAC approval and a bounded lease. Windows may display an unknown publisher warning; JTS never suppresses it or imports a trust-root certificate.

The current-user package does not install the optional managed service. Shipping managed mode requires a separate administrator-approved, same-publisher service installer and its own ACL, upgrade, uninstall, and negative-access evidence.

## Release build

Run the build on a trusted Windows 10/11 x64 runner with .NET 8 SDK and the
protected project release private key outside the checkout/package:

```powershell
$env:JTS_RELEASE_PRIVATE_KEY_PATH = '<protected-external-project-P256-key.pem>'

.\scripts\build-current-user-setup.ps1
```

The script:

1. publishes self-contained, single-file `win-x64` Agent and UAC broker payloads;
2. embeds the same project public key into every executable;
3. signs a release manifest over the final Agent/Broker hashes;
4. embeds both payloads and that manifest into the self-contained Setup; and
5. emits the executable plus its SHA-256 record under `artifacts\current-user-setup`.

Private key bytes never enter MSBuild properties or packaged resources. For the
optional Authenticode profile, also supply both `JTS_SIGN_CERT_SHA1` and
`JTS_SIGN_TIMESTAMP_URL` and install the Windows SDK. That profile uses the
protected certificate store and fails on partial or unsuccessful signing; it
does not silently downgrade to unsigned.

For diagnostic builds only, `-AllowUnsignedDevelopmentBuild` generates a
temporary project key and writes a prominent marker. The matching diagnostic
manifest can satisfy the runtime trust gate; the package is still not a
distributable release artifact and the Mac embedding step rejects it.

## macOS app resource ingestion

The Windows release runner transfers the production Setup executable and its
sibling `.sha256` file to the authorized Mac release workspace without
committing either generated binary. The following Xcode build and Mac validation scripts run in the separate [JTS-Terminal-2.0 repository](https://github.com/leixyou/JTS-Terminal-2.0), not this Windows checkout. Supply those paths to the 2.0 Xcode build:

```bash
xcodebuild \
  -project JTSTerminal.xcodeproj \
  -scheme JTSTerminalRDP2 \
  -configuration Release \
  JTS_WINDOWS_COMPANION_INSTALLER_PATH=/absolute/path/JTS-Windows-Companion-2.0.0-win-x64.exe \
  JTS_WINDOWS_COMPANION_INSTALLER_SHA256_PATH=/absolute/path/JTS-Windows-Companion-2.0.0-win-x64.sha256 \
  archive
```

The `JTSTerminalRDP2` resource phase calls
`scripts/embed_windows_companion_installer.sh`. Release builds fail if the
external artifact is absent; Debug builds may omit it. The phase accepts only
one nonempty regular `.exe` smaller than 2 GiB and one small single-record
SHA-256 manifest naming that exact input. It rejects symbolic links, digest
mismatch, development/authorized-lab markers, and stale partial output, then
copies the verified pair into the app as:

```text
Contents/Resources/JTS-Windows-Companion-Setup.exe
Contents/Resources/JTS-Windows-Companion-Setup.sha256
```

`scripts/validate_rdp2_bundle.sh` re-verifies that fixed pair. This Mac-side
hash binding prevents accidental artifact substitution but does not validate
Authenticode. Production Windows evidence must bind the candidate, installed
images, project public-key identity and exact manifest to the intended release;
a diagnostic-key package cannot substitute for it.

In the macOS product, a stable `Companion missing` status offers installation
directly through the already connected RDP desktop. JTS Terminal temporarily
offers only the fixed Setup resource under a fresh strict internal Windows
basename, requires the RDP peer's streamed path-free clipboard capability,
opens `%TEMP%` through a short `Win+R` entry, requires both the resulting desktop
transition and a conservative cold-start readiness window, and sends `Ctrl+V`
over RDP to materialize the virtual clipboard file. A second short bounded Run
command opens PowerShell and applies the same readiness barrier before JTS
Terminal types the longer fixed verifier into that console. It checks exact
size and SHA-256 under a deny-write/delete handle held through launch/wait, Setup timeout,
forced timeout termination, exit status, and cleanup before waiting for the
real DVC pairing/ready state. This flow never asks the user to select an
executable or folder, does not depend on localized Explorer verb names, and
does not reuse a Windows staging basename from a previous attempt.

## Install, repair, and remove

Interactive install:

```powershell
.\JTS-Windows-Companion-2.0.0-win-x64.exe
```

Quiet install or repair:

```powershell
.\JTS-Windows-Companion-2.0.0-win-x64.exe --install --quiet
.\JTS-Windows-Companion-2.0.0-win-x64.exe --repair --quiet
```

Uninstall while retaining the paired identity:

```powershell
& "$env:LOCALAPPDATA\Programs\JTS Terminal\Windows Companion\JTS.WindowsCompanion.Setup.exe" --uninstall
```

Uninstall and explicitly purge identity, pairing, and transfer state:

```powershell
& "$env:LOCALAPPDATA\Programs\JTS Terminal\Windows Companion\JTS.WindowsCompanion.Setup.exe" --uninstall --purge-data
```

## Windows release evidence

Use [REAL_WINDOWS_QA_RUNBOOK.md](REAL_WINDOWS_QA_RUNBOOK.md) as the canonical
procedure. Timestamped runbooks under `build/release-evidence` are immutable
historical copies and must not be reused as current-source instructions.

Do not mark the Windows installer gate complete until a clean Windows 10 x64 VM and a clean Windows 11 x64 VM each record:

- Candidate and installed Agent/Broker/Setup SHA-256, exact manifest and embedded
  project-key identity, plus tampered-manifest/image and wrong-peer rejection.
  Authenticode/signtool evidence is additional only when that profile is selected.
- Setup launch without UAC and installation under the current user's Local AppData.
- Add/Remove Programs repair and uninstall behavior.
- First install, upgrade, repair, uninstall, and purge failpoint runs after every durable transaction phase, proving the exact old directory and HKCU values return before commit and post-commit launch/purge obligations resume after forced process termination.
- Confirmation that no mixed Agent/Broker/Setup version, `.setup-*`, `.journal-*.tmp`, `.backup-*`, temporary detached-Setup root/helper, or pending transaction journal remains after successful recovery or commit. The documented empty persistent lock file is expected and must contain zero bytes.
- Startup launch in the interactive user session, including PID-bound readiness only after the RDP DVC is open.
- DPAPI `CurrentUser` decryption of `identity.v1.json` and
  `paired-peer.v1.json` with the product entropy, stable encrypted-file hashes
  across Agent restart, repair, normal uninstall/reinstall, and failed
  decryption from a second standard Windows user. Plaintext is never retained.
- Pairing, RDP disconnect/reconnect, the full list/stat/read/write/upload/download
  file matrix, range integrity, traversal/reparse rejection, interrupted-transfer
  spool cleanup bound to the exact old/new session and transfer ID, same-channel
  file transfer resume, a bounded DVC trace, and fresh post-reconnect file I/O.
- Zero-skip Windows-interactive independent-child UI Automation TRX evidence
  plus public MCP semantic wait/set/invoke evidence against a separately
  launched, PID-bound process.
- Explicit UAC accept, Companion decline, UAC cancel/timeout, exact-payload
  success, changed-script/path/scope/timeout rejection, immediate lease release,
  Job Object cleanup, and the secure-desktop AI-input interlock with human input
  still available.
- Normal uninstall preserving pairing state, followed by reinstall and successful reconnect.
- Purge uninstall removing the state directory only after explicit confirmation.
- Stage-bound exact-image process snapshots confirming that no Agent/Broker/Setup
  TCP/UDP endpoint, firewall exception, machine service, or HKLM registration was
  added before, during, or after the runtime checks. Each endpoint record uses a
  monotonic stability window of at least 2,000 ms, repeated post-hash samples
  separated by bounded waits of up to 250 ms, and a separate terminal sample.
  It revalidates the exact PID, path, and process start identity after every
  sample; query failure, identity change, or endpoint-set drift invalidates the
  run. This is evidence only for the recorded bounded interval.
- A separate production-artifact pass on each OS, bound to the designated project
  key, source identity, manifest and per-role hashes recorded outside the QA
  candidate. Authorized-lab diagnostic keys never close this gate. If the
  optional Authenticode profile is selected, additionally require its intended
  publisher, timestamps and canonical Windows SDK verification evidence.

The macOS cross-build proves source compatibility only. It is not evidence for Windows Authenticode, DPAPI, WTS DVC, UI Automation, UAC, startup registration, or uninstall behavior.

## Owner-delegated device enrollment

A device with AI control enabled can provision its exact Mac identity through the explicit current-user Setup enrollment command. The request schema, atomic consent receipt, offline revoke command, and unchanged authenticated handshake are documented in [DELEGATED_ENROLLMENT.md](DELEGATED_ENROLLMENT.md).
