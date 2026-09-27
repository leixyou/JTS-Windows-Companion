# Optional unattended first installation (2.5 development)

This .NET 10 library composes the first-install transaction for Windows x64.
It is consumed by the new managed setup UI behind a native bootstrap; the
[developer-only packaging route](../../packaging/README.md) has been cross-built
and inspected, not executed or accepted on Windows. Neither this library nor
that development candidate is an installed/released Companion.
The old 2.0 installer, accounts and state are not replaced. The independent relay
does not reference this module and cannot invoke its installation entry point.

## Entry point and consent

`WindowsUnattendedInstaller.InstallWithConsentAsync(bundleDirectory, relayOrigin,
cancellationToken)` requires an interactive, already-elevated, non-SYSTEM Windows
x64 caller. It verifies the payload, then displays a local Yes/No confirmation
with **No as the default**, explaining the dedicated accounts, service roles and
selected relay. The caller must have completed Windows elevation; this library
does not bypass UAC or supply a silent/replayed approval switch.

The relay is an explicit HTTPS root origin without credentials, path, query or
fragment. Configuration does not trust a self-signed certificate automatically.
Installation approves neither a remote device nor a capability or MCP client;
those remain separate approvals. Success returns enrollment ID, device ID and
relay origin after observing local SCM Running, not proof of pairing, relay
connectivity or a completed remote task.

## Payload, accounts and initialization

The bundle must contain an embedded-key-verifiable **schema-2** project release
manifest covering four managed single-file EXEs: the three installation roles
below and `JTS.WindowsCompanion.UnattendedSetup.exe`. It also authenticates the
adjacent native DLL inventory; the current candidate contains `e_sqlite3.dll`.
The installed program directory receives these three EXEs plus the authenticated
DLLs and manifest, **not the setup UI**:

- `JTS.WindowsCompanion.AuthorityService.exe`
- `JTS.WindowsCompanion.WorkerRunner.exe`
- `JTS.WindowsCompanion.AuthorityProvisioner.exe`

Source handles remain open during copying, destination files are created without
overwrite and their hashes are rechecked. An adjacent key override, extra script,
unknown executable role or DLL absent from the authenticated inventory is not
accepted as the installation payload. Authenticode is optional; project manifest
verification is mandatory. Native/content self-extraction is disabled: the native
bootstrap verifies and stages the required files before managed startup. The
destination is an enrollment-
specific protected Program Files directory, not a mutable `current` link.

Two new local standard accounts receive separate cryptographically generated
passwords held in disposable native buffers. Passwords are not passed through
argv, the provisioning intent, receipt or logs. Account creation never adopts an
existing name. Later operations require the exact SID, enrollment marker and
role receipt. The account policy grants service logon and denies interactive,
RDP, network and batch logon; it grants no administrator membership. Denying
network logon is not a restriction on the account's outbound network access.

The authority initializer uses service logon, a restricted exact-account token,
an explicitly loaded user profile and a private noninteractive desktop. Its
suspended process is atomically attached to a kill-on-close Job Object and
verified before resuming. The fixed command carries only the enrollment UUID.
CurrentUser DPAPI initialization occurs under the authority account, never the
installer account. The Worker does not receive the authority's identity/state.

See the [initializer contract](../JTS.WindowsCompanion.AuthorityProvisioner/README.md)
and [service registration contract](Services/README.md) for the separate roles.

## Transaction and failure boundaries

1. Validate protected roots and take the exclusive installer lease. Refuse an
   existing live installation, journal, pending journal update or target path.
2. Write the enrollment-bound journal; record intent before each external step
   and persist each created account's SID receipt before proceeding.
3. Create protected programs and an isolated provisioning stage. The intent is
   installer-owned and authority-read-only. State access is limited to Authority,
   SYSTEM and Administrators, excluding Worker. Run the initializer and confirm
   process exit and profile unload.
4. Verify the `staged-not-enabled` receipt, account/enrollment bindings, public
   identity, timestamps and exact sizes/hashes of all four closed state files.
   Unexpected files, links, duplicate inventory and changed content fail.
5. Register only new, disabled services through their original creation handles.
   Revalidate the staged receipt, then create runtime configuration and move state
   to the live location without overwrite.
6. Persist activation intent before enabling either service. Set Worker to
   on-demand and Authority to automatic, then start Authority and observe SCM.

Journal writes use an exclusive pending file and a flushed replacement. A failed
or interrupted write is not silently discarded, and an existing journal is never
automatically resumed. These source-level safeguards are not power-loss or
reboot acceptance evidence.

Before activation, rollback is allowed only with confirmed in-process ownership
and confirmed helper termination. It removes only this transaction's stopped,
disabled service registrations and exact owned accounts. Created program/state
directories are retained under `.failed` / `.failed-live` names instead of being
recursively deleted; user profiles are not recursively removed.

Unknown account ownership, unconfirmed helper stop/profile unload, failed cleanup
or journal persistence requires local diagnosis. Once activation intent is
recorded, failure or cancellation preserves installed state and requires explicit
local repair: it never claims the service did not run or deletes a potentially
active identity. Disabling an account is not evidence that its processes stopped.

There is no automatic retry, recovery, upgrade, uninstall or credential rotation
workflow here. A failed/rolled-back journal is not silently reset for another
attempt. The separate native bootstrap and first-install UI now have a
development-only package; they do not add any recovery/upgrade/removal workflow
to this library and are not a distribution-ready installer.

## Focused verification and open gates

From the client repository root, with .NET SDK/runtime 10 available:

```sh
scripts/verify_companion_next.sh unattended-installation
```

`JTS_DOTNET` may select an absolute SDK executable. This performs locked restore
and only this module's tests; it does not install accounts/services or run the
2.0, macOS, real-server or release gates.

The earlier 2026-09-19 first-install API run recorded **70 passed, 0 failed, 0 skipped**. It covers
portable account/password contracts, journal ordering and failure injection,
ownership/activation preservation, receipt tampering and launch/environment
contracts, plus rejection of the public entry point off Windows. Receipt tests
use real temporary files and certificates but synthetic state-file contents;
they are not DPAPI/SQLite initialization or native installer evidence.

The later package-attempt-5 evidence (historical local evidence, not included)
adds cross-published binaries, a cross-built native bootstrap and static package
inspection, with an ephemeral development key. Its `nativeWindowsExecuted` value
is false: no native Windows installation was executed for either result. Required
acceptance still includes:

- Actual create-only directory ACLs, account rights, service descriptors and
  embedded-manifest deployment on Windows 11 and the separate Windows 10 ESU target.
- Profile loading/unloading and CurrentUser DPAPI identity reopening under SCM,
  including boot without an interactive user and failed-start/reboot recovery.
- Service-token elevation/Mandatory Integrity Control (MIC) behavior. The explicit
  startup reduction must pass the unchanged standard-account policy; lowering a
  primary token alone does not prove that process/token kernel-object labels
  permit the required cross-account supervision. No label or rights weakening is
  implied; see the [execution boundary](../JTS.WindowsCompanion.Execution/README.md).
- Real helper containment/drain and cancellation, exact-owned rollback, recovery
  after interrupted installation, and unchanged 2.0 coexistence.
- Windows/MSVC build and real execution of the packaged elevated setup, protected
  local pairing/consent/revocation/recovery,
  actual remote control, Mac integration and the remaining 2.5 release gates.

Portable passes close only this development scope, not P1/P2 or product release.
