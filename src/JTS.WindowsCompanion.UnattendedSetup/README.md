# Windows connection manager and first installation

This is the managed Windows x64 UI behind the separate 2.5 native bootstrap,
calling the unattended installation library and the authenticated local enrollment
management service. It is not the existing 2.0 current-user installer, an updater,
a repair tool or an uninstaller. Its executable manifest requests Windows administrator
approval. Authenticode remains optional; the build-embedded P-256 release key
and signed project release manifest are required.

For explicitly authorized native testing, launch the outer **native bootstrap**,
not this managed executable directly. There is currently only a developer package;
no released or Windows-accepted installer is claimed. See the
[packaging instructions and evidence](../../packaging/README.md).
The bootstrap embeds the release, obtains Windows administrator approval and
stages it in a fresh administrator-protected directory before starting this UI.
This managed UI supports an explicit owner-delegated installation command and is not distributed as a standalone
installer. Its protected directory contains all four final managed single-file
executables, the adjacent native DLL inventory and the authenticated inventory:

- `JTS.WindowsCompanion.UnattendedSetup.exe`
- `JTS.WindowsCompanion.AuthorityService.exe`
- `JTS.WindowsCompanion.WorkerRunner.exe`
- `JTS.WindowsCompanion.AuthorityProvisioner.exe`
- `e_sqlite3.dll`, the required adjacent native DLL in the current candidate
- `JTS.WindowsCompanion.release.json`, using schema 2 to sign every EXE and DLL

Build/publish Setup before producing that final manifest. Pass
`CompanionReleasePublicKeyPath` as a global build property so the Core reference
embeds the intended public key; no adjacent trust-key override is accepted.
Publish requires `win-x64`, self-contained managed single-file output. The current
Windows SDK host carries CoreCLR/JIT in the authenticated EXE; SQLite remains
adjacent. Neither native-library self-extraction nor content self-extraction is
allowed. The bootstrap authenticates and stages these files before elevated
managed startup; the installation library later copies the three authenticated
service/initializer EXEs and authenticated DLLs into protected Program Files
storage, excluding this UI executable. An installed
.NET runtime is not required on the target computer. This project adds no NuGet
package dependencies. Publish tooling must keep private signing keys out of the
distributable bundle.

Startup authenticates the actual process executable and retains read-only leases
on it and the adjacent manifest before displaying an install-enabled window.
The installation library separately authenticates and holds the other three
EXEs and authenticated native DLLs. An unsigned development build without a complete manifest cannot be
used to bypass these checks.

No arguments or `--manage` opens the same connection manager. Paste the one-use
code from an AI-enabled Mac device and select **Connect**. On a new computer,
strict code validation supplies the relay origin before any installation begins.
The local services install once, then the code is submitted to the Authority's
administrator-authenticated management pipe. Already-installed computers go
directly to that pipe. The setup process never writes the pairing database.

The code is masked and cleared after submission. The service persists the attempt
and resumes the exchange after interruption; closing this window does not cancel
it. Status refreshes every two seconds. **Cancel pairing** closes an unbound
attempt, and **Revoke access** removes a bound device. `pending`, `claimed`,
`committing`, `bound`, `revoking`, `revoked`, `cancelled`, `expired` and error
states remain distinct. No extra human pairing approval follows the Mac's
AI-control authorization. Windows UAC and signed payload verification remain.

Pairing and RDP are displayed separately. No RDP login is required to bind. RDP
failure does not consume an unbound, unexpired code, and it does not invalidate
an established binding. Bound credentials persist until revocation. This window
does not test RDP credentials or change RDP/NLA/firewall configuration.

**Install without pairing** accepts an explicit HTTPS root origin for installation
before a code is available. The field has no relay default. Outer TLS certificate
PKI checks are skipped by default; inner device-pinned mutual TLS is required.
The separate [public-request CLI](../../docs/RELAY_ENDPOINT_INSTALLATION.md)
remains supported for explicit first installation.

`--status` emits public status JSON and `rdpStatus:"notChecked"`. `--enroll-code`
reads one line of at most 4096 characters from standard input, never an argument
or a file. Use an already elevated interactive administrator shell so UAC does
not discard the redirected streams. Codes and arbitrary exception details are
never printed. The native parent passes only three duplicated standard handles.

During installation the close button and window close action are disabled. The
synchronous native launch runs on the UI thread so its brief window-station switch
cannot race WinForms window creation. A failed or interrupted transaction remains
for local review; the manager does not automatically delete, repair or rerun it.
An older service without the new management pipe reports unavailable and retains
all state. Updating that older service requires a separate migration workflow.
No action runs installation merely because the window was opened.

## Development package status and open gates

The [2026-09-19 package-attempt-5 evidence](../../../build/2.5-evidence/20260919-unattended-setup/package-attempt-5/packaging-evidence.json)
records four managed Windows x64 bundles, a native AMD64 bootstrap requesting
`requireAdministrator`, a verified Core public-key resource, the schema-2 manifest
and six matching bootstrap payload resources. The macOS-hosted cross-build and
content inspection passed; no Windows executable was run. The candidate is marked
`DEVELOPMENT-NOT-FOR-DISTRIBUTION`, uses an ephemeral development key and has no
Authenticode signature. Do not distribute it or embed it in the Mac app, and do
not disable Windows reputation checks or organization policy to launch it.

This build/content evidence does **not** establish real Windows UI/UAC, account,
profile/DPAPI, SCM, kernel-token, relay or restart acceptance. Those native gates,
including a Windows/MSVC build, Windows 11 and Windows 10 ESU, remain separate and must be recorded
against the exact published bundle. Upgrade, recovery and removal remain open
product work; the first-install UI never pretends to provide them.
