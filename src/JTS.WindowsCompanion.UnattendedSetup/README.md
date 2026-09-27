# Optional unattended first-install window

This is the managed Windows x64 UI behind the separate 2.5 native bootstrap,
calling the unattended installation library. It is not the existing 2.0 current-user installer, an updater, a repair
tool or an uninstaller. Its executable manifest requests Windows administrator
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

The relay field starts empty, with no official domain or IP default. Enter an
explicit HTTPS root origin. Outer TLS certificate PKI checks are skipped by default;
inner device-pinned mutual TLS remains mandatory. Review and
acknowledge the two dedicated standard accounts, the automatic Authority service,
the on-demand Worker, and the independent pairing/capability/MCP authorization.
Click **Install**; the library then shows a final confirmation defaulting to No.
The separate [owner-delegated CLI](../../docs/RELAY_ENDPOINT_INSTALLATION.md)
imports a SHA-256-pinned public request from the AI-enabled Mac target without
another pairing prompt. UAC and payload verification remain. No automatic
installation on window load, upgrade, repair or transaction replay is supported.

During the transaction the inputs, close button and window close action are
disabled. There is no global process-kill or mid-transaction cancellation button.
The library's synchronous native launch is entered on the UI thread so its brief
process-window-station switch cannot race WinForms window creation; subsequent
asynchronous process/service waits return to the message pump. OS shutdown or
forced termination can still interrupt a process: the durable transaction record
must be reviewed locally, not deleted or replayed. A completed first install
reports only local SCM startup, with public device and enrollment identifiers;
it does not claim relay connectivity, pairing, remote access or acceptance.

UI errors are selected only from complete fixed codes. Unknown errors get a fixed
safe message; exception messages, nested errors, local paths and secrets are not
shown or logged. Only pre-transaction declined confirmation or rejected origin
permits another click. Other outcomes require local review or closing Setup.

## Development package status and open gates

The 2026-09-19 package-attempt-5 evidence (historical local evidence, not included)
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
