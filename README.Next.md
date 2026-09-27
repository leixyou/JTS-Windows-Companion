# Companion Next development modules

`JTS.WindowsCompanion.Next.slnx` contains the endpoint Relay, Runtime, Pairing,
Control, Execution, WorkerIpc, WorkerService and UnattendedInstallation libraries,
one-shot WorkerRunner, AuthorityService and AuthorityProvisioner entry points,
the optional UnattendedSetup Windows UI and ten focused test projects: **22
projects, comprising 12 source projects and 10 test projects**. These are development foundations
for the planned 2.5 route, **not a delivered 2.5 Companion**. The existing
`JTS.WindowsCompanion.sln`, its .NET 8 targets and the installed 2.0 Agent/service
are unchanged. No relay server project or sibling-source reference is included.
The endpoint contract is the immutable [JTS Relay 1.0.0-alpha.1
snapshot](Protocols/JTSRelay/1.0.0-alpha.1/PROVENANCE.md), wire protocol 1;
its specification and public fixtures are data, not executable dependencies.

The September 27 endpoint implementation adds owner-delegated first-install
enrollment, file transfer and fixed-loopback RDP lanes to the existing Authority.
See [outbound installation and exact lane contracts](docs/RELAY_ENDPOINT_INSTALLATION.md).
Outer HTTPS/WSS stays encrypted but skips carrier PKI checks by default; inner
device-pinned mutual TLS remains mandatory. Windows native installation, unattended
boot, real PowerShell and real NLA/desktop acceptance still require the target.

## SDK and runtime requirements

- Open, list or restore the combined Next solution using **.NET SDK 10+**.
- Relay library/tests currently target **net8.0**. Their separate project can
  build with SDK 8+, and tests require a .NET 8 runtime visible to the selected
  `dotnet` host.
- Runtime, Pairing, Control, Execution, WorkerIpc, WorkerService, WorkerRunner, AuthorityService, AuthorityProvisioner and UnattendedInstallation target **net10.0** and require SDK 10+ and runtime 10.
- UnattendedSetup targets **net10.0-windows10.0.19041.0**, enables Windows
  targeting and publishes Windows x64 only. It can be cross-built, but its UI,
  elevation and installation behavior require real Windows acceptance.
- WorkerService additionally references the existing endpoint Core project
  (net8.0, no package dependencies) for its embedded-key release-manifest verifier.
  That does not add a relay-server dependency or change Core's target/runtime path.
- An isolated SDK 10 installation may contain only runtime 10. In that case use
  the .NET 8 `dotnet` host for Relay tests, or install runtime 8 in the selected
  host. The verification script never opts into major-version roll-forward.
- This entry point adds no shared `global.json`, so it does not force the old
  2.0 solution onto a new SDK. `JTS_DOTNET` selects the executable explicitly.

Each of the twenty-two new projects has a versioned `packages.lock.json`, including
transitive dependency hashes. Verification restores in locked mode and fails
when the declared dependency graph disagrees. For an intentional dependency
update, update the exact package reference, explicitly regenerate its lock file
with `dotnet restore --force-evaluate`, inspect the lock changes, then run the
affected scope. Do not regenerate locks automatically after a locked-mode error.
The opt-in packaging graph has separate [versioned Windows publish locks](packaging/next-locks/README.md)
and pins SDK 10.0.401 and runtime 10.0.12; it does not rewrite these ordinary
development locks or change the old 2.0 build settings.

## Focused local verification

From this repository root, choose one scope explicitly:

```sh
scripts/verify_companion_next.sh relay --list
JTS_DOTNET=/absolute/path/to/dotnet scripts/verify_companion_next.sh runtime --restore-only
JTS_DOTNET=/absolute/path/to/dotnet scripts/verify_companion_next.sh relay
JTS_DOTNET=/absolute/path/to/dotnet scripts/verify_companion_next.sh runtime
JTS_DOTNET=/absolute/path/to/dotnet scripts/verify_companion_next.sh pairing
JTS_DOTNET=/absolute/path/to/dotnet scripts/verify_companion_next.sh control
JTS_DOTNET=/absolute/path/to/dotnet scripts/verify_companion_next.sh execution
JTS_DOTNET=/absolute/path/to/dotnet scripts/verify_companion_next.sh worker-ipc
JTS_DOTNET=/absolute/path/to/dotnet scripts/verify_companion_next.sh worker-service
JTS_DOTNET=/absolute/path/to/dotnet scripts/verify_companion_next.sh authority-service
JTS_DOTNET=/absolute/path/to/dotnet scripts/verify_companion_next.sh authority-provisioner
JTS_DOTNET=/absolute/path/to/dotnet scripts/verify_companion_next.sh unattended-installation
```

`--list` is a project/requirements preview, not test discovery or acceptance.
`--restore-only` checks lock files without compiling or running tests. Omitting
the option performs a locked restore and the selected suite only. Missing scope
is an error; there is no `all` mode and no automatic old-suite, UI, installed
Windows, service provisioning, release or deployment action.

The Relay actual-server composition test remains opt-in through both
`JTS_RELAY_TEST_DOTNET` and `JTS_RELAY_TEST_SERVER_DLL`; without them it is skipped,
not counted as evidence of integration. Supplying them launches a temporary
loopback fixture, never a deployed node. See the [Relay contract and test
boundaries](src/JTS.WindowsCompanion.Relay/README.md) and [Runtime host contract
and remaining integration](src/JTS.WindowsCompanion.Runtime/README.md).
The [Control host](src/JTS.WindowsCompanion.Control/README.md) joins pinned TLS,
per-request grants and the durable runtime without requiring a desktop. Its
loopback tests still use inert test-only executors, not a production PowerShell
worker. A protected SQLite grant provider and durable-before-live revocation are
implemented; real Windows DPAPI/ACL ownership, consent UI, service/account and
policy recovery integration remain open. See [policy storage](src/JTS.WindowsCompanion.Control/POLICY_STORAGE.md).

The Control module now also provides `CompanionRelayControlService`: outbound
presence/offer acceptance, bounded deduplicated sessions, transient backoff,
pairing-bound grants and immediate owner-wide revocation. Its real loopback relay
integration passes task submit/disconnect/reconnect/query/cancel/output without
RDP, using a test-only executor and local approval fixture over the durable
pairing registry. This is not an installed Windows network service. The independent
[Pairing module](src/JTS.WindowsCompanion.Pairing/README.md) stores identity-bound,
protected pairing epochs and permanent revocation records. Its Control adapter
projects only Control grant IDs and rejects a different local device identity.
The [identity component](src/JTS.WindowsCompanion.Pairing/Identity/README.md) now
provides explicit Windows DPAPI CurrentUser provisioning/loading with exact
account/enrollment/device binding, restrictive file ACL checks and owned certificate
lifetime. Native Windows consent, DPAPI/account/ACL/key-store acceptance, service
acceptance, certificate renewal, native file/RDP operation and actual Windows public-route
acceptance remain open. Its native tests skip without an explicit Windows account/root.

The [Execution module](src/JTS.WindowsCompanion.Execution/README.md) implements
standard-account token checks, fixed PowerShell startup, atomic Job Object
containment and confirmed process-tree drain. Its native Windows tests are
explicitly skipped off Windows or without the dedicated-account opt-in. Portable
test passes do not close those gates. Do not compose it into the account owning
the policy database. The separate [WorkerIpc adapter](src/JTS.WindowsCompanion.WorkerIpc/README.md)
now provides bounded one-task dispatch, exact Windows process/pipe identity checks
and independent authority-owned process supervision. Its portable tests do not
verify Windows ACLs/native APIs. The [WorkerService module](src/JTS.WindowsCompanion.WorkerService/README.md)
now implements the fixed, manifest-verified SCM launcher, policy checks and one-shot
service host. WorkerRunner accepts `--service`; it is not an installed product.
The first-install library now has a developer-only native-bootstrap/UI package
route, described below; that package is not native Windows acceptance.
Builds without an embedded release key cannot
launch a Worker through this path.

The [AuthorityService entry point](src/JTS.WindowsCompanion.AuthorityService/README.md)
now composes protected identity/pairing/grant/job state, outbound Control and the
separate supervised Worker under SCM. It never provisions missing state or enables
the route implicitly. Lifecycle checks cover expiry stop, cancellation, failures
and drain-before-resource-release using portable adapters. Actual Windows service
installation/boot, native tokens/ACLs and local consent/recovery IPC remain open;
a successful build is not an installed service.

The separate [AuthorityProvisioner](src/JTS.WindowsCompanion.AuthorityProvisioner/README.md)
now prepares first-time identity and empty policy/job stores under the authority
account, using an installer-owned time-bounded intent and isolated protected stage.
It reopens/verifies state before producing a staged-only receipt; it cannot publish
live state, authorize peers, enable a route or install/start services. Failed stages
are retained, not reset. Portable storage/failure checks are not native Windows
profile/DPAPI/ACL or complete transactional-installer acceptance.

The [UnattendedInstallation library](src/JTS.WindowsCompanion.UnattendedInstallation/README.md)
now joins visible local consent, create-only dedicated accounts, explicit profile
initialization, receipt verification, disabled service registration and protected
publication. Activation intent is durable before any service is enabled; uncertain
ownership/helper stop or post-activation failure preserves state for local repair.
Only confirmed-owned, never-activated resources may be rolled back. This remains
a first-install API, not an upgrade/uninstall/recovery workflow or proof of
Windows service operation. SCM startup now explicitly reduces
an otherwise policy-valid service token to Medium and rechecks it; elevation,
groups and privilege checks are not relaxed. Native token/process-object labels,
profile/DPAPI, SCM and cross-account supervision remain real-Windows gates.

## Developer-only first-install package

The [packaging route](packaging/README.md) builds a native elevated bootstrap plus
the [UnattendedSetup UI](src/JTS.WindowsCompanion.UnattendedSetup/README.md).
The bootstrap stages authenticated payload bytes in a new administrator-protected
directory before managed startup. The UI accepts an explicit relay origin and
requires a user click followed by the installation library's default-No local
confirmation. The owner-delegated CLI imports an existing device AI-control authorization; it does not add another pairing approval. Normal Windows UAC still applies.

The schema-2 project release manifest covers four EXEs and, in the current
candidate, `e_sqlite3.dll`. The service installation copies only the three service/
initializer EXEs and authenticated DLLs; it excludes the setup UI. The managed
bundles disable native/content self-extraction, compression, trimming and
ReadyToRun. Authenticode remains optional; embedded-key project manifest
verification is required.

The 2026-09-19 package evidence (historical local evidence, not included)
records successful Windows x64 cross-publication, native bootstrap cross-build,
bundle/Core-key-resource checks and verification of all six embedded resources
(five signed payload files plus the manifest). This is explicitly
`DEVELOPMENT-NOT-FOR-DISTRIBUTION`, with an ephemeral key and
`nativeWindowsExecuted: false`. No Windows executable was run. Do not distribute
this candidate or embed it in the Mac app. A Windows/MSVC build, real Windows UI,
UAC, account/SCM/ACL, profile/DPAPI, boot/recovery and remote-route acceptance all
remain open.

## Remaining runtime and solution gates

The Runtime's schema-2 ledger now commits an authenticated uncertainty guard
before dispatch. Unknown stop or incomplete dispatch survives restart and blocks
new runtime/control-host attachment; queued work is cancelled, not replayed.
Provisioning/migration and incident-bound recovery are explicit local operations.
A native stop verifier and protected service/consent integration remain missing;
portable recovery tests are not Windows stop evidence. See the Runtime contract.

To inspect the twenty-two-project solution (plus transitive Core) without executing suites:

```sh
/absolute/path/to/dotnet10 sln WindowsCompanion/JTS.WindowsCompanion.Next.slnx list
/absolute/path/to/dotnet10 restore WindowsCompanion/JTS.WindowsCompanion.Next.slnx --locked-mode
```

Local transport/runtime tests do not replace Windows 10/11 TLS, DPAPI, dedicated
standard-account execution, process-tree cancellation, service lifecycle,
permission UI, RDP or App Store release acceptance.
