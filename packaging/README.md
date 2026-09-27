# Companion 2.5 developer-only first-install packaging

The current route creates an inspectable Windows x64 installation candidate; it
does **not** install or execute it. The successful development candidate is not a
released Companion, an upgrade/removal tool, Windows acceptance or completion of
the 2.5 release gates. The existing 2.0 package and Mac app are not replaced.

## Build inputs and isolation

Run `scripts/build_companion_next_setup.py` from the client repository with:

- .NET **SDK 10.0.401**, selected by the absolute `--dotnet` path.
- A .NET 8 host/runtime, selected by absolute `--tool-dotnet`, to execute the
  existing project release-manifest tool. The script builds that tool with SDK 10.
- Python 3.11+ and CMake 3.24+.
- For the verified macOS-hosted development route, MinGW-w64 Windows x64 C++ and
  resource compilers with static runtime libraries and an explicit prefix.
  The Windows path selects Visual Studio x64/MSVC; that build remains unverified.
- A **new** output directory. Existing output is refused, never overwritten.

Example developer cross-build; substitute installed absolute SDK paths and an
unused output path:

```sh
python3 scripts/build_companion_next_setup.py \
  --dotnet /absolute/path/to/dotnet10 \
  --tool-dotnet /absolute/path/to/dotnet8 \
  --development \
  --mingw-prefix x86_64-w64-mingw32- \
  --output /absolute/path/to/new-next-setup-output
```

`--development` generates a temporary P-256 signing key and a unique development
release ID. The private key is neither packaged nor retained as a release identity;
the temporary workspace is removed on normal context exit. This is not a secure-
erasure claim. The output is explicitly **DEVELOPMENT-NOT-FOR-DISTRIBUTION** and
must not be distributed or embedded in the Mac app.

`JtsNextPackageBuild=true` opts into `Directory.Build.targets`: 2.5 metadata,
runtime 10.0.12, `win-x64` self-contained publishing and the separate
[packaging dependency locks](next-locks/README.md). Managed/native publication is
serialized into an isolated temporary artifacts tree. Locked restore failures
stop the build; ordinary `packages.lock.json` graphs are not regenerated. Native-
library/content self-extraction, single-file compression, trimming and ReadyToRun
are disabled. The ordinary Next and 2.0 build settings remain separate.

The script also has an external release-key path, restricted to a Windows x64
build host and a regular private-key file outside this repository. That path has
not been accepted as a release process. Cross-compilation is development-only;
supplying a designated release key would not close any native or product gate.
Do not put production signing keys in source, logs or distributable artifacts.

## Payload and trust boundary

The native C++ bootstrap is the only public launch surface. Its elevation
manifest requests administrator approval; it prepares a fresh protected staging
directory before any managed installer starts. See the
[native bootstrap contract](../native/UnattendedBootstrap/README.md) for directory,
environment, ownership, retention and child-process boundaries. It provides no
UAC bypass. The [owner-delegated installation CLI](../docs/RELAY_ENDPOINT_INSTALLATION.md)
can import an existing AI-control authorization without another pairing prompt.

The current schema-2 project manifest authenticates five payload files:

| File | Role |
| --- | --- |
| `JTS.WindowsCompanion.UnattendedSetup.exe` | Visible first-install UI; not installed as a service |
| `JTS.WindowsCompanion.AuthorityService.exe` | Automatic Authority network service |
| `JTS.WindowsCompanion.WorkerRunner.exe` | On-demand, separate-account Worker |
| `JTS.WindowsCompanion.AuthorityProvisioner.exe` | One-shot identity/state initializer |
| `e_sqlite3.dll` | Adjacent native SQLite dependency |

Those five files plus `JTS.WindowsCompanion.release.json` form six embedded
bootstrap resources. Each managed EXE carries the self-contained Windows runtime
host and managed bundle, without native extraction; SQLite remains adjacent.
The installer later copies only the three service/initializer EXEs, authenticated
DLLs and manifest into protected Program Files storage. It excludes the setup UI.

The script verifies each bundle's actual v6 header, allowed entry types, offsets,
zero extraction flags, zero compressed-entry sizes and identical Core assembly bytes. A
separate metadata inspector verifies exactly one embedded
`JTS.Companion.ReleasePublicKey` resource against the generated public key,
then checks the schema-2 signature and exact payload inventory/hashes. The native
PE inspection checks AMD64, absence of a CLR directory, elevation manifest,
system import names and every embedded payload's size/hash. These checks do not
execute any inspected assembly or native payload.

Authenticode is optional and absent from the development candidate. Project
release-manifest verification remains mandatory. The outer bootstrap's provenance
must be authenticated independently, using its expected SHA-256 from a trusted
channel and optionally Authenticode; an embedded checksum is not proof that a
download came from JTS. Do not disable SmartScreen or organization policy.

## Outputs and observed evidence

The output directory contains the outer EXE, a ZIP containing that EXE plus
`README.txt`, `SHA256SUMS` and `packaging-evidence.json`, and local build logs and
per-role publish inventories. Raw managed setup EXEs, public/private key files,
temporary payload directories and generated C++ resource inputs are not separate
delivery artifacts. The script never launches the installer or deploys a service.

Package attempt 5, 2026-09-19 (historical local evidence, not included)
records the completed developer cross-build and content checks: four v6.0 managed
AMD64 bundles with zero extraction flags, the same Core SHA-256, a schema-2 signed
five-file inventory, and six verified resources in the native bootstrap.
`kind` is `DEVELOPMENT-NOT-FOR-DISTRIBUTION`, `authenticode` is false and
**`nativeWindowsExecuted` is false**. This is one verified development package,
not evidence that installation, its UI or any remote function works on Windows.

## Remaining native and release gates

- Windows x64/MSVC build and exact-package launch on Windows 11 and the separate
  Windows 10 ESU target; visible UI, UAC accept/cancel, and no silent authorization.
- Protected staging and actual DLL loading, hostile environment/reparse/path
  negatives, disk/write failures, payload tampering and unknown child exit.
- Account/ACL/service policy, CurrentUser DPAPI profile creation/reopening,
  containment, SCM boot without login, failure preservation and explicit recovery.
- Separate pairing/capability/MCP grants, real control/file/RDP routes, Mac
  integration and all broader 2.5 security, stability and release requirements.

Staging is deliberately retained for local diagnosis; this package does not add
automatic cleanup, upgrade, repair, uninstall or credential rotation. A production
distribution identity and operating procedure still need their own acceptance.
