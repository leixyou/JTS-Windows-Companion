# Native elevated setup bootstrap (2.5 development)

This Windows x64 C++ bootstrap prepares a protected directory before starting any
managed installer code. It creates no accounts or services and grants no remote
access. The managed first-install library remains responsible for its separate,
visible installation confirmation and transaction. This source has **not been
compiled or accepted on Windows** in the current development increment.

## Trust and startup boundary

- `bootstrap.manifest` requests `requireAdministrator`, without `uiAccess`.
  Startup also rejects non-elevated, non-administrator, SYSTEM, impersonated and
  noninteractive callers. No unattended/elevation-bypass switch is provided.
- MSVC uses a static CRT (`/MT` in Release); MinGW-w64 uses static GCC/C++ runtime
  linkage. The bootstrap has no managed runtime or app-local runtime DLL startup
  dependency. Its own dynamic search is restricted to System32; current-directory
  DLL searching is removed before the managed child is created.
- The download must be authenticated externally through the release SHA-256
  obtained from a trusted channel and, optionally, Authenticode. Embedded payload
  hashes establish continuity within this executable, **not the provenance of a
  downloaded executable**. The managed project release-manifest check remains a
  separate requirement. Windows reputation/security prompts are not bypassed.

The package must publish each managed executable as a self-contained single-file
managed bundle **with native-library self-extraction disabled**. Required native
DLLs are separate payload files beside the four executables. The bootstrap does
not set or inherit `DOTNET_BUNDLE_EXTRACT_BASE_DIR` or execute a managed apphost
from Downloads/a user-writable extraction directory. The publisher must verify
the actual publish outputs, native dependencies and bundle settings; this native
loader cannot infer those settings from a filename or hash.

## Protected staging and execution

Staging uses the OS ProgramData known folder, not inherited environment values:

```text
%ProgramData%/JTS Terminal/.Setup25/<new UUID>/
  JTS.WindowsCompanion.UnattendedSetup.exe
  JTS.WindowsCompanion.AuthorityService.exe
  JTS.WindowsCompanion.WorkerRunner.exe
  JTS.WindowsCompanion.AuthorityProvisioner.exe
  JTS.WindowsCompanion.release.json
  <native DLLs>
  Temp/
```

Every existing ancestor must be non-reparse and have a trusted owner and no
untrusted replace/delete rights. Existing `JTS Terminal` / `.Setup25` parents must
additionally have a protected administrator/SYSTEM-owned DACL without lower-
privilege write access. Unsafe existing directories are rejected, never re-ACL'd.
The new `.Setup25` parent, UUID directory and Temp directory use atomic
`CreateDirectoryW` with an explicit protected administrator/SYSTEM-only DACL.
If newly created, the shared `JTS Terminal` parent additionally gives Authenticated
Users read/execute only so other JTS accounts can inspect that ancestor; staging
does not inherit this access. No-delete-share directory handles hold the checked
path chain during setup.

Each resource is size-checked and SHA-256 checked with Windows CNG. Extracted files
are create-new with explicit Administrators ownership and administrator/SYSTEM-only
protected DACLs, flushed and rehashed through a reopened read-only handle. These
`FILE_SHARE_READ` leases prohibit replacement/writing while the managed child
runs. No write-access image handle is retained during process loading.

The only child is the absolute staged `JTS.WindowsCompanion.UnattendedSetup.exe`,
with either no arguments or the bounded explicit delegated-install argument string,
no inherited handles, and the staging directory as its working
directory. Its explicit Unicode environment contains only OS/profile paths,
System32-only PATH and the private staging Temp/TMP. Ambient `DOTNET_*`,
`COMPlus_*`, `COR_*`, profiler variables, credentials and relay settings are not
copied. The native startup notice does not authorize installation; the managed
screen obtains the relay choice and actual confirmation. The delegated CLI instead
requires the strict, SHA-256-pinned owner authorization request; the authenticated
managed child validates all eight arguments before installation. No shell is used.

The bootstrap waits on the exact child-process handle. A quit request or wait
failure is not interpreted as cancellation or proof of cleanup. All staging is
retained on success, cancellation and failure for explicit local diagnosis;
unknown child state is reported without deleting its files or terminating a
possibly active installer. There is no recursive cleanup, profile deletion or
rollback of services/accounts in this component. Retained directories consume
disk space and need a future explicit, ownership-aware maintenance workflow.

## Generated resource contract

The payload packager supplies `payload_table.h` and `payload.rc` in a generated
directory passed as `JTS_PAYLOAD_DIR`. The header defines global entries:

```cpp
struct PayloadFile {
    int resourceId;
    const wchar_t* name;
    unsigned long long size;
    const char* sha256;
};
constexpr PayloadFile kPayloadFiles[] = { /* generated authenticated payload */ };
```

The resource script maps each matching numeric ID to `RCDATA`. The separate
checked-in `bootstrap.rc` embeds the elevation manifest as resource 1 of type
`RT_MANIFEST`; the generated script must not duplicate that manifest resource.
Files must have unique case-insensitive portable basenames and unique IDs in
1..65535. Paths, alternate streams, DOS device names, dot traversal and trailing
dots are rejected. There are at most 128 files, each 1 byte..1 GiB, at most 2 GiB
total, with lowercase 64-character SHA-256 values. All four named executables and
the project release manifest are mandatory. No generated payload is checked into
this source directory.

## Building and acceptance

Use CMake 3.24+ and a Windows x64 toolchain with an RC compiler:

```sh
cmake -S WindowsCompanion/native/UnattendedBootstrap -B build/unattended-bootstrap \
  -DJTS_PAYLOAD_DIR=/absolute/path/to/generated-payload
cmake --build build/unattended-bootstrap --config Release
```

For Visual Studio select `-A x64` from its developer environment. MinGW-w64 may
cross-build with an explicit Windows x64 CMake toolchain file and `windres`;
static runtime libraries are required. Output is `JTS.WindowsCompanion.Setup.exe`.
Do not replace missing native toolchains with a managed self-extracting launcher.
The final local inventory found clang++, CMake, `x86_64-w64-mingw32-g++` and
`x86_64-w64-mingw32-windres` on the macOS host, but no MSVC `cl`. This source-writing
subtask installed no toolchain and ran no native build.

Before delivery, build with both supported configurations, inspect PE imports,
the manifest and embedded file table, verify the outer release checksum, then
exercise real Windows 11 / Windows 10 ESU UAC and startup. Negative acceptance
must cover hostile environment values, unsafe/reparse parents, existing output
collisions, tampered resources, write/flush/disk failures and an unconfirmed child
exit. Confirm managed startup loads only expected native files from the protected
stage/System32 and never self-extracts native code. Portable packager checks or a
successful PE cross-build do not close these Windows or full 2.5 release gates.

API references: Microsoft [CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw)
and [GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo).
