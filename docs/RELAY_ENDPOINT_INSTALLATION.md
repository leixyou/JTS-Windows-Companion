# Outbound Windows endpoint installation

This is an authorized-lab first-install route. The package includes a native UAC
bootstrap, self-contained .NET 10 Authority/Worker services and the protected
provisioner. It does not require .NET on the target. Cross-compilation and protocol
tests do not establish native Windows installation or desktop acceptance.

The Authority opens only outbound HTTPS/WSS connections. Outer traffic remains TLS
encrypted; public-CA, hostname and certificate-date checks are skipped by default
for the untrusted relay carrier. There is no plaintext fallback. Inner TLS still
requires the exact enrolled P-256 SPKI, certificate checks, mutual authentication,
ALPN and exact session/lane binding. `validateOuterCertificate:true` opts back into
OS trust. The independent relay protocol snapshot is unchanged.

## One authorized enrollment

Export a fresh public request from the Mac target whose AI-control setting is
enabled. That setting is the owner's delegated authority; a second pairing dialog
is not required. Pass these arguments to the outer native installer, in this order:

```powershell
.\JTS-Windows-Companion-2.5-DEVELOPMENT-NOT-FOR-DISTRIBUTION-win-x64.exe `
  --relay https://relay.example.com:8443 `
  --delegated-enrollment C:\JTS\request.json `
  --sha256 REQUEST_SHA256_LOWERCASE `
  --export C:\JTS\windows-enrollment.json
```

The request and export paths must be absolute and not traverse reparse points.
Export is create-new; an existing file is never overwritten. UAC elevation,
authenticated payload checks, separate standard Authority/Worker accounts and
their private ACL/DPAPI boundaries remain mandatory. No arguments opens the
existing interactive installer.

The strict request requires the following fields. It also accepts the optional
boolean `allowWindows10TLS12`; omission or `false` selects TLS 1.3. For Windows 10
and Windows Server 2019, explicitly generate the Mac request with this field set
to `true`. The pinned request SHA-256 covers that choice, which is stored with the
pairing and exported back to the Mac. TLS 1.2 compatibility retains pinned mutual
authentication, ALPN and the approved ECDHE-ECDSA/AES-GCM cipher suites. There is
no automatic protocol downgrade or handshake-failure fallback.

```json
{
  "version": 1,
  "authorizationSource": "ownerDelegated",
  "authorizationReference": "device-ai-control-enabled",
  "controllerDeviceID": "lowercase SHA256 of DER SPKI",
  "controllerSPKIBase64": "canonical padded base64 P-256 SPKI",
  "pairingID": "lowercase nonzero UUID",
  "grantID": "distinct control UUID",
  "fileGrantID": "distinct file UUID",
  "rdpGrantID": "distinct rdp UUID",
  "issuedAtUtc": "UTC ISO8601 timestamp",
  "expiresAtUtc": "UTC ISO8601 timestamp within 30 minutes"
}
```

Request expiry is checked at import. The stored pairing and permissions last until
revocation; the device certificate still has its independent renewal boundary.
The admin-owned provisioning intent pins the request SHA-256. The Authority creates
the exact three-lane pairing and the separate control capability record while
running under its own account, then verifies/reopens the protected stores. A local
receipt records the source, request hash, Authority SID, public Windows identity and
exact controller/grant IDs. There is no network enrollment RPC.

Success exports public JSON with `version`, `name`, `installationState` equal to
`installedAwaitingRelayAdmission`, `relayURL`, `peerSPKIBase64`, `peerDeviceID`,
`pairingID`, `grantID`, `fileGrantID`, `rdpGrantID` and `allowWindows10TLS12`. The node owner must admit the
exact public controller/companion identities and peer relationship. Until first
successful presence, the Authority waits with cancellable 1–30 second backoff on
401/403; no business session is authorized. After admission, loss of node authority
retains the existing fatal policy. Mac enrollment verifies real `device.status`
with the control grant before binding the target.

## Combined private test package

The combined package places the current-user and independent installers in
`current-user/JTS.WindowsCompanion.Setup.exe` and
`independent/JTS.WindowsCompanion.Setup.exe`, with a hash-pinned
`connection-package.json` and `Connect-RelayWindows.ps1` at its root. Extract the
entire package before use. The wrapper supports Windows PowerShell 5.1.

For a console-first relay installation, run the wrapper as the intended logged-in
user, using `-RelayOnly`, the fresh request, its Mac-provided SHA-256 and the
relay HTTPS origin. The independent installer requests UAC when needed; an already
elevated interactive administrator is also accepted in this mode. SYSTEM is
always rejected.
After relay admission and a successful RDP connection, run the current-user EXE
inside that RDP session to install the semantic UIA Agent. The current-user
installer requires a live DVC channel; its absence is a failure after installation
commit and must not be treated as successful readiness.

Without `-RelayOnly`, the wrapper installs the current-user Agent first, then the
independent endpoint. This mode therefore requires an active RDP session. For
LAN-only testing, connect RDP first and run only the current-user EXE in the remote
session; the independent service and relay request are unnecessary.

## Business channels

Control retains `control-v1` jobs and the dedicated standard-account PowerShell
Worker. Exact cwd `.` maps to `%ProgramData%\JTS Terminal\Companion25\shared`,
freshly checked before launch. Other accepted cwd values remain canonical absolute
local Windows paths. No script executes inside the Authority account.

File and RDP use the existing four-byte unsigned big-endian length + strict UTF-8
JSON envelope, maximum 98304 bytes. Request fields are exactly
`version:1,id,operation,grantId,parameters`; response fields are exactly
`version:1,id,ok,result,errorCode`. IDs are lowercase nonzero UUIDs.

The file channel begins with `file.open` and `{}` parameters, returning
`{ready:true}`. Every later request must use the same file grant and is checked
against current protected pairing state before execution and reply. Paths are
relative to the sole `shared` root; absolute paths, traversal, ADS and reparse
points are rejected. `.` is only accepted for list/stat. Operation methods:

| Operation | Parameters | Result |
| --- | --- | --- |
| `file.roots` | `{}` | `{roots:[{id,name,readOnly,maximumFileBytes}]}` |
| `file.list` | `rootId,path,offset,limit` | `{entries:[info],nextOffset:number|null}` |
| `file.stat` | `rootId,path,includeSha256` | `info` |
| `file.read` | `rootId,path,offset,maximumBytes` | `dataBase64,nextOffset,eof,size,sha256` (chunk hash) |
| `file.write.begin` | `transferId,rootId,path,totalBytes,sha256,overwrite` | `transferId,nextOffset,totalBytes,sha256` |
| `file.write.chunk` | `transferId,offset,dataBase64,final` | `transferId,nextOffset` |
| `file.write.commit` | `transferId` | `info` |
| `file.mkdir` | `rootId,path` | `info` |
| `file.remove` | `rootId,path` | `{removed:true}` (directories must be empty) |
| `file.move` | `rootId,path,destinationPath,overwrite` | `info` |

`info` fields are `name,path,isDirectory,size,modifiedAtUnixMilliseconds,sha256`
(nullable unless computed). List limit is 1–100, paths at most 1024 characters,
chunks at most 32768 decoded bytes, files at most 256 MiB. Upload IDs are bound to
the exact owner, file grant and destination/hash metadata. Exact chunk retries are
idempotent; reconnect and repeat begin returns the saved offset. In-memory upload
state lasts 15 idle minutes and does not survive an Authority restart. Commit
verifies the full digest and atomically moves a same-directory temporary file;
failed/incomplete uploads do not replace the destination.

RDP begins with `rdp.open` and `{}`, returning `{ready:true}` only after grant
validation and successful connection to **127.0.0.1:3389**. Thereafter it carries
raw RDP bytes. No client-supplied host or port is accepted. Grant validity is
rechecked every two seconds and pairing changes cancel live sessions. One RDP
session per owner and the service-wide connection bounds apply. Controller
half-close permits up to 15 seconds to drain the local endpoint's final response.

The installer does not change Windows RDP/NLA/firewall or login policy. The target
must have a usable RDP listener and credentials; real Windows/NLA/desktop checks
remain required. Semantic UIA remains in the original current-user DVC Agent and
uses its separate identity/delegation. A service/raw RDP success is not UIA proof.

This candidate has no automatic upgrade/uninstall/recovery workflow. Existing
independent installation state is preserved and requires explicit local review;
the existing 2.0 current-user installation is not replaced.
