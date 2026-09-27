# Windows Companion distribution policy

## Owner decision — 2026-09-05

Windows Companion Authenticode signing is optional, not a mandatory prerequisite
for JTS Terminal 2.0 distribution. Purchasing a Windows code-signing certificate
or obtaining a production signing service is not itself a release blocker.
This overrides earlier documentation that made production Authenticode and
timestamp evidence mandatory for every Companion artifact.

This decision does not change macOS app/helper signing, Windows UAC or security
policy, DVC pairing and message authentication, DPAPI protection, file-root
authorization, or release-artifact integrity requirements. A hash is useful only
when its expected value is obtained from an independently trusted source; an
editable adjacent checksum file is not a replacement publisher identity.

Unsigned Windows executables may show an unknown publisher warning or be blocked
by SmartScreen, Smart App Control, or organization policy. JTS must disclose this
and must not disable operating-system protections or install a trusted-root
certificate automatically to suppress those warnings. See Microsoft's
[code signing options](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options)
and [UAC behavior](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works).

The owner subsequently confirmed that administrator/UAC capability must be
retained. The normal current-user installer continues to configure the UAC
broker; ordinary shell execution does not silently become elevated. The optional
managed service is still a separate, administrator-installed deployment, not a
new part of the normal Setup.

## Release identity without Authenticode

The replacement is an application-level ECDSA P-256 release manifest. It needs no
commercial certificate, Windows certificate-chain trust, or installed root
certificate. It does require a protected project release private key, kept
outside the source tree and package; only its public key is embedded in the Core
assembly when publishing every executable.

`JTS.WindowsCompanion.release.json` contains a base64 payload and a fixed-width
P1363 ECDSA/SHA-256 signature over those exact payload bytes. The strict payload
schema is `schemaVersion`, `releaseId`, and `files` (`fileName` / `sha256`).
Duplicate or unknown fields, unsafe names, duplicate case-insensitive filenames,
wrong keys, unsupported schemas, and modified executable bytes fail closed.
There is no runtime environment, command-line, adjacent-key or unsigned fallback
that can replace the compiled trust anchor.

- Setup authenticates its embedded manifest and checks Agent/Broker bytes before
  activation. The manifest is installed in the same directory transaction.
- Agent validates itself, then validates the Broker against that same immutable
  inventory. Broker independently validates itself and the actual Agent pipe
  peer against its own verified inventory. File handles remain locked through
  launch/attestation; PID, path, SID, nonce, pipe ACL, request binding, deadlines,
  consent and actual `runas` remain enforced.
- Managed mode retains SCM/LocalSystem/Session-0/SID and protected directory
  checks. Its service and allowed handlers need entries in its authenticated
  release inventory in addition to the fixed-operation handler hash. It never
  acquires an arbitrary administrator shell.

The embedded payload manifest cannot contain Setup's own final hash (that would
be circular). Initial Setup provenance is instead the exact installer hash
carried inside the Apple-signed Mac application, or another independently trusted
release channel. Staged and detached Setup copies are compared with the locked
running source copy. This copy check protects continuity, not independent
publisher identity. A malicious replacement of the initial Setup or of the
entire application/trust anchor is outside the self-verification guarantee.

## Publishing and validation

### Separate 2.5 optional unattended installer

The Next unattended installer does not replace the 2.0 current-user setup. Its
schema-2 inventory permits bounded flat EXE/DLL names, while schema 1 remains
exe-only. A native elevated bootstrap embeds the final signed inventory and all
four managed role EXEs plus native dependencies. Protected extraction precedes
managed startup; managed native/content self-extraction is prohibited. The UI
verifies its own final hash and the installed payload, which excludes the UI.
The outer bootstrap cannot authenticate its own provenance: its expected final
hash still requires an independently trusted delivery channel.

The developer packaging path and separate locks are documented in
[`packaging/README.md`](../packaging/README.md). The first diagnostic package is
cross-compiled with a disposable identity, no Authenticode and zero Windows
execution. It must not be distributed or embedded into the Mac app. Production
identity builds require an external protected key and Windows x64 builder;
this path and all native installation/UAC gates remain unaccepted. Optional
Authenticode does not waive those gates or permit OS-protection bypasses.

### Existing 2.0 current-user installer

`build-current-user-setup.ps1` accepts an external release private-key path and
embeds only the derived public key. Agent/Broker are published first; the
manifest records their final bytes; Setup then embeds all three resources.
Authenticode is an optional additional publishing step when both a certificate
thumbprint and timestamp URL are explicitly supplied. Partial or failed signing
does not silently fall back to unsigned.

`-AllowUnsignedDevelopmentBuild` uses a temporary diagnostic key and retains the
`UNSIGNED-DEVELOPMENT` filename and marker. It must never be renamed, bundled
in the Mac app, or treated as release evidence. A production package needs a
designated, protected release key and a real Windows x64 publish: a macOS build
does not contain the production Windows UI Automation implementation.

Source-level tests and cross-compilation do not prove Windows installation or
elevation. Windows 10/11 clean install, repair, upgrade, uninstall, DVC/pairing,
actual UAC, altered executable/manifest and impostor-peer denial remain release
gates. The historically named signed-UAC and authorized-lab drivers now build
with separate ephemeral diagnostic keys, pin exact artifact snapshots and
remove their private keys; they do not create trusted certificates. Schema-3
UAC evidence still requires real execution, and old Authenticode-profile
results cannot be relabeled as acceptance of this path. PowerShell/Windows
runtime acceptance remains pending; local source contracts are not that proof.
