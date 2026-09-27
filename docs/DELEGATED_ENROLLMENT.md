# Current-user delegated enrollment

A device's enabled AI-control setting is the owner's authorization for delegated
pairing. Setup can record that authorization for one exact Mac/Windows identity
pair, without pretending an interactive consent dialog was clicked. This is a
local, current-user provisioning command, not an unauthenticated DVC method.
The normal interactive pairing path is unchanged for devices without delegation.

## Import contract

Run the distribution Setup from outside its installation directory:

```powershell
$setupProcess = Start-Process -FilePath $setup -ArgumentList @(
    '--install', '--quiet',
    '--delegated-enrollment', ('"' + $requestPath + '"'),
    '--delegated-enrollment-sha256', $requestSha256
) -PassThru
if (-not $setupProcess.WaitForExit(120000)) { throw 'Setup is still running.' }
if ($setupProcess.ExitCode -ne 0) { throw ('Setup exit code ' + $setupProcess.ExitCode) }
```

The SHA256 must come from the owner-authorized Mac export/transport, rather than
being trusted only because it sits next to the request file. It pins the exact
UTF-8 request bytes. Do not use `Start-Process -Wait`, which also waits for the
long-lived Agent child. Arguments contain public enrollment data only.

The strict JSON object has exactly these fields (camelCase, no duplicates or
unknown fields), with a maximum encoded size of 16 KiB:

| Field | Value |
| --- | --- |
| `schemaVersion` | integer `1` |
| `grantId` | nonempty UUID in hyphenated form |
| `authorizationSource` | `ownerDelegated` |
| `targetId` | the nonempty JTS device UUID |
| `targetBinding` | nonempty target description, at most 512 characters, no control characters |
| `macIdentity` | exactly `deviceId`, `publicKeyBase64`, `fingerprintSha256` |
| `expectedWindows` | exactly `deviceId`, `fingerprintSha256` |
| `issuedAtUtc` / `expiresAtUtc` | ISO8601 timestamps with explicit timezone; maximum 30-minute interval |
| `authorizationReference` | `device-ai-control-enabled` |

The Mac key is a complete NIST P-256 SubjectPublicKeyInfo DER encoded as Base64;
its full SHA256 must match the supplied fingerprint. The Windows identity must
already exist and match both expected fields. Enrollment never creates a new
Windows identity or replaces an existing peer silently. The import must occur
within the request validity window. Expiry limits import, not the lifetime of a
persisted permission.

Before disturbing running processes, Setup validates the request, current Windows
identity, and existing peer. After verified installation commits, it revalidates
and atomically saves the protected grant before starting Agent. Its recovery
record disables automatic Agent launch when enrollment is incomplete. An error
after installation commit is reported as failure; it is not reported as a fully
rolled-back install. Existing Setup self-repair from inside the installation
folder must detach so its executable can be replaced: delegated invocation there
returns exit code `4` (deferred), not enrollment success. Use the distribution
Setup for synchronous automation.

## Receipt and authenticated session

The DPAPI-protected receipt contains the request's complete grant/target/Mac/
Windows bindings, source/reference and import timestamps, plus `requestSha256`,
actual `windowsUserSid`, actual `windowsSessionId`, and `approvedAtUtc`. Grant and
receipt are one atomic protected write. The same request preserves the original
receipt/time; a different grant or changed request for an existing peer requires
explicit revocation first. Existing interactive approval is never relabeled as
delegated approval.

Enrollment does not create a live authorized session. A fresh existing v1
challenge and a valid signature from the exact Mac private key are still required.
No frame authentication, file-root, Mac capability, elevation or OS UAC checks
are removed. The authorize response adds:

```json
{"authorizationSource":"ownerDelegated","delegationGrantId":"<grantId>"}
```

Legacy interactive grants return `authorizationSource: "interactive"` and a null
`delegationGrantId`.

## Revocation

The existing authenticated `companion.unpair` clears the active grant and receipt,
resets live session/frame authorization, and records a protected revocation
receipt/tombstone. An offline recovery command is also available:

```powershell
& $installedSetup --revoke-delegation '<exact-grant-id>' --quiet
```

An absent or different active grant ID fails without stopping the current Agent.
A matching ID stops the current-user Agent/broker and atomically revokes the grant.
Repair or the next authorized launch can reconnect visually; the removed
permission is not restored. Mac per-device revocation must also suppress automatic
export until the owner re-enables delegation. A revoked grant ID cannot be
reimported, including after process restart. New owner-authorized grant IDs can be
imported after revocation. Revocation history retains up to 1024 IDs; once full,
new delegated enrollment fails visibly instead of discarding tombstones. Existing
permissions remain revocable.

Peer envelope v2 stores the active grant, revoked grant IDs, and the most recent
revocation receipt in one DPAPI-protected payload. Existing v1 envelopes remain
readable. Older Companion builds cannot read v2 and must not be used to downgrade
an enrolled installation. Neither request files nor receipts contain private keys.

## Agent reconnect lifecycle

The current-user Agent remains in its existing Windows session when native WTS
channel open/read/write reports transport unavailability. It retries in the same
process with cancellation-aware backoff of 1, 2, 4, then at most 8 seconds. Each
attempt owns a fresh channel, authorization session, router, Agent replay state,
transfer coordinator, and elevation client. Old requests and any outstanding
native receive are cancelled and drained before those resources are disposed and
the next attempt starts. Interrupted transfers belong to the old generation.

A persisted peer/delegation survives disconnect, but live authorization does not:
reconnection requires a new challenge and valid private-key proof. Pairing dialogs
run off the receive loop and honor cancellation so they cannot hold a disconnected
generation open. Installer readiness is attempted only once after the first native
channel opens. Protocol/authentication errors and unrelated native/cryptographic/
configuration failures remain terminal rather than being retried as disconnects.
This is not a watchdog, service install, or process-respawn mechanism; Windows
logoff still ends the current-user process.

Native WTS reads and writes share a cancellation-aware gate because the WTS
wrapper APIs are not thread safe. The gate covers each finite 500 ms read call
or write call, while idle-read delay stays outside it. Whole-frame write ordering
is retained separately. For the first 16 outbound frames and native writes in a
channel generation, fixed transport-stage events report progress and byte/error
counts; they never include frame contents, identity keys, or request parameters.
These events distinguish response construction from an actual completed write.
