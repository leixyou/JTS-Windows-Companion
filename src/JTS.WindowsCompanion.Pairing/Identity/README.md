# Protected endpoint identity loading (2.5 development)

`WindowsRelayIdentityStore` is the explicit Windows production entry point.
It creates or loads an identity; it does not install a service, pair a peer, add a
certificate root, contact a relay, enable a route or replace the old 2.0 identity.
First creation must be reached only from the owner's confirmed local provisioning
workflow. These callable APIs are not evidence that such a workflow has run.

## Required account and configuration

- Provision a dedicated protected local directory and the intended account first.
  Pass the exact expected account SID from trusted installation configuration.
  The API checks the current token's user SID, rejects impersonation and built-in
  service/Administrator RIDs, and accepts only canonical account SIDs with RID
  1000 or higher. Matching a SID alone is **not** proof of a low-privilege token;
  unattended service/Worker composition must enforce their separate token policies.
- Parent DACL must be protected. Parent, file and lease allow access only to that
  account, SYSTEM, Administrators or TrustedInstaller; untrusted inherited allow
  entries on the private parent are rejected too. Existing ancestors cannot be
  owned/replaced by an untrusted account. Unknown callback/object ACE forms fail
  closed rather than being ignored. Windows ACL behavior still needs native tests.
- Use an absolute local drive path, no UNC, alternate data stream, dot traversal
  or reparse points. The installer is responsible for profile loading, directory
  provisioning and narrow ACLs; this API never repairs/broadens them automatically.
- Generate and persist a nonempty enrollment UUID in protected installation
  configuration before explicit creation. After creation, record the returned
  public device ID. Ordinary `Open` requires **both** the UUID and the expected
  device ID; it must not derive the expected pin from the file it is checking.
- The arbitrary-script Worker must be a separate account and cannot access this
  state or the authority account's operating-system key storage. Current-user
  mode cannot protect keys against arbitrary code already running as that same user.

## Creation, loading and ownership

`CreateNew` generates a P-256 key and self-signed non-CA certificate with digital
signature plus client/server authentication uses. The certificate is valid for
365 days, with a five-minute not-before tolerance. The identity is the SHA-256 of
the public SPKI, not its file path or friendly name. The public description holds
only SPKI, public certificate, device ID and certificate expiry.

The bounded version-1 record contains public DER and PKCS#8 private material.
Production protection is fixed to **DPAPI CurrentUser** with an enrollment-bound
purpose. Only the sealed bytes are written to the application file. There is no
plaintext, LocalMachine or portable protector fallback. Clear private buffers are
erased on success/failure; the portable injectable storage core is internal.

Creation uses an exclusive lease, exclusive new file and flush-to-disk. It never
overwrites existing state. A partial published write remains invalid and blocks
normal startup; missing, corrupt, wrong-account, wrong-enrollment, wrong-device or
expired state is never automatically replaced. Recovery must be explicit and must
not revive an old pairing/capability snapshot. Whole valid snapshot rollback and
authority-account compromise are outside this seal's protection.

Open checks size/framing/certificate profile and the private/public key match.
Windows then explicitly imports an in-memory PFX into the current-user key set,
without `MachineKeySet`, `Exportable` or `PersistKeySet`. This is a declared mode,
not a retry/fallback after TLS failure. Microsoft documents
[UserKeySet and the other import flags](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509keystorageflags?view=net-10.0)
and the [bounded PKCS#12 loader](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificateloader.loadpkcs12?view=net-10.0).
The intent is to supply a Schannel-compatible credential, not to assume an
ephemeral-key Mac handshake proves Windows support. Native key ACL, profile,
Schannel and cleanup/restart behavior remain required acceptance.

Keep `StoredRelayIdentity` alive until every borrowing relay client/stream drains;
then dispose it to release the certificate and file lease. Do not log private
material or raw cryptographic exceptions. The [authority host](../../JTS.WindowsCompanion.AuthorityService/README.md)
now monitors expiry and stops the route two minutes before it becomes unusable;
renewal/rotation UI and native host acceptance remain open. Never silently replace the key on
expiry, because that would change device identity without local confirmation.

## Focused checks

The portable storage/profile/access-policy checks use ephemeral authenticated test
protection and disposable directories. A real loopback mutual TLS test reopens two
persisted identities and the companion pairing registry before exchanging data.
On Mac it selects an explicit TLS 1.2 fixture policy; it is not Windows evidence.

Native tests are opt-in under a pre-provisioned authorized account. Set
`JTS_IDENTITY_TEST_ACCOUNT_SID` to that exact account and
`JTS_IDENTITY_TEST_DIRECTORY` to an existing protected local root, then run only
`WindowsIdentityAcceptanceTests` with SDK/runtime 10. They create/delete uniquely
named test subdirectories only, exercise actual DPAPI, reopen and TLS, and reject
a deliberately broadened test-file ACL. They do not create accounts/services,
change the parent root, import roots or enable a production route.

Run the TLS 1.3 case on Windows 11 and explicit TLS 1.2 case on the actual Windows
10 ESU target; a Windows 11 TLS 1.2 result alone does not prove Win10 compatibility.
Absent Windows or explicit account/root, these gates report skipped. Separate
cross-account denial, OS key-store cleanup, service boot without login, installer,
pairing consent, live certificate lifecycle and public-route acceptance remain open.
