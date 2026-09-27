# Authority-account first initialization (2.5 development)

This separate Windows x64 executable prepares a **new, disabled, isolated**
authority-state directory. It is not the elevated installer, a migration tool,
a service, an approval UI, or an installed/released Companion. It neither starts
networking nor launches a Worker. The old 2.0 installer and state are unchanged.

## Fixed installer-to-account contract

The only command is `--provision <canonical-lowercase-enrollment-UUID>`. It accepts
no path, password, script, relay origin, public-key override or repair switch.
The native entry point requires the exact standard authority-account token,
protected single-file Program Files deployment and embedded release-manifest
trust. Authenticode remains optional; manifest verification is not optional.
Ordinary development builds without the embedded release key fail closed.

The future elevated installer must first obtain explicit Windows installation
consent, create **separate** standard authority and Worker accounts, and prepare:

```text
%ProgramData%/JTS Terminal/Companion25/
  .provision/<enrollment-UUID>/
    intent.json                   installer-owned, protected, authority read-only
    state/                        protected, authority-private, initially empty
```

The installer-owned root, `.provision` and enrollment parent must not permit the
authority, Worker or other untrusted accounts to create/replace their content.
Ancestors cannot permit untrusted replacement. SYSTEM/Administrators/TrustedInstaller
are accepted owners of those boundaries; the authority itself is not an accepted
intent owner. Unknown native ACE forms, writable intent/parents, links and broad
private-state access fail. These are native policy implementations, not yet
Windows ACL acceptance evidence. The helper does not create or repair ACLs.

Intent schema 1 has exactly these fields: `schemaVersion: 1`,
`operation: "initialize-new-authority"`, `enrollmentId`, `authoritySid`, `workerSid`,
`createdAt`, `expiresAt`, plus optional `delegationSha256`. The optional hash pins
the exact admin-owned, authority-readable `delegation-request.json` in the same
staging directory. Its strict [owner-delegated contract](../../docs/RELAY_ENDPOINT_INSTALLATION.md)
is never accepted through network RPC. IDs/SIDs must be canonical and bind the fixed directory,
actual authority account and distinct non-built-in Worker SID. Times use UTC
round-trip `O` format, with a positive lifetime of at most 30 minutes. Future,
expired, duplicate, extra, malformed and over-4096-byte inputs fail. There is no
boolean field that substitutes for actual installation consent. The installer
owns obtaining consent; the protected intent only delegates this limited step.

Run under the **authority account with its own profile loaded**, not as the
administrator, SYSTEM or an impersonated user. DPAPI is fixed to CurrentUser;
the helper never receives an account password. Native account/profile launch
and DPAPI/Schannel behavior still require the installer and real Windows tests.

## State and failure semantics

1. Verify program/token, intent and protected paths; hold the intent read lease.
   Refuse any existing live `authority` path. No upgrade or reinitialization here.
2. Exclusively create and flush `state/attempt.json`. Any previous attempt,
   success, unexpected file or concurrent invocation prevents initialization.
3. Generate the sealed endpoint identity in this account. Create pairing,
   Control-grant and job stores. With a pinned owner-delegated request, create its
   exact three-lane pairing/control capability and local authorization receipt;
   otherwise pairing and grants remain empty.
4. Close and reopen all four stores, validate the exact public identity, expected
   pairing/grant inventories and clean job safety state. Check private paths and
   require closed SQLite state without unexplained WAL/SHM or other files.
5. Write/flush `ready.pending.json`, recheck intent time and absence of a live
   installation, then rename to `ready.json` without overwrite.

The versioned receipt says `staged-not-enabled`, includes enrollment/account IDs,
the public identity description and hashes/sizes of the four closed state files
and, when delegated, the fifth public authorization receipt.
It contains no password/private key/script or local absolute paths. The identity
object uses `RelayIdentityDescription` property names. It is an integrity handoff
record, **not signed installer authorization**, and cannot by itself enable a route.

On failure, the helper leaves the attempted stage for installer diagnosis and
explicit cleanup. It does not retry, reset identity, delete unknown content, move
the directory into the live location, or touch a previous installation. It never
writes `authority.json`, creates accounts/services, grants capabilities or connects
to a relay. Successful exit is 0 with a fixed staged-only message; platform refusal
is 10, known contract failures 11, other failures 70. Raw exception contents are
not printed. A crashed/incomplete receipt is not acceptance.

The future installer must independently validate its transaction ownership and
receipt/state, publish protected state on the same volume, write the explicit
runtime configuration and activate services only after completing its transaction.
It must keep credentials out of argv/files/logs, confirm cleanup by exact account
SID, and handle failed activation/unknown Worker execution without claiming safe
rollback. This helper does not establish power-loss durability of that unfinished
installation transaction. Updating, rotating, recovering and uninstalling live
state need different explicit operations; never repurpose this first-init path.

## Focused checks

`scripts/verify_companion_next.sh authority-provisioner` selects only this module.
Portable tests use real temporary files, cryptographic identities and SQLite stores
with a **test-only authenticated protector**, and native ACL facts as fixtures.
They cover strict intent/arguments, account separation, installer-owned permission
policy, first creation/reopen, empty grants/jobs, no implicit enablement, content
hashes, repeat/concurrent invocations, failure isolation, late expiry/publication,
unexplained state and symlink rejection. Test assemblies alone can access the
internal identity fixture; production has no injectable CLI/protection override.

These do not prove Windows DPAPI, profile loading, actual token/ACL/manifest
deployment or transactional service installation. Native Windows, full installer,
secure local consent/revocation/recovery IPC, old/new coexistence, service boot,
Mac integration and final 2.5 release gates remain open.
