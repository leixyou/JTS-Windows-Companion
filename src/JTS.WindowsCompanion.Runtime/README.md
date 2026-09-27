# Durable job runtime foundation (2.5 alpha)

This standalone net10.0 module provides a SQLite WAL ledger and an explicitly
pumped, serial scheduler. It does not install a service, impersonate a user,
execute PowerShell, or expose an MCP/HTTP endpoint. It does not replace the
existing fixed-operation VRC/managed providers.

## Host integration contract

1. Provision a private owner-only directory and supply an absolute database
   path, an `ITaskPayloadProtector`, an `IJobGrantAuthority` and an `IJobExecutor`.
   The store holds an exclusive process lease; exactly one runtime can attach.
   First-time provisioning uses `DurableJobStore.CreateNew`; ordinary construction
   opens an existing initialized store only. Never catch missing/corrupt store
   errors and automatically recreate the ledger or lose its deduplication history.
2. Use `CurrentUserDpapiTaskProtector` in the protected ledger-owning Windows account context.
   It fails on other platforms; no plaintext/LocalMachine fallback exists.
   Only the test assembly supplies a deterministic AEAD fixture protector.
   The arbitrary-script Worker must not own the authorization database or service
   keys. Production composition needs a protected authority/Worker IPC boundary;
   do not move those stores into the script account just to call an in-process executor.
3. Authenticate the controller and bind each request ID to its payload SHA-256,
   owner device, grant, job kind, deadline and `allowDisconnected` choice.
   A repeated exact request returns its stored receipt; changed fields conflict.
4. `SetOwnerConnected` receives the host's aggregate authenticated **control**
   presence, not individual file/RDP socket state. Default jobs require that
   presence; an explicitly detached job may survive network disconnection.
5. `RunNextAsync` rechecks the injected grant authority before dispatch and
   closes the concurrent revoke/dispatch race. The host must persist grant
   revocation in its authority before calling `RevokeGrant`; this runtime's
   immediate revoke cache is not the durable authorization database.
   Presence is bounded to 128 connected owners and the immediate revoke cache
   to 4096 entries by default. Presence overflow rejects the new owner. Revoke
   overflow cancels all queued/running jobs and permanently closes admission
   for that runtime; it never evicts revocations. The host must reconcile its
   bounded admission registry and durable authority before creating a new runtime.
   Device pairing revocation uses `RevokeOwner` after durable local revocation;
   this cancels all of that owner's grants/jobs, including detached work, and
   rejects submission/dispatch races without affecting another owner. Its bounded
   deny cache also fails closed rather than evicting a prior revocation.
   After verifying a newly persisted pairing, the trusted host may use
   `ActivateOwnerGrantsAsync` to admit only its new grant IDs. Activation waits
   for the old executor to finish, checks concurrent revocation, and preserves
   all old grant tombstones and cancelled job receipts. Revoking the owner again
   removes this limited admission. No remote caller can invoke this host API.
6. An executor must honor cancellation and stop/drain actual child processes.
   The runtime reports `Cancelling` until execution returns, never pretends a
   process has stopped. Shutdown fails visibly after five seconds if an
   executor does not drain; the store must remain open until it actually stops.
   If termination cannot be confirmed, throw `JobExecutionStateUnknownException`.
   This records `Interrupted / EXECUTOR_STATE_UNKNOWN`, cancels queued work,
   permanently closes this runtime's admission and faults its scheduler. It is
   not translated to cancellation, even if the caller already requested cancel.
   An authenticated durable guard is committed in the same transaction as the
   Running receipt **before** any executor dispatch. Unconfirmed stop or a five-
   second shutdown timeout quarantines the ledger. A failed quarantine write
   leaves the earlier dispatch guard, so restart still cannot resume execution.
7. Dispose the runtime before its caller-owned store. A restart changes running
   or cancelling jobs to `Interrupted`, not `Queued`. Their external effects may
   be unknown. Incomplete dispatch quarantines the whole ledger and cancels all
   pending jobs, including detached ones; a new runtime/control host cannot attach.
   Only a clean restart preserves queued detached jobs for fresh authorization;
   queued interactive jobs are always cancelled because their session ended.

## Local recovery and schema migration

Schema 2 adds a protected store identity/header and fixed-size, versioned safety
record. Missing, corrupt, oversized or cross-store records fail closed; they are
not replaced with a clean state. `GetRecoveryRequirement` exposes only local
incident metadata. It does not claim that an executor has stopped.

After draining and disposing the runtime, the trusted authority may call
`ConfirmExecutionRecoveryAsync` with that exact incident and an independently
implemented `IJobRecoveryVerifier`. It must confirm actual executor descendants
are stopped/fenced, not trust a pipe acknowledgement, SCM status or service restart.
This is **not** a remote/MCP capability, and there is no permissive default verifier.
Verification has a ten-second bound; cancellation, refusal, timeout, exceptions,
write failure or a changed incident leave execution blocked. Runtime attachment,
concurrent recovery and store disposal are fenced while verification is pending.
Late verification cannot clear the fault. Successful recovery never rewrites or
replays Interrupted receipts; new work still requires current authorization.

An ordinary open of schema 1 reports `JOB_STORE_UPGRADE_REQUIRED`. Explicit offline
`UpgradeLegacy` validates existing receipts and transactionally adds schema 2,
always quarantined with `LEGACY_STORE_REVIEW_REQUIRED`, even when no Running row
exists: the old in-memory latch cannot prove quiescence. Preserve a protected
backup, stop/fence all old executors and complete trusted local recovery before
resuming. Missing/other schema versions are not migrated automatically. Never
restore an old clean database or change its identity as a fault-reset shortcut.

These seals rely on the protected authority account and directory ACLs. They do
not detect restoration of an entire old valid database snapshot, compromise of
the protector-owning account, or a second independently provisioned ledger used
to launch the same Worker. Production must enforce a single authority and use a
separate explicit disaster-recovery procedure; Windows provisioning, native stop
proof and recovery consent UI are still required.

Owner/grant matching in lookup/cancel is defense in depth, not external request
authentication. The host must enforce pairing, MCP capabilities, execution
account, data scopes and grant expiry; a device fingerprint is not a bearer
credential. Approved scope metadata alone is not a PowerShell sandbox.

## Bounds and persistence

Defaults: 32 queued/running jobs, 4096 immutable receipts, 64 KiB payload, 128 KiB
output per job, 8 MiB aggregate retained output, maximum 24-hour execution
deadline, and seven-day result data retention. Limits are constructor-validated.
Payloads and outputs are protected before SQL writes and bound to the immutable
request digest and data purpose. Plain output never enters the database or WAL.
Completed jobs discard the active payload; retention removes result data but
keeps immutable receipts. Receipt exhaustion rejects new work rather than
deleting deduplication history and allowing old requests to replay. Administrative
archive/receipt-epoch rotation is not implemented in this foundation.

Retention is logical deletion of encrypted blobs, not a promise of forensic
erasure from filesystem snapshots. SQLite and the private directory still
contain operational metadata such as device IDs, grant IDs and timestamps.

## Remaining production work

The separate [Execution module](../JTS.WindowsCompanion.Execution/README.md)
implements a dedicated-account PowerShell executor with token attestation, stdin
script delivery, fixed environment, bounded output and Job Object drain. Native
Windows behavior is not verified on a macOS test host. It must be integrated
behind the authority/Worker IPC boundary and tested on real Windows before the
route is enabled. The [WorkerIpc adapter](../JTS.WindowsCompanion.WorkerIpc/README.md)
now supplies this dispatch/supervision boundary, but requires the still-unfinished
native cross-account validation and service provisioning. The WorkerService module
now implements the fixed SCM launcher/host, but not its installer or authority
service composition. Durable local grants are implemented in the Control module;
protected account/ACL ownership, service provisioning, permission UI, task
streaming/MCP routing, native local recovery verifier and OS restart/account-loss
acceptance remain open. The portable recovery tests use explicit test-only stop
verifiers, not real Windows process evidence.

The targeted runtime test project is
`WindowsCompanion/tests/JTS.WindowsCompanion.Runtime.Tests/JTS.WindowsCompanion.Runtime.Tests.csproj`.
It exercises actual SQLite reopen/WAL, authenticated encryption fixtures,
idempotency, restart, ownership, cancellation, deadlines and retention without
running scripts or changing local/remote accounts.
