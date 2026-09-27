# Authority ↔ one-shot Worker IPC (2.5 development)

This endpoint-owned .NET 10 module supplies `WindowsWorkerJobExecutor` for the
protected control/ledger account and `WindowsWorkerEndpoint` for a different,
dedicated standard account. `WorkerRunner` composes the latter with the fixed
PowerShell executor. Neither project belongs to, references or changes JTS Relay.
They do not grant capabilities, install accounts/services or enable the new route.

## Trust and process lifetime

The authority creates a random, first-instance, local-only named pipe before
launch. Its protected DACL grants full rights only to the authority SID and
specific read/write rights to the configured Worker SID. The Worker receives no
create-instance, change-permissions or change-owner right. No Everyone, Anonymous
or shared service-account ACE is added. Client opens use identification-only SQOS.
Microsoft documents why generic write would also grant
[pipe-instance creation](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights);
the implementation intentionally requests individual rights instead.

Each side compares the kernel's named-pipe peer PID with an independently opened,
held process handle. Expected launch identity binds PID, creation FILETIME,
primary account SID, exact executable path and SHA-256; it is never accepted from
the peer's message. Executable files stay open without write/delete sharing for
the session. Reused PIDs, another same-account process, changed image/hash or an
elevated process are rejected. Kernel peer APIs:
[client PID](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeclientprocessid),
[server PID](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getnamedpipeserverprocessid).

The trusted launcher supplies the waiting Worker's identity and attaches an
**authority-owned** kill-on-close Job Object before any Execute frame is sent.
The Worker receives neither that job handle nor authority keys/stores. The proxy
checks actual active-process count after terminating the job on **all** outcomes,
including a claimed successful result. Worker acknowledgements alone cannot
establish that processes stopped. Failure to confirm stop becomes
`JobExecutionStateUnknownException`, not Cancelled or Succeeded.

The Worker remains able to influence its own output and memory under its account;
scripts are not isolated from other processes/resources owned by that account.
This is why the authority, durable grants, service keys/config and program files
must remain protected under a different identity. An executable hash check is not
a replacement for the complete release manifest or immutable program-directory
ACLs (including adjacent assemblies). Job Objects do not undo external/brokered
effects. See the [Execution boundary](../JTS.WindowsCompanion.Execution/README.md).

## Single-task protocol and supervision

Each local pipe carries one task only, no command queue, account selection, grant
mutation, arbitrary executable selection or second execution. See
[wire version 1](../../Protocols/JTSCompanion/worker-ipc-v1.md) in the client
repository (the file is separate from the immutable relay snapshot).

The authority sends the exact bounded runtime binding/payload, streams output
into the existing bounded/protected sink, and emits a pulse every two seconds.
Each pulse write has a two-second bound. Seven seconds without a valid pulse,
pipe loss or malformed/second Execute causes Worker cancellation. This is a local
authority lease, not RDP/network presence: approved detached tasks survive Mac
disconnect while the authority service remains healthy.

Authority cancellation closes the pipe and terminates its Worker job. A claimed
result is returned only after independent process drain (three-second maximum).
Ambiguous delivery, unexpected EOF or malformed replies after dispatch becomes
unknown/interrupted; there is no retry or new task ID. The runtime handles its
existing 24-hour deadline and durable idempotency/authorization rules.

## Launch integration

`IWorkerProcessLauncher` is an explicit **required** trusted integration. The
separate [WorkerService module](../JTS.WindowsCompanion.WorkerService/README.md)
now implements it with a fixed SCM service and no permissive same-account fallback.
It starts the release-manifest-verified one-shot Worker under the configured
standard account, obtain PID/start/image evidence independently (not from pipe
hello data), grant only the necessary authority process rights, attach the job
and return its lease. A failed launch must prove cleanup or report unknown.

The required production composition is an explicitly installed on-demand Worker service
and low-privilege authority service, with protected service DACLs, minimal required
token privileges and no automatic Worker crash restart. The authority needs only
access to that fixed service, not credentials or a generic privileged process
launcher. Account provisioning/recovery, the authority service, production bundle/
ACL acceptance and boot-without-login remain incomplete. A portable service-policy
test is not Windows service/ACL evidence.

`WorkerRunner` now supports SCM `--service` and an explicit one-shot console entry.
The shared codec validates seven launch arguments: session UUID, authority
PID, authority start FILETIME, authority SID, authority image path, authority image
SHA-256 and Worker SID. They are public rendezvous metadata, not script/password/
secret data. It is not exposed as a network or MCP command. The peers grant each
other only necessary process/token query rights; authority-only Worker termination/
job-assignment rights are separate. Failure to establish those rights does not
trigger privilege escalation or disable identity validation.

## Verification

`scripts/verify_companion_next.sh worker-ipc` restores locked dependencies, builds
both IPC and WorkerRunner, and runs only the IPC suite. Portable tests use real
loopback duplex streams and inert executors/independent-supervisor fixtures. They
exercise bounded framing, exact binding, sequence/version/session rejection,
output, single execution, cancellation, lease expiry, ambiguous loss and stop
confirmation. They do **not** authenticate Windows processes or execute scripts.

Windows pipe ACL/SQOS, cross-account image/token/process access, nested Job Objects,
real PowerShell, service startup/recovery and Windows 11/10 ESU must be tested on
actual approved hosts. No native Windows test is silently represented by the
portable suite's zero-skip result. No 2.0, UI, public relay, Release or archive
checks are invoked by this scope.
