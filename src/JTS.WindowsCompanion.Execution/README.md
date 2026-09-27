# Dedicated-account PowerShell execution (2.5 development)

This endpoint-owned .NET 10 library implements `IJobExecutor` for `powershell.v1`.
It is **not an installed unattended service** and is not composed into the daily
2.0 Agent, UAC broker or test echo host. The independent relay never references it.
The process running this executor must already be the explicitly provisioned
dedicated standard-account Worker. The configured expected SID is trusted local
setup state, not a request parameter; this library does not log on, provision,
elevate or select another user.

## Execution boundary

- Parent and suspended child primary tokens must match the configured canonical
  user SID. Built-in service accounts, built-in Administrator/Guest, elevation,
  high integrity, privileged operator/admin groups (including deny-only groups)
  and non-allowlisted privileges are rejected. A filtered admin token is not a
  standard Worker. Unexpected service-logon privileges are **not silently allowed**;
  the WorkerService launcher checks an explicit minimal SCM privilege list before
  launch, while this executor still verifies the actual token independently.
- Fixed system Windows PowerShell 5.1, `-NoProfile -NonInteractive`, no execution
  policy bypass. Only a constant bootstrap is in `-EncodedCommand`; UTF-8 user
  script arrives via stdin. No script in argv, environment, diagnostics or temp
  files. Request data cannot select an executable, account or environment.
- Environment is an exact allowlist of OS/profile/temp paths. PATH and
  PSModulePath are fixed system locations, not inherited parent values; no
  credentials, profiler hooks or user search paths are copied from the parent.
- Three locally connected, current-user-only pipes provide asynchronous stdin,
  stdout and stderr. Only their three child handles are inherited, using the
  explicit process handle list. The job and parent pipe handles are not inherited.
- `CreateProcessW` uses the atomic `PROC_THREAD_ATTRIBUTE_JOB_LIST`, a suspended
  initial thread and a kill-on-close Job Object without breakaway. After child
  token verification the thread is resumed. There is no launch-then-assign race
  or fallback to a process outside the job if an attribute/token check fails.
- Output is bounded by the required runtime sink; stdout/stderr bytes are merged
  in arrival-chunk order, not a terminal emulation or separate error log. The
  executor observes sink failure promptly, terminates the job, cancels pending
  I/O and zeroes temporary byte buffers. Managed JSON/script strings cannot be
  guaranteed erased from the managed heap.
- Cancellation, sink failure and normal root exit all terminate remaining job
  descendants. Completion waits for the job's active-process count to reach zero,
  not just for the initial PowerShell PID. Explicit native drain is bounded to
  three seconds; pending managed I/O receives cancellation and a one-second bound.
  Dispose retains kernel kill-on-close as a last resort, not proof of termination.

When termination cannot be attested, `JobExecutionStateUnknownException` makes
the runtime persist **Interrupted / EXECUTOR_STATE_UNKNOWN**, cancel queued work,
close new admission and fault the host scheduler. It must not become Cancelled,
Succeeded or an automatic retry. The service integration must surface this and
require operator recovery after checking the Worker; automatically constructing
a fresh runtime is not a safe recovery procedure. The runtime now persists an
authenticated pre-dispatch/quarantine guard, rejecting reattachment after an
uncertain outcome. Its local incident-bound recovery API still requires native
independent stop proof and protected service composition; see the
[runtime recovery contract](../JTS.WindowsCompanion.Runtime/README.md).

## This is not a script sandbox

Scripts have all of the dedicated account's actual Windows permissions. Working
directory validation is not a filesystem capability boundary: scripts can access
other files/registry/network resources allowed to that account. The standard
account must not be able to modify service identities, grants, configuration,
program files or trusted IPC. A separate protected authorization/service account
must own them. Do not instantiate the executor inside that authority process.

Job Objects contain ordinary inherited process trees, not external effects or
arbitrary brokered work. For example, WMI-created processes do not inherit this
Job Object. A task may already have written a file, sent a network request or
requested another service to act before cancellation. No rollback or complete
containment of arbitrary script side effects is claimed. UIA, login-session
interaction and individually approved UAC operations remain separate components.

References: Microsoft [process attributes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute),
[Job Objects and inheritance limits](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects),
[PowerShell CLI](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1).

## Explicit SCM startup integrity reduction

`WindowsStandardAccount.RestrictServiceCurrent(expectedSid)` is called only by
Authority service startup and Worker SCM startup, before Worker reports Running
or exposes peer access. It opens only this process's primary token. Medium,
High and System are the only admitted input integrity classes; Low,
Medium-Plus and unexpected classes are rejected. Existing exact-SID,
non-elevated, group and privilege checks run **before** any write, substituting
only the proposed Medium integrity value for that preflight. Administrator,
filtered-admin and dangerous-privilege tokens remain rejected, not sanitized.

For an otherwise accepted High/System token, the native call lowers only
`TokenIntegrityLevel` to Medium and then rereads all facts using the unchanged
Worker policy. Exact Medium readback is mandatory. Already-Medium tokens are
rechecked without a write. Ordinary `VerifyCurrent`, interactive execution,
the initialization helper and the parent installer are unchanged. No privilege
enablement, impersonation or fallback is added.

This does not prove native service compatibility: if Windows reports the service
token as elevated, the existing elevation rule still rejects it. Primary-token
integrity reduction also does not establish that existing process/token kernel
object labels permit later cross-account supervision; native peer ACL, token and
Job Object tests remain required. No object-label lowering or broader peer rights
are silently performed here.

References: Microsoft [integrity controls](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control),
[SetTokenInformation](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-settokeninformation),
[TOKEN_MANDATORY_LABEL](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_mandatory_label).

## Verification and still-open integration

The explicit `execution` scope runs portable payload/account-policy/lifecycle
fixtures plus opt-in Windows tests. Fixture lifecycle passes are not native
CreateProcess, Job Object, PowerShell, service-logon or account ACL evidence.
The Windows tests are marked skipped unless on 64-bit Windows 10+ with
`JTS_EXECUTION_TEST_WORKER_SID` explicitly set. Run them **as the dedicated standard
account**, not from an administrator terminal, on both Windows 11 and Windows 10
ESU; the OS guard is not a support promise for every Windows 10 installation.

The opt-in tests execute bounded fixture scripts only: Unicode stdout/stderr,
zero/nonzero exit and cancellation of an ordinary child process. They do not
install services, change ACLs or relax token checks. They must complete with no
skips on each approved Windows host. Further service integration must verify
blocked I/O/output flood, abrupt Worker/service termination, boot without login,
restricted service token creation, protected account/ACL/IPC ownership and real
control RPC across reconnect/revocation before P1/P2 can close.

The separate [WorkerIpc adapter](../JTS.WindowsCompanion.WorkerIpc/README.md) now
supplies authenticated Windows pipe endpoints and independent authority-owned
process supervision. Its native paths still need cross-account Windows checks;
the trusted SCM launcher/host now exists in WorkerService and the first-install
library now provides protected account/service provisioning. Packaged setup and
native acceptance remain missing. Mac XPC/
UI/MCP and pairing/consent also remain open. A library constructor or local fixture
is not proof those product routes exist.
