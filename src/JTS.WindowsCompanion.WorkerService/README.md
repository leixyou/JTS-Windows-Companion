# On-demand Worker service (2.5 development)

This client-owned .NET 10 module implements the fixed SCM Worker launcher and
one-shot service host. It does not create an account, install/configure a service,
hold a password, enable a route or provide a privileged general-purpose launcher.
It is not part of JTS Relay and does not change the installed 2.0 Companion.

## Required installation contract

An explicitly authorized installer must provision `JTSCompanionWorker25` as an
own-process, on-demand service under a dedicated local standard account. The
configured command must be the quoted, protected `JTS.WindowsCompanion.WorkerRunner.exe`
path followed by the exact `--service` switch. Automatic recovery actions,
triggers, delayed/automatic startup and interactive/shared-process service types
are rejected. No task is automatically replayed after Worker failure.

The required-privilege list must contain only `SeChangeNotifyPrivilege` and the
service SID must be enabled. The launcher checks the explicit configuration;
the executor independently checks actual parent/child tokens. SCM can remove
unneeded token privileges through its
[required-privileges configuration](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_required_privileges_infow).
Neither that configuration nor portable tests prove native token behavior.

The protected service DACL allows only SYSTEM/Administrators and the exact
authority SID. The authority gets QUERY_CONFIG, QUERY_STATUS, START, STOP and
READ_CONTROL (`0x20035`), not CHANGE_CONFIG, DELETE, WRITE_DAC, WRITE_OWNER or
SC_MANAGER_CREATE_SERVICE. The Worker gets no service-control ACE. See Microsoft's
[service access rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights).

Program files must be under Program Files, owned by SYSTEM, Administrators or
TrustedInstaller, with no untrusted modification/replacement permissions on the
binary, containing directory or existing ancestors. The existing Core project's
embedded-key P-256 release manifest verifies and locks the exact Worker executable;
an adjacent public key cannot replace the compiled trust anchor. Ordinary builds
without that anchor fail closed. Authenticode remains optional, not substituted
for this check. No change to Core or the old 2.0 release path is required here.

The release Worker is intended as a self-contained single-file win-x64 executable.
The launcher rejects adjacent same-name DLL/runtimeconfig sidecars; a production
packaging gate must still verify the complete signed inventory and publish layout.
Absence of those sidecars alone is not proof of correct bundling. No release
artifact or trusted unattended installer is delivered by this checkpoint.

## Startup, ownership and shutdown

The sole authority process serializes launch attempts, including uncertain-start
cleanup. Already-running services are not adopted or terminated. The SCM receives
only seven public rendezvous/identity values, never task scripts, keys or passwords.
The Worker PID comes from SCM; a held process must match the newly started time,
configured SID, protected image path and verified hash. The authority owns an
outer kill-on-close Job Object before sending any Execute frame.

The synchronous native start call is always observed to completion, even if the
caller cancels. Microsoft documents that
[StartService can block for 30 seconds](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew)
and returns before service readiness. Cancellation is therefore not an immediate
stop guarantee. Readiness has a ten-second bound after the native call (also
subject to the caller's earlier deadline); failure cleanup independently probes
for up to three seconds and verified process drain has its own three-second bound.
There is no automatic second StartService call. Unverified/ambiguous cleanup
raises `JobExecutionStateUnknownException`, not a successful cancellation.

The process-local launch gate is not a multi-process mutex. Production authority
composition must enforce one protected authority service/ledger owner. It must
also preserve the runtime's authenticated pre-dispatch/quarantine guard across
service restarts. Runtime/host reattachment now refuses unresolved execution;
native stop verification and local recovery consent are still required before
clearing that incident. See the [runtime recovery contract](../JTS.WindowsCompanion.Runtime/README.md).

Each side modifies only its own process/token DACL to permit peer identity reads.
Both peers get QUERY_LIMITED_INFORMATION, SYNCHRONIZE and TOKEN_QUERY; only the
authority additionally gets Worker TERMINATE/SET_QUOTA for job assignment. No VM
access, remote-thread, handle duplication or token duplication/impersonation right
is added. Existing unexpected exact-peer ACEs fail closed. Native default ACLs
and ability to make these narrowly scoped changes still need real Windows testing.

`WorkerRunner --service` hosts one task then reports stopped. STOP/SHUTDOWN
cancellation runs outside the SCM control handler; a separate five-second watchdog
exits a hung Worker process. Completion still requires the authority's independent
job drain, not just a service status or Worker message. UIA/UAC are not hosted here.

## Focused verification and remaining gates

Use `scripts/verify_companion_next.sh worker-service` with SDK/runtime 10. The
portable suite checks configuration/access policy, native-buffer bounds and the
startup/cancellation/ownership state machine using synthetic SCM facts and leases.
It builds WorkerRunner but never installs a service or exercises Windows APIs.

The IPC scope separately tests public launch-argument validation. A successful
non-Windows runner guard proves only safe refusal, not SCM interoperability.

The [authority service entry point](../JTS.WindowsCompanion.AuthorityService/README.md)
now composes the outbound Control host with this launcher, protected config/identity
and existing stores. Its own program preflight shares the release-manifest/ACL
verifier with this launcher; ordinary untrusted builds still cannot launch services.

Still required: consented transactional installation/removal, dedicated-account
credentials/rights and ACL provisioning, actual authority service acceptance and
local consent/recovery IPC, native incident-bound recovery verification, cross-account native
pipe/token/process access, single-file Windows publishing with release trust,
real SCM start/stop and UAC, boot without login, and Windows 11/10 ESU acceptance.
Mac XPC/UI/MCP, durable files, actual RDP and public-network/release gates also
remain open. Never work around missing native evidence by broadening privileges.
