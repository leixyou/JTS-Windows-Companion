# First-install service registrations

`WindowsInstalledServices` only creates the two fixed 2.5 services during an
explicit elevated first-install transaction. It neither modifies 2.0 services
nor adopts pre-existing registrations. It retains the original `CreateService`
handles immediately, before any subsequent configuration can fail.

`RegisterDisabled(authority, authorityPassword, worker, workerPassword,
programDirectory, enrollmentId)` validates distinct exact account/enrollment
bindings and both protected manifest-verified executables. Password pointers are
used only for SCM calls; this object does not copy, persist or log passwords.
The caller owns their lifetime. Both services remain disabled and stopped.

Each is own-process under its separate local account, with an exact quoted image
path plus `--service`. The enrollment ID and role are written into the service
description. The service SID is unrestricted (not a built-in service user), only
`SeChangeNotifyPrivilege` is requested, and there are no recovery actions,
triggers, delayed starts or protected-process launch. SCM ACLs are protected,
administrator-owned and grant SYSTEM/Administrators service control. Only the
Worker registration additionally grants its authority account exactly `0x20035`.
The implementation re-reads configuration, description, account SID, optional
settings and ACL after registration; settings are not considered correct merely
because write APIs succeeded.

Before `ActivateAsync(token)`, the caller must have completed publication and
durably journaled activation intent. The method irreversibly records an activation
attempt before enabling either service, changes Worker to demand-start and
Authority to automatic-start, then starts **only Authority**. The synchronous SCM
start RPC is observed to completion, followed by a 35-second bounded observation
for local SCM Running. Cancellation or any ambiguous/failing start preserves the
installation; this method never attempts destructive cleanup or claims remote
online/pairing/business acceptance.

`RollbackNeverActivated()` refuses after an activation attempt. Before that, it
requires every owned service still disabled/stopped and uses only original
creation handles to mark deletion. It never reopens an arbitrary name to delete
it. Deletion may remain pending if another process retains a diagnostic handle.
If rollback fails, the outer transaction must preserve dependent accounts/state
for explicit recovery. A process crash loses these handle-based ownership proofs;
the enrollment marker alone is insufficient authority for automatic cleanup.
`Dispose()` closes handles only, and does not remove or stop a service.

Native installation remains unaccepted until tested on Windows. In particular,
SCM service token integrity/elevation must be reconciled with the existing strict
standard-account validator; this module deliberately does not weaken it. Service
startup, unattended boot, DPAPI/profile continuity, ACL negative tests, failed
activation, rollback and old/new coexistence need real acceptance.

## Native API references

- [CreateServiceW](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew): create-only handle ownership, quoted image path and service account.
- [Required privileges](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_required_privileges_infow): explicit list removes unneeded privileges at the next start.
- [Failure actions](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_failure_actionsw): clearing requires a non-null pointer with zero action count, not a null unchanged pointer.
- [Trigger configuration](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_trigger_info): clearing an already-empty trigger list is an invalid operation; fresh empty state is instead inspected.
- [SetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo): protected DACL assignment uses the exact service handle.
- [DeleteService](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-deleteservice): marks deletion until all handles close and the service is stopped.
