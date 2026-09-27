# Durable device pairing (2.5 development)

This client-owned endpoint library stores explicit local pairing policy. It is
not the independent relay server, a remote enrollment endpoint, Windows consent
UI, service installer or capability/MCP authorization store. The relay's admission
list, an RDP connection and old DVC permissions never create a pairing here.

The separate [identity storage component](Identity/README.md) now provides explicit
Windows current-user creation/loading, expected account/device/enrollment binding
and identity lease ownership. Native acceptance and service/consent composition
remain required; the pairing registry still takes an already established identity.

## Authority and lifecycle

- Provision the protected directory and identity first. `CreateNew` exclusively
  creates a new database; ordinary construction opens existing state only. Missing,
  corrupt, incompatible or wrong-identity state must not trigger automatic reset.
- Supply the exact local device identity and a trusted `ITaskPayloadProtector`.
  Production Windows composition must use the protected authority account's
  DPAPI CurrentUser identity and restrictive ACLs. There is no plaintext/default
  protector. The arbitrary-script Worker must not read or modify this directory,
  keys, configuration or binaries; merely choosing a path does not enforce ACLs.
- `ApproveLocally` is callable only by the trusted local approval workflow after
  Windows displays the peer identity, requested lanes/grants and expiry and the
  user confirms. Its matching `verifiedPeerFingerprint` argument is a host
  assertion, **not evidence that consent UI actually ran**. That integration is
  still required. There is no remote approval RPC or automatic enrollment.
- Each immutable epoch has a nonempty ID, pinned peer identity/TLS policy, expiry
  and explicit lanes. A peer has at most one current epoch, even when expired.
  Revoke before replacing it; a repeated identical approval is idempotent, while
  reusing an ID with changed policy or revocation is rejected.
- Control, File and RDP grant IDs are separate. Unknown lanes, grants for an
  unapproved lane and duplicate IDs across lanes are rejected. Omitted grant IDs
  mean no capability grant; re-pairing never inherits old grants. The separate
  capability authority must still approve each operation. MCP-client consent
  remains a third boundary, not a property of this database.
- `RevokeAsync` commits the exact epoch first. Unknown epochs may receive durable
  tombstones; wrong-owner or stale-epoch calls cannot revoke a newer active pair.
  Successful commit does not subsequently throw caller cancellation. The caller
  must then enforce live task/session stop; the store alone cannot terminate work.
- The Control adapter binds its local identity to the relay client before host
  creation and exposes only Control policies/IDs. Live re-pair after owner revoke
  requires a fresh authorized control-service lifetime. File/RDP business adapters
  are not implemented by this module.

## Storage and bounds

SQLite uses WAL, FULL synchronization, a process-exclusive lease and bounded page/
journal settings. Schema 1 has a protected header binding the store UUID and local
device. Strict versioned binary policy records are protected with purposes bound
to that store, local device, controller and epoch. This is a local storage format,
not a change to the frozen relay wire protocol.

Database selectors (device/epoch IDs and current/revoked index state) are metadata,
not encrypted secrets. Policy, grant IDs and approval/revocation times are sealed.
Reads authenticate selectors against the protected record. Invalid framing,
oversized records, unsupported policy, wrong protector, changed header or foreign
record substitution fail closed; no weak-auth or key fallback exists.

Default capacity is 256 total epochs, configurable up to 4096; revoked epochs count
and are never automatically pruned or evicted. Each epoch accepts at most 4096
grant IDs across all lanes. Local management pages contain at most 64 records.
Admission closes at capacity rather than forgetting revocation. `ListLocally` is
not a remote operation or an authorization result.

Paths must be absolute and provisioned. Database/lease/WAL/SHM and parent reparse
points are rejected; Windows additionally checks path ancestors. Portable checks
do not prove Windows ACL ownership or prevent a privileged same-account attacker.
Record deletion may deny availability. Whole valid snapshot rollback and compromise
of the protector account are not detected by these seals. Backup/identity recovery
must re-enroll or rotate authorization before re-enabling the route; it must not
silently revive old grants. No automatic disaster-recovery workflow is supplied.

## Focused verification

Run `scripts/verify_companion_next.sh pairing` with SDK/runtime 10. Tests use
private temporary SQLite state, ephemeral authenticated fixture keys and simulated
approval. They cover reopen, three-lane isolation, permanent revocation, re-pair,
tamper/cross-store substitution, strict records, bounds, lease and identity checks.
They do not establish Windows consent, DPAPI, ACL, service installation/boot or
public endpoint acceptance. Integration is separately exercised by the Control
module's selected durable-pairing and actual local relay-process tests.
