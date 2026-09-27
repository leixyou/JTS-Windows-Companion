# Local durable control authorization

`DurableControlGrantStore` implements `IControlGrantProvider` and
`IDurableControlGrantProvider` in the endpoint, not JTS Relay. It persists
capability consent, not device pairing or a blanket MCP-client grant.
Initializing a store does not grant any permissions.

## Initialization and authority ownership

- Trusted local setup explicitly calls `CreateNew` once with a provisioned private
  directory and a required protector. Ordinary startup opens an existing store.
  Missing state, invalid format/header, wrong key or unsupported schema fails
  closed; no auto-create/reset/upgrade fallback exists.
- Database, parent, lease, WAL and SHM paths cannot be links/reparse points.
  Windows ancestor reparse points are rejected; Unix fixtures also reject a
  group/world-writable immediate parent. The Windows installer must additionally
  enforce and verify real owner/ACL boundaries. Path checks do not provision ACLs.
- On Windows use `CurrentUserDpapiTaskProtector` under the **authorization-owning
  account**, with the policy-specific protection purpose. Never use LocalMachine
  or plaintext fallback. Neither the arbitrary-script Worker account nor its
  processes may modify policy files or obtain this DPAPI identity. The service/Worker
  IPC boundary must keep mutation inside trusted local consent management.
- Call `ApproveLocally` only after Windows consent and separate pairing checks.
  No corresponding mutation operation exists in control RPC or MCP. This library
  does not provide a dialog or proof that its caller showed one; consent and
  account isolation remain required integration gates.

## Persistence and immutable IDs

The versioned SQLite WAL database uses full synchronous commits, an exclusive
process lease and a bounded registry (4,096 records by default, 16,384 constructor
ceiling). A protected header detects account/key mismatch even for an empty store.
Records protect permissions, expiry, approval and revocation timestamps before
SQL/WAL writes. Protection context binds store, device fingerprint and grant ID.
Only opaque IDs and owner fingerprints are indexed as minimum metadata.

Exact duplicate approval returns the original record. Changes to owner, operations,
job kinds, expiry or detached permission under an existing ID conflict. Renewal
requires a new ID, fresh local approval and explicit handling of the old grant.
Every lookup rereads/authenticates the record and checks owner, approval time,
expiry and revocation; no stale allow cache exists.

Revocation retains a protected tombstone, including for previously unknown IDs,
so delayed approvals cannot reuse them. Expired records and tombstones are not
silently evicted. A full registry refuses new IDs but can revoke known ones.
Registry rollover is not automatic and must not erase historical denials.

## Live revocation and failure reporting

Use local `RevokeGrantDurablyAsync` for a running host. It commits through the
durable provider before immediate task/connection cancellation. Cancellation of
the caller after commit cannot skip the hook. Providers must not throw cancellation
after committing. Non-durable providers cannot claim durable revocation.

Persistence failure stops host admission, streams and the scheduler, returning
`CONTROL_REVOCATION_NOT_DURABLE`. This means durable revocation was **not confirmed**,
not proof of either rollback or success. Inspect/repair with trusted local management
before explicitly resuming; do not blindly auto-restart with the old policy.
Distinguish persisted policy, cancellation requested and actual executor drain;
a timeout does not prove a process stopped.

Dispose the host before its policy/job stores and protectors. On normal restart,
tombstones deny queued detached tasks before execution. Running work stays
interrupted/unknown under the existing runtime recovery rule.

## Threat and acceptance boundaries

Protected records detect damage/substitution, not malicious administrators, a
hostile process running as the protection-owning account, or rollback of an entire
old valid database snapshot. SQLite durability is not a hardware monotonic
anti-rollback guarantee. Endpoint recovery must not restore old grants and silently
enable routes: re-consent/rotate the authority epoch before resuming after rollback
or identity recovery. That workflow remains a release gate. Relay backup/restore
instructions cannot authorize restoring endpoint grants.

Tests exercise actual SQLite reopen, protected records, tombstones, corruption,
store/grant substitution, limits, host cancellation and fresh checks after restart.
Encryption keys and consent are disposable test fixtures. Windows DPAPI, ACLs,
account separation, installation recovery, consent UI and actual process-tree
cancellation still require Windows evidence.
