# Authenticated Companion control host (2.5 development)

`CompanionControlHost` composes the client-owned Relay transport and Runtime job
ledger. It is not the standalone JTS Relay server, an installer, a PowerShell
executor or a public HTTP endpoint. It does not reference the sibling relay tree.

Its direct stream entry point, `ServeAsync`, performs pinned mutual TLS and exact
control-lane binding itself. `ServeRelayAsync` uses the sealed relay client's
authenticated channel path before the same dispatcher. No public plaintext dispatch method exists. Every
request uses a required local `IControlGrantProvider`; authenticated device identity
does not confer execution permission. See the [endpoint control contract](../../../Protocols/JTSCompanion/control-v1.md).

The service also dispatches independently authorized file/RDP lanes through
`RelayFileLane` and `RelayRdpLane`, after the same pinned TLS/binding step. It uses
one offer poller, bounded sessions and common pairing cancellation. File requests
revalidate their lane grant; RDP has an independent two-second authority watcher.
The exact business framing and owner-delegated install flow are documented in
[outbound endpoint installation](../../docs/RELAY_ENDPOINT_INSTALLATION.md).

## Composition requirements

- Provision a private runtime store with the correct execution account's payload
  protector. Supply a durable, current local grant provider and a real executor;
  there are no production allow-all or echo defaults.
  The available `DurableControlGrantStore` is documented in
  [policy storage and its account boundary](POLICY_STORAGE.md). Policy authority
  must not become writable by the arbitrary-script Worker.
- Start one host per store and route only explicitly paired control sessions to it.
  The host serially schedules queued jobs, wakes on submission/recovery, and tracks
  aggregate owner control presence across multiple authenticated connections.
  A quarantined job ledger rejects construction before the scheduler starts, even
  after reopening. Recovery is a trusted local authority operation, never a control
  RPC. See [runtime provisioning/migration/recovery](../JTS.WindowsCompanion.Runtime/README.md).
- Observe `Completion`: unexpected scheduler failure shuts down admission and
  streams. Connection exceptions must be handled by the owning service; do not
  log raw payloads, outputs, credentials or arbitrary exception messages.
- Prefer local `RevokeGrantDurablyAsync` with a durable provider: it persists local
  revocation before calling `RevokeGrant` and stops the host on persistence failure.
  For other providers, persist revocation first, then call `RevokeGrant`. The immediate
  cache protects races but is not a replacement for durable revocation. It is
  bounded and fails closed on exhaustion rather than forgetting old denials.
- On host shutdown, cancel/drain sessions and executor before disposing the store.
  A failed drain is a visible error; do not report Windows processes stopped just
  because a timeout elapsed. The owner remains responsible for carrier cleanup
  when admission fails before session registration.
- Keep the independent control lease alive with authorized serialized polling
  while interactive jobs should continue. Idle timeout is a disconnect, not an
  unattended permission grant. Device pairing, capability grants and MCP-client
  grants must be integrated separately before exposing this in the daily app.

## Outbound control-service lifecycle

`CompanionRelayControlService` composes the control host, existing relay client
and an explicitly supplied local `IControlRelayPairings` authority. It is a
callable service lifecycle, **not an installed Windows SCM authority service**.
It does not create keys, install accounts, open a listener, discover trust from
relay admission, or infer permissions from an RDP/DVC profile.

- Supply an already provisioned identity/client/store, durable capability grants,
  protected pairing authority and the supervised Worker IPC executor. The caller
  retains their ownership until the service and its tasks fully drain.
  `IControlRelayPairings.LocalDeviceId` must match the relay client's identity;
  mismatch is rejected before the host/runtime attaches. The explicit
  `DurableControlRelayPairings` adapter uses the independent [Pairing registry](../JTS.WindowsCompanion.Pairing/README.md),
  exposes only Control-enabled pairings and projects only their Control grant IDs.
- Pairings have immutable local epoch IDs, pinned peer/TLS policy, expiry and
  explicitly approved capability-grant IDs. A newly confirmed pairing does not
  automatically regain old grants. The pairing provider must persist revocation
  of the exact epoch before returning; stale IDs must not silently revoke another
  epoch. It must not be writable by the script Worker.
- Start `RunAsync` once and observe its completion/status. Presence refreshes
  every 15 seconds; offers poll every two seconds. Eligible control offers run
  concurrently without blocking presence. At most 16 control sessions, four per
  owner, are active. File/RDP offers are deliberately left for their respective
  future business handlers, never passed to the control dispatcher.
- Connection attempts are deduplicated for 65 seconds in a bounded 512-entry
  ID-only cache. No ticket is retried after uncertain upgrade/handshake, and no
  business command is replayed by reconnect. Capacity defers offers; it never
  removes an earlier attempt merely to admit a new one.
- Transient connection/HTTP 408/429/selected 5xx/deadline errors use exponential
  backoff, jittered within one-to-thirty-second bounds (first delay 0.8–1 second).
  Trust/authentication/protocol incompatibility stops instead of silently
  downgrading or looping with invalid credentials. A single failed endpoint
  channel is isolated and exposes a fixed error code, never raw exceptions/tickets.
- Pairing policy is read before acceptance and every authorized request/dispatch,
  including resumed detached work. A task deadline cannot exceed pairing expiry.
  Active pairing changes are reconciled during polling; their immutable epoch,
  TLS policy, expiry and grant-ID set must match. Pairing expiry also cancels the
  session independently of node availability; an individual session is capped
  at 24 hours. This is not a 24-hour stability result.
- Local `RevokePairingAsync` persists first, then cancels all work for that owner,
  including detached jobs, and closes its sessions. Cancellation after successful
  persistence cannot skip live enforcement. Failed persistence stops the service
  without claiming durable revocation. Local enrollment can explicitly call
  `ActivatePairingAsync` for the exact newly persisted epoch. It serializes against
  revocation and offer acceptance, drains old sessions and execution, and admits
  only the new epoch's control grants. Owner/grant tombstones and cancelled jobs
  are retained. A second revocation removes this grant-scoped admission; repeating
  the same activation does not interrupt its new live sessions. This is a local
  composition API, never a remote control operation.
- Other owners and their capability records are not rewritten. Pairing, endpoint
  capabilities and MCP-client authorization remain separate approval boundaries.
  Unexpected scheduler failure closes networking. Shutdown cancels sessions and
  the scheduler/Worker; an unconfirmed drain is an error, not a stopped claim.

Protected pairing persistence and identity loading are implemented; the new
[authority SCM entry point](../JTS.WindowsCompanion.AuthorityService/README.md)
composes them with this host and the supervised Worker. Native Windows consent,
service/account/ACL acceptance and installer are still required, along with Mac XPC/UI/MCP, real Windows
Worker execution, file/RDP service dispatch and public end-to-end acceptance.
No permissive pairing provider or production executor default is supplied.

## Focused verification

`scripts/verify_companion_next.sh control`, with a selected
.NET 10 SDK/runtime. Tests create fresh keys, private temporary SQLite state and
inert executors, and remove that fixture state after completion. No real Windows
account, service, credential, server or installed Companion is changed.

`RelayControlServiceInteropTests` additionally needs explicit `JTS_RELAY_TEST_DOTNET`
and `JTS_RELAY_TEST_SERVER_DLL` paths; otherwise it is reported skipped. It launches
a disposable loopback relay process, not a deployed node or sibling-source build,
and verifies automatic offer acceptance, pinned inner TLS, control RPC, default
disconnect cancellation, detached reconnect/query/cancel, output/idempotency and
pairing revocation, using the durable pairing registry and a test-only local
approval fixture. Endpoint keys stay in memory; only disposable public admission
and protected temporary state are written. It uses an inert executor, not PowerShell; on Mac it explicitly uses
the TLS 1.2 fixture policy, not Windows 11 TLS 1.3 evidence.
