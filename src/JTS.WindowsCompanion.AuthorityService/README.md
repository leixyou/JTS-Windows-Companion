# Low-privilege authority service composition (2.5 development)

This client-owned .NET 10 SCM entry point composes identity, pairing, capability,
durable jobs, outbound Control and the separate supervised Worker. It is not JTS
Relay, an installer or an installed/released Companion. File/RDP handlers, local
consent IPC and Mac integration remain separate unfinished work.

## Fixed startup contract

- 64-bit Windows only; exact `--service` switch only. SCM service name is
  `JTSCompanionAuthority25`; ServiceMain accepts no additional start arguments.
  No script, password, config path, arbitrary executable or trust-key override
  can be supplied through argv. There is no provisioning or console-run switch.
- An explicitly approved installer must provision a dedicated standard authority
  account different from the standard Worker. Startup verifies actual SID,
  groups, privileges and integrity using the Execution module's token policy.
  SYSTEM, built-in service accounts, elevated/admin and filtered-admin tokens
  are rejected. Native service-token behavior still needs verification; do not
  broaden the policy merely to make an unverified installation work.
- Both service executables require protected single-file Program Files locations,
  trusted program/ancestor ACLs and the existing embedded-key release manifest.
  Own executable is locked for the lifetime; Worker trust/config is also rechecked
  on each launch. Adjacent public keys cannot replace the anchor. Authenticode
  remains optional, manifest trust mandatory. Builds without the embedded key
  refuse startup. Full bundled/native-library inventory is still a release gate.

State is fixed under Windows CommonApplicationData:

```text
JTS Terminal/Companion25/authority/
  authority.json
  identity.sealed
  pairings.sqlite
  control-grants.sqlite
  jobs.sqlite
```

Protected schema-1 configuration requires explicit `enabled: true`, enrollment
UUID, expected device pin, authority SID, HTTPS origin and exact Worker account/
SID/image. Unknown/duplicate fields, URL credentials, HTTP (including loopback),
path/query/fragment or the same authority/Worker account fail. The supplied example
is deliberately disabled and incomplete, not a ready provisioning artifact.

Startup validates current account, own program trust and protected configuration,
then identity/database/lease/WAL/SHM paths and ACLs. It opens pre-existing identity,
pairing, grants and jobs; rechecks SQLite sidecars; verifies Worker image; finally
constructs Control with `WindowsWorkerJobExecutor` and `WindowsScmWorkerLauncher`.
The job store uses authority-account DPAPI. Worker receives only authorized payload
over exact-process IPC and has no direct authority-state access.

**Startup never provisions missing state, migrates old databases, clears quarantine,
approves a peer/grant or changes account/service ACLs.** Queued detached work still
requires current pairing/capability reauthorization. Unknown execution blocks host
attachment; restarting the service does not count as stop/recovery proof.

## Runtime and stop

SCM Running means local composition completed, not that a relay/peer is online.
Control owns one presence/poll loop for control, file and RDP sessions without an
RDP window. HTTPS/WSS remains encrypted while outer certificate PKI checks are
skipped by default. Inner pinned mutual TLS remains mandatory; no development HTTP
is enabled. The first presence waits with bounded backoff for node admission;
after admission, node authorization failure retains the fatal policy. See the
[installation/lane contract](../../docs/RELAY_ENDPOINT_INSTALLATION.md).

Startup refuses certificates within two minutes of expiry. The live monitor polls
at most once a minute and cancels at that lead time; clock advances and monitor
failure also stop admission. No automatic key rotation or trust renewal occurs.
Explicit renewal/re-enrollment and user warnings remain UI/installer work.

SCM stop/shutdown cancellation runs off its control handler. The lifecycle cancels
and drains Control/Worker before releasing relay, job/grant/pairing stores,
identity and file leases in reverse order. Failed drain retains resources for an
explicit retry or process exit. Status/runtime failures still attempt cleanup.
Drain is bounded to 15 seconds. Native startup/stop watchdogs exit a hung authority
after 30/20 seconds. Exit is **not proof of Worker-tree termination**; the durable
execution guard/quarantine remains necessary for later recovery.

Transitions follow the [SCM service-state contract](https://learn.microsoft.com/en-us/windows/win32/services/service-status-transitions).
Service exit 70 is failure, 71 unconfirmed drain/release or watchdog exit, 72 identity
renewal required. None is a successful remote-task cancellation receipt. Native
SCM callbacks, process-tree behavior and no-login boot remain unverified.

## Focused verification and remaining gates

`scripts/verify_companion_next.sh authority-service` runs only configuration,
lifecycle and ownership checks with locked dependencies. Runtime/status adapters
are fixtures, not SCM/DPAPI/PowerShell. Related Worker-service tests cover the
shared program/launch policy. Mac refusal is a guard result, not Windows evidence.

Still required: consented transactional account/service/ACL/identity/store installer;
no-login profile behavior; secure Agent-to-authority approval/revocation/recovery IPC;
rollback/upgrade/removal; native Worker/service start-stop and Win11/Win10 ESU;
certificate renewal and self-host node trust; Mac XPC/UI/MCP, durable files, actual
RDP, public routes and release gates. No account/service install, new grant or
public deployment is performed by building this entry point. Keep old 2.0 intact.

The separate [AuthorityProvisioner](../JTS.WindowsCompanion.AuthorityProvisioner/README.md)
now implements authority-account first initialization into an isolated disabled
stage. It does not publish this service's live directory/configuration or install
accounts/services; the transactional installer and native acceptance remain open.
