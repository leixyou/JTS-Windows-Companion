# Independent relay endpoint transport (2.5 alpha)

This net8.0 module is independent of RDP/DVC and does not reference a relay server
project. It implements the data-only [JTS Relay protocol 1 snapshot](../../Protocols/JTSRelay/1.0.0-alpha.1/PROVENANCE.md)
contract. It does not
install a service, enable network access, create keys, pair devices, or dispatch
commands. Agent/UI/service integration and live Windows acceptance remain open.

## Trust and use

- Supply an existing P-256 certificate with its private key as
  `RelayEndpointIdentity`; retain certificate ownership until connections close.
- Load `RelayPeerTrust` from independently confirmed local pairing policy. Never
  construct trust from a relay offer, cloud account or node device listing.
- `RelayControlClient` validates `/v1/info`, signs single-use HTTP challenges,
  publishes presence, lists admitted peers, requests sessions and polls offers.
- `OpenSecureChannelAsync(offer, pairedPeer)` claims a ticket once and returns an
  `SslStream` only after readiness, pinned mutual TLS, `jts-relay-v1` ALPN and an
  exact encrypted session/lane/device-pair binding. Control, file and RDP each
  use their own stream. Business framing and operation authorization sit above it.
- Default enrollment should select `Tls13`. `ExplicitWindows10Tls12` is only for
  an explicitly enrolled Windows 10 compatibility peer; it permits TLS 1.2 with
  ECDHE_ECDSA/AES-GCM only. There is no protocol retry or plaintext fallback.
- Certificate validation trusts the paired P-256 SPKI, with current validity
  dates; it does not rely on relay certificates or import OS roots. Inner TLS
  resumption/renegotiation are disabled. Outer HTTPS/WSS remains encrypted but
  skips carrier certificate PKI checks by default; `validateOuterCertificate:true`
  selects normal OS trust. This option never changes the inner device trust policy.
- All HTTP and WebSocket redirects are disabled. HTTP is accepted only for an
  explicitly enabled numeric loopback development origin. Tickets are bound to
  their issuing origin and never appear in URLs or generated `ToString` output.
- Cancel/close sessions when local grants are revoked. Transport authentication
  is not permission to execute: callers must still enforce local capabilities,
  users, task ownership, UAC, data roots, deadlines and operation consent.

The carrier preserves ordered bytes across arbitrary WebSocket fragments, uses
16 KiB writes, bounds HTTP/readiness/binding input, and rejects text after ready
and more than eight consecutive empty fragments. Node discovery is capped at
256 peers and polling at 32 offers; larger deployments need matching pagination
rather than silently truncating results.

## Targeted verification

The isolated [Companion Next entry point](../../README.Next.md) documents SDK and
runtime requirements, dependency locks and the single-module verification script.

```sh
dotnet test WindowsCompanion/tests/JTS.WindowsCompanion.Relay.Tests/JTS.WindowsCompanion.Relay.Tests.csproj
```

The independent suite includes real TCP/WebSocket-framed mutual TLS tests. On
macOS, the native .NET TLS backend exercises the explicit TLS 1.2 compatibility
path; it does not constitute Windows 11 TLS 1.3 or Schannel runtime evidence.

To additionally run the actual relay HTTP/upgrade/TLS composition test, set
`JTS_RELAY_TEST_DOTNET` to an absolute .NET runtime and
`JTS_RELAY_TEST_SERVER_DLL` to the absolute, locally built relay server DLL. That
test launches only a loopback node with temporary public-key admission, keeps
private keys in memory, tests all three lanes and deletes its own temporary node
database after stopping its child process. Without these explicit inputs, that
single external-server test is reported skipped, not passed.

The 2026-09-17 local run passed all 27 cases including actual relay composition.
Windows 10/11 TLS, platform certificate handling, installed identity protection,
grant revocation wiring and real service/RDP operation acceptance are still
required before distribution.
