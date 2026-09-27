# Independent security-v2 data snapshot

Snapshot: 2.0.0-security.1, frozen 2026-09-27.
Source repository: https://github.com/leixyou/JTS-Relay
Source directory: protocol/security-v2

This is the owner's frozen working-tree artifact, identified by the included
SHA-256 inventories. It was not yet committed when copied. The source repository
baseline was f4b5f1b483ee9ff6ca2a311a47b0a9a715b4adb7; that baseline does NOT
contain this new snapshot and is not represented as its source revision.

The upstream PROTOCOL.md SHA-256 is
98b9635333bc18821eb1b9abebec87fc3a38c9a3f899b61d59cf0f295d1bb7e7.
The security-v2 subtree, including its SHA256SUMS, is copied byte-for-byte.
The root SHA256SUMS also covers this provenance file and the upstream inventory.

Only a specification and public fixed-key test vectors are included. The vectors
publish test scalars 1 and 2; they are not production credentials. There is no
relay source code, project dependency, private identity or runtime configuration.
Existing 1.0.0-alpha.1 and 1.0.0-enrollment.1 snapshots remain unchanged. New
endpoint builds consume the V2 signature contracts without V1 fallback.
