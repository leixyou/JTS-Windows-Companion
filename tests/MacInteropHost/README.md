# Mac/.NET interoperability test host

This executable is a **test fixture**, not a Windows service, production Companion, installer or relay server. It references this repository's actual Relay and Control modules. The command executor is an inert echo/block fixture; it never invokes a shell or loads an installed user's grants.

The [Mac transport tests](https://github.com/leixyou/JTS-Terminal-2.0/tree/main/Packages/JTSCompanionTransport/Tests/JTSCompanionTransportTests) select an already built host with `JTS_INTEROP_DOTNET` and `JTS_INTEROP_HOST_DLL`. Neither repository reads the other repository's source at build time.

## Build and run the local fixture

From this repository root, use a .NET 10 SDK/runtime. Place build artifacts outside the source checkout:

```sh
dotnet build tests/MacInteropHost/InteropHost.csproj \
  --configuration Release --artifacts-path /absolute/path/to/interop-artifacts \
  -p:RestoreLockedMode=true
```

Then, in a separate checkout of the Mac repository:

```sh
export JTS_INTEROP_DOTNET=/absolute/path/to/dotnet
export JTS_INTEROP_HOST_DLL=/absolute/path/to/interop-artifacts/bin/InteropHost/release/InteropHost.dll
swift test --package-path Packages/JTSCompanionTransport --filter InteropTests
swift test --package-path Packages/JTSCompanionTransport --filter ControlInteropTests
```

With no command-line arguments, the host reads a bounded JSON request from standard input and creates a short-lived P-256 identity. It listens only on a randomly selected loopback port, returns its public identity and port, then exercises pinned inner TLS and either an echo exchange or the actual `CompanionControlHost`. Its ephemeral state is temporary and removed on normal shutdown. It has a 30-second deadline. On macOS the fixture explicitly uses the TLS 1.2 compatibility policy; device pinning remains required.

## Optional HTTPS relay fixture

`--public-relay-fixture` is explicitly selected by `PublicRelayInteropTests`. That test additionally requires:

- `JTS_PUBLIC_RELAY_ORIGIN`: an authorized HTTPS relay origin.
- `JTS_PUBLIC_RELAY_TEST_IDENTITIES`: an external protected directory containing the disposable `controller.key` and `companion.key` test identities.
- Those two disposable public identities must already be admitted on that relay. The fixture does not update relay admission.

Do not use production device or release keys. No identities, passwords, deployed URLs or signing keys are included here. The source's outer HTTPS/WSS certificate-validation default and inner pinned mutual TLS are unchanged.

The fixture uses actual Control, File and RDP lane handlers with temporary grants and directories. Its RDP destination is a test-owned echo listener on `127.0.0.1:3389`; if that port is already occupied it fails rather than contacting the existing process. Run it only on a test host where that port is free. It has a three-minute deadline and sends only public fixture metadata on standard output.

A successful run proves the selected transport and message exchanges. It does **not** prove Windows installation, DPAPI, UAC, unattended service boot, PowerShell execution, Windows UI Automation, or a real RDP/NLA login. The public fixture explicitly reports `nativeWindows: false`.
