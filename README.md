# JTS Windows Companion

**一个 JTS 终端，让 AI 像操作本机一样，直接调用远程 Windows 的命令、文件和界面能力。**

JTS Windows Companion brings a Windows machine into the [JTS Terminal](https://github.com/leixyou/JTS-Terminal-2.0) workspace. AI clients use one terminal to request remote commands, file operations and semantic Windows UI Automation, with structured results returned to the same workflow. Companion executes authorized operations on Windows and keeps device identity, capability grants and Windows account boundaries in force.

For a directly reachable machine, the current-user Agent communicates through the RDP dynamic virtual channel, including over a LAN. When a direct path is unavailable, the outbound relay endpoint connects through the independently deployable [JTS Relay](https://github.com/leixyou/JTS-Relay), which forwards encrypted control, file and RDP streams. Semantic UI Automation runs in the interactive Windows session through the current-user Agent; the relay provides connectivity.

**Status: developer preview.** This source snapshot includes the current-user RDP Companion and the newer outbound relay endpoint. Portable tests and cross-compilation do not certify installation, unattended boot, Windows account isolation, UI Automation, or a real Windows RDP/NLA session. Release acceptance for the new relay route remains open. No installer or production signing key is included.

## Components

| Component | Purpose |
| --- | --- |
| Current-user Agent | Runs inside the interactive Windows session. Exposes PowerShell, sandboxed files and semantic Windows UI Automation through the RDP dynamic virtual channel. |
| Authority service | Opens outbound relay connections and enforces paired-device identity, capability grants and durable task state. |
| Worker | Executes authorized commands under a separate, restricted Windows account. |
| File lane | Transfers bounded, hash-verified chunks within a configured shared root. |
| RDP lane | Bridges the authenticated tunnel to the Windows RDP listener at `127.0.0.1:3389`. |
| Setup and native bootstrap | Install authenticated release payloads. The current-user and unattended installers have separate installation boundaries. |

Enabling AI control for a device supplies that device's pairing delegation. Delegation is bound to device identity and revocable grants; it does not remove command, file, operating-system or elevation boundaries. See [delegated enrollment](docs/DELEGATED_ENROLLMENT.md).

## Encryption and network requirements

Both endpoints connect outward to the relay over **HTTPS/WSS**. Server certificate chain, hostname and validity checks for this outer carrier are skipped by default. This is an explicit compatibility policy: transport bytes are encrypted, but the outer carrier certificate is not used to authenticate the relay. There is no production HTTP fallback.

Within that carrier, the Mac and Windows endpoints require **mutual TLS with pinned device public keys** and separate control, file and RDP grants. The relay forwards encrypted application bytes and cannot decrypt them. It can observe connection metadata, delay traffic or refuse service. Do not remove the inner identity checks when configuring an untrusted or self-signed relay. A Windows 10 TLS 1.2 compatibility mode is explicit; it retains device pins.

The relay must admit both endpoint public identities before accepting sessions. Deploy your own [JTS Relay](https://github.com/leixyou/JTS-Relay), choose its HTTPS URL, and use that URL in enrollment. There is no bundled public relay or default live server. The optional HTTP support in test fixtures is restricted to explicit loopback development tests.

## Build from source

The repository is self-contained. It does not compile or import source from a sibling relay or Mac checkout. `Protocols/` contains data-only interoperability contracts.

- Current-user solution: .NET SDK/runtime 8 or later, with the .NET 8 runtime available for tests.
- Relay/Authority solution: .NET SDK 10 and runtime 10; its Relay library still targets .NET 8.
- Interactive Windows components: Windows 10/11 x64 and the Windows Desktop targeting/runtime packs.
- Native unattended installer: Python 3.11+, CMake 3.24+, Windows x64 MSVC, or MinGW-w64 for a diagnostic cross-build. Its packaging script pins SDK 10.0.401 and runtime 10.0.12.

```sh
# Portable development build; native Windows features still need Windows verification.
dotnet restore JTS.WindowsCompanion.sln
dotnet build JTS.WindowsCompanion.sln --configuration Release --no-restore

# The Next solution requires SDK 10.
dotnet restore JTS.WindowsCompanion.Next.slnx --locked-mode
dotnet build JTS.WindowsCompanion.Next.slnx --configuration Release --no-restore

# Choose an individual portable test project.
dotnet test tests/JTS.WindowsCompanion.Control.Tests --configuration Release
python3 -m unittest scripts.tests.test_companion_next_package scripts.tests.test_companion_bundle_inspection scripts.tests.test_companion_native_inspection
```

On macOS/Linux, ordinary current-user builds deliberately exclude the Windows UIA implementation. Build production Windows/UIA artifacts on Windows. The explicitly named cross-lab publisher enables the Windows branch for diagnostic cross-compilation; it is not a Windows acceptance result.

The current-user publisher is `scripts/build-current-user-setup.ps1`. The unattended publisher is `scripts/build_companion_next_setup.py`. Both verify release manifests and exact payload hashes. Keep publisher private keys outside the checkout and packages. Development mode generates a disposable key and labels its installer unsuitable for production distribution. See [current-user installation](docs/CURRENT_USER_SETUP.md) and [unattended packaging](packaging/README.md).

## Connect a Windows machine

1. Build and inspect the appropriate Windows installer from this source, or use a separately authenticated release when one is available.
2. Use JTS Terminal to export a fresh, device-bound delegation request and its SHA-256. Transfer that public request to the intended Windows machine.
3. Install the current-user Agent in the intended interactive user session if semantic UI Automation is needed. Run the separate unattended Setup with its HTTPS relay URL, delegated enrollment request, request SHA-256 and a new public enrollment output path. Windows may require its normal UAC consent.
4. Admit the exported Mac and Windows public identities on your relay, then import the Windows enrollment bundle in JTS Terminal. Private device keys remain on their own endpoint.
5. Verify an actual command, file round trip and RDP session before using the route for unattended administration. Semantic UIA requires the interactive Agent's separate DVC authorization.

The unattended preview implements first installation. Upgrade, uninstall and automated recovery for that route are not supplied. The installer does not automatically enable a Windows RDP listener, firewall rule or account logon policy. See [the exact relay installation and lane contract](docs/RELAY_ENDPOINT_INSTALLATION.md) before deploying it.

## Documentation

- [Current-user Agent architecture and verification](README.CurrentUser.md)
- [Relay/Authority development modules](README.Next.md)
- [Elevation and managed execution](docs/ELEVATION_AND_MANAGED_MODE.md)
- [Windows QA checklist](docs/REAL_WINDOWS_QA_RUNBOOK.md)
- [Optional Mac/.NET transport interoperability fixture](tests/MacInteropHost/README.md)
- [Contribution guide](CONTRIBUTING.md), [security reporting](SECURITY.md) and [third-party notices](THIRD-PARTY-NOTICES.md)

## License

Licensed under [Apache-2.0](LICENSE). Dependency licenses are listed separately in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
