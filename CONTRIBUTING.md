# Contributing

Use small changes with a focused test for the affected module. Preserve current-user DVC compatibility and keep the relay service in its own repository. Update data-only protocol snapshots through a new version rather than importing sibling source.

Run the affected `dotnet test` project. Packaging changes also need the Python packaging tests. State which checks ran on real Windows and which were portable, cross-compiled, skipped or simulated. Never describe a transport fixture as unattended Windows or RDP/NLA acceptance.

Do not commit device identities, grants, enrollment requests, runtime databases, private keys, signed installers, machine-specific logs or credentials. Use generated test keys, reserved example addresses and temporary state. Production release keys belong outside the checkout.

Pull requests should explain the user-visible change, test evidence and remaining platform limitations. See SECURITY.md for vulnerability reporting.
