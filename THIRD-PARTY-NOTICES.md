# Third-party notices

This source repository references the packages below; dependency source and restored binaries are not vendored. Versions and hashes are recorded in the checked-in NuGet lock files. License metadata was inspected from the corresponding locally restored NuGet packages.

The project license does not replace dependency licenses. When distributing self-contained installers, retain applicable .NET runtime, SQLitePCLRaw/SQLite and compiler-runtime license/notice files for the exact payload. The source snapshot is not an installer distribution.

| Package | Version | Upstream license metadata | Source |
| --- | --- | --- | --- |
| Microsoft.CodeCoverage | 17.12.0 | MIT | [Upstream](https://github.com/microsoft/vstest) |
| Microsoft.Data.Sqlite | 10.0.12 | MIT | [Upstream](https://github.com/dotnet/dotnet) |
| Microsoft.Data.Sqlite.Core | 10.0.12 | MIT | [Upstream](https://github.com/dotnet/dotnet) |
| Microsoft.NET.ILLink.Tasks | 10.0.12 | MIT | [Upstream](https://github.com/dotnet/dotnet) |
| Microsoft.NET.ILLink.Tasks | 8.0.31 | MIT | [Upstream](https://github.com/dotnet/runtime) |
| Microsoft.NET.Test.Sdk | 17.12.0 | MIT | [Upstream](https://github.com/microsoft/vstest) |
| Microsoft.TestPlatform.ObjectModel | 17.12.0 | MIT | [Upstream](https://github.com/microsoft/vstest) |
| Microsoft.TestPlatform.TestHost | 17.12.0 | MIT | [Upstream](https://github.com/microsoft/vstest) |
| Newtonsoft.Json | 13.0.1 | MIT | [Upstream](https://github.com/JamesNK/Newtonsoft.Json) |
| SQLitePCLRaw.bundle_e_sqlite3 | 2.1.12 | Apache-2.0 | [Upstream](https://github.com/ericsink/SQLitePCL.raw) |
| SQLitePCLRaw.core | 2.1.12 | Apache-2.0 | [Upstream](https://github.com/ericsink/SQLitePCL.raw) |
| SQLitePCLRaw.lib.e_sqlite3 | 2.1.12 | Apache-2.0 | [Upstream](https://github.com/ericsink/SQLitePCL.raw) |
| SQLitePCLRaw.provider.e_sqlite3 | 2.1.12 | Apache-2.0 | [Upstream](https://github.com/ericsink/SQLitePCL.raw) |
| System.Reflection.Metadata | 1.6.0 | MIT (package LICENSE.TXT) | [Upstream](https://www.nuget.org/packages/System.Reflection.Metadata/1.6.0) |
| System.Security.Cryptography.ProtectedData | 10.0.12 | MIT | [Upstream](https://github.com/dotnet/dotnet) |
| xunit | 2.9.2 | Apache-2.0 | [Upstream](https://github.com/xunit/xunit) |
| xunit.abstractions | 2.0.3 | See upstream license URL (legacy package metadata) | [Upstream](https://www.nuget.org/packages/xunit.abstractions/2.0.3) |
| xunit.analyzers | 1.16.0 | Apache-2.0 | [Upstream](https://github.com/xunit/xunit.analyzers) |
| xunit.assert | 2.9.2 | Apache-2.0 | [Upstream](https://github.com/xunit/xunit) |
| xunit.core | 2.9.2 | Apache-2.0 | [Upstream](https://github.com/xunit/xunit) |
| xunit.extensibility.core | 2.9.2 | Apache-2.0 | [Upstream](https://github.com/xunit/xunit) |
| xunit.extensibility.execution | 2.9.2 | Apache-2.0 | [Upstream](https://github.com/xunit/xunit) |
| xunit.runner.visualstudio | 2.8.2 | Apache-2.0 | [Upstream](https://github.com/xunit/visualstudio.xunit) |

## Included notice texts

- [Microsoft .NET package MIT license](third-party/dotnet/LICENSE.TXT)
- [Microsoft .NET package third-party notices](third-party/dotnet/THIRD-PARTY-NOTICES.TXT)
- [Newtonsoft.Json MIT license](third-party/newtonsoft-json/LICENSE.md)

SQLitePCLRaw and xUnit package metadata declare Apache-2.0. Their sources remain available through the upstream links above. Native Windows packaging uses either MSVC or MinGW-w64; compiler and system runtime obligations depend on the chosen toolchain and exact linked outputs.

The relay protocol under `Protocols/JTSRelay/1.0.0-alpha.1` is an immutable data-only artifact. Its provenance records the historical pre-publication development distribution; it is not a live server identity or a prohibition on this source publication. Its original wire files and checksums are retained unchanged.
