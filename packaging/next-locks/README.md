# Opt-in 2.5 Windows packaging dependency graphs

These generated lock files apply only with `JtsNextPackageBuild=true`, .NET SDK
10.0.401, net10 runtime 10.0.12, `RuntimeIdentifier=win-x64`, and
`SelfContained=true`. `Directory.Build.targets` sets this separate lock location
and 2.5 assembly metadata; normal 2.0 and Next development graphs are unchanged.
The opt-in targets explicitly set the singular `RuntimeIdentifier=win-x64` so
self-contained restore does not add the build host's RID. `dotnet restore --runtime`
alone sets the plural `RuntimeIdentifiers` and can otherwise produce a host-specific
lock graph. The same packaging locks are verified on macOS and Windows.

The build script consumes these locks without rewriting them. Dependency or SDK
changes require intentional restore with `--force-evaluate`, review of changed
graphs/hashes, then affected packaging checks. Do not regenerate after a release
build's locked-restore failure. These files are not runtime credentials or a
substitute for real Windows acceptance.
