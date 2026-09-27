using System.Buffers.Binary;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using JTS.WindowsCompanion.Security;

/// <summary>Read-only inspection of diagnostic cross-published files. Never launches Windows binaries.</summary>
internal static class PublishedPayloadEvidence
{
    internal static void Inspect(string root, string corePath, string setupAssemblyPath)
    {
        if (!File.Exists(Path.Combine(root, "DIAGNOSTIC-ONLY-MACOS-CROSS-PUBLISH.txt")))
            throw new ArgumentException("Diagnostic marker is required.");
        var publicKeyBytes = File.ReadAllBytes(Path.Combine(root, "test-public-key.pem"));
        var manifestBytes = File.ReadAllBytes(Path.Combine(root, ReleaseManifestTrust.ManifestFileName));
        var release = ReleaseManifestTrust.Verify(manifestBytes, Encoding.UTF8.GetString(publicKeyBytes));
        if (!release.ReleaseId.StartsWith("diagnostic-", StringComparison.Ordinal))
            throw new InvalidOperationException("Expected an explicitly diagnostic release identity.");
        var agentPath = Path.Combine(root, "agent", "JTS.WindowsCompanion.Agent.exe");
        var brokerPath = Path.Combine(root, "broker", "JTS.WindowsCompanion.UacBroker.exe");
        var setupPath = Path.Combine(root, "setup", "JTS.WindowsCompanion.Setup.exe");
        release.VerifyFile(agentPath, Path.GetFileName(agentPath));
        release.VerifyFile(brokerPath, Path.GetFileName(brokerPath));

        var coreBytes = File.ReadAllBytes(corePath);
        var setupAssemblyBytes = File.ReadAllBytes(setupAssemblyPath);
        RequireEqual(ReadResource(corePath, "JTS.Companion.ReleasePublicKey"), publicKeyBytes, "Core public anchor");
        RequireEqual(ReadResource(setupAssemblyPath, "JTS.Setup.Payload.ReleaseManifest.json"), manifestBytes, "Setup release manifest");
        RequireEqual(ReadResource(setupAssemblyPath, "JTS.Setup.Payload.Agent.exe"), File.ReadAllBytes(agentPath), "Setup Agent payload");
        RequireEqual(ReadResource(setupAssemblyPath, "JTS.Setup.Payload.UacBroker.exe"), File.ReadAllBytes(brokerPath), "Setup Broker payload");

        // The publisher leaves bundle compression disabled. Exact DLL inclusion
        // ties the inspected managed resources to the final self-contained EXEs.
        foreach (var path in new[] { agentPath, brokerPath, setupPath })
        {
            var executable = File.ReadAllBytes(path);
            if (executable.AsSpan().IndexOf(coreBytes) < 0)
                throw new InvalidOperationException("A final executable does not contain the inspected Core assembly.");
            if (path == setupPath && executable.AsSpan().IndexOf(setupAssemblyBytes) < 0)
                throw new InvalidOperationException("The final Setup does not contain the inspected Setup assembly.");
        }

        Console.WriteLine(JsonSerializer.Serialize(new
        {
            evidenceKind = "diagnostic-macos-cross-publish-only",
            releaseId = release.ReleaseId,
            productionIdentity = false,
            realWindowsQa = false,
            binariesLaunched = false,
            coreManifestVerification = "passed",
            actualAgentAndBrokerHashesVerified = true,
            publicAnchorEmbeddedInAllFinalExecutables = true,
            setupManifestAndPayloadResourcesMatchFinalFiles = true,
            coreAssemblySha256 = Hash(coreBytes),
            manifestSha256 = Hash(manifestBytes),
            publicKeySha256 = Hash(publicKeyBytes),
            files = new[] { agentPath, brokerPath, setupPath }.Select(path => new
            {
                path = Path.GetRelativePath(root, path),
                length = new FileInfo(path).Length,
                sha256 = Hash(File.ReadAllBytes(path)),
            }),
        }, new JsonSerializerOptions { WriteIndented = true }));
    }

    private static byte[] ReadResource(string assemblyPath, string name)
    {
        using var file = File.OpenRead(assemblyPath);
        using var pe = new PEReader(file);
        var metadata = pe.GetMetadataReader();
        var directory = pe.PEHeaders.CorHeader?.ResourcesDirectory
            ?? throw new InvalidOperationException("The inspected file has no managed resources.");
        foreach (var handle in metadata.ManifestResources)
        {
            var resource = metadata.GetManifestResource(handle);
            if (metadata.GetString(resource.Name) != name)
                continue;
            if (!resource.Implementation.IsNil)
                throw new InvalidOperationException("Expected an embedded resource.");
            var offset = checked((int)resource.Offset);
            var content = pe.GetSectionData(checked(directory.RelativeVirtualAddress + offset));
            var length = BinaryPrimitives.ReadInt32LittleEndian(content.GetContent(0, 4).AsSpan());
            return content.GetContent(4, length).ToArray();
        }
        throw new InvalidOperationException($"Missing managed resource: {name}");
    }

    private static void RequireEqual(byte[] actual, byte[] expected, string label)
    {
        if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(actual), SHA256.HashData(expected)))
            throw new InvalidOperationException($"Resource mismatch: {label}");
    }

    private static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
}
