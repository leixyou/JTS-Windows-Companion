using System.Security.Cryptography;
using System.Text.Json;
using JTS.WindowsCompanion.ReleaseManifestTool;
using JTS.WindowsCompanion.Security;
using ToolProgram = JTS.WindowsCompanion.ReleaseManifestTool.Program;

internal static class BundleManifestChecks
{
    internal static int Run(string privateKeyPath, string publicPem, string root)
    {
        var checks = 0;
        var executable = Write("Bundle.exe", "final app bytes");
        var library = Write("runtime.dll", "final native bytes");
        var manifest = Path.Combine(root, "bundle-release.json");
        Check(ToolProgram.Main(["sign-bundle", "--private-key", privateKeyPath, "--release-id", "2.5.0-test",
            "--output", manifest, "--file", library, "--file", executable]) == 0, "CLI schema-2 bundle signing");
        var release = ReleaseManifestTrust.Verify(File.ReadAllBytes(manifest), publicPem);
        Check(release.SchemaVersion == 2 && release.ReleaseId == "2.5.0-test", "Core accepts signed bundle schema");
        Check(release.FileNames.SequenceEqual(new[] { "Bundle.exe", "runtime.dll" }), "sorted authenticated bundle inventory");
        release.VerifyFile(executable, "Bundle.exe"); checks++;
        release.VerifyFile(library, "runtime.dll"); checks++;
        using (var envelope = JsonDocument.Parse(File.ReadAllBytes(manifest)))
        using (var payload = JsonDocument.Parse(Convert.FromBase64String(envelope.RootElement.GetProperty("payload").GetString()!)))
        {
            var files = payload.RootElement.GetProperty("files").EnumerateArray().ToArray();
            Check(files[1].GetProperty("sha256").GetString() == Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(library))).ToLowerInvariant(),
                "bundle hashes final native bytes");
        }
        File.WriteAllText(library, "modified native bytes");
        Reject(() => release.VerifyFile(library, "runtime.dll"), "Core rejects modified bundle DLL");
        var unused = Path.Combine(root, "bundle-must-not-exist.json");
        Reject(() => ReleaseSigning.SignManifest(privateKeyPath, "test", [library], unused), "schema-1 signing remains executable-only");
        Reject(() => ReleaseSigning.SignBundleManifest(privateKeyPath, "test", [], unused), "empty bundle refused");
        Reject(() => ReleaseSigning.SignBundleManifest(privateKeyPath, "test", [library, library], unused), "duplicate bundle name refused");
        Reject(() => ReleaseSigning.SignBundleManifest(privateKeyPath, "test", [library, Path.Combine(root, "RUNTIME.DLL")], unused), "case-insensitive duplicate bundle name refused");
        Reject(() => ReleaseSigning.SignBundleManifest(privateKeyPath, "test", Enumerable.Repeat(executable, 129).ToArray(), unused), "bundle count limit");
        Reject(() => ReleaseSigning.SignBundleManifest(privateKeyPath, "test", [executable], manifest), "bundle output refuses overwrite");
        foreach (var name in new[] { "payload.json", "payload.pdb", "payload.so", "payload.dll.config", new string('a', 125) + ".dll" })
        {
            var path = Write(name, "not an accepted bundle payload");
            Reject(() => ReleaseSigning.SignBundleManifest(privateKeyPath, "test", [path], unused), "unsupported bundle filename");
        }
        // No reserved device file is opened: name validation must reject it first on Windows too.
        foreach (var name in new[] { "NUL.dll", "con.exe", "COM1.native.dll", "LPT9.dll", "native.dll:stream" })
            Reject(() => ReleaseSigning.SignBundleManifest(privateKeyPath, "test", [Path.Combine(root, name)], unused), "unsafe bundle filename");
        Reject(() => ReleaseSigning.SignBundleManifest(privateKeyPath, "test", [Write("empty.dll", "")], unused), "empty bundle file refused");
        Check(!File.Exists(unused), "invalid bundles leave no manifest");

        var maximumFiles = Enumerable.Range(0, 128).Select(index => Write("Library" + index.ToString("D3") + ".dll", "native")).ToArray();
        var maximumManifest = Path.Combine(root, "maximum-bundle.json");
        ReleaseSigning.SignBundleManifest(privateKeyPath, "maximum-test", maximumFiles, maximumManifest);
        Check(new FileInfo(maximumManifest).Length <= 65536, "bounded bundle envelope");
        Check(ReleaseManifestTrust.Verify(File.ReadAllBytes(maximumManifest), publicPem).FileNames.Count == 128, "Core accepts maximum bundle");
        return checks;

        string Write(string name, string content)
        { var path = Path.Combine(root, name); File.WriteAllText(path, content); return path; }
        void Check(bool condition, string label)
        { if (!condition) throw new InvalidOperationException("Bundle test failed: " + label); checks++; }
        void Reject(Action action, string label)
        {
            try { action(); }
            catch (Exception error) when (error is ArgumentException or IOException or UnauthorizedAccessException or CryptographicException)
            { checks++; return; }
            throw new InvalidOperationException("Bundle test failed: " + label);
        }
    }
}
