using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using JTS.WindowsCompanion.ReleaseManifestTool;
using ToolProgram = JTS.WindowsCompanion.ReleaseManifestTool.Program;

if (args is ["--inspect-published", var evidenceRoot, var coreAssemblyPath, var setupAssemblyPath])
{
    PublishedPayloadEvidence.Inspect(evidenceRoot, coreAssemblyPath, setupAssemblyPath);
    return;
}
if (args.Length != 0)
    throw new ArgumentException("Expected no arguments, or --inspect-published <evidence-root> <Core.dll> <Setup.dll>.");

var root = Directory.CreateTempSubdirectory("jts-release-signing-tests-").FullName;
var checks = 0;
try
{
    var privatePath = Path.Combine(root, "ephemeral-private.pem");
    var publicPath = Path.Combine(root, "public.pem");
    ReleaseSigning.GeneratePrivateKey(privatePath);
    Check(File.ReadAllText(privatePath).Contains("BEGIN PRIVATE KEY", StringComparison.Ordinal), "PKCS8 private key");
    if (OperatingSystem.IsWindows())
    {
        var security = new FileInfo(privatePath).GetAccessControl();
        using var identity = WindowsIdentity.GetCurrent();
        var owner = identity.User;
        Check(security.AreAccessRulesProtected && security.GetOwner(typeof(SecurityIdentifier))?.Equals(owner) == true, "private key owner DACL");
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            Check(rule.IdentityReference.Equals(owner) && !rule.IsInherited, "no inherited key readers");
    }
    else
    {
        Check(File.GetUnixFileMode(privatePath) == (UnixFileMode.UserRead | UnixFileMode.UserWrite), "private key mode 0600");
    }
    var originalKeyHash = SHA256.HashData(File.ReadAllBytes(privatePath));
    Reject(() => ReleaseSigning.GeneratePrivateKey(privatePath), "existing private key refuses overwrite");
    Check(originalKeyHash.SequenceEqual(SHA256.HashData(File.ReadAllBytes(privatePath))), "existing private key unchanged");
    ReleaseSigning.ExportPublicKey(privatePath, publicPath);
    var publicPem = File.ReadAllText(publicPath);
    Check(publicPem.Contains("BEGIN PUBLIC KEY", StringComparison.Ordinal) && !publicPem.Contains("PRIVATE", StringComparison.Ordinal), "public export has no private material");
    Reject(() => ReleaseSigning.ExportPublicKey(privatePath, publicPath), "existing public output refuses overwrite");
    using var publicKey = ECDsa.Create();
    publicKey.ImportFromPem(publicPem);
    Check(publicKey.KeySize == 256, "P256 public key");

    var agentPath = Path.Combine(root, "JTS.WindowsCompanion.Agent.exe");
    var brokerPath = Path.Combine(root, "JTS.WindowsCompanion.UacBroker.exe");
    File.WriteAllBytes(agentPath, [0, 1, 2, 255]);
    File.WriteAllBytes(brokerPath, Encoding.UTF8.GetBytes("final broker bytes"));
    var manifestPath = Path.Combine(root, ReleaseSigning.ManifestFileName);
    ReleaseSigning.SignManifest(privatePath, "2.0.0-test", [brokerPath, agentPath], manifestPath);
    checks += CoreInteroperability.VerifyFixture(publicPem, manifestPath, agentPath, brokerPath);
    using var envelope = JsonDocument.Parse(File.ReadAllBytes(manifestPath));
    Check(envelope.RootElement.EnumerateObject().Select(item => item.Name).Order().SequenceEqual(new[] { "payload", "signature" }), "strict envelope keys");
    var payload = Convert.FromBase64String(envelope.RootElement.GetProperty("payload").GetString()!);
    var signature = Convert.FromBase64String(envelope.RootElement.GetProperty("signature").GetString()!);
    Check(signature.Length == 64 && publicKey.VerifyData(payload, signature, HashAlgorithmName.SHA256,
        DSASignatureFormat.IeeeP1363FixedFieldConcatenation), "exact payload P1363 signature");
    Check(payload[0] == (byte)'{', "UTF8 payload has no BOM");
    using var body = JsonDocument.Parse(payload);
    Check(body.RootElement.GetProperty("schemaVersion").GetInt32() == 1
        && body.RootElement.GetProperty("releaseId").GetString() == "2.0.0-test", "manifest version and identity");
    var entries = body.RootElement.GetProperty("files").EnumerateArray().ToArray();
    Check(entries.Length == 2 && entries[0].GetProperty("fileName").GetString() == Path.GetFileName(agentPath), "payloads sorted deterministically");
    Check(entries[0].GetProperty("sha256").GetString() == Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(agentPath))).ToLowerInvariant(), "final binary hash");
    var tampered = (byte[])payload.Clone();
    tampered[^2] ^= 1;
    Check(!publicKey.VerifyData(tampered, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation), "tampered payload rejected");
    using var wrongKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    Check(!wrongKey.VerifyData(payload, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation), "wrong release key rejected");
    Reject(() => ReleaseSigning.SignManifest(privatePath, "2.0.0", [agentPath], manifestPath), "existing manifest refuses overwrite");

    var unusedOutput = Path.Combine(root, "must-not-exist.json");
    foreach (var invalidId in new[] { "", "contains whitespace", "../release", new string('a', 65), "非ASCII" })
        Reject(() => ReleaseSigning.SignManifest(privatePath, invalidId, [agentPath], unusedOutput), "invalid release ID rejected");
    Reject(() => ReleaseSigning.SignManifest(privatePath, "2.0.0", [], unusedOutput), "empty file list rejected");
    Reject(() => ReleaseSigning.SignManifest(privatePath, "2.0.0", [agentPath, agentPath], unusedOutput), "duplicate filename rejected");
    var notExe = Path.Combine(root, "payload.bin");
    File.WriteAllText(notExe, "payload");
    Reject(() => ReleaseSigning.SignManifest(privatePath, "2.0.0", [notExe], unusedOutput), "nonexe payload rejected");
    using var wrongCurve = ECDsa.Create(ECCurve.NamedCurves.nistP384);
    var wrongCurvePath = Path.Combine(root, "wrong-curve.pem");
    using (var output = RestrictedKeyFile.CreateNew(wrongCurvePath))
        output.Write(Encoding.UTF8.GetBytes(wrongCurve.ExportPkcs8PrivateKeyPem()));
    Reject(() => ReleaseSigning.ExportPublicKey(wrongCurvePath, unusedOutput), "nonP256 private key rejected");
    Reject(() => ReleaseSigning.ExportPublicKey(publicPath, unusedOutput), "public-only input rejected");
    if (!OperatingSystem.IsWindows())
    {
        File.SetUnixFileMode(privatePath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
        Reject(() => ReleaseSigning.ExportPublicKey(privatePath, unusedOutput), "shared private key permissions rejected");
        File.SetUnixFileMode(privatePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
    Check(!File.Exists(unusedOutput), "invalid requests create no output");

    var captured = new StringWriter();
    var previousOut = Console.Out;
    var previousError = Console.Error;
    try
    {
        Console.SetOut(captured);
        Console.SetError(captured);
        Check(ToolProgram.Main(["public-key", "--private-key", privatePath, "--output", Path.Combine(root, "cli-public.pem")]) == 0, "CLI public export");
        Check(ToolProgram.Main(["keygen", "--private-key", privatePath]) != 0, "CLI collision fails");
        Check(ToolProgram.Main(["keygen", "--private-key", privatePath, "--unknown", "value"]) != 0, "CLI unknown option fails");
    }
    finally
    {
        Console.SetOut(previousOut);
        Console.SetError(previousError);
    }
    Check(!captured.ToString().Contains("PRIVATE KEY", StringComparison.Ordinal)
        && !captured.ToString().Contains(privatePath, StringComparison.Ordinal), "CLI never echoes private material or key path");
    checks += BundleManifestChecks.Run(privatePath, publicPem, root);
    Console.WriteLine($"Release manifest tooling: {checks} checks passed (ephemeral keys only).");
}
finally
{
    Directory.Delete(root, recursive: true);
}

void Check(bool condition, string label)
{
    if (!condition) throw new InvalidOperationException($"Test failed: {label}");
    checks++;
}

void Reject(Action action, string label)
{
    var rejected = false;
    try { action(); }
    catch (Exception error) when (error is ArgumentException or IOException or UnauthorizedAccessException or CryptographicException)
    { rejected = true; }
    Check(rejected, label);
}
