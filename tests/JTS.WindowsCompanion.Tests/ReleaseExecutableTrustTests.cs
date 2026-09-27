using System.Security.Cryptography;
using System.Text.Json;
using JTS.WindowsCompanion.Security;
using JTS.WindowsCompanion.Windows.Managed;
using JTS.WindowsCompanion.Windows.Security;

namespace JTS.WindowsCompanion.Tests;

public sealed class ReleaseExecutableTrustTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("jts-release-executable-").FullName;
    private readonly ECDsa _releaseKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    [Fact]
    public void ReleaseVerifier_RequiresTheExactPeerRoleAndPinnedBytes()
    {
        var agent = WriteFile("JTS.WindowsCompanion.Agent.exe", "agent without Authenticode");
        var broker = WriteFile("JTS.WindowsCompanion.UacBroker.exe", "broker without Authenticode");
        var verifier = Verifier(agent, broker);

        verifier.Verify(agent, Path.GetFileName(agent));
        using (var heldBroker = verifier.OpenVerifiedFile(broker, Path.GetFileName(broker)))
        {
            Assert.True(heldBroker.CanRead);
            Assert.False(heldBroker.CanWrite);
        }
        Assert.Throws<UnauthorizedAccessException>(() => verifier.Verify(agent, Path.GetFileName(broker)));

        File.WriteAllText(broker, "modified broker");
        Assert.Throws<UnauthorizedAccessException>(() => verifier.Verify(broker, Path.GetFileName(broker)));
    }

    [Fact]
    public void ReleaseVerifier_DoesNotAcceptPeerFromAnotherAuthenticatedRelease()
    {
        var agent = WriteFile("JTS.WindowsCompanion.Agent.exe", "release one");
        var releaseOne = Verifier(agent);
        File.WriteAllText(agent, "release two");
        var releaseTwo = Verifier(agent);

        releaseTwo.Verify(agent, Path.GetFileName(agent));
        Assert.Throws<UnauthorizedAccessException>(() => releaseOne.Verify(agent, Path.GetFileName(agent)));
    }

    [Fact]
    public void ManagedHandler_RequiresBothAuthenticatedReleaseAndFixedOperationDigest()
    {
        var handler = WriteFile("fixed-handler.exe", "approved handler");
        var verifier = new ReleaseManifestInstalledHandlerVerifier(Verifier(handler));
        var digest = Hash(handler);

        verifier.Verify(handler, digest);
        Assert.Throws<UnauthorizedAccessException>(() => verifier.Verify(handler, new string('0', 64)));

        File.WriteAllText(handler, "changed handler");
        Assert.Throws<UnauthorizedAccessException>(() => verifier.Verify(handler, Hash(handler)));
    }

    [Fact]
    public void ManagedHandler_RejectsUnlistedHandlerEvenWhenItsOperationDigestMatches()
    {
        var approved = WriteFile("approved.exe", "approved");
        var unlisted = WriteFile("unlisted.exe", "unlisted");
        var verifier = new ReleaseManifestInstalledHandlerVerifier(Verifier(approved));

        Assert.Throws<UnauthorizedAccessException>(() => verifier.Verify(unlisted, Hash(unlisted)));
    }

    private ReleaseManifestExecutableTrustVerifier Verifier(params string[] files)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            schemaVersion = 1,
            releaseId = "2.0.0-test",
            files = files.Select(path => new { fileName = Path.GetFileName(path), sha256 = Hash(path) }),
        });
        var envelope = JsonSerializer.SerializeToUtf8Bytes(new
        {
            payload = Convert.ToBase64String(payload),
            signature = Convert.ToBase64String(_releaseKey.SignData(
                payload, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)),
        });
        return new ReleaseManifestExecutableTrustVerifier(
            ReleaseManifestTrust.Verify(envelope, _releaseKey.ExportSubjectPublicKeyInfoPem()));
    }

    private string WriteFile(string name, string text)
    {
        var path = Path.Combine(_directory, name);
        File.WriteAllText(path, text);
        return path;
    }

    private static string Hash(string path) => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));

    public void Dispose()
    {
        _releaseKey.Dispose();
        Directory.Delete(_directory, recursive: true);
    }
}
