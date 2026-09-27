using System.Security.Cryptography;
using System.Text.Json;
using JTS.WindowsCompanion.Security;

internal static class CoreInteroperability
{
    internal static int VerifyFixture(string publicPem, string manifestPath, string agentPath, string brokerPath)
    {
        var checks = 0;
        var envelope = File.ReadAllBytes(manifestPath);
        var release = ReleaseManifestTrust.Verify(envelope, publicPem);
        if (release.ReleaseId != "2.0.0-test")
            throw new InvalidOperationException("Core verifier returned the wrong release identity.");
        checks++;
        release.VerifyFile(agentPath, Path.GetFileName(agentPath));
        checks++;
        release.VerifyFile(brokerPath, Path.GetFileName(brokerPath));
        checks++;

        using var wrongKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        MustReject(() => ReleaseManifestTrust.Verify(envelope, wrongKey.ExportSubjectPublicKeyInfoPem()));
        using var document = JsonDocument.Parse(envelope);
        var payload = Convert.FromBase64String(document.RootElement.GetProperty("payload").GetString()!);
        payload[^2] ^= 1;
        var tamperedEnvelope = JsonSerializer.SerializeToUtf8Bytes(new
        {
            payload = Convert.ToBase64String(payload),
            signature = document.RootElement.GetProperty("signature").GetString(),
        });
        MustReject(() => ReleaseManifestTrust.Verify(tamperedEnvelope, publicPem));

        var originalBytes = File.ReadAllBytes(agentPath);
        try
        {
            File.WriteAllBytes(agentPath, [42]);
            MustReject(() => release.VerifyFile(agentPath, Path.GetFileName(agentPath)));
        }
        finally
        {
            File.WriteAllBytes(agentPath, originalBytes);
        }
        return checks;

        void MustReject(Action action)
        {
            try { action(); }
            catch (UnauthorizedAccessException) { checks++; return; }
            throw new InvalidOperationException("Core accepted a tampered manifest, file, or wrong release key.");
        }
    }
}
