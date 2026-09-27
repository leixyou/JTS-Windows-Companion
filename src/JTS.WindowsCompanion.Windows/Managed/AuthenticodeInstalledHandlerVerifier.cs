using System.IO;
using JTS.WindowsCompanion.Managed;
using JTS.WindowsCompanion.Windows.Security;

namespace JTS.WindowsCompanion.Windows.Managed;

public sealed class AuthenticodeInstalledHandlerVerifier : IInstalledHandlerVerifier
{
    private readonly Sha256InstalledHandlerVerifier _hashVerifier = new();
    private readonly WindowsAuthenticodeTrustVerifier _signatureVerifier = new();
    private readonly string _trustedSignedServicePath;

    public AuthenticodeInstalledHandlerVerifier(string trustedSignedServicePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(trustedSignedServicePath);
        _trustedSignedServicePath = Path.GetFullPath(trustedSignedServicePath);
        var selfPolicy = _signatureVerifier.CreateSameSignerPolicy(
            _trustedSignedServicePath,
            Path.GetFileName(_trustedSignedServicePath));
        _signatureVerifier.Verify(_trustedSignedServicePath, selfPolicy);
    }

    public void Verify(string executablePath, string expectedSha256)
    {
        _hashVerifier.Verify(executablePath, expectedSha256);
        var policy = _signatureVerifier.CreateSameSignerPolicy(
            _trustedSignedServicePath,
            Path.GetFileName(executablePath));
        _signatureVerifier.Verify(executablePath, policy);
    }
}
