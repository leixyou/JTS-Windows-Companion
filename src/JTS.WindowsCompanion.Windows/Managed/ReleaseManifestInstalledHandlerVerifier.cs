using System.IO;
using JTS.WindowsCompanion.Managed;
using JTS.WindowsCompanion.Windows.Security;

namespace JTS.WindowsCompanion.Windows.Managed;

/// <summary>Requires both the fixed-operation digest and an entry in the service's authenticated release.</summary>
public sealed class ReleaseManifestInstalledHandlerVerifier : IInstalledHandlerVerifier
{
    private readonly Sha256InstalledHandlerVerifier _hashVerifier = new();
    private readonly IReleaseExecutableTrustVerifier _releaseVerifier;

    public ReleaseManifestInstalledHandlerVerifier(string serviceExecutablePath)
        : this(ReleaseManifestExecutableTrustVerifier.ForExecutable(serviceExecutablePath))
    {
    }

    internal ReleaseManifestInstalledHandlerVerifier(IReleaseExecutableTrustVerifier releaseVerifier)
    {
        _releaseVerifier = releaseVerifier ?? throw new ArgumentNullException(nameof(releaseVerifier));
    }

    public void Verify(string executablePath, string expectedSha256)
    {
        using var fileLock = _releaseVerifier.OpenVerifiedFile(executablePath, Path.GetFileName(executablePath));
        _hashVerifier.Verify(executablePath, expectedSha256);
    }
}
