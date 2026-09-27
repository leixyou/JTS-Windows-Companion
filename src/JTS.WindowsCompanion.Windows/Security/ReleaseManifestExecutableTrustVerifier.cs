using System.IO;
using JTS.WindowsCompanion.Security;

namespace JTS.WindowsCompanion.Windows.Security;

public interface IReleaseExecutableTrustVerifier
{
    void Verify(string executablePath, string expectedFileName);
    FileStream OpenVerifiedFile(string executablePath, string expectedFileName);
}

/// <summary>
/// Binds every executable check to one already authenticated release manifest.
/// A peer cannot select a different release manifest or replace the embedded public key.
/// </summary>
public sealed class ReleaseManifestExecutableTrustVerifier : IReleaseExecutableTrustVerifier
{
    private readonly VerifiedReleaseManifest _manifest;

    public ReleaseManifestExecutableTrustVerifier(VerifiedReleaseManifest manifest)
    {
        _manifest = manifest ?? throw new ArgumentNullException(nameof(manifest));
    }

    public static ReleaseManifestExecutableTrustVerifier ForExecutable(string executablePath) =>
        new(ReleaseManifestTrust.LoadForExecutable(executablePath));

    public void Verify(string executablePath, string expectedFileName) =>
        _manifest.VerifyFile(executablePath, expectedFileName);

    public FileStream OpenVerifiedFile(string executablePath, string expectedFileName) =>
        _manifest.OpenVerifiedFile(executablePath, expectedFileName);
}
