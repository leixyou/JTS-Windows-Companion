using System.Security.Cryptography;

namespace JTS.WindowsCompanion.Security;

/// <summary>An immutable inventory authenticated by the release public key, not by adjacent checksums.</summary>
public sealed class VerifiedReleaseManifest
{
    private readonly IReadOnlyDictionary<string, string> _hashes;

    internal VerifiedReleaseManifest(int schemaVersion, string releaseId, string payloadSha256, Dictionary<string, string> hashes)
    {
        SchemaVersion = schemaVersion;
        ReleaseId = releaseId;
        PayloadSha256 = payloadSha256;
        _hashes = new Dictionary<string, string>(hashes, StringComparer.OrdinalIgnoreCase);
        FileNames = Array.AsReadOnly(hashes.Keys.Order(StringComparer.Ordinal).ToArray());
    }

    public int SchemaVersion { get; }
    public string ReleaseId { get; }
    public string PayloadSha256 { get; }
    /// <summary>Immutable authenticated names only; consumers must still verify and hold each file they use.</summary>
    public IReadOnlyList<string> FileNames { get; }

    public void VerifyFile(string executablePath, string expectedFileName)
    {
        using var file = OpenVerifiedFile(executablePath, expectedFileName);
    }

    /// <summary>Keep this handle alive until launch/peer attestation completes to deny replacement on Windows.</summary>
    public FileStream OpenVerifiedFile(string executablePath, string expectedFileName)
    {
        if (!_hashes.TryGetValue(expectedFileName, out var expectedHash))
            throw new UnauthorizedAccessException("The payload file is not part of this authenticated release.");
        var fullPath = Path.GetFullPath(executablePath);
        if (!string.Equals(Path.GetFileName(fullPath), expectedFileName, StringComparison.OrdinalIgnoreCase))
            throw new UnauthorizedAccessException("The payload filename does not match its release role.");
        RejectReparsePoints(fullPath);
        var file = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        try
        {
            RejectReparsePoints(fullPath);
            if (file.Length == 0 || !CryptographicOperations.FixedTimeEquals(
                    SHA256.HashData(file), Convert.FromHexString(expectedHash)))
                throw new UnauthorizedAccessException("The payload bytes do not match the authenticated release.");
            file.Position = 0;
            return file;
        }
        catch { file.Dispose(); throw; }
    }

    internal static void RejectReparsePoints(string path)
    {
        // macOS /var and /tmp are symlinks. Only Windows uses these checks as a runtime trust boundary.
        var current = Path.GetFullPath(path);
        do
        {
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new UnauthorizedAccessException("Release executables and manifests cannot use reparse points.");
            current = OperatingSystem.IsWindows() ? Path.GetDirectoryName(current) : null;
        } while (!string.IsNullOrEmpty(current));
    }
}
