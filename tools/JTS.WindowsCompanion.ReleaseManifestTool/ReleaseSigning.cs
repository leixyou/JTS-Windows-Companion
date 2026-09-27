using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace JTS.WindowsCompanion.ReleaseManifestTool;

internal static class ReleaseSigning
{
    internal const string ManifestFileName = "JTS.WindowsCompanion.release.json";
    private static readonly UTF8Encoding Utf8 = new(false, true);

    internal static void GeneratePrivateKey(string path)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var privateDer = key.ExportPkcs8PrivateKey();
        var pemCharacters = PemEncoding.Write("PRIVATE KEY", privateDer);
        var pem = Utf8.GetBytes(pemCharacters);
        try
        {
            using var output = RestrictedKeyFile.CreateNew(path);
            output.Write(pem);
            output.Flush(flushToDisk: true);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pem);
            CryptographicOperations.ZeroMemory(privateDer);
            Array.Clear(pemCharacters);
        }
    }

    internal static void ExportPublicKey(string privateKeyPath, string outputPath)
    {
        using var key = LoadPrivateKey(privateKeyPath);
        WriteNew(outputPath, Utf8.GetBytes(key.ExportSubjectPublicKeyInfoPem()));
    }

    internal static void SignManifest(string privateKeyPath, string releaseId, IReadOnlyList<string> files, string outputPath)
        => Sign(privateKeyPath, releaseId, files, outputPath, schemaVersion: 1);

    internal static void SignBundleManifest(string privateKeyPath, string releaseId, IReadOnlyList<string> files, string outputPath)
        => Sign(privateKeyPath, releaseId, files, outputPath, schemaVersion: 2);

    private static void Sign(string privateKeyPath, string releaseId, IReadOnlyList<string> files, string outputPath, int schemaVersion)
    {
        if (!IsPortableName(releaseId, 64))
            throw new ArgumentException("A bounded, nonempty release ID is required.");
        var maximumFiles = schemaVersion == 1 ? 64 : 128;
        if (files.Count < 1 || files.Count > maximumFiles)
            throw new ArgumentException("The payload file count is outside the supported manifest bounds.");

        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var entries = files.Select(path =>
        {
            var name = Path.GetFileName(path);
            if (!IsPayloadName(name, schemaVersion)
                || !names.Add(name))
                throw new ArgumentException("Payload names must be unique simple filenames.");
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (schemaVersion == 2 && stream.Length == 0)
                throw new ArgumentException("Bundle payload files must not be empty.");
            return new { fileName = name, sha256 = Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant() };
        }).OrderBy(entry => entry.fileName, StringComparer.Ordinal).ToArray();

        var payload = JsonSerializer.SerializeToUtf8Bytes(new { schemaVersion, releaseId, files = entries });
        using var key = LoadPrivateKey(privateKeyPath);
        var signature = key.SignData(payload, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        var envelope = JsonSerializer.SerializeToUtf8Bytes(new
        {
            payload = Convert.ToBase64String(payload),
            signature = Convert.ToBase64String(signature),
        });
        WriteNew(outputPath, envelope);
    }

    private static bool IsPayloadName(string name, int schemaVersion)
    {
        if (!IsPortableName(name, 128)) return false;
        var executable = name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);
        if (schemaVersion == 1) return executable;
        if (!executable && !name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) return false;
        var stem = name.Split('.')[0].ToUpperInvariant();
        return stem is not ("CON" or "PRN" or "AUX" or "NUL")
            && !(stem.Length == 4 && (stem.StartsWith("COM", StringComparison.Ordinal) || stem.StartsWith("LPT", StringComparison.Ordinal))
                && stem[3] is >= '1' and <= '9');
    }

    private static bool IsPortableName(string value, int maximumLength) =>
        value.Length >= 1 && value.Length <= maximumLength && char.IsAsciiLetterOrDigit(value[0])
        && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '_' or '-');

    private static ECDsa LoadPrivateKey(string path)
    {
        var info = new FileInfo(path);
        if (!info.Exists || info.Length is < 1 or > 16384 || info.LinkTarget is not null)
            throw new ArgumentException("A regular private-key PEM file is required.");
        RestrictedKeyFile.AssertOwnerOnly(path);
        var pemBytes = File.ReadAllBytes(path);
        char[] pem;
        try { pem = Utf8.GetChars(pemBytes); }
        finally { CryptographicOperations.ZeroMemory(pemBytes); }
        var key = ECDsa.Create();
        try
        {
            key.ImportFromPem(pem);
            var parameters = key.ExportParameters(includePrivateParameters: true);
            try
            {
                if (parameters.D is not { Length: 32 }
                    || parameters.Curve.Oid.Value != ECCurve.NamedCurves.nistP256.Oid.Value)
                    throw new CryptographicException("The release key must be a P-256 private key.");
            }
            finally
            {
                if (parameters.D is not null)
                    CryptographicOperations.ZeroMemory(parameters.D);
            }
            return key;
        }
        catch
        {
            key.Dispose();
            throw;
        }
        finally
        {
            Array.Clear(pem);
        }
    }

    private static void WriteNew(string path, ReadOnlySpan<byte> bytes)
    {
        using var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        output.Write(bytes);
        output.Flush(flushToDisk: true);
    }
}
