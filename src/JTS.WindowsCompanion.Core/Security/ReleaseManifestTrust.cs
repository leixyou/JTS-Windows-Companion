using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace JTS.WindowsCompanion.Security;

/// <summary>
/// Authenticates a release's exact payload bytes without an OS code-signing certificate.
/// The production trust anchor is compiled into Core; an adjacent file cannot replace it.
/// </summary>
public static class ReleaseManifestTrust
{
    public const string ManifestFileName = "JTS.WindowsCompanion.release.json";
    private const string PublicKeyResource = "JTS.Companion.ReleasePublicKey";
    private const int MaximumEnvelopeBytes = 64 * 1024;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static VerifiedReleaseManifest LoadForExecutable(string executablePath)
    {
        var fullPath = Path.GetFullPath(executablePath);
        var manifestPath = Path.Combine(Path.GetDirectoryName(fullPath)!, ManifestFileName);
        VerifiedReleaseManifest.RejectReparsePoints(manifestPath);
        using var file = new FileStream(manifestPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (file.Length is <= 0 or > MaximumEnvelopeBytes)
            throw new UnauthorizedAccessException("The release manifest size is invalid.");
        var envelope = new byte[(int)file.Length];
        file.ReadExactly(envelope);
        var release = VerifyUsingEmbeddedKey(envelope);
        release.VerifyFile(fullPath, Path.GetFileName(fullPath));
        return release;
    }

    public static VerifiedReleaseManifest VerifyUsingEmbeddedKey(byte[] envelope)
    {
        using var resource = typeof(ReleaseManifestTrust).Assembly.GetManifestResourceStream(PublicKeyResource)
            ?? throw new UnauthorizedAccessException("This build has no embedded Companion release trust key.");
        if (resource.Length is <= 0 or > 4096)
            throw new UnauthorizedAccessException("The embedded Companion release trust key is invalid.");
        using var reader = new StreamReader(resource, StrictUtf8, detectEncodingFromByteOrderMarks: false);
        return Verify(envelope, reader.ReadToEnd());
    }

    /// <summary>Explicit-key entry point for publishing tools and isolated tests, not runtime configuration.</summary>
    public static VerifiedReleaseManifest Verify(byte[] envelope, string publicKeyPem)
    {
        try
        {
            if (envelope is null || envelope.Length is <= 0 or > MaximumEnvelopeBytes)
                throw new UnauthorizedAccessException("The release manifest size is invalid.");
            using var outer = Parse(envelope);
            RequireProperties(outer.RootElement, "payload", "signature");
            var payload = DecodeBase64(outer.RootElement.GetProperty("payload"));
            var signature = DecodeBase64(outer.RootElement.GetProperty("signature"));
            using var key = ImportPublicKey(publicKeyPem);
            if (signature.Length != 64 || !key.VerifyData(payload, signature, HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                throw new UnauthorizedAccessException("The release manifest signature is invalid.");

            using var document = Parse(payload);
            var root = document.RootElement;
            RequireProperties(root, "schemaVersion", "releaseId", "files");
            var schemaVersion = root.GetProperty("schemaVersion").GetInt32();
            if (schemaVersion is not (1 or 2))
                throw new UnauthorizedAccessException("The release manifest schema is unsupported.");
            var releaseId = root.GetProperty("releaseId").GetString();
            if (!IsPortableName(releaseId, 64))
                throw new UnauthorizedAccessException("The release identifier is invalid.");
            var files = root.GetProperty("files");
            var maximumFiles = schemaVersion == 1 ? 64 : 128;
            if (files.ValueKind != JsonValueKind.Array || files.GetArrayLength() < 1 || files.GetArrayLength() > maximumFiles)
                throw new UnauthorizedAccessException("The release file inventory is invalid.");
            var hashes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var entry in files.EnumerateArray())
            {
                RequireProperties(entry, "fileName", "sha256");
                var name = entry.GetProperty("fileName").GetString();
                var hash = entry.GetProperty("sha256").GetString();
                if (!IsPayloadName(name, schemaVersion)
                    || hash is null || hash.Length != 64 || !hash.All(char.IsAsciiHexDigit)
                    || !hashes.TryAdd(name!, hash.ToUpperInvariant()))
                    throw new UnauthorizedAccessException("The release file entry is invalid or duplicated.");
            }
            return new VerifiedReleaseManifest(schemaVersion, releaseId!, Convert.ToHexString(SHA256.HashData(payload)), hashes);
        }
        catch (Exception error) when (error is JsonException or CryptographicException or FormatException
            or InvalidOperationException or ArgumentException or DecoderFallbackException or OverflowException)
        {
            throw new UnauthorizedAccessException("The Companion release manifest or trust key is invalid.", error);
        }
    }

    private static JsonDocument Parse(byte[] bytes)
    {
        // JsonDocument alone need not decode every string: explicitly reject malformed UTF-8 first.
        _ = StrictUtf8.GetString(bytes);
        return JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 8 });
    }

    private static void RequireProperties(JsonElement element, params string[] expected)
    {
        if (element.ValueKind != JsonValueKind.Object)
            throw new UnauthorizedAccessException("The release manifest contains a non-object record.");
        var remaining = new HashSet<string>(expected, StringComparer.Ordinal);
        foreach (var property in element.EnumerateObject())
            if (!remaining.Remove(property.Name))
                throw new UnauthorizedAccessException("The release manifest contains unknown or duplicate fields.");
        if (remaining.Count != 0)
            throw new UnauthorizedAccessException("The release manifest is missing required fields.");
    }

    private static byte[] DecodeBase64(JsonElement element)
    {
        var encoded = element.GetString() ?? throw new FormatException("Missing base64 value.");
        var bytes = Convert.FromBase64String(encoded);
        if (Convert.ToBase64String(bytes) != encoded)
            throw new FormatException("Noncanonical base64 value.");
        return bytes;
    }

    private static ECDsa ImportPublicKey(string pem)
    {
        if (pem is null || pem.Length > 4096 || !PemEncoding.TryFind(pem, out var fields)
            || pem[fields.Label] != "PUBLIC KEY"
            || !string.IsNullOrWhiteSpace(pem[..fields.Location.Start])
            || !string.IsNullOrWhiteSpace(pem[fields.Location.End..]))
            throw new UnauthorizedAccessException("The Companion release anchor must be one P-256 public key.");
        var der = Convert.FromBase64String(pem[fields.Base64Data]);
        var key = ECDsa.Create();
        try
        {
            key.ImportSubjectPublicKeyInfo(der, out var consumed);
            if (consumed != der.Length || key.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7")
                throw new UnauthorizedAccessException("The Companion release anchor must use P-256.");
            return key;
        }
        catch { key.Dispose(); throw; }
    }

    private static bool IsPortableName(string? name, int maximumLength) =>
        name is { Length: > 0 } && name.Length <= maximumLength && char.IsAsciiLetterOrDigit(name[0])
        && name.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '_' or '-');

    private static bool IsPayloadName(string? name, int schemaVersion)
    {
        if (name is null || !IsPortableName(name, 128)) return false;
        var executable = name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase);
        if (schemaVersion == 1) return executable; // Preserve the 2.0 executable-only contract exactly.
        if (!executable && !name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) return false;
        // Windows reserves device basenames even when followed by an extension.
        var stem = name.Split('.')[0].ToUpperInvariant();
        return stem is not ("CON" or "PRN" or "AUX" or "NUL")
            && !(stem.Length == 4 && (stem.StartsWith("COM", StringComparison.Ordinal) || stem.StartsWith("LPT", StringComparison.Ordinal))
                && stem[3] is >= '1' and <= '9');
    }
}
