using System.Security.Cryptography;
using System.Text;

namespace JTS.WindowsCompanion.Enrollment;

public sealed class EnrollmentException(string code) : IOException(code)
{
    public string Code { get; } = code;
}

public static class EnrollmentCodeInspector
{
    public static Uri GetRelayOrigin(string code)
    { using var parsed = EnrollmentCode.Parse(code); return new Uri(parsed.RelayOrigin); }
}

internal sealed class EnrollmentCode(string origin, Guid id, byte[] secret) : IDisposable
{
    internal string RelayOrigin { get; } = origin;
    internal Guid InvitationId { get; } = id;
    internal byte[] Secret { get; } = secret;
    internal static EnrollmentCode Parse(string text)
    {
        try
        {
            const string prefix = "jts-pair://enroll?";
            if (text is null || text.Length > 4096 || !text.StartsWith(prefix, StringComparison.Ordinal) || text.Any(char.IsControl)) throw Invalid();
            var fields = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var part in text[prefix.Length..].Split('&'))
            {
                var pair = part.Split('=');
                if (pair.Length != 2 || pair[0] is not ("relay" or "id" or "key") || !fields.TryAdd(pair[0], pair[1])) throw Invalid();
            }
            if (fields.Count != 3) throw Invalid();
            var encoded = fields["relay"];
            for (var i = 0; i < encoded.Length; i++)
                if (encoded[i] == '%' && (i + 2 >= encoded.Length || !Uri.IsHexDigit(encoded[++i]) || !Uri.IsHexDigit(encoded[++i]))) throw Invalid();
            var decodedOrigin = Uri.UnescapeDataString(encoded);
            var origin = CanonicalOrigin(decodedOrigin);
            if (decodedOrigin != origin) throw Invalid();
            if (!Guid.TryParseExact(fields["id"], "D", out var id) || id == Guid.Empty || id.ToString("D") != fields["id"]) throw Invalid();
            var key = fields["key"];
            if (key.Length != 43 || key.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_'))) throw Invalid();
            var bytes = Convert.FromBase64String(key.Replace('-', '+').Replace('_', '/') + "=");
            if (bytes.Length != 32 || Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_') != key) throw Invalid();
            return new(origin, id, bytes);
        }
        catch (Exception e) when (e is ArgumentException or FormatException or KeyNotFoundException) { throw Invalid(); }
    }
    internal static string CanonicalOrigin(string text)
    {
        if (text is null || text.Length > 2048 || text.Any(char.IsControl) || !Uri.TryCreate(text, UriKind.Absolute, out var uri)
            || uri.Scheme != "https" || uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0
            || uri.AbsolutePath != "/" || uri.Host.Length == 0 || uri.Port is < 1 or > 65535) throw Invalid();
        var normalized = uri.GetLeftPart(UriPartial.Authority);
        if (text != normalized && text != normalized + "/") throw Invalid();
        return normalized;
    }
    internal byte[] Derive(string label)
        => HKDF.DeriveKey(HashAlgorithmName.SHA256, Secret, 32,
            Encoding.UTF8.GetBytes($"JTS-PAIR-1\n{InvitationId:D}"), Encoding.UTF8.GetBytes(label));
    public void Dispose() => CryptographicOperations.ZeroMemory(Secret);
    public override string ToString() => "EnrollmentCode (secret omitted)";
    private static EnrollmentException Invalid() => new("ENROLLMENT_CODE_INVALID");
}
