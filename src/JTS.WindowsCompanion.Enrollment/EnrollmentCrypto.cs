using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using JTS.WindowsCompanion.Pairing;

namespace JTS.WindowsCompanion.Enrollment;

internal static class EnrollmentCrypto
{
    internal static string Hash(ReadOnlySpan<byte> bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));
    internal static byte[] Base64(string text, int maximum = 8192)
    {
        try
        {
            if (text is null || text.Length > maximum * 2) throw Invalid();
            var bytes = Convert.FromBase64String(text);
            if (bytes.Length > maximum || Convert.ToBase64String(bytes) != text) throw Invalid();
            return bytes;
        }
        catch (FormatException) { throw Invalid(); }
    }
    internal static void Fields(JsonElement value, params string[] fields)
    {
        if (value.ValueKind != JsonValueKind.Object) throw Invalid();
        var remaining = fields.ToHashSet(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject()) if (!remaining.Remove(property.Name)) throw Invalid();
        if (remaining.Count != 0) throw Invalid();
    }
    internal static byte[] Decrypt(EnrollmentCode code, string label, byte[] combined, string? offerHash = null)
    {
        if (combined.Length is < 28 or > 8192) throw Invalid();
        var clear = new byte[combined.Length - 28]; var key = code.Derive(label);
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(combined.AsSpan(0, 12), combined.AsSpan(12, clear.Length), combined.AsSpan(12 + clear.Length), clear, Aad(code, label, offerHash));
            return clear;
        }
        catch (CryptographicException) { CryptographicOperations.ZeroMemory(clear); throw Invalid(); }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
    internal static byte[] Encrypt(EnrollmentCode code, string label, byte[] clear, string? offerHash = null)
    {
        if (clear.Length > 8164) throw Invalid();
        var combined = new byte[clear.Length + 28]; RandomNumberGenerator.Fill(combined.AsSpan(0, 12)); var key = code.Derive(label);
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Encrypt(combined.AsSpan(0, 12), clear, combined.AsSpan(12, clear.Length), combined.AsSpan(12 + clear.Length), Aad(code, label, offerHash));
            return combined;
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }
    private static byte[] Aad(EnrollmentCode code, string label, string? hash)
        => Encoding.UTF8.GetBytes($"JTS-PAIR-1\n{code.InvitationId:D}\n{label}" + (hash is null ? "" : "\n" + hash));
    internal static (byte[] Bytes, string Hash, RelayDelegatedEnrollment Request) ReadOffer(EnrollmentCode code, byte[] encrypted, TimeProvider clock)
    {
        var clear = Decrypt(code, "offer", encrypted);
        try
        {
            using var document = JsonDocument.Parse(clear); var p = document.RootElement;
            Fields(p, "version", "relayOrigin", "requestBase64", "requestSha256");
            if (p.GetProperty("version").GetInt32() != 1 || p.GetProperty("relayOrigin").GetString() != code.RelayOrigin) throw Invalid();
            var bytes = Base64(p.GetProperty("requestBase64").GetString()!, 16384); var hash = Hash(bytes);
            if (p.GetProperty("requestSha256").GetString() != hash) throw Invalid();
            return (bytes, hash, RelayDelegatedEnrollment.Parse(bytes, clock));
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException or ArgumentException or KeyNotFoundException) { throw Invalid(); }
        finally { CryptographicOperations.ZeroMemory(clear); }
    }
    internal static byte[] Response(EnrollmentCode code, string requestHash, byte[] enrollment, string offerHash)
        => Encrypt(code, "response", JsonSerializer.SerializeToUtf8Bytes(new { version = 1, invitationId = code.InvitationId.ToString("D"),
            relayOrigin = code.RelayOrigin, requestSha256 = requestHash, enrollmentBase64 = Convert.ToBase64String(enrollment) }), offerHash);
    internal static byte[] Transcript(Guid id, string controller, byte[] offer, byte[] response, byte[] spki)
        => Encoding.UTF8.GetBytes($"JTS-PAIR-1\n{id:D}\n{controller}\n{Hash(offer)}\n{Hash(response)}\n{Hash(spki)}");
    private static EnrollmentException Invalid() => new("ENROLLMENT_PAYLOAD_INVALID");
}
