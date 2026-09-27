using System.Security.Cryptography;
using System.Text.Json;
using JTS.WindowsCompanion.Runtime;

namespace JTS.WindowsCompanion.Control;

public sealed class ControlPolicyException(string code) : IOException(code)
{
    public string Code { get; } = code;
}

/// <summary>Local management metadata. A tombstone can exist before any approval.</summary>
public sealed record ControlPolicyRecord(string OwnerDeviceId, Guid GrantId, ControlGrant? Grant,
    DateTimeOffset? ApprovedAt, DateTimeOffset? RevokedAt);

internal static class ControlPolicyCodec
{
    internal const int MaximumPlaintext = 8 * 1024;
    internal const int MaximumCiphertext = MaximumPlaintext + 4096;
    private static readonly JsonSerializerOptions Options = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    internal static void Identity(string owner, Guid id)
    {
        if (owner is not { Length: 64 } || owner.Any(c => !"0123456789abcdef".Contains(c)) || id == Guid.Empty)
            throw new ControlPolicyException("CONTROL_POLICY_IDENTITY_INVALID");
    }

    internal static bool SameGrant(ControlGrant a, ControlGrant b) => a.OwnerDeviceId == b.OwnerDeviceId
        && a.GrantId == b.GrantId && a.ExpiresAt == b.ExpiresAt && a.AllowDisconnected == b.AllowDisconnected
        && a.Operations.SequenceEqual(b.Operations) && a.JobKinds.SequenceEqual(b.JobKinds);

    internal static byte[] Seal(ControlPolicyRecord record, ITaskPayloadProtector protector, byte[] purpose)
    {
        var grant = record.Grant;
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new
        {
            version = 1, owner = record.OwnerDeviceId, grantId = record.GrantId.ToString("D"),
            approvedAt = record.ApprovedAt?.ToUnixTimeMilliseconds(), revokedAt = record.RevokedAt?.ToUnixTimeMilliseconds(),
            grant = grant is null ? null : new GrantData(grant.ExpiresAt.ToUnixTimeMilliseconds(), grant.AllowDisconnected,
                grant.Operations.Select(ControlWire.Name).ToArray(), grant.JobKinds.ToArray()),
        }, Options);
        try
        {
            if (bytes.Length > MaximumPlaintext) throw Invalid();
            var cipher = protector.Protect(bytes, purpose);
            if (cipher is not { Length: > 0 and <= MaximumCiphertext }) throw Invalid();
            return cipher;
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    internal static ControlPolicyRecord Open(byte[] cipher, string owner, Guid id, ITaskPayloadProtector protector, byte[] purpose)
    {
        byte[]? clear = null;
        try
        {
            if (cipher.Length is 0 or > MaximumCiphertext) throw Invalid();
            clear = protector.Unprotect(cipher, purpose);
            if (clear is not { Length: > 0 and <= MaximumPlaintext }) throw Invalid();
            using var doc = ControlWire.Parse(clear);
            var node = doc.RootElement;
            ControlWire.Fields(node, "version", "owner", "grantId", "approvedAt", "revokedAt", "grant");
            if (ControlWire.Integer(node, "version") != 1 || ControlWire.Text(node, "owner", 64) != owner
                || ControlWire.Id(node, "grantId") != id) throw Invalid();
            var approved = Time(node, "approvedAt"); var revoked = Time(node, "revokedAt");
            var value = node.GetProperty("grant"); ControlGrant? grant = null;
            if (value.ValueKind != JsonValueKind.Null)
            {
                ControlWire.Fields(value, "expiresAt", "allowDisconnected", "operations", "jobKinds");
                var ops = Strings(value, "operations", 5, 32).Select(ControlWire.Operation).ToArray();
                var kinds = Strings(value, "jobKinds", 32, 64);
                grant = new(owner, id, DateTimeOffset.FromUnixTimeMilliseconds(ControlWire.Integer(value, "expiresAt")),
                    ops, kinds, ControlWire.Boolean(value, "allowDisconnected"));
                if (approved is null || grant.ExpiresAt <= approved) throw Invalid();
            }
            else if (approved is not null || revoked is null) throw Invalid();
            return new(owner, id, grant, approved, revoked);
        }
        catch (Exception error) when (error is CryptographicException or JsonException or ArgumentException
            or ControlProtocolException or InvalidOperationException) { throw Invalid(); }
        finally { if (clear is not null) CryptographicOperations.ZeroMemory(clear); }
    }

    private static string[] Strings(JsonElement node, string name, int maximumCount, int maximumLength)
    {
        var value = node.GetProperty(name);
        if (value.ValueKind != JsonValueKind.Array || value.GetArrayLength() > maximumCount) throw Invalid();
        var result = value.EnumerateArray().Select(v => v.ValueKind == JsonValueKind.String ? v.GetString() : null).ToArray();
        if (result.Any(v => v is null || v.Length is 0 || v.Length > maximumLength)
            || result.Distinct(StringComparer.Ordinal).Count() != result.Length) throw Invalid();
        return result.Select(v => v!).ToArray();
    }
    private static DateTimeOffset? Time(JsonElement node, string name)
        => node.GetProperty(name).ValueKind == JsonValueKind.Null ? null
            : DateTimeOffset.FromUnixTimeMilliseconds(ControlWire.Integer(node, name));
    internal static ControlPolicyException Invalid() => new("CONTROL_POLICY_INVALID");
    private sealed record GrantData(long ExpiresAt, bool AllowDisconnected, string[] Operations, string[] JobKinds);
}
