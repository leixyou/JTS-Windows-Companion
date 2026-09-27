using System.Security.Cryptography;
using JTS.WindowsCompanion.Relay;
using JTS.WindowsCompanion.Runtime;

namespace JTS.WindowsCompanion.Pairing;

// Versioned binary local record, not the relay wire format. Strict framing avoids duplicate/unknown fields.
internal static class RelayPairingCodec
{
    internal const int MaximumPlaintext = 70 * 1024;
    internal const int MaximumCiphertext = MaximumPlaintext + 4096;

    internal static byte[] Seal(RelayPairingRecord record, ITaskPayloadProtector protector, byte[] purpose)
    {
        using var bytes = new MemoryStream();
        try
        {
            using (var writer = new BinaryWriter(bytes, System.Text.Encoding.UTF8, leaveOpen: true))
            {
                writer.Write((byte)1); writer.Write(record.PairingId.ToByteArray());
                writer.Write(Convert.FromHexString(record.ControllerDeviceId));
                writer.Write(record.Policy is not null);
                if (record.Policy is { } policy)
                {
                    writer.Write(record.ApprovedAt!.Value.ToUnixTimeMilliseconds()); writer.Write(policy.ExpiresAt.ToUnixTimeMilliseconds());
                    writer.Write((byte)policy.TlsPolicy);
                    writer.Write((byte)policy.AllowedLanes.Aggregate(0, (mask, lane) => mask | (1 << (int)lane)));
                    foreach (var lane in Enum.GetValues<RelayLane>())
                    {
                        var grants = policy.GrantsFor(lane); writer.Write(checked((ushort)grants.Count));
                        foreach (var id in grants) writer.Write(id.ToByteArray());
                    }
                }
                writer.Write(record.RevokedAt.HasValue);
                if (record.RevokedAt is { } revoked) writer.Write(revoked.ToUnixTimeMilliseconds());
            }
            if (bytes.Length > MaximumPlaintext) throw PairingValidation.Invalid();
            var cipher = protector.Protect(bytes.GetBuffer().AsSpan(0, (int)bytes.Length), purpose);
            if (cipher is not { Length: > 0 and <= MaximumCiphertext }) throw PairingValidation.Invalid();
            return cipher;
        }
        finally { CryptographicOperations.ZeroMemory(bytes.GetBuffer()); }
    }

    internal static RelayPairingRecord Open(byte[] cipher, string owner, Guid id, ITaskPayloadProtector protector, byte[] purpose)
    {
        byte[]? clear = null;
        try
        {
            if (cipher.Length is < 1 or > MaximumCiphertext) throw PairingValidation.Invalid();
            clear = protector.Unprotect(cipher, purpose);
            if (clear is not { Length: > 0 and <= MaximumPlaintext }) throw PairingValidation.Invalid();
            using var bytes = new MemoryStream(clear, writable: false); using var reader = new BinaryReader(bytes);
            if (reader.ReadByte() != 1 || ReadId(reader) != id
                || Convert.ToHexString(reader.ReadBytes(32)).ToLowerInvariant() != owner) throw PairingValidation.Invalid();
            RelayDevicePairing? policy = null; DateTimeOffset? approved = null, revoked = null;
            if (ReadBoolean(reader))
            {
                approved = DateTimeOffset.FromUnixTimeMilliseconds(reader.ReadInt64());
                var expires = DateTimeOffset.FromUnixTimeMilliseconds(reader.ReadInt64());
                var tls = (RelayTlsPolicy)reader.ReadByte(); var mask = reader.ReadByte();
                if (mask is < 1 or > 7 || expires <= approved) throw PairingValidation.Invalid();
                var lanes = Enum.GetValues<RelayLane>().Where(l => (mask & (1 << (int)l)) != 0).ToArray();
                var grants = new Dictionary<RelayLane, IReadOnlyList<Guid>>(); var total = 0;
                foreach (var lane in Enum.GetValues<RelayLane>())
                {
                    var count = reader.ReadUInt16(); total += count;
                    if (total > RelayDevicePairing.MaximumGrantIds || (!lanes.Contains(lane) && count != 0)) throw PairingValidation.Invalid();
                    var ids = new Guid[count]; for (var i = 0; i < count; i++) ids[i] = ReadId(reader);
                    if (lanes.Contains(lane)) grants.Add(lane, ids);
                }
                policy = new(id, owner, tls, expires, lanes, grants);
            }
            if (ReadBoolean(reader)) revoked = DateTimeOffset.FromUnixTimeMilliseconds(reader.ReadInt64());
            if (bytes.Position != bytes.Length || (policy is null && revoked is null)) throw PairingValidation.Invalid();
            return new(owner, id, policy, approved, revoked);
        }
        catch (Exception e) when (e is CryptographicException or ArgumentException or EndOfStreamException or OverflowException)
        { throw PairingValidation.Invalid(); }
        finally { if (clear is not null) CryptographicOperations.ZeroMemory(clear); }
    }

    private static Guid ReadId(BinaryReader reader)
    {
        var bytes = reader.ReadBytes(16);
        if (bytes.Length != 16 || new Guid(bytes) == Guid.Empty) throw PairingValidation.Invalid();
        return new Guid(bytes);
    }
    private static bool ReadBoolean(BinaryReader reader) => reader.ReadByte() switch
    { 0 => false, 1 => true, _ => throw PairingValidation.Invalid() };
}
