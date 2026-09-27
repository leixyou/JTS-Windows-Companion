using System.Buffers.Binary;
using System.Security.Cryptography;

namespace JTS.WindowsCompanion.Protocol;

public sealed record BinaryChunk(Guid TransferId, long Offset, bool Final, ReadOnlyMemory<byte> Data);

public static class BinaryChunkCodec
{
    internal const int HeaderLength = 16 + 8 + 1 + 4 + SHA256.HashSizeInBytes;
    internal const int MaximumDataLength =
        CompanionProtocol.MaxAuthenticatedBinaryPayloadBytes - HeaderLength;

    public static byte[] Encode(BinaryChunk chunk)
    {
        if (chunk.Offset < 0 || chunk.Data.Length > MaximumDataLength)
        {
            throw new CompanionProtocolException("CHUNK_INVALID", "The binary chunk is outside the allowed bounds.");
        }

        var output = GC.AllocateUninitializedArray<byte>(HeaderLength + chunk.Data.Length);
        chunk.TransferId.TryWriteBytes(output);
        BinaryPrimitives.WriteInt64BigEndian(output.AsSpan(16, 8), chunk.Offset);
        output[24] = chunk.Final ? (byte)1 : (byte)0;
        BinaryPrimitives.WriteInt32BigEndian(output.AsSpan(25, 4), chunk.Data.Length);
        SHA256.HashData(chunk.Data.Span, output.AsSpan(29, SHA256.HashSizeInBytes));
        chunk.Data.Span.CopyTo(output.AsSpan(HeaderLength));
        return output;
    }

    public static BinaryChunk Decode(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < HeaderLength)
        {
            throw new CompanionProtocolException("CHUNK_TRUNCATED", "The binary chunk header is incomplete.");
        }

        var dataLength = BinaryPrimitives.ReadInt32BigEndian(payload.Slice(25, 4));
        if (dataLength < 0
            || dataLength > MaximumDataLength
            || payload.Length != HeaderLength + dataLength)
        {
            throw new CompanionProtocolException("CHUNK_LENGTH_INVALID", "The binary chunk length is invalid.");
        }

        var offset = BinaryPrimitives.ReadInt64BigEndian(payload.Slice(16, 8));
        var finalValue = payload[24];
        if (offset < 0 || finalValue > 1)
        {
            throw new CompanionProtocolException("CHUNK_INVALID", "The binary chunk is outside the allowed bounds.");
        }

        var data = payload[HeaderLength..];
        Span<byte> digest = stackalloc byte[SHA256.HashSizeInBytes];
        SHA256.HashData(data, digest);
        if (!CryptographicOperations.FixedTimeEquals(digest, payload.Slice(29, SHA256.HashSizeInBytes)))
        {
            throw new CompanionProtocolException("CHUNK_DIGEST_INVALID", "The binary chunk digest is invalid.");
        }

        return new BinaryChunk(
            new Guid(payload[..16]),
            offset,
            finalValue == 1,
            data.ToArray());
    }
}
