using System.Buffers.Binary;
using System.Security.Cryptography;

namespace JTS.WindowsCompanion.Protocol;

public sealed record CompanionFrame(
    ushort Version,
    CompanionFrameType Type,
    CompanionFrameFlags Flags,
    ulong Sequence,
    ReadOnlyMemory<byte> Payload);

public static class CompanionFrameCodec
{
    private static ReadOnlySpan<byte> Magic => "JTSD"u8;

    public static byte[] Encode(CompanionFrame frame)
    {
        ValidatePayloadLength(frame.Type, frame.Payload.Length);

        var output = GC.AllocateUninitializedArray<byte>(CompanionProtocol.HeaderLength + frame.Payload.Length);
        Magic.CopyTo(output);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4, 2), frame.Version);
        output[6] = (byte)frame.Type;
        output[7] = (byte)frame.Flags;
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(8, 8), frame.Sequence);
        BinaryPrimitives.WriteInt32BigEndian(output.AsSpan(16, 4), frame.Payload.Length);
        WriteDigest(frame.Payload.Span, output.AsSpan(20, 4));
        frame.Payload.Span.CopyTo(output.AsSpan(CompanionProtocol.HeaderLength));
        return output;
    }

    internal static CompanionFrame Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < CompanionProtocol.HeaderLength)
        {
            throw new CompanionProtocolException("FRAME_TRUNCATED", "The frame header is incomplete.");
        }

        if (!encoded[..4].SequenceEqual(Magic))
        {
            throw new CompanionProtocolException("FRAME_MAGIC_INVALID", "The frame magic is invalid.");
        }

        var version = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(4, 2));
        var type = (CompanionFrameType)encoded[6];
        if (!Enum.IsDefined(type))
        {
            throw new CompanionProtocolException("FRAME_TYPE_INVALID", "The frame type is not supported.");
        }

        var flags = (CompanionFrameFlags)encoded[7];
        var sequence = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(8, 8));
        var payloadLength = BinaryPrimitives.ReadInt32BigEndian(encoded.Slice(16, 4));
        ValidatePayloadLength(type, payloadLength);
        if (encoded.Length != CompanionProtocol.HeaderLength + payloadLength)
        {
            throw new CompanionProtocolException("FRAME_LENGTH_INVALID", "The frame length does not match its header.");
        }

        var payload = encoded[CompanionProtocol.HeaderLength..];
        Span<byte> digest = stackalloc byte[4];
        WriteDigest(payload, digest);
        if (!CryptographicOperations.FixedTimeEquals(digest, encoded.Slice(20, 4)))
        {
            throw new CompanionProtocolException("FRAME_DIGEST_INVALID", "The frame payload digest is invalid.");
        }

        return new CompanionFrame(version, type, flags, sequence, payload.ToArray());
    }

    internal static int ReadEncodedLength(ReadOnlySpan<byte> header)
    {
        if (header.Length < CompanionProtocol.HeaderLength)
        {
            throw new ArgumentException("A complete header is required.", nameof(header));
        }

        if (!header[..4].SequenceEqual(Magic))
        {
            throw new CompanionProtocolException("FRAME_MAGIC_INVALID", "The frame magic is invalid.");
        }

        var type = (CompanionFrameType)header[6];
        if (!Enum.IsDefined(type))
        {
            throw new CompanionProtocolException("FRAME_TYPE_INVALID", "The frame type is not supported.");
        }

        var payloadLength = BinaryPrimitives.ReadInt32BigEndian(header.Slice(16, 4));
        ValidatePayloadLength(type, payloadLength);
        return checked(CompanionProtocol.HeaderLength + payloadLength);
    }

    private static void ValidatePayloadLength(CompanionFrameType type, int payloadLength)
    {
        var maximum = type == CompanionFrameType.BinaryChunk
            ? CompanionProtocol.MaxBinaryPayloadBytes
            : CompanionProtocol.MaxControlPayloadBytes;
        if (payloadLength < 0 || payloadLength > maximum)
        {
            throw new CompanionProtocolException("FRAME_TOO_LARGE", "The frame payload is outside the allowed size.");
        }
    }

    private static void WriteDigest(ReadOnlySpan<byte> payload, Span<byte> destination)
    {
        Span<byte> fullDigest = stackalloc byte[SHA256.HashSizeInBytes];
        SHA256.HashData(payload, fullDigest);
        fullDigest[..destination.Length].CopyTo(destination);
        CryptographicOperations.ZeroMemory(fullDigest);
    }
}

public sealed class CompanionFrameDecoder
{
    private byte[] _buffer = new byte[16 * 1024];
    private int _count;

    public void Append(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length > CompanionProtocol.MaxBufferedBytes - _count)
        {
            throw new CompanionProtocolException("FRAME_BUFFER_LIMIT", "The frame buffer limit was exceeded.");
        }

        EnsureCapacity(_count + bytes.Length);
        bytes.CopyTo(_buffer.AsSpan(_count));
        _count += bytes.Length;
    }

    public bool TryRead(out CompanionFrame? frame)
    {
        frame = null;
        if (_count < CompanionProtocol.HeaderLength)
        {
            return false;
        }

        var encodedLength = CompanionFrameCodec.ReadEncodedLength(_buffer.AsSpan(0, CompanionProtocol.HeaderLength));
        if (_count < encodedLength)
        {
            return false;
        }

        frame = CompanionFrameCodec.Decode(_buffer.AsSpan(0, encodedLength));
        _count -= encodedLength;
        if (_count > 0)
        {
            _buffer.AsSpan(encodedLength, _count).CopyTo(_buffer);
        }

        return true;
    }

    public void Reset()
    {
        if (_count > 0)
        {
            Array.Clear(_buffer, 0, _count);
            _count = 0;
        }
    }

    private void EnsureCapacity(int required)
    {
        if (_buffer.Length >= required)
        {
            return;
        }

        var newSize = Math.Min(CompanionProtocol.MaxBufferedBytes, Math.Max(required, _buffer.Length * 2));
        Array.Resize(ref _buffer, newSize);
    }
}
