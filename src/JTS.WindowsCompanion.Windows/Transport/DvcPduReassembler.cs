using System.Buffers.Binary;
using JTS.WindowsCompanion.Protocol;

namespace JTS.WindowsCompanion.Windows.Transport;

[Flags]
internal enum DvcPduFlags : uint
{
    Middle = 0,
    First = 1,
    Last = 2,
    Only = First | Last,
}

/// <summary>
/// Reassembles the CHANNEL_PDU_HEADER-prefixed chunks returned by
/// WTSVirtualChannelRead for a Dynamic Virtual Channel.
/// </summary>
internal sealed class DvcPduReassembler
{
    internal const int HeaderLength = sizeof(uint) * 2;
    private const uint KnownFlags = (uint)DvcPduFlags.Only;

    private byte[]? _buffer;
    private int _count;
    private int _expectedLength;

    public bool TryAppend(ReadOnlySpan<byte> pdu, out ReadOnlyMemory<byte> message)
    {
        message = default;
        if (pdu.Length < HeaderLength)
        {
            throw Error(
                "DVC_PDU_HEADER_TRUNCATED",
                "The Dynamic Virtual Channel PDU header is incomplete.");
        }

        var declaredLength = BinaryPrimitives.ReadUInt32LittleEndian(pdu[..sizeof(uint)]);
        var rawFlags = BinaryPrimitives.ReadUInt32LittleEndian(pdu.Slice(sizeof(uint), sizeof(uint)));
        if ((rawFlags & ~KnownFlags) != 0)
        {
            throw Error(
                "DVC_PDU_FLAGS_INVALID",
                "The Dynamic Virtual Channel PDU contains unsupported flags.");
        }

        if (declaredLength == 0)
        {
            throw Error(
                "DVC_PDU_LENGTH_INVALID",
                "The Dynamic Virtual Channel message length must be positive.");
        }

        if (declaredLength > CompanionProtocol.MaxBufferedBytes)
        {
            throw Error(
                "DVC_PDU_BUFFER_LIMIT",
                "The Dynamic Virtual Channel message exceeds the receive buffer limit.");
        }

        var expectedLength = checked((int)declaredLength);
        var payload = pdu[HeaderLength..];
        if (payload.IsEmpty || payload.Length > expectedLength)
        {
            throw Error(
                "DVC_PDU_LENGTH_INVALID",
                "The Dynamic Virtual Channel chunk length is invalid.");
        }

        var flags = (DvcPduFlags)rawFlags;
        var isFirst = (flags & DvcPduFlags.First) != 0;
        var isLast = (flags & DvcPduFlags.Last) != 0;

        if (isFirst)
        {
            if (_buffer is not null)
            {
                throw Error(
                    "DVC_PDU_SEQUENCE_INVALID",
                    "A Dynamic Virtual Channel message started before the previous message ended.");
            }

            if (isLast)
            {
                if (payload.Length != expectedLength)
                {
                    throw Error(
                        "DVC_PDU_LENGTH_INVALID",
                        "The complete Dynamic Virtual Channel chunk does not match its declared length.");
                }

                message = payload.ToArray();
                return true;
            }

            if (payload.Length >= expectedLength)
            {
                throw Error(
                    "DVC_PDU_LENGTH_INVALID",
                    "A non-final Dynamic Virtual Channel chunk completes its declared message length.");
            }

            _buffer = GC.AllocateUninitializedArray<byte>(expectedLength);
            payload.CopyTo(_buffer);
            _count = payload.Length;
            _expectedLength = expectedLength;
            return false;
        }

        if (_buffer is null)
        {
            throw Error(
                "DVC_PDU_SEQUENCE_INVALID",
                "A Dynamic Virtual Channel continuation arrived without a first chunk.");
        }

        if (expectedLength != _expectedLength)
        {
            throw Error(
                "DVC_PDU_LENGTH_INVALID",
                "The Dynamic Virtual Channel declared length changed during reassembly.");
        }

        var nextCount = checked(_count + payload.Length);
        if (nextCount > _expectedLength || (!isLast && nextCount == _expectedLength))
        {
            throw Error(
                "DVC_PDU_LENGTH_INVALID",
                "The Dynamic Virtual Channel chunks do not match the declared message length.");
        }

        if (isLast && nextCount != _expectedLength)
        {
            throw Error(
                "DVC_PDU_LENGTH_INVALID",
                "The last Dynamic Virtual Channel chunk does not complete the declared message length.");
        }

        payload.CopyTo(_buffer.AsSpan(_count));
        _count = nextCount;
        if (!isLast)
        {
            return false;
        }

        var completed = _buffer;
        ClearState();
        message = completed;
        return true;
    }

    public void Reset()
    {
        if (_buffer is not null && _count > 0)
        {
            Array.Clear(_buffer, 0, _count);
        }

        ClearState();
    }

    private CompanionProtocolException Error(string code, string message)
    {
        Reset();
        return new CompanionProtocolException(code, message);
    }

    private void ClearState()
    {
        _buffer = null;
        _count = 0;
        _expectedLength = 0;
    }
}
