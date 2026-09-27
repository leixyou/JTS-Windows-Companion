using System.Buffers.Binary;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Windows.Transport;

namespace JTS.WindowsCompanion.Tests;

public sealed class DvcPduReassemblerTests
{
    [Fact]
    public void OnlyChunk_ReturnsCompleteMessage()
    {
        var reassembler = new DvcPduReassembler();
        var payload = "complete-message"u8.ToArray();

        var completed = reassembler.TryAppend(
            CreatePdu(payload.Length, DvcPduFlags.Only, payload),
            out var message);

        Assert.True(completed);
        Assert.Equal(payload, message.ToArray());
    }

    [Fact]
    public void FirstMiddleLast_ReassemblesFrameForCompanionDecoder()
    {
        var expectedFrame = new CompanionFrame(
            CompanionProtocol.CurrentVersion,
            CompanionFrameType.ControlJson,
            CompanionFrameFlags.Final,
            73,
            "{\"ready\":true,\"source\":\"dvc\"}"u8.ToArray());
        var encodedFrame = CompanionFrameCodec.Encode(expectedFrame);
        var reassembler = new DvcPduReassembler();

        Assert.False(reassembler.TryAppend(
            CreatePdu(encodedFrame.Length, DvcPduFlags.First, encodedFrame[..11]),
            out _));
        Assert.False(reassembler.TryAppend(
            CreatePdu(encodedFrame.Length, DvcPduFlags.Middle, encodedFrame[11..29]),
            out _));
        Assert.True(reassembler.TryAppend(
            CreatePdu(encodedFrame.Length, DvcPduFlags.Last, encodedFrame[29..]),
            out var message));

        var decoder = new CompanionFrameDecoder();
        decoder.Append(message.Span);
        Assert.True(decoder.TryRead(out var actualFrame));
        Assert.NotNull(actualFrame);
        Assert.Equal(expectedFrame.Sequence, actualFrame.Sequence);
        Assert.Equal(expectedFrame.Payload.ToArray(), actualFrame.Payload.ToArray());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(DvcPduReassembler.HeaderLength - 1)]
    public void TruncatedHeader_IsRejected(int byteCount)
    {
        var reassembler = new DvcPduReassembler();

        var exception = Assert.Throws<CompanionProtocolException>(() =>
            reassembler.TryAppend(new byte[byteCount], out _));

        Assert.Equal("DVC_PDU_HEADER_TRUNCATED", exception.Code);
    }

    [Fact]
    public void UnsupportedFlags_AreRejected()
    {
        var reassembler = new DvcPduReassembler();
        var pdu = CreatePdu(1, (DvcPduFlags)0x10, [0x41]);

        var exception = Assert.Throws<CompanionProtocolException>(() =>
            reassembler.TryAppend(pdu, out _));

        Assert.Equal("DVC_PDU_FLAGS_INVALID", exception.Code);
    }

    [Theory]
    [InlineData((uint)DvcPduFlags.Middle)]
    [InlineData((uint)DvcPduFlags.Last)]
    public void ContinuationWithoutFirst_IsRejected(uint rawFlags)
    {
        var reassembler = new DvcPduReassembler();

        var exception = Assert.Throws<CompanionProtocolException>(() =>
            reassembler.TryAppend(CreatePdu(2, (DvcPduFlags)rawFlags, [0x41]), out _));

        Assert.Equal("DVC_PDU_SEQUENCE_INVALID", exception.Code);
    }

    [Fact]
    public void NestedFirst_IsRejectedAndClearsPartialMessage()
    {
        var reassembler = new DvcPduReassembler();
        Assert.False(reassembler.TryAppend(
            CreatePdu(4, DvcPduFlags.First, [0x41]),
            out _));

        var exception = Assert.Throws<CompanionProtocolException>(() =>
            reassembler.TryAppend(CreatePdu(4, DvcPduFlags.First, [0x42]), out _));

        Assert.Equal("DVC_PDU_SEQUENCE_INVALID", exception.Code);
        Assert.True(reassembler.TryAppend(
            CreatePdu(1, DvcPduFlags.Only, [0x43]),
            out var recovered));
        Assert.Equal([0x43], recovered.ToArray());
    }

    [Fact]
    public void DeclaredLengthChange_IsRejected()
    {
        var reassembler = new DvcPduReassembler();
        Assert.False(reassembler.TryAppend(
            CreatePdu(4, DvcPduFlags.First, [0x41]),
            out _));

        var exception = Assert.Throws<CompanionProtocolException>(() =>
            reassembler.TryAppend(CreatePdu(5, DvcPduFlags.Middle, [0x42]), out _));

        Assert.Equal("DVC_PDU_LENGTH_INVALID", exception.Code);
    }

    [Theory]
    [InlineData(1, 2)]
    [InlineData(3, 2)]
    public void OnlyChunkLengthMismatch_IsRejected(int declaredLength, int payloadLength)
    {
        var reassembler = new DvcPduReassembler();

        var exception = Assert.Throws<CompanionProtocolException>(() =>
            reassembler.TryAppend(
                CreatePdu(declaredLength, DvcPduFlags.Only, new byte[payloadLength]),
                out _));

        Assert.Equal("DVC_PDU_LENGTH_INVALID", exception.Code);
    }

    [Theory]
    [InlineData(3)]
    [InlineData(5)]
    public void LastChunkMustCompleteExactDeclaredLength(int finalPayloadLength)
    {
        var reassembler = new DvcPduReassembler();
        Assert.False(reassembler.TryAppend(
            CreatePdu(6, DvcPduFlags.First, [0x41, 0x42]),
            out _));

        var exception = Assert.Throws<CompanionProtocolException>(() =>
            reassembler.TryAppend(
                CreatePdu(6, DvcPduFlags.Last, new byte[finalPayloadLength]),
                out _));

        Assert.Equal("DVC_PDU_LENGTH_INVALID", exception.Code);
    }

    [Fact]
    public void MiddleChunkCannotCompleteDeclaredLength()
    {
        var reassembler = new DvcPduReassembler();
        Assert.False(reassembler.TryAppend(
            CreatePdu(4, DvcPduFlags.First, [0x41, 0x42]),
            out _));

        var exception = Assert.Throws<CompanionProtocolException>(() =>
            reassembler.TryAppend(
                CreatePdu(4, DvcPduFlags.Middle, [0x43, 0x44]),
                out _));

        Assert.Equal("DVC_PDU_LENGTH_INVALID", exception.Code);
    }

    [Fact]
    public void MessageOverBufferLimit_IsRejectedBeforeAllocation()
    {
        var reassembler = new DvcPduReassembler();

        var exception = Assert.Throws<CompanionProtocolException>(() =>
            reassembler.TryAppend(
                CreatePdu(CompanionProtocol.MaxBufferedBytes + 1L, DvcPduFlags.First, [0x41]),
                out _));

        Assert.Equal("DVC_PDU_BUFFER_LIMIT", exception.Code);
    }

    [Fact]
    public void ZeroLengthMessage_IsRejected()
    {
        var reassembler = new DvcPduReassembler();

        var exception = Assert.Throws<CompanionProtocolException>(() =>
            reassembler.TryAppend(CreatePdu(0, DvcPduFlags.Only, []), out _));

        Assert.Equal("DVC_PDU_LENGTH_INVALID", exception.Code);
    }

    [Fact]
    public void Reset_DiscardsInProgressMessage()
    {
        var reassembler = new DvcPduReassembler();
        Assert.False(reassembler.TryAppend(
            CreatePdu(4, DvcPduFlags.First, [0x41, 0x42]),
            out _));

        reassembler.Reset();

        var exception = Assert.Throws<CompanionProtocolException>(() =>
            reassembler.TryAppend(
                CreatePdu(4, DvcPduFlags.Last, [0x43, 0x44]),
                out _));
        Assert.Equal("DVC_PDU_SEQUENCE_INVALID", exception.Code);
    }

    [Fact]
    public void EmptyFragment_IsRejectedAndClearsPartialMessage()
    {
        var reassembler = new DvcPduReassembler();
        Assert.False(reassembler.TryAppend(
            CreatePdu(2, DvcPduFlags.First, [0x41]),
            out _));

        var exception = Assert.Throws<CompanionProtocolException>(() =>
            reassembler.TryAppend(CreatePdu(2, DvcPduFlags.Last, []), out _));

        Assert.Equal("DVC_PDU_LENGTH_INVALID", exception.Code);
        Assert.True(reassembler.TryAppend(
            CreatePdu(1, DvcPduFlags.Only, [0x42]),
            out var recovered));
        Assert.Equal([0x42], recovered.ToArray());
    }

    private static byte[] CreatePdu(long declaredLength, DvcPduFlags flags, ReadOnlySpan<byte> payload)
    {
        var pdu = new byte[DvcPduReassembler.HeaderLength + payload.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(pdu, checked((uint)declaredLength));
        BinaryPrimitives.WriteUInt32LittleEndian(
            pdu.AsSpan(sizeof(uint), sizeof(uint)),
            (uint)flags);
        payload.CopyTo(pdu.AsSpan(DvcPduReassembler.HeaderLength));
        return pdu;
    }
}
