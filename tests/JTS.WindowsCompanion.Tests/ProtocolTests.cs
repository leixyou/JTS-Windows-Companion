using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Security;

namespace JTS.WindowsCompanion.Tests;

public sealed class ProtocolTests
{
    private const string SwiftRequestFixtureHex = "4A545344000101010102030405060708000000EE639F36787B2270726F746F636F6C56657273696F6E223A312C22726571756573744964223A2230303131323233332D343435352D363637372D383839392D616162626363646465656666222C226D6574686F64223A22636F6D70616E696F6E2E68656C6C6F222C22646561646C696E65556E69784D696C6C697365636F6E6473223A313730303030303030303030302C226964656D706F74656E63794B6579223A22666978747572652D31222C22657870656374656453746174655265766973696F6E223A372C22706172616D6574657273223A7B22636C69656E744E616D65223A224A5453205465726D696E616C227D7D";

    private const string DotNetResponseFixtureHex = "4A5453440001010100000000000000090000006FCB33D9AE7B2270726F746F636F6C56657273696F6E223A312C22726571756573744964223A2230303131323233332D343435352D363637372D383839392D616162626363646465656666222C2273756363657373223A747275652C22726573756C74223A7B227265616479223A747275657D7D";

    private const string BinaryFixtureHex = "4A54534400010201000000000000000A00000048F3F67DED33221100554477668899AABBCCDDEEFF0000000000001000010000000B2DA5FCCB1C91B935DBEC5F8061B905162C9D33B0FF6E71B01A9A06BF66AEF55262696E6172792D64617461";

    [Fact]
    public void Protocol_UsesProductWideDynamicVirtualChannelName()
    {
        Assert.Equal("JTS.Companion.v1", CompanionProtocol.DynamicVirtualChannelName);
    }

    [Fact]
    public void FrameDecoder_ReassemblesFragmentedFrames()
    {
        var expected = new CompanionFrame(
            CompanionProtocol.CurrentVersion,
            CompanionFrameType.ControlJson,
            CompanionFrameFlags.Final,
            42,
            "{\"ok\":true}"u8.ToArray());
        var encoded = CompanionFrameCodec.Encode(expected);
        var decoder = new CompanionFrameDecoder();

        foreach (var chunk in encoded.Chunk(3))
        {
            decoder.Append(chunk);
        }

        Assert.True(decoder.TryRead(out var actual));
        Assert.NotNull(actual);
        Assert.Equal(expected.Version, actual.Version);
        Assert.Equal(expected.Type, actual.Type);
        Assert.Equal(expected.Flags, actual.Flags);
        Assert.Equal(expected.Sequence, actual.Sequence);
        Assert.Equal(expected.Payload.ToArray(), actual.Payload.ToArray());
        Assert.False(decoder.TryRead(out _));
    }

    [Fact]
    public void FrameDecoder_ResetDiscardsPartialFrame()
    {
        var expected = new CompanionFrame(
            CompanionProtocol.CurrentVersion,
            CompanionFrameType.ControlJson,
            CompanionFrameFlags.Final,
            43,
            "{\"reconnected\":true}"u8.ToArray());
        var encoded = CompanionFrameCodec.Encode(expected);
        var decoder = new CompanionFrameDecoder();
        decoder.Append(encoded.AsSpan(0, CompanionProtocol.HeaderLength - 1));

        decoder.Reset();
        decoder.Append(encoded);

        Assert.True(decoder.TryRead(out var actual));
        Assert.NotNull(actual);
        Assert.Equal(expected.Sequence, actual.Sequence);
        Assert.Equal(expected.Payload.ToArray(), actual.Payload.ToArray());
        Assert.False(decoder.TryRead(out _));
    }

    [Fact]
    public void FrameDecoder_RejectsTamperedPayload()
    {
        var encoded = CompanionFrameCodec.Encode(new CompanionFrame(
            CompanionProtocol.CurrentVersion,
            CompanionFrameType.ControlJson,
            CompanionFrameFlags.Final,
            1,
            "payload"u8.ToArray()));
        encoded[^1] ^= 0x1;
        var decoder = new CompanionFrameDecoder();
        decoder.Append(encoded);

        var exception = Assert.Throws<CompanionProtocolException>(() => decoder.TryRead(out _));
        Assert.Equal("FRAME_DIGEST_INVALID", exception.Code);
    }

    [Fact]
    public void FrameCodec_RejectsOversizedControlPayload()
    {
        var frame = new CompanionFrame(
            CompanionProtocol.CurrentVersion,
            CompanionFrameType.ControlJson,
            CompanionFrameFlags.Final,
            1,
            new byte[CompanionProtocol.MaxControlPayloadBytes + 1]);

        var exception = Assert.Throws<CompanionProtocolException>(() => CompanionFrameCodec.Encode(frame));
        Assert.Equal("FRAME_TOO_LARGE", exception.Code);
    }

    [Fact]
    public void FrameCodec_DecodesSwiftRequestFixture()
    {
        var encoded = Convert.FromHexString(SwiftRequestFixtureHex);
        var decoder = new CompanionFrameDecoder();
        decoder.Append(encoded);

        Assert.True(decoder.TryRead(out var frame));
        Assert.NotNull(frame);
        Assert.Equal(CompanionProtocol.CurrentVersion, frame.Version);
        Assert.Equal(CompanionFrameType.ControlJson, frame.Type);
        Assert.Equal(CompanionFrameFlags.Final, frame.Flags);
        Assert.Equal(0x0102030405060708UL, frame.Sequence);
        Assert.Equal(encoded, CompanionFrameCodec.Encode(frame));

        var request = ControlMessageSerializer.Deserialize<CompanionRequest>(frame.Payload.Span);
        Assert.Equal(Guid.Parse("00112233-4455-6677-8899-aabbccddeeff"), request.RequestId);
        Assert.Equal("companion.hello", request.Method);
        Assert.Equal(1_700_000_000_000, request.DeadlineUnixMilliseconds);
        Assert.Equal("fixture-1", request.IdempotencyKey);
        Assert.Equal(7UL, request.ExpectedStateRevision);
        Assert.Equal("JTS Terminal", request.Parameters.GetProperty("clientName").GetString());
    }

    [Fact]
    public void FrameCodec_DotNetResponseMatchesSwiftFixture()
    {
        var requestId = Guid.Parse("00112233-4455-6677-8899-aabbccddeeff");
        var response = CompanionResponse.Ok(requestId, new { ready = true });
        var frame = new CompanionFrame(
            CompanionProtocol.CurrentVersion,
            CompanionFrameType.ControlJson,
            CompanionFrameFlags.Final,
            9,
            ControlMessageSerializer.Serialize(response));

        Assert.Equal(DotNetResponseFixtureHex, Convert.ToHexString(CompanionFrameCodec.Encode(frame)));
    }

    [Fact]
    public void BinaryChunkCodec_RoundTripsAndAuthenticatesChunk()
    {
        var expected = new BinaryChunk(Guid.NewGuid(), 4096, true, "binary-data"u8.ToArray());
        var encoded = BinaryChunkCodec.Encode(expected);
        var actual = BinaryChunkCodec.Decode(encoded);

        Assert.Equal(expected.TransferId, actual.TransferId);
        Assert.Equal(expected.Offset, actual.Offset);
        Assert.Equal(expected.Final, actual.Final);
        Assert.Equal(expected.Data.ToArray(), actual.Data.ToArray());

        encoded[^1] ^= 0x1;
        var exception = Assert.Throws<CompanionProtocolException>(() => BinaryChunkCodec.Decode(encoded));
        Assert.Equal("CHUNK_DIGEST_INVALID", exception.Code);
    }

    [Fact]
    public void BinaryChunkCodec_MatchesSwiftGuidAndDigestFixture()
    {
        var chunk = new BinaryChunk(
            Guid.Parse("00112233-4455-6677-8899-aabbccddeeff"),
            4096,
            true,
            "binary-data"u8.ToArray());
        var frame = new CompanionFrame(
            CompanionProtocol.CurrentVersion,
            CompanionFrameType.BinaryChunk,
            CompanionFrameFlags.Final,
            10,
            BinaryChunkCodec.Encode(chunk));

        var encoded = CompanionFrameCodec.Encode(frame);
        Assert.Equal(BinaryFixtureHex, Convert.ToHexString(encoded));

        var decodedFrame = DecodeFrame(encoded);
        var decodedChunk = BinaryChunkCodec.Decode(decodedFrame.Payload.Span);
        Assert.Equal(chunk.TransferId, decodedChunk.TransferId);
        Assert.Equal(chunk.Offset, decodedChunk.Offset);
        Assert.Equal(chunk.Final, decodedChunk.Final);
        Assert.Equal(chunk.Data.ToArray(), decodedChunk.Data.ToArray());
    }

    [Fact]
    public void ReplayGuard_RequiresStrictlyIncreasingSequence()
    {
        var guard = new SequenceReplayGuard();
        guard.Accept(10);
        var replay = Assert.Throws<CompanionProtocolException>(() => guard.Accept(10));
        var older = Assert.Throws<CompanionProtocolException>(() => guard.Accept(9));

        Assert.Equal("REPLAY_REJECTED", replay.Code);
        Assert.Equal("REPLAY_REJECTED", older.Code);
        guard.Accept(11);
    }

    private static CompanionFrame DecodeFrame(byte[] encoded)
    {
        var decoder = new CompanionFrameDecoder();
        decoder.Append(encoded);
        Assert.True(decoder.TryRead(out var frame));
        return Assert.IsType<CompanionFrame>(frame);
    }
}
