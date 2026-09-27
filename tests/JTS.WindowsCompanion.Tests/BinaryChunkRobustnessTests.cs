using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Security;
using JTS.WindowsCompanion.Transfers;

namespace JTS.WindowsCompanion.Tests;

public sealed class BinaryChunkRobustnessTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(BinaryChunkCodec.MaximumDataLength)]
    public void Codec_RoundTripsExactLengthBoundaries(int dataLength)
    {
        var data = new byte[dataLength];
        if (data.Length > 0)
        {
            data[0] = 0xA5;
            data[^1] = 0x5A;
        }

        var expected = new BinaryChunk(Guid.NewGuid(), long.MaxValue, true, data);
        var encoded = BinaryChunkCodec.Encode(expected);
        var actual = BinaryChunkCodec.Decode(encoded);

        Assert.Equal(BinaryChunkCodec.HeaderLength + dataLength, encoded.Length);
        Assert.Equal(expected.TransferId, actual.TransferId);
        Assert.Equal(expected.Offset, actual.Offset);
        Assert.True(actual.Final);
        Assert.Equal(data, actual.Data.ToArray());
    }

    [Fact]
    public void Codec_RejectsTruncatedMalformedAndOverLimitPayloads()
    {
        var encoded = BinaryChunkCodec.Encode(new BinaryChunk(
            Guid.Parse("00112233-4455-6677-8899-aabbccddeeff"),
            4_096,
            true,
            "binary-data"u8.ToArray()));

        for (var length = 0; length < BinaryChunkCodec.HeaderLength; length++)
        {
            AssertCode(
                "CHUNK_TRUNCATED",
                () => BinaryChunkCodec.Decode(encoded[..length]));
        }

        var negativeLength = encoded.ToArray();
        BinaryPrimitives.WriteInt32BigEndian(negativeLength.AsSpan(25, 4), -1);
        AssertCode("CHUNK_LENGTH_INVALID", () => BinaryChunkCodec.Decode(negativeLength));

        var inconsistentLength = encoded.ToArray();
        BinaryPrimitives.WriteInt32BigEndian(
            inconsistentLength.AsSpan(25, 4),
            encoded.Length - BinaryChunkCodec.HeaderLength + 1);
        AssertCode("CHUNK_LENGTH_INVALID", () => BinaryChunkCodec.Decode(inconsistentLength));

        var oversized = new byte[CompanionProtocol.MaxAuthenticatedBinaryPayloadBytes + 1];
        BinaryPrimitives.WriteInt32BigEndian(
            oversized.AsSpan(25, 4),
            BinaryChunkCodec.MaximumDataLength + 1);
        AssertCode("CHUNK_LENGTH_INVALID", () => BinaryChunkCodec.Decode(oversized));

        AssertCode(
            "CHUNK_INVALID",
            () => BinaryChunkCodec.Encode(new BinaryChunk(
                Guid.NewGuid(),
                0,
                false,
                new byte[BinaryChunkCodec.MaximumDataLength + 1])));
    }

    [Fact]
    public void Codec_RejectsNegativeOffsetInvalidFinalMarkerAndDigestChanges()
    {
        var encoded = BinaryChunkCodec.Encode(new BinaryChunk(
            Guid.NewGuid(),
            7,
            false,
            "chunk"u8.ToArray()));

        var negativeOffset = encoded.ToArray();
        BinaryPrimitives.WriteInt64BigEndian(negativeOffset.AsSpan(16, 8), -1);
        AssertCode("CHUNK_INVALID", () => BinaryChunkCodec.Decode(negativeOffset));

        var invalidFinal = encoded.ToArray();
        invalidFinal[24] = 2;
        AssertCode("CHUNK_INVALID", () => BinaryChunkCodec.Decode(invalidFinal));

        var changedDigest = encoded.ToArray();
        changedDigest[29] ^= 0x80;
        AssertCode("CHUNK_DIGEST_INVALID", () => BinaryChunkCodec.Decode(changedDigest));

        var changedData = encoded.ToArray();
        changedData[^1] ^= 0x01;
        AssertCode("CHUNK_DIGEST_INVALID", () => BinaryChunkCodec.Decode(changedData));
    }

    [Fact]
    public void SequenceGuard_RejectsDuplicateAndOutOfOrderChunkFrames()
    {
        var guard = new SequenceReplayGuard();
        guard.Accept(9);

        AssertCode("REPLAY_REJECTED", () => guard.Accept(9));
        AssertCode("REPLAY_REJECTED", () => guard.Accept(8));

        guard.Accept(10);
    }

    [Fact]
    public async Task Coordinator_RejectsOutOfOrderOverlapConflictsAndInvalidCompletion()
    {
        var root = Directory.CreateTempSubdirectory();
        var transfers = new BinaryTransferCoordinator(root.FullName);
        try
        {
            var transferId = Guid.NewGuid();
            var data = "abcdefgh"u8.ToArray();
            await transfers.BeginUploadAsync(
                Parameters(new
                {
                    transferId,
                    purpose = "robustness",
                    totalBytes = data.LongLength,
                    sha256 = Sha256(data),
                }),
                CancellationToken.None);

            await AssertCodeAsync(
                "TRANSFER_CHUNK_TOO_LARGE",
                () => transfers.AcceptUploadChunkAsync(
                    new BinaryChunk(
                        transferId,
                        0,
                        false,
                        new byte[BinaryTransferCoordinator.MaximumChunkBytes + 1]),
                    CancellationToken.None).AsTask());
            await AssertCodeAsync(
                "TRANSFER_RANGE_INVALID",
                () => transfers.AcceptUploadChunkAsync(
                    new BinaryChunk(transferId, -1, false, ReadOnlyMemory<byte>.Empty),
                    CancellationToken.None).AsTask());
            await AssertCodeAsync(
                "TRANSFER_RANGE_INVALID",
                () => transfers.AcceptUploadChunkAsync(
                    new BinaryChunk(transferId, long.MaxValue, false, new byte[] { 0x00 }),
                    CancellationToken.None).AsTask());
            await AssertCodeAsync(
                "TRANSFER_OFFSET_CONFLICT",
                () => transfers.AcceptUploadChunkAsync(
                    new BinaryChunk(transferId, 4, true, data.AsMemory(4)),
                    CancellationToken.None).AsTask());
            await AssertCodeAsync(
                "TRANSFER_FINAL_INVALID",
                () => transfers.AcceptUploadChunkAsync(
                    new BinaryChunk(transferId, 0, true, data.AsMemory(0, 4)),
                    CancellationToken.None).AsTask());
            await AssertCodeAsync(
                "TRANSFER_FINAL_INVALID",
                () => transfers.AcceptUploadChunkAsync(
                    new BinaryChunk(transferId, 0, false, data),
                    CancellationToken.None).AsTask());

            var first = data.AsMemory(0, 4);
            var second = data.AsMemory(4, 4);
            await transfers.AcceptUploadChunkAsync(
                new BinaryChunk(transferId, 0, false, first),
                CancellationToken.None);
            await transfers.AcceptUploadChunkAsync(
                new BinaryChunk(transferId, 0, false, first),
                CancellationToken.None);

            await AssertCodeAsync(
                "TRANSFER_OFFSET_CONFLICT",
                () => transfers.AcceptUploadChunkAsync(
                    new BinaryChunk(transferId, 0, false, "abce"u8.ToArray()),
                    CancellationToken.None).AsTask());
            await AssertCodeAsync(
                "TRANSFER_OFFSET_CONFLICT",
                () => transfers.AcceptUploadChunkAsync(
                    new BinaryChunk(transferId, 2, false, "cdef"u8.ToArray()),
                    CancellationToken.None).AsTask());
            await AssertCodeAsync(
                "TRANSFER_OFFSET_CONFLICT",
                () => transfers.AcceptUploadChunkAsync(
                    new BinaryChunk(transferId, 5, false, "fgh"u8.ToArray()),
                    CancellationToken.None).AsTask());
            await AssertCodeAsync(
                "TRANSFER_FINAL_INVALID",
                () => transfers.AcceptUploadChunkAsync(
                    new BinaryChunk(transferId, 0, true, first),
                    CancellationToken.None).AsTask());

            await transfers.AcceptUploadChunkAsync(
                new BinaryChunk(transferId, 4, true, second),
                CancellationToken.None);
            await transfers.AcceptUploadChunkAsync(
                new BinaryChunk(transferId, 4, true, second),
                CancellationToken.None);

            await AssertCodeAsync(
                "TRANSFER_FINAL_INVALID",
                () => transfers.AcceptUploadChunkAsync(
                    new BinaryChunk(transferId, 4, false, second),
                    CancellationToken.None).AsTask());
            await AssertCodeAsync(
                "TRANSFER_FINAL_INVALID",
                () => transfers.AcceptUploadChunkAsync(
                    new BinaryChunk(transferId, data.LongLength, true, ReadOnlyMemory<byte>.Empty),
                    CancellationToken.None).AsTask());

            await transfers.FinalizeUploadAsync(
                Parameters(new { transferId }),
                CancellationToken.None);
            var verified = await transfers.GetValidatedUploadAsync(
                transferId,
                "robustness",
                data.LongLength,
                Sha256(data),
                CancellationToken.None);
            Assert.Equal(data, await File.ReadAllBytesAsync(verified.FilePath));
        }
        finally
        {
            await transfers.DisposeAsync();
            root.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task Coordinator_HashMismatchRemovesCompletedTransferState()
    {
        var root = Directory.CreateTempSubdirectory();
        var transfers = new BinaryTransferCoordinator(root.FullName);
        try
        {
            var transferId = Guid.NewGuid();
            var data = "hash-bound"u8.ToArray();
            await transfers.BeginUploadAsync(
                Parameters(new
                {
                    transferId,
                    purpose = "robustness",
                    totalBytes = data.LongLength,
                    sha256 = new string('0', 64),
                }),
                CancellationToken.None);
            await transfers.AcceptUploadChunkAsync(
                new BinaryChunk(transferId, 0, true, data),
                CancellationToken.None);

            await AssertCodeAsync(
                "TRANSFER_HASH_MISMATCH",
                () => transfers.FinalizeUploadAsync(
                    Parameters(new { transferId }),
                    CancellationToken.None).AsTask());

            var restarted = Element(await transfers.BeginUploadAsync(
                Parameters(new
                {
                    transferId,
                    purpose = "robustness",
                    totalBytes = data.LongLength,
                    sha256 = Sha256(data),
                }),
                CancellationToken.None));
            Assert.Equal(0, restarted.GetProperty("nextOffset").GetInt64());
        }
        finally
        {
            await transfers.DisposeAsync();
            root.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task Coordinator_AcceptsExactDuplicateEmptyFinalChunk()
    {
        var root = Directory.CreateTempSubdirectory();
        var transfers = new BinaryTransferCoordinator(root.FullName);
        try
        {
            var transferId = Guid.NewGuid();
            await transfers.BeginUploadAsync(
                Parameters(new
                {
                    transferId,
                    purpose = "robustness",
                    totalBytes = 0,
                    sha256 = Sha256([]),
                }),
                CancellationToken.None);
            var final = new BinaryChunk(
                transferId,
                0,
                true,
                ReadOnlyMemory<byte>.Empty);

            await transfers.AcceptUploadChunkAsync(final, CancellationToken.None);
            await transfers.AcceptUploadChunkAsync(final, CancellationToken.None);
            await transfers.FinalizeUploadAsync(
                Parameters(new { transferId }),
                CancellationToken.None);
        }
        finally
        {
            await transfers.DisposeAsync();
            root.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task SessionDisconnectCleanup_RemovesPartialStateAndFreshSessionStartsAtZero()
    {
        var root = Directory.CreateTempSubdirectory();
        var transferId = Guid.NewGuid();
        var data = "disconnect-cleanup"u8.ToArray();
        var parameters = Parameters(new
        {
            transferId,
            purpose = "robustness",
            totalBytes = data.LongLength,
            sha256 = Sha256(data),
        });
        var disconnected = new BinaryTransferCoordinator(root.FullName);
        await disconnected.BeginUploadAsync(parameters, CancellationToken.None);
        await disconnected.AcceptUploadChunkAsync(
            new BinaryChunk(transferId, 0, false, data.AsMemory(0, 4)),
            CancellationToken.None);
        Assert.NotEmpty(root.EnumerateFileSystemInfos("*", SearchOption.AllDirectories));

        await disconnected.DisposeAsync();

        Assert.Empty(root.EnumerateFileSystemInfos("*", SearchOption.AllDirectories));
        await Assert.ThrowsAsync<ObjectDisposedException>(
            () => disconnected.AcceptUploadChunkAsync(
                new BinaryChunk(transferId, 4, true, data.AsMemory(4)),
                CancellationToken.None).AsTask());

        var fresh = new BinaryTransferCoordinator(root.FullName);
        try
        {
            var restarted = Element(await fresh.BeginUploadAsync(parameters, CancellationToken.None));
            Assert.Equal(0, restarted.GetProperty("nextOffset").GetInt64());
            await fresh.AcceptUploadChunkAsync(
                new BinaryChunk(transferId, 0, true, data),
                CancellationToken.None);
            await fresh.FinalizeUploadAsync(
                Parameters(new { transferId }),
                CancellationToken.None);
        }
        finally
        {
            await fresh.DisposeAsync();
            root.Delete(recursive: true);
        }
    }

    private static void AssertCode(string expected, Action action)
    {
        var exception = Assert.Throws<CompanionProtocolException>(action);
        Assert.Equal(expected, exception.Code);
    }

    private static async Task AssertCodeAsync(string expected, Func<Task> action)
    {
        var exception = await Assert.ThrowsAsync<CompanionProtocolException>(action);
        Assert.Equal(expected, exception.Code);
    }

    private static JsonElement Parameters(object value) => JsonSerializer.SerializeToElement(
        value,
        ControlMessageSerializer.Options);

    private static JsonElement Element(object value) => JsonSerializer.SerializeToElement(
        value,
        ControlMessageSerializer.Options);

    private static string Sha256(ReadOnlySpan<byte> data) =>
        Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
}
