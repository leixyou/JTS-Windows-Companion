using System.Security.Cryptography;
using System.Text.Json;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Transfers;

namespace JTS.WindowsCompanion.Tests;

public sealed class BinaryTransferTests
{
    [Fact]
    public async Task Upload_AcceptsLargeContiguousChunksAndExactDuplicateRetry()
    {
        var root = Directory.CreateTempSubdirectory();
        await using var transfers = new BinaryTransferCoordinator(root.FullName);
        var transferId = Guid.NewGuid();
        var data = RandomNumberGenerator.GetBytes(2 * 1024 * 1024 + 137);
        var sha256 = Sha256(data);
        await transfers.BeginUploadAsync(
            Parameters(new
            {
                transferId,
                purpose = "vrc-worker-submit",
                totalBytes = data.LongLength,
                sha256,
            }),
            CancellationToken.None);

        var first = data.AsMemory(0, 1024 * 1024);
        await transfers.AcceptUploadChunkAsync(
            new BinaryChunk(transferId, 0, false, first),
            CancellationToken.None);
        await transfers.AcceptUploadChunkAsync(
            new BinaryChunk(transferId, 0, false, first),
            CancellationToken.None);
        await transfers.AcceptUploadChunkAsync(
            new BinaryChunk(transferId, first.Length, true, data.AsMemory(first.Length)),
            CancellationToken.None);
        var finalized = Element(await transfers.FinalizeUploadAsync(
            Parameters(new { transferId }),
            CancellationToken.None));
        var upload = await transfers.GetValidatedUploadAsync(
            transferId,
            "vrc-worker-submit",
            data.LongLength,
            sha256,
            CancellationToken.None);

        Assert.True(finalized.GetProperty("completed").GetBoolean());
        Assert.Equal(data, await File.ReadAllBytesAsync(upload.FilePath));
        root.Delete(recursive: true);
    }

    [Fact]
    public async Task Upload_RejectsGapAndDeletesHashMismatch()
    {
        var root = Directory.CreateTempSubdirectory();
        await using var transfers = new BinaryTransferCoordinator(root.FullName);
        var transferId = Guid.NewGuid();
        var data = "hash-bound-transfer"u8.ToArray();
        await transfers.BeginUploadAsync(
            Parameters(new
            {
                transferId,
                purpose = "vrc-worker-submit",
                totalBytes = data.LongLength,
                sha256 = new string('0', 64),
            }),
            CancellationToken.None);

        var gap = await Assert.ThrowsAsync<CompanionProtocolException>(() => transfers.AcceptUploadChunkAsync(
            new BinaryChunk(transferId, 1, false, data.AsMemory(1)),
            CancellationToken.None).AsTask());
        Assert.Equal("TRANSFER_OFFSET_CONFLICT", gap.Code);

        await transfers.AcceptUploadChunkAsync(
            new BinaryChunk(transferId, 0, true, data),
            CancellationToken.None);
        var mismatch = await Assert.ThrowsAsync<CompanionProtocolException>(() => transfers.FinalizeUploadAsync(
            Parameters(new { transferId }),
            CancellationToken.None).AsTask());
        Assert.Equal("TRANSFER_HASH_MISMATCH", mismatch.Code);
        var missing = await Assert.ThrowsAsync<CompanionProtocolException>(() => transfers.GetValidatedUploadAsync(
            transferId,
            "vrc-worker-submit",
            data.LongLength,
            new string('0', 64),
            CancellationToken.None).AsTask());
        Assert.Equal("TRANSFER_NOT_VERIFIED", missing.Code);
        root.Delete(recursive: true);
    }

    [Fact]
    public async Task TransferStore_EnforcesConcurrencyLimitAndReleaseIsIdempotent()
    {
        var root = Directory.CreateTempSubdirectory();
        await using var transfers = new BinaryTransferCoordinator(root.FullName);
        var ids = Enumerable.Range(0, BinaryTransferCoordinator.MaximumConcurrentTransfers)
            .Select(_ => Guid.NewGuid())
            .ToArray();
        foreach (var transferId in ids)
        {
            await transfers.BeginUploadAsync(
                Parameters(new
                {
                    transferId,
                    purpose = "vrc-worker-submit",
                    totalBytes = 1,
                    sha256 = Sha256([0]),
                }),
                CancellationToken.None);
        }

        var limit = await Assert.ThrowsAsync<CompanionProtocolException>(() => transfers.BeginUploadAsync(
            Parameters(new
            {
                transferId = Guid.NewGuid(),
                purpose = "vrc-worker-submit",
                totalBytes = 1,
                sha256 = Sha256([0]),
            }),
            CancellationToken.None).AsTask());
        Assert.Equal("TRANSFER_CONCURRENCY_LIMIT", limit.Code);

        var firstRelease = Element(await transfers.ReleaseAsync(
            Parameters(new { transferId = ids[0] }),
            CancellationToken.None));
        var secondRelease = Element(await transfers.ReleaseAsync(
            Parameters(new { transferId = ids[0] }),
            CancellationToken.None));
        Assert.True(firstRelease.GetProperty("released").GetBoolean());
        Assert.False(secondRelease.GetProperty("released").GetBoolean());
        root.Delete(recursive: true);
    }

    [Fact]
    public async Task Download_RetryResumesAtVerifiedOffsetWithoutRepeatingBytes()
    {
        var root = Directory.CreateTempSubdirectory();
        await using var transfers = new BinaryTransferCoordinator(root.FullName);
        var data = RandomNumberGenerator.GetBytes(6 * 1024 * 1024 + 41);
        var reservation = await transfers.ReserveDownloadAsync("vrc-worker-result", CancellationToken.None);
        await File.WriteAllBytesAsync(reservation.FilePath, data);
        var descriptor = await transfers.FinalizeDownloadAsync(reservation.TransferId, CancellationToken.None);
        using var output = new MemoryStream();
        var failOnce = true;
        transfers.BindSender((chunk, _) =>
        {
            if (failOnce && chunk.Offset > 0)
            {
                failOnce = false;
                throw new IOException("simulated DVC interruption");
            }

            Assert.Equal(output.Length, chunk.Offset);
            output.Write(chunk.Data.Span);
            return ValueTask.CompletedTask;
        });

        await Assert.ThrowsAsync<IOException>(() => transfers.SendDownloadAsync(
            Parameters(new { transferId = descriptor.TransferId, offset = 0 }),
            CancellationToken.None).AsTask());
        var resumeOffset = output.Length;
        var response = Element(await transfers.SendDownloadAsync(
            Parameters(new { transferId = descriptor.TransferId, offset = resumeOffset }),
            CancellationToken.None));

        Assert.True(resumeOffset > 0);
        Assert.True(response.GetProperty("completed").GetBoolean());
        Assert.Equal(data, output.ToArray());
        Assert.Equal(Sha256(data), descriptor.Sha256);
        root.Delete(recursive: true);
    }

    [Fact]
    public async Task EmptyFileTransfer_UsesAnExplicitFinalChunkAndVerifiedEmptyDigest()
    {
        var root = Directory.CreateTempSubdirectory();
        await using var transfers = new BinaryTransferCoordinator(root.FullName);
        var uploadId = Guid.NewGuid();
        var emptySha256 = Sha256([]);
        await transfers.BeginUploadAsync(
            Parameters(new
            {
                transferId = uploadId,
                purpose = "file-upload",
                totalBytes = 0,
                sha256 = emptySha256,
            }),
            CancellationToken.None);
        await transfers.AcceptUploadChunkAsync(
            new BinaryChunk(uploadId, 0, true, ReadOnlyMemory<byte>.Empty),
            CancellationToken.None);
        await transfers.FinalizeUploadAsync(
            Parameters(new { transferId = uploadId }),
            CancellationToken.None);
        var upload = await transfers.GetValidatedUploadAsync(
            uploadId,
            "file-upload",
            0,
            emptySha256,
            CancellationToken.None);
        Assert.Equal(0, new FileInfo(upload.FilePath).Length);

        var reservation = await transfers.ReserveDownloadAsync("file-download", CancellationToken.None);
        await File.WriteAllBytesAsync(reservation.FilePath, []);
        var download = await transfers.FinalizeDownloadAsync(
            reservation.TransferId,
            maximumBytes: 64 * 1024 * 1024,
            allowEmpty: true,
            CancellationToken.None);
        BinaryChunk? sent = null;
        transfers.BindSender((chunk, _) =>
        {
            sent = chunk;
            return ValueTask.CompletedTask;
        });

        var completed = Element(await transfers.SendDownloadAsync(
            Parameters(new { transferId = download.TransferId, offset = 0 }),
            CancellationToken.None));

        Assert.NotNull(sent);
        Assert.True(sent!.Final);
        Assert.Empty(sent.Data.ToArray());
        Assert.Equal(0, completed.GetProperty("totalBytes").GetInt64());
        Assert.Equal(emptySha256, download.Sha256);
        root.Delete(recursive: true);
    }

    [Fact]
    public async Task Dispose_RemovesAllSessionTransferFiles()
    {
        var root = Directory.CreateTempSubdirectory();
        var transfers = new BinaryTransferCoordinator(root.FullName);
        await transfers.BeginUploadAsync(
            Parameters(new
            {
                transferId = Guid.NewGuid(),
                purpose = "vrc-worker-submit",
                totalBytes = 1,
                sha256 = Sha256([0]),
            }),
            CancellationToken.None);
        Assert.NotEmpty(root.EnumerateFileSystemInfos("*", SearchOption.AllDirectories));

        await transfers.DisposeAsync();

        Assert.Empty(root.EnumerateFileSystemInfos("*", SearchOption.AllDirectories));
        root.Delete(recursive: true);
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
