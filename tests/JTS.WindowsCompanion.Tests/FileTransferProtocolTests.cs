using System.Security.Cryptography;
using System.Text.Json;
using JTS.WindowsCompanion.Agent;
using JTS.WindowsCompanion.Files;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Transfers;

namespace JTS.WindowsCompanion.Tests;

public sealed class FileTransferProtocolTests
{
    [Fact]
    public async Task FileUpload_ConsumesVerifiedSpoolAndAtomicallyWritesSandboxedDestination()
    {
        using var root = new TemporaryDirectory();
        using var spool = new TemporaryDirectory();
        Directory.CreateDirectory(Path.Combine(root.Path, "output"));
        using var files = new SandboxedFileService(new FileSandbox([
            new FileRoot("workspace", root.Path),
        ]));
        await using var transfers = new BinaryTransferCoordinator(spool.Path);
        var router = Router(files, transfers);
        var transferId = Guid.NewGuid();
        var content = RandomNumberGenerator.GetBytes(FileMethodRegistrar.MaximumInlineFileBytes + 137);
        var sha256 = Sha256(content);

        Assert.True((await DispatchAsync(router, "transfer.begin", new
        {
            transferId,
            purpose = FileMethodRegistrar.FileUploadPurpose,
            totalBytes = content.LongLength,
            sha256,
        })).Success);
        await transfers.AcceptUploadChunkAsync(
            new BinaryChunk(transferId, 0, true, content),
            CancellationToken.None);
        Assert.True((await DispatchAsync(router, "transfer.finalize", new { transferId })).Success);

        var uploaded = await DispatchAsync(router, "files.upload", new
        {
            rootId = "workspace",
            relativePath = "output/upload.bin",
            transferId,
            totalBytes = content.LongLength,
            sha256,
            overwrite = false,
        });

        Assert.True(uploaded.Success);
        Assert.Equal(content, await File.ReadAllBytesAsync(Path.Combine(root.Path, "output", "upload.bin")));
        Assert.Equal(content.LongLength, uploaded.Result?.GetProperty("bytesTransferred").GetInt64());
        Assert.Equal(sha256, uploaded.Result?.GetProperty("sha256").GetString(), ignoreCase: true);
        var released = await DispatchAsync(router, "transfer.release", new { transferId });
        Assert.False(released.Result?.GetProperty("released").GetBoolean());
    }

    [Fact]
    public async Task FileDownload_StagesRequestedRangeAndReturnsHashBoundBinaryDescriptor()
    {
        using var root = new TemporaryDirectory();
        using var spool = new TemporaryDirectory();
        var content = RandomNumberGenerator.GetBytes(2 * 1024 * 1024 + 31);
        await File.WriteAllBytesAsync(Path.Combine(root.Path, "source.bin"), content);
        using var files = new SandboxedFileService(new FileSandbox([
            new FileRoot("workspace", root.Path),
        ]));
        await using var transfers = new BinaryTransferCoordinator(spool.Path);
        using var received = new MemoryStream();
        transfers.BindSender((chunk, cancellationToken) =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            Assert.Equal(received.Length, chunk.Offset);
            received.Write(chunk.Data.Span);
            return ValueTask.CompletedTask;
        });
        var router = Router(files, transfers);
        const int offset = 12_345;
        const int length = 700_000;

        var staged = await DispatchAsync(router, "files.download", new
        {
            rootId = "workspace",
            relativePath = "source.bin",
            offset,
            length,
        });

        Assert.True(staged.Success);
        var descriptor = staged.Result!.Value;
        var transferId = descriptor.GetProperty("transferId").GetGuid();
        Assert.Equal(FileMethodRegistrar.FileDownloadPurpose, descriptor.GetProperty("purpose").GetString());
        Assert.Equal(length, descriptor.GetProperty("totalBytes").GetInt64());
        Assert.Equal(offset, descriptor.GetProperty("offset").GetInt64());
        Assert.False(descriptor.GetProperty("endOfFile").GetBoolean());

        var downloaded = await DispatchAsync(router, "transfer.download", new { transferId, offset = 0 });
        var expected = content.AsSpan(offset, length).ToArray();
        Assert.True(downloaded.Success);
        Assert.Equal(expected, received.ToArray());
        Assert.Equal(Sha256(expected), descriptor.GetProperty("sha256").GetString());
        Assert.True((await DispatchAsync(router, "transfer.release", new { transferId })).Success);
    }

    [Fact]
    public async Task FileTransfer_EnforcesInlineAndRangeLimitsBeforeWriting()
    {
        using var root = new TemporaryDirectory();
        using var spool = new TemporaryDirectory();
        var oversizedInline = RandomNumberGenerator.GetBytes(FileMethodRegistrar.MaximumInlineFileBytes + 1);
        await File.WriteAllBytesAsync(Path.Combine(root.Path, "large.bin"), oversizedInline);
        using var files = new SandboxedFileService(new FileSandbox([
            new FileRoot("workspace", root.Path),
        ]));
        await using var transfers = new BinaryTransferCoordinator(spool.Path);
        var router = Router(files, transfers);

        var read = await DispatchAsync(router, "files.read", new
        {
            rootId = "workspace",
            relativePath = "large.bin",
        });
        var write = await DispatchAsync(router, "files.write", new
        {
            rootId = "workspace",
            relativePath = "inline.bin",
            contentBase64 = Convert.ToBase64String(oversizedInline),
            expectedSha256 = Sha256(oversizedInline),
            overwrite = false,
        });
        var range = await DispatchAsync(router, "files.download", new
        {
            rootId = "workspace",
            relativePath = "large.bin",
            offset = 0,
            length = FileMethodRegistrar.MaximumMcpFileTransferBytes + 1,
        });
        var traversal = await DispatchAsync(router, "files.download", new
        {
            rootId = "workspace",
            relativePath = "../outside.bin",
            offset = 0,
            length = 1,
        });

        Assert.Equal("BINARY_TRANSFER_REQUIRED", read.Error?.Code);
        Assert.Equal("BINARY_TRANSFER_REQUIRED", write.Error?.Code);
        Assert.False(File.Exists(Path.Combine(root.Path, "inline.bin")));
        Assert.Equal("FILE_TRANSFER_RANGE_INVALID", range.Error?.Code);
        Assert.Equal("PATH_TRAVERSAL", traversal.Error?.Code);
    }

    [Fact]
    public async Task BinaryImport_RechecksHashAndCancellationBeforeAtomicMove()
    {
        using var root = new TemporaryDirectory();
        using var spool = new TemporaryDirectory();
        Directory.CreateDirectory(Path.Combine(root.Path, "output"));
        var source = Path.Combine(spool.Path, "verified.part");
        var content = RandomNumberGenerator.GetBytes(256 * 1024);
        await File.WriteAllBytesAsync(source, content);
        using var files = new SandboxedFileService(new FileSandbox([
            new FileRoot("workspace", root.Path),
        ]));

        var mismatch = await Assert.ThrowsAsync<FileSandboxException>(async () =>
            await files.ImportBinaryAsync(
                new BinaryFileImportRequest(
                    "workspace",
                    "output/mismatch.bin",
                    source,
                    content.LongLength,
                    new string('0', 64),
                    FileMethodRegistrar.MaximumMcpFileTransferBytes,
                    Overwrite: false),
                CancellationToken.None));
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await files.ImportBinaryAsync(
                new BinaryFileImportRequest(
                    "workspace",
                    "output/cancelled.bin",
                    source,
                    content.LongLength,
                    Sha256(content),
                    FileMethodRegistrar.MaximumMcpFileTransferBytes,
                    Overwrite: false),
                cancelled.Token));

        Assert.Equal("HASH_MISMATCH", mismatch.Code);
        Assert.False(File.Exists(Path.Combine(root.Path, "output", "mismatch.bin")));
        Assert.False(File.Exists(Path.Combine(root.Path, "output", "cancelled.bin")));
        Assert.Empty(Directory.EnumerateFiles(Path.Combine(root.Path, "output"), "*.part"));
    }

    [Fact]
    public async Task BinaryExport_RejectsAnExistingDirectoryAsItsSpoolDestination()
    {
        using var root = new TemporaryDirectory();
        using var spool = new TemporaryDirectory();
        await File.WriteAllBytesAsync(Path.Combine(root.Path, "source.bin"), [1, 2, 3]);
        using var files = new SandboxedFileService(new FileSandbox([
            new FileRoot("workspace", root.Path),
        ]));

        var exception = await Assert.ThrowsAsync<FileSandboxException>(async () =>
            await files.ExportBinaryRangeAsync(
                new BinaryFileExportRequest(
                    "workspace",
                    "source.bin",
                    spool.Path,
                    Offset: 0,
                    Length: 3,
                    MaximumBytes: FileMethodRegistrar.MaximumMcpFileTransferBytes),
                CancellationToken.None));

        Assert.Equal("TRANSFER_DESTINATION_INVALID", exception.Code);
    }

    private static CompanionRequestRouter Router(
        SandboxedFileService files,
        BinaryTransferCoordinator transfers)
    {
        var router = new CompanionRequestRouter(new TestAuthorizationGate());
        FileMethodRegistrar.Register(router, files, transfers);
        BinaryTransferMethodRegistrar.Register(router, transfers);
        return router;
    }

    private static ValueTask<CompanionResponse> DispatchAsync(
        CompanionRequestRouter router,
        string method,
        object parameters) => router.DispatchAsync(
            new CompanionRequest(
                CompanionProtocol.CurrentVersion,
                Guid.NewGuid(),
                method,
                null,
                null,
                null,
                JsonSerializer.SerializeToElement(parameters, ControlMessageSerializer.Options)),
            DateTimeOffset.UtcNow,
            CancellationToken.None);

    private static string Sha256(ReadOnlySpan<byte> data) =>
        Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"jts-file-transfer-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
    }
}
