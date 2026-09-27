using System.Security.Cryptography;

namespace JTS.WindowsCompanion.Files;

public sealed partial class SandboxedFileService
{
    private const int StreamingBufferBytes = 128 * 1024;

    public async ValueTask<RemoteFileInfo> ImportBinaryAsync(
        BinaryFileImportRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateTransferBounds(request.ExpectedBytes, request.MaximumBytes);
        var expectedSha256 = NormalizeSha256(request.ExpectedSha256);
        return await WithSlotAsync(async () =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            var destination = _sandbox.Resolve(
                request.RootId,
                request.RelativePath,
                allowMissingLeaf: true);
            if (destination.Root.ReadOnly)
            {
                throw new FileSandboxException("ROOT_READ_ONLY", "The requested file root is read-only.");
            }

            if (request.ExpectedBytes > destination.Root.MaximumFileBytes)
            {
                throw new FileSandboxException("FILE_TOO_LARGE", "The content exceeds the configured root limit.");
            }

            var source = RequireRegularTransferFile(request.SourceFilePath, "TRANSFER_SOURCE_INVALID");
            if (source.Length != request.ExpectedBytes)
            {
                throw new FileSandboxException(
                    "TRANSFER_SIZE_MISMATCH",
                    "The verified transfer size does not match the file import request.");
            }

            if (Directory.Exists(destination.FullPath))
            {
                throw new FileSandboxException("NOT_A_FILE", "The destination is a directory.");
            }

            if (!request.Overwrite && File.Exists(destination.FullPath))
            {
                throw new FileSandboxException("OVERWRITE_REJECTED", "The destination already exists.");
            }

            var parent = Path.GetDirectoryName(destination.FullPath)
                ?? throw new FileSandboxException("PATH_INVALID", "The destination has no parent directory.");
            var temporaryPath = Path.Combine(parent, $".jts-{Guid.NewGuid():N}.part");
            try
            {
                var actualSha256 = await CopyAndHashAsync(
                    source.FullName,
                    temporaryPath,
                    request.ExpectedBytes,
                    cancellationToken).ConfigureAwait(false);
                if (!FixedDigestEquals(actualSha256, expectedSha256))
                {
                    throw new FileSandboxException(
                        "HASH_MISMATCH",
                        "The transferred content hash does not match the request.");
                }

                cancellationToken.ThrowIfCancellationRequested();
                var revalidated = _sandbox.Resolve(
                    request.RootId,
                    request.RelativePath,
                    allowMissingLeaf: true);
                if (!string.Equals(
                        revalidated.FullPath,
                        destination.FullPath,
                        OperatingSystem.IsWindows()
                            ? StringComparison.OrdinalIgnoreCase
                            : StringComparison.Ordinal))
                {
                    throw new FileSandboxException("PATH_INVALID", "The destination path changed during import.");
                }

                if (!request.Overwrite && File.Exists(destination.FullPath))
                {
                    throw new FileSandboxException("OVERWRITE_REJECTED", "The destination already exists.");
                }

                File.Move(temporaryPath, destination.FullPath, request.Overwrite);
                var written = new FileInfo(destination.FullPath);
                return new RemoteFileInfo(
                    written.Name,
                    destination.RelativePath,
                    IsDirectory: false,
                    written.Length,
                    written.LastWriteTimeUtc,
                    actualSha256);
            }
            finally
            {
                DeleteTemporaryFile(temporaryPath);
            }
        }, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<BinaryFileExportResult> ExportBinaryRangeAsync(
        BinaryFileExportRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateTransferBounds(request.Length, request.MaximumBytes);
        if (request.Offset < 0)
        {
            throw new FileSandboxException("TRANSFER_RANGE_INVALID", "The file download offset is invalid.");
        }

        return await WithSlotAsync(async () =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            var sourcePath = _sandbox.Resolve(request.RootId, request.RelativePath);
            if (Directory.Exists(sourcePath.FullPath))
            {
                throw new FileSandboxException("NOT_A_FILE", "The requested path is a directory.");
            }

            var source = new FileInfo(sourcePath.FullPath);
            if (!source.Exists)
            {
                throw new FileSandboxException("PATH_NOT_FOUND", "The requested file does not exist.");
            }

            if ((source.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                throw new FileSandboxException(
                    "REPARSE_POINT_REJECTED",
                    "Symbolic links and reparse points are not allowed.");
            }

            if (source.Length > sourcePath.Root.MaximumFileBytes)
            {
                throw new FileSandboxException("FILE_TOO_LARGE", "The file exceeds the configured root limit.");
            }

            if (request.Offset > source.Length)
            {
                throw new FileSandboxException(
                    "TRANSFER_RANGE_INVALID",
                    "The file download offset is beyond the end of the file.");
            }

            ValidateTransferDestination(request.DestinationFilePath);
            var bytesToCopy = Math.Min(request.Length, source.Length - request.Offset);
            await CopyRangeAsync(
                source.FullName,
                request.DestinationFilePath,
                request.Offset,
                bytesToCopy,
                cancellationToken).ConfigureAwait(false);
            return new BinaryFileExportResult(
                sourcePath.RelativePath,
                source.Length,
                request.Offset,
                bytesToCopy,
                EndOfFile: request.Offset + bytesToCopy == source.Length,
                source.LastWriteTimeUtc);
        }, cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<string> CopyAndHashAsync(
        string sourcePath,
        string destinationPath,
        long expectedBytes,
        CancellationToken cancellationToken)
    {
        await using var source = new FileStream(
            sourcePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            StreamingBufferBytes,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        await using var destination = new FileStream(
            destinationPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            StreamingBufferBytes,
            FileOptions.Asynchronous | FileOptions.SequentialScan | FileOptions.WriteThrough);
        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[StreamingBufferBytes];
        var remaining = expectedBytes;
        while (remaining > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var count = await source.ReadAsync(
                buffer.AsMemory(0, (int)Math.Min(buffer.Length, remaining)),
                cancellationToken).ConfigureAwait(false);
            if (count <= 0)
            {
                throw new FileSandboxException(
                    "TRANSFER_TRUNCATED",
                    "The verified transfer changed during file import.");
            }

            hasher.AppendData(buffer, 0, count);
            await destination.WriteAsync(buffer.AsMemory(0, count), cancellationToken).ConfigureAwait(false);
            remaining -= count;
        }

        if (source.ReadByte() != -1)
        {
            throw new FileSandboxException(
                "TRANSFER_SIZE_MISMATCH",
                "The verified transfer changed during file import.");
        }

        await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
        return Convert.ToHexString(hasher.GetHashAndReset());
    }

    private static async ValueTask CopyRangeAsync(
        string sourcePath,
        string destinationPath,
        long offset,
        long count,
        CancellationToken cancellationToken)
    {
        await using var source = new FileStream(
            sourcePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            StreamingBufferBytes,
            FileOptions.Asynchronous | FileOptions.RandomAccess);
        await using var destination = new FileStream(
            destinationPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            StreamingBufferBytes,
            FileOptions.Asynchronous | FileOptions.SequentialScan | FileOptions.WriteThrough);
        source.Position = offset;
        var buffer = new byte[StreamingBufferBytes];
        var remaining = count;
        while (remaining > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var read = await source.ReadAsync(
                buffer.AsMemory(0, (int)Math.Min(buffer.Length, remaining)),
                cancellationToken).ConfigureAwait(false);
            if (read <= 0)
            {
                throw new FileSandboxException(
                    "TRANSFER_TRUNCATED",
                    "The source file changed during download staging.");
            }

            await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            remaining -= read;
        }

        await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static FileInfo RequireRegularTransferFile(string path, string errorCode)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
        {
            throw new FileSandboxException(errorCode, "The transfer spool path is invalid.");
        }

        var file = new FileInfo(Path.GetFullPath(path));
        if (!file.Exists
            || (file.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
        {
            throw new FileSandboxException(errorCode, "The transfer spool file is missing or unsafe.");
        }

        return file;
    }

    private static void ValidateTransferDestination(string path)
    {
        if (string.IsNullOrWhiteSpace(path)
            || !Path.IsPathFullyQualified(path)
            || File.Exists(path)
            || Directory.Exists(path))
        {
            throw new FileSandboxException(
                "TRANSFER_DESTINATION_INVALID",
                "The transfer destination path is invalid.");
        }

        var parent = Path.GetDirectoryName(Path.GetFullPath(path));
        if (parent is null || !Directory.Exists(parent))
        {
            throw new FileSandboxException(
                "TRANSFER_DESTINATION_INVALID",
                "The transfer destination directory is invalid.");
        }

        var parentInfo = new DirectoryInfo(parent);
        if ((parentInfo.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new FileSandboxException(
                "TRANSFER_DESTINATION_INVALID",
                "The transfer destination directory is unsafe.");
        }
    }

    private static void ValidateTransferBounds(long bytes, long maximumBytes)
    {
        if (maximumBytes < 0 || bytes < 0 || bytes > maximumBytes)
        {
            throw new FileSandboxException(
                "TRANSFER_SIZE_INVALID",
                "The file transfer size is outside the configured limit.");
        }
    }

    private static string NormalizeSha256(string value)
    {
        if (string.IsNullOrWhiteSpace(value)
            || value.Length != 64
            || value.Any(character => !char.IsAsciiHexDigit(character)))
        {
            throw new FileSandboxException("HASH_INVALID", "The transfer SHA-256 is invalid.");
        }

        return value.ToUpperInvariant();
    }

    private static bool FixedDigestEquals(string lhs, string rhs) => CryptographicOperations.FixedTimeEquals(
        Convert.FromHexString(lhs),
        Convert.FromHexString(rhs));

    private static void DeleteTemporaryFile(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
        }
    }
}
