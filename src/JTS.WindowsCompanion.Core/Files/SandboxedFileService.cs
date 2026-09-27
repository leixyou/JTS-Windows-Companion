using System.Security.Cryptography;

namespace JTS.WindowsCompanion.Files;

public sealed partial class SandboxedFileService : IDisposable
{
    private readonly FileSandbox _sandbox;
    private readonly SemaphoreSlim _operationSlots;
    private bool _disposed;

    public SandboxedFileService(FileSandbox sandbox, int maximumConcurrentOperations = 4)
    {
        ArgumentNullException.ThrowIfNull(sandbox);
        if (maximumConcurrentOperations is < 1 or > 16)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumConcurrentOperations));
        }

        _sandbox = sandbox;
        _operationSlots = new SemaphoreSlim(maximumConcurrentOperations, maximumConcurrentOperations);
    }

    public async ValueTask<IReadOnlyList<RemoteFileInfo>> ListAsync(
        string rootId,
        string relativePath,
        CancellationToken cancellationToken)
    {
        return await WithSlotAsync(() =>
        {
            var path = _sandbox.Resolve(rootId, relativePath);
            if (!Directory.Exists(path.FullPath))
            {
                throw new FileSandboxException("NOT_A_DIRECTORY", "The requested path is not a directory.");
            }

            var entries = new List<RemoteFileInfo>();
            foreach (var entry in new DirectoryInfo(path.FullPath).EnumerateFileSystemInfos())
            {
                cancellationToken.ThrowIfCancellationRequested();
                if ((entry.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    continue;
                }

                var isDirectory = (entry.Attributes & FileAttributes.Directory) != 0;
                entries.Add(new RemoteFileInfo(
                    entry.Name,
                    Path.Combine(path.RelativePath, entry.Name).Replace(Path.DirectorySeparatorChar, '/'),
                    isDirectory,
                    isDirectory ? 0 : ((FileInfo)entry).Length,
                    entry.LastWriteTimeUtc));
            }

            var result = (IReadOnlyList<RemoteFileInfo>)entries
                .OrderByDescending(entry => entry.IsDirectory)
                .ThenBy(entry => entry.Name, StringComparer.OrdinalIgnoreCase)
                .ToArray();
            return ValueTask.FromResult(result);
        }, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<RemoteFileInfo> StatAsync(
        string rootId,
        string relativePath,
        bool includeSha256,
        CancellationToken cancellationToken)
    {
        return await WithSlotAsync(async () =>
        {
            var path = _sandbox.Resolve(rootId, relativePath);
            if (Directory.Exists(path.FullPath))
            {
                var directory = new DirectoryInfo(path.FullPath);
                return new RemoteFileInfo(directory.Name, path.RelativePath, true, 0, directory.LastWriteTimeUtc);
            }

            var file = new FileInfo(path.FullPath);
            if (file.Length > path.Root.MaximumFileBytes)
            {
                throw new FileSandboxException("FILE_TOO_LARGE", "The file exceeds the configured root limit.");
            }

            var digest = includeSha256
                ? await ComputeSha256Async(path.FullPath, cancellationToken).ConfigureAwait(false)
                : null;
            return new RemoteFileInfo(file.Name, path.RelativePath, false, file.Length, file.LastWriteTimeUtc, digest);
        }, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<FileReadResult> ReadAsync(
        string rootId,
        string relativePath,
        CancellationToken cancellationToken)
    {
        return await ReadAsync(
            rootId,
            relativePath,
            long.MaxValue,
            cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<FileReadResult> ReadAsync(
        string rootId,
        string relativePath,
        long maximumBytes,
        CancellationToken cancellationToken)
    {
        if (maximumBytes < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumBytes));
        }

        return await WithSlotAsync(async () =>
        {
            var path = _sandbox.Resolve(rootId, relativePath);
            var file = new FileInfo(path.FullPath);
            if (!file.Exists)
            {
                throw new FileSandboxException("PATH_NOT_FOUND", "The requested file does not exist.");
            }

            if (file.Length > path.Root.MaximumFileBytes
                || file.Length > maximumBytes
                || file.Length > int.MaxValue)
            {
                throw new FileSandboxException("FILE_TOO_LARGE", "The file exceeds the configured root limit.");
            }

            var content = GC.AllocateUninitializedArray<byte>((int)file.Length);
            await using var stream = new FileStream(
                path.FullPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                64 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            await stream.ReadExactlyAsync(content, cancellationToken).ConfigureAwait(false);
            return new FileReadResult(
                path.RelativePath,
                content,
                Convert.ToHexString(SHA256.HashData(content)),
                file.LastWriteTimeUtc);
        }, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<RemoteFileInfo> WriteAsync(FileWriteRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        return await WithSlotAsync(async () =>
        {
            var path = _sandbox.Resolve(request.RootId, request.RelativePath, allowMissingLeaf: true);
            if (path.Root.ReadOnly)
            {
                throw new FileSandboxException("ROOT_READ_ONLY", "The requested file root is read-only.");
            }

            if (request.Content.Length > path.Root.MaximumFileBytes)
            {
                throw new FileSandboxException("FILE_TOO_LARGE", "The content exceeds the configured root limit.");
            }

            var actualDigest = Convert.ToHexString(SHA256.HashData(request.Content.Span));
            if (!string.Equals(actualDigest, request.ExpectedSha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new FileSandboxException("HASH_MISMATCH", "The content hash does not match the request.");
            }

            if (!request.Overwrite && File.Exists(path.FullPath))
            {
                throw new FileSandboxException("OVERWRITE_REJECTED", "The destination already exists.");
            }

            var parent = Path.GetDirectoryName(path.FullPath)
                ?? throw new FileSandboxException("PATH_INVALID", "The destination has no parent directory.");
            Directory.CreateDirectory(parent);
            var temporaryPath = Path.Combine(parent, $".jts-{Guid.NewGuid():N}.part");
            try
            {
                await File.WriteAllBytesAsync(temporaryPath, request.Content.ToArray(), cancellationToken).ConfigureAwait(false);
                File.Move(temporaryPath, path.FullPath, request.Overwrite);
            }
            finally
            {
                if (File.Exists(temporaryPath))
                {
                    File.Delete(temporaryPath);
                }
            }

            var file = new FileInfo(path.FullPath);
            return new RemoteFileInfo(file.Name, path.RelativePath, false, file.Length, file.LastWriteTimeUtc, actualDigest);
        }, cancellationToken).ConfigureAwait(false);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _operationSlots.Dispose();
        _disposed = true;
    }

    private async ValueTask<T> WithSlotAsync<T>(Func<ValueTask<T>> operation, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        await _operationSlots.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await operation().ConfigureAwait(false);
        }
        finally
        {
            _operationSlots.Release();
        }
    }

    private static async ValueTask<string> ComputeSha256Async(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        var digest = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        return Convert.ToHexString(digest);
    }
}
