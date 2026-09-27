using System.Security.Cryptography;
using System.Text.Json;
using JTS.WindowsCompanion.Protocol;

namespace JTS.WindowsCompanion.Transfers;

public sealed record ValidatedBinaryTransfer(
    Guid TransferId,
    string Purpose,
    long TotalBytes,
    string Sha256,
    string FilePath);

public sealed class BinaryTransferCoordinator : IAsyncDisposable
{
    public const long MaximumTransferBytes = 512L * 1024 * 1024;
    public const int MaximumChunkBytes = 4 * 1024 * 1024;
    public const int MaximumConcurrentTransfers = 4;

    private static readonly TimeSpan IdleLifetime = TimeSpan.FromMinutes(15);
    private readonly string _sessionRoot;
    private readonly Dictionary<Guid, TransferState> _transfers = [];
    private readonly SemaphoreSlim _gate = new(1, 1);
    private Func<BinaryChunk, CancellationToken, ValueTask>? _sender;
    private bool _disposed;

    public BinaryTransferCoordinator(string rootDirectory)
    {
        if (string.IsNullOrWhiteSpace(rootDirectory) || !Path.IsPathFullyQualified(rootDirectory))
        {
            throw new ArgumentException("A fully-qualified binary transfer root is required.", nameof(rootDirectory));
        }

        var root = Path.GetFullPath(rootDirectory);
        Directory.CreateDirectory(root);
        if ((new DirectoryInfo(root).Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new ArgumentException("The binary transfer root cannot be a reparse point.", nameof(rootDirectory));
        }

        _sessionRoot = Path.Combine(root, $"session-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_sessionRoot);
    }

    public void BindSender(Func<BinaryChunk, CancellationToken, ValueTask> sender)
    {
        ArgumentNullException.ThrowIfNull(sender);
        if (Interlocked.CompareExchange(ref _sender, sender, null) is not null)
        {
            throw new InvalidOperationException("The binary transfer sender is already bound.");
        }
    }

    public async ValueTask<object> BeginUploadAsync(JsonElement parameters, CancellationToken cancellationToken)
    {
        RequireProperties(parameters, "transferId", "purpose", "totalBytes", "sha256");
        var transferId = ReadTransferId(parameters);
        var purpose = ReadPurpose(parameters);
        var totalBytes = ReadTotalBytes(parameters);
        var sha256 = ReadSha256(parameters);

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            PruneExpired();
            if (_transfers.TryGetValue(transferId, out var existing))
            {
                if (existing is not UploadState upload
                    || upload.Purpose != purpose
                    || upload.TotalBytes != totalBytes
                    || upload.Sha256 != sha256)
                {
                    throw new CompanionProtocolException(
                        "TRANSFER_ID_CONFLICT",
                        "The transfer ID is already bound to different metadata.");
                }

                upload.Touch();
                return Descriptor(upload, upload.ReceivedBytes, upload.Verified);
            }

            EnsureCapacity();
            var path = TransferPath(transferId, "upload");
            await using (new FileStream(
                path,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                64 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
            }

            var state = new UploadState(transferId, purpose, totalBytes, sha256, path);
            _transfers.Add(transferId, state);
            return Descriptor(state, 0, completed: false);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask AcceptUploadChunkAsync(BinaryChunk chunk, CancellationToken cancellationToken)
    {
        if (chunk.Data.Length > MaximumChunkBytes)
        {
            throw new CompanionProtocolException("TRANSFER_CHUNK_TOO_LARGE", "The transfer chunk exceeds its configured limit.");
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            if (!_transfers.TryGetValue(chunk.TransferId, out var value) || value is not UploadState upload)
            {
                throw new CompanionProtocolException("TRANSFER_NOT_FOUND", "The upload transfer is not active.");
            }

            if (upload.Verified)
            {
                throw new CompanionProtocolException("TRANSFER_ALREADY_FINALIZED", "The upload transfer is already finalized.");
            }

            if (chunk.Offset < 0
                || chunk.Offset > upload.TotalBytes
                || chunk.Data.Length > upload.TotalBytes - chunk.Offset)
            {
                throw new CompanionProtocolException("TRANSFER_RANGE_INVALID", "The upload chunk is outside the declared transfer size.");
            }
            var end = chunk.Offset + chunk.Data.Length;

            if (chunk.Offset < upload.ReceivedBytes)
            {
                if (end > upload.ReceivedBytes
                    || !await ExistingBytesMatchAsync(upload.FilePath, chunk, cancellationToken).ConfigureAwait(false))
                {
                    throw new CompanionProtocolException(
                        "TRANSFER_OFFSET_CONFLICT",
                        "The retried upload chunk does not match the bytes already received.");
                }

                if (chunk.Final != (end == upload.TotalBytes))
                {
                    throw new CompanionProtocolException("TRANSFER_FINAL_INVALID", "The upload final marker is misplaced.");
                }

                upload.Touch();
                return;
            }

            if (upload.SawFinal)
            {
                if (upload.TotalBytes == 0
                    && chunk.Offset == 0
                    && chunk.Data.IsEmpty
                    && chunk.Final)
                {
                    upload.Touch();
                    return;
                }

                throw new CompanionProtocolException(
                    "TRANSFER_FINAL_INVALID",
                    "The upload already received its final chunk.");
            }

            if (chunk.Offset != upload.ReceivedBytes)
            {
                throw new CompanionProtocolException(
                    "TRANSFER_OFFSET_CONFLICT",
                    "Upload chunks must be contiguous or exact duplicate retries.");
            }

            if (chunk.Data.IsEmpty && upload.ReceivedBytes != upload.TotalBytes)
            {
                throw new CompanionProtocolException("TRANSFER_CHUNK_EMPTY", "A non-terminal upload chunk cannot be empty.");
            }

            if (chunk.Final != (end == upload.TotalBytes))
            {
                throw new CompanionProtocolException(
                    "TRANSFER_FINAL_INVALID",
                    "The upload final marker must identify the exact declared end.");
            }

            await using var stream = new FileStream(
                upload.FilePath,
                FileMode.Open,
                FileAccess.Write,
                FileShare.None,
                64 * 1024,
                FileOptions.Asynchronous | FileOptions.WriteThrough);
            stream.Position = chunk.Offset;
            await stream.WriteAsync(chunk.Data, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            upload.ReceivedBytes = end;
            upload.SawFinal = chunk.Final;
            upload.Touch();
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask<object> FinalizeUploadAsync(JsonElement parameters, CancellationToken cancellationToken)
    {
        RequireProperties(parameters, "transferId");
        var transferId = ReadTransferId(parameters);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            if (!_transfers.TryGetValue(transferId, out var value) || value is not UploadState upload)
            {
                throw new CompanionProtocolException("TRANSFER_NOT_FOUND", "The upload transfer is not active.");
            }

            if (!upload.Verified)
            {
                if (!upload.SawFinal || upload.ReceivedBytes != upload.TotalBytes)
                {
                    throw new CompanionProtocolException("TRANSFER_INCOMPLETE", "The upload transfer is incomplete.");
                }

                var actual = await HashFileAsync(upload.FilePath, cancellationToken).ConfigureAwait(false);
                if (!FixedDigestEquals(actual, upload.Sha256))
                {
                    DeleteFile(upload.FilePath);
                    _transfers.Remove(transferId);
                    throw new CompanionProtocolException(
                        "TRANSFER_HASH_MISMATCH",
                        "The complete upload does not match its declared SHA-256.");
                }

                upload.Verified = true;
            }

            upload.Touch();
            return Descriptor(upload, upload.ReceivedBytes, completed: true);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask<ValidatedBinaryTransfer> GetValidatedUploadAsync(
        Guid transferId,
        string purpose,
        long totalBytes,
        string sha256,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            if (!_transfers.TryGetValue(transferId, out var value)
                || value is not UploadState upload
                || !upload.Verified
                || upload.Purpose != purpose
                || upload.TotalBytes != totalBytes
                || upload.Sha256 != NormalizeSha256(sha256))
            {
                throw new CompanionProtocolException(
                    "TRANSFER_NOT_VERIFIED",
                    "The request does not reference a matching verified upload.");
            }

            upload.Touch();
            return new ValidatedBinaryTransfer(
                upload.TransferId,
                upload.Purpose,
                upload.TotalBytes,
                upload.Sha256,
                upload.FilePath);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask<(Guid TransferId, string FilePath)> ReserveDownloadAsync(
        string purpose,
        CancellationToken cancellationToken)
    {
        ValidatePurpose(purpose);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            PruneExpired();
            EnsureCapacity();
            var transferId = Guid.NewGuid();
            var path = TransferPath(transferId, "download");
            var state = new DownloadState(transferId, purpose, path);
            _transfers.Add(transferId, state);
            return (transferId, path);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask<ValidatedBinaryTransfer> FinalizeDownloadAsync(
        Guid transferId,
        CancellationToken cancellationToken)
    {
        return await FinalizeDownloadAsync(
            transferId,
            MaximumTransferBytes,
            allowEmpty: false,
            cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<ValidatedBinaryTransfer> FinalizeDownloadAsync(
        Guid transferId,
        long maximumBytes,
        bool allowEmpty,
        CancellationToken cancellationToken)
    {
        if (maximumBytes < 0 || maximumBytes > MaximumTransferBytes)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumBytes));
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            if (!_transfers.TryGetValue(transferId, out var value) || value is not DownloadState download)
            {
                throw new CompanionProtocolException("TRANSFER_NOT_FOUND", "The download transfer is not reserved.");
            }

            var info = new FileInfo(download.FilePath);
            if (!info.Exists
                || (info.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0
                || (!allowEmpty && info.Length == 0)
                || info.Length > maximumBytes)
            {
                throw new CompanionProtocolException(
                    "TRANSFER_SIZE_INVALID",
                    "The staged download is empty when disallowed, unsafe, or exceeds its configured limit.");
            }

            download.TotalBytes = info.Length;
            download.Sha256 = await HashFileAsync(download.FilePath, cancellationToken).ConfigureAwait(false);
            download.Verified = true;
            download.Touch();
            return new ValidatedBinaryTransfer(
                download.TransferId,
                download.Purpose,
                download.TotalBytes,
                download.Sha256,
                download.FilePath);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask<object> SendDownloadAsync(JsonElement parameters, CancellationToken cancellationToken)
    {
        RequireProperties(parameters, "transferId", "offset");
        var transferId = ReadTransferId(parameters);
        var offset = ReadOffset(parameters);
        DownloadState download;
        Func<BinaryChunk, CancellationToken, ValueTask> sender;
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();
            if (!_transfers.TryGetValue(transferId, out var value)
                || value is not DownloadState candidate
                || !candidate.Verified)
            {
                throw new CompanionProtocolException("TRANSFER_NOT_VERIFIED", "The download transfer is not ready.");
            }

            if (offset < 0 || offset > candidate.TotalBytes)
            {
                throw new CompanionProtocolException("TRANSFER_RANGE_INVALID", "The download resume offset is invalid.");
            }

            download = candidate;
            download.Touch();
            sender = _sender ?? throw new CompanionProtocolException(
                "BINARY_HANDLER_REQUIRED",
                "The DVC binary sender is not available.");
        }
        finally
        {
            _gate.Release();
        }

        await using var stream = new FileStream(
            download.FilePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            MaximumChunkBytes,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        stream.Position = offset;
        var buffer = new byte[MaximumChunkBytes];
        var sent = offset;
        if (sent == download.TotalBytes)
        {
            await sender(new BinaryChunk(transferId, sent, true, ReadOnlyMemory<byte>.Empty), cancellationToken)
                .ConfigureAwait(false);
        }
        else
        {
            while (sent < download.TotalBytes)
            {
                var count = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (count <= 0)
                {
                    throw new CompanionProtocolException("TRANSFER_TRUNCATED", "The download file changed during transfer.");
                }

                var final = sent + count == download.TotalBytes;
                await sender(
                    new BinaryChunk(transferId, sent, final, buffer.AsMemory(0, count).ToArray()),
                    cancellationToken).ConfigureAwait(false);
                sent += count;
            }
        }

        return new
        {
            transferId,
            sentBytes = sent - offset,
            totalBytes = download.TotalBytes,
            sha256 = download.Sha256,
            completed = sent == download.TotalBytes,
        };
    }

    public async ValueTask<object> ReleaseAsync(JsonElement parameters, CancellationToken cancellationToken)
    {
        RequireProperties(parameters, "transferId");
        var transferId = ReadTransferId(parameters);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var released = RemoveTransfer(transferId);
            return new { transferId, released };
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask ReleaseAsync(Guid transferId, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            RemoveTransfer(transferId);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        await _gate.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_disposed)
            {
                return;
            }

            foreach (var transfer in _transfers.Values)
            {
                DeleteFile(transfer.FilePath);
            }

            _transfers.Clear();
            _disposed = true;
            try
            {
                Directory.Delete(_sessionRoot, recursive: true);
            }
            catch (IOException)
            {
            }
        }
        finally
        {
            _gate.Release();
            _gate.Dispose();
        }
    }

    private void EnsureCapacity()
    {
        if (_transfers.Count >= MaximumConcurrentTransfers)
        {
            throw new CompanionProtocolException(
                "TRANSFER_CONCURRENCY_LIMIT",
                "The Companion binary transfer concurrency limit was reached.");
        }
    }

    private void PruneExpired()
    {
        var cutoff = DateTimeOffset.UtcNow - IdleLifetime;
        foreach (var transferId in _transfers
                     .Where(pair => pair.Value.LastActivity < cutoff)
                     .Select(pair => pair.Key)
                     .ToArray())
        {
            RemoveTransfer(transferId);
        }
    }

    private bool RemoveTransfer(Guid transferId)
    {
        if (!_transfers.Remove(transferId, out var transfer))
        {
            return false;
        }

        DeleteFile(transfer.FilePath);
        return true;
    }

    private string TransferPath(Guid transferId, string suffix) => Path.Combine(
        _sessionRoot,
        $"{transferId:N}.{suffix}.part");

    private static async ValueTask<bool> ExistingBytesMatchAsync(
        string path,
        BinaryChunk chunk,
        CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.RandomAccess);
        stream.Position = chunk.Offset;
        var existing = new byte[chunk.Data.Length];
        await stream.ReadExactlyAsync(existing, cancellationToken).ConfigureAwait(false);
        return CryptographicOperations.FixedTimeEquals(existing, chunk.Data.Span);
    }

    private static async ValueTask<string> HashFileAsync(string path, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            128 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        return Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false))
            .ToLowerInvariant();
    }

    private static object Descriptor(UploadState upload, long nextOffset, bool completed) => new
    {
        transferId = upload.TransferId,
        purpose = upload.Purpose,
        totalBytes = upload.TotalBytes,
        sha256 = upload.Sha256,
        nextOffset,
        completed,
    };

    private static Guid ReadTransferId(JsonElement parameters)
    {
        var value = ReadRequiredString(parameters, "transferId");
        return Guid.TryParse(value, out var transferId) && transferId != Guid.Empty
            ? transferId
            : throw new CompanionProtocolException("TRANSFER_ID_INVALID", "The transfer ID is invalid.");
    }

    private static string ReadPurpose(JsonElement parameters)
    {
        var purpose = ReadRequiredString(parameters, "purpose");
        ValidatePurpose(purpose);
        return purpose;
    }

    private static void ValidatePurpose(string purpose)
    {
        if (purpose.Length is < 1 or > 64
            || purpose.Any(character =>
                !(char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or '_')))
        {
            throw new CompanionProtocolException("TRANSFER_PURPOSE_INVALID", "The transfer purpose is invalid.");
        }
    }

    private static long ReadTotalBytes(JsonElement parameters)
    {
        if (!parameters.TryGetProperty("totalBytes", out var value)
            || !value.TryGetInt64(out var totalBytes)
            || totalBytes < 0
            || totalBytes > MaximumTransferBytes)
        {
            throw new CompanionProtocolException("TRANSFER_SIZE_INVALID", "The transfer size is outside the configured limit.");
        }

        return totalBytes;
    }

    private static long ReadOffset(JsonElement parameters)
    {
        if (!parameters.TryGetProperty("offset", out var value) || !value.TryGetInt64(out var offset))
        {
            throw new CompanionProtocolException("TRANSFER_RANGE_INVALID", "The transfer offset is invalid.");
        }

        return offset;
    }

    private static string ReadSha256(JsonElement parameters) => NormalizeSha256(
        ReadRequiredString(parameters, "sha256"));

    private static string NormalizeSha256(string value)
    {
        if (value.Length != 64 || value.Any(character => !char.IsAsciiHexDigit(character)))
        {
            throw new CompanionProtocolException("TRANSFER_HASH_INVALID", "The transfer SHA-256 is invalid.");
        }

        return value.ToLowerInvariant();
    }

    private static string ReadRequiredString(JsonElement parameters, string name)
    {
        if (parameters.ValueKind != JsonValueKind.Object
            || !parameters.TryGetProperty(name, out var value)
            || value.ValueKind != JsonValueKind.String
            || string.IsNullOrEmpty(value.GetString()))
        {
            throw new CompanionProtocolException("TRANSFER_REQUEST_INVALID", "The transfer request is invalid.");
        }

        return value.GetString()!;
    }

    private static void RequireProperties(JsonElement parameters, params string[] expectedNames)
    {
        if (parameters.ValueKind != JsonValueKind.Object)
        {
            throw new CompanionProtocolException("TRANSFER_REQUEST_INVALID", "Transfer parameters must be an object.");
        }

        var expected = expectedNames.ToHashSet(StringComparer.Ordinal);
        var actual = parameters.EnumerateObject().Select(property => property.Name).ToArray();
        if (actual.Length != expected.Count || actual.Any(name => !expected.Contains(name)))
        {
            throw new CompanionProtocolException(
                "TRANSFER_REQUEST_INVALID",
                "The transfer request contains missing or unsupported fields.");
        }
    }

    private static bool FixedDigestEquals(string lhs, string rhs) => CryptographicOperations.FixedTimeEquals(
        Convert.FromHexString(lhs),
        Convert.FromHexString(rhs));

    private static void DeleteFile(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
        }
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);

    private abstract class TransferState(
        Guid transferId,
        string purpose,
        string filePath)
    {
        public Guid TransferId { get; } = transferId;
        public string Purpose { get; } = purpose;
        public string FilePath { get; } = filePath;
        public DateTimeOffset LastActivity { get; private set; } = DateTimeOffset.UtcNow;
        public void Touch() => LastActivity = DateTimeOffset.UtcNow;
    }

    private sealed class UploadState(
        Guid transferId,
        string purpose,
        long totalBytes,
        string sha256,
        string filePath)
        : TransferState(transferId, purpose, filePath)
    {
        public long TotalBytes { get; } = totalBytes;
        public string Sha256 { get; } = sha256;
        public long ReceivedBytes { get; set; }
        public bool SawFinal { get; set; }
        public bool Verified { get; set; }
    }

    private sealed class DownloadState(Guid transferId, string purpose, string filePath)
        : TransferState(transferId, purpose, filePath)
    {
        public long TotalBytes { get; set; }
        public string Sha256 { get; set; } = string.Empty;
        public bool Verified { get; set; }
    }
}
