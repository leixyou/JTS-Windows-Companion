using System.Text.Json;
using JTS.WindowsCompanion.Agent;
using JTS.WindowsCompanion.Protocol;
using JTS.WindowsCompanion.Security;
using JTS.WindowsCompanion.Transfers;

namespace JTS.WindowsCompanion.Files;

public static class FileMethodRegistrar
{
    public const int MaximumInlineFileBytes = 512 * 1024;
    public const long MaximumMcpFileTransferBytes = 64L * 1024 * 1024;
    public const string FileUploadPurpose = "file-upload";
    public const string FileDownloadPurpose = "file-download";

    private const int MaximumInlineBase64Characters = ((MaximumInlineFileBytes + 2) / 3) * 4;

    public static void Register(
        CompanionRequestRouter router,
        SandboxedFileService? files,
        BinaryTransferCoordinator transfers,
        CompanionSensitiveInteractionCoordinator? sensitiveInteractions = null)
    {
        ArgumentNullException.ThrowIfNull(router);
        ArgumentNullException.ThrowIfNull(transfers);
        var interactions = sensitiveInteractions ?? new CompanionSensitiveInteractionCoordinator();
        router.Register("files.list", async (request, cancellationToken) =>
        {
            var service = RequireService(files);
            var parameters = Deserialize<PathParameters>(request.Parameters);
            return await service.ListAsync(
                parameters.RootId,
                parameters.RelativePath,
                cancellationToken).ConfigureAwait(false);
        });
        router.Register("files.stat", async (request, cancellationToken) =>
        {
            var service = RequireService(files);
            var parameters = Deserialize<StatParameters>(request.Parameters);
            return await service.StatAsync(
                parameters.RootId,
                parameters.RelativePath,
                parameters.IncludeSha256,
                cancellationToken).ConfigureAwait(false);
        });
        router.Register("files.read", async (request, cancellationToken) =>
        {
            var service = RequireService(files);
            var parameters = Deserialize<PathParameters>(request.Parameters);
            FileReadResult result;
            try
            {
                result = await service.ReadAsync(
                    parameters.RootId,
                    parameters.RelativePath,
                    MaximumInlineFileBytes,
                    cancellationToken).ConfigureAwait(false);
            }
            catch (FileSandboxException exception) when (exception.Code == "FILE_TOO_LARGE")
            {
                throw new CompanionProtocolException(
                    "BINARY_TRANSFER_REQUIRED",
                    "Files larger than 512 KiB require files.download.");
            }

            return new
            {
                result.RelativePath,
                contentBase64 = Convert.ToBase64String(result.Content.Span),
                result.Sha256,
                result.LastWriteTimeUtc,
            };
        });
        router.Register("files.write", async (request, cancellationToken) =>
        {
            using var interaction = interactions.Enter(CompanionSensitiveInteractionKind.FileMutation);
            var service = RequireService(files);
            var parameters = Deserialize<WriteParameters>(request.Parameters);
            var content = DecodeInlineContent(parameters.ContentBase64);
            return await service.WriteAsync(
                new FileWriteRequest(
                    parameters.RootId,
                    parameters.RelativePath,
                    content,
                    parameters.ExpectedSha256,
                    parameters.Overwrite),
                cancellationToken).ConfigureAwait(false);
        });
        router.Register("files.upload", async (request, cancellationToken) =>
        {
            using var interaction = interactions.Enter(CompanionSensitiveInteractionKind.FileMutation);
            var service = RequireService(files);
            var parameters = Deserialize<UploadParameters>(request.Parameters);
            ValidateBinaryMetadata(
                parameters.TransferId,
                parameters.TotalBytes,
                parameters.Sha256);
            var upload = await transfers.GetValidatedUploadAsync(
                parameters.TransferId,
                FileUploadPurpose,
                parameters.TotalBytes,
                parameters.Sha256,
                cancellationToken).ConfigureAwait(false);
            try
            {
                var imported = await service.ImportBinaryAsync(
                    new BinaryFileImportRequest(
                        parameters.RootId,
                        parameters.RelativePath,
                        upload.FilePath,
                        upload.TotalBytes,
                        upload.Sha256,
                        MaximumMcpFileTransferBytes,
                        parameters.Overwrite),
                    cancellationToken).ConfigureAwait(false);
                return new
                {
                    transferId = upload.TransferId,
                    imported.RelativePath,
                    destinationPath = imported.RelativePath,
                    bytesTransferred = imported.Length,
                    imported.Sha256,
                    imported.LastWriteTimeUtc,
                };
            }
            finally
            {
                await transfers.ReleaseAsync(parameters.TransferId, CancellationToken.None).ConfigureAwait(false);
            }
        });
        router.Register("files.download", async (request, cancellationToken) =>
        {
            var service = RequireService(files);
            var parameters = Deserialize<DownloadParameters>(request.Parameters);
            ValidateDownloadRange(parameters.Offset, parameters.Length);
            var reservation = await transfers.ReserveDownloadAsync(
                FileDownloadPurpose,
                cancellationToken).ConfigureAwait(false);
            try
            {
                var exported = await service.ExportBinaryRangeAsync(
                    new BinaryFileExportRequest(
                        parameters.RootId,
                        parameters.RelativePath,
                        reservation.FilePath,
                        parameters.Offset,
                        parameters.Length,
                        MaximumMcpFileTransferBytes),
                    cancellationToken).ConfigureAwait(false);
                var transfer = await transfers.FinalizeDownloadAsync(
                    reservation.TransferId,
                    MaximumMcpFileTransferBytes,
                    allowEmpty: true,
                    cancellationToken).ConfigureAwait(false);
                if (transfer.TotalBytes != exported.BytesTransferred)
                {
                    throw new CompanionProtocolException(
                        "TRANSFER_SIZE_MISMATCH",
                        "The staged file download size does not match its descriptor.");
                }

                return new
                {
                    transferId = transfer.TransferId,
                    purpose = transfer.Purpose,
                    totalBytes = transfer.TotalBytes,
                    sha256 = transfer.Sha256,
                    exported.RelativePath,
                    exported.Offset,
                    exported.SourceLength,
                    exported.EndOfFile,
                    exported.LastWriteTimeUtc,
                };
            }
            catch
            {
                await transfers.ReleaseAsync(reservation.TransferId, CancellationToken.None).ConfigureAwait(false);
                throw;
            }
        });
    }

    private static T Deserialize<T>(JsonElement element)
    {
        try
        {
            return element.Deserialize<T>(ControlMessageSerializer.Options)
                ?? throw new CompanionProtocolException(
                    "REQUEST_INVALID",
                    "The file request parameters are missing.");
        }
        catch (JsonException)
        {
            throw new CompanionProtocolException(
                "REQUEST_INVALID",
                "The file request parameters are invalid.");
        }
    }

    private static byte[] DecodeInlineContent(string value)
    {
        if (value is null || value.Length > MaximumInlineBase64Characters)
        {
            throw new CompanionProtocolException(
                "BINARY_TRANSFER_REQUIRED",
                "Files larger than 512 KiB require files.upload.");
        }

        byte[] content;
        try
        {
            content = Convert.FromBase64String(value);
        }
        catch (FormatException)
        {
            throw new CompanionProtocolException("CONTENT_INVALID", "The request contains invalid base64 data.");
        }

        if (content.Length > MaximumInlineFileBytes)
        {
            throw new CompanionProtocolException(
                "BINARY_TRANSFER_REQUIRED",
                "Files larger than 512 KiB require files.upload.");
        }

        return content;
    }

    private static void ValidateBinaryMetadata(Guid transferId, long totalBytes, string sha256)
    {
        if (transferId == Guid.Empty
            || totalBytes < 0
            || totalBytes > MaximumMcpFileTransferBytes
            || string.IsNullOrWhiteSpace(sha256)
            || sha256.Length != 64
            || sha256.Any(character => !char.IsAsciiHexDigit(character)))
        {
            throw new CompanionProtocolException(
                "FILE_TRANSFER_INVALID",
                "The file upload descriptor is invalid.");
        }
    }

    private static void ValidateDownloadRange(long offset, long length)
    {
        if (offset < 0 || length < 0 || length > MaximumMcpFileTransferBytes)
        {
            throw new CompanionProtocolException(
                "FILE_TRANSFER_RANGE_INVALID",
                "The file download range is outside the configured limit.");
        }
    }

    private static SandboxedFileService RequireService(SandboxedFileService? service) =>
        service ?? throw new CompanionProtocolException(
            "FILES_NOT_CONFIGURED",
            "The requested companion feature is not configured.");

    private sealed record PathParameters(string RootId, string RelativePath);

    private sealed record StatParameters(string RootId, string RelativePath, bool IncludeSha256 = false);

    private sealed record WriteParameters(
        string RootId,
        string RelativePath,
        string ContentBase64,
        string ExpectedSha256,
        bool Overwrite = false);

    private sealed record UploadParameters(
        string RootId,
        string RelativePath,
        Guid TransferId,
        long TotalBytes,
        string Sha256,
        bool Overwrite = false);

    private sealed record DownloadParameters(
        string RootId,
        string RelativePath,
        long Offset,
        long Length);
}
