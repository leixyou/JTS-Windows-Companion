namespace JTS.WindowsCompanion.Files;

public sealed record FileRoot(
    string Id,
    string Path,
    bool ReadOnly = false,
    long MaximumFileBytes = 256L * 1024 * 1024);

public sealed record SandboxedPath(FileRoot Root, string FullPath, string RelativePath);

public sealed record RemoteFileInfo(
    string Name,
    string RelativePath,
    bool IsDirectory,
    long Length,
    DateTimeOffset LastWriteTimeUtc,
    string? Sha256 = null);

public sealed record FileReadResult(
    string RelativePath,
    ReadOnlyMemory<byte> Content,
    string Sha256,
    DateTimeOffset LastWriteTimeUtc);

public sealed record FileWriteRequest(
    string RootId,
    string RelativePath,
    ReadOnlyMemory<byte> Content,
    string ExpectedSha256,
    bool Overwrite);

public sealed record BinaryFileImportRequest(
    string RootId,
    string RelativePath,
    string SourceFilePath,
    long ExpectedBytes,
    string ExpectedSha256,
    long MaximumBytes,
    bool Overwrite);

public sealed record BinaryFileExportRequest(
    string RootId,
    string RelativePath,
    string DestinationFilePath,
    long Offset,
    long Length,
    long MaximumBytes);

public sealed record BinaryFileExportResult(
    string RelativePath,
    long SourceLength,
    long Offset,
    long BytesTransferred,
    bool EndOfFile,
    DateTimeOffset LastWriteTimeUtc);

public sealed class FileSandboxException : Exception
{
    public FileSandboxException(string code, string message)
        : base(message)
    {
        Code = code;
    }

    public string Code { get; }
}
