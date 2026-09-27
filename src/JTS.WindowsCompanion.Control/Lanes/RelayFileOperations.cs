using System.Security.Cryptography;
using System.Text.Json;
using JTS.WindowsCompanion.Files;

namespace JTS.WindowsCompanion.Control;

internal sealed class RelayFileOperations(FileSandbox sandbox, RelayFileUploads uploads)
{
    internal const int ChunkBytes = 32768;
    internal async Task<object> ExecuteAsync(string owner, Guid grant, string operation, JsonElement p, CancellationToken token)
    {
        switch (operation)
        {
            case "file.roots":
                ControlWire.Fields(p);
                return new { roots = sandbox.Roots.Select(r => new { id = r.Id, name = "Shared", readOnly = r.ReadOnly, maximumFileBytes = r.MaximumFileBytes }).ToArray() };
            case "file.list": return List(p, token);
            case "file.stat":
                ControlWire.Fields(p, "rootId", "path", "includeSha256");
                var statPath = Resolve(p, directory: true);
                return await DescribeAsync(statPath, ControlWire.Boolean(p, "includeSha256"), token).ConfigureAwait(false);
            case "file.read": return await ReadAsync(p, token).ConfigureAwait(false);
            case "file.write.begin": case "file.write.chunk": case "file.write.commit":
                return await uploads.ExecuteAsync(owner, grant, operation, p, token).ConfigureAwait(false);
            case "file.mkdir":
                ControlWire.Fields(p, "rootId", "path"); var directory = Resolve(p, missing: true); Writable(directory);
                if (File.Exists(directory.FullPath)) throw Error("PATH_EXISTS");
                Directory.CreateDirectory(directory.FullPath);
                return await DescribeAsync(directory, false, token).ConfigureAwait(false);
            case "file.remove":
                ControlWire.Fields(p, "rootId", "path"); var removed = Resolve(p); Writable(removed);
                if (Directory.Exists(removed.FullPath)) Directory.Delete(removed.FullPath, recursive: false);
                else File.Delete(removed.FullPath);
                return new { removed = true };
            case "file.move":
                ControlWire.Fields(p, "rootId", "path", "destinationPath", "overwrite");
                var source = Resolve(p); Writable(source);
                var destination = sandbox.Resolve(source.Root.Id, PathText(p, "destinationPath"), allowMissingLeaf: true);
                Writable(destination);
                if (Directory.Exists(source.FullPath)) Directory.Move(source.FullPath, destination.FullPath);
                else File.Move(source.FullPath, destination.FullPath, ControlWire.Boolean(p, "overwrite"));
                return await DescribeAsync(destination, false, token).ConfigureAwait(false);
            default: throw new ControlProtocolException("FILE_OPERATION_UNSUPPORTED");
        }
    }
    private object List(JsonElement p, CancellationToken token)
    {
        ControlWire.Fields(p, "rootId", "path", "offset", "limit"); var path = Resolve(p, directory: true);
        var offset = ControlWire.Integer(p, "offset"); var limit = ControlWire.Integer(p, "limit");
        if (offset is < 0 or > 10000 || limit is < 1 or > 100) throw Error("FILE_RANGE_INVALID");
        var entries = new List<FileSystemInfo>();
        foreach (var entry in new DirectoryInfo(path.FullPath).EnumerateFileSystemInfos())
        {
            token.ThrowIfCancellationRequested();
            if ((entry.Attributes & FileAttributes.ReparsePoint) != 0) continue;
            if (entries.Count == 10000) throw Error("FILE_DIRECTORY_LIMIT");
            entries.Add(entry);
        }
        var sorted = entries.OrderBy(e => e.Name, StringComparer.OrdinalIgnoreCase).ThenBy(e => e.Name, StringComparer.Ordinal).ToArray();
        var page = sorted.Skip((int)offset).Take((int)limit).Select(e => Describe(e,
            path.RelativePath == "." ? e.Name : path.RelativePath.Replace('\\', '/') + "/" + e.Name, null)).ToArray();
        return new { entries = page, nextOffset = offset + page.Length < sorted.Length ? (long?)(offset + page.Length) : null };
    }
    private async Task<object> ReadAsync(JsonElement p, CancellationToken token)
    {
        ControlWire.Fields(p, "rootId", "path", "offset", "maximumBytes"); var path = Resolve(p);
        var offset = ControlWire.Integer(p, "offset"); var maximum = ControlWire.Integer(p, "maximumBytes");
        if (offset < 0 || maximum is < 1 or > ChunkBytes) throw Error("FILE_RANGE_INVALID");
        await using var input = new FileStream(path.FullPath, FileMode.Open, FileAccess.Read, FileShare.Read, ChunkBytes, FileOptions.Asynchronous);
        if (input.Length > path.Root.MaximumFileBytes || offset > input.Length) throw Error("FILE_RANGE_INVALID");
        input.Position = offset; var bytes = new byte[Math.Min(maximum, input.Length - offset)];
        await input.ReadExactlyAsync(bytes, token).ConfigureAwait(false);
        return new { dataBase64 = Convert.ToBase64String(bytes), nextOffset = offset + bytes.Length,
            eof = offset + bytes.Length == input.Length, size = input.Length, sha256 = Convert.ToHexStringLower(SHA256.HashData(bytes)) };
    }
    private SandboxedPath Resolve(JsonElement p, bool directory = false, bool missing = false)
    {
        var root = ControlWire.Text(p, "rootId", 64); var path = PathText(p, "path");
        return directory ? sandbox.ResolveDirectory(root, path) : sandbox.Resolve(root, path, missing);
    }
    internal static string PathText(JsonElement p, string key)
    {
        var path = ControlWire.Text(p, key, 1024);
        if (path.Any(c => char.IsControl(c) || c == ':')) throw Error("PATH_INVALID");
        return path;
    }
    internal static void Writable(SandboxedPath path) { if (path.Root.ReadOnly) throw Error("ROOT_READ_ONLY"); }
    internal static FileSandboxException Error(string code) => new(code, code);
    internal static object Describe(FileSystemInfo entry, string path, string? hash)
        => new { name = entry.Name, path = path.Replace('\\', '/'), isDirectory = entry is DirectoryInfo,
            size = entry is FileInfo file ? file.Length : 0, modifiedAtUnixMilliseconds = new DateTimeOffset(entry.LastWriteTimeUtc).ToUnixTimeMilliseconds(), sha256 = hash };
    internal static async Task<object> DescribeAsync(SandboxedPath path, bool hash, CancellationToken token)
    {
        if (Directory.Exists(path.FullPath)) return Describe(new DirectoryInfo(path.FullPath), path.RelativePath, null);
        string? digest = null;
        if (hash)
        {
            await using var input = File.OpenRead(path.FullPath);
            if (input.Length > path.Root.MaximumFileBytes) throw Error("FILE_TOO_LARGE");
            digest = Convert.ToHexStringLower(await SHA256.HashDataAsync(input, token).ConfigureAwait(false));
        }
        return Describe(new FileInfo(path.FullPath), path.RelativePath, digest);
    }
}
