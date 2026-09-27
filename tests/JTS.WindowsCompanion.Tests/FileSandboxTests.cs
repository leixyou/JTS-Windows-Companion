using System.Security.Cryptography;
using JTS.WindowsCompanion.Files;

namespace JTS.WindowsCompanion.Tests;

public sealed class FileSandboxTests
{
    [Theory]
    [InlineData("../outside.txt")]
    [InlineData("folder/../../outside.txt")]
    [InlineData("folder\\..\\outside.txt")]
    [InlineData("/etc/passwd")]
    [InlineData("C:\\Windows\\System32\\config\\SAM")]
    public void Resolve_RejectsTraversalAndAbsolutePaths(string relativePath)
    {
        using var temporary = new TemporaryDirectory();
        var sandbox = new FileSandbox([new FileRoot("workspace", temporary.Path)]);

        Assert.Throws<FileSandboxException>(() => sandbox.Resolve("workspace", relativePath, allowMissingLeaf: true));
    }

    [Fact]
    public void Resolve_RejectsSymbolicLinkEscape()
    {
        using var root = new TemporaryDirectory();
        using var outside = new TemporaryDirectory();
        var link = Path.Combine(root.Path, "escape");
        Directory.CreateSymbolicLink(link, outside.Path);
        File.WriteAllText(Path.Combine(outside.Path, "secret.txt"), "secret");
        var sandbox = new FileSandbox([new FileRoot("workspace", root.Path)]);

        var exception = Assert.Throws<FileSandboxException>(() => sandbox.Resolve("workspace", "escape/secret.txt"));
        Assert.Equal("REPARSE_POINT_REJECTED", exception.Code);
    }

    [Fact]
    public async Task FileService_WritesAtomicallyAndVerifiesHash()
    {
        using var temporary = new TemporaryDirectory();
        Directory.CreateDirectory(Path.Combine(temporary.Path, "output"));
        using var service = new SandboxedFileService(new FileSandbox([new FileRoot("workspace", temporary.Path)]));
        var content = "verified content"u8.ToArray();
        var digest = Convert.ToHexString(SHA256.HashData(content));

        var written = await service.WriteAsync(
            new FileWriteRequest("workspace", "output/result.bin", content, digest, Overwrite: false),
            CancellationToken.None);
        var read = await service.ReadAsync("workspace", "output/result.bin", CancellationToken.None);

        Assert.Equal(digest, written.Sha256);
        Assert.Equal(content, read.Content.ToArray());
        Assert.Equal(digest, read.Sha256);
        var overwrite = await Assert.ThrowsAsync<FileSandboxException>(async () =>
            await service.WriteAsync(
                new FileWriteRequest("workspace", "output/result.bin", content, digest, Overwrite: false),
                CancellationToken.None));
        Assert.Equal("OVERWRITE_REJECTED", overwrite.Code);
    }

    [Fact]
    public async Task FileService_RejectsHashMismatchAndReadOnlyRoot()
    {
        using var temporary = new TemporaryDirectory();
        using var writable = new SandboxedFileService(new FileSandbox([new FileRoot("workspace", temporary.Path)]));
        var content = "content"u8.ToArray();

        var mismatch = await Assert.ThrowsAsync<FileSandboxException>(async () =>
            await writable.WriteAsync(
                new FileWriteRequest("workspace", "new.bin", content, new string('0', 64), Overwrite: false),
                CancellationToken.None));
        Assert.Equal("HASH_MISMATCH", mismatch.Code);

        using var readOnly = new SandboxedFileService(new FileSandbox([new FileRoot("readonly", temporary.Path, ReadOnly: true)]));
        var denied = await Assert.ThrowsAsync<FileSandboxException>(async () =>
            await readOnly.WriteAsync(
                new FileWriteRequest(
                    "readonly",
                    "new.bin",
                    content,
                    Convert.ToHexString(SHA256.HashData(content)),
                    Overwrite: false),
                CancellationToken.None));
        Assert.Equal("ROOT_READ_ONLY", denied.Code);
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"jts-companion-tests-{Guid.NewGuid():N}");
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
