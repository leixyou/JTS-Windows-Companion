using System.Security.Cryptography;
using System.Text.Json;
using Xunit;

namespace JTS.WindowsCompanion.Control.Tests;

public sealed class RelayFileLaneTests
{
    [Fact]
    public async Task WrongLaneGrantCannotOpenOrReadFiles()
    {
        await using var f = new LaneFixture(); await using var c = await f.ConnectAsync();
        Assert.Equal("LANE_GRANT_REQUIRED", (await c.Request("file.open", new { }, f.RdpGrant)).GetProperty("errorCode").GetString());
    }
    [Fact]
    public async Task UploadReconnectRetryHashAndAtomicCommitThenRangedDownload()
    {
        await using var f = new LaneFixture(); var bytes = RandomNumberGenerator.GetBytes(70000); var id = Guid.NewGuid();
        var hash = Convert.ToHexStringLower(SHA256.HashData(bytes)); var target = Path.Combine(f.Shared, "result.bin");
        await File.WriteAllTextAsync(target, "old");
        var begin = new { transferId = id, rootId = "shared", path = "result.bin", totalBytes = bytes.Length, sha256 = hash, overwrite = true };
        await using (var c = await f.ConnectAsync())
        {
            Ok(await c.Request("file.open", new { })); Ok(await c.Request("file.write.begin", begin));
            var chunk = new { transferId = id, offset = 0, dataBase64 = Convert.ToBase64String(bytes[..32768]), final = false };
            Ok(await c.Request("file.write.chunk", chunk));
            Assert.Equal(32768, Ok(await c.Request("file.write.chunk", chunk)).GetProperty("nextOffset").GetInt64());
            Assert.Equal("old", await File.ReadAllTextAsync(target));
        }
        await using (var c = await f.ConnectAsync())
        {
            Ok(await c.Request("file.open", new { }));
            Assert.Equal(32768, Ok(await c.Request("file.write.begin", begin)).GetProperty("nextOffset").GetInt64());
            for (var offset = 32768; offset < bytes.Length; offset += 32768)
            {
                var chunk = bytes[offset..Math.Min(offset + 32768, bytes.Length)];
                Ok(await c.Request("file.write.chunk", new { transferId = id, offset, dataBase64 = Convert.ToBase64String(chunk), final = offset + chunk.Length == bytes.Length }));
            }
            Assert.Equal("old", await File.ReadAllTextAsync(target));
            Assert.Equal(hash, Ok(await c.Request("file.write.commit", new { transferId = id })).GetProperty("sha256").GetString());
            Ok(await c.Request("file.write.commit", new { transferId = id }));
            Assert.Equal(bytes, await File.ReadAllBytesAsync(target));
            var range = Ok(await c.Request("file.read", new { rootId = "shared", path = "result.bin", offset = 32768, maximumBytes = 32768 }));
            Assert.Equal(bytes[32768..65536], Convert.FromBase64String(range.GetProperty("dataBase64").GetString()!));
            Assert.Equal(65536, range.GetProperty("nextOffset").GetInt64());
            Assert.False(range.GetProperty("eof").GetBoolean());
        }
    }
    [Fact]
    public async Task FailedDigestDoesNotReplaceDestination()
    {
        await using var f = new LaneFixture(); await using var c = await f.ConnectAsync(); var id = Guid.NewGuid();
        await File.WriteAllTextAsync(Path.Combine(f.Shared, "keep"), "old"); Ok(await c.Request("file.open", new { }));
        Ok(await c.Request("file.write.begin", new { transferId = id, rootId = "shared", path = "keep", totalBytes = 1, sha256 = new string('0', 64), overwrite = true }));
        Ok(await c.Request("file.write.chunk", new { transferId = id, offset = 0, dataBase64 = "AQ==", final = true }));
        Assert.Equal("TRANSFER_HASH_MISMATCH", (await c.Request("file.write.commit", new { transferId = id })).GetProperty("errorCode").GetString());
        Assert.Equal("old", await File.ReadAllTextAsync(Path.Combine(f.Shared, "keep")));
    }
    [Fact]
    public async Task RootListingMutationAndRevocationEnforceDifferentBoundaries()
    {
        await using var f = new LaneFixture(); await using var c = await f.ConnectAsync(); Ok(await c.Request("file.open", new { }));
        Ok(await c.Request("file.mkdir", new { rootId = "shared", path = "folder" }));
        var list = Ok(await c.Request("file.list", new { rootId = "shared", path = ".", offset = 0, limit = 100 }));
        Assert.Equal("folder", list.GetProperty("entries")[0].GetProperty("path").GetString());
        Assert.Equal("PATH_TRAVERSAL", (await c.Request("file.remove", new { rootId = "shared", path = "." })).GetProperty("errorCode").GetString());
        await f.Pairings.RevokeAsync(LaneFixture.Owner, f.PairingId);
        Assert.Equal("LANE_GRANT_REQUIRED", (await c.Request("file.roots", new { })).GetProperty("errorCode").GetString());
    }
    [Theory]
    [InlineData("../escape")] [InlineData("folder/../escape")] [InlineData("C:/escape")] [InlineData("file:stream")]
    public async Task UnsafePathsNeverCreateDestination(string path)
    {
        await using var f = new LaneFixture(); await using var c = await f.ConnectAsync(); Ok(await c.Request("file.open", new { }));
        Assert.False((await c.Request("file.mkdir", new { rootId = "shared", path })).GetProperty("ok").GetBoolean());
        Assert.Empty(Directory.GetFileSystemEntries(f.Shared));
    }
    [Fact]
    public async Task StatMoveAndNonrecursiveRemoveKeepOtherData()
    {
        await using var f = new LaneFixture(); await using var c = await f.ConnectAsync(); Ok(await c.Request("file.open", new { }));
        await File.WriteAllTextAsync(Path.Combine(f.Shared, "old"), "value");
        var moved = Ok(await c.Request("file.move", new { rootId = "shared", path = "old", destinationPath = "new", overwrite = false }));
        Assert.Equal("new", moved.GetProperty("path").GetString());
        var stat = Ok(await c.Request("file.stat", new { rootId = "shared", path = "new", includeSha256 = true }));
        Assert.Equal(5, stat.GetProperty("size").GetInt64()); Assert.NotNull(stat.GetProperty("sha256").GetString());
        Directory.CreateDirectory(Path.Combine(f.Shared, "folder")); await File.WriteAllTextAsync(Path.Combine(f.Shared, "folder", "keep"), "keep");
        Assert.False((await c.Request("file.remove", new { rootId = "shared", path = "folder" })).GetProperty("ok").GetBoolean());
        Ok(await c.Request("file.remove", new { rootId = "shared", path = "new" }));
        Assert.False(File.Exists(Path.Combine(f.Shared, "new"))); Assert.True(File.Exists(Path.Combine(f.Shared, "folder", "keep")));
    }
    [Fact]
    public async Task RdpCannotAcceptArbitraryTargetOrFileGrant()
    {
        await using var f = new LaneFixture();
        await using (var c = await f.ConnectAsync(new RelayRdpLane(f.Pairings)))
            Assert.Equal("LANE_GRANT_REQUIRED", (await c.Request("rdp.open", new { })).GetProperty("errorCode").GetString());
        await using (var c = await f.ConnectAsync(new RelayRdpLane(f.Pairings)))
            Assert.Equal("CONTROL_REQUEST_INVALID", (await c.Request("rdp.open", new { host = "example.org", port = 22 }, f.RdpGrant)).GetProperty("errorCode").GetString());
    }
    private static JsonElement Ok(JsonElement response)
    { Assert.True(response.GetProperty("ok").GetBoolean(), response.ToString()); return response.GetProperty("result"); }
}
