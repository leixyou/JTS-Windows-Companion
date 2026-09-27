using System.Security.Cryptography;
using System.Text.Json;
using JTS.WindowsCompanion.Control;
using JTS.WindowsCompanion.Pairing;
using JTS.WindowsCompanion.Runtime;
using Microsoft.Data.Sqlite;
using Xunit;

namespace JTS.WindowsCompanion.AuthorityProvisioner.Tests;

public sealed class StagingTests
{
    [Fact]
    public void RealIdentityAndStoresReopenEmptyAndReceiptDoesNotEnableAnything()
    {
        using var f = new ProvisioningFixture(); f.State().Create(f.Paths, f.Intent);
        using var receipt = JsonDocument.Parse(File.ReadAllBytes(f.Paths.FilePath("ready.json")));
        var root = receipt.RootElement; var device = root.GetProperty("identity").GetProperty("DeviceId").GetString()!;
        Assert.Equal("staged-not-enabled", root.GetProperty("state").GetString());
        Assert.Equal(f.Enrollment, root.GetProperty("enrollmentId").GetGuid());
        Assert.Equal(ProvisioningFixture.Authority, root.GetProperty("authoritySid").GetString());
        Assert.Equal(ProvisioningFixture.Worker, root.GetProperty("workerSid").GetString());
        Assert.False(Directory.Exists(f.Paths.Live)); Assert.False(File.Exists(f.Paths.FilePath("authority.json")));
        Assert.False(File.Exists(f.Paths.FilePath("ready.pending.json")));
        foreach (var file in root.GetProperty("files").EnumerateArray())
        {
            var bytes = File.ReadAllBytes(f.Paths.FilePath(file.GetProperty("name").GetString()!));
            Assert.Equal(bytes.Length, file.GetProperty("bytes").GetInt64());
            Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(bytes)), file.GetProperty("sha256").GetString());
        }
        using var identity = f.Open(f.Paths.FilePath("identity.sealed"), f.Intent, device);
        using var pairings = new DurableRelayPairingStore(f.Paths.FilePath("pairings.sqlite"), device, f.Protector);
        using var grants = new DurableControlGrantStore(f.Paths.FilePath("control-grants.sqlite"), f.Protector);
        using var jobs = new DurableJobStore(f.Paths.FilePath("jobs.sqlite"), f.Protector);
        Assert.Empty(pairings.ListLocally()); Assert.Empty(grants.ListLocally()); Assert.Null(jobs.GetRecoveryRequirement());
        using var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = f.Paths.FilePath("jobs.sqlite"), Mode = SqliteOpenMode.ReadOnly, Pooling = false }.ToString());
        db.Open(); using var command = db.CreateCommand(); command.CommandText = "SELECT count(*) FROM jobs;";
        Assert.Equal(0L, command.ExecuteScalar());
    }
    [Fact]
    public void ReadyStateCannotBeReinitializedOrIdentityRotated()
    {
        using var f = new ProvisioningFixture(); f.State().Create(f.Paths, f.Intent);
        var before = Directory.GetFiles(f.Paths.State).ToDictionary(p => new FileInfo(p).Name, File.ReadAllBytes);
        Assert.Throws<IOException>(() => f.State().Create(f.Paths, f.Intent));
        foreach (var entry in before) Assert.Equal(entry.Value, File.ReadAllBytes(f.Paths.FilePath(entry.Key)));
    }
    [Fact]
    public void ExistingLiveInstallationIsUntouched()
    {
        using var f = new ProvisioningFixture(); Directory.CreateDirectory(f.Paths.Live); File.WriteAllText(Path.Combine(f.Paths.Live, "sentinel"), "old");
        Assert.Equal("PROVISION_EXISTING_INSTALLATION", Assert.Throws<ProvisioningException>(() => f.State().Create(f.Paths, f.Intent)).Code);
        Assert.Empty(Directory.GetFiles(f.Paths.State)); Assert.Equal("old", File.ReadAllText(Path.Combine(f.Paths.Live, "sentinel")));
    }
    [Fact]
    public void EnrollmentMustMatchStagingDirectory()
    {
        using var f = new ProvisioningFixture();
        Assert.Equal("PROVISION_ENROLLMENT_MISMATCH", Assert.Throws<ProvisioningException>(() => f.State().Create(f.Paths, f.Intent with { EnrollmentId = Guid.NewGuid() })).Code);
        Assert.Empty(Directory.GetFiles(f.Paths.State));
    }
    [Fact]
    public void ConcurrentInstallerPublicationPreventsReadyReceipt()
    {
        using var f = new ProvisioningFixture(); var state = f.State(path =>
        { if (Path.GetFileName(path) == "ready.pending.json") Directory.CreateDirectory(f.Paths.Live); });
        Assert.Equal("PROVISION_EXISTING_INSTALLATION", Assert.Throws<ProvisioningException>(() => state.Create(f.Paths, f.Intent)).Code);
        Assert.False(File.Exists(f.Paths.FilePath("ready.json"))); Assert.Empty(Directory.GetFiles(f.Paths.Live));
    }
    [Theory]
    [InlineData("identity.sealed")] [InlineData("authority.json")] [InlineData("ready.json")]
    public void NonemptyStageIsNeverRepaired(string name)
    {
        using var f = new ProvisioningFixture(); File.WriteAllText(f.Paths.FilePath(name), "untouched");
        Assert.Equal("PROVISION_STAGE_NOT_EMPTY", Assert.Throws<ProvisioningException>(() => f.State().Create(f.Paths, f.Intent)).Code);
        Assert.Equal("untouched", File.ReadAllText(f.Paths.FilePath(name)));
    }
    [Fact]
    public void ReopenFailureLeavesOnlyIsolatedAttemptAndCannotBeRetried()
    {
        using var f = new ProvisioningFixture(); f.BeforeOpen = () => throw new CryptographicException("fixture-reopen-failure");
        Assert.Throws<CryptographicException>(() => f.State().Create(f.Paths, f.Intent));
        Assert.False(File.Exists(f.Paths.FilePath("ready.json"))); Assert.False(Directory.Exists(f.Paths.Live));
        Assert.True(File.Exists(f.Paths.FilePath("attempt.json"))); f.BeforeOpen = null;
        Assert.Throws<IOException>(() => f.State().Create(f.Paths, f.Intent));
    }
    [Theory]
    [InlineData("identity.sealed")] [InlineData("pairings.sqlite")] [InlineData("control-grants.sqlite")]
    [InlineData("jobs.sqlite")] [InlineData("ready.pending.json")] [InlineData("ready.json")]
    public void AccessFailureAtEachBoundaryCannotPublishReady(string name)
    {
        using var f = new ProvisioningFixture();
        var state = f.State(path => { if (Path.GetFileName(path) == name) throw new UnauthorizedAccessException(); });
        Assert.Throws<UnauthorizedAccessException>(() => state.Create(f.Paths, f.Intent));
        Assert.False(File.Exists(f.Paths.FilePath("ready.json"))); Assert.False(Directory.Exists(f.Paths.Live));
    }
    [Fact]
    public void ExpiryDuringGenerationRejectsReceiptCommit()
    {
        using var f = new ProvisioningFixture(); var state = f.State(path =>
        { if (Path.GetFileName(path) == "ready.pending.json") f.Clock.Now = f.Intent.ExpiresAt; });
        Assert.Equal("PROVISION_INTENT_EXPIRED_OR_INVALID", Assert.Throws<ProvisioningException>(() => state.Create(f.Paths, f.Intent)).Code);
        Assert.False(File.Exists(f.Paths.FilePath("ready.json"))); Assert.True(File.Exists(f.Paths.FilePath("ready.pending.json")));
    }
    [Fact]
    public void UnexpectedSidecarIsNotDeletedOrPublished()
    {
        using var f = new ProvisioningFixture(); f.BeforeOpen = () => File.WriteAllText(f.Paths.FilePath("unknown.sqlite-wal"), "keep");
        Assert.Equal("PROVISION_UNEXPECTED_STATE", Assert.Throws<ProvisioningException>(() => f.State().Create(f.Paths, f.Intent)).Code);
        Assert.Equal("keep", File.ReadAllText(f.Paths.FilePath("unknown.sqlite-wal"))); Assert.False(File.Exists(f.Paths.FilePath("ready.json")));
    }
    [Fact]
    public async Task TwoInvocationsCannotBothInitialize()
    {
        using var f = new ProvisioningFixture(); using var entered = new ManualResetEventSlim(); using var release = new ManualResetEventSlim();
        f.BeforeCreate = () => { entered.Set(); if (!release.Wait(TimeSpan.FromSeconds(10))) throw new TimeoutException(); };
        var first = Task.Run(() => f.State().Create(f.Paths, f.Intent));
        try
        {
            Assert.True(entered.Wait(TimeSpan.FromSeconds(5)));
            Assert.Throws<IOException>(() => f.State().Create(f.Paths, f.Intent));
        }
        finally { release.Set(); await first; }
        Assert.True(File.Exists(f.Paths.FilePath("ready.json")));
    }
    [NonWindowsLinkFact]
    public void RedirectedStateDirectoryIsRejectedWithoutTouchingTarget()
    {
        using var f = new ProvisioningFixture(); var target = Path.Combine(f.Root, "unrelated"); Directory.CreateDirectory(target);
        Directory.Delete(f.Paths.State); Directory.CreateSymbolicLink(f.Paths.State, target);
        try
        {
            Assert.Equal("PROVISION_LINK_REJECTED", Assert.Throws<ProvisioningException>(() => f.State().Create(f.Paths, f.Intent)).Code);
            Assert.Empty(Directory.GetFiles(target));
        }
        finally { Directory.Delete(f.Paths.State); }
    }
}

public sealed class NonWindowsLinkFactAttribute : FactAttribute
{
    public NonWindowsLinkFactAttribute()
    { if (OperatingSystem.IsWindows()) Skip = "Portable symlink fixture; no Windows symlink privilege is requested."; }
}
