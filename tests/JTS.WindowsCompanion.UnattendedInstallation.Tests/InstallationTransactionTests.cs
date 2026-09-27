using System.Text.Json;
using System.Text.Json.Nodes;
using Xunit;

namespace JTS.WindowsCompanion.UnattendedInstallation.Tests;

public sealed class InstallationTransactionTests
{
    [Fact]
    public async Task DurableIntentPrecedesEveryMutationAndActivationIsLast()
    {
        using var f = new InstallationFixture(); var result = await f.Create().RunAsync(CancellationToken.None);
        Assert.Equal(InstallPhase.Active, result.Phase); Assert.Equal(result, InstallJournal.Read(f.JournalPath));
        Assert.Equal(["authority", "worker", "configure", "initialize", "register", "publish", "activate"], f.Calls);
        Assert.NotEqual(result.Authority!.Sid, result.Worker!.Sid); Assert.Equal(new string('b', 64), result.DeviceId);
        var bytes = File.ReadAllText(f.JournalPath); Assert.DoesNotContain("password", bytes, StringComparison.OrdinalIgnoreCase);
    }
    [Theory]
    [InlineData("authority")] [InlineData("worker")]
    public async Task MissingAccountReceiptIsAmbiguousNeverAdoptedOrDeleted(string operation)
    {
        using var f = new InstallationFixture { Fail = operation };
        Assert.Equal("INSTALL_ACCOUNT_OWNERSHIP_UNCERTAIN", (await Assert.ThrowsAsync<UnattendedInstallationException>(() => f.Create().RunAsync(CancellationToken.None))).Code);
        Assert.Equal(InstallPhase.RepairRequired, InstallJournal.Read(f.JournalPath).Phase); Assert.DoesNotContain("rollback", f.Calls);
    }
    [Theory]
    [InlineData("configure")] [InlineData("initialize")] [InlineData("register")] [InlineData("publish")]
    public async Task ConfirmedPreActivationFailureRollsBackOnce(string operation)
    {
        using var f = new InstallationFixture { Fail = operation };
        Assert.Equal("INSTALL_FAILED_ROLLED_BACK", (await Assert.ThrowsAsync<UnattendedInstallationException>(() => f.Create().RunAsync(CancellationToken.None))).Code);
        Assert.Equal(InstallPhase.RolledBack, InstallJournal.Read(f.JournalPath).Phase);
        Assert.Equal(1, f.Calls.Count(c => c == "rollback")); Assert.DoesNotContain("activate", f.Calls);
    }
    [Theory]
    [InlineData("PROVISION_PROCESS_STOP_UNCONFIRMED")] [InlineData("PROVISION_PROFILE_UNLOAD_UNCONFIRMED")]
    public async Task UnconfirmedHelperNeverTriggersDestructiveRollback(string code)
    {
        using var f = new InstallationFixture { Fail = "initialize", FailureCode = code };
        Assert.Equal("INSTALL_PROVISIONING_REQUIRES_LOCAL_REPAIR", (await Assert.ThrowsAsync<UnattendedInstallationException>(() => f.Create().RunAsync(CancellationToken.None))).Code);
        Assert.Equal(InstallPhase.RepairRequired, f.Journal.Current.Phase); Assert.DoesNotContain("rollback", f.Calls);
    }
    [Fact]
    public async Task ActivationFailurePreservesIdentityAccountsAndState()
    {
        using var f = new InstallationFixture { Fail = "activate" };
        Assert.Equal("INSTALL_ACTIVATION_REQUIRES_LOCAL_REPAIR", (await Assert.ThrowsAsync<UnattendedInstallationException>(() => f.Create().RunAsync(CancellationToken.None))).Code);
        Assert.Equal(InstallPhase.RepairRequired, f.Journal.Current.Phase); Assert.NotNull(f.Journal.Current.DeviceId); Assert.DoesNotContain("rollback", f.Calls);
    }
    [Fact]
    public async Task FailedRollbackIsNotClaimedSuccessfulAndCannotRestart()
    {
        using var f = new InstallationFixture { Fail = "publish", RollbackConfirmed = false }; var engine = f.Create();
        Assert.Equal("INSTALL_ROLLBACK_REQUIRES_LOCAL_REPAIR", (await Assert.ThrowsAsync<UnattendedInstallationException>(() => engine.RunAsync(CancellationToken.None))).Code);
        Assert.Equal(InstallPhase.RepairRequired, f.Journal.Current.Phase);
        await Assert.ThrowsAsync<UnattendedInstallationException>(() => engine.RunAsync(CancellationToken.None));
        await Assert.ThrowsAsync<UnattendedInstallationException>(() => f.Create().RunAsync(CancellationToken.None));
        Assert.Equal(1, f.Calls.Count(c => c == "rollback"));
    }
    [Fact]
    public async Task CancellationBeforeActivationCannotEnableServices()
    {
        using var f = new InstallationFixture(); using var stop = new CancellationTokenSource();
        f.OnCall = name => { if (name == "publish") stop.Cancel(); };
        await Assert.ThrowsAsync<UnattendedInstallationException>(() => f.Create().RunAsync(stop.Token));
        Assert.Equal(InstallPhase.RolledBack, f.Journal.Current.Phase); Assert.DoesNotContain("activate", f.Calls);
    }
    [Fact]
    public async Task JournalWriteFailureBeforeActivationDoesNotStartOrCleanAnything()
    {
        using var f = new InstallationFixture(); f.OnCall = name =>
        { if (name == "publish") File.WriteAllText(f.JournalPath + ".pending", "interrupted-update"); };
        await Assert.ThrowsAsync<UnattendedInstallationException>(() => f.Create().RunAsync(CancellationToken.None));
        Assert.Equal(InstallPhase.Publishing, InstallJournal.Read(f.JournalPath).Phase);
        Assert.DoesNotContain("activate", f.Calls); Assert.DoesNotContain("rollback", f.Calls);
    }
    [Fact]
    public void ExistingJournalAndImmutableBindingCannotBeOverwritten()
    {
        using var f = new InstallationFixture(); var original = File.ReadAllBytes(f.JournalPath);
        Assert.Throws<IOException>(() => new InstallJournal(f.JournalPath, f.Initial with { EnrollmentId = Guid.NewGuid() }));
        Assert.Equal(original, File.ReadAllBytes(f.JournalPath));
        Assert.Throws<UnattendedInstallationException>(() => f.Journal.Save(f.Initial with { Phase = InstallPhase.CreatingAuthority, RelayOrigin = "https://other.invalid/" }));
        Assert.Throws<UnattendedInstallationException>(() => f.Journal.Save(f.Initial with { Phase = InstallPhase.Active }));
    }
    [Theory]
    [InlineData("SchemaVersion", "9")] [InlineData("Phase", "999")] [InlineData("RelayOrigin", "null")]
    [InlineData("ReleaseHash", "\"INVALID\"")] [InlineData("extra", "true")]
    public void InvalidJournalIsNotRecoveryAuthority(string field, string value)
    {
        using var f = new InstallationFixture(); var json = JsonNode.Parse(File.ReadAllBytes(f.JournalPath))!; json[field] = JsonNode.Parse(value);
        File.WriteAllText(f.JournalPath, json.ToJsonString()); Assert.Throws<UnattendedInstallationException>(() => InstallJournal.Read(f.JournalPath));
    }
    [Fact]
    public void DuplicateAndMalformedUtf8JournalAreRejected()
    {
        using var f = new InstallationFixture(); var json = JsonSerializer.Serialize(f.Initial);
        File.WriteAllText(f.JournalPath, json.Replace("{", "{\"SchemaVersion\":1,", StringComparison.Ordinal));
        Assert.Throws<UnattendedInstallationException>(() => InstallJournal.Read(f.JournalPath));
        File.WriteAllBytes(f.JournalPath, [0xff]); Assert.Throws<UnattendedInstallationException>(() => InstallJournal.Read(f.JournalPath));
    }
}
