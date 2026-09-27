using Xunit;

namespace JTS.WindowsCompanion.Execution.Tests;

public sealed class ServiceIntegrityRestrictionTests
{
    private const string Sid = ExecutionContractTests.WorkerSid;
    private static WorkerTokenFacts Good(int integrity = 8192)
        => new(Sid, false, integrity, ["S-1-5-32-545", "S-1-5-6"], ["SeChangeNotifyPrivilege"]);

    [Theory]
    [InlineData(12288)]
    [InlineData(16384)]
    public void LowersOnlyValidatedServiceIntegrityAndRereadsBeforeReturning(int initialIntegrity)
    {
        var facts = Good(initialIntegrity); var operations = new List<string>();
        ServiceIntegrityRestriction.Apply(Sid, () => { operations.Add("read"); return facts; }, () =>
        { operations.Add("lower"); facts = facts with { IntegrityRid = 8192 }; });
        Assert.Equal(new[] { "read", "lower", "read" }, operations);
        WorkerAccountPolicy.Validate(Sid, facts);
    }
    [Fact]
    public void MediumIsVerifiedWithoutWritingToken()
    {
        var reads = 0;
        ServiceIntegrityRestriction.Apply(Sid, () => { reads++; return Good(); }, () => Assert.Fail("must not rewrite medium token"));
        Assert.Equal(2, reads);
    }
    [Theory]
    [InlineData(0)]
    [InlineData(4096)]
    [InlineData(8191)]
    [InlineData(8193)]
    [InlineData(8448)]
    [InlineData(12289)]
    [InlineData(20480)]
    public void UnexpectedOrLowerIntegrityNeverCausesTokenWrite(int integrity)
        => AssertRejectedBeforeWrite(Good(integrity));

    [Fact]
    public void EveryExistingSecurityCheckPrecedesIntegrityWrite()
    {
        foreach (var facts in new[]
        {
            Good(16384) with { UserSid = "S-1-5-21-123-456-789-1002" },
            Good(16384) with { UserSid = "S-1-5-18" },
            Good(16384) with { Elevated = true },
            Good(16384) with { Groups = ["S-1-5-32-544"] },
            Good(16384) with { Groups = ["S-1-5-32-547"] },
            Good(16384) with { Groups = ["S-1-5-32-548"] },
            Good(16384) with { Groups = ["S-1-5-32-549"] },
            Good(16384) with { Groups = ["S-1-5-32-550"] },
            Good(16384) with { Groups = ["S-1-5-32-551"] },
            Good(16384) with { Privileges = ["SeImpersonatePrivilege"] },
            Good(16384) with { Privileges = ["SeCreateGlobalPrivilege"] },
            Good(16384) with { Privileges = ["SeDebugPrivilege"] },
            Good(16384) with { Privileges = ["SeAssignPrimaryTokenPrivilege"] },
        }) AssertRejectedBeforeWrite(facts);
    }
    [Theory]
    [InlineData("S-1-5-18")]
    [InlineData("S-1-5-21-123-456-789-500")]
    [InlineData("S-1-5-21-123-456-789-01001")]
    public void InvalidConfiguredAccountNeverCausesWrite(string sid)
    {
        var writes = 0;
        Assert.Throws<ArgumentException>(() => ServiceIntegrityRestriction.Apply(sid, () => Good(16384), () => writes++));
        Assert.Equal(0, writes);
    }
    [Fact]
    public void NativeWriteFailureDoesNotClaimSuccessfulReduction()
    {
        var reads = 0;
        Assert.Throws<IOException>(() => ServiceIntegrityRestriction.Apply(Sid,
            () => { reads++; return Good(16384); }, () => throw new IOException("write refused")));
        Assert.Equal(1, reads);
    }
    [Theory]
    [InlineData(16384)]
    [InlineData(12288)]
    [InlineData(4096)]
    public void NativeSuccessWithoutExactMediumReadbackFails(int observed)
    {
        var reads = 0;
        Assert.Throws<InvalidOperationException>(() => ServiceIntegrityRestriction.Apply(Sid,
            () => ++reads == 1 ? Good(16384) : Good(observed), () => { }));
        Assert.Equal(2, reads);
    }
    [Fact]
    public void PostWriteRechecksIdentityElevationGroupsAndPrivileges()
    {
        foreach (var after in new[]
        {
            Good() with { UserSid = "S-1-5-21-123-456-789-1002" }, Good() with { Elevated = true },
            Good() with { Groups = ["S-1-5-32-544"] }, Good() with { Privileges = ["SeImpersonatePrivilege"] },
        })
        {
            var reads = 0;
            Assert.Throws<InvalidOperationException>(() => ServiceIntegrityRestriction.Apply(Sid,
                () => ++reads == 1 ? Good(16384) : after, () => { }));
        }
    }
    [Fact]
    public void OrdinaryWorkerValidatorStillRejectsHighAndSystemIntegrity()
    {
        Assert.Throws<InvalidOperationException>(() => WorkerAccountPolicy.Validate(Sid, Good(12288)));
        Assert.Throws<InvalidOperationException>(() => WorkerAccountPolicy.Validate(Sid, Good(16384)));
    }
    [NonWindowsServiceFact]
    public void PublicServiceEntryHasNoNonWindowsFallback()
    {
        Assert.Throws<PlatformNotSupportedException>(() => WindowsStandardAccount.RestrictServiceCurrent(Sid));
    }
    private static void AssertRejectedBeforeWrite(WorkerTokenFacts facts)
    {
        var writes = 0;
        Assert.Throws<InvalidOperationException>(() => ServiceIntegrityRestriction.Apply(Sid, () => facts, () => writes++));
        Assert.Equal(0, writes);
    }
}

internal sealed class NonWindowsServiceFactAttribute : FactAttribute
{
    public NonWindowsServiceFactAttribute()
    {
        if (OperatingSystem.IsWindows()) Skip = "Non-Windows refusal contract; native service startup requires separate acceptance.";
    }
}
