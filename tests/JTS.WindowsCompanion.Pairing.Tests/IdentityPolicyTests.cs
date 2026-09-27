using Xunit;

namespace JTS.WindowsCompanion.Pairing.Tests;

public sealed class IdentityPolicyTests
{
    private const string Authority = "S-1-5-21-111-222-333-1001", Worker = "S-1-5-21-111-222-333-1002";
    [Fact]
    public void OnlyExactDedicatedAccountCanLoadIdentity()
    {
        IdentityAccessPolicy.Account(Authority, Authority);
        Assert.Throws<RelayIdentityStoreException>(() => IdentityAccessPolicy.Account(Authority, Worker));
    }
    [Theory]
    [InlineData("S-1-5-18")]
    [InlineData("S-1-5-19")]
    [InlineData("S-1-5-20")]
    [InlineData("S-1-5-21-111-222-333-500")]
    [InlineData("S-1-5-21-0111-222-333-1001")]
    [InlineData("S-1-5-21-111-222-333--1001")]
    [InlineData("S-1-5-21-111-222-333-4294967296")]
    public void BuiltinOrNoncanonicalAccountsAreRejected(string sid)
        => Assert.Throws<RelayIdentityStoreException>(() => IdentityAccessPolicy.Account(sid, sid));

    [Fact]
    public void PrivateDirectoryRequiresProtectedAclAndNoWorkerReadOrInheritedAccess()
    {
        var allowed = new IdentitySecurityFacts(Authority, true,
            [new(Authority, 0x1f01ff, true, false), new(IdentityAccessPolicy.SystemSid, 0x1f01ff, true, false)]);
        IdentityAccessPolicy.Object(allowed, Authority, true, true);
        Assert.Throws<RelayIdentityStoreException>(() => IdentityAccessPolicy.Object(allowed with { Protected = false }, Authority, true, true));
        Assert.Throws<RelayIdentityStoreException>(() => IdentityAccessPolicy.Object(allowed with { Owner = Worker }, Authority, true, true));
        foreach (var inheritOnly in new[] { false, true })
            Assert.Throws<RelayIdentityStoreException>(() => IdentityAccessPolicy.Object(allowed with
            { Entries = [.. allowed.Entries, new(Worker, 1, true, inheritOnly)] }, Authority, true, true));
        IdentityAccessPolicy.Object(allowed with { Entries = [.. allowed.Entries, new(Worker, 1, false, false)] }, Authority, true, true);
    }
    [Theory]
    [InlineData(0x10000000)]
    [InlineData(0x40000000)]
    [InlineData(0x80000)]
    [InlineData(0x40000)]
    [InlineData(0x10000)]
    [InlineData(0x40)]
    public void AncestorMustNotBeReplaceableByUntrustedAccount(int mask)
    {
        var facts = new IdentitySecurityFacts(IdentityAccessPolicy.InstallerSid, false, [new(Worker, mask, true, false)]);
        Assert.Throws<RelayIdentityStoreException>(() => IdentityAccessPolicy.Object(facts, Authority, false, false));
        IdentityAccessPolicy.Object(facts with { Entries = [new(Worker, 0x200a9, true, false)] }, Authority, false, false);
    }
    [NonWindowsIdentityFact]
    public void ProductionEntryPointsNeverFallBackToPortableProtection()
    {
        using var fixture = new IdentityFixture();
        Assert.Throws<PlatformNotSupportedException>(() => WindowsRelayIdentityStore.CreateNew(fixture.Path, fixture.EnrollmentId, Authority));
        Assert.Throws<PlatformNotSupportedException>(() => WindowsRelayIdentityStore.Open(fixture.Path, fixture.EnrollmentId, Authority, new string('a', 64)));
        Assert.False(File.Exists(fixture.Path));
    }
}

internal sealed class NonWindowsIdentityFactAttribute : FactAttribute
{
    public NonWindowsIdentityFactAttribute() { if (OperatingSystem.IsWindows()) Skip = "This case checks the non-Windows refusal only."; }
}
