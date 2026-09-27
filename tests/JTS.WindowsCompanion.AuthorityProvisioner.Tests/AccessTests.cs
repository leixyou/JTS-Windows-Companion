using Xunit;

namespace JTS.WindowsCompanion.AuthorityProvisioner.Tests;

public sealed class AccessTests
{
    private static ProvisioningSecurity Valid => new(ProvisioningIntentAccess.AdminSid, true,
        [new(ProvisioningIntentAccess.AdminSid, 0x1f01ff, true), new(ProvisioningFixture.Authority, 0x120089, true)]);
    [Fact]
    public void AdministratorOwnedReadOnlyIntentIsAccepted() => ProvisioningIntentAccess.Require(Valid, true);
    [Theory]
    [InlineData(0x10000000)] [InlineData(0x40000000)] [InlineData(0x40000)] [InlineData(0x80000)]
    [InlineData(0x10000)] [InlineData(0x40)] [InlineData(2)] [InlineData(4)] [InlineData(0x10)] [InlineData(0x100)]
    public void AccountCannotForgeIntentByChangingContentOrReplacingParents(int right)
    {
        var facts = Valid with { Entries = [.. Valid.Entries, new(ProvisioningFixture.Authority, right, true)] };
        Assert.Throws<ProvisioningException>(() => ProvisioningIntentAccess.Require(facts, true));
        Assert.Throws<ProvisioningException>(() => ProvisioningIntentAccess.Require(facts with
            { Entries = [new(ProvisioningFixture.Worker, right, true, InheritOnly: true)] }, true));
    }
    [Fact]
    public void AccountOwnedOrInheritedIntentIsNotInstallerApproval()
    {
        Assert.Throws<ProvisioningException>(() => ProvisioningIntentAccess.Require(Valid with { Owner = ProvisioningFixture.Authority }, true));
        Assert.Throws<ProvisioningException>(() => ProvisioningIntentAccess.Require(Valid with { Protected = false }, true));
    }
    [Fact]
    public void AncestorsCanPermitSiblingCreationButNotReplacement()
    {
        ProvisioningIntentAccess.Require(Valid with { Protected = false, Entries = [new("S-1-5-11", 4, true)] }, false);
        Assert.Throws<ProvisioningException>(() => ProvisioningIntentAccess.Require(Valid with { Entries = [new("S-1-5-11", 0x40, true)] }, false));
    }
}
