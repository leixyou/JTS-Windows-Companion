using JTS.WindowsCompanion.UnattendedSetup;
using Xunit;

namespace JTS.WindowsCompanion.UnattendedInstallation.Tests;

public sealed class SetupPresentationTests
{
    [Theory]
    [InlineData("https://relay.example", "https://relay.example/")]
    [InlineData(" https://192.0.2.10:8443/ ", "https://192.0.2.10:8443/")]
    [InlineData("https://[2001:db8::1]:8443", "https://[2001:db8::1]:8443/")]
    public void ExplicitHttpsRootNormalizes(string input, string expected)
    { Assert.True(RelayOriginInput.TryNormalize(input, out var actual)); Assert.Equal(expected, actual); }

    [Theory]
    [InlineData(null)] [InlineData("")] [InlineData("http://relay.example")]
    [InlineData("https://user:password@relay.example")]
    [InlineData("https://relay.example/path")] [InlineData("https://relay.example/?secret=x")]
    [InlineData("https://relay.example/#x")] [InlineData("https://relay.example\\x")]
    [InlineData("https://relay.exa\nmple")]
    public void NoImplicitOrUnsafeOrigin(string? input)
    { Assert.False(RelayOriginInput.TryNormalize(input, out var actual)); Assert.Empty(actual); }

    [Fact]
    public void UnknownFailureNeverEchoesSecretsOrPermitsRetry()
    {
        var value = SetupFailure.From(new IOException("secret user path token", new Exception("more secret")));
        Assert.DoesNotContain("secret", value.Text); Assert.False(value.MayRetry);
    }
    [Fact]
    public void OnlyTypedPreTransactionDeclineAllowsRetry()
    {
        Assert.True(SetupFailure.From(new OperationCanceledException("INSTALL_LOCAL_CONSENT_DECLINED")).MayRetry);
        Assert.False(SetupFailure.From(new Exception("INSTALL_LOCAL_CONSENT_DECLINED")).MayRetry);
        Assert.False(SetupFailure.From(new OperationCanceledException()).MayRetry);
    }
    [Theory]
    [InlineData("INSTALL_ACTIVATION_REQUIRES_LOCAL_REPAIR")]
    [InlineData("INSTALL_PROVISIONING_REQUIRES_LOCAL_REPAIR")]
    [InlineData("INSTALL_ROLLBACK_REQUIRES_LOCAL_REPAIR")]
    [InlineData("INSTALL_ACCOUNT_OWNERSHIP_UNCERTAIN")]
    [InlineData("INSTALL_FAILED_ROLLED_BACK")]
    [InlineData("INSTALL_EXISTING_STATE_REQUIRES_LOCAL_REVIEW")]
    public void UnresolvedTransactionNeverOffersBlindRetry(string code)
        => Assert.False(SetupFailure.From(new IOException(code)).MayRetry);
}
