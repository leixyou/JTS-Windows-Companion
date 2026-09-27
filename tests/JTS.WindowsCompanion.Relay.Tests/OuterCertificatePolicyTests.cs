using System.Net.Security;
using Xunit;

namespace JTS.WindowsCompanion.Relay.Tests;

public sealed class OuterCertificatePolicyTests
{
    [Fact]
    public void CarrierDefaultAcceptsUntrustedCertificatesWithoutEnablingRedirectsOrCookies()
    {
        using var handler = RelayControlClient.CreateOuterHandler(false);
        Assert.NotNull(handler.SslOptions.RemoteCertificateValidationCallback);
        Assert.True(handler.SslOptions.RemoteCertificateValidationCallback!(new object(), null, null, SslPolicyErrors.RemoteCertificateChainErrors | SslPolicyErrors.RemoteCertificateNameMismatch));
        Assert.False(handler.AllowAutoRedirect); Assert.False(handler.UseCookies);
    }
    [Fact]
    public void StrictCarrierOptInUsesSystemTrust()
    { using var handler = RelayControlClient.CreateOuterHandler(true); Assert.Null(handler.SslOptions.RemoteCertificateValidationCallback); }
}
