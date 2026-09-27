using System.Security.Cryptography;
using System.Text.Json;
using JTS.WindowsCompanion.Pairing;
using JTS.WindowsCompanion.Relay;
using Xunit;

namespace JTS.WindowsCompanion.UnattendedInstallation.Tests;

public sealed class RelayEnrollmentExportTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ExportPreservesTheExactAuthorizedTlsPolicyAndEveryLaneGrant(bool allowTls12)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var spki = key.ExportSubjectPublicKeyInfo(); var encoded = Convert.ToBase64String(spki);
        var device = Convert.ToHexStringLower(SHA256.HashData(spki)); var now = DateTimeOffset.UtcNow;
        var request = new RelayDelegatedEnrollment(device, encoded, Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), now, now.AddMinutes(20), allowTls12);
        using var json = JsonDocument.Parse(RelayEnrollmentExport.Create("fixture", "https://relay.example/", encoded, device, request));
        var export = json.RootElement;
        Assert.Equal(allowTls12, export.GetProperty("allowWindows10TLS12").GetBoolean());
        Assert.Equal(allowTls12 ? RelayTlsPolicy.ExplicitWindows10Tls12 : RelayTlsPolicy.Tls13, request.Pairing().TlsPolicy);
        Assert.Equal(request.PairingID, export.GetProperty("pairingID").GetGuid());
        Assert.Equal(request.GrantID, export.GetProperty("grantID").GetGuid());
        Assert.Equal(request.FileGrantID, export.GetProperty("fileGrantID").GetGuid());
        Assert.Equal(request.RdpGrantID, export.GetProperty("rdpGrantID").GetGuid());
        Assert.Equal(encoded, export.GetProperty("peerSPKIBase64").GetString());
        Assert.Equal(device, export.GetProperty("peerDeviceID").GetString());
    }
}
