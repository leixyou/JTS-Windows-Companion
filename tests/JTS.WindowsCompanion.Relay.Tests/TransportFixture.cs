using System.Net;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace JTS.WindowsCompanion.Relay.Tests;

internal static class TransportFixture
{
    internal static X509Certificate2 Certificate(string name)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=" + name, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        var usages = new OidCollection { new("1.3.6.1.5.5.7.3.1"), new("1.3.6.1.5.5.7.3.2") };
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages, critical: true));
        var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(1));
        if (!OperatingSystem.IsWindows()) return certificate;
        // Schannel requires a user-key credential, as in the production identity
        // loader. Do not persist it beyond the returned certificate's lifetime.
        using (certificate)
        {
            var pfx = certificate.Export(X509ContentType.Pkcs12);
            try { return new X509Certificate2(pfx, (string?)null, X509KeyStorageFlags.UserKeySet); }
            finally { CryptographicOperations.ZeroMemory(pfx); }
        }
    }

    internal static async Task<(WebSocket Client, WebSocket Server)> WebSocketsAsync()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var endpoint = (IPEndPoint)listener.LocalEndpoint;
        var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        var accept = listener.AcceptSocketAsync();
        await client.ConnectAsync(endpoint);
        var server = await accept;
        client.NoDelay = server.NoDelay = true;
        return (
            WebSocket.CreateFromStream(new NetworkStream(client, ownsSocket: true), false, null, Timeout.InfiniteTimeSpan),
            WebSocket.CreateFromStream(new NetworkStream(server, ownsSocket: true), true, null, Timeout.InfiniteTimeSpan));
    }

    internal static RelayBinding Binding(RelayEndpointIdentity client, RelayEndpointIdentity server, RelayLane lane = RelayLane.Control)
        => new(Guid.NewGuid(), lane, client.DeviceId, server.DeviceId);

    internal static RelayPeerTrust Trust(RelayEndpointIdentity identity, RelayTlsPolicy policy = RelayTlsPolicy.ExplicitWindows10Tls12)
        => new(identity.DeviceId, policy, [RelayLane.Control, RelayLane.File, RelayLane.Rdp]);
}
