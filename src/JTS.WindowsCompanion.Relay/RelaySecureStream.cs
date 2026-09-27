using System.Buffers.Binary;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace JTS.WindowsCompanion.Relay;

/// <summary>Returns a business stream only after mutual pinned TLS and exact encrypted lane binding.</summary>
public static class RelaySecureStream
{
    private static readonly SslApplicationProtocol ApplicationProtocol = new("jts-relay-v1");

    public static async Task<SslStream> AuthenticateAsync(Stream carrier, RelayEndpointIdentity identity,
        RelayPeerTrust pairedPeer, RelayBinding binding, bool controller, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(carrier);
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(pairedPeer);
        binding.Validate();
        var policy = pairedPeer.TlsPolicy;
        var localDevice = controller ? binding.ControllerDeviceId : binding.CompanionDeviceId;
        var peerDevice = controller ? binding.CompanionDeviceId : binding.ControllerDeviceId;
        if (localDevice != identity.DeviceId) throw new RelayProtocolException("RELAY_IDENTITY_MISMATCH");
        pairedPeer.Require(peerDevice, binding.Lane);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(20));
        var tls = new SslStream(carrier, leaveInnerStreamOpen: false,
            (_, certificate, _, _) => CertificateMatches(certificate, peerDevice));
        try
        {
            var protocols = policy == RelayTlsPolicy.Tls13 ? SslProtocols.Tls13 : SslProtocols.Tls12;
            if (controller)
            {
                await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    // Keep each synthetic DNS label below 64 bytes; identity is the SPKI pin, not DNS.
                    TargetHost = peerDevice[..32] + "." + peerDevice[32..] + ".jts.invalid",
                    ClientCertificates = new X509CertificateCollection { identity.Certificate },
                    LocalCertificateSelectionCallback = (_, _, _, _, _) => identity.Certificate,
                    EnabledSslProtocols = protocols,
                    ApplicationProtocols = [ApplicationProtocol],
                    AllowRenegotiation = false,
                    AllowTlsResume = false,
                    EncryptionPolicy = EncryptionPolicy.RequireEncryption,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                }, deadline.Token).ConfigureAwait(false);
            }
            else
            {
                await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = identity.Certificate,
                    ClientCertificateRequired = true,
                    EnabledSslProtocols = protocols,
                    ApplicationProtocols = [ApplicationProtocol],
                    AllowRenegotiation = false,
                    AllowTlsResume = false,
                    EncryptionPolicy = EncryptionPolicy.RequireEncryption,
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                }, deadline.Token).ConfigureAwait(false);
            }
            if (!tls.IsEncrypted || !tls.IsMutuallyAuthenticated
                || tls.NegotiatedApplicationProtocol != ApplicationProtocol
                || !AcceptNegotiatedCipher(policy, tls.SslProtocol, tls.NegotiatedCipherSuite))
                throw new RelayProtocolException("RELAY_TLS_POLICY_REJECTED");
            await ExchangeBindingAsync(tls, binding, deadline.Token).ConfigureAwait(false);
            return tls;
        }
        catch
        {
            await tls.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    internal static bool AcceptNegotiatedCipher(RelayTlsPolicy policy, SslProtocols protocol, TlsCipherSuite suite) => policy switch
    {
        RelayTlsPolicy.Tls13 => protocol == SslProtocols.Tls13 && suite is
            TlsCipherSuite.TLS_AES_128_GCM_SHA256 or TlsCipherSuite.TLS_AES_256_GCM_SHA384 or TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        RelayTlsPolicy.ExplicitWindows10Tls12 => protocol == SslProtocols.Tls12 && suite is
            TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 or TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        _ => false,
    };

    private static bool CertificateMatches(X509Certificate? certificate, string deviceId)
    {
        if (certificate is null) return false;
        try
        {
            using var peer = new X509Certificate2(certificate);
            var now = DateTime.UtcNow;
            return now >= peer.NotBefore.ToUniversalTime() && now <= peer.NotAfter.ToUniversalTime()
                && CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(deviceId), Convert.FromHexString(RelayEndpointIdentity.CertificateDeviceId(peer)));
        }
        catch (Exception exception) when (exception is CryptographicException or RelayProtocolException or FormatException)
        { return false; }
    }

    internal static async Task ExchangeBindingAsync(Stream stream, RelayBinding binding, CancellationToken token)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new
        {
            protocolVersion = 1, sessionId = binding.SessionId.ToString("D"), lane = RelayWire.LaneName(binding.Lane),
            controllerDeviceId = binding.ControllerDeviceId, companionDeviceId = binding.CompanionDeviceId,
        });
        var header = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(header, (uint)bytes.Length);
        await stream.WriteAsync(header, token).ConfigureAwait(false);
        await stream.WriteAsync(bytes, token).ConfigureAwait(false);
        await stream.FlushAsync(token).ConfigureAwait(false);
        await stream.ReadExactlyAsync(header, token).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadUInt32BigEndian(header);
        if (length is 0 or > 1024) throw new RelayProtocolException("RELAY_BINDING_LIMIT");
        var peerBytes = new byte[(int)length];
        await stream.ReadExactlyAsync(peerBytes, token).ConfigureAwait(false);
        using var json = RelayWire.Parse(peerBytes);
        var value = json.RootElement;
        RelayWire.Properties(value, "protocolVersion", "sessionId", "lane", "controllerDeviceId", "companionDeviceId");
        if (value.GetProperty("protocolVersion").ValueKind != JsonValueKind.Number
            || !value.GetProperty("protocolVersion").TryGetInt32(out var version) || version != 1
            || RelayWire.String(value, "sessionId", 36) != binding.SessionId.ToString("D")
            || RelayWire.String(value, "lane", 8) != RelayWire.LaneName(binding.Lane)
            || RelayWire.String(value, "controllerDeviceId", 64) != binding.ControllerDeviceId
            || RelayWire.String(value, "companionDeviceId", 64) != binding.CompanionDeviceId)
            throw new RelayProtocolException("RELAY_BINDING_MISMATCH");
    }
}
