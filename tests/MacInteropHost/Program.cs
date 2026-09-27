using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using JTS.WindowsCompanion.Relay;

if (args is ["--public-relay-fixture"])
    return await PublicRelayInteropHost.RunAsync();

// Test-only loopback carrier. No private keys or production configuration are read or printed.
using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
try
{
    var line = await Console.In.ReadLineAsync(deadline.Token);
    if (line is null || line.Length > 1024) return 2;
    using var request = JsonDocument.Parse(line);
    var controllerId = request.RootElement.GetProperty("controllerDeviceId").GetString()!;
    var mode = request.RootElement.TryGetProperty("mode", out var modeValue) ? modeValue.GetString() : "echo";
    if (mode is not ("echo" or "control")) return 2;
    var sessionId = Guid.Parse(request.RootElement.GetProperty("sessionId").GetString()!);
    var lane = request.RootElement.GetProperty("lane").GetString() switch
    {
        "control" => RelayLane.Control, "file" => RelayLane.File, "rdp" => RelayLane.Rdp,
        _ => throw new InvalidDataException("test_lane_invalid"),
    };
    using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    var certificateRequest = new CertificateRequest("CN=JTS ephemeral interop test", key, HashAlgorithmName.SHA256);
    certificateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
    certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
    using var certificate = certificateRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(1));
    var identity = new RelayEndpointIdentity(certificate);
    var policy = OperatingSystem.IsMacOS() ? RelayTlsPolicy.ExplicitWindows10Tls12 : RelayTlsPolicy.Tls13;
    var peer = new RelayPeerTrust(controllerId, policy, [lane]);
    var binding = new RelayBinding(sessionId, lane, controllerId, identity.DeviceId);
    binding.Validate();
    if (mode == "control" && lane != RelayLane.Control) return 2;
    await using var control = mode == "control" ? new ControlInteropFixture(controllerId) : null;
    using var listener = new TcpListener(IPAddress.Loopback, 0);
    listener.Start(1);
    Console.WriteLine(JsonSerializer.Serialize(new
    {
        port = ((IPEndPoint)listener.LocalEndpoint).Port,
        companionDeviceId = identity.DeviceId,
        publicKeySpkiBase64 = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()),
        tlsPolicy = policy == RelayTlsPolicy.Tls13 ? "tls13" : "tls12",
        grantId = control?.GrantId.ToString("D"),
    }));
    await Console.Out.FlushAsync(deadline.Token);
    using var client = await listener.AcceptTcpClientAsync(deadline.Token);
    listener.Stop();
    if (control is not null)
    {
        await control.Host.ServeAsync(client.GetStream(), identity, peer, binding, deadline.Token);
        return 0;
    }
    await using var tls = await RelaySecureStream.AuthenticateAsync(client.GetStream(), identity, peer, binding,
        controller: false, deadline.Token);
    var header = new byte[4];
    await tls.ReadExactlyAsync(header, deadline.Token);
    var size = BinaryPrimitives.ReadUInt32BigEndian(header);
    if (size is 0 or > 65532) return 2;
    var payload = new byte[size];
    await tls.ReadExactlyAsync(payload, deadline.Token);
    await tls.WriteAsync(header, deadline.Token);
    await tls.WriteAsync(payload, deadline.Token);
    await tls.FlushAsync(deadline.Token);
    return 0;
}
catch
{
    Console.Error.WriteLine("interop_handshake_or_exchange_failed");
    return 1;
}
