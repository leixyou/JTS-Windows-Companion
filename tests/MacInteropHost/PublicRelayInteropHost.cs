using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using JTS.WindowsCompanion.Control;
using JTS.WindowsCompanion.Pairing;
using JTS.WindowsCompanion.Relay;

// Explicitly selected acceptance fixture. The keys belong to the disposable
// public-node test pair; this never enrolls a user device or runs a shell.
internal static class PublicRelayInteropHost
{
    internal static async Task<int> RunAsync()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        var directory = Directory.CreateTempSubdirectory("jts-public-relay-interop-");
        try
        {
            if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(directory.FullName,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            var line = await Console.In.ReadLineAsync(deadline.Token);
            if (line is null || line.Length > 4096) return 2;
            using var json = JsonDocument.Parse(line);
            var origin = new Uri(json.RootElement.GetProperty("origin").GetString()!);
            if (origin.Scheme != "https") return 2;
            var keyPath = json.RootElement.GetProperty("companionKeyPath").GetString()!;
            var controllerSPKI = Convert.FromBase64String(json.RootElement.GetProperty("controllerSPKI").GetString()!);
            var controllerId = Convert.ToHexString(SHA256.HashData(controllerSPKI)).ToLowerInvariant();
            if (!Path.IsPathFullyQualified(keyPath) || new FileInfo(keyPath).Length > 4096) return 2;
            if (!OperatingSystem.IsWindows() && (File.GetUnixFileMode(keyPath)
                & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.OtherRead | UnixFileMode.OtherWrite)) != 0) return 2;
            using var key = ECDsa.Create(); key.ImportFromPem(await File.ReadAllTextAsync(keyPath, deadline.Token));
            var request = new CertificateRequest("CN=JTS public interop test", key, HashAlgorithmName.SHA256);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(1));
            var identity = new RelayEndpointIdentity(certificate);
            using var client = new RelayControlClient(origin, identity);
            await using var control = new ControlInteropFixture(controllerId);
            using var pairings = DurableRelayPairingStore.CreateNew(Path.Combine(directory.FullName, "pairings.sqlite"), identity.DeviceId, control);
            var fileGrant = Guid.NewGuid(); var rdpGrant = Guid.NewGuid();
            var policy = new RelayDevicePairing(Guid.NewGuid(), controllerId, RelayTlsPolicy.ExplicitWindows10Tls12,
                DateTimeOffset.UtcNow.AddMinutes(3), Enum.GetValues<RelayLane>(),
                new Dictionary<RelayLane, IReadOnlyList<Guid>> {
                    [RelayLane.Control] = [control.GrantId], [RelayLane.File] = [fileGrant], [RelayLane.Rdp] = [rdpGrant] });
            pairings.ApproveLocally(policy, controllerId); // Isolated test fixture state, never production consent.
            var shared = Directory.CreateDirectory(Path.Combine(directory.FullName, "shared"));
            var spool = Directory.CreateDirectory(Path.Combine(directory.FullName, "spool"));
            await using var files = new RelayFileLane(pairings, shared.FullName, spool.FullName);
            var rdp = new RelayRdpLane(pairings);
            // A bounded test-owned listener, not an RDP/NLA server. Binding fails
            // rather than contacting any pre-existing process on port 3389.
            using var listener = new TcpListener(IPAddress.Loopback, 3389);
            listener.Start(1);
            var echo = EchoAsync(listener, deadline.Token);
            await client.TouchPresenceAsync(deadline.Token);
            Console.WriteLine(JsonSerializer.Serialize(new { ready = true, companionDeviceId = identity.DeviceId,
                publicKeySpkiBase64 = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()),
                controlGrantId = control.GrantId.ToString("D"), fileGrantId = fileGrant.ToString("D"), rdpGrantId = rdpGrant.ToString("D"),
                tlsPolicy = "tls12", fixture = "public-relay-local-dotnet-not-windows" }));
            await Console.Out.FlushAsync(deadline.Token);
            var accepted = new HashSet<RelayLane>(); var tasks = new List<Task>();
            var nextPresence = DateTimeOffset.UtcNow.AddSeconds(10);
            while (accepted.Count < 3)
            {
                foreach (var offer in await client.PollAsync(deadline.Token))
                {
                    if (offer.Binding.ControllerDeviceId != controllerId || !accepted.Add(offer.Binding.Lane)) continue;
                    tasks.Add(ServeAsync(offer));
                }
                if (DateTimeOffset.UtcNow >= nextPresence)
                {
                    await client.TouchPresenceAsync(deadline.Token); nextPresence = DateTimeOffset.UtcNow.AddSeconds(10);
                }
                await Task.Delay(100, deadline.Token);
            }
            await Task.WhenAll(tasks).WaitAsync(deadline.Token); await echo;
            Console.WriteLine("{\"complete\":true,\"lanes\":3,\"nativeWindows\":false}");
            return 0;

            async Task ServeAsync(RelayChannelOffer offer)
            {
                try
                {
                    if (offer.Binding.Lane == RelayLane.Control)
                        await control.Host.ServeRelayAsync(client, offer, policy.PeerTrust, deadline.Token);
                    else
                    {
                        await using var stream = await client.OpenSecureChannelAsync(offer, policy.PeerTrust, deadline.Token);
                        if (offer.Binding.Lane == RelayLane.File) await files.ServeAsync(stream, controllerId, deadline.Token);
                        else await rdp.ServeAsync(stream, controllerId, deadline.Token);
                    }
                }
                catch (IOException)
                {
                    // The native client closes a lane by cancelling its carrier.
                    // Like the production service, isolate that expected abort;
                    // the Swift side verifies every response before closing.
                    Console.Error.WriteLine("public_relay_lane_closed:" + offer.Binding.Lane);
                }
                catch (Exception error)
                {
                    Console.Error.WriteLine("public_relay_lane_failed:" + offer.Binding.Lane + ":" + error.GetType().Name);
                    throw;
                }
            }
        }
        catch (Exception error)
        {
            // Type only; never print private paths, credentials, tickets or payloads.
            Console.Error.WriteLine("public_relay_fixture_failed:" + error.GetType().Name);
            return 1;
        }
        finally { try { directory.Delete(recursive: true); } catch { } }
    }

    private static async Task EchoAsync(TcpListener listener, CancellationToken token)
    {
        using var client = await listener.AcceptTcpClientAsync(token);
        listener.Stop();
        await using var stream = client.GetStream();
        var bytes = new byte[65536];
        await stream.ReadExactlyAsync(bytes, token);
        await stream.WriteAsync(bytes, token);
        await stream.FlushAsync(token);
        // Keep the test endpoint open until the controller closes, like a live
        // RDP session. EOF-tail delivery is covered by the lane bridge tests.
        int trailing;
        try { trailing = await stream.ReadAsync(new byte[1], token); }
        catch (IOException) { return; } // The verified client roundtrip ends by aborting its carrier.
        if (trailing != 0) throw new InvalidDataException("Unexpected extra fixture bytes.");
    }
}
