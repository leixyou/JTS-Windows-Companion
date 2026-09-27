using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Xunit;

namespace JTS.WindowsCompanion.Relay.Tests;

public sealed class RelayServerInteropTests
{
    [RelayServerFact]
    public async Task ActualRelayHttpTicketsWebSocketAndInnerTlsInteroperateForEveryLane()
    {
        var runtime = Environment.GetEnvironmentVariable("JTS_RELAY_TEST_DOTNET")!;
        var serverDll = Environment.GetEnvironmentVariable("JTS_RELAY_TEST_SERVER_DLL")!;
        Assert.True(Path.IsPathFullyQualified(runtime) && File.Exists(runtime));
        Assert.True(Path.IsPathFullyQualified(serverDll) && File.Exists(serverDll));
        using var controllerCertificate = TransportFixture.Certificate("controller");
        using var companionCertificate = TransportFixture.Certificate("companion");
        var controllerIdentity = new RelayEndpointIdentity(controllerCertificate);
        var companionIdentity = new RelayEndpointIdentity(companionCertificate);
        var temporary = Directory.CreateTempSubdirectory("jts-relay-interop-");
        Process? server = null;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try
        {
            using var portProbe = new TcpListener(IPAddress.Loopback, 0);
            portProbe.Start();
            var port = ((IPEndPoint)portProbe.LocalEndpoint).Port;
            portProbe.Stop();
            var origin = new Uri($"http://127.0.0.1:{port}/");
            var configPath = Path.Combine(temporary.FullName, "relay.json");
            var configuration = new
            {
                Relay = new
                {
                    DatabasePath = Path.Combine(temporary.FullName, "state.sqlite"), AllowLoopbackHttp = true,
                    Devices = new[]
                    {
                        new { DeviceId = controllerIdentity.DeviceId, PublicKeySpkiBase64 = PublicKey(controllerCertificate), Role = "controller", Peers = new[] { companionIdentity.DeviceId } },
                        new { DeviceId = companionIdentity.DeviceId, PublicKeySpkiBase64 = PublicKey(companionCertificate), Role = "companion", Peers = new[] { controllerIdentity.DeviceId } },
                    },
                },
            };
            // Only public admission keys are written. Test endpoint private keys stay in memory.
            await File.WriteAllBytesAsync(configPath, JsonSerializer.SerializeToUtf8Bytes(configuration), deadline.Token);
            var start = new ProcessStartInfo(runtime) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
            start.ArgumentList.Add(serverDll);
            start.ArgumentList.Add("--config"); start.ArgumentList.Add(configPath);
            start.ArgumentList.Add("--urls"); start.ArgumentList.Add(origin.AbsoluteUri);
            start.Environment["Logging__LogLevel__Default"] = "Warning";
            server = Process.Start(start)!;
            var outputDrain = DrainAsync(server.StandardOutput);
            var errorDrain = DrainAsync(server.StandardError);
            using var health = new HttpClient { Timeout = TimeSpan.FromSeconds(1) };
            var ready = false;
            for (var attempt = 0; attempt < 50 && !server.HasExited; attempt++)
            {
                try { ready = (await health.GetAsync(new Uri(origin, "healthz"), deadline.Token)).IsSuccessStatusCode; }
                catch (HttpRequestException) { }
                if (ready) break;
                await Task.Delay(50, deadline.Token);
            }
            Assert.True(ready, "The explicitly configured local relay test process did not start.");
            using var controller = new RelayControlClient(origin, controllerIdentity, allowLoopbackDevelopmentHttp: true);
            using var companion = new RelayControlClient(origin, companionIdentity, allowLoopbackDevelopmentHttp: true);
            await controller.TouchPresenceAsync(deadline.Token);
            await companion.TouchPresenceAsync(deadline.Token);
            Assert.Equal(companionIdentity.DeviceId, Assert.Single(await controller.ListPeersAsync(deadline.Token)).DeviceId);
            var policy = OperatingSystem.IsMacOS() ? RelayTlsPolicy.ExplicitWindows10Tls12 : RelayTlsPolicy.Tls13;
            foreach (var lane in Enum.GetValues<RelayLane>())
            {
                var offer = await controller.RequestSessionAsync(companionIdentity.DeviceId, lane, deadline.Token);
                var remoteOffer = Assert.Single(await companion.PollAsync(deadline.Token), o => o.Binding.SessionId == offer.Binding.SessionId);
                var streams = await Task.WhenAll(
                    controller.OpenSecureChannelAsync(offer, TransportFixture.Trust(companionIdentity, policy), deadline.Token),
                    companion.OpenSecureChannelAsync(remoteOffer, TransportFixture.Trust(controllerIdentity, policy), deadline.Token));
                await using var controllerStream = streams[0];
                await using var companionStream = streams[1];
                var plaintext = Encoding.UTF8.GetBytes("JTS-INNER-TLS-" + lane + "-" + Guid.NewGuid());
                var received = new byte[plaintext.Length];
                await Task.WhenAll(controllerStream.WriteAsync(plaintext, deadline.Token).AsTask(),
                    companionStream.ReadExactlyAsync(received, deadline.Token).AsTask());
                Assert.Equal(plaintext, received);
                await Assert.ThrowsAsync<RelayProtocolException>(() => controller.OpenSecureChannelAsync(offer, TransportFixture.Trust(companionIdentity, policy), deadline.Token));
            }
            server.Kill(entireProcessTree: true);
            await server.WaitForExitAsync(deadline.Token);
            await Task.WhenAll(outputDrain, errorDrain);
        }
        finally
        {
            if (server is { HasExited: false }) { server.Kill(entireProcessTree: true); await server.WaitForExitAsync(); }
            server?.Dispose();
            temporary.Delete(recursive: true);
        }
    }

    private static string PublicKey(X509Certificate2 certificate)
    {
        using var key = certificate.GetECDsaPublicKey()!;
        return Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());
    }
    private static async Task DrainAsync(StreamReader reader)
    {
        var buffer = new char[4096];
        while (await reader.ReadAsync(buffer) != 0) { } // Do not retain or echo node logs.
    }
}

internal sealed class RelayServerFactAttribute : FactAttribute
{
    public RelayServerFactAttribute()
    {
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("JTS_RELAY_TEST_DOTNET"))
            || string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("JTS_RELAY_TEST_SERVER_DLL")))
            Skip = "Requires explicitly supplied local relay test runtime and server DLL; no deployed server is used.";
    }
}
