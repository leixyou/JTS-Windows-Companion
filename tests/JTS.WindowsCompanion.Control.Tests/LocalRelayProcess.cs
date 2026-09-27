using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using JTS.WindowsCompanion.Relay;
using Xunit;

namespace JTS.WindowsCompanion.Control.Tests;

// Opt-in external executable, not a source/project reference to the independent relay repository.
internal sealed class LocalRelayProcess : IAsyncDisposable
{
    private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("jts-control-relay-node-");
    private Process? _process;
    private Task? _logs;
    internal Uri Origin { get; private set; } = null!;

    internal async Task StartAsync(X509Certificate2 controller, X509Certificate2 companion, CancellationToken token)
    {
        var runtime = Environment.GetEnvironmentVariable("JTS_RELAY_TEST_DOTNET")!;
        var dll = Environment.GetEnvironmentVariable("JTS_RELAY_TEST_SERVER_DLL")!;
        Assert.True(Path.IsPathFullyQualified(runtime) && File.Exists(runtime));
        Assert.True(Path.IsPathFullyQualified(dll) && File.Exists(dll));
        using var port = new TcpListener(IPAddress.Loopback, 0); port.Start();
        Origin = new($"http://127.0.0.1:{((IPEndPoint)port.LocalEndpoint).Port}/"); port.Stop();
        var controllerId = new RelayEndpointIdentity(controller).DeviceId;
        var companionId = new RelayEndpointIdentity(companion).DeviceId;
        var configuration = new { Relay = new
        {
            DatabasePath = Path.Combine(_directory.FullName, "state.sqlite"), AllowLoopbackHttp = true,
            Devices = new[]
            {
                new { DeviceId = controllerId, PublicKeySpkiBase64 = PublicKey(controller), Role = "controller", Peers = new[] { companionId } },
                new { DeviceId = companionId, PublicKeySpkiBase64 = PublicKey(companion), Role = "companion", Peers = new[] { controllerId } },
            },
        } };
        var config = Path.Combine(_directory.FullName, "relay.json");
        await File.WriteAllBytesAsync(config, JsonSerializer.SerializeToUtf8Bytes(configuration), token);
        var start = new ProcessStartInfo(runtime) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
        start.ArgumentList.Add(dll); start.ArgumentList.Add("--config"); start.ArgumentList.Add(config);
        start.ArgumentList.Add("--urls"); start.ArgumentList.Add(Origin.AbsoluteUri);
        start.Environment["Logging__LogLevel__Default"] = "Warning";
        _process = Process.Start(start) ?? throw new IOException("fixture_process_not_started");
        _logs = Task.WhenAll(DrainAsync(_process.StandardOutput), DrainAsync(_process.StandardError));
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(1) };
        for (var i = 0; i < 50 && !_process.HasExited; i++)
        {
            try { using var response = await http.GetAsync(new Uri(Origin, "healthz"), token); if (response.IsSuccessStatusCode) return; }
            catch (HttpRequestException) { }
            await Task.Delay(50, token);
        }
        throw new IOException("fixture_relay_not_ready");
    }
    private static string PublicKey(X509Certificate2 certificate)
    { using var key = certificate.GetECDsaPublicKey()!; return Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()); }
    private static async Task DrainAsync(StreamReader reader)
    { var chars = new char[4096]; while (await reader.ReadAsync(chars) > 0) { } }
    public async ValueTask DisposeAsync()
    {
        if (_process is { HasExited: false }) { _process.Kill(entireProcessTree: true); await _process.WaitForExitAsync(); }
        if (_logs is not null) await _logs;
        _process?.Dispose(); _directory.Delete(true);
    }
}

internal sealed class LocalRelayFactAttribute : FactAttribute
{
    public LocalRelayFactAttribute()
    {
        if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("JTS_RELAY_TEST_DOTNET"))
            || string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("JTS_RELAY_TEST_SERVER_DLL")))
            Skip = "Requires an explicitly selected local relay executable; never targets the deployed node.";
    }
}
