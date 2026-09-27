using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using JTS.WindowsCompanion.Pairing;
using JTS.WindowsCompanion.Relay;

namespace JTS.WindowsCompanion.Control.Tests;

internal sealed class LaneFixture : IAsyncDisposable
{
    internal string Root { get; } = Directory.CreateTempSubdirectory("jts-lane-").FullName;
    internal string Shared => Path.Combine(Root, "shared");
    internal const string Owner = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    internal Guid PairingId { get; } = Guid.NewGuid();
    internal Guid FileGrant { get; } = Guid.NewGuid();
    internal Guid RdpGrant { get; } = Guid.NewGuid();
    internal DurableRelayPairingStore Pairings { get; }
    internal RelayFileLane Files { get; }
    private readonly FixtureProtector _protector = new();
    internal LaneFixture()
    {
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(Root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        Directory.CreateDirectory(Shared);
        Pairings = DurableRelayPairingStore.CreateNew(Path.Combine(Root, "pairings.sqlite"), new string('b', 64), _protector);
        Pairings.ApproveLocally(new(PairingId, Owner, RelayTlsPolicy.Tls13, DateTimeOffset.UtcNow.AddDays(1),
            [RelayLane.Control, RelayLane.File, RelayLane.Rdp], new Dictionary<RelayLane, IReadOnlyList<Guid>>
            { [RelayLane.Control] = [Guid.NewGuid()], [RelayLane.File] = [FileGrant], [RelayLane.Rdp] = [RdpGrant] }), Owner);
        Files = new(Pairings, Shared, Path.Combine(Root, "spool"));
    }
    internal async Task<LaneConnection> ConnectAsync(ICompanionRelayLaneHandler? handler = null)
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        var client = new TcpClient(); await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
        var accepted = await listener.AcceptTcpClientAsync();
        var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var service = Task.Run(async () => { using (accepted) await (handler ?? Files).ServeAsync(accepted.GetStream(), Owner, stop.Token); });
        return new(client, stop, service, FileGrant);
    }
    public async ValueTask DisposeAsync() { await Files.DisposeAsync(); Pairings.Dispose(); _protector.Dispose(); Directory.Delete(Root, true); }
}

internal sealed class LaneConnection(TcpClient client, CancellationTokenSource stop, Task server, Guid defaultGrant) : IAsyncDisposable
{
    internal async Task<JsonElement> Request(string operation, object parameters, Guid? grant = null)
    {
        await ControlWire.WriteAsync(client.GetStream(), JsonSerializer.SerializeToUtf8Bytes(new
        { version = 1, id = Guid.NewGuid(), operation, grantId = grant ?? defaultGrant, parameters }), stop.Token);
        var bytes = await ControlWire.ReadAsync(client.GetStream(), stop.Token) ?? throw new EndOfStreamException();
        using var json = JsonDocument.Parse(bytes); return json.RootElement.Clone();
    }
    public async ValueTask DisposeAsync()
    {
        stop.Cancel(); client.Dispose();
        try { await server; } catch (Exception error) when (error is OperationCanceledException or IOException) { }
        stop.Dispose();
    }
}
