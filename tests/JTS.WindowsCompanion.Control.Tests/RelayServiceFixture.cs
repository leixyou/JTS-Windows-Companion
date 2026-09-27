using System.Collections.Concurrent;
using JTS.WindowsCompanion.Relay;
using JTS.WindowsCompanion.Runtime;

namespace JTS.WindowsCompanion.Control.Tests;

internal sealed class RelayServiceFixture : IAsyncDisposable, IControlRelayPairings, IControlGrantProvider, IJobExecutor
{
    private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("jts-relay-service-");
    private readonly FixtureProtector _protector = new();
    internal FakeRelayConnector Connector { get; } = new();
    public string LocalDeviceId => Connector.DeviceId;
    internal string Owner { get; } = new('a', 64);
    internal Guid GrantId { get; } = Guid.NewGuid();
    internal ControlRelayPairing? Pairing { get; set; }
    internal ControlGrant Grant { get; }
    internal Dictionary<Guid, ControlGrant> AdditionalGrants { get; } = [];
    internal DurableJobStore Store { get; }
    internal CompanionRelayControlService Service { get; }
    internal Task? Run { get; private set; }
    internal bool PairingReadFails, RevokeFails;
    internal Action? AfterRevoke;
    internal int Executions;
    internal TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal RelayServiceFixture(bool fast = true, bool waitForRelayAdmission = false)
    {
        Pairing = new(Guid.NewGuid(), new(Owner, RelayTlsPolicy.Tls13, [RelayLane.Control]), DateTimeOffset.UtcNow.AddHours(1), [GrantId]);
        Grant = new(Owner, GrantId, DateTimeOffset.UtcNow.AddHours(2), Enum.GetValues<ControlOperation>(), ["fixture.block", "fixture.echo"], true);
        Store = DurableJobStore.CreateNew(Path.Combine(_directory.FullName, "jobs.sqlite"), _protector);
        var timing = fast ? new RelayControlTiming(TimeSpan.FromMilliseconds(10), TimeSpan.FromMilliseconds(30),
            TimeSpan.FromMilliseconds(25), TimeSpan.FromMilliseconds(100)) : RelayControlTiming.Default;
        Service = new(Connector, Store, this, this, this, TimeProvider.System, timing, waitForRelayAdmission);
    }
    internal Task Start() => Run = Service.RunAsync();
    public ValueTask<ControlRelayPairing?> FindAsync(string owner, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (PairingReadFails) throw new IOException("fixture-only private exception");
        return ValueTask.FromResult(Pairing?.Trust.DeviceId == owner ? Pairing : null);
    }
    public ValueTask RevokeAsync(string owner, Guid id, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (RevokeFails) throw new IOException("fixture-only private disk detail");
        if (Pairing?.PairingId == id && Pairing.Trust.DeviceId == owner) Pairing = null;
        AfterRevoke?.Invoke(); return ValueTask.CompletedTask;
    }
    public ValueTask<ControlGrant?> FindAsync(string owner, Guid grant, CancellationToken token)
        => ValueTask.FromResult(owner != Owner ? null : grant == GrantId ? Grant : AdditionalGrants.GetValueOrDefault(grant));
    public async ValueTask<JobExecutionResult> ExecuteAsync(JobBinding binding, ReadOnlyMemory<byte> payload, IJobOutputSink output, CancellationToken token)
    {
        Interlocked.Increment(ref Executions); Started.TrySetResult();
        if (binding.Kind == "fixture.block") await Task.Delay(Timeout.Infinite, token);
        return new(true, "OK");
    }
    internal RelayChannelOffer Offer(RelayLane lane = RelayLane.Control, Guid? id = null, string? owner = null, string? companion = null)
        => new(new(id ?? Guid.NewGuid(), lane, owner ?? Owner, companion ?? Connector.DeviceId), new string('T', 43),
            DateTimeOffset.UtcNow.AddSeconds(30), new Uri("https://fixture.invalid"));
    internal static async Task Until(Func<bool> condition)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(4));
        while (!condition()) await Task.Delay(10, deadline.Token);
    }
    public async ValueTask DisposeAsync()
    {
        await Service.DisposeAsync(); Store.Dispose(); _protector.Dispose(); _directory.Delete(true);
    }
}

internal sealed class FakeRelayConnector : IControlRelayConnector
{
    public string DeviceId { get; } = new('b', 64);
    internal ConcurrentQueue<RelayChannelOffer[]> Batches { get; } = new();
    internal ConcurrentQueue<Guid> Served { get; } = new();
    internal Func<CancellationToken, Task>? Touch;
    internal Func<CancellationToken, Task<IReadOnlyList<RelayChannelOffer>>>? Poll;
    internal Func<CompanionControlHost, RelayChannelOffer, CancellationToken, Task>? Serve;
    internal int PresenceCount, PollCount, ClosedCount;
    internal bool AllLanes;
    public bool Supports(RelayLane lane) => AllLanes || lane == RelayLane.Control;
    public Task TouchPresenceAsync(CancellationToken token)
    { Interlocked.Increment(ref PresenceCount); return Touch?.Invoke(token) ?? Task.CompletedTask; }
    public Task<IReadOnlyList<RelayChannelOffer>> PollAsync(CancellationToken token)
    {
        Interlocked.Increment(ref PollCount);
        return Poll?.Invoke(token) ?? Task.FromResult<IReadOnlyList<RelayChannelOffer>>(Batches.TryDequeue(out var batch) ? batch : []);
    }
    public async Task ServeAsync(CompanionControlHost host, RelayChannelOffer offer, RelayPeerTrust trust, CancellationToken token)
    {
        Served.Enqueue(offer.Binding.SessionId);
        try
        {
            if (Serve is not null) await Serve(host, offer, token);
            else await Task.Delay(Timeout.Infinite, token);
        }
        finally { Interlocked.Increment(ref ClosedCount); }
    }
}
