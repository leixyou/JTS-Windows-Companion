using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using JTS.WindowsCompanion.Relay;
using JTS.WindowsCompanion.Runtime;
using JTS.WindowsCompanion.Pairing;
using Xunit;

namespace JTS.WindowsCompanion.Control.Tests;

public sealed class RelayControlServiceInteropTests
{
    [LocalRelayFact]
    public async Task ActualRelayServiceAcceptsPinnedControlAndRecoversDetachedJobAcrossConnections()
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        using var controllerCertificate = ControlFixture.Certificate(); using var companionCertificate = ControlFixture.Certificate();
        var controllerIdentity = new RelayEndpointIdentity(controllerCertificate);
        var companionIdentity = new RelayEndpointIdentity(companionCertificate);
        await using var node = new LocalRelayProcess();
        await node.StartAsync(controllerCertificate, companionCertificate, timeout.Token);
        using var controller = new RelayControlClient(node.Origin, controllerIdentity, true);
        using var companion = new RelayControlClient(node.Origin, companionIdentity, true);
        var policy = OperatingSystem.IsMacOS() ? RelayTlsPolicy.ExplicitWindows10Tls12 : RelayTlsPolicy.Tls13;
        using var f = new BusinessFixture(controllerIdentity.DeviceId, companionIdentity.DeviceId, policy);
        await using var service = new CompanionRelayControlService(companion, f.Store, f, f.Pairings, f);
        var serviceRun = service.RunAsync(timeout.Token);
        await controller.TouchPresenceAsync(timeout.Token);
        await RelayServiceFixture.Until(() => service.Status.State == RelayControlServiceState.Online);
        Assert.NotNull(Assert.Single(await controller.ListPeersAsync(timeout.Token)).LastSeenAt);
        var companionTrust = new RelayPeerTrust(companionIdentity.DeviceId, policy, [RelayLane.Control]);

        var ordinary = Guid.NewGuid();
        await using (var first = await Connect())
        {
            using var status = await Call(first, "device.status", new { }); Assert.True(Ok(status));
            using var submit = await Call(first, "job.submit", f.Submission(ordinary, false)); Assert.True(Ok(submit));
            await UntilState(ordinary, DurableJobState.Running);
        }
        await UntilState(ordinary, DurableJobState.Cancelled);

        var detached = Guid.NewGuid();
        await using (var second = await Connect())
        {
            using var submit = await Call(second, "job.submit", f.Submission(detached, true)); Assert.True(Ok(submit));
            await UntilState(detached, DurableJobState.Running);
        }
        Assert.Equal(DurableJobState.Running, f.Get(detached).State);
        await using (var third = await Connect())
        {
            using var query = await Call(third, "job.get", new { jobId = detached.ToString("D") });
            Assert.Equal("running", query.RootElement.GetProperty("result").GetProperty("state").GetString());
            using var cancel = await Call(third, "job.cancel", new { jobId = detached.ToString("D") }); Assert.True(Ok(cancel));
            await UntilState(detached, DurableJobState.Cancelled);

            var echo = Guid.NewGuid(); var submission = f.Submission(echo, false, "fixture.echo");
            using var sent = await Call(third, "job.submit", submission); Assert.True(Ok(sent));
            await UntilState(echo, DurableJobState.Succeeded);
            using var duplicate = await Call(third, "job.submit", submission); Assert.True(Ok(duplicate));
            using var output = await Call(third, "job.output", new { jobId = echo.ToString("D"), offset = 0, maximumBytes = 32 });
            Assert.Equal("fixture-content"u8.ToArray(), Convert.FromBase64String(output.RootElement.GetProperty("result").GetProperty("dataBase64").GetString()!));
            Assert.Equal(3, f.Executions);

            var revoked = Guid.NewGuid();
            using var last = await Call(third, "job.submit", f.Submission(revoked, true)); Assert.True(Ok(last));
            await UntilState(revoked, DurableJobState.Running);
            await service.RevokePairingAsync(controllerIdentity.DeviceId, f.PairingId, timeout.Token);
            await UntilState(revoked, DurableJobState.Cancelled);
            Assert.Equal("PAIRING_REVOKED", f.Get(revoked).ResultCode);
            Assert.Null(await f.Pairings.FindAsync(controllerIdentity.DeviceId, timeout.Token));
        }
        await service.DisposeAsync(); await serviceRun;
        Assert.Equal(RelayControlServiceState.Stopped, service.Status.State);

        async Task<SslStream> Connect()
        {
            var offer = await controller.RequestSessionAsync(companionIdentity.DeviceId, RelayLane.Control, timeout.Token);
            return await controller.OpenSecureChannelAsync(offer, companionTrust, timeout.Token);
        }
        async Task<JsonDocument> Call(Stream stream, string operation, object parameters)
        {
            var id = Guid.NewGuid().ToString("D");
            var request = JsonSerializer.SerializeToUtf8Bytes(new { version = 1, id, operation, grantId = f.GrantId.ToString("D"), parameters });
            await ControlWire.WriteAsync(stream, request, timeout.Token);
            var result = JsonDocument.Parse(await ControlWire.ReadAsync(stream, timeout.Token) ?? throw new IOException("fixture_control_closed"));
            Assert.Equal(id, result.RootElement.GetProperty("id").GetString()); return result;
        }
        Task UntilState(Guid id, DurableJobState state) => RelayServiceFixture.Until(() => f.Get(id).State == state);
    }
    private static bool Ok(JsonDocument response) => response.RootElement.GetProperty("ok").GetBoolean();

    private sealed class BusinessFixture : IControlGrantProvider, IJobExecutor, IDisposable
    {
        private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("jts-control-business-");
        private readonly FixtureProtector _protector = new();
        private readonly string _owner;
        internal Guid GrantId { get; } = Guid.NewGuid();
        internal Guid PairingId { get; } = Guid.NewGuid();
        private readonly DurableRelayPairingStore _pairingStore;
        internal DurableControlRelayPairings Pairings { get; }
        internal DurableJobStore Store { get; }
        internal int Executions;
        internal BusinessFixture(string owner, string companion, RelayTlsPolicy policy)
        {
            _owner = owner;
            if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(_directory.FullName, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            _pairingStore = DurableRelayPairingStore.CreateNew(Path.Combine(_directory.FullName, "pairings.sqlite"), companion, _protector);
            _pairingStore.ApproveLocally(new(PairingId, owner, policy, DateTimeOffset.UtcNow.AddMinutes(2), [RelayLane.Control],
                new Dictionary<RelayLane, IReadOnlyList<Guid>> { [RelayLane.Control] = [GrantId] }), owner); // Test approval only, not a Windows consent claim.
            Pairings = new(_pairingStore);
            Store = DurableJobStore.CreateNew(Path.Combine(_directory.FullName, "jobs.sqlite"), _protector);
        }
        public ValueTask<ControlGrant?> FindAsync(string owner, Guid id, CancellationToken token) => ValueTask.FromResult<ControlGrant?>(
            owner == _owner && id == GrantId ? new(owner, id, DateTimeOffset.UtcNow.AddMinutes(3), Enum.GetValues<ControlOperation>(), ["fixture.block", "fixture.echo"], true) : null);
        public async ValueTask<JobExecutionResult> ExecuteAsync(JobBinding binding, ReadOnlyMemory<byte> payload, IJobOutputSink output, CancellationToken token)
        {
            Interlocked.Increment(ref Executions);
            if (binding.Kind == "fixture.block") await Task.Delay(Timeout.Infinite, token);
            await output.AppendAsync(payload, token); return new(true, "OK");
        }
        internal object Submission(Guid id, bool detached, string kind = "fixture.block") => new
        {
            jobId = id.ToString("D"), kind, deadlineUnixMilliseconds = DateTimeOffset.UtcNow.AddMinutes(1).ToUnixTimeMilliseconds(),
            allowDisconnected = detached, payloadBase64 = Convert.ToBase64String("fixture-content"u8),
        };
        internal JobSnapshot Get(Guid id) => Store.Get(id, _owner, GrantId);
        public void Dispose() { Store.Dispose(); _pairingStore.Dispose(); _protector.Dispose(); _directory.Delete(true); }
    }
}
