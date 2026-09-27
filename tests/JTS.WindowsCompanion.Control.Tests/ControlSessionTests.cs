using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using JTS.WindowsCompanion.Relay;
using JTS.WindowsCompanion.Runtime;
using Xunit;

namespace JTS.WindowsCompanion.Control.Tests;

public sealed class ControlSessionTests
{
    [Fact]
    public async Task AuthenticatedSubmitDeduplicatesAndFetchesBoundedOutputWithoutDesktop()
    {
        await using var f = new ControlFixture(); await using var client = await f.ConnectAsync();
        using var status = await client.CallAsync("device.status", new { }); Assert.True(Ok(status));
        var id = Guid.NewGuid(); var payload = Enumerable.Range(0, 65536).Select(i => (byte)i).ToArray();
        var request = f.Submission(id, payload: payload);
        using var receipt = await client.CallAsync("job.submit", request); Assert.True(Ok(receipt));
        using var repeated = await client.CallAsync("job.submit", request); Assert.True(Ok(repeated));
        await f.WaitForAsync(id, DurableJobState.Succeeded); Assert.Equal(1, f.Executions);
        using var query = await client.CallAsync("job.get", new { jobId = id.ToString("D") });
        Assert.Equal("succeeded", query.RootElement.GetProperty("result").GetProperty("state").GetString());
        using var output = await client.CallAsync("job.output", new { jobId = id.ToString("D"), offset = 32768, maximumBytes = 32768 });
        Assert.True(Ok(output)); Assert.Equal(payload[32768..], Convert.FromBase64String(output.RootElement.GetProperty("result").GetProperty("dataBase64").GetString()!));
        using var conflict = await client.CallAsync("job.submit", f.Submission(id, payload: [9]));
        Assert.Equal("JOB_IDEMPOTENCY_CONFLICT", Code(conflict));
    }

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task LastControlDisconnectCancelsOnlyConnectedTasks(bool detached)
    {
        await using var f = new ControlFixture(); var client = await f.ConnectAsync(); var id = Guid.NewGuid();
        using var receipt = await client.CallAsync("job.submit", f.Submission(id, "fixture.block", detached)); Assert.True(Ok(receipt));
        await f.Started.Task.WaitAsync(TimeSpan.FromSeconds(5)); await client.DisposeAsync();
        if (detached)
        {
            Assert.Equal(DurableJobState.Running, f.Store.Get(id, f.ClientIdentity.DeviceId, f.GrantId).State);
            f.Release.TrySetResult(); await f.WaitForAsync(id, DurableJobState.Succeeded);
            await using var reconnected = await f.ConnectAsync();
            using var query = await reconnected.CallAsync("job.get", new { jobId = id.ToString("D") }); Assert.True(Ok(query));
        }
        else await f.WaitForAsync(id, DurableJobState.Cancelled);
    }

    [Fact]
    public async Task OneOfTwoConnectionsClosingDoesNotCancelJob()
    {
        await using var f = new ControlFixture(); var first = await f.ConnectAsync(); await using var second = await f.ConnectAsync();
        var id = Guid.NewGuid(); using var receipt = await first.CallAsync("job.submit", f.Submission(id, "fixture.block")); Assert.True(Ok(receipt));
        await f.Started.Task.WaitAsync(TimeSpan.FromSeconds(5)); await first.DisposeAsync();
        Assert.Equal(DurableJobState.Running, f.Store.Get(id, f.ClientIdentity.DeviceId, f.GrantId).State);
        using var cancelled = await second.CallAsync("job.cancel", new { jobId = id.ToString("D") }); Assert.True(Ok(cancelled));
        await f.WaitForAsync(id, DurableJobState.Cancelled);
    }

    [Fact]
    public async Task RevocationStopsDetachedExecutionAndRejectsReconnectedGrant()
    {
        await using var f = new ControlFixture(); await using var client = await f.ConnectAsync(); var id = Guid.NewGuid();
        using var receipt = await client.CallAsync("job.submit", f.Submission(id, "fixture.block", true)); Assert.True(Ok(receipt));
        await f.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        f.Grant = null; f.Host.RevokeGrant(f.ClientIdentity.DeviceId, f.GrantId);
        await f.WaitForAsync(id, DurableJobState.Cancelled);
        await using var reconnect = await f.ConnectAsync();
        using var result = await reconnect.CallAsync("job.get", new { jobId = id.ToString("D") });
        Assert.Equal("CONTROL_GRANT_REJECTED", Code(result));
    }

    [Fact]
    public async Task GrantLimitsDetachedKindAndDeadlineEvenOverAuthenticatedTLS()
    {
        await using var f = new ControlFixture(); await using var client = await f.ConnectAsync();
        f.Grant = new(f.ClientIdentity.DeviceId, f.GrantId, DateTimeOffset.UtcNow.AddSeconds(30), Enum.GetValues<ControlOperation>(), ["fixture.echo"]);
        using var detached = await client.CallAsync("job.submit", f.Submission(Guid.NewGuid(), detached: true, deadline: DateTimeOffset.UtcNow.AddSeconds(10)));
        using var kind = await client.CallAsync("job.submit", f.Submission(Guid.NewGuid(), "fixture.block", deadline: DateTimeOffset.UtcNow.AddSeconds(10)));
        using var deadline = await client.CallAsync("job.submit", f.Submission(Guid.NewGuid()));
        Assert.Equal("CONTROL_GRANT_REJECTED", Code(detached)); Assert.Equal("CONTROL_GRANT_REJECTED", Code(kind));
        Assert.Equal("CONTROL_GRANT_REJECTED", Code(deadline)); Assert.Equal(0, f.Executions);
    }

    [Fact]
    public async Task TaskDeadlineCannotExceed24HoursAndOwnerCannotBeInjected()
    {
        await using var f = new ControlFixture(); await using var client = await f.ConnectAsync();
        using var longTask = await client.CallAsync("job.submit", f.Submission(Guid.NewGuid(), deadline: DateTimeOffset.UtcNow.AddHours(24.5)));
        Assert.Equal("JOB_REQUEST_INVALID", Code(longTask));
        using var injected = await client.CallAsync("device.status", new { ownerDeviceId = new string('a', 64) });
        Assert.Equal("CONTROL_REQUEST_INVALID", Code(injected));
        using var wrongGrant = await client.CallAsync("device.status", new { }, Guid.NewGuid());
        Assert.Equal("CONTROL_GRANT_REJECTED", Code(wrongGrant));
    }

    [Theory]
    [InlineData(RelayLane.File)] [InlineData(RelayLane.Rdp)]
    public async Task OtherLanesCannotDispatchControl(RelayLane lane)
    {
        await using var f = new ControlFixture();
        await Assert.ThrowsAnyAsync<Exception>(async () => { await using var _ = await f.ConnectAsync(lane); });
        Assert.Contains(f.SessionErrors, e => e is ControlProtocolException { Code: "CONTROL_LANE_REQUIRED" });
    }

    [Fact]
    public async Task DifferentGrantCannotReadOrCancelExistingReceipt()
    {
        await using var f = new ControlFixture(); await using var client = await f.ConnectAsync();
        var id = Guid.NewGuid();
        using var submitted = await client.CallAsync("job.submit", f.Submission(id)); Assert.True(Ok(submitted));
        await f.WaitForAsync(id, DurableJobState.Succeeded);
        var other = Guid.NewGuid();
        f.Grant = new(f.ClientIdentity.DeviceId, other, DateTimeOffset.UtcNow.AddMinutes(1), Enum.GetValues<ControlOperation>(), ["fixture.echo"]);
        using var query = await client.CallAsync("job.get", new { jobId = id.ToString("D") }, other);
        using var cancel = await client.CallAsync("job.cancel", new { jobId = id.ToString("D") }, other);
        using var output = await client.CallAsync("job.output", new { jobId = id.ToString("D"), offset = 0, maximumBytes = 4 }, other);
        Assert.Equal("JOB_NOT_FOUND", Code(query)); Assert.Equal("JOB_NOT_FOUND", Code(cancel)); Assert.Equal("JOB_NOT_FOUND", Code(output));
        Assert.Equal(DurableJobState.Succeeded, f.Store.Get(id, f.ClientIdentity.DeviceId, f.GrantId).State);
    }

    [Fact]
    public async Task EveryRequestRechecksOperationAndExpiredGrant()
    {
        await using var f = new ControlFixture(); await using var client = await f.ConnectAsync();
        f.Grant = new(f.ClientIdentity.DeviceId, f.GrantId, DateTimeOffset.UtcNow.AddMinutes(1), [ControlOperation.Status], []);
        using var status = await client.CallAsync("device.status", new { }); Assert.True(Ok(status));
        using var submit = await client.CallAsync("job.submit", f.Submission(Guid.NewGuid()));
        Assert.Equal("CONTROL_GRANT_REJECTED", Code(submit));
        f.Grant = new(f.ClientIdentity.DeviceId, f.GrantId, DateTimeOffset.UtcNow.AddSeconds(-1), [ControlOperation.Status], []);
        using var expired = await client.CallAsync("device.status", new { });
        Assert.Equal("CONTROL_GRANT_REJECTED", Code(expired)); Assert.Equal(0, f.Executions);
    }

    [Fact]
    public async Task UnknownOrDuplicateEnvelopePropertiesCloseSessionBeforeExecution()
    {
        await using var f = new ControlFixture(); await using var client = await f.ConnectAsync();
        var bytes = Encoding.UTF8.GetBytes("{\"version\":1,\"version\":1}");
        await ControlWire.WriteAsync(client.Stream, bytes, CancellationToken.None);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        Assert.Null(await ControlWire.ReadAsync(client.Stream, timeout.Token)); Assert.Equal(0, f.Executions);
    }

    [Fact]
    public async Task OversizedFrameClosesWithoutAllocatingRequestedBody()
    {
        await using var f = new ControlFixture(); await using var client = await f.ConnectAsync();
        var header = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(header, uint.MaxValue);
        await client.Stream.WriteAsync(header); await client.Stream.FlushAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        Assert.Null(await ControlWire.ReadAsync(client.Stream, timeout.Token));
        await client.WaitForServerCompletionAsync();
        Assert.Contains(f.SessionErrors, e => e is ControlProtocolException { Code: "CONTROL_FRAME_LIMIT" });
    }

    private static bool Ok(JsonDocument value) => value.RootElement.GetProperty("ok").GetBoolean();
    private static string? Code(JsonDocument value) => value.RootElement.GetProperty("errorCode").GetString();
}
