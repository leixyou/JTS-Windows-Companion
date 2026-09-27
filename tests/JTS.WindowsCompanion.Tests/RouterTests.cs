using System.Text.Json;
using JTS.WindowsCompanion.Agent;
using JTS.WindowsCompanion.Protocol;

namespace JTS.WindowsCompanion.Tests;

public sealed class RouterTests
{
    [Fact]
    public async Task Router_CachesIdempotentResponsesWithoutRepeatingHandler()
    {
        var router = new CompanionRequestRouter(new TestAuthorizationGate());
        var calls = 0;
        router.Register("fixed.operation", (_, _) =>
        {
            calls++;
            return ValueTask.FromResult<object?>(new { calls });
        });
        var request = Request("fixed.operation", "stable-key");

        var first = await router.DispatchAsync(request, DateTimeOffset.UtcNow, CancellationToken.None);
        var second = await router.DispatchAsync(
            request with { RequestId = Guid.NewGuid() },
            DateTimeOffset.UtcNow,
            CancellationToken.None);

        Assert.True(first.Success);
        Assert.True(second.Success);
        Assert.Equal(1, calls);
        Assert.NotEqual(first.RequestId, second.RequestId);
        Assert.Equal(first.Result?.GetProperty("calls").GetInt32(), second.Result?.GetProperty("calls").GetInt32());
    }

    [Fact]
    public async Task Router_RejectsExpiredUnknownAndUnsupportedRequests()
    {
        var router = new CompanionRequestRouter(new TestAuthorizationGate());
        var now = DateTimeOffset.UtcNow;

        var expired = await router.DispatchAsync(
            Request("missing", null) with { DeadlineUnixMilliseconds = now.AddSeconds(-1).ToUnixTimeMilliseconds() },
            now,
            CancellationToken.None);
        var unknown = await router.DispatchAsync(Request("missing", null), now, CancellationToken.None);
        var version = await router.DispatchAsync(
            Request("missing", null) with { ProtocolVersion = CompanionProtocol.CurrentVersion + 1 },
            now,
            CancellationToken.None);

        Assert.Equal("DEADLINE_EXCEEDED", expired.Error?.Code);
        Assert.Equal("METHOD_NOT_FOUND", unknown.Error?.Code);
        Assert.Equal("PROTOCOL_VERSION_UNSUPPORTED", version.Error?.Code);
    }

    [Fact]
    public async Task Router_CoalescesConcurrentRequestsWithTheSameIdempotencyKey()
    {
        var router = new CompanionRequestRouter(new TestAuthorizationGate());
        var calls = 0;
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        router.Register("fixed.concurrent", async (_, cancellationToken) =>
        {
            Interlocked.Increment(ref calls);
            await gate.Task.WaitAsync(cancellationToken);
            return new { completed = true };
        });
        var request = Request("fixed.concurrent", "concurrent-key");
        var first = router.DispatchAsync(request, DateTimeOffset.UtcNow, CancellationToken.None).AsTask();
        var second = router.DispatchAsync(
            request with { RequestId = Guid.NewGuid() },
            DateTimeOffset.UtcNow,
            CancellationToken.None).AsTask();
        gate.SetResult();

        var responses = await Task.WhenAll(first, second);
        Assert.All(responses, response => Assert.True(response.Success));
        Assert.Equal(1, calls);
        Assert.NotEqual(responses[0].RequestId, responses[1].RequestId);
    }

    [Fact]
    public async Task Router_DoesNotExposeUnexpectedExceptionMessages()
    {
        var router = new CompanionRequestRouter(new TestAuthorizationGate());
        router.Register("failure", (_, _) => throw new InvalidOperationException("sensitive internal detail"));

        var response = await router.DispatchAsync(Request("failure", null), DateTimeOffset.UtcNow, CancellationToken.None);

        Assert.Equal("INTERNAL_ERROR", response.Error?.Code);
        Assert.DoesNotContain("sensitive", response.Error?.Message, StringComparison.OrdinalIgnoreCase);
    }

    private static CompanionRequest Request(string method, string? idempotencyKey) => new(
        CompanionProtocol.CurrentVersion,
        Guid.NewGuid(),
        method,
        null,
        idempotencyKey,
        null,
        JsonSerializer.SerializeToElement(new { }));
}
