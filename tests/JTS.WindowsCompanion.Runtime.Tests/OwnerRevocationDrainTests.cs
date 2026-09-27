using Xunit;

namespace JTS.WindowsCompanion.Runtime.Tests;

public sealed class OwnerRevocationDrainTests
{
    [Fact]
    public async Task RevocationDrainWaitsForDetachedExecutorAndCancelsItsQueuedSuccessor()
    {
        using var f = new RuntimeFixture(); using var store = f.Open();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var stopped = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var executor = new FixtureExecutor { Execute = async (_, _, _, token) =>
        {
            started.SetResult(); using var cancellation = token.Register(() => stopped.TrySetResult());
            await release.Task; token.ThrowIfCancellationRequested(); return new(true, "OK");
        } };
        await using var runtime = new DurableJobRuntime(store, new FixtureAuthority(), executor);
        var active = f.Job(allowDisconnected: true); var queued = f.Job(allowDisconnected: true);
        await runtime.SubmitAsync(active); await runtime.SubmitAsync(queued);
        var running = runtime.RunNextAsync(); await started.Task.WaitAsync(TimeSpan.FromSeconds(3));
        runtime.SetOwnerConnected(f.Owner, false); Assert.False(stopped.Task.IsCompleted);
        runtime.RevokeOwner(f.Owner); await stopped.Task.WaitAsync(TimeSpan.FromSeconds(3));
        var draining = runtime.DrainRevokedOwnerAsync(f.Owner).AsTask(); Assert.False(draining.IsCompleted);
        Assert.Equal(DurableJobState.Cancelled, store.Get(queued.Binding.RequestId, f.Owner, f.Grant).State);
        release.SetResult(); await running; await draining;
        Assert.Equal(DurableJobState.Cancelled, store.Get(active.Binding.RequestId, f.Owner, f.Grant).State);
        await Assert.ThrowsAsync<JobRuntimeException>(() => runtime.SubmitAsync(f.Job(allowDisconnected: true)));
    }
    [Fact]
    public async Task UnrevokedOwnerCannotProduceDrainConfirmation()
    {
        using var f = new RuntimeFixture(); using var store = f.Open();
        await using var runtime = new DurableJobRuntime(store, new FixtureAuthority(), new FixtureExecutor());
        Assert.Equal("JOB_OWNER_NOT_REVOKED", (await Assert.ThrowsAsync<JobRuntimeException>(() => runtime.DrainRevokedOwnerAsync(f.Owner).AsTask())).Code);
    }
}
