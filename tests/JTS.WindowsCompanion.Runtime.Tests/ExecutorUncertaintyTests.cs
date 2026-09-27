using Xunit;

namespace JTS.WindowsCompanion.Runtime.Tests;

public sealed class ExecutorUncertaintyTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UnconfirmedStopIsInterruptedAndClosesAdmissionEvenWhenCancellationWasRequested(bool cancel)
    {
        using var fixture = new RuntimeFixture(); using var store = fixture.Open();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var executor = new FixtureExecutor { Execute = async (_, _, _, _) =>
        {
            entered.SetResult(); await release.Task;
            throw new JobExecutionStateUnknownException();
        } };
        await using var runtime = new DurableJobRuntime(store, new FixtureAuthority(), executor);
        var job = fixture.Job(allowDisconnected: true);
        var queued = fixture.Job(allowDisconnected: true);
        await runtime.SubmitAsync(job);
        var run = runtime.RunNextAsync(); await entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
        await runtime.SubmitAsync(queued);
        if (cancel) runtime.Cancel(job.Binding.RequestId, fixture.Owner, fixture.Grant);
        release.SetResult();
        var failure = await Assert.ThrowsAsync<JobRuntimeException>(() => run);
        Assert.Equal("JOB_EXECUTOR_STATE_UNKNOWN", failure.Code);
        var receipt = store.Get(job.Binding.RequestId, fixture.Owner, fixture.Grant);
        Assert.Equal(DurableJobState.Interrupted, receipt.State);
        Assert.Equal("EXECUTOR_STATE_UNKNOWN", receipt.ResultCode);
        Assert.Equal(DurableJobState.Cancelled, store.Get(queued.Binding.RequestId, fixture.Owner, fixture.Grant).State);
        var refusal = await Assert.ThrowsAsync<JobRuntimeException>(() => runtime.SubmitAsync(fixture.Job(allowDisconnected: true)));
        Assert.Equal("JOB_EXECUTOR_STATE_UNKNOWN", refusal.Code);
        Assert.Equal(1, executor.Calls);
        var incident = store.GetRecoveryRequirement(); Assert.NotNull(incident);
        await runtime.DisposeAsync();
        Assert.Equal("JOB_EXECUTOR_STATE_UNKNOWN", Assert.Throws<JobRuntimeException>(() =>
            new DurableJobRuntime(store, new FixtureAuthority(), executor)).Code);
        store.Dispose();
        using var reopened = fixture.Open(); reopened.PruneExpiredData();
        Assert.Equal(incident, reopened.GetRecoveryRequirement());
        Assert.Equal("JOB_EXECUTOR_STATE_UNKNOWN", Assert.Throws<JobRuntimeException>(() =>
            new DurableJobRuntime(reopened, new FixtureAuthority(), executor)).Code);
        Assert.Equal(receipt, reopened.Get(job.Binding.RequestId, fixture.Owner, fixture.Grant));
    }
}
