using Microsoft.Data.Sqlite;
using Xunit;

namespace JTS.WindowsCompanion.Runtime.Tests;

public sealed class RuntimeSafetyFailureTests
{
    private const string FailGuardWrite = """
        CREATE TRIGGER reject_guard_write BEFORE UPDATE ON job_runtime_safety BEGIN
          SELECT RAISE(ABORT, 'fixture write failure');
        END;
        """;

    [Fact]
    public async Task GuardMustCommitBeforeExecutorCanRun()
    {
        using var f = new RuntimeFixture(); using var store = f.Open();
        var executor = new FixtureExecutor();
        await using var runtime = new DurableJobRuntime(store, new FixtureAuthority(), executor);
        var job = f.Job(allowDisconnected: true); await runtime.SubmitAsync(job);
        SafetyFixture.Sql(f, FailGuardWrite);
        await Assert.ThrowsAsync<SqliteException>(() => runtime.RunNextAsync());
        Assert.Equal(0, executor.Calls);
        Assert.Equal(DurableJobState.Queued, store.Get(job.Binding.RequestId, f.Owner, f.Grant).State);
        Assert.Null(store.GetRecoveryRequirement());
        SafetyFixture.Sql(f, "DROP TRIGGER reject_guard_write;");
    }

    [Fact]
    public async Task FailedQuarantineWriteStillLeavesPriorDispatchMarkerDurable()
    {
        using var f = new RuntimeFixture(); using var store = f.Open();
        var executor = new FixtureExecutor { Execute = (_, _, _, _) =>
        {
            SafetyFixture.Sql(f, FailGuardWrite);
            throw new JobExecutionStateUnknownException();
        } };
        await using var runtime = new DurableJobRuntime(store, new FixtureAuthority(), executor);
        var job = f.Job(allowDisconnected: true); await runtime.SubmitAsync(job);
        await Assert.ThrowsAsync<SqliteException>(() => runtime.RunNextAsync());
        Assert.Equal("JOB_EXECUTOR_STATE_UNKNOWN", (await Assert.ThrowsAsync<JobRuntimeException>(() =>
            runtime.SubmitAsync(f.Job(allowDisconnected: true)))).Code);
        await runtime.DisposeAsync(); store.Dispose();
        SafetyFixture.Sql(f, "DROP TRIGGER reject_guard_write;");
        using var reopened = f.Open();
        Assert.Equal(job.Binding.RequestId, reopened.GetRecoveryRequirement()!.RequestId);
        Assert.Equal(DurableJobState.Interrupted, reopened.Get(job.Binding.RequestId, f.Owner, f.Grant).State);
        Assert.Throws<JobRuntimeException>(() => new DurableJobRuntime(reopened, new FixtureAuthority(), executor));
        Assert.Equal(1, executor.Calls);
    }

    [Fact]
    public async Task ShutdownTimeoutPersistsQuarantineEvenIfExecutorEventuallyReturnsSuccess()
    {
        using var f = new RuntimeFixture(); using var store = f.Open();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var executor = new FixtureExecutor { Execute = async (_, _, _, _) =>
        { entered.SetResult(); await release.Task; return new(true, "OK"); } };
        var runtime = new DurableJobRuntime(store, new FixtureAuthority(), executor);
        var job = f.Job(allowDisconnected: true); await runtime.SubmitAsync(job);
        var run = runtime.RunNextAsync(); await entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
        try
        {
            Assert.Equal("JOB_EXECUTOR_DID_NOT_STOP", (await Assert.ThrowsAsync<JobRuntimeException>(() => runtime.DisposeAsync().AsTask())).Code);
            Assert.Equal("EXECUTOR_DID_NOT_STOP", store.GetRecoveryRequirement()!.Reason);
            Assert.Equal("JOB_RUNTIME_STILL_ATTACHED", Assert.Throws<JobRuntimeException>(store.Dispose).Code);
        }
        finally { release.TrySetResult(); await run; await runtime.DisposeAsync(); }
        Assert.Equal(DurableJobState.Interrupted, store.Get(job.Binding.RequestId, f.Owner, f.Grant).State);
        Assert.NotNull(store.GetRecoveryRequirement()); store.Dispose();
        using var reopened = f.Open(); Assert.NotNull(reopened.GetRecoveryRequirement());
    }
}
