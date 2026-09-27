using System.Text;
using Xunit;

namespace JTS.WindowsCompanion.Runtime.Tests;

public sealed class DurableJobLifecycleTests
{
    [Fact]
    public async Task DisconnectCancelsDefaultJobAndDrainsExecutorBeforeTerminalState()
    {
        using var fixture = new RuntimeFixture(); using var store = fixture.Open();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var stopped = false;
        var executor = new FixtureExecutor { Execute = async (_, _, _, token) =>
        {
            entered.SetResult();
            try { await Task.Delay(Timeout.InfiniteTimeSpan, token); }
            finally { stopped = true; }
            return new JobExecutionResult(true, "UNREACHABLE");
        } };
        await using var runtime = new DurableJobRuntime(store, new FixtureAuthority(), executor);
        runtime.SetOwnerConnected(fixture.Owner, true);
        var job = fixture.Job(); await runtime.SubmitAsync(job);
        var execution = runtime.RunNextAsync(); await entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
        runtime.SetOwnerConnected(fixture.Owner, false);
        await execution.WaitAsync(TimeSpan.FromSeconds(3));
        Assert.True(stopped);
        var receipt = store.Get(job.Binding.RequestId, fixture.Owner, fixture.Grant);
        Assert.Equal(DurableJobState.Cancelled, receipt.State); Assert.Equal("OWNER_DISCONNECTED", receipt.ResultCode);
    }

    [Fact]
    public async Task ExplicitDetachedJobSurvivesNetworkDisconnect()
    {
        using var fixture = new RuntimeFixture(); using var store = fixture.Open();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var executor = new FixtureExecutor { Execute = async (_, _, output, token) =>
        {
            entered.SetResult(); await release.Task.WaitAsync(token);
            await output.AppendAsync(Encoding.UTF8.GetBytes("result"), token);
            return new JobExecutionResult(true, "OK");
        } };
        await using var runtime = new DurableJobRuntime(store, new FixtureAuthority(), executor);
        runtime.SetOwnerConnected(fixture.Owner, true);
        var job = fixture.Job(allowDisconnected: true); await runtime.SubmitAsync(job);
        var execution = runtime.RunNextAsync(); await entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
        runtime.SetOwnerConnected(fixture.Owner, false);
        Assert.Equal(DurableJobState.Running, store.Get(job.Binding.RequestId, fixture.Owner, fixture.Grant).State);
        release.SetResult(); await execution.WaitAsync(TimeSpan.FromSeconds(3));
        Assert.Equal(DurableJobState.Succeeded, store.Get(job.Binding.RequestId, fixture.Owner, fixture.Grant).State);
    }

    [Fact]
    public async Task OnlineGrantRevocationCancelsDetachedRunningAndQueuedJobs()
    {
        using var fixture = new RuntimeFixture(); using var store = fixture.Open();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var executor = new FixtureExecutor { Execute = async (_, _, _, token) =>
        {
            entered.TrySetResult(); await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return new JobExecutionResult(true, "UNREACHABLE");
        } };
        var authority = new FixtureAuthority();
        await using var runtime = new DurableJobRuntime(store, authority, executor);
        var first = fixture.Job(allowDisconnected: true); var second = fixture.Job(allowDisconnected: true);
        await runtime.SubmitAsync(first);
        var execution = runtime.RunNextAsync(); await entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
        await runtime.SubmitAsync(second);
        authority.Allowed = false; runtime.RevokeGrant(fixture.Owner, fixture.Grant);
        await execution.WaitAsync(TimeSpan.FromSeconds(3));
        Assert.Equal(DurableJobState.Cancelled, store.Get(first.Binding.RequestId, fixture.Owner, fixture.Grant).State);
        Assert.Equal(DurableJobState.Cancelled, store.Get(second.Binding.RequestId, fixture.Owner, fixture.Grant).State);
        Assert.False(await runtime.RunNextAsync()); Assert.Equal(1, executor.Calls);
        await Assert.ThrowsAsync<JobRuntimeException>(() => runtime.SubmitAsync(fixture.Job(allowDisconnected: true)));
    }

    [Fact]
    public async Task DeadlineCancelsExecutionWithoutReportingSuccess()
    {
        using var fixture = new RuntimeFixture(); using var store = fixture.Open();
        var executor = new FixtureExecutor { Execute = async (_, _, _, token) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, token); return new JobExecutionResult(true, "UNREACHABLE");
        } };
        await using var runtime = new DurableJobRuntime(store, new FixtureAuthority(), executor);
        var job = fixture.Job(allowDisconnected: true, deadline: DateTimeOffset.UtcNow.AddMilliseconds(200));
        await runtime.SubmitAsync(job); await runtime.RunNextAsync().WaitAsync(TimeSpan.FromSeconds(3));
        Assert.Equal(DurableJobState.Expired, store.Get(job.Binding.RequestId, fixture.Owner, fixture.Grant).State);
    }

    [Fact]
    public async Task OutputLimitCancelsExecutorEvenIfItCatchesSinkFailure()
    {
        using var fixture = new RuntimeFixture();
        using var store = fixture.Open(new DurableJobLimits { MaximumOutputBytesPerJob = 3 });
        var tokenCancelled = false;
        var executor = new FixtureExecutor { Execute = async (_, _, output, token) =>
        {
            try { await output.AppendAsync(new byte[4], token); }
            catch (JobRuntimeException) { }
            tokenCancelled = token.IsCancellationRequested;
            return new JobExecutionResult(true, "NOT_SUCCESS");
        } };
        await using var runtime = new DurableJobRuntime(store, new FixtureAuthority(), executor);
        var job = fixture.Job(allowDisconnected: true); await runtime.SubmitAsync(job); await runtime.RunNextAsync();
        Assert.True(tokenCancelled);
        var receipt = store.Get(job.Binding.RequestId, fixture.Owner, fixture.Grant);
        Assert.Equal(DurableJobState.Failed, receipt.State); Assert.Equal("JOB_OUTPUT_LIMIT", receipt.ResultCode);
        Assert.Equal(0, receipt.OutputBytes);
    }

    [Fact]
    public async Task QueueAndReceiptCapacityDoNotDeleteIdempotencyHistory()
    {
        using var fixture = new RuntimeFixture();
        using var store = fixture.Open(new DurableJobLimits { MaximumQueuedJobs = 1, MaximumReceiptCount = 1 });
        await using var runtime = new DurableJobRuntime(store, new FixtureAuthority(), new FixtureExecutor());
        var job = fixture.Job(allowDisconnected: true); await runtime.SubmitAsync(job);
        await Assert.ThrowsAsync<JobRuntimeException>(() => runtime.SubmitAsync(fixture.Job(allowDisconnected: true)));
        await runtime.RunNextAsync();
        var error = await Assert.ThrowsAsync<JobRuntimeException>(() => runtime.SubmitAsync(fixture.Job(allowDisconnected: true)));
        Assert.Equal("JOB_RECEIPT_CAPACITY", error.Code);
        Assert.Equal(DurableJobState.Succeeded, (await runtime.SubmitAsync(job)).State);
    }

    [Fact]
    public async Task DeadlineBeyond24HoursAndOversizedPayloadAreRejected()
    {
        using var fixture = new RuntimeFixture(); using var store = fixture.Open();
        await using var runtime = new DurableJobRuntime(store, new FixtureAuthority(), new FixtureExecutor());
        await Assert.ThrowsAsync<JobRuntimeException>(() => runtime.SubmitAsync(fixture.Job(allowDisconnected: true, deadline: DateTimeOffset.UtcNow.AddHours(25))));
        await Assert.ThrowsAsync<JobRuntimeException>(() => runtime.SubmitAsync(fixture.Job(allowDisconnected: true, payload: new string('x', 65_537))));
    }

    [Fact]
    public async Task DefaultJobRequiresLiveAuthenticatedOwner()
    {
        using var fixture = new RuntimeFixture(); using var store = fixture.Open();
        await using var runtime = new DurableJobRuntime(store, new FixtureAuthority(), new FixtureExecutor());
        var error = await Assert.ThrowsAsync<JobRuntimeException>(() => runtime.SubmitAsync(fixture.Job()));
        Assert.Equal("JOB_OWNER_OFFLINE", error.Code);
    }

    [Fact]
    public async Task OnlyOneRuntimeMayAttachToStore()
    {
        using var fixture = new RuntimeFixture(); using var store = fixture.Open();
        await using var runtime = new DurableJobRuntime(store, new FixtureAuthority(), new FixtureExecutor());
        Assert.Throws<JobRuntimeException>(() => new DurableJobRuntime(store, new FixtureAuthority(), new FixtureExecutor()));
    }

    [Fact]
    public async Task RevocationBetweenAuthorityCheckAndDispatchPreventsExecution()
    {
        using var fixture = new RuntimeFixture(); using var store = fixture.Open();
        var authority = new PausingAuthority(pauseAtCall: 2);
        var executor = new FixtureExecutor();
        await using var runtime = new DurableJobRuntime(store, authority, executor);
        var job = fixture.Job(allowDisconnected: true); await runtime.SubmitAsync(job);
        var execution = runtime.RunNextAsync();
        await authority.Entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
        runtime.RevokeGrant(fixture.Owner, fixture.Grant);
        authority.Release.SetResult(); await execution.WaitAsync(TimeSpan.FromSeconds(3));
        Assert.Equal(0, executor.Calls);
        Assert.Equal(DurableJobState.Cancelled, store.Get(job.Binding.RequestId, fixture.Owner, fixture.Grant).State);
    }

    [Fact]
    public async Task SubmissionSnapshotsCallerPayloadBeforeAwaitingAuthority()
    {
        using var fixture = new RuntimeFixture(); using var store = fixture.Open();
        var authority = new PausingAuthority(pauseAtCall: 1);
        await using var runtime = new DurableJobRuntime(store, authority, new FixtureExecutor());
        var buffer = Encoding.UTF8.GetBytes("original");
        var job = new JobSubmission(Guid.NewGuid(), "fixture.exec", fixture.Owner, fixture.Grant,
            DateTimeOffset.UtcNow.AddMinutes(1), buffer, allowDisconnected: true);
        var submit = runtime.SubmitAsync(job); await authority.Entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
        Array.Fill<byte>(buffer, (byte)'x'); authority.Release.SetResult(); await submit;
        Assert.Equal("original", Encoding.UTF8.GetString(store.ReadPayload(job.Binding)));
    }

    [Fact]
    public async Task QueueCapacityIsEnforcedSeparatelyFromHistoryCapacity()
    {
        using var fixture = new RuntimeFixture();
        using var store = fixture.Open(new DurableJobLimits { MaximumQueuedJobs = 1, MaximumReceiptCount = 8 });
        await using var runtime = new DurableJobRuntime(store, new FixtureAuthority(), new FixtureExecutor());
        await runtime.SubmitAsync(fixture.Job(allowDisconnected: true));
        var error = await Assert.ThrowsAsync<JobRuntimeException>(() => runtime.SubmitAsync(fixture.Job(allowDisconnected: true)));
        Assert.Equal("JOB_QUEUE_FULL", error.Code);
        await runtime.RunNextAsync();
        Assert.Equal(DurableJobState.Queued, (await runtime.SubmitAsync(fixture.Job(allowDisconnected: true))).State);
    }

    [Fact]
    public void DpapiNeverFallsBackToPlaintextOnNonWindows()
    {
        if (!OperatingSystem.IsWindows()) Assert.Throws<PlatformNotSupportedException>(() => new CurrentUserDpapiTaskProtector());
        else
        {
            var protector = new CurrentUserDpapiTaskProtector();
            var clear = Encoding.UTF8.GetBytes("Windows DPAPI runtime fixture");
            var cipher = protector.Protect(clear, "test-context"u8);
            Assert.NotEqual(clear, cipher); Assert.Equal(clear, protector.Unprotect(cipher, "test-context"u8));
            Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(() => protector.Unprotect(cipher, "wrong-context"u8));
        }
    }

    private sealed class PausingAuthority(int pauseAtCall) : IJobGrantAuthority
    {
        private int _calls;
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async ValueTask<bool> CanExecuteAsync(JobBinding binding, CancellationToken cancellationToken)
        {
            if (Interlocked.Increment(ref _calls) == pauseAtCall)
            {
                Entered.SetResult(); await Release.Task.WaitAsync(cancellationToken);
            }
            return true;
        }
    }
}
