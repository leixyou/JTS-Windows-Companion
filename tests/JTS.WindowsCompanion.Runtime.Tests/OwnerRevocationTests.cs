using Xunit;

namespace JTS.WindowsCompanion.Runtime.Tests;

public sealed class OwnerRevocationTests
{
    [Fact]
    public async Task PairingRevocationCancelsDetachedOwnerButPreservesOtherOwner()
    {
        using var f = new RuntimeFixture(); using var store = f.Open();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var executor = new FixtureExecutor { Execute = async (binding, _, _, token) =>
        {
            if (binding.OwnerDeviceId == f.Owner) { started.SetResult(); await Task.Delay(Timeout.Infinite, token); }
            return new(true, "OK");
        } };
        await using var runtime = new DurableJobRuntime(store, new FixtureAuthority(), executor);
        var first = f.Job(allowDisconnected: true); await runtime.SubmitAsync(first);
        var run = runtime.RunNextAsync(); await started.Task.WaitAsync(TimeSpan.FromSeconds(3));
        var queued = f.Job(allowDisconnected: true); await runtime.SubmitAsync(queued);
        var other = new JobSubmission(Guid.NewGuid(), "fixture.exec", new string('b', 64), Guid.NewGuid(),
            DateTimeOffset.UtcNow.AddMinutes(1), "fixture"u8.ToArray(), true);
        await runtime.SubmitAsync(other); runtime.RevokeOwner(f.Owner); await run;
        Assert.Equal("PAIRING_REVOKED", store.Get(first.Binding.RequestId, f.Owner, f.Grant).ResultCode);
        Assert.Equal(DurableJobState.Cancelled, store.Get(queued.Binding.RequestId, f.Owner, f.Grant).State);
        Assert.True(await runtime.RunNextAsync());
        Assert.Equal(DurableJobState.Succeeded, store.Get(other.Binding.RequestId, other.Binding.OwnerDeviceId, other.Binding.GrantId).State);
        await Assert.ThrowsAsync<JobRuntimeException>(() => runtime.SubmitAsync(f.Job(allowDisconnected: true)));
    }

    [Fact]
    public async Task OwnerRevocationDuringFreshAuthorityCheckCannotRaceDispatch()
    {
        using var f = new RuntimeFixture(); using var store = f.Open();
        var authority = new PausingAuthority(); var executor = new FixtureExecutor();
        await using var runtime = new DurableJobRuntime(store, authority, executor);
        var job = f.Job(allowDisconnected: true); await runtime.SubmitAsync(job);
        var run = runtime.RunNextAsync(); await authority.Entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
        runtime.RevokeOwner(f.Owner); authority.Release.SetResult(); await run;
        Assert.Equal(0, executor.Calls); Assert.Equal(DurableJobState.Cancelled, store.Get(job.Binding.RequestId, f.Owner, f.Grant).State);
    }

    [Fact]
    public async Task OwnerRevocationCapacityFailsClosedWithoutEvictingOldDenials()
    {
        using var f = new RuntimeFixture(); using var store = f.Open(new() { MaximumRememberedRevocations = 1 });
        await using var runtime = new DurableJobRuntime(store, new FixtureAuthority(), new FixtureExecutor());
        var job = f.Job(allowDisconnected: true); await runtime.SubmitAsync(job);
        runtime.RevokeOwner(new string('b', 64));
        Assert.Equal("JOB_AUTHORIZATION_CAPACITY", Assert.Throws<JobRuntimeException>(() => runtime.RevokeOwner(f.Owner)).Code);
        Assert.Equal(DurableJobState.Cancelled, store.Get(job.Binding.RequestId, f.Owner, f.Grant).State);
        await Assert.ThrowsAsync<JobRuntimeException>(() => runtime.RunNextAsync());
    }

    private sealed class PausingAuthority : IJobGrantAuthority
    {
        private int _calls;
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async ValueTask<bool> CanExecuteAsync(JobBinding binding, CancellationToken token)
        {
            if (++_calls == 2) { Entered.SetResult(); await Release.Task.WaitAsync(token); }
            return true;
        }
    }
}
