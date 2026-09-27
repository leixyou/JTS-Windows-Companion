using System.Text;
using Xunit;

namespace JTS.WindowsCompanion.Runtime.Tests;

public sealed class DurableJobBoundaryTests
{
    [Theory]
    [InlineData("kind")]
    [InlineData("owner")]
    [InlineData("request")]
    [InlineData("grant")]
    [InlineData("expired")]
    [InlineData("future")]
    public async Task InvalidBindingsNeverReachGrantAuthority(string invalid)
    {
        using var fixture = new RuntimeFixture(); using var store = fixture.Open();
        var authority = new FixtureAuthority();
        await using var runtime = new DurableJobRuntime(store, authority, new FixtureExecutor());
        var job = new JobSubmission(invalid == "request" ? Guid.Empty : Guid.NewGuid(),
            invalid == "kind" ? "invalid/kind" : "fixture.exec",
            invalid == "owner" ? "not-a-device" : fixture.Owner,
            invalid == "grant" ? Guid.Empty : fixture.Grant,
            DateTimeOffset.UtcNow.AddHours(invalid == "expired" ? -1 : invalid == "future" ? 25 : 1),
            "fixture"u8.ToArray(), allowDisconnected: true);
        var error = await Assert.ThrowsAsync<JobRuntimeException>(() => runtime.SubmitAsync(job));
        Assert.Equal("JOB_REQUEST_INVALID", error.Code); Assert.Equal(0, authority.Calls);
    }

    [Fact]
    public async Task PresenceCapacityRejectsNewOwnerWithoutEvictingExistingOwner()
    {
        using var fixture = new RuntimeFixture();
        using var store = fixture.Open(new DurableJobLimits { MaximumConnectedOwners = 1 });
        await using var runtime = new DurableJobRuntime(store, new FixtureAuthority(), new FixtureExecutor());
        runtime.SetOwnerConnected(fixture.Owner, true); runtime.SetOwnerConnected(fixture.Owner, true);
        var error = Assert.Throws<JobRuntimeException>(() => runtime.SetOwnerConnected(new string('b', 64), true));
        Assert.Equal("JOB_PRESENCE_CAPACITY", error.Code);
        Assert.Equal(DurableJobState.Queued, (await runtime.SubmitAsync(fixture.Job())).State);
        runtime.SetOwnerConnected(fixture.Owner, false);
        runtime.SetOwnerConnected(new string('b', 64), true);
    }

    [Fact]
    public async Task RevocationCapacityCancelsAllOwnersAndPermanentlyFailsClosed()
    {
        using var fixture = new RuntimeFixture();
        using var store = fixture.Open(new DurableJobLimits { MaximumRememberedRevocations = 1 });
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var drained = false;
        var executor = new FixtureExecutor { Execute = async (_, _, _, token) =>
        {
            entered.SetResult();
            try { await Task.Delay(Timeout.InfiniteTimeSpan, token); }
            finally { drained = true; }
            return new JobExecutionResult(true, "UNREACHABLE");
        } };
        var authority = new FixtureAuthority();
        await using var runtime = new DurableJobRuntime(store, authority, executor);
        var first = fixture.Job(allowDisconnected: true);
        var second = new JobSubmission(Guid.NewGuid(), "fixture.exec", new string('b', 64), Guid.NewGuid(),
            DateTimeOffset.UtcNow.AddMinutes(1), "fixture"u8.ToArray(), allowDisconnected: true);
        await runtime.SubmitAsync(first);
        var execution = runtime.RunNextAsync(); await entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
        await runtime.SubmitAsync(second);
        var otherGrant = Guid.NewGuid(); runtime.RevokeGrant(fixture.Owner, otherGrant);
        runtime.RevokeGrant(fixture.Owner, otherGrant); // Repeated revocation consumes no capacity.
        var error = Assert.Throws<JobRuntimeException>(() => runtime.RevokeGrant(fixture.Owner, fixture.Grant));
        Assert.Equal("JOB_AUTHORIZATION_CAPACITY", error.Code);
        await execution.WaitAsync(TimeSpan.FromSeconds(3)); Assert.True(drained);
        foreach (var binding in new[] { first.Binding, second.Binding })
        {
            var snapshot = store.Get(binding.RequestId, binding.OwnerDeviceId, binding.GrantId);
            Assert.Equal(DurableJobState.Cancelled, snapshot.State);
            Assert.Equal("AUTHORIZATION_CACHE_CAPACITY", snapshot.ResultCode);
        }
        var calls = authority.Calls;
        error = await Assert.ThrowsAsync<JobRuntimeException>(() => runtime.SubmitAsync(fixture.Job(allowDisconnected: true)));
        Assert.Equal("JOB_AUTHORIZATION_CAPACITY", error.Code); Assert.Equal(calls, authority.Calls);
        await Assert.ThrowsAsync<JobRuntimeException>(() => runtime.RunNextAsync());
        Assert.Equal(1, executor.Calls);
    }

    [Fact]
    public async Task RevocationDuringSubmissionAuthorityCheckPreventsInsert()
    {
        using var fixture = new RuntimeFixture(); using var store = fixture.Open();
        var authority = new PausingAuthority();
        await using var runtime = new DurableJobRuntime(store, authority, new FixtureExecutor());
        var job = fixture.Job(allowDisconnected: true);
        var submission = runtime.SubmitAsync(job); await authority.Entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
        runtime.RevokeGrant(fixture.Owner, fixture.Grant); authority.Release.SetResult();
        var error = await Assert.ThrowsAsync<JobRuntimeException>(() => submission);
        Assert.Equal("JOB_GRANT_REJECTED", error.Code);
        Assert.Throws<JobRuntimeException>(() => store.Get(job.Binding.RequestId, fixture.Owner, fixture.Grant));
    }

    [Fact]
    public async Task LateExecutorResultCannotSucceedWhenDeadlineTimerHasNotFired()
    {
        using var fixture = new RuntimeFixture(); var clock = new FixtureClock(DateTimeOffset.UtcNow);
        using var store = fixture.Open(clock: clock);
        var executor = new FixtureExecutor { Execute = (_, _, _, _) =>
        {
            clock.Advance(TimeSpan.FromMinutes(2));
            return ValueTask.FromResult(new JobExecutionResult(true, "LATE_SUCCESS"));
        } };
        await using var runtime = new DurableJobRuntime(store, new FixtureAuthority(), executor, clock);
        var job = fixture.Job(allowDisconnected: true); await runtime.SubmitAsync(job); await runtime.RunNextAsync();
        var receipt = store.Get(job.Binding.RequestId, fixture.Owner, fixture.Grant);
        Assert.Equal(DurableJobState.Expired, receipt.State); Assert.Equal("DEADLINE_EXPIRED", receipt.ResultCode);
    }

    [Fact]
    public async Task OutputAfterDeadlineIsRejectedWithoutWaitingForTimer()
    {
        using var fixture = new RuntimeFixture(); var clock = new FixtureClock(DateTimeOffset.UtcNow);
        using var store = fixture.Open(clock: clock);
        var executor = new FixtureExecutor { Execute = async (_, _, output, token) =>
        {
            clock.Advance(TimeSpan.FromMinutes(2));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await output.AppendAsync(Encoding.UTF8.GetBytes("late"), token));
            return new JobExecutionResult(true, "LATE_SUCCESS");
        } };
        await using var runtime = new DurableJobRuntime(store, new FixtureAuthority(), executor, clock);
        var job = fixture.Job(allowDisconnected: true); await runtime.SubmitAsync(job); await runtime.RunNextAsync();
        var receipt = store.Get(job.Binding.RequestId, fixture.Owner, fixture.Grant);
        Assert.Equal(DurableJobState.Expired, receipt.State); Assert.Equal(0, receipt.OutputBytes);
    }

    private sealed class PausingAuthority : IJobGrantAuthority
    {
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async ValueTask<bool> CanExecuteAsync(JobBinding binding, CancellationToken cancellationToken)
        {
            Entered.SetResult(); await Release.Task.WaitAsync(cancellationToken); return true;
        }
    }
}
