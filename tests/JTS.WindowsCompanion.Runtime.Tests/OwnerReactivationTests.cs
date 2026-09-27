using Xunit;

namespace JTS.WindowsCompanion.Runtime.Tests;

public sealed class OwnerReactivationTests
{
    [Fact]
    public async Task ReactivationWaitsForTheOldExecutorAndAdmitsOnlyNewGrants()
    {
        using var f = new RuntimeFixture(); using var store = f.Open();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var executor = new FixtureExecutor { Execute = async (binding, _, _, _) =>
        {
            if (binding.GrantId == f.Grant) { started.SetResult(); await release.Task; }
            return new(true, "OK");
        } };
        await using var runtime = new DurableJobRuntime(store, new FixtureAuthority(), executor);
        var oldJob = f.Job(allowDisconnected: true); await runtime.SubmitAsync(oldJob);
        var running = runtime.RunNextAsync(); await started.Task.WaitAsync(TimeSpan.FromSeconds(3));
        runtime.RevokeOwner(f.Owner); var newGrant = Guid.NewGuid();
        var activation = runtime.ActivateOwnerGrantsAsync(f.Owner, [newGrant]).AsTask();
        Assert.False(activation.IsCompleted);
        release.SetResult(); await running; await activation;
        await Assert.ThrowsAsync<JobRuntimeException>(() => runtime.SubmitAsync(f.Job(allowDisconnected: true)));
        var newJob = new JobSubmission(Guid.NewGuid(), "fixture.exec", f.Owner, newGrant,
            DateTimeOffset.UtcNow.AddMinutes(1), "fresh"u8.ToArray(), true);
        await runtime.SubmitAsync(newJob); await runtime.RunNextAsync();
        Assert.Equal(DurableJobState.Succeeded, store.Get(newJob.Binding.RequestId, f.Owner, newGrant).State);
        Assert.Equal(DurableJobState.Cancelled, store.Get(oldJob.Binding.RequestId, f.Owner, f.Grant).State);
        runtime.RevokeOwner(f.Owner);
        await Assert.ThrowsAsync<JobRuntimeException>(() => runtime.SubmitAsync(new JobSubmission(Guid.NewGuid(), "fixture.exec", f.Owner,
            newGrant, DateTimeOffset.UtcNow.AddMinutes(1), "new"u8.ToArray(), true)));
    }

    [Fact]
    public async Task ExplicitGrantTombstoneCannotBeReadmitted()
    {
        using var f = new RuntimeFixture(); using var store = f.Open();
        await using var runtime = new DurableJobRuntime(store, new FixtureAuthority(), new FixtureExecutor());
        runtime.RevokeOwner(f.Owner); runtime.RevokeGrant(f.Owner, f.Grant);
        Assert.Equal("JOB_REBIND_REJECTED", (await Assert.ThrowsAsync<JobRuntimeException>(() =>
            runtime.ActivateOwnerGrantsAsync(f.Owner, [f.Grant]).AsTask())).Code);
    }
}
