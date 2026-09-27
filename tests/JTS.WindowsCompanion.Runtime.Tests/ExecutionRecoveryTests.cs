using Xunit;

namespace JTS.WindowsCompanion.Runtime.Tests;

public sealed class ExecutionRecoveryTests
{
    [Fact]
    public async Task VerifiedLocalRecoveryDoesNotReplayInterruptedJobAndCannotApproveNextIncident()
    {
        using var f = new RuntimeFixture(); using var store = f.Open();
        var job = SafetyFixture.Interrupt(store, f); var incident = store.GetRecoveryRequirement()!;
        var verifier = new Verifier((seen, _) => { Assert.Equal(incident, seen); return ValueTask.FromResult(true); });
        await store.ConfirmExecutionRecoveryAsync(incident.IncidentId, verifier);
        Assert.Null(store.GetRecoveryRequirement());
        var executor = new FixtureExecutor();
        await using (var runtime = new DurableJobRuntime(store, new FixtureAuthority(), executor))
        {
            Assert.Equal(DurableJobState.Interrupted, (await runtime.SubmitAsync(job)).State);
            Assert.False(await runtime.RunNextAsync()); Assert.Equal(0, executor.Calls);
            await runtime.SubmitAsync(f.Job(allowDisconnected: true)); Assert.True(await runtime.RunNextAsync());
            Assert.Equal(1, executor.Calls);
        }
        SafetyFixture.Interrupt(store, f);
        Assert.NotEqual(incident.IncidentId, store.GetRecoveryRequirement()!.IncidentId);
        Assert.Equal("JOB_RECOVERY_INCIDENT_MISMATCH", (await Assert.ThrowsAsync<JobRuntimeException>(() =>
            store.ConfirmExecutionRecoveryAsync(incident.IncidentId, verifier).AsTask())).Code);
        Assert.Equal(1, verifier.Calls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FailedOrCancelledVerificationDoesNotClearPersistentQuarantine(bool cancelled)
    {
        using var f = new RuntimeFixture(); using var store = f.Open(); SafetyFixture.Interrupt(store, f);
        var incident = store.GetRecoveryRequirement()!;
        using var caller = new CancellationTokenSource();
        var verifier = new Verifier((_, _) => { if (cancelled) caller.Cancel(); return ValueTask.FromResult(cancelled); });
        if (cancelled) await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            store.ConfirmExecutionRecoveryAsync(incident.IncidentId, verifier, caller.Token).AsTask());
        else Assert.Equal("JOB_RECOVERY_NOT_CONFIRMED", (await Assert.ThrowsAsync<JobRuntimeException>(() =>
            store.ConfirmExecutionRecoveryAsync(incident.IncidentId, verifier).AsTask())).Code);
        Assert.Equal(incident, store.GetRecoveryRequirement());
        store.Dispose(); using var reopened = f.Open(); Assert.Equal(incident, reopened.GetRecoveryRequirement());
    }

    [Fact]
    public async Task RecoveryFencesRuntimeAttachmentDisposalAndConcurrentApproval()
    {
        using var f = new RuntimeFixture(); using var store = f.Open(); SafetyFixture.Interrupt(store, f);
        var incident = store.GetRecoveryRequirement()!;
        var result = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var verifier = new Verifier((_, _) => new(result.Task));
        var recovering = store.ConfirmExecutionRecoveryAsync(incident.IncidentId, verifier).AsTask();
        try
        {
            Assert.Equal("JOB_RECOVERY_IN_PROGRESS", Assert.Throws<JobRuntimeException>(() =>
                new DurableJobRuntime(store, new FixtureAuthority(), new FixtureExecutor())).Code);
            Assert.Equal("JOB_RECOVERY_IN_PROGRESS", Assert.Throws<JobRuntimeException>(store.Dispose).Code);
            Assert.Equal("JOB_RECOVERY_IN_PROGRESS", (await Assert.ThrowsAsync<JobRuntimeException>(() =>
                store.ConfirmExecutionRecoveryAsync(incident.IncidentId, verifier).AsTask())).Code);
        }
        finally { result.TrySetResult(true); await recovering; }
        Assert.Null(store.GetRecoveryRequirement());
    }

    [Fact]
    public async Task TimedOutVerifierCannotClearQuarantineWhenItsLateResultArrives()
    {
        using var f = new RuntimeFixture(); using var store = f.Open(); SafetyFixture.Interrupt(store, f);
        var incident = store.GetRecoveryRequirement()!;
        var result = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        CancellationToken verifierToken = default;
        var verifier = new Verifier((_, token) => { verifierToken = token; return new(result.Task); });
        var error = await Assert.ThrowsAsync<JobRuntimeException>(() => store.ConfirmExecutionRecoveryAsync(incident.IncidentId, verifier).AsTask());
        Assert.Equal("JOB_RECOVERY_TIMED_OUT", error.Code); Assert.True(verifierToken.IsCancellationRequested);
        result.SetResult(true); Assert.Equal(incident, store.GetRecoveryRequirement());
        store.Dispose(); using var reopened = f.Open(); Assert.Equal(incident, reopened.GetRecoveryRequirement());
    }

    [Fact]
    public async Task ChangedProtectedIncidentCannotUseAlreadyPendingApproval()
    {
        using var f = new RuntimeFixture(); using var store = f.Open(); SafetyFixture.Interrupt(store, f);
        var incident = store.GetRecoveryRequirement()!;
        var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        var verification = store.ConfirmExecutionRecoveryAsync(incident.IncidentId, new Verifier((_, _) => new(release.Task))).AsTask();
        var changed = RuntimeSafetyCodec.Seal(new(incident.StoreId, RuntimeSafetyState.Quarantined, Guid.NewGuid(),
            incident.RequestId, incident.Reason, incident.RecordedAt.ToUnixTimeMilliseconds()), f.Protector);
        SafetyFixture.ReplaceGuard(f, changed); release.SetResult(true);
        Assert.Equal("JOB_RECOVERY_INCIDENT_MISMATCH", (await Assert.ThrowsAsync<JobRuntimeException>(() => verification)).Code);
        Assert.NotEqual(incident.IncidentId, store.GetRecoveryRequirement()!.IncidentId);
    }

    private sealed class Verifier(Func<ExecutionRecoveryRequirement, CancellationToken, ValueTask<bool>> verify) : IJobRecoveryVerifier
    {
        internal int Calls { get; private set; }
        public ValueTask<bool> VerifyStoppedAsync(ExecutionRecoveryRequirement incident, CancellationToken cancellationToken)
        { Calls++; return verify(incident, cancellationToken); }
    }
}
