using Xunit;

namespace JTS.WindowsCompanion.AuthorityService.Tests;

public sealed class LifetimeTests
{
    [Fact]
    public async Task StopDrainsBeforeReportingStoppedAndCannotStartTwice()
    {
        var states = new List<AuthorityStatus>(); using var stop = new CancellationTokenSource();
        var runtime = new FakeRuntime(); var drained = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        runtime.Drain = async () => { runtime.Draining.TrySetResult(); await drained.Task; };
        var lifetime = new AuthorityLifetime(states.Add);
        var run = lifetime.RunAsync(_ => runtime, stop.Token);
        await runtime.Started.Task.WaitAsync(TimeSpan.FromSeconds(2)); stop.Cancel();
        await runtime.Draining.Task.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.DoesNotContain(states, s => s.Phase == AuthorityPhase.Stopped); drained.SetResult();
        Assert.Equal(0, await run.WaitAsync(TimeSpan.FromSeconds(2)));
        Assert.Equal(new[] { AuthorityPhase.Starting, AuthorityPhase.Running, AuthorityPhase.Stopping, AuthorityPhase.Stopped }, states.Select(s => s.Phase));
        Assert.Equal(1, runtime.Disposals);
        await Assert.ThrowsAsync<AuthorityException>(() => lifetime.RunAsync(_ => runtime, CancellationToken.None));
    }
    [Fact]
    public async Task CancelBeforeOpenDoesNotConstructRuntime()
    {
        using var stop = new CancellationTokenSource(); stop.Cancel(); var constructed = false;
        Assert.Equal(0, await new AuthorityLifetime(_ => { }).RunAsync(_ => { constructed = true; return new FakeRuntime(); }, stop.Token));
        Assert.False(constructed);
    }
    [Fact]
    public async Task CancelDuringOpenClosesResourcesWithoutStartingNetworking()
    {
        using var stop = new CancellationTokenSource(); var runtime = new FakeRuntime();
        var result = await new AuthorityLifetime(_ => { }).RunAsync(_ => { stop.Cancel(); return runtime; }, stop.Token);
        Assert.Equal(0, result); Assert.False(runtime.Started.Task.IsCompleted); Assert.Equal(1, runtime.Disposals);
    }
    [Fact]
    public async Task InitializationFailureNeverReportsRunning()
    {
        var states = new List<AuthorityStatus>();
        Assert.Equal(70, await new AuthorityLifetime(states.Add).RunAsync(_ => throw new IOException("untrusted message"), CancellationToken.None));
        Assert.DoesNotContain(states, s => s.Phase == AuthorityPhase.Running); Assert.Equal(70, states[^1].ExitCode);
    }
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RuntimeFaultOrUnexpectedCompletionStillDrainsAndReportsFailure(bool throwError)
    {
        var runtime = new FakeRuntime { Work = _ => throwError ? Task.FromException(new IOException()) : Task.CompletedTask };
        Assert.Equal(70, await new AuthorityLifetime(_ => { }).RunAsync(_ => runtime, CancellationToken.None));
        Assert.Equal(1, runtime.Disposals);
    }
    [Fact]
    public async Task ExpiringIdentityRefusesAdmissionButReleasesLoadedResources()
    {
        var runtime = new FakeRuntime { IdentityExpiresAt = DateTimeOffset.UtcNow.AddMinutes(1) };
        Assert.Equal(72, await new AuthorityLifetime(_ => { }).RunAsync(_ => runtime, CancellationToken.None));
        Assert.False(runtime.Started.Task.IsCompleted); Assert.Equal(1, runtime.Disposals);
    }
    [Fact]
    public async Task ClockAdvanceStopsLiveRouteBeforeCertificateExpiry()
    {
        var clock = new MutableClock(); var runtime = new FakeRuntime { IdentityExpiresAt = clock.GetUtcNow().AddHours(1) };
        var run = new AuthorityLifetime(_ => { }, clock, FastTiming).RunAsync(_ => runtime, CancellationToken.None);
        await runtime.Started.Task.WaitAsync(TimeSpan.FromSeconds(2)); clock.Advance();
        Assert.Equal(72, await run.WaitAsync(TimeSpan.FromSeconds(2))); Assert.Equal(1, runtime.Disposals);
    }
    [Fact]
    public async Task FailedExpiryWatcherStopsInsteadOfLeavingServiceRunning()
    {
        var clock = new MutableClock(); var runtime = new FakeRuntime { IdentityExpiresAt = clock.GetUtcNow().AddHours(1) };
        var run = new AuthorityLifetime(_ => { }, clock, FastTiming).RunAsync(_ => runtime, CancellationToken.None);
        await runtime.Started.Task.WaitAsync(TimeSpan.FromSeconds(2)); clock.Fail = true;
        Assert.Equal(70, await run.WaitAsync(TimeSpan.FromSeconds(2))); Assert.Equal(1, runtime.Disposals);
    }
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FailedOrTimedOutDrainCannotReportNormalStop(bool hang)
    {
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var runtime = new FakeRuntime { Work = _ => Task.CompletedTask,
            Drain = () => hang ? new ValueTask(release.Task) : ValueTask.FromException(new IOException()) };
        var states = new List<AuthorityStatus>();
        try
        {
            Assert.Equal(71, await new AuthorityLifetime(states.Add, timing: FastTiming).RunAsync(_ => runtime, CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(2)));
            Assert.Equal(71, states[^1].ExitCode);
        }
        finally { release.TrySetResult(); }
    }
    [Fact]
    public async Task StatusReportingFailureDoesNotSkipCleanup()
    {
        var runtime = new FakeRuntime();
        var result = await new AuthorityLifetime(s => { if (s.Phase == AuthorityPhase.Running) throw new IOException(); })
            .RunAsync(_ => runtime, CancellationToken.None);
        Assert.Equal(70, result); Assert.Equal(1, runtime.Disposals); Assert.False(runtime.Started.Task.IsCompleted);
    }
    internal static AuthorityTiming FastTiming { get; } = new(TimeSpan.FromMinutes(2), TimeSpan.FromMilliseconds(5), TimeSpan.FromMilliseconds(50));
    private sealed class MutableClock : TimeProvider
    {
        private long _advance; internal volatile bool Fail;
        public override DateTimeOffset GetUtcNow() => Fail ? throw new IOException() : DateTimeOffset.UtcNow.AddHours(Interlocked.Read(ref _advance));
        internal void Advance() => Interlocked.Exchange(ref _advance, 2);
    }
    private sealed class FakeRuntime : IAuthorityRuntime
    {
        public DateTimeOffset IdentityExpiresAt { get; init; } = DateTimeOffset.UtcNow.AddDays(1);
        internal TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Draining { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Func<CancellationToken, Task> Work { get; init; } = token => Task.Delay(Timeout.Infinite, token);
        internal Func<ValueTask> Drain { get; set; } = () => ValueTask.CompletedTask;
        internal int Disposals;
        public Task RunAsync(CancellationToken token) { Started.TrySetResult(); return Work(token); }
        public ValueTask DisposeAsync() { Disposals++; return Drain(); }
    }
}
