using JTS.WindowsCompanion.Windows.Elevation;

namespace JTS.WindowsCompanion.Tests;

public sealed class BrokerProcessShutdownTests
{
    [Fact]
    public async Task StopAsync_WaitsForGracefulBrokerExitBeforeKilling()
    {
        var process = new FakeBrokerProcess();
        var timeProvider = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var stopping = BrokerProcessShutdown.StopAsync(process, timeProvider);
        await process.WaitStarted.WaitAsync(TimeSpan.FromSeconds(5));

        process.Exit();

        await stopping;
        Assert.Equal(0, process.KillCount);
    }

    [Fact]
    public async Task StopAsync_KillsBrokerTreeAfterGracePeriodAndWaitsForExit()
    {
        var process = new FakeBrokerProcess(exitWhenKilled: true);
        var timeProvider = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var stopping = BrokerProcessShutdown.StopAsync(process, timeProvider);
        await process.WaitStarted.WaitAsync(TimeSpan.FromSeconds(5));

        timeProvider.Advance(BrokerProcessShutdown.GracefulExitTimeout);

        await stopping;
        Assert.Equal(1, process.KillCount);
        Assert.True(process.HasExited);
    }

    [Fact]
    public async Task StopAsync_FailsClosedWhenKilledBrokerDoesNotExit()
    {
        var process = new FakeBrokerProcess(exitWhenKilled: false);
        var timeProvider = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var stopping = BrokerProcessShutdown.StopAsync(process, timeProvider);
        await process.WaitStarted.WaitAsync(TimeSpan.FromSeconds(5));
        timeProvider.Advance(BrokerProcessShutdown.GracefulExitTimeout);
        await process.WaitStarted.WaitAsync(TimeSpan.FromSeconds(5));

        timeProvider.Advance(BrokerProcessShutdown.ForcedExitTimeout);

        await Assert.ThrowsAsync<InvalidOperationException>(() => stopping);
        Assert.Equal(1, process.KillCount);
    }

    private sealed class FakeBrokerProcess : IBrokerProcessLifetime
    {
        private readonly bool _exitWhenKilled;
        private readonly TaskCompletionSource _exit = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public FakeBrokerProcess(bool exitWhenKilled = false)
        {
            _exitWhenKilled = exitWhenKilled;
        }

        public int Id => 42;

        public bool HasExited { get; private set; }

        public int KillCount { get; private set; }

        public SemaphoreSlim WaitStarted { get; } = new(0);

        public async Task WaitForExitAsync(CancellationToken cancellationToken)
        {
            WaitStarted.Release();
            await _exit.Task.WaitAsync(cancellationToken);
        }

        public void KillProcessTree()
        {
            KillCount++;
            if (_exitWhenKilled)
            {
                Exit();
            }
        }

        public void Exit()
        {
            HasExited = true;
            _exit.TrySetResult();
        }

        public void Dispose()
        {
            WaitStarted.Dispose();
        }
    }
}
