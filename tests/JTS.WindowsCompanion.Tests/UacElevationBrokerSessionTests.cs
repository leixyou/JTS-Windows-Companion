using System.IO.Pipes;
using JTS.WindowsCompanion.Elevation;
using JTS.WindowsCompanion.Windows.Elevation;

namespace JTS.WindowsCompanion.Tests;

public sealed class UacElevationBrokerSessionTests
{
    [Fact]
    public async Task DisposeAsync_SignalsCancellationAndWaitsForBrokerExit()
    {
        var timeProvider = new ManualTimeProvider(DateTimeOffset.UtcNow);
        using var cancellationEvent = new EventWaitHandle(false, EventResetMode.ManualReset);
        var process = new EventAwareBrokerProcess(cancellationEvent);
        var session = CreateSession(process, cancellationEvent, timeProvider, TimeSpan.FromMinutes(5));

        await session.DisposeAsync();

        Assert.True(process.SawCancellationSignal);
        Assert.True(process.WaitedForExit);
        Assert.True(process.Disposed);
    }

    [Fact]
    public async Task LeaseDeadline_SignalsAndStopsBrokerWithoutAStatusQuery()
    {
        var timeProvider = new ManualTimeProvider(DateTimeOffset.UtcNow);
        using var cancellationEvent = new EventWaitHandle(false, EventResetMode.ManualReset);
        var process = new EventAwareBrokerProcess(cancellationEvent);
        var session = CreateSession(process, cancellationEvent, timeProvider, TimeSpan.FromMinutes(5));

        timeProvider.Advance(TimeSpan.FromMinutes(5));
        await session.DisposeAsync();

        Assert.True(process.SawCancellationSignal);
        Assert.True(process.WaitedForExit);
        Assert.True(process.Disposed);
    }

    private static UacElevationBrokerClient.BrokerLeaseSession CreateSession(
        IBrokerProcessLifetime process,
        EventWaitHandle cancellationEvent,
        TimeProvider timeProvider,
        TimeSpan duration)
    {
        var now = timeProvider.GetUtcNow();
        var lease = new ElevationLease(Guid.NewGuid(), now, now + duration, []);
        var action = new ElevatedPowerShellActionDescriptor(
            "test-action",
            "Write-Output ok",
            Path.GetTempPath(),
            1_000,
            4_096,
            new Dictionary<string, string>(),
            [new ResolvedElevationDataScope("temp", Path.GetTempPath(), ElevationScopeAccess.ReadWrite)]);
        var pipe = new NamedPipeServerStream(
            $"u{Guid.NewGuid():N}",
            PipeDirection.InOut,
            1,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
        return new UacElevationBrokerClient.BrokerLeaseSession(
            process,
            pipe,
            new string('A', 64),
            lease,
            action,
            cancellationEvent,
            timeProvider);
    }

    private sealed class EventAwareBrokerProcess : IBrokerProcessLifetime
    {
        private readonly EventWaitHandle _cancellationEvent;

        public EventAwareBrokerProcess(EventWaitHandle cancellationEvent)
        {
            _cancellationEvent = cancellationEvent;
        }

        public int Id => 42;

        public bool HasExited { get; private set; }

        public bool SawCancellationSignal { get; private set; }

        public bool WaitedForExit { get; private set; }

        public bool Disposed { get; private set; }

        public Task WaitForExitAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            WaitedForExit = true;
            SawCancellationSignal = _cancellationEvent.WaitOne(0);
            HasExited = SawCancellationSignal;
            return HasExited
                ? Task.CompletedTask
                : Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        }

        public void KillProcessTree()
        {
            HasExited = true;
        }

        public void Dispose()
        {
            Disposed = true;
        }
    }
}
