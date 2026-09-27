using JTS.WindowsCompanion.Runtime;
using JTS.WindowsCompanion.WorkerIpc;
using Xunit;

namespace JTS.WindowsCompanion.WorkerService.Tests;

public sealed class ServiceLaunchTests
{
    private static WorkerLaunchDescriptor Descriptor() => new(Guid.NewGuid(),
        new WindowsProcessIdentity(123, 1234567, ServicePolicyTests.Authority, @"C:\Program Files\JTS\authority.exe", new string('a', 64)), ServicePolicyTests.Worker);
    [Fact]
    public async Task ExactlyOneStartAndIndependentAttachmentTransfersLease()
    {
        var operations = new Operations(); var descriptor = Descriptor();
        using var lease = await ServiceLaunchEngine.LaunchAsync(operations, descriptor, default);
        Assert.Same(operations.Lease, lease); Assert.Equal(1, operations.Starts); Assert.Equal(1, operations.Attaches);
        Assert.Equal(0, lease.Stops); Assert.Equal(descriptor, WorkerLaunchArguments.Decode(operations.Arguments!));
    }
    [Fact]
    public async Task BusyServiceIsNeitherAdoptedNorStopped()
    {
        var operations = new Operations { Started = true };
        await Assert.ThrowsAsync<WorkerServiceException>(() => ServiceLaunchEngine.LaunchAsync(operations, Descriptor(), default).AsTask());
        Assert.Equal(0, operations.Starts); Assert.Equal(0, operations.Attaches); Assert.Equal(0, operations.Lease.Stops);
    }
    [Fact]
    public async Task AlreadyRunningRaceDoesNotGrantOwnershipToCaller()
    {
        var operations = new Operations { StartResult = new(false, 1056) };
        await Assert.ThrowsAsync<WorkerServiceException>(() => ServiceLaunchEngine.LaunchAsync(operations, Descriptor(), default).AsTask());
        Assert.Equal(1, operations.Starts); Assert.Equal(0, operations.Attaches); Assert.Equal(0, operations.Lease.Stops);
    }
    [Fact]
    public async Task CancellationDuringUncancellableScmCallWaitsForRealOutcomeThenCleansUp()
    {
        var operations = new Operations { HoldStart = true }; using var token = new CancellationTokenSource();
        var launch = ServiceLaunchEngine.LaunchAsync(operations, Descriptor(), token.Token).AsTask();
        await operations.Entered.Task; token.Cancel(); Assert.False(launch.IsCompleted);
        operations.Release.SetResult();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => launch.WaitAsync(TimeSpan.FromSeconds(3)));
        Assert.Equal(1, operations.Starts); Assert.Equal(1, operations.Lease.Stops);
    }
    [Fact]
    public async Task CancellationImmediatelyAfterAttachmentDoesNotStopTwice()
    {
        using var token = new CancellationTokenSource(); var operations = new Operations { Attached = () => token.Cancel() };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ServiceLaunchEngine.LaunchAsync(operations, Descriptor(), token.Token).AsTask());
        Assert.Equal(1, operations.Attaches); Assert.Equal(1, operations.Lease.Stops);
    }
    [Fact]
    public async Task UnconfirmedCleanupRemainsUnknownNotCancelled()
    {
        using var token = new CancellationTokenSource();
        var operations = new Operations { Attached = () => token.Cancel(), Lease = new Lease { Fail = true } };
        await Assert.ThrowsAsync<JobExecutionStateUnknownException>(() => ServiceLaunchEngine.LaunchAsync(operations, Descriptor(), token.Token).AsTask());
        Assert.Equal(1, operations.Lease.Stops);
    }
    [Fact]
    public async Task AmbiguousStartTimeoutDoesNotRetryAndSupervisesAnyVerifiedNewProcess()
    {
        var operations = new Operations { StartResult = new(false, 1053) };
        await Assert.ThrowsAsync<JobExecutionStateUnknownException>(() => ServiceLaunchEngine.LaunchAsync(operations, Descriptor(), default).AsTask());
        Assert.Equal(1, operations.Starts); Assert.Equal(1, operations.Lease.Stops);
    }
    [Fact]
    public async Task StoppedScmStateAloneDoesNotProveNewWorkerDrained()
    {
        var operations = new Operations { Vanish = true };
        await Assert.ThrowsAsync<JobExecutionStateUnknownException>(() => ServiceLaunchEngine.LaunchAsync(operations, Descriptor(), default).AsTask());
        Assert.Equal(1, operations.Starts); Assert.Equal(0, operations.Attaches);
    }
    [Fact]
    public async Task ReadOnlyReadyProbeCanRetryWithoutStartingAgain()
    {
        var operations = new Operations { FirstProbeNotReady = true };
        using var lease = await ServiceLaunchEngine.LaunchAsync(operations, Descriptor(), default);
        Assert.Equal(1, operations.Starts); Assert.Equal(2, operations.Attaches);
    }
    [Fact]
    public async Task SecondRequestCannotRaceUnresolvedStartAndCanCancelWithoutTouchingScm()
    {
        var operations = new Operations { HoldStart = true };
        var first = ServiceLaunchEngine.LaunchAsync(operations, Descriptor(), default).AsTask();
        await operations.Entered.Task;
        using var token = new CancellationTokenSource();
        try
        {
            var second = ServiceLaunchEngine.LaunchAsync(operations, Descriptor(), token.Token).AsTask();
            Assert.False(second.IsCompleted); Assert.Equal(1, operations.Starts);
            token.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => second.WaitAsync(TimeSpan.FromSeconds(3)));
            Assert.Equal(1, operations.Starts); Assert.Equal(0, operations.Attaches);
        }
        finally { operations.Release.TrySetResult(); using var lease = await first.WaitAsync(TimeSpan.FromSeconds(3)); }
    }
    [Fact]
    public async Task StartupGateRemainsHeldUntilUncertainProcessCleanupCompletes()
    {
        var lease = new Lease { HoldStop = true };
        var operations = new Operations { StartResult = new(false, 1053), Lease = lease };
        var first = ServiceLaunchEngine.LaunchAsync(operations, Descriptor(), default).AsTask();
        await lease.StopEntered.Task;
        using var token = new CancellationTokenSource();
        try
        {
            var second = ServiceLaunchEngine.LaunchAsync(new Operations(), Descriptor(), token.Token).AsTask();
            Assert.False(second.IsCompleted); token.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => second.WaitAsync(TimeSpan.FromSeconds(3)));
            Assert.Equal(1, operations.Starts); Assert.Equal(1, lease.Stops);
        }
        finally
        {
            lease.ReleaseStop.TrySetResult();
            await Assert.ThrowsAsync<JobExecutionStateUnknownException>(() => first.WaitAsync(TimeSpan.FromSeconds(3)));
        }
    }
    private sealed class Lease : IServiceProcessLease
    {
        internal bool Fail { get; init; } internal int Stops { get; private set; }
        internal bool HoldStop { get; init; }
        internal TaskCompletionSource StopEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource ReleaseStop { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async Task StopAndConfirmAsync()
        {
            Stops++; StopEntered.TrySetResult();
            if (HoldStop) await ReleaseStop.Task;
            if (Fail) throw new JobExecutionStateUnknownException();
        }
        public void Dispose() { }
    }
    private sealed class Operations : IServiceLaunchOperations<Lease>
    {
        internal Lease Lease { get; init; } = new();
        internal bool Started { get; set; }
        internal bool HoldStart { get; init; }
        internal bool Vanish { get; init; }
        internal bool FirstProbeNotReady { get; init; }
        internal Action? Attached { get; init; }
        internal StartOutcome StartResult { get; init; } = new(true, 0);
        internal TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal int Starts { get; private set; } internal int Attaches { get; private set; }
        internal string[]? Arguments { get; private set; }
        public ServiceState ReadState() => Started && !Vanish ? new(4, 999) : new(1, 0);
        public async Task<StartOutcome> StartAsync(string[] publicArguments)
        {
            Starts++; Arguments = publicArguments; Entered.TrySetResult();
            if (HoldStart) await Release.Task;
            Started = true; return StartResult;
        }
        public Lease? TryAttach(uint pid, long startedNotBefore)
        { Assert.Equal(999u, pid); Assert.True(startedNotBefore > 0); Attaches++; if (FirstProbeNotReady && Attaches == 1) return null; Attached?.Invoke(); return Lease; }
    }
}
