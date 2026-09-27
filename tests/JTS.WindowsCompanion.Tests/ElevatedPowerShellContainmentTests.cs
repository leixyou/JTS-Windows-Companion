using System.Diagnostics;
using JTS.WindowsCompanion.Elevation;

namespace JTS.WindowsCompanion.Tests;

public sealed class ElevatedPowerShellContainmentTests
{
    [Theory]
    [InlineData(BlockingStage.Start)]
    [InlineData(BlockingStage.StandardInput)]
    [InlineData(BlockingStage.WaitForExit)]
    [InlineData(BlockingStage.StandardOutput)]
    public async Task Executor_CancelsEveryProcessLifecycleStageAndDisposesContainment(BlockingStage stage)
    {
        using var directory = new TemporaryDirectory();
        var timeProvider = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var factory = new BlockingProcessFactory(stage);
        var executor = Executor(factory, timeProvider);
        using var cancellation = new CancellationTokenSource();

        var execution = executor.ExecuteAsync(Action(directory.Path), cancellation.Token).AsTask();
        await factory.Process.StageEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => execution);
        Assert.True(factory.Process.Disposed);
        Assert.True(factory.Process.HasExited);
        if (stage != BlockingStage.StandardOutput)
        {
            Assert.True(factory.Process.TerminationCount > 0);
        }
    }

    [Fact]
    public async Task LeaseExpiration_ActivelyCancelsRunningPowerShell()
    {
        using var directory = new TemporaryDirectory();
        var timeProvider = new ManualTimeProvider(DateTimeOffset.UtcNow);
        using var leases = new ElevationLeaseManager(timeProvider);
        var action = Action(directory.Path);
        var lease = IssueLease(leases, action, TimeSpan.FromMinutes(5));
        var leaseCancellation = leases.Authorize(
            lease.LeaseId,
            action.ActionId,
            ElevatedActionKind.ApprovedPowerShell,
            action.CanonicalPayload);
        var factory = new BlockingProcessFactory(BlockingStage.WaitForExit);
        var execution = Executor(factory, timeProvider).ExecuteAsync(action, leaseCancellation).AsTask();
        await factory.Process.StageEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));

        timeProvider.Advance(TimeSpan.FromMinutes(5));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => execution);
        Assert.True(leaseCancellation.IsCancellationRequested);
        Assert.Equal(1, factory.Process.TerminationCount);
        Assert.Equal(0, leases.ActiveLeaseCount);
    }

    [Fact]
    public async Task LeaseRevocation_ActivelyCancelsRunningPowerShell()
    {
        using var directory = new TemporaryDirectory();
        var timeProvider = new ManualTimeProvider(DateTimeOffset.UtcNow);
        using var leases = new ElevationLeaseManager(timeProvider);
        var action = Action(directory.Path);
        var lease = IssueLease(leases, action, TimeSpan.FromMinutes(5));
        var leaseCancellation = leases.Authorize(
            lease.LeaseId,
            action.ActionId,
            ElevatedActionKind.ApprovedPowerShell,
            action.CanonicalPayload);
        var factory = new BlockingProcessFactory(BlockingStage.WaitForExit);
        var execution = Executor(factory, timeProvider).ExecuteAsync(action, leaseCancellation).AsTask();
        await factory.Process.StageEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));

        leases.Revoke(lease.LeaseId);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => execution);
        Assert.True(leaseCancellation.IsCancellationRequested);
        Assert.Equal(1, factory.Process.TerminationCount);
    }

    [Fact]
    public async Task ExecutionTimeout_TerminatesContainmentAndReturnsTimedOutResult()
    {
        using var directory = new TemporaryDirectory();
        var timeProvider = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var factory = new BlockingProcessFactory(BlockingStage.WaitForExit);
        var action = Action(directory.Path) with { TimeoutMilliseconds = 1_000 };
        var execution = Executor(factory, timeProvider).ExecuteAsync(action, CancellationToken.None).AsTask();
        await factory.Process.StageEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));

        timeProvider.Advance(TimeSpan.FromSeconds(1));

        var result = await execution;
        Assert.True(result.TimedOut);
        Assert.Equal(1, factory.Process.TerminationCount);
        Assert.True(factory.Process.Disposed);
    }

    [Fact]
    public async Task ProductionExecutor_FailsClosedWithoutWindowsJobObjects()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using var directory = new TemporaryDirectory();
        var executor = new ElevatedPowerShellExecutor(new FixedElevationVerifier());
        await Assert.ThrowsAsync<PlatformNotSupportedException>(async () =>
            await executor.ExecuteAsync(Action(directory.Path), CancellationToken.None));
    }

    private static ElevatedPowerShellExecutor Executor(
        IContainedProcessFactory factory,
        TimeProvider timeProvider) =>
        new(new FixedElevationVerifier(), factory, timeProvider);

    private static ElevatedPowerShellActionDescriptor Action(string directory) => new(
        "approved-action",
        "Write-Output ok",
        directory,
        15 * 60 * 1_000,
        4_096,
        new Dictionary<string, string>(),
        [new ResolvedElevationDataScope("factory", directory, ElevationScopeAccess.ReadWrite)]);

    private static ElevationLease IssueLease(
        ElevationLeaseManager leases,
        ElevatedPowerShellActionDescriptor action,
        TimeSpan duration) =>
        leases.IssueApproved(
            new ElevationLeaseRequest(
                Guid.NewGuid(),
                duration,
                [new ElevatedActionGrant(
                    action.ActionId,
                    ElevatedActionKind.ApprovedPowerShell,
                    action.PayloadSha256,
                    "Run approved PowerShell")]),
            userConfirmedOnSecureDesktop: true);

    public enum BlockingStage
    {
        Start,
        StandardInput,
        WaitForExit,
        StandardOutput,
    }

    private sealed class FixedElevationVerifier : IProcessElevationVerifier
    {
        public bool IsElevated => true;
    }

    private sealed class BlockingProcessFactory : IContainedProcessFactory
    {
        public BlockingProcessFactory(BlockingStage stage)
        {
            Process = new BlockingProcess(stage);
        }

        public BlockingProcess Process { get; }

        public IContainedProcess Create(ProcessStartInfo startInfo)
        {
            Assert.Equal("powershell.exe", startInfo.FileName);
            return Process;
        }
    }

    private sealed class BlockingProcess : IContainedProcess
    {
        private readonly BlockingStage _stage;
        private readonly TaskCompletionSource _exit = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public BlockingProcess(BlockingStage stage)
        {
            _stage = stage;
            StandardOutput = stage == BlockingStage.StandardOutput
                ? new BlockingTextReader(StageEntered)
                : new StringReader(string.Empty);
        }

        public TaskCompletionSource StageEntered { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TextReader StandardOutput { get; }

        public TextReader StandardError { get; } = new StringReader(string.Empty);

        public bool HasExited { get; private set; }

        public int ExitCode => HasExited ? -1 : throw new InvalidOperationException();

        public int TerminationCount { get; private set; }

        public bool Disposed { get; private set; }

        public async ValueTask StartAsync(CancellationToken cancellationToken)
        {
            if (_stage != BlockingStage.Start)
            {
                return;
            }

            StageEntered.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        }

        public async ValueTask WriteStandardInputAsync(
            ReadOnlyMemory<char> text,
            CancellationToken cancellationToken)
        {
            if (_stage != BlockingStage.StandardInput)
            {
                return;
            }

            StageEntered.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
        }

        public async Task WaitForExitAsync(CancellationToken cancellationToken)
        {
            if (_stage == BlockingStage.StandardOutput)
            {
                HasExited = true;
                _exit.TrySetResult();
                return;
            }

            if (_stage == BlockingStage.WaitForExit)
            {
                StageEntered.TrySetResult();
            }

            await _exit.Task.WaitAsync(cancellationToken);
        }

        public ValueTask TerminateAsync()
        {
            if (!HasExited)
            {
                TerminationCount++;
                HasExited = true;
                _exit.TrySetResult();
            }

            return ValueTask.CompletedTask;
        }

        public async ValueTask DisposeAsync()
        {
            if (!HasExited)
            {
                await TerminateAsync();
            }

            Disposed = true;
            StandardOutput.Dispose();
            StandardError.Dispose();
        }
    }

    private sealed class BlockingTextReader : TextReader
    {
        private readonly TaskCompletionSource _entered;

        public BlockingTextReader(TaskCompletionSource entered)
        {
            _entered = entered;
        }

        public override async ValueTask<int> ReadAsync(
            Memory<char> buffer,
            CancellationToken cancellationToken = default)
        {
            _entered.TrySetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return 0;
        }
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"jts-elevation-containment-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
    }
}
