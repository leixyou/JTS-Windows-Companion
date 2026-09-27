using System.Text;
using JTS.WindowsCompanion.Runtime;
using Xunit;

namespace JTS.WindowsCompanion.Execution.Tests;

public sealed class ExecutorLifecycleTests
{
    [Fact]
    public async Task SuccessSendsScriptOnlyToStdinAndDrainsBeforeReturning()
    {
        using var child = new FakeProcess { ExitOnResume = 0, Output = new MemoryStream("result"u8.ToArray()) };
        var platform = new FakePlatform(child); var sink = new CaptureSink(); var job = ExecutionContractTests.Job("secret 中文");
        var result = await new StandardAccountPowerShellExecutor(platform).ExecuteAsync(job.Binding, job.Payload, sink, default);
        Assert.True(result.Success); Assert.True(child.Drained); Assert.True(child.Disposed);
        Assert.Equal("secret 中文", Encoding.UTF8.GetString(child.InputBytes.ToArray()));
        Assert.Equal("result", Encoding.UTF8.GetString(sink.Bytes.ToArray()));
        Assert.Equal(@"C:\Work", platform.Directory);
    }
    [Fact]
    public async Task NonzeroExitIsNotSuccess()
    {
        using var child = new FakeProcess { ExitOnResume = 7 }; var job = ExecutionContractTests.Job();
        var result = await new StandardAccountPowerShellExecutor(new FakePlatform(child)).ExecuteAsync(job.Binding, job.Payload, new CaptureSink(), default);
        Assert.False(result.Success); Assert.Equal("POWERSHELL_EXIT_NONZERO", result.ResultCode);
    }
    [Fact]
    public async Task CancellationWaitsForConfirmedTreeDrain()
    {
        using var child = new FakeProcess { Output = new BlockedReadStream() }; using var cancellation = new CancellationTokenSource();
        var job = ExecutionContractTests.Job();
        var run = new StandardAccountPowerShellExecutor(new FakePlatform(child)).ExecuteAsync(job.Binding, job.Payload, new CaptureSink(), cancellation.Token).AsTask();
        await child.Started.Task.WaitAsync(TimeSpan.FromSeconds(2)); cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => run.WaitAsync(TimeSpan.FromSeconds(2)));
        Assert.True(child.Drained); Assert.True(child.Disposed);
    }
    [Fact]
    public async Task OutputQuotaFailureStopsWithoutWaitingForRootExit()
    {
        using var child = new FakeProcess { Output = new MemoryStream(new byte[4096]) }; var job = ExecutionContractTests.Job();
        var run = new StandardAccountPowerShellExecutor(new FakePlatform(child)).ExecuteAsync(job.Binding, job.Payload,
            new CaptureSink { Reject = true }, default).AsTask();
        var error = await Assert.ThrowsAsync<JobRuntimeException>(() => run.WaitAsync(TimeSpan.FromSeconds(2)));
        Assert.Equal("JOB_OUTPUT_LIMIT", error.Code); Assert.True(child.Drained);
    }
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task UnconfirmedDrainOverridesSuccessAndCancellation(bool cancel)
    {
        using var child = new FakeProcess { ExitOnResume = cancel ? null : 0, FailDrain = true };
        using var cancellation = new CancellationTokenSource(); var job = ExecutionContractTests.Job();
        var run = new StandardAccountPowerShellExecutor(new FakePlatform(child)).ExecuteAsync(job.Binding, job.Payload,
            new CaptureSink(), cancellation.Token).AsTask();
        await child.Started.Task.WaitAsync(TimeSpan.FromSeconds(2)); if (cancel) cancellation.Cancel();
        await Assert.ThrowsAsync<JobExecutionStateUnknownException>(() => run.WaitAsync(TimeSpan.FromSeconds(2)));
        Assert.True(child.Disposed);
    }
    [Fact]
    public async Task CancelledOrInvalidRequestsNeverLaunch()
    {
        using var child = new FakeProcess(); var platform = new FakePlatform(child);
        var executor = new StandardAccountPowerShellExecutor(platform); var job = ExecutionContractTests.Job();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => executor.ExecuteAsync(job.Binding, job.Payload, new CaptureSink(), new CancellationToken(true)).AsTask());
        await Assert.ThrowsAsync<JobRuntimeException>(() => executor.ExecuteAsync(job.Binding with { Kind = "bad" }, job.Payload, new CaptureSink(), default).AsTask());
        Assert.Equal(0, platform.Calls);
    }
    [Fact]
    public async Task ResumeFailureStillDrainsSuspendedProcess()
    {
        using var child = new FakeProcess { FailResume = true }; var job = ExecutionContractTests.Job();
        await Assert.ThrowsAsync<InvalidOperationException>(() => new StandardAccountPowerShellExecutor(new FakePlatform(child))
            .ExecuteAsync(job.Binding, job.Payload, new CaptureSink(), default).AsTask());
        Assert.True(child.Drained); Assert.True(child.Disposed);
    }

    private sealed class FakePlatform(FakeProcess child) : IWorkerExecutionPlatform
    {
        internal string? Directory { get; private set; }
        internal int Calls { get; private set; }
        public IWorkerProcess Start(string workingDirectory) { Calls++; Directory = workingDirectory; return child; }
    }
    private sealed class FakeProcess : IWorkerProcess
    {
        internal MemoryStream InputBytes { get; } = new();
        public Stream Input => InputBytes;
        public Stream Output { get; init; } = new MemoryStream();
        public Stream Error { get; } = new MemoryStream();
        internal uint? ExitOnResume { get; init; }
        internal bool FailDrain { get; init; }
        internal bool FailResume { get; init; }
        internal bool Drained { get; private set; }
        internal bool Disposed { get; private set; }
        internal TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource<uint> _exit = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public void Resume()
        {
            Started.TrySetResult(); if (FailResume) throw new InvalidOperationException();
            if (ExitOnResume is { } code) _exit.TrySetResult(code);
        }
        public Task<uint> WaitForExitAsync(CancellationToken token) => _exit.Task.WaitAsync(token);
        public Task TerminateAndDrainAsync()
        {
            if (FailDrain) throw new JobExecutionStateUnknownException();
            Drained = true; _exit.TrySetResult(1); return Task.CompletedTask;
        }
        public void Dispose() { Disposed = true; InputBytes.Dispose(); Output.Dispose(); Error.Dispose(); }
    }
    internal sealed class CaptureSink : IJobOutputSink
    {
        internal MemoryStream Bytes { get; } = new();
        internal bool Reject { get; init; }
        public ValueTask AppendAsync(ReadOnlyMemory<byte> output, CancellationToken cancellationToken)
        {
            if (Reject) throw new JobRuntimeException("JOB_OUTPUT_LIMIT");
            return Bytes.WriteAsync(output, cancellationToken);
        }
    }
    private sealed class BlockedReadStream : MemoryStream
    {
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        { await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken); return 0; }
    }
}
