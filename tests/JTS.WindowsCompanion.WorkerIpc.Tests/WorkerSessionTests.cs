using System.Net;
using System.Net.Sockets;
using JTS.WindowsCompanion.Runtime;
using Xunit;

namespace JTS.WindowsCompanion.WorkerIpc.Tests;

public sealed class WorkerSessionTests
{
    [Fact]
    public async Task RejectedPayloadStillReleasesAlreadyLaunchedWorkerWithoutDispatch()
    {
        using var pair = await StreamPair.Create(); var job = WorkerWireTests.Job(); var supervisor = new Supervisor();
        await Assert.ThrowsAsync<WorkerIpcException>(() => WorkerAuthoritySession.ExecuteAsync(pair.Authority, Guid.NewGuid(),
            supervisor, job.Binding with { PayloadSha256 = new string('0', 64) }, job.Payload, new Sink(), default).AsTask());
        Assert.True(supervisor.Called.Task.IsCompleted);
        var bytes = new byte[1]; Assert.Equal(0, await pair.Worker.ReadAsync(bytes));
    }
    [Fact]
    public async Task WorkerDeadlineBeforeAuthorityTimerCallbackDoesNotBecomeUnknown()
    {
        using var pair = await StreamPair.Create(); var session = Guid.NewGuid(); var original = WorkerWireTests.Job();
        var job = new JobSubmission(original.Binding.RequestId, original.Binding.Kind, original.Binding.OwnerDeviceId,
            original.Binding.GrantId, DateTimeOffset.UtcNow.AddMilliseconds(500), original.Payload, true);
        var worker = WorkerExecutionSession.RunOnceAsync(pair.Worker, session, new Executor(async (_, _, _, ct) =>
        { await Task.Delay(Timeout.InfiniteTimeSpan, ct); return new JobExecutionResult(true, "UNREACHABLE"); }), default);
        var result = await WorkerAuthoritySession.ExecuteAsync(pair.Authority, session, new Supervisor(), job.Binding,
            job.Payload, new Sink(), default).AsTask().WaitAsync(TimeSpan.FromSeconds(3));
        Assert.False(result.Success); Assert.Equal("DEADLINE_EXPIRED", result.ResultCode); await worker;
    }
    [Fact]
    public async Task PowerShellFailureCodeSurvivesTheProcessBoundary()
    {
        using var pair = await StreamPair.Create(); var session = Guid.NewGuid(); var job = WorkerWireTests.Job();
        var worker = WorkerExecutionSession.RunOnceAsync(pair.Worker, session,
            new Executor((_, _, _, _) => ValueTask.FromResult(new JobExecutionResult(false, "POWERSHELL_EXIT_NONZERO"))), default);
        var result = await WorkerAuthoritySession.ExecuteAsync(pair.Authority, session, new Supervisor(), job.Binding, job.Payload, new Sink(), default);
        Assert.False(result.Success); Assert.Equal("POWERSHELL_EXIT_NONZERO", result.ResultCode); await worker;
    }
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WrongJobPulseOrSecondExecuteCancelsRatherThanRunningAnotherTask(bool secondExecute)
    {
        using var pair = await StreamPair.Create(); var session = Guid.NewGuid(); var job = WorkerWireTests.Job();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); var calls = 0;
        var worker = WorkerExecutionSession.RunOnceAsync(pair.Worker, session, new Executor(async (_, _, _, ct) =>
        { calls++; entered.SetResult(); await Task.Delay(Timeout.InfiniteTimeSpan, ct); return new JobExecutionResult(true, "UNREACHABLE"); }), default);
        var wire = new WorkerWire(pair.Authority, session); var body = WorkerRequestCodec.Encode(job.Binding, job.Payload, DateTimeOffset.UtcNow);
        await wire.SendAsync(WorkerMessage.Execute, job.Binding.RequestId, body, default);
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
        await wire.SendAsync(secondExecute ? WorkerMessage.Execute : WorkerMessage.Pulse,
            secondExecute ? job.Binding.RequestId : Guid.NewGuid(), secondExecute ? body : Array.Empty<byte>(), default);
        using var result = await wire.ReadAsync(default).WaitAsync(TimeSpan.FromSeconds(3));
        Assert.Equal(WorkerMessage.Result, result.Type); Assert.Equal((byte)WorkerOutcome.Cancelled, result.Body[0]);
        Assert.Equal(1, calls); await worker;
    }
    [Fact]
    public async Task MissingAuthorityPulseCancelsWithinLeaseWithoutRdpPresence()
    {
        using var pair = await StreamPair.Create(); var session = Guid.NewGuid(); var job = WorkerWireTests.Job();
        var worker = WorkerExecutionSession.RunOnceAsync(pair.Worker, session, new Executor(async (_, _, _, ct) =>
        { await Task.Delay(Timeout.InfiniteTimeSpan, ct); return new JobExecutionResult(true, "UNREACHABLE"); }), default);
        var wire = new WorkerWire(pair.Authority, session);
        await wire.SendAsync(WorkerMessage.Execute, job.Binding.RequestId, WorkerRequestCodec.Encode(job.Binding, job.Payload, DateTimeOffset.UtcNow), default);
        using var result = await wire.ReadAsync(default).WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal((byte)WorkerOutcome.Cancelled, result.Body[0]); await worker;
    }
    [Fact]
    public async Task RealDuplexStreamCarriesOneTaskOutputAndResultButWaitsForIndependentStop()
    {
        using var pair = await StreamPair.Create(); var session = Guid.NewGuid(); var job = WorkerWireTests.Job();
        var supervisor = new Supervisor { Hold = true }; var sink = new Sink();
        var worker = WorkerExecutionSession.RunOnceAsync(pair.Worker, session, new Executor(async (_, bytes, output, token) =>
        { await output.AppendAsync(bytes, token); return new JobExecutionResult(true, "OK"); }), default);
        var authority = WorkerAuthoritySession.ExecuteAsync(pair.Authority, session, supervisor, job.Binding, job.Payload, sink, default).AsTask();
        await supervisor.Called.Task.WaitAsync(TimeSpan.FromSeconds(3));
        Assert.False(authority.IsCompleted); supervisor.Release.SetResult();
        Assert.True((await authority.WaitAsync(TimeSpan.FromSeconds(3))).Success);
        await worker.WaitAsync(TimeSpan.FromSeconds(3)); Assert.Equal(job.Payload.ToArray(), sink.Bytes.ToArray());
    }
    [Fact]
    public async Task CancellationDisconnectsWorkerAndConfirmsStopBeforeCancellationReceipt()
    {
        using var pair = await StreamPair.Create(); var session = Guid.NewGuid(); var job = WorkerWireTests.Job();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var drained = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var token = new CancellationTokenSource(); var supervisor = new Supervisor();
        var worker = WorkerExecutionSession.RunOnceAsync(pair.Worker, session, new Executor(async (_, _, _, ct) =>
        {
            entered.SetResult();
            try { await Task.Delay(Timeout.InfiniteTimeSpan, ct); }
            finally { drained.SetResult(); }
            return new JobExecutionResult(true, "UNREACHABLE");
        }), default);
        var authority = WorkerAuthoritySession.ExecuteAsync(pair.Authority, session, supervisor, job.Binding, job.Payload, new Sink(), token.Token).AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(3)); token.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => authority.WaitAsync(TimeSpan.FromSeconds(3)));
        Assert.True(supervisor.Called.Task.IsCompleted); await drained.Task.WaitAsync(TimeSpan.FromSeconds(3));
        await ObserveClosedWorker(worker);
    }
    [Fact]
    public async Task OutputLimitStopsAuthoritySessionAndWorker()
    {
        using var pair = await StreamPair.Create(); var session = Guid.NewGuid(); var job = WorkerWireTests.Job(); var supervisor = new Supervisor();
        var worker = WorkerExecutionSession.RunOnceAsync(pair.Worker, session, new Executor(async (_, _, output, ct) =>
        { while (true) await output.AppendAsync(new byte[4096], ct); }), default);
        var authority = WorkerAuthoritySession.ExecuteAsync(pair.Authority, session, supervisor, job.Binding, job.Payload,
            new Sink { Reject = true }, default).AsTask();
        Assert.Equal("JOB_OUTPUT_LIMIT", (await Assert.ThrowsAsync<JobRuntimeException>(() => authority.WaitAsync(TimeSpan.FromSeconds(3)))).Code);
        Assert.True(supervisor.Called.Task.IsCompleted); await ObserveClosedWorker(worker);
    }
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task IndependentStopFailureCannotBecomeSuccessOrCancelled(bool cancel)
    {
        using var pair = await StreamPair.Create(); var session = Guid.NewGuid(); var job = WorkerWireTests.Job();
        using var token = new CancellationTokenSource();
        var supervisor = new Supervisor { Fail = true };
        var worker = WorkerExecutionSession.RunOnceAsync(pair.Worker, session, new Executor((_, _, _, _) =>
        { if (cancel) token.Cancel(); return ValueTask.FromResult(new JobExecutionResult(true, "OK")); }), default);
        var authority = WorkerAuthoritySession.ExecuteAsync(pair.Authority, session, supervisor, job.Binding, job.Payload, new Sink(), token.Token).AsTask();
        await Assert.ThrowsAsync<JobExecutionStateUnknownException>(() => authority.WaitAsync(TimeSpan.FromSeconds(3)));
        await ObserveClosedWorker(worker);
    }
    [Fact]
    public async Task PeerLossAfterDispatchIsUnknownNotAnImplicitRetry()
    {
        using var pair = await StreamPair.Create(); var session = Guid.NewGuid(); var job = WorkerWireTests.Job(); var supervisor = new Supervisor();
        var authority = WorkerAuthoritySession.ExecuteAsync(pair.Authority, session, supervisor, job.Binding, job.Payload, new Sink(), default).AsTask();
        using var frame = await new WorkerWire(pair.Worker, session).ReadAsync(default);
        Assert.Equal(WorkerMessage.Execute, frame.Type); pair.Worker.Dispose();
        await Assert.ThrowsAsync<JobExecutionStateUnknownException>(() => authority.WaitAsync(TimeSpan.FromSeconds(3)));
        Assert.True(supervisor.Called.Task.IsCompleted);
    }
    [Fact]
    public async Task WrongJobResultCannotCompleteCurrentTask()
    {
        using var pair = await StreamPair.Create(); var session = Guid.NewGuid(); var job = WorkerWireTests.Job(); var supervisor = new Supervisor();
        var authority = WorkerAuthoritySession.ExecuteAsync(pair.Authority, session, supervisor, job.Binding, job.Payload, new Sink(), default).AsTask();
        var wire = new WorkerWire(pair.Worker, session); using var request = await wire.ReadAsync(default);
        await wire.SendAsync(WorkerMessage.Result, Guid.NewGuid(), new[] { (byte)WorkerOutcome.Succeeded }, default);
        await Assert.ThrowsAsync<JobExecutionStateUnknownException>(() => authority.WaitAsync(TimeSpan.FromSeconds(3)));
    }
    [Fact]
    public async Task ExplicitUnknownResultIsNotReportedAsOrdinaryFailure()
    {
        using var pair = await StreamPair.Create(); var session = Guid.NewGuid(); var job = WorkerWireTests.Job();
        var worker = WorkerExecutionSession.RunOnceAsync(pair.Worker, session,
            new Executor((_, _, _, _) => throw new JobExecutionStateUnknownException()), default);
        await Assert.ThrowsAsync<JobExecutionStateUnknownException>(() => WorkerAuthoritySession.ExecuteAsync(pair.Authority, session,
            new Supervisor(), job.Binding, job.Payload, new Sink(), default).AsTask());
        await worker.WaitAsync(TimeSpan.FromSeconds(3));
    }
    private static async Task ObserveClosedWorker(Task worker)
    {
        try { await worker.WaitAsync(TimeSpan.FromSeconds(3)); }
        catch (Exception error) when (error is IOException or ObjectDisposedException or OperationCanceledException) { }
    }
    private sealed class Executor(Func<JobBinding, ReadOnlyMemory<byte>, IJobOutputSink, CancellationToken, ValueTask<JobExecutionResult>> execute) : IJobExecutor
    {
        public ValueTask<JobExecutionResult> ExecuteAsync(JobBinding binding, ReadOnlyMemory<byte> payload, IJobOutputSink output, CancellationToken token)
            => execute(binding, payload, output, token);
    }
    private sealed class Supervisor : IWorkerSupervisor
    {
        internal bool Hold { get; init; } internal bool Fail { get; init; }
        internal TaskCompletionSource Called { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async Task StopAndConfirmAsync()
        { Called.TrySetResult(); if (Hold) await Release.Task; if (Fail) throw new IOException(); }
    }
    private sealed class Sink : IJobOutputSink
    {
        internal MemoryStream Bytes { get; } = new(); internal bool Reject { get; init; }
        public ValueTask AppendAsync(ReadOnlyMemory<byte> output, CancellationToken token)
        { if (Reject) throw new JobRuntimeException("JOB_OUTPUT_LIMIT"); return Bytes.WriteAsync(output, token); }
    }
    private sealed class StreamPair(TcpClient authority, TcpClient worker) : IDisposable
    {
        internal Stream Authority { get; } = authority.GetStream();
        internal Stream Worker { get; } = worker.GetStream();
        internal static async Task<StreamPair> Create()
        {
            using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
            var client = new TcpClient(); var accepted = listener.AcceptTcpClientAsync();
            await client.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
            return new StreamPair(client, await accepted);
        }
        public void Dispose() { authority.Dispose(); worker.Dispose(); }
    }
}
