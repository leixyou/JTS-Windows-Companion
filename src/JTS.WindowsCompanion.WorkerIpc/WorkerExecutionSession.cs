using JTS.WindowsCompanion.Runtime;

namespace JTS.WindowsCompanion.WorkerIpc;

internal static class WorkerExecutionSession
{
    internal static async Task RunOnceAsync(Stream authenticatedPipe, Guid session, IJobExecutor executor, CancellationToken token)
    {
        using var wireLifetime = CancellationTokenSource.CreateLinkedTokenSource(token);
        using var close = wireLifetime.Token.Register(() => authenticatedPipe.Dispose());
        var wire = new WorkerWire(authenticatedPipe, session);
        using var startTimeout = CancellationTokenSource.CreateLinkedTokenSource(token);
        startTimeout.CancelAfter(TimeSpan.FromSeconds(5));
        using var request = await wire.ReadAsync(startTimeout.Token).ConfigureAwait(false);
        var (binding, payload) = WorkerRequestCodec.Decode(request, DateTimeOffset.UtcNow);
        using var execution = CancellationTokenSource.CreateLinkedTokenSource(token);
        execution.CancelAfter(TimeSpan.FromTicks(Math.Max(0, (binding.Deadline - DateTimeOffset.UtcNow).Ticks)));
        using var monitorStop = new CancellationTokenSource();
        var monitor = MonitorAsync(wire, binding.RequestId, execution, monitorStop.Token);
        var outcome = WorkerOutcome.Unknown;
        try
        {
            var result = await executor.ExecuteAsync(binding, payload, new PipeOutput(wire, binding.RequestId), execution.Token).ConfigureAwait(false);
            outcome = execution.IsCancellationRequested ? WorkerOutcome.Cancelled : result.Success ? WorkerOutcome.Succeeded
                : result.ResultCode == "POWERSHELL_EXIT_NONZERO" ? WorkerOutcome.PowerShellNonzero : WorkerOutcome.Failed;
        }
        catch (JobExecutionStateUnknownException) { outcome = WorkerOutcome.Unknown; }
        catch (OperationCanceledException) when (execution.IsCancellationRequested) { outcome = WorkerOutcome.Cancelled; }
        catch (Exception) { outcome = WorkerOutcome.Failed; }
        finally
        {
            monitorStop.Cancel();
            try { await monitor.ConfigureAwait(false); } catch (Exception) { }
        }
        using var resultTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        await wire.SendAsync(WorkerMessage.Result, binding.RequestId, new[] { (byte)outcome }, resultTimeout.Token).ConfigureAwait(false);
        // One pipe, one task, one process lifetime. The caller exits; no next-request loop or grant editing exists.
    }
    private static async Task MonitorAsync(WorkerWire wire, Guid job, CancellationTokenSource execution, CancellationToken stop)
    {
        try
        {
            while (true)
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stop);
                timeout.CancelAfter(TimeSpan.FromSeconds(7));
                using var frame = await wire.ReadAsync(timeout.Token).ConfigureAwait(false);
                if (frame.Type != WorkerMessage.Pulse || frame.Job != job) throw new WorkerIpcException();
            }
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
        catch { execution.Cancel(); }
    }
    private sealed class PipeOutput(WorkerWire wire, Guid job) : IJobOutputSink
    {
        private readonly SemaphoreSlim _writer = new(1, 1);
        private int _total;
        public async ValueTask AppendAsync(ReadOnlyMemory<byte> output, CancellationToken token)
        {
            await _writer.WaitAsync(token).ConfigureAwait(false);
            try
            {
                if (output.Length > 1_048_576 - _total) throw new JobRuntimeException("JOB_OUTPUT_LIMIT");
                _total += output.Length;
                while (!output.IsEmpty)
                {
                    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
                    timeout.CancelAfter(TimeSpan.FromSeconds(2));
                    var count = Math.Min(output.Length, 4096);
                    await wire.SendAsync(WorkerMessage.Output, job, output[..count], timeout.Token).ConfigureAwait(false);
                    output = output[count..];
                }
            }
            finally { _writer.Release(); }
        }
    }
}
