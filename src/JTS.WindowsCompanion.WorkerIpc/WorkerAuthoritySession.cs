using System.Security.Cryptography;
using JTS.WindowsCompanion.Runtime;

namespace JTS.WindowsCompanion.WorkerIpc;

internal interface IWorkerSupervisor
{
    // OS-owned supervision, not an assertion sent by the Worker being supervised.
    Task StopAndConfirmAsync();
}

internal static class WorkerAuthoritySession
{
    internal static async ValueTask<JobExecutionResult> ExecuteAsync(Stream authenticatedPipe, Guid session,
        IWorkerSupervisor supervisor, JobBinding binding, ReadOnlyMemory<byte> payload, IJobOutputSink output, CancellationToken token)
    {
        byte[]? body = null;
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(token);
        using var close = lifetime.Token.Register(() => authenticatedPipe.Dispose());
        Task? pulse = null;
        var dispatched = false;
        try
        {
            body = WorkerRequestCodec.Encode(binding, payload, DateTimeOffset.UtcNow);
            token.ThrowIfCancellationRequested();
            var wire = new WorkerWire(authenticatedPipe, session);
            using (var send = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token))
            {
                send.CancelAfter(TimeSpan.FromSeconds(3));
                dispatched = true; // A partial write is an uncertain delivery outcome, never retry a new ID.
                await wire.SendAsync(WorkerMessage.Execute, binding.RequestId, body, send.Token).ConfigureAwait(false);
            }
            pulse = PulseAsync(wire, binding.RequestId, lifetime);
            var receivedBytes = 0;
            while (true)
            {
                using var frame = await wire.ReadAsync(lifetime.Token).ConfigureAwait(false);
                if (frame.Job != binding.RequestId) throw new WorkerIpcException();
                if (frame.Type == WorkerMessage.Output)
                {
                    receivedBytes += frame.Body.Length;
                    if (receivedBytes > 1_048_576) throw new JobRuntimeException("JOB_OUTPUT_LIMIT");
                    await output.AppendAsync(frame.Body, token).ConfigureAwait(false);
                    continue;
                }
                if (frame.Type != WorkerMessage.Result || !Enum.IsDefined((WorkerOutcome)frame.Body[0])) throw new WorkerIpcException();
                return (WorkerOutcome)frame.Body[0] switch
                {
                    WorkerOutcome.Succeeded => new JobExecutionResult(true, "OK"),
                    WorkerOutcome.Failed => new JobExecutionResult(false, "JOB_EXECUTION_FAILED"),
                    WorkerOutcome.PowerShellNonzero => new JobExecutionResult(false, "POWERSHELL_EXIT_NONZERO"),
                    WorkerOutcome.Cancelled when token.IsCancellationRequested => throw new OperationCanceledException(token),
                    // Worker and authority timer callbacks need not run in the same millisecond.
                    WorkerOutcome.Cancelled when binding.Deadline <= DateTimeOffset.UtcNow => new JobExecutionResult(false, "DEADLINE_EXPIRED"),
                    _ => throw new JobExecutionStateUnknownException(),
                };
            }
        }
        catch (JobExecutionStateUnknownException) { throw; }
        catch (Exception) when (token.IsCancellationRequested) { throw new OperationCanceledException(token); }
        catch (JobRuntimeException) { throw; }
        catch (Exception) when (dispatched) { throw new JobExecutionStateUnknownException(); }
        finally
        {
            lifetime.Cancel();
            try
            {
                // Even a claimed success is provisional until the authority independently stops the full Worker job.
                try { await supervisor.StopAndConfirmAsync().ConfigureAwait(false); }
                catch (Exception) { throw new JobExecutionStateUnknownException(); }
            }
            finally
            {
                if (pulse is not null)
                    try { await pulse.ConfigureAwait(false); } catch (Exception) { }
                if (body is not null) CryptographicOperations.ZeroMemory(body);
            }
        }
    }
    private static async Task PulseAsync(WorkerWire wire, Guid job, CancellationTokenSource lifetime)
    {
        try
        {
            while (true)
            {
                await Task.Delay(TimeSpan.FromSeconds(2), lifetime.Token).ConfigureAwait(false);
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
                timeout.CancelAfter(TimeSpan.FromSeconds(2));
                await wire.SendAsync(WorkerMessage.Pulse, job, ReadOnlyMemory<byte>.Empty, timeout.Token).ConfigureAwait(false);
            }
        }
        catch { lifetime.Cancel(); throw; }
    }
}
