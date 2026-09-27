using System.Security.Cryptography;
using System.Text;
using JTS.WindowsCompanion.Runtime;

namespace JTS.WindowsCompanion.Execution;

/// <summary>Runs inside the separately provisioned standard-account Worker, never the grant authority or SYSTEM host.</summary>
public sealed class StandardAccountPowerShellExecutor : IJobExecutor
{
    private readonly IWorkerExecutionPlatform _platform;
    public StandardAccountPowerShellExecutor(string expectedWorkerSid)
    {
        WorkerAccountPolicy.ValidateConfiguredSid(expectedWorkerSid);
        if (!OperatingSystem.IsWindows() || Environment.Is64BitProcess is false)
            throw new PlatformNotSupportedException("A 64-bit Windows standard-account Worker is required.");
        _platform = new WindowsWorkerPlatform(expectedWorkerSid);
    }
    internal StandardAccountPowerShellExecutor(IWorkerExecutionPlatform platform) => _platform = platform;

    public async ValueTask<JobExecutionResult> ExecuteAsync(JobBinding binding, ReadOnlyMemory<byte> payload,
        IJobOutputSink output, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(output);
        var request = PowerShellRequest.Parse(binding, payload);
        cancellationToken.ThrowIfCancellationRequested();
        // Start attests both parent and suspended child tokens; child is born inside a kill-on-close job.
        using var process = _platform.Start(request.WorkingDirectory);
        using var io = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        using var outputGate = new SemaphoreSlim(1, 1);
        var script = Encoding.UTF8.GetBytes(request.Script);
        var tasks = new List<Task>();
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            process.Resume();
            var input = SendScriptAsync(process.Input, script, io.Token);
            var stdout = PumpAsync(process.Output, output, outputGate, io.Token);
            var stderr = PumpAsync(process.Error, output, outputGate, io.Token);
            var exited = process.WaitForExitAsync(io.Token);
            tasks.AddRange([input, stdout, stderr, exited]);
            var pending = new List<Task>(tasks);
            while (pending.Count != 0)
            {
                var completed = await Task.WhenAny(pending).ConfigureAwait(false);
                await completed.ConfigureAwait(false); // Observe pump/quota errors before waiting on a blocked process.
                pending.Remove(completed);
                if (ReferenceEquals(completed, exited))
                    await process.TerminateAndDrainAsync().ConfigureAwait(false); // Also remove descendants after root exit.
            }
            cancellationToken.ThrowIfCancellationRequested();
            var code = await exited.ConfigureAwait(false);
            return new JobExecutionResult(code == 0, code == 0 ? "OK" : "POWERSHELL_EXIT_NONZERO");
        }
        finally
        {
            try
            {
                // Independent of caller cancellation. Terminal receipt is not published until drain is confirmed.
                await process.TerminateAndDrainAsync().ConfigureAwait(false);
            }
            finally
            {
                io.Cancel();
                try
                {
                    try { await Task.WhenAll(tasks).WaitAsync(TimeSpan.FromSeconds(1)).ConfigureAwait(false); }
                    catch (TimeoutException) { throw new JobExecutionStateUnknownException(); }
                    catch (Exception) { /* Original error or unconfirmed native drain remains authoritative. */ }
                }
                finally { CryptographicOperations.ZeroMemory(script); }
            }
        }
    }

    private static async Task SendScriptAsync(Stream input, byte[] script, CancellationToken cancellationToken)
    {
        try { await input.WriteAsync(script, cancellationToken).ConfigureAwait(false); await input.FlushAsync(cancellationToken).ConfigureAwait(false); }
        finally { await input.DisposeAsync().ConfigureAwait(false); }
    }
    private static async Task PumpAsync(Stream stream, IJobOutputSink sink, SemaphoreSlim gate, CancellationToken cancellationToken)
    {
        var buffer = new byte[4096];
        try
        {
            int read;
            while ((read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) != 0)
            {
                await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
                try { await sink.AppendAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false); }
                finally { gate.Release(); }
            }
        }
        finally { CryptographicOperations.ZeroMemory(buffer); }
    }
}

internal interface IWorkerExecutionPlatform { IWorkerProcess Start(string workingDirectory); }
internal interface IWorkerProcess : IDisposable
{
    Stream Input { get; }
    Stream Output { get; }
    Stream Error { get; }
    void Resume();
    Task<uint> WaitForExitAsync(CancellationToken cancellationToken);
    Task TerminateAndDrainAsync();
}
