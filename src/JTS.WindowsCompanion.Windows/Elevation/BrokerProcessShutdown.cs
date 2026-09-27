using System.Diagnostics;

namespace JTS.WindowsCompanion.Windows.Elevation;

internal interface IBrokerProcessLifetime : IDisposable
{
    int Id { get; }

    bool HasExited { get; }

    Task WaitForExitAsync(CancellationToken cancellationToken);

    void KillProcessTree();
}

internal sealed class SystemBrokerProcessLifetime : IBrokerProcessLifetime
{
    private readonly Process _process;

    private SystemBrokerProcessLifetime(Process process)
    {
        _process = process;
    }

    public int Id => _process.Id;

    public bool HasExited => _process.HasExited;

    public static SystemBrokerProcessLifetime Start(ProcessStartInfo startInfo) =>
        new(Process.Start(startInfo)
            ?? throw new InvalidOperationException("The release-verified UAC broker could not be started."));

    public Task WaitForExitAsync(CancellationToken cancellationToken) =>
        _process.WaitForExitAsync(cancellationToken);

    public void KillProcessTree()
    {
        if (!_process.HasExited)
        {
            _process.Kill(entireProcessTree: true);
        }
    }

    public void Dispose() => _process.Dispose();
}

internal static class BrokerProcessShutdown
{
    internal static readonly TimeSpan GracefulExitTimeout = TimeSpan.FromSeconds(5);
    internal static readonly TimeSpan ForcedExitTimeout = TimeSpan.FromSeconds(5);

    public static async Task StopAsync(
        IBrokerProcessLifetime process,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(process);
        ArgumentNullException.ThrowIfNull(timeProvider);
        if (process.HasExited)
        {
            return;
        }

        if (await WaitForExitAsync(process, GracefulExitTimeout, timeProvider).ConfigureAwait(false))
        {
            return;
        }

        Exception? terminationFailure = null;
        try
        {
            process.KillProcessTree();
        }
        catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            terminationFailure = exception;
        }

        if (!await WaitForExitAsync(process, ForcedExitTimeout, timeProvider).ConfigureAwait(false))
        {
            throw new InvalidOperationException(
                "The UAC broker process did not terminate after cancellation.",
                terminationFailure);
        }
    }

    private static async Task<bool> WaitForExitAsync(
        IBrokerProcessLifetime process,
        TimeSpan timeout,
        TimeProvider timeProvider)
    {
        using var cancellation = new CancellationTokenSource(timeout, timeProvider);
        try
        {
            await process.WaitForExitAsync(cancellation.Token).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            return process.HasExited;
        }
    }
}
