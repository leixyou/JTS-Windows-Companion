using System.ComponentModel;

namespace JTS.WindowsCompanion.Setup;

internal sealed record CompanionProcessStopState(
    bool AgentWasRunning,
    bool BrokerWasRunning);

internal sealed class PreparedCompanionProcessStop : IDisposable
{
    private static readonly TimeSpan GracefulStopTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan ForcedStopTimeout = TimeSpan.FromSeconds(5);

    private readonly IReadOnlyList<PreparedTarget> _targets;
    private bool _disposed;
    private bool _executed;

    internal PreparedCompanionProcessStop(
        CompanionProcessStopState state,
        IReadOnlyList<PreparedTarget> targets)
    {
        State = state;
        _targets = targets;
    }

    public CompanionProcessStopState State { get; }

    public void Execute()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_executed)
        {
            throw new InvalidOperationException("The prepared Companion process stop has already executed.");
        }
        _executed = true;

        var failures = new List<Exception>();
        foreach (var target in _targets.OrderBy(target => target.Role))
        {
            try
            {
                Stop(target);
            }
            catch (Exception exception)
            {
                failures.Add(new InvalidOperationException(
                    $"The running {target.FileName} process (PID {target.Handle.ProcessId}) did not stop.",
                    exception));
            }
        }

        if (failures.Count > 0)
        {
            throw new AggregateException(
                "One or more installed Companion processes did not stop.",
                failures);
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        foreach (var target in _targets)
        {
            target.Handle.Dispose();
        }
    }

    private static void Stop(PreparedTarget target)
    {
        if (target.Handle.HasExited)
        {
            return;
        }

        var closeRequested = false;
        try
        {
            closeRequested = target.Handle.RequestClose();
        }
        catch (Exception exception) when (exception is Win32Exception or InvalidOperationException)
        {
            // Graceful window close is best effort. The prevalidated exact process
            // handle remains the authority for the bounded forced-stop fallback.
        }

        if (closeRequested && target.Handle.WaitForExit(GracefulStopTimeout))
        {
            return;
        }

        target.Handle.Terminate();
        if (!target.Handle.WaitForExit(ForcedStopTimeout))
        {
            throw new TimeoutException("The process remained active after forced termination.");
        }
    }

    internal sealed record PreparedTarget(
        CompanionProcessRole Role,
        string FileName,
        ICompanionProcessStopHandle Handle);
}
