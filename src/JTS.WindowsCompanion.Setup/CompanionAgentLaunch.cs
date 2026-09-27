using JTS.WindowsCompanion.Lifecycle;

namespace JTS.WindowsCompanion.Setup;

internal sealed class CompanionAgentLaunch : IDisposable
{
    private readonly CompanionAgentReadinessServer _readiness;

    public CompanionAgentLaunch(
        int processId,
        CompanionAgentReadinessServer readiness)
    {
        if (processId <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(processId));
        }

        ProcessId = processId;
        _readiness = readiness ?? throw new ArgumentNullException(nameof(readiness));
    }

    public int ProcessId { get; }

    public Task WaitForReadyAsync(TimeSpan timeout, CancellationToken cancellationToken) =>
        _readiness.WaitForReadyAsync(ProcessId, timeout, cancellationToken);

    public void Dispose() => _readiness.Dispose();
}
